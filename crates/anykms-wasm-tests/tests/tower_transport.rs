//! `TowerTransport` on a JS host, and an HTTP backend running over it: the Cloudflare Workers
//! shape (anykms-aws + anykms-http's `tower` and `js` features, no reqwest in the tree), with an
//! in-memory tower service standing in for `tower-worker-fetch`'s `FetchService`, which needs
//! workerd to run.
//!
//! The backend's data path reads the clock (the SigV4 signing time, the credential cache): with
//! the `js` features those reads go through `anykms_core::time`, where `std::time` would panic.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anykms_aws::credentials::StaticCredentials;
use anykms_aws::{AwsProvider, Credentials};
use anykms_core::prelude::*;
use anykms_core::{KeyTypeCheck, Zeroizing};
use anykms_http::http::{self, Request, Response, StatusCode};
use anykms_http::tower::RequestBody;
use anykms_http::{HttpTransport, SendError, TowerTransport};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Full;
use tower_service::Service;
use wasm_bindgen_test::wasm_bindgen_test;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const KEY_ARN: &str = "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111";

/// A service that replies with a canned response and keeps what it was sent.
#[derive(Clone)]
struct Canned {
    status: StatusCode,
    body: Bytes,
    seen: Arc<Mutex<Vec<Request<RequestBody>>>>,
}

impl Service<Request<RequestBody>> for Canned {
    type Response = Response<Full<Bytes>>;
    type Error = BoxError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RequestBody>) -> Self::Future {
        self.seen.lock().unwrap().push(req);
        let mut resp = Response::new(Full::new(self.body.clone()));
        *resp.status_mut() = self.status;
        std::future::ready(Ok(resp))
    }
}

fn canned(status: StatusCode, body: &[u8]) -> Canned {
    Canned {
        status,
        body: Bytes::copy_from_slice(body),
        seen: Arc::new(Mutex::new(Vec::new())),
    }
}

/// The adapter moves bytes on this target: the body and `content-length` reach the service, the
/// response comes back whole, and the limit is enforced.
#[wasm_bindgen_test]
async fn tower_transport_runs_on_the_js_host() {
    let svc = canned(StatusCode::OK, b"{\"ok\":true}");
    let t = TowerTransport::new(svc.clone());
    let req = Request::post("https://kms.eu-west-1.amazonaws.com/")
        .body(Zeroizing::new(b"{\"KeyId\":\"k\"}".to_vec()))
        .unwrap();
    let resp = t.send(req, 64).await.expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&resp.body()[..], b"{\"ok\":true}");
    let seen = svc.seen.lock().unwrap();
    assert_eq!(seen[0].headers()[http::header::CONTENT_LENGTH], "13");

    let t = TowerTransport::new(canned(StatusCode::OK, &[b'x'; 100]));
    let req = Request::get("https://kms.eu-west-1.amazonaws.com/")
        .body(Zeroizing::new(Vec::new()))
        .unwrap();
    match t.send(req, 16).await {
        Err(SendError::TooLarge { status }) => assert_eq!(status, StatusCode::OK),
        other => panic!("{other:?}"),
    }
}

/// An HTTP backend over the adapter, with explicit credentials (the only kind that makes sense
/// on a Worker), performs an operation: the SigV4 signing time comes from the JS clock, the
/// signed request reaches the service, and the response is parsed.
#[wasm_bindgen_test]
async fn aws_encrypts_over_a_tower_transport() {
    let ciphertext = base64::engine::general_purpose::STANDARD.encode(b"wrapped");
    let svc = canned(
        StatusCode::OK,
        format!("{{\"CiphertextBlob\":\"{ciphertext}\",\"KeyId\":\"{KEY_ARN}\"}}").as_bytes(),
    );
    let provider = AwsProvider::builder()
        .credentials(StaticCredentials::new(Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        )))
        .allowed_accounts(["123456789012"])
        .allowed_regions(["eu-west-1"])
        .http_transport(TowerTransport::new(svc.clone()))
        .build()
        .expect("an AWS provider over a tower transport");

    let ct = provider
        .aead_key(format!("aws-kms://{KEY_ARN}"))
        .expect("key")
        // No `DescribeKey` round trip: one canned reply serves the one call.
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"plaintext", b"")
        .await
        .expect("encrypt");
    assert_eq!(ct.as_bytes(), b"wrapped");

    let seen = svc.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let req = &seen[0];
    assert_eq!(req.uri(), "https://kms.eu-west-1.amazonaws.com/");
    assert_eq!(req.headers()["x-amz-target"], "TrentService.Encrypt");
    // Signed at the JS wall clock: today's date in the credential scope.
    let today = {
        let d = js_sys::Date::new_0();
        format!(
            "{:04}{:02}{:02}",
            d.get_utc_full_year(),
            d.get_utc_month() + 1,
            d.get_utc_date()
        )
    };
    let auth = req.headers()["authorization"].to_str().unwrap();
    assert!(
        auth.contains(&format!(
            "Credential=AKIAIOSFODNN7EXAMPLE/{today}/eu-west-1/kms/aws4_request"
        )),
        "{auth}"
    );
    assert!(
        req.headers()["x-amz-date"]
            .to_str()
            .unwrap()
            .starts_with(&today)
    );
    assert!(req.headers().contains_key(http::header::CONTENT_LENGTH));
}
