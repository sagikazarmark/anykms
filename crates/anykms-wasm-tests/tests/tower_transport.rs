//! `TowerTransport` on a JS host, and an HTTP backend running over it: the Cloudflare Workers
//! shape (anykms-aws + anykms-http's `tower` and `js` features, no reqwest in the tree), with an
//! in-memory tower service standing in for `tower-worker-fetch`'s `FetchService`, which needs
//! workerd to run.
//!
//! The backend's data path reads the clock (the SigV4 signing time, the credential cache): with
//! the `js` features those reads go through `anykms_core::time`, where `std::time` would panic.
//!
//! The link-local credential sources (EC2 IMDS, the GCP metadata server, Azure IMDS) cannot be
//! reached from a Worker, and the host's `fetch` need not honour the probes' timeouts: each must
//! fail with a `Configuration` error before anything is sent, whether chosen explicitly or by a
//! default chain.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anykms_aws::credentials::StaticCredentials;
use anykms_aws::{AwsProvider, Credentials};
use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck, Zeroizing};
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

/// `err` is the `Configuration` error a link-local source must fail with here, and `svc` saw
/// nothing: no probe was sent.
fn assert_failed_before_sending(err: &anykms_core::Error, svc: &Canned) {
    assert_eq!(err.kind(), ErrorKind::Configuration, "{err:?}");
    assert!(
        svc.seen.lock().unwrap().is_empty(),
        "a request reached the service: {err:?}"
    );
}

/// AWS without explicit credentials: the default chain ends at IMDS, which fails before a probe.
#[wasm_bindgen_test]
async fn aws_default_chain_fails_before_probing_imds() {
    let svc = canned(StatusCode::OK, b"{}");
    let provider = AwsProvider::builder()
        .allowed_accounts(["123456789012"])
        .allowed_regions(["eu-west-1"])
        .http_transport(TowerTransport::new(svc.clone()))
        .build()
        .expect("a provider without credentials builds; the chain resolves lazily");
    let err = provider
        .aead_key(format!("aws-kms://{KEY_ARN}"))
        .expect("key")
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"plaintext", b"")
        .await
        .expect_err("no credential source works on a JS host");
    assert_failed_before_sending(&err, &svc);
    // The chain names what it tried; the source says why IMDS was not.
    let source = std::error::Error::source(&err).expect("the IMDS failure as source");
    assert!(
        source
            .to_string()
            .contains("not reachable from this target"),
        "{source}"
    );

    // Chosen explicitly, the same.
    let svc = canned(StatusCode::OK, b"{}");
    let provider = AwsProvider::builder()
        .credentials(anykms_aws::credentials::ImdsCredentials::new())
        .http_transport(TowerTransport::new(svc.clone()))
        .build()
        .expect("builds");
    let err = provider
        .aead_key(format!("aws-kms://{KEY_ARN}"))
        .expect("key")
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"plaintext", b"")
        .await
        .expect_err("IMDS is unreachable");
    assert_failed_before_sending(&err, &svc);
}

/// GCP: ADC skips the metadata server without a probe and reports no credentials; chosen
/// explicitly, the metadata server is refused at `build()`.
#[wasm_bindgen_test]
async fn gcp_metadata_server_fails_before_probing() {
    use anykms_gcp::{Credentials, GcpProvider};
    const KEY: &str = "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k";

    let svc = canned(StatusCode::OK, b"{}");
    let provider = GcpProvider::builder()
        .http_transport(TowerTransport::new(svc.clone()))
        .build()
        .expect("ADC resolves lazily");
    let err = provider
        .aead_key(KEY)
        .expect("key")
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"plaintext", b"")
        .await
        .expect_err("no credential source works on a JS host");
    assert_failed_before_sending(&err, &svc);

    let svc = canned(StatusCode::OK, b"{}");
    let err = GcpProvider::builder()
        .credentials(Credentials::metadata_server())
        .http_transport(TowerTransport::new(svc.clone()))
        .build()
        .expect_err("the metadata server is unreachable");
    assert_failed_before_sending(&err, &svc);
}

/// Azure: a managed identity through IMDS fails at the token request, before it is sent.
#[wasm_bindgen_test]
async fn azure_imds_managed_identity_fails_before_sending() {
    use anykms_azure::{AzureProvider, ManagedIdentity};

    let svc = canned(StatusCode::OK, b"{}");
    let provider = AzureProvider::builder()
        .credential(ManagedIdentity::system())
        .http_transport(TowerTransport::new(svc.clone()))
        .build()
        .expect("builds; the token is fetched lazily");
    let err = provider
        // AES-GCM keys live on Managed HSM; any handle would do, the token comes first.
        .aead_key("azure-kv://contoso.managedhsm.azure.net/keys/k")
        .expect("key")
        .encrypt(b"plaintext", b"")
        .await
        .expect_err("IMDS is unreachable");
    assert_failed_before_sending(&err, &svc);
}
