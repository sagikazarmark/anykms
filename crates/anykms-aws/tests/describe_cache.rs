//! The provider's shared `DescribeKey` cache over an injected transport that holds a request
//! until the test releases it: forgetting one key's metadata leaves concurrent reads of other
//! keys alone.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anykms_aws::AwsProvider;
use anykms_aws::Credentials;
use anykms_aws::anykms_http::transport::{Request, Response};
use anykms_aws::anykms_http::{HttpTransport, SendError};
use anykms_aws::credentials::StaticCredentials;
use anykms_core::prelude::*;
use anykms_core::{BoxFuture, ErrorKind, KeyTypeCheck};
use anykms_testkit::ScriptedTransport;
use serde_json::json;
use support::*;
use tokio::sync::Notify;

/// A [`ScriptedTransport`] whose first `DescribeKey` is held until `release`; `arrived` is
/// notified once it was sent.
#[derive(Default)]
struct HoldFirstDescribe {
    script: ScriptedTransport,
    held: AtomicBool,
    arrived: Notify,
    release: Notify,
}

impl HttpTransport for HoldFirstDescribe {
    fn send(&self, req: Request, limit: usize) -> BoxFuture<'_, Result<Response, SendError>> {
        let hold = req
            .headers()
            .get("x-amz-target")
            .is_some_and(|t| t == "TrentService.DescribeKey")
            && !self.held.swap(true, Ordering::SeqCst);
        // The script answers in the order requests are sent.
        let answer = self.script.send(req, limit);
        Box::pin(async move {
            if hold {
                self.arrived.notify_one();
                self.release.notified().await;
            }
            answer.await
        })
    }
}

fn targets(t: &ScriptedTransport) -> Vec<String> {
    t.seen()
        .iter()
        .map(|r| {
            r.headers["x-amz-target"]
                .to_str()
                .unwrap()
                .trim_start_matches("TrentService.")
                .to_owned()
        })
        .collect()
}

/// A key found missing (here by a request answered `NotFoundException`) drops only its own
/// metadata: a `DescribeKey` of another key in flight meanwhile still stores, and that key's
/// next request sends no `DescribeKey`.
#[tokio::test]
async fn forgetting_one_key_keeps_a_concurrent_describe_of_another_key() {
    let t = Arc::new(HoldFirstDescribe::default());
    let meta = json!({"KeyMetadata": {
        "Arn": SYM, "KeyId": SYM.rsplit('/').next().unwrap(), "AWSAccountId": ACCOUNT,
        "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled",
        "CreationDate": 1_700_000_000.123, "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
    }});
    let encrypted = json!({"CiphertextBlob": b64(b"b"), "KeyId": SYM}).to_string();
    t.script
        .reply(200, meta.to_string())
        .reply(
            400,
            json!({"__type": "NotFoundException", "message": "Key does not exist"}).to_string(),
        )
        .reply(200, encrypted.clone())
        .reply(200, encrypted);
    let p = AwsProvider::builder()
        .credentials(StaticCredentials::new(Credentials::new(
            "AKID", "SECRET", None,
        )))
        .http_transport(t.clone())
        .build()
        .unwrap();
    let a = p.aead_key(uri(SYM)).unwrap();
    let b = p
        .aead_key(uri(SYM2))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);

    let first = tokio::spawn({
        let a = a.clone();
        async move { a.encrypt(b"x", b"").await }
    });
    t.arrived.notified().await;
    let e = b.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    t.release.notify_one();
    first.await.unwrap().unwrap();

    a.encrypt(b"x", b"")
        .await
        .expect("another key's forget discarded this key's DescribeKey");
    assert_eq!(
        targets(&t.script),
        ["DescribeKey", "Encrypt", "Encrypt", "Encrypt"]
    );
}
