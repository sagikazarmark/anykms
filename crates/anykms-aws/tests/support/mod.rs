//! Helpers shared by the mock-server tests.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anykms_aws::credentials::{SourceContext, StaticCredentials};
use anykms_aws::{AwsProvider, AwsProviderBuilder, CredentialSource, Credentials};
use anykms_core::{BoxFuture, Result};
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const ACCOUNT: &str = "111122223333";
pub const SYM: &str = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111";
pub const SYM2: &str =
    "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-222222222222";
pub const EC: &str = "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-2222-2222-222222222222";
pub const RSA_SIGN: &str =
    "arn:aws:kms:us-east-1:111122223333:key/33333333-3333-3333-3333-333333333333";
pub const ED: &str = "arn:aws:kms:us-east-1:111122223333:key/44444444-4444-4444-4444-444444444444";
pub const HMAC: &str =
    "arn:aws:kms:us-east-1:111122223333:key/55555555-5555-5555-5555-555555555555";
pub const RSA_WRAP: &str =
    "arn:aws:kms:us-east-1:111122223333:key/66666666-6666-6666-6666-666666666666";
pub const ALIAS: &str = "arn:aws:kms:us-east-1:111122223333:alias/app-signer";
pub const OTHER: &str =
    "arn:aws:kms:us-east-1:111122223333:key/99999999-9999-9999-9999-999999999999";

/// The SPKI of tests/data/rsa-2048.pk8.
pub const RSA_SPKI_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtGdBZL6CdjvE4+f9Wu4HF3WOT3y81qm/XFtXRHhG7QJN9PIFDQ8miESQHqRQmBfr9jpneEYWRQOJ/Ul5uxS4i0xNCmpPOCdgKOZT3PQyVExW0jQV90AkXW/5tVWS3GW4db61agY3PZlhkIKNMMvX4dLuSof4uoAN/a8mz2ZD5YA87hOFylb7Brgsv3Ok64y7tyJAgOjUSBrHojvkQRBvjJBjlnlqL684S55xHMhgxQDkiw8FYNKM4+W0eDNfdFpbpqee20UatB2+y609JIfq0ePiufSIZYTToOItfxOZQe84vjcGx8UoRu6z8VWIIsayfIuMgVKQDLi6XZCulLQw8wIDAQAB";

pub fn uri(arn: &str) -> String {
    format!("aws-kms://{arn}")
}

pub fn b64(d: impl AsRef<[u8]>) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(d)
}

pub fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

pub fn builder(server: &MockServer) -> AwsProviderBuilder {
    AwsProvider::builder()
        .credentials(StaticCredentials::new(Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
        )))
        .endpoint_url(server.uri())
        .allow_loopback_http()
}

pub fn provider(server: &MockServer) -> AwsProvider {
    builder(server).build().unwrap()
}

/// Responds to `TrentService.<target>` (optionally only for a body containing `matching`).
pub async fn on(
    server: &MockServer,
    target: &str,
    matching: Option<Value>,
    status: u16,
    body: Value,
) {
    let mut m = Mock::given(method("POST")).and(header(
        "x-amz-target",
        format!("TrentService.{target}").as_str(),
    ));
    if let Some(j) = matching {
        m = m.and(body_partial_json(j));
    }
    m.respond_with(
        ResponseTemplate::new(status)
            .insert_header("x-amzn-RequestId", "req-0001")
            .set_body_json(body),
    )
    .mount(server)
    .await;
}

/// `DescribeKey` for `arn` with these fields.
pub async fn describe(server: &MockServer, arn: &str, spec: &str, usage: &str, extra: Value) {
    let mut meta = json!({
        "Arn": arn,
        "KeyId": arn.rsplit('/').next().unwrap(),
        "AWSAccountId": ACCOUNT,
        "KeySpec": spec,
        "KeyUsage": usage,
        "KeyState": "Enabled",
        "CreationDate": 1_700_000_000.123,
    });
    for (k, v) in extra.as_object().unwrap() {
        meta[k] = v.clone();
    }
    on(
        server,
        "DescribeKey",
        Some(json!({"KeyId": arn})),
        200,
        json!({"KeyMetadata": meta}),
    )
    .await;
}

pub async fn describe_all(server: &MockServer) {
    describe(
        server,
        SYM,
        "SYMMETRIC_DEFAULT",
        "ENCRYPT_DECRYPT",
        json!({"EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]}),
    )
    .await;
    describe(
        server,
        EC,
        "ECC_NIST_P256",
        "SIGN_VERIFY",
        json!({"SigningAlgorithms": ["ECDSA_SHA_256"]}),
    )
    .await;
    describe(
        server,
        RSA_SIGN,
        "RSA_2048",
        "SIGN_VERIFY",
        json!({"SigningAlgorithms": ["RSASSA_PSS_SHA_256", "RSASSA_PKCS1_V1_5_SHA_256"]}),
    )
    .await;
    describe(
        server,
        ED,
        "ECC_NIST_EDWARDS25519",
        "SIGN_VERIFY",
        json!({"SigningAlgorithms": ["ED25519_SHA_512", "ED25519_PH_SHA_512"]}),
    )
    .await;
    describe(
        server,
        HMAC,
        "HMAC_256",
        "GENERATE_VERIFY_MAC",
        json!({"MacAlgorithms": ["HMAC_SHA_256"]}),
    )
    .await;
    describe(
        server,
        RSA_WRAP,
        "RSA_2048",
        "ENCRYPT_DECRYPT",
        json!({"EncryptionAlgorithms": ["RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"]}),
    )
    .await;
}

/// The JSON bodies of every request for `target`.
pub async fn bodies(server: &MockServer, target: &str) -> Vec<Value> {
    let want = format!("TrentService.{target}");
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.headers.get("x-amz-target").and_then(|v| v.to_str().ok()) == Some(want.as_str())
        })
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

pub async fn count(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

/// A credential source that hands out `AKID<n>` and counts fetches.
#[derive(Debug, Default)]
pub struct Counting {
    pub fetches: AtomicUsize,
    /// Same credentials every time (no change after a refetch).
    pub fixed: bool,
}

impl CredentialSource for Counting {
    fn kind(&self) -> &'static str {
        "counting"
    }

    fn credentials<'a>(&'a self, _: &'a SourceContext) -> BoxFuture<'a, Result<Credentials>> {
        let n = self.fetches.fetch_add(1, Ordering::SeqCst) + 1;
        let n = if self.fixed { 1 } else { n };
        Box::pin(async move {
            Ok(Credentials::new(
                format!("AKID{n}"),
                format!("SECRET{n}"),
                Some(format!("TOKEN{n}")),
            ))
        })
    }
}

pub fn counting(fixed: bool) -> Arc<Counting> {
    Arc::new(Counting {
        fetches: AtomicUsize::new(0),
        fixed,
    })
}
