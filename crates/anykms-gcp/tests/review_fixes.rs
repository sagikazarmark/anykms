//! Regression tests for the 2026-11 security review findings on the GCP backend (L1, L19, L22,
//! L28, L31 and the informational items).

mod common;

use std::fmt::Write as _;
use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{Ciphertext, Digest, ErrorKind, KeyTypeCheck, SignatureAlgorithm};
use anykms_gcp::{AuthEndpoints, Credentials, Endpoint, GcpProvider, GcpProviderBuilder};
use common::FakeKms;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "projects/my-project/locations/global/keyRings/r/cryptoKeys/k";

fn provider(server: &MockServer) -> GcpProvider {
    GcpProvider::builder()
        .credentials(Credentials::static_token("ya29.mock"))
        .endpoint(Endpoint::custom(server.uri()))
        .allow_loopback_http()
        .public_key_ttl(Duration::ZERO)
        .build()
        .unwrap()
}

fn aead(server: &MockServer) -> anykms_gcp::GcpAeadKey {
    provider(server)
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
}

/// Every rendering of an error and its `source()` chain.
fn render(e: &anykms_core::Error) -> String {
    let mut s = format!("{e} {e:?}");
    let mut src = std::error::Error::source(e);
    while let Some(x) = src {
        write!(s, " {x} {x:?}").unwrap();
        src = x.source();
    }
    s
}

async fn decrypt_answering(body: Value) -> anykms_core::Result<Vec<u8>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}:decrypt")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    aead(&server)
        .decrypt(&Ciphertext::from_bytes(b"c".to_vec()), b"")
        .await
        .map(|d| d.to_vec())
}

/// L19: a 200 body without `protectionLevel` (`{}`, `[]`, a gateway's empty object) is not a
/// decrypt response, so it is never an empty plaintext. A real empty plaintext (Cloud KMS omits
/// the empty `plaintext` field) still decrypts.
#[tokio::test]
async fn l19_decrypt_requires_a_response_marker() {
    for body in [json!({}), json!([]), json!({"protectionLevel": ""})] {
        let e = decrypt_answering(body.clone()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Backend, "{body}: {e}");
    }
    let pt = decrypt_answering(json!({"protectionLevel": "SOFTWARE", "plaintextCrc32c": "0"}))
        .await
        .unwrap();
    assert_eq!(pt, Vec::<u8>::new());
}

/// L22: a non-canonical `error.status` never becomes `BackendDetail::code` (nor reaches
/// `Display`/`Debug`); the HTTP status's canonical code stands in. Canonical codes are kept.
#[tokio::test]
async fn l22_server_status_is_filtered_to_canonical_codes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}:encrypt")))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": {
            "code": 400, "status": "STATUSMARKER injected\nline", "message": "m"}})))
        .mount(&server)
        .await;
    let e = aead(&server).encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(
        e.detail().unwrap().code(),
        Some("INVALID_ARGUMENT"),
        "{e:?}"
    );
    assert!(!render(&e).contains("STATUSMARKER"), "{e:?}");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}:encrypt")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": {
            "code": 403, "status": "PERMISSION_DENIED", "message": "denied"}})))
        .mount(&server)
        .await;
    let e = aead(&server).encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert_eq!(e.detail().unwrap().code(), Some("PERMISSION_DENIED"));
}

/// L22, the OAuth path: a token endpoint answering with a google.rpc.Status whose `status` is
/// arbitrary text.
#[tokio::test]
async fn l22_token_endpoint_status_is_filtered() {
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": {
            "code": 400, "status": "STATUSMARKER injected", "message": "m"}})))
        .mount(&server)
        .await;
    let f = json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
        "refresh_token": "r"});
    let p = GcpProvider::builder()
        .credentials(Credentials::from_json(f.to_string()))
        .endpoint(Endpoint::custom(server.uri()))
        .auth_endpoints(AuthEndpoints::custom(&server.uri()).unwrap())
        .allow_loopback_http()
        .build()
        .unwrap();
    let e = p
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated, "{e}");
    assert!(!render(&e).contains("STATUSMARKER"), "{e:?}");
    if let Some(code) = e.detail().and_then(|d| d.code()) {
        assert!(
            code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
            "{code}"
        );
    }
}

/// L28: a "cache forever" public-key TTL neither panics at build (the local-verification bound)
/// nor when an entry is stored (`Instant` overflow), and the cache still works.
#[tokio::test]
async fn l28_huge_public_key_ttl_does_not_panic() {
    let fake = FakeKms::start().await;
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    for ttl in [Duration::MAX, Duration::from_secs(u64::MAX / 4)] {
        let p = common::cached_builder(&fake)
            .public_key_ttl(ttl)
            .build()
            .unwrap();
        let s = p
            .digest_signing_key(common::vuri(&ec, 1), SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap();
        let d = Digest::sha256(b"m");
        let sig = s.sign_digest(&d).await.unwrap();
        s.verify_digest(&d, &sig).await.unwrap();
        let before = fake.calls("GET publicKey");
        s.verify_digest(&d, &sig).await.unwrap();
        assert_eq!(fake.calls("GET publicKey"), before, "served from the cache");
    }
}

/// Builds `b` and runs one encrypt with it: the error, from either step.
async fn outcome(b: GcpProviderBuilder) -> anykms_core::Error {
    match b.build() {
        Err(e) => e,
        Ok(p) => p
            .aead_key(format!("gcp-kms://{KEY}"))
            .unwrap()
            .with_key_type_check(KeyTypeCheck::TrustCaller)
            .encrypt(b"x", b"")
            .await
            .unwrap_err(),
    }
}

fn metadata_builder(host: &'static str) -> GcpProviderBuilder {
    GcpProviderBuilder::from_env_with(move |v| (v == "GCE_METADATA_HOST").then(|| host.to_owned()))
        .unwrap()
        .credentials(Credentials::metadata_server())
        .endpoint(Endpoint::custom("http://127.0.0.1:9"))
        .allow_loopback_http()
}

fn adc_builder(host: &'static str) -> GcpProviderBuilder {
    GcpProviderBuilder::from_env_with(move |v| match v {
        "GCE_METADATA_HOST" => Some(host.to_owned()),
        "HOME" | "APPDATA" => Some("/nonexistent/anykms-gcp-review".to_owned()),
        _ => None,
    })
    .unwrap()
    .endpoint(Endpoint::custom("http://127.0.0.1:9"))
    .allow_loopback_http()
}

fn external_account(url: &str) -> Credentials {
    Credentials::from_json(
        json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/pool",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "credential_source": {"url": url, "headers": {"X-Secret": "HEADERSECRET"}},
        })
        .to_string(),
    )
}

fn names_plain_http(e: &anykms_core::Error) -> bool {
    e.kind() == ErrorKind::Configuration && e.to_string().contains("plain http")
}

/// L1: plain-HTTP credential endpoints on a host other than loopback, link-local or
/// `metadata.google.internal` are refused before any request, for `GCE_METADATA_HOST` (the
/// metadata source and the ADC probe) and an `external_account` `credential_source.url`.
#[tokio::test]
async fn l1_remote_plain_http_credential_endpoints_are_refused() {
    let e = outcome(metadata_builder("metadata-proxy.invalid:8080")).await;
    assert!(names_plain_http(&e), "{e}");
    let e = outcome(adc_builder("metadata-proxy.invalid:8080")).await;
    assert!(names_plain_http(&e), "{e}");
    let e = outcome(
        GcpProvider::builder()
            .credentials(external_account("http://token-broker.invalid/token"))
            .endpoint(Endpoint::custom("http://127.0.0.1:9"))
            .allow_loopback_http(),
    )
    .await;
    assert!(names_plain_http(&e), "{e}");
    assert!(!render(&e).contains("HEADERSECRET"));

    // With the opt-in the policy passes them (they then fail on DNS, not on the policy).
    let e =
        outcome(metadata_builder("metadata-proxy.invalid:8080").allow_remote_http_credentials())
            .await;
    assert!(!names_plain_http(&e), "{e}");
    let e = outcome(
        GcpProvider::builder()
            .credentials(external_account("http://token-broker.invalid/token"))
            .endpoint(Endpoint::custom("http://127.0.0.1:9"))
            .allow_loopback_http()
            .allow_remote_http_credentials(),
    )
    .await;
    assert!(!names_plain_http(&e), "{e}");
    // https:// to any host and plain HTTP to local hosts need no opt-in.
    for url in [
        "https://token-broker.invalid/token",
        "http://169.254.169.254/metadata/identity/oauth2/token",
        "http://localhost:1/token",
    ] {
        let e = outcome(
            GcpProvider::builder()
                .credentials(external_account(url))
                .endpoint(Endpoint::custom("http://127.0.0.1:9"))
                .allow_loopback_http(),
        )
        .await;
        assert!(!names_plain_http(&e), "{url}: {e}");
    }
    let e = outcome(metadata_builder("metadata.google.internal")).await;
    assert!(!names_plain_http(&e), "{e}");
}

/// L31: a FIFO named as the subject-token file fails at once instead of blocking a runtime
/// worker forever. The fix is in `anykms_http::zbuf::read_file` (shared by every file reader),
/// so this passes only with it.
#[cfg(unix)]
#[test]
fn l31_fifo_subject_token_file_does_not_hang() {
    let dir = std::env::temp_dir().join(format!("anykms-gcp-fifo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("subject");
    let _ = std::fs::remove_file(&fifo);
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let creds = Credentials::from_json(
        json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/pool",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "credential_source": {"file": fifo},
        })
        .to_string(),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let e = rt.block_on(outcome(
            GcpProvider::builder()
                .credentials(creds)
                .endpoint(Endpoint::custom("http://127.0.0.1:9"))
                .allow_loopback_http(),
        ));
        let _ = tx.send(e.kind());
    });
    let kind = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reading a FIFO subject-token file blocked");
    assert_eq!(kind, ErrorKind::Configuration);
}

/// Info: a typed constructor's type mismatch does not echo an unrecognized `type` string
/// (the file's contents); a known type is still named.
#[tokio::test]
async fn info_credential_type_mismatch_does_not_echo_unknown_types() {
    let server = MockServer::start().await;
    let dir = std::env::temp_dir().join(format!("anykms-gcp-type-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let odd = dir.join("odd.json");
    std::fs::write(&odd, json!({"type": "TYPEMARKER\u{1b}[31m"}).to_string()).unwrap();
    let p = |c| {
        GcpProvider::builder()
            .credentials(c)
            .endpoint(Endpoint::custom(server.uri()))
            .allow_loopback_http()
            .build()
            .unwrap()
    };
    let enc = |p: GcpProvider| async move {
        p.aead_key(format!("gcp-kms://{KEY}"))
            .unwrap()
            .with_key_type_check(KeyTypeCheck::TrustCaller)
            .encrypt(b"x", b"")
            .await
            .unwrap_err()
    };
    let e = enc(p(Credentials::service_account_file(&odd))).await;
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert!(!render(&e).contains("TYPEMARKER"), "{e}");
    assert!(e.to_string().contains("odd.json"), "{e}");
    let au = dir.join("au.json");
    std::fs::write(&au, json!({"type": "authorized_user"}).to_string()).unwrap();
    let e = enc(p(Credentials::service_account_file(&au))).await;
    assert!(e.to_string().contains("authorized_user"), "{e}");
}

/// Info: decrypt refuses an oversized ciphertext locally (no request), like every other input.
#[tokio::test]
async fn info_decrypt_caps_the_ciphertext() {
    let server = MockServer::start().await;
    let e = aead(&server)
        .decrypt(&Ciphertext::from_bytes(vec![1; 128 * 1024 + 1]), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{e}");
    assert!(server.received_requests().await.unwrap().is_empty());
}
