//! Mock-server cases (wiremock): exact request bodies, every row of the error table
//! (`docs/cloud/gcp.md` §7), response integrity checks, redirects, timeouts, the 401 retry and
//! describe paging. Each case pins one behavior with hand-written responses.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{
    BoxFuture, Ciphertext, Digest, ErrorKind, KeyTypeCheck, KeyVersion, MacAlgorithm, Operation,
    Preflight, SignatureAlgorithm, Tag,
};
use anykms_gcp::{CredentialSource, Credentials, Endpoint, GcpProvider, GcpProviderBuilder, Token};
use base64::Engine as _;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "projects/my-project/locations/global/keyRings/r/cryptoKeys/k";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// CRC32C, independent of the crate.
fn crc(data: &[u8]) -> String {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
    }
    (!c).to_string()
}

fn builder(server: &MockServer) -> GcpProviderBuilder {
    GcpProvider::builder()
        .credentials(Credentials::static_token("ya29.mock"))
        .endpoint(Endpoint::custom(server.uri()))
        .allow_loopback_http()
        .public_key_ttl(Duration::ZERO)
}

fn provider(server: &MockServer) -> GcpProvider {
    builder(server).build().unwrap()
}

fn aead(server: &MockServer) -> anykms_gcp::GcpAeadKey {
    provider(server)
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
}

fn post(p: &str) -> wiremock::MockBuilder {
    Mock::given(method("POST")).and(path(format!("/v1/{p}")))
}

fn encrypt_ok(ct: &[u8]) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "name": format!("{KEY}/cryptoKeyVersions/3"),
        "ciphertext": b64(ct),
        "ciphertextCrc32c": crc(ct),
        "verifiedPlaintextCrc32c": true,
        "verifiedAdditionalAuthenticatedDataCrc32c": true,
        "protectionLevel": "SOFTWARE",
    }))
}

#[tokio::test]
async fn request_bodies_are_minimal_with_crc32c_strings() {
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .and(header("authorization", "Bearer ya29.mock"))
        .and(header("x-goog-user-project", "billing-proj"))
        .and(header("content-type", "application/json"))
        .and(body_json(
            json!({"plaintext": b64(b"pt"), "plaintextCrc32c": crc(b"pt")}),
        ))
        .respond_with(encrypt_ok(b"ct-1"))
        .expect(1)
        .mount(&server)
        .await;
    post(&format!("{KEY}:encrypt"))
        .and(body_json(json!({
            "plaintext": b64(b"pt"), "plaintextCrc32c": crc(b"pt"),
            "additionalAuthenticatedData": b64(b"aad"),
            "additionalAuthenticatedDataCrc32c": crc(b"aad"),
        })))
        .respond_with(encrypt_ok(b"ct-2"))
        .expect(1)
        .mount(&server)
        .await;
    post(&format!("{KEY}:decrypt"))
        .and(body_json(
            json!({"ciphertext": b64(b"ct-1"), "ciphertextCrc32c": crc(b"ct-1")}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "plaintext": b64(b"pt"), "plaintextCrc32c": crc(b"pt"), "usedPrimary": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let k = builder(&server)
        .quota_project("billing-proj")
        .build()
        .unwrap()
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let ct = k.encrypt(b"pt", b"").await.unwrap();
    assert_eq!(ct.as_bytes(), b"ct-1");
    assert_eq!(k.encrypt(b"pt", b"aad").await.unwrap().as_bytes(), b"ct-2");
    let d = k.decrypt_with_info(&ct, b"").await.unwrap();
    assert_eq!(d.plaintext(), b"pt");
    assert_eq!(d.used_primary(), Some(true));
}

#[tokio::test]
async fn signing_and_mac_request_bodies() {
    let server = MockServer::start().await;
    let v = format!("{KEY}/cryptoKeyVersions/2");
    let d = Digest::sha384(b"m");
    let mut sig = vec![0x30u8];
    sig.resize(90, 7);
    post(&format!("{v}:asymmetricSign"))
        .and(body_json(json!({
            "digest": {"sha384": b64(d.as_bytes())},
            "digestCrc32c": crc(d.as_bytes()),
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": v, "signature": b64(&sig), "signatureCrc32c": crc(&sig),
            "verifiedDigestCrc32c": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    post(&format!("{v}:asymmetricSign"))
        .and(body_json(
            json!({"data": b64(b"msg"), "dataCrc32c": crc(b"msg")}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": v, "signature": b64(&[1; 64]), "signatureCrc32c": crc(&[1; 64]),
            "verifiedDataCrc32c": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let tag = [5u8; 32];
    post(&format!("{v}:macSign"))
        .and(body_json(
            json!({"data": b64(b"tok"), "dataCrc32c": crc(b"tok")}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": v, "mac": b64(&tag), "macCrc32c": crc(&tag), "verifiedDataCrc32c": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let v7 = format!("{KEY}/cryptoKeyVersions/7");
    post(&format!("{v7}:macVerify"))
        .and(body_json(json!({
            "data": b64(b"tok"), "dataCrc32c": crc(b"tok"),
            "mac": b64(&tag), "macCrc32c": crc(&tag),
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": v7, "success": true, "verifiedDataCrc32c": true,
            "verifiedMacCrc32c": true, "verifiedSuccessIntegrity": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let p = provider(&server);
    let uri = format!("gcp-kms://{v}");
    let s = p
        .digest_signing_key(&uri, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let out = s.sign_digest(&d).await.unwrap();
    assert_eq!(out.key_version(), Some(&KeyVersion::from_u64(2)));
    let e = p
        .ed25519_key(&uri)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    e.sign_message(b"msg").await.unwrap();
    let m = p
        .mac_key(&uri, MacAlgorithm::HmacSha256)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let t = m.mac(b"tok").await.unwrap();
    assert_eq!(t.as_bytes(), &tag);
    // The tag's version, not the handle's, is verified (a version of this key only).
    let t7 = Tag::from_parts(MacAlgorithm::HmacSha256, Some(KeyVersion::from_u64(7)), tag);
    m.verify_mac(b"tok", &t7).await.unwrap();
}

/// One row of the error table: a response and the kind it maps to.
struct Row {
    status: u16,
    body: Value,
    op: Operation,
    want: ErrorKind,
}

fn status(code: u16, status: &str, message: &str) -> Value {
    json!({"error": {"code": code, "status": status, "message": message}})
}

#[tokio::test]
async fn error_table() {
    use ErrorKind as K;
    use Operation as O;
    let rows = vec![
        Row {
            status: 400,
            body: status(
                400,
                "INVALID_ARGUMENT",
                "Decryption failed: verify that 'name' refers to the correct CryptoKey.",
            ),
            op: O::Decrypt,
            want: K::DecryptFailed,
        },
        Row {
            status: 400,
            body: status(
                400,
                "INVALID_ARGUMENT",
                "The checksum in field ciphertext_crc32c did not match the data in field ciphertext.",
            ),
            op: O::Decrypt,
            want: K::Unavailable,
        },
        Row {
            status: 400,
            body: status(
                400,
                "INVALID_ARGUMENT",
                "The checksum in field plaintext_crc32c did not match the data in field plaintext.",
            ),
            op: O::Encrypt,
            want: K::Unavailable,
        },
        Row {
            status: 400,
            body: status(400, "INVALID_ARGUMENT", "Plaintext too large"),
            op: O::Encrypt,
            want: K::InvalidArgument,
        },
        Row {
            status: 400,
            body: status(400, "OUT_OF_RANGE", "x"),
            op: O::Encrypt,
            want: K::InvalidArgument,
        },
        Row {
            status: 400,
            body: status(
                400,
                "FAILED_PRECONDITION",
                &format!("{KEY}/cryptoKeyVersions/1 is not enabled, current state is: DISABLED."),
            ),
            op: O::Encrypt,
            want: K::KeyStateInvalid,
        },
        Row {
            status: 400,
            body: status(
                400,
                "FAILED_PRECONDITION",
                &format!("{KEY}/cryptoKeyVersions/1 is not enabled, current state is: DESTROYED."),
            ),
            op: O::Decrypt,
            want: K::KeyVersionUnusable,
        },
        Row {
            status: 400,
            body: status(
                400,
                "FAILED_PRECONDITION",
                &format!(
                    "Operation requested for Key {KEY} has incorrect key purpose: ASYMMETRIC_SIGN"
                ),
            ),
            op: O::Encrypt,
            want: K::KeyMismatch,
        },
        Row {
            status: 400,
            body: status(400, "FAILED_PRECONDITION", "The EKM is unreachable"),
            op: O::Encrypt,
            want: K::Backend,
        },
        Row {
            status: 401,
            body: status(
                401,
                "UNAUTHENTICATED",
                "Request had invalid authentication credentials.",
            ),
            op: O::Encrypt,
            want: K::Unauthenticated,
        },
        Row {
            status: 403,
            body: status(
                403,
                "PERMISSION_DENIED",
                &format!(
                    "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied on resource '{KEY}' (or it may not exist)."
                ),
            ),
            op: O::Encrypt,
            want: K::PermissionDenied,
        },
        Row {
            status: 403,
            body: status(
                403,
                "PERMISSION_DENIED",
                "Request is prohibited by organization's policy. vpcServiceControlsUniqueIdentifier: x",
            ),
            op: O::Encrypt,
            want: K::PermissionDenied,
        },
        Row {
            status: 403,
            body: json!({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "Cloud KMS API has not been used in project 1 before or it is disabled.",
                "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED", "domain": "googleapis.com"}]}}),
            op: O::Encrypt,
            want: K::Configuration,
        },
        Row {
            status: 403,
            body: json!({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "This API method requires billing to be enabled.",
                "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "BILLING_DISABLED", "domain": "googleapis.com"}]}}),
            op: O::Encrypt,
            want: K::Configuration,
        },
        Row {
            status: 403,
            body: json!({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "Request had insufficient authentication scopes.",
                "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "domain": "googleapis.com"}]}}),
            op: O::Decrypt,
            want: K::Configuration,
        },
        Row {
            status: 404,
            body: status(404, "NOT_FOUND", &format!("CryptoKey {KEY} not found.")),
            op: O::Encrypt,
            want: K::NotFound,
        },
        Row {
            status: 409,
            body: status(409, "ABORTED", "x"),
            op: O::Encrypt,
            want: K::Unavailable,
        },
        Row {
            status: 503,
            body: status(503, "UNAVAILABLE", "The service is currently unavailable."),
            op: O::Encrypt,
            want: K::Unavailable,
        },
        Row {
            status: 504,
            body: status(504, "DEADLINE_EXCEEDED", "Deadline expired"),
            op: O::Encrypt,
            want: K::Timeout,
        },
        Row {
            status: 501,
            body: status(501, "UNIMPLEMENTED", "x"),
            op: O::Encrypt,
            want: K::Unsupported,
        },
        Row {
            status: 500,
            body: status(500, "INTERNAL", "Internal error encountered."),
            op: O::Encrypt,
            want: K::Backend,
        },
        Row {
            status: 500,
            body: status(500, "UNKNOWN", "x"),
            op: O::Encrypt,
            want: K::Backend,
        },
    ];
    for row in rows {
        let server = MockServer::start().await;
        let verb = if row.op == Operation::Decrypt {
            "decrypt"
        } else {
            "encrypt"
        };
        post(&format!("{KEY}:{verb}"))
            .respond_with(ResponseTemplate::new(row.status).set_body_json(row.body.clone()))
            .mount(&server)
            .await;
        let k = aead(&server);
        let e = match row.op {
            Operation::Decrypt => k
                .decrypt(&Ciphertext::from_bytes(b"ct".to_vec()), b"")
                .await
                .unwrap_err(),
            _ => k.encrypt(b"x", b"").await.unwrap_err(),
        };
        assert_eq!(e.kind(), row.want, "{} {} -> {e}", row.status, row.body);
        assert_eq!(e.resource(), Some(format!("gcp-kms://{KEY}").as_str()));
        let d = e.detail().expect("detail");
        assert_eq!(d.http_status, Some(row.status));
        assert!(d.code().is_some(), "{e}");
        // Unpinned messages are never echoed.
        let msg = row.body["error"]["message"].as_str().unwrap();
        let pinned = [
            "Decryption failed",
            "checksum",
            "current state",
            "denied on resource",
            "prohibited by organization",
            "invalid authentication",
            "incorrect key purpose",
        ];
        if msg.len() > 3 && !pinned.iter().any(|p| msg.contains(p)) {
            assert!(!format!("{e} {e:?}").contains(msg), "{e:?}");
        }
    }
}

#[tokio::test]
async fn non_json_and_odd_responses() {
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>Bad Gateway</html>"))
        .mount(&server)
        .await;
    let e = aead(&server).encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);

    // Throttled: Retry-After header, else RetryInfo.
    for (resp, want) in [
        (
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "7")
                .set_body_json(status(429, "RESOURCE_EXHAUSTED", "Quota exceeded")),
            Duration::from_secs(7),
        ),
        (
            ResponseTemplate::new(429).set_body_json(json!({"error": {"code": 429,
            "status": "RESOURCE_EXHAUSTED", "message": "Quota exceeded",
            "details": [
                {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "2.5s"},
                {"@type": "type.googleapis.com/google.rpc.RequestInfo", "requestId": "req-123"}
            ]}})),
            Duration::from_millis(2500),
        ),
    ] {
        let server = MockServer::start().await;
        post(&format!("{KEY}:encrypt"))
            .respond_with(resp)
            .mount(&server)
            .await;
        let e = aead(&server).encrypt(b"x", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Throttled);
        assert!(e.is_retryable());
        assert_eq!(e.retry_after(), Some(want));
    }
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({"error": {"code": 429,
            "status": "RESOURCE_EXHAUSTED", "message": "q",
            "details": [{"@type": "type.googleapis.com/google.rpc.RequestInfo", "requestId": "req-123"}]}})))
        .mount(&server)
        .await;
    let e = aead(&server).encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.detail().unwrap().request_id(), Some("req-123"));
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let target = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/v1/{KEY}:encrypt", target.uri())),
        )
        .mount(&server)
        .await;
    let e = aead(&server).encrypt(b"secret", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
}

#[tokio::test]
async fn timeouts() {
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(encrypt_ok(b"c").set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;
    // The per-request timeout lives on the transport.
    let k = builder(&server)
        .http_transport(
            anykms_gcp::anykms_http::ReqwestTransport::builder()
                .require_roots(false)
                .request_timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
}

#[tokio::test]
async fn response_integrity_failures() {
    let name = format!("{KEY}/cryptoKeyVersions/1");
    let cases: Vec<(&str, Value, ErrorKind)> = vec![
        (
            "encrypt",
            json!({"name": name, "ciphertext": b64(b"c"), "ciphertextCrc32c": "1",
                "verifiedPlaintextCrc32c": true}),
            ErrorKind::Unavailable,
        ),
        (
            "encrypt",
            json!({"name": name, "ciphertext": b64(b"c"), "ciphertextCrc32c": crc(b"c")}),
            ErrorKind::Unavailable,
        ),
        (
            "encrypt",
            json!({"name": "projects/other/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                "ciphertext": b64(b"c"), "ciphertextCrc32c": crc(b"c"), "verifiedPlaintextCrc32c": true}),
            ErrorKind::Backend,
        ),
        ("encrypt", json!({"unexpected": true}), ErrorKind::Backend),
        (
            "decrypt",
            json!({"plaintext": b64(b"secret"), "plaintextCrc32c": crc(b"other")}),
            ErrorKind::Unavailable,
        ),
        (
            "decrypt",
            json!({"plaintext": b64(b"secret")}),
            ErrorKind::Unavailable,
        ),
        ("decrypt", json!({"plaintext": "!!!"}), ErrorKind::Backend),
    ];
    for (verb, body, want) in cases {
        let server = MockServer::start().await;
        post(&format!("{KEY}:{verb}"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let k = aead(&server);
        let e = match verb {
            "encrypt" => k.encrypt(b"x", b"").await.unwrap_err(),
            _ => k
                .decrypt(&Ciphertext::from_bytes(b"c".to_vec()), b"")
                .await
                .unwrap_err(),
        };
        assert_eq!(e.kind(), want, "{verb} {body}: {e}");
        assert!(!format!("{e:?}").contains("secret"));
    }
    // macVerify: `success` contradicted by `verifiedSuccessIntegrity`.
    let server = MockServer::start().await;
    post(&format!("{name}:macVerify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": name, "success": true, "verifiedDataCrc32c": true,
            "verifiedMacCrc32c": true, "verifiedSuccessIntegrity": false,
        })))
        .mount(&server)
        .await;
    let m = provider(&server)
        .mac_key(format!("gcp-kms://{name}"), MacAlgorithm::HmacSha256)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let t = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::from_u64(1)),
        [0; 32],
    );
    assert_eq!(
        m.verify_mac(b"d", &t).await.unwrap_err().kind(),
        ErrorKind::Unavailable
    );
    // An oversized response.
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(200 * 1024)))
        .mount(&server)
        .await;
    let k = builder(&server)
        .max_response_bytes(64 * 1024)
        .build()
        .unwrap()
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Backend
    );
}

/// Returns `old` until invalidated, then `new`.
#[derive(Debug)]
struct Rotating {
    rotated: std::sync::atomic::AtomicBool,
    calls: AtomicUsize,
}

impl CredentialSource for Rotating {
    fn token(&self) -> BoxFuture<'_, anykms_core::Result<Option<Token>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let t = if self.rotated.load(Ordering::SeqCst) {
            "ya29.new"
        } else {
            "ya29.old"
        };
        Box::pin(async move { Ok(Some(Token::new(t, None))) })
    }

    fn invalidate(&self, rejected: &Token) {
        if rejected.expose() == "ya29.old" {
            self.rotated.store(true, Ordering::SeqCst);
        }
    }
}

#[tokio::test]
async fn unauthenticated_refreshes_once_and_only_once() {
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .and(header("authorization", "Bearer ya29.old"))
        .respond_with(ResponseTemplate::new(401).set_body_json(status(401, "UNAUTHENTICATED", "x")))
        .expect(1)
        .mount(&server)
        .await;
    post(&format!("{KEY}:encrypt"))
        .and(header("authorization", "Bearer ya29.new"))
        .respond_with(encrypt_ok(b"c"))
        .expect(1)
        .mount(&server)
        .await;
    let src = Arc::new(Rotating {
        rotated: false.into(),
        calls: AtomicUsize::new(0),
    });
    let k = builder(&server)
        .credentials(Credentials::custom(src.clone()))
        .build()
        .unwrap()
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    k.encrypt(b"x", b"").await.unwrap();

    // A 401 with the refreshed token too: reported, not retried again.
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(ResponseTemplate::new(401).set_body_json(status(401, "UNAUTHENTICATED", "x")))
        .expect(2)
        .mount(&server)
        .await;
    let src = Arc::new(Rotating {
        rotated: false.into(),
        calls: AtomicUsize::new(0),
    });
    let k = builder(&server)
        .credentials(Credentials::custom(src))
        .build()
        .unwrap()
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Unauthenticated
    );
    // A static token cannot change: no retry at all.
    let server = MockServer::start().await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(ResponseTemplate::new(401).set_body_json(status(401, "UNAUTHENTICATED", "x")))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        aead(&server).encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Unauthenticated
    );
}

#[tokio::test]
async fn key_type_check_reads_metadata_once() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": KEY, "purpose": "ENCRYPT_DECRYPT",
            "versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protectionLevel": "SOFTWARE"},
        })))
        .expect(1)
        .mount(&server)
        .await;
    post(&format!("{KEY}:encrypt"))
        .respond_with(encrypt_ok(b"c"))
        .expect(3)
        .mount(&server)
        .await;
    let k = provider(&server)
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap();
    for _ in 0..3 {
        k.encrypt(b"x", b"").await.unwrap();
    }
    // A RAW_ENCRYPT_DECRYPT key is refused, naming what it is.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": KEY, "purpose": "RAW_ENCRYPT_DECRYPT",
        })))
        .mount(&server)
        .await;
    let e = provider(&server)
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    assert!(e.to_string().contains("RAW_ENCRYPT_DECRYPT"), "{e}");
}

#[tokio::test]
async fn external_keys_are_refused_for_signing() {
    let server = MockServer::start().await;
    let v = format!("{KEY}/cryptoKeyVersions/1");
    let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n";
    Mock::given(method("GET"))
        .and(path(format!("/v1/{v}/publicKey")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pem": pem, "pemCrc32c": crc(pem.as_bytes()), "name": v,
            "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "EXTERNAL",
        })))
        .mount(&server)
        .await;
    mount_enabled_version(&server, "EC_SIGN_P256_SHA256").await;
    let e = provider(&server)
        .digest_signing_key(
            format!("gcp-kms://{v}"),
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .unwrap()
        .sign_digest(&Digest::sha256(b"m"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
}

#[tokio::test]
async fn describe_pages_through_versions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": KEY, "purpose": "ENCRYPT_DECRYPT",
            "primary": {"name": format!("{KEY}/cryptoKeyVersions/2"), "state": "ENABLED",
                "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
            "versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protectionLevel": "HSM"},
            "rotationPeriod": "7776000s",
        })))
        .mount(&server)
        .await;
    let ver = |n: u64, st: &str| {
        json!({"name": format!("{KEY}/cryptoKeyVersions/{n}"), "state": st,
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protectionLevel": "HSM",
            "createTime": "2024-05-06T07:08:09.123456Z"})
    };
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}/cryptoKeyVersions")))
        .and(query_param("pageSize", "1000"))
        .and(query_param("pageToken", "p2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"cryptoKeyVersions": [ver(2, "ENABLED")]})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}/cryptoKeyVersions")))
        .and(query_param("pageSize", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"cryptoKeyVersions": [ver(1, "DISABLED")], "nextPageToken": "p2"}),
        ))
        .mount(&server)
        .await;
    let k = provider(&server)
        .aead_key(format!("gcp-kms://{KEY}"))
        .unwrap();
    let info = k.describe().await.unwrap();
    assert_eq!(info.versions().len(), 2);
    assert_eq!(info.primary_version(), Some(&KeyVersion::from_u64(2)));
    let g = k
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_gcp::GcpKeyInfo>()
        .unwrap()
        .clone();
    assert_eq!(g.rotation_period(), Some("7776000s"));
    assert_eq!(g.versions()[0].created_at(), Some(1_714_979_289));
}

#[tokio::test]
async fn local_validation_happens_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let p = provider(&server);
    let k = p.aead_key(format!("gcp-kms://{KEY}")).unwrap();
    let big = vec![0; 65537];
    assert_eq!(
        k.encrypt(&big, b"").await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        k.encrypt(b"x", &big).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    let v = format!("gcp-kms://{KEY}/cryptoKeyVersions/1");
    let s = p
        .digest_signing_key(&v, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    assert_eq!(
        s.sign_digest(&Digest::sha384(b"m"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        s.public_key_version(&KeyVersion::new("../2"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    let m = p.mac_key(&v, MacAlgorithm::HmacSha256).unwrap();
    assert_eq!(
        m.mac(&big).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    let other = Tag::from_parts(
        MacAlgorithm::HmacSha512,
        Some(KeyVersion::from_u64(1)),
        [0; 64],
    );
    assert_eq!(
        m.verify_mac(b"x", &other).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    // Opening never does I/O, whatever the credentials.
    let lazy = builder(&server)
        .credentials(Credentials::metadata_server())
        .auth_endpoints(anykms_gcp::AuthEndpoints::custom(&server.uri()).unwrap())
        .build()
        .unwrap();
    lazy.aead_key(format!("gcp-kms://{KEY}")).unwrap();
}

/// A3(c): a malformed version from input (`public_key_version`, a signature's or tag's version)
/// is `InvalidArgument` (caller class) and never a `ParseUri` error, which is `Configuration`;
/// a malformed URI from configuration is.
#[tokio::test]
async fn input_versions_never_produce_parse_uri_errors() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let p = provider(&server);
    let v = format!("gcp-kms://{KEY}/cryptoKeyVersions/1");
    let s = p
        .digest_signing_key(&v, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let m = p.mac_key(&v, MacAlgorithm::HmacSha256).unwrap();
    let d = Digest::sha256(b"m");
    for bad in [
        "",
        "0",
        "01",
        "-1",
        "abc",
        "../2",
        "1/x",
        "18446744073709551616",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        &format!("gcp-kms://{KEY}/cryptoKeyVersions/1"),
    ] {
        let kv = KeyVersion::new(bad);
        let sig = anykms_core::Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(kv.clone()),
            vec![0x30; 70],
        );
        let tag = Tag::from_parts(MacAlgorithm::HmacSha256, Some(kv.clone()), [0; 32]);
        for e in [
            s.public_key_version(&kv).await.unwrap_err(),
            s.verify_digest(&d, &sig).await.unwrap_err(),
            m.verify_mac(b"x", &tag).await.unwrap_err(),
        ] {
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{bad:?}: {e}");
            assert_ne!(e.operation(), Operation::ParseUri, "{bad:?}: {e}");
            assert!(e.is_caller_error(), "{bad:?}: {e}");
        }
    }
    let e = p
        .aead_key(format!("gcp-kms://{KEY}/cryptoKeyVersions/0"))
        .unwrap_err();
    assert_eq!(e.operation(), Operation::ParseUri);
    assert_eq!(e.kind(), ErrorKind::Configuration);
}

/// A versioned operation, for the tables below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VOp {
    EncryptAad,
    Sign,
    SignEd25519,
    Mac,
    MacVerify,
    PublicKey,
    Unwrap,
    Describe,
    MacCheck,
}

impl VOp {
    /// The HTTP method and path (after `/v1/`) of the request the operation ends with.
    fn route(self) -> (&'static str, String) {
        let v = format!("{KEY}/cryptoKeyVersions/1");
        match self {
            VOp::EncryptAad => ("POST", format!("{KEY}:encrypt")),
            VOp::Sign | VOp::SignEd25519 => ("POST", format!("{v}:asymmetricSign")),
            VOp::Mac => ("POST", format!("{v}:macSign")),
            VOp::MacVerify => ("POST", format!("{v}:macVerify")),
            VOp::PublicKey => ("GET", format!("{v}/publicKey")),
            VOp::Unwrap => ("POST", format!("{v}:asymmetricDecrypt")),
            VOp::Describe => ("GET", KEY.to_owned()),
            VOp::MacCheck => ("GET", v),
        }
    }

    /// Runs the operation (key-type checks off, except for `MacCheck`) and returns its error.
    async fn run(self, server: &MockServer) -> anykms_core::Error {
        let p = provider(server);
        let ver = format!("gcp-kms://{KEY}/cryptoKeyVersions/1");
        let t = KeyTypeCheck::TrustCaller;
        let tag = Tag::from_parts(
            MacAlgorithm::HmacSha256,
            Some(KeyVersion::from_u64(1)),
            [0; 32],
        );
        let r = match self {
            VOp::EncryptAad => aead(server).encrypt(b"x", b"ad").await.map(drop),
            VOp::Sign => p
                .digest_signing_key(&ver, SignatureAlgorithm::EcdsaP256Sha256)
                .unwrap()
                .with_key_type_check(t)
                .sign_digest(&Digest::sha256(b"m"))
                .await
                .map(drop),
            VOp::SignEd25519 => p
                .ed25519_key(&ver)
                .unwrap()
                .with_key_type_check(t)
                .sign_message(b"m")
                .await
                .map(drop),
            VOp::Mac => p
                .mac_key(&ver, MacAlgorithm::HmacSha256)
                .unwrap()
                .with_key_type_check(t)
                .mac(b"d")
                .await
                .map(drop),
            VOp::MacVerify => {
                p.mac_key(&ver, MacAlgorithm::HmacSha256)
                    .unwrap()
                    .with_key_type_check(t)
                    .verify_mac(b"d", &tag)
                    .await
            }
            VOp::PublicKey => {
                // §3.1(f): the version-state lookup before `getPublicKey` finds it enabled.
                mount_enabled_version(server, "EC_SIGN_P256_SHA256").await;
                p.digest_signing_key(&ver, SignatureAlgorithm::EcdsaP256Sha256)
                    .unwrap()
                    .public_key()
                    .await
                    .map(drop)
            }
            VOp::Unwrap => p
                .key_wrap_key(&ver)
                .unwrap()
                .with_key_type_check(t)
                .unwrap_key(&Ciphertext::from_bytes(vec![1; 256]))
                .await
                .map(drop),
            VOp::Describe => p
                .describe_key(format!("gcp-kms://{KEY}"))
                .unwrap()
                .describe()
                .await
                .map(drop),
            VOp::MacCheck => p
                .mac_key(&ver, MacAlgorithm::HmacSha256)
                .unwrap()
                .preflight()
                .await
                .map(drop),
        };
        r.expect_err("the operation must fail")
    }
}

/// Answers `cryptoKeyVersions.get` of version 1 of [`KEY`] with an enabled version of `alg`.
async fn mount_enabled_version(server: &MockServer, alg: &str) {
    mount_version_state(server, "ENABLED", alg).await;
}

async fn mount_version_state(server: &MockServer, state: &str, alg: &str) {
    let ver = format!("{KEY}/cryptoKeyVersions/1");
    Mock::given(method("GET"))
        .and(path(format!("/v1/{ver}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": ver, "state": state, "algorithm": alg, "protectionLevel": "SOFTWARE",
        })))
        .mount(server)
        .await;
}

/// Every response-integrity field and every response `name` of every operation (review §4.2):
/// a wrong or missing CRC32C, a `verified*` flag missing (it defaults to false), or a response
/// for another key is refused.
#[tokio::test]
async fn response_integrity_and_name_checks_on_every_operation() {
    use ErrorKind::{Backend, Unavailable};
    let ver = format!("{KEY}/cryptoKeyVersions/1");
    let other_key = "projects/my-project/locations/global/keyRings/r/cryptoKeys/other";
    let other_ver = format!("{other_key}/cryptoKeyVersions/1");
    let mut sig = vec![0x30u8];
    sig.resize(70, 7);
    let ed = [1u8; 64];
    let mac = [5u8; 32];
    let pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
    let dek = b"secret-data-key-0123456789abcdef";
    let cases: Vec<(VOp, Value, ErrorKind)> = vec![
        // encrypt: AAD sent, its flag missing.
        (
            VOp::EncryptAad,
            json!({"name": format!("{KEY}/cryptoKeyVersions/3"), "ciphertext": b64(b"c"),
                "ciphertextCrc32c": crc(b"c"), "verifiedPlaintextCrc32c": true}),
            Unavailable,
        ),
        // asymmetricSign (digest).
        (
            VOp::Sign,
            json!({"name": ver, "signature": b64(&sig), "signatureCrc32c": "1",
                "verifiedDigestCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::Sign,
            json!({"name": ver, "signature": b64(&sig), "verifiedDigestCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::Sign,
            json!({"name": ver, "signature": b64(&sig), "signatureCrc32c": crc(&sig)}),
            Unavailable,
        ),
        (
            VOp::Sign,
            json!({"name": ver, "signature": b64(&sig), "signatureCrc32c": crc(&sig),
                "verifiedDataCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::Sign,
            json!({"name": other_ver, "signature": b64(&sig), "signatureCrc32c": crc(&sig),
                "verifiedDigestCrc32c": true}),
            Backend,
        ),
        // asymmetricSign (data, Ed25519).
        (
            VOp::SignEd25519,
            json!({"name": ver, "signature": b64(&ed), "signatureCrc32c": crc(&ed)}),
            Unavailable,
        ),
        (
            VOp::SignEd25519,
            json!({"name": ver, "signature": b64(&ed), "signatureCrc32c": crc(&ed),
                "verifiedDigestCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::SignEd25519,
            json!({"name": ver, "signature": b64(&ed), "signatureCrc32c": "7",
                "verifiedDataCrc32c": true}),
            Unavailable,
        ),
        // macSign.
        (
            VOp::Mac,
            json!({"name": ver, "mac": b64(&mac), "macCrc32c": "1", "verifiedDataCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::Mac,
            json!({"name": ver, "mac": b64(&mac), "verifiedDataCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::Mac,
            json!({"name": ver, "mac": b64(&mac), "macCrc32c": crc(&mac)}),
            Unavailable,
        ),
        (
            VOp::Mac,
            json!({"name": other_ver, "mac": b64(&mac), "macCrc32c": crc(&mac),
                "verifiedDataCrc32c": true}),
            Backend,
        ),
        // macVerify.
        (
            VOp::MacVerify,
            json!({"name": ver, "success": true, "verifiedMacCrc32c": true,
                "verifiedSuccessIntegrity": true}),
            Unavailable,
        ),
        (
            VOp::MacVerify,
            json!({"name": ver, "success": true, "verifiedDataCrc32c": true,
                "verifiedSuccessIntegrity": true}),
            Unavailable,
        ),
        (
            VOp::MacVerify,
            json!({"name": other_ver, "success": true, "verifiedDataCrc32c": true,
                "verifiedMacCrc32c": true, "verifiedSuccessIntegrity": true}),
            Backend,
        ),
        // getPublicKey.
        (
            VOp::PublicKey,
            json!({"name": ver, "pem": pem, "pemCrc32c": "1", "algorithm": "EC_SIGN_P256_SHA256"}),
            Unavailable,
        ),
        (
            VOp::PublicKey,
            json!({"name": ver, "pem": pem, "algorithm": "EC_SIGN_P256_SHA256"}),
            Unavailable,
        ),
        (
            VOp::PublicKey,
            json!({"name": other_ver, "pem": pem, "pemCrc32c": crc(pem.as_bytes()),
                "algorithm": "EC_SIGN_P256_SHA256"}),
            Backend,
        ),
        // asymmetricDecrypt.
        (
            VOp::Unwrap,
            json!({"plaintext": b64(dek), "plaintextCrc32c": crc(dek)}),
            Unavailable,
        ),
        (
            VOp::Unwrap,
            json!({"plaintext": b64(dek), "plaintextCrc32c": "1",
                "verifiedCiphertextCrc32c": true}),
            Unavailable,
        ),
        (
            VOp::Unwrap,
            json!({"plaintext": b64(dek), "verifiedCiphertextCrc32c": true}),
            Unavailable,
        ),
        // cryptoKeys.get and cryptoKeyVersions.get naming another key.
        (
            VOp::Describe,
            json!({"name": other_key, "purpose": "ENCRYPT_DECRYPT"}),
            Backend,
        ),
        (
            VOp::MacCheck,
            json!({"name": other_ver, "state": "ENABLED", "algorithm": "HMAC_SHA256"}),
            Backend,
        ),
    ];
    for (op, body, want) in cases {
        let server = MockServer::start().await;
        let (m, p) = op.route();
        Mock::given(method(m))
            .and(path(format!("/v1/{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let e = op.run(&server).await;
        assert_eq!(e.kind(), want, "{op:?} {body}: {e}");
        assert!(e.resource().is_some(), "{op:?}: {e}");
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("secret"), "{shown}");
    }

    // A list page naming another key's version.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name": KEY, "purpose": "ENCRYPT_DECRYPT"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{KEY}/cryptoKeyVersions")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"cryptoKeyVersions": [
                {"name": other_ver, "state": "ENABLED", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}
            ]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(VOp::Describe.run(&server).await.kind(), Backend);
}

/// The version-state, not-found and permission rows of the error table on every versioned
/// operation, not only the AEAD path. A3: a version that is not enabled is `KeyStateInvalid`
/// when the handle chose it (sign, MAC, `public_key()`, RSA unwrap, the MAC key-type check) and
/// `KeyVersionUnusable` when the input did (MAC verification); a missing tag version does not
/// verify.
#[tokio::test]
async fn error_table_on_versioned_operations() {
    use ErrorKind as K;
    let ver = format!("{KEY}/cryptoKeyVersions/1");
    let disabled = status(
        400,
        "FAILED_PRECONDITION",
        &format!("{ver} is not enabled, current state is: DISABLED."),
    );
    let destroyed = status(
        400,
        "FAILED_PRECONDITION",
        &format!("{ver} is not enabled, current state is: DESTROYED."),
    );
    let missing = status(
        404,
        "NOT_FOUND",
        &format!("CryptoKeyVersion {ver} not found."),
    );
    let denied = status(
        403,
        "PERMISSION_DENIED",
        &format!(
            "Permission 'cloudkms.cryptoKeyVersions.useToSign' denied on resource '{ver}' (or it may not exist)."
        ),
    );
    for op in [
        VOp::Sign,
        VOp::SignEd25519,
        VOp::Mac,
        VOp::MacVerify,
        VOp::PublicKey,
        VOp::Unwrap,
        VOp::MacCheck,
    ] {
        let input = op == VOp::MacVerify;
        let unusable = if input {
            K::KeyVersionUnusable
        } else {
            K::KeyStateInvalid
        };
        let rows = [
            (400, &disabled, unusable),
            (400, &destroyed, unusable),
            (
                404,
                &missing,
                if input {
                    K::VerificationFailed
                } else {
                    K::NotFound
                },
            ),
            (403, &denied, K::PermissionDenied),
        ];
        for (code, body, want) in rows {
            let server = MockServer::start().await;
            let (m, p) = op.route();
            Mock::given(method(m))
                .and(path(format!("/v1/{p}")))
                .respond_with(ResponseTemplate::new(code).set_body_json(body.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let e = op.run(&server).await;
            assert_eq!(e.kind(), want, "{op:?} {code}: {e}");
            assert_eq!(
                e.resource(),
                Some(format!("gcp-kms://{ver}").as_str()),
                "{op:?}"
            );
            let d = e.detail().expect("detail");
            assert_eq!(d.http_status, Some(code));
            assert!(d.code().is_some());
        }
    }
}

/// R-34: concurrent first uses of a key, through handles opened separately from one provider,
/// share one key-type check and its result, a failure included.
#[tokio::test]
async fn concurrent_key_type_misses_share_one_read() {
    for status in [200, 503] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/{KEY}")))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({
                        "name": KEY, "purpose": "ENCRYPT_DECRYPT",
                        "versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protectionLevel": "SOFTWARE"},
                    }))
                    .set_delay(Duration::from_millis(300)),
            )
            .expect(1)
            .mount(&server)
            .await;
        post(&format!("{KEY}:encrypt"))
            .respond_with(encrypt_ok(b"c"))
            .expect(if status == 200 { 20 } else { 0 })
            .mount(&server)
            .await;
        let p = provider(&server);
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let k = p.aead_key(format!("gcp-kms://{KEY}")).unwrap();
                tokio::spawn(async move { k.encrypt(b"x", b"").await })
            })
            .collect();
        for t in tasks {
            match t.await.unwrap() {
                Ok(_) => assert_eq!(status, 200),
                Err(e) => {
                    assert_eq!(status, 503);
                    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
                    assert_eq!(e.operation(), Operation::Encrypt);
                }
            }
        }
    }
}
