//! Mock-server cases: transport and error-mapping behavior that real dev servers cannot trigger
//! on demand. Each case pins one row of the plan's error table or a security property.

use std::sync::Arc;
use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{
    Ciphertext, DataKeySpec, Digest, ErrorKind, KeyTypeCheck, KeyUri, KeyVersion, MacAlgorithm,
    Signature, SignatureAlgorithm, Tag,
};
use anykms_transit::{FileToken, Flavor, ServerConfig, TransitProvider};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn uri(name: &str) -> KeyUri {
    format!("hashivault:///transit/keys/{name}")
        .parse()
        .unwrap()
}

fn provider(server: &MockServer, flavor: Flavor) -> TransitProvider {
    provider_with(
        ServerConfig::new(server.uri(), flavor)
            .token("s.mock-token")
            .allow_loopback_http(),
    )
}

fn provider_with(cfg: ServerConfig) -> TransitProvider {
    TransitProvider::builder()
        .server("default", cfg)
        .build()
        .unwrap()
}

async fn key_type(server: &MockServer, name: &str, t: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/transit/keys/{name}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"type": t, "latest_version": 1, "keys": {"1": 1}}})),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn redirect_is_not_followed_and_token_not_leaked() {
    let target = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/v1/transit/encrypt/k", target.uri())),
        )
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    let e = k.encrypt(b"secret", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(e.is_retryable());
    // `target` verifies on drop that it received zero requests.
}

#[tokio::test]
async fn unknown_warning_fails_closed() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ciphertext": "vault:v1:AAAA"},
            "warnings": ["Endpoint ignored these unrecognized parameters: [associated_data]"]
        })))
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::OpenBao)
        .aead_key(uri("k"))
        .unwrap();
    let e = k.encrypt(b"x", b"aad").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
}

/// A server that ignores `associated_data` on the datakey endpoint (OpenBao < 2.5) answers 200
/// with an unknown-parameter warning: the data key is discarded and the call fails closed.
#[tokio::test]
async fn datakey_ignored_aad_warning_fails_closed() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/plaintext/k"))
        .and(wiremock::matchers::body_partial_json(
            json!({"bits": 256, "associated_data": "YWFk"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "plaintext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "ciphertext": "vault:v1:AAAA"
            },
            "warnings": ["Endpoint ignored these unrecognized parameters: [associated_data]"]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::OpenBao)
        .aead_key(uri("k"))
        .unwrap();
    let e = k
        .generate_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    assert!(!e.is_retryable());
}

/// `datakey/wrapped` sends exactly what `datakey/plaintext` sends (bits, base64 AAD), returns the
/// ciphertext, and is a part of the opaque AEAD handle the provider opens.
#[tokio::test]
async fn wrapped_datakey_binds_aad_on_openbao() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/wrapped/k"))
        .and(wiremock::matchers::body_json(
            json!({"bits": 256, "associated_data": "YWFk"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ciphertext": "vault:v2:AAAA", "key_version": 2}
        })))
        .expect(2)
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::OpenBao);
    let k = p.aead_key(uri("k")).unwrap();
    let ct = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap();
    assert_eq!(ct.as_bytes(), b"vault:v2:AAAA");
    let opaque =
        anykms_core::Provider::aead(&p, &uri("k"), &anykms_core::OpenOptions::new()).unwrap();
    assert!(opaque.supports_wrapped_data_keys());
    let ct = opaque
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap();
    assert_eq!(ct.as_bytes(), b"vault:v2:AAAA");
}

/// `Provider::data_keys` opens an AEAD key as a data-key source: `datakey/plaintext`, named by
/// the key's resource, with the Vault AAD refusal before any request.
#[tokio::test]
async fn data_key_sources_use_datakey_plaintext() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/plaintext/k"))
        .and(wiremock::matchers::body_json(json!({"bits": 256})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "plaintext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "ciphertext": "vault:v1:AAAA"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let reg = anykms_core::Registry::builder()
        .provider(provider(&server, Flavor::Vault))
        .build()
        .unwrap();
    let k = reg.data_keys("hashivault:///transit/keys/k").unwrap();
    assert!(k.supports_describe());
    assert_eq!(k.resource(), Some("hashivault://default/transit/keys/k"));
    let dk = k.generate_data_key(DataKeySpec::Aes256, b"").await.unwrap();
    assert_eq!(dk.ciphertext().as_bytes(), b"vault:v1:AAAA");
    let e = k
        .generate_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
}

/// Without AAD the request carries no `associated_data`, on Vault too.
#[tokio::test]
async fn wrapped_datakey_without_aad() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/wrapped/k"))
        .and(wiremock::matchers::body_json(json!({"bits": 256})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ciphertext": "vault:v1:AAAA", "key_version": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    let ct = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_eq!(ct.as_bytes(), b"vault:v1:AAAA");
}

/// Vault ignores `associated_data` on `datakey/*`: AAD is refused before any request, as for
/// plaintext data keys.
#[tokio::test]
async fn wrapped_datakey_aad_on_vault_is_refused_before_io() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    let e = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (
            ErrorKind::Unsupported,
            anykms_core::Operation::GenerateDataKey
        ),
        "{e}"
    );
    assert_eq!(e.resource(), Some("hashivault://default/transit/keys/k"));
}

/// An ignored-parameter warning (OpenBao < 2.5 ignores `associated_data`) fails closed, and a
/// malformed returned ciphertext is never handed out.
#[tokio::test]
async fn wrapped_datakey_warning_and_malformed_ciphertext_fail() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/wrapped/k"))
        .and(wiremock::matchers::body_partial_json(
            json!({"associated_data": "YWFk"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ciphertext": "vault:v1:AAAA"},
            "warnings": ["Endpoint ignored these unrecognized parameters: [associated_data]"]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/datakey/wrapped/k"))
        .and(wiremock::matchers::body_json(json!({"bits": 256})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": {"ciphertext": "AAAA"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::OpenBao)
        .aead_key(uri("k"))
        .unwrap();
    let e = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    assert!(!e.is_retryable());
    let e = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
}

#[tokio::test]
async fn throttling_parses_retry_after_http_date() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    let at = std::time::SystemTime::now() + Duration::from_secs(120);
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", httpdate::fmt_http_date(at).as_str())
                .set_body_json(json!({"errors": ["rate limit quota exceeded"]})),
        )
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled);
    let d = e.retry_after().expect("Retry-After parsed");
    assert!(
        d > Duration::from_secs(100) && d <= Duration::from_secs(120),
        "{d:?}"
    );
}

#[tokio::test]
async fn throttling_parses_retry_after_zero() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "0")
                .set_body_json(json!({"errors": ["request path \"transit/encrypt/k\": rate limit quota exceeded"]})),
        )
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::OpenBao)
        .aead_key(uri("k"))
        .unwrap();
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled);
    assert!(e.is_retryable());
    assert_eq!(e.retry_after(), Some(Duration::ZERO));
}

#[tokio::test]
async fn transient_and_unknown_500s() {
    let server = MockServer::start().await;
    key_type(&server, "a", "aes256-gcm96").await;
    key_type(&server, "b", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/a"))
        .respond_with(ResponseTemplate::new(500).set_body_json(
            json!({"errors": ["local node not active but active cluster node not found"]}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/b"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(
                json!({"errors": ["weird internal failure mentioning SECRETMARKER"]}),
            ),
        )
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::Vault);
    let e = p
        .aead_key(uri("a"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    let e = p
        .aead_key(uri("b"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    assert!(
        !format!("{e} {e:?}").contains("SECRETMARKER"),
        "unknown server messages must be redacted"
    );
}

#[tokio::test]
async fn sealed_and_namespace_errors() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"errors": ["Vault is sealed"]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/n"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"errors": ["namespace not found"]})),
        )
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::OpenBao);
    let e = p
        .aead_key(uri("k"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);
    let e = p
        .aead_key(uri("n"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
}

#[tokio::test]
async fn rejected_credentials_are_unauthenticated() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    key_type(&server, "j", "aes256-gcm96").await;
    key_type(&server, "p", "aes256-gcm96").await;
    for (name, status, msg) in [
        ("k", 401, "missing client token"),
        ("j", 403, "invalid token"),
        ("p", 403, "permission denied"),
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/v1/transit/encrypt/{name}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"errors": [msg]})))
            .mount(&server)
            .await;
    }
    let p = provider(&server, Flavor::Vault);
    let kind = async |name: &str| {
        let e = p
            .aead_key(uri(name))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err();
        assert!(e.is_config_error() && !e.is_retryable(), "{e}");
        e.kind()
    };
    assert_eq!(kind("k").await, ErrorKind::Unauthenticated);
    assert_eq!(kind("j").await, ErrorKind::Unauthenticated);
    // A plain 403 cannot be told from a policy denial.
    assert_eq!(kind("p").await, ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn malformed_and_truncated_responses_do_not_leak() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    // A decrypt response whose JSON is malformed after the plaintext field.
    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/k"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":{"plaintext":"U0VDUkVUTUFSS0VS","#),
        )
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    let e = k
        .decrypt(&Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    let text = format!("{e} {e:?}");
    assert!(
        !text.contains("U0VDUkVUTUFSS0VS") && !text.contains("SECRETMARKER"),
        "{text}"
    );
    assert!(
        std::error::Error::source(&e).is_none(),
        "parse errors on secret-bearing responses must not be attached"
    );
}

/// Ciphertexts the server returns are checked for the `vault:v<N>:` shape, like signatures and
/// HMACs, so a malformed one is never handed out (and stored) as if it could be decrypted later.
#[tokio::test]
async fn malformed_returned_ciphertexts_are_refused() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    for (endpoint, data) in [
        ("encrypt/k", json!({"ciphertext": "vault:AAAA"})),
        ("rewrap/k", json!({"ciphertext": "vault:v0:AAAA"})),
        (
            "datakey/plaintext/k",
            json!({
                "plaintext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "ciphertext": "AAAA"
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/v1/transit/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": data })))
            .mount(&server)
            .await;
    }
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    let e = k
        .rewrap(&Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()), b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    let e = k
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
}

/// The per-request timeout lives on the transport.
#[cfg(feature = "reqwest")]
#[tokio::test]
async fn slow_server_times_out() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&server)
        .await;
    let p = provider_with(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token("t")
            .allow_loopback_http()
            .http_transport(
                anykms_transit::anykms_http::ReqwestTransport::builder()
                    .require_roots(false)
                    .request_timeout(Duration::from_millis(300))
                    .build()
                    .unwrap(),
            ),
    );
    let e = p
        .aead_key(uri("k"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
    assert!(e.is_retryable());
}

#[tokio::test]
async fn local_validation_makes_zero_requests() {
    let server = MockServer::start().await;
    // Any request at all fails the test.
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::Vault);
    let k = p.aead_key(uri("k")).unwrap();
    assert_eq!(
        k.generate_data_key(DataKeySpec::Aes256, b"aad")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        k.rewrap(&Ciphertext::from_bytes(b"vault:v1:AAAA".to_vec()), b"aad")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        k.decrypt(&Ciphertext::from_bytes(b"not-transit".to_vec()), b"")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DecryptFailed
    );
    let s = p
        .digest_signing_key(uri("s"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    assert_eq!(
        s.sign_digest(&Digest::sha384(b"m"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    let unversioned =
        Signature::from_parts(SignatureAlgorithm::EcdsaP256Sha256, None, vec![1, 2, 3]);
    assert_eq!(
        s.verify_digest(&Digest::sha256(b"m"), &unversioned)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    let odd = Signature::from_parts(
        SignatureAlgorithm::EcdsaP256Sha256,
        Some(KeyVersion::new("x")),
        vec![1],
    );
    assert_eq!(
        s.verify_digest(&Digest::sha256(b"m"), &odd)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    let m = p.mac_key(uri("m"), MacAlgorithm::HmacSha256).unwrap();
    let t = Tag::from_parts(
        MacAlgorithm::HmacSha512,
        Some(KeyVersion::from(1)),
        vec![0; 64],
    );
    assert_eq!(
        m.verify_mac(b"x", &t).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}

#[tokio::test]
async fn key_type_mismatch_is_refused_before_use() {
    let server = MockServer::start().await;
    key_type(&server, "rsa", "rsa-2048").await;
    key_type(&server, "p384", "ecdsa-p384").await;
    key_type(&server, "der", "aes256-gcm96").await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/derived"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"type": "aes256-gcm96", "derived": true, "latest_version": 1}}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::Vault);
    // An RSA key would "encrypt" with RSA-OAEP: not an AEAD.
    assert_eq!(
        p.aead_key(uri("rsa"))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::KeyMismatch
    );
    // A P-384 key would happily sign a "P-256" request.
    let s = p
        .digest_signing_key(uri("p384"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    assert_eq!(
        s.sign_digest(&Digest::sha256(b"m"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::KeyMismatch
    );
    assert_eq!(
        p.mac_key(uri("der"), MacAlgorithm::HmacSha256)
            .unwrap()
            .mac(b"x")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::KeyMismatch
    );
    assert_eq!(
        p.aead_key(uri("derived"))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
}

#[tokio::test]
async fn trust_caller_skips_the_describe() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"ciphertext": "vault:v1:AAAA"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault)
        .aead_key(uri("k"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap().as_bytes(),
        b"vault:v1:AAAA"
    );
}

/// Returns "old-token" until invalidated, then "new-token" (an agent that rotated the token
/// while a request was in flight).
#[derive(Debug, Default)]
struct RotatingToken {
    rotated: std::sync::atomic::AtomicBool,
    refreshable: bool,
}

impl anykms_transit::TokenSource for RotatingToken {
    fn token(
        &self,
    ) -> anykms_core::BoxFuture<'_, anykms_core::Result<Option<anykms_transit::Token>>> {
        let t = if self.rotated.load(std::sync::atomic::Ordering::SeqCst) {
            "new-token"
        } else {
            "old-token"
        };
        Box::pin(async move { Ok(Some(anykms_transit::Token::from(t))) })
    }

    fn invalidate(&self, _rejected: &anykms_transit::Token) {
        if self.refreshable {
            self.rotated
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

async fn token_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .and(header("X-Vault-Token", "new-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"ciphertext": "vault:v2:AAAA"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .and(header("X-Vault-Token", "old-token"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn token_refresh_after_403_retries_once() {
    let server = token_server().await;
    let source = Arc::new(RotatingToken {
        refreshable: true,
        ..Default::default()
    });
    let p = provider_with(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token_source(source)
            .allow_loopback_http(),
    );
    let k = p
        .aead_key(uri("k"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap().as_bytes(),
        b"vault:v2:AAAA"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "one 403, one retry"
    );
}

#[tokio::test]
async fn unchanged_token_is_not_retried() {
    let server = token_server().await;
    let source = Arc::new(RotatingToken::default());
    let p = provider_with(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token_source(source)
            .allow_loopback_http(),
    );
    let k = p
        .aead_key(uri("k"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn file_token_is_reread_after_change() {
    let dir = std::env::temp_dir().join(format!("anykms-mock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("token");
    std::fs::write(&file, "old-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let server = token_server().await;
    let p = provider_with(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token_source(Arc::new(FileToken::new(&file)))
            .allow_loopback_http(),
    );
    let k = p
        .aead_key(uri("k"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    std::fs::write(&file, "new-token\n").unwrap();
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap().as_bytes(),
        b"vault:v2:AAAA"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A token file rewritten in place with the same size and modification time looks unchanged to
/// `FileToken`'s cache; the 403 from the server makes it re-read the file and retry once.
#[tokio::test]
async fn file_token_rewrite_keeping_mtime_is_picked_up_after_403() {
    let dir = std::env::temp_dir().join(format!("anykms-mock-mtime-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("token");
    std::fs::write(&file, "old-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    let server = token_server().await;
    let p = provider_with(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token_source(Arc::new(FileToken::new(&file)))
            .allow_loopback_http(),
    );
    let k = p
        .aead_key(uri("k"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    let before = server.received_requests().await.unwrap().len();
    std::fs::write(&file, "new-token\n").unwrap(); // same length
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap().as_bytes(),
        b"vault:v2:AAAA"
    );
    // The cached old token was sent first, rejected, and the request retried with the new one.
    assert_eq!(server.received_requests().await.unwrap().len(), before + 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn configuration_is_validated() {
    let bad = |c: ServerConfig| {
        TransitProvider::builder()
            .server("default", c)
            .build()
            .unwrap_err()
            .kind()
    };
    assert_eq!(
        bad(ServerConfig::new("http://10.0.0.1:8200", Flavor::Vault).allow_loopback_http()),
        ErrorKind::Configuration
    );
    assert_eq!(
        bad(ServerConfig::new("http://localhost:8200", Flavor::Vault).allow_loopback_http()),
        ErrorKind::Configuration
    );
    assert_eq!(
        bad(ServerConfig::new("http://127.0.0.1:8200", Flavor::Vault)),
        ErrorKind::Configuration
    );
    assert_eq!(
        bad(ServerConfig::new(
            "https://user:pw@vault:8200",
            Flavor::Vault
        )),
        ErrorKind::Configuration
    );
    assert_eq!(
        bad(ServerConfig::new("https://vault:8200/v1", Flavor::Vault)),
        ErrorKind::Configuration
    );
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new("http://127.0.0.1:1", Flavor::Vault)
                .allow_loopback_http()
                .namespace("team-a")
                .allowed_mounts(["transit"]),
        )
        .build()
        .unwrap();
    let open = |s: &str| p.aead_key(s).map(|_| ()).map_err(|e| e.kind());
    assert_eq!(open("hashivault:///transit/keys/k"), Ok(()));
    assert_eq!(
        open("openbao:///transit/keys/k"),
        Ok(()),
        "schemes are synonyms"
    );
    assert_eq!(
        open("hashivault:///other/keys/k"),
        Err(ErrorKind::Configuration)
    );
    assert_eq!(
        open("hashivault:///transit/keys/k?namespace=team-b"),
        Err(ErrorKind::Configuration)
    );
    assert_eq!(
        open("hashivault:///transit/keys/k?namespace=team-a"),
        Ok(())
    );
    assert_eq!(
        open("hashivault://nope/transit/keys/k"),
        Err(ErrorKind::Configuration)
    );
    assert!(!format!("{p:?}").contains("s.mock-token"));
}

#[tokio::test]
async fn malformed_warnings_fail_closed() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    key_type(&server, "j", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ciphertext": "vault:v1:AAAA"}, "warnings": [{"msg": "structured"}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/j"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ciphertext": "vault:v1:AAAA"}, "warnings": "not a list"
        })))
        .mount(&server)
        .await;
    // A duplicate `warnings` key fails the strict warnings parse while the handler's lenient
    // parse would accept the body: it must fail closed, not pass as warning-free.
    key_type(&server, "d", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/d"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"data":{"ciphertext":"vault:v1:AAAA"},"warnings":["ignored"],"warnings":null}"#,
            "application/json",
        ))
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::Vault);
    for k in ["k", "j", "d"] {
        let e = p
            .aead_key(uri(k))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{k}: {e}");
    }
}

/// Multi-segment mounts reach Vault Enterprise path namespaces (`team-b/transit` is the `transit`
/// mount of namespace `team-b`), so they bypass `allowed_namespaces` unless explicitly listed.
/// Reserved (system) mounts are always refused. Both are refused before any I/O.
#[tokio::test]
async fn namespace_bypass_via_mount_path_is_refused() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let open = |cfg: ServerConfig, s: &str| {
        provider_with(cfg)
            .aead_key(s)
            .map(|_| ())
            .map_err(|e| (e.kind(), e.message().to_owned()))
    };
    let base = || {
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token("s.mock-token")
            .allow_loopback_http()
            .namespace("team-a")
    };
    // No allowed_mounts: single-segment mounts (dashes included) are fine, multi-segment ones
    // are refused with a pointer to allowed_mounts.
    assert_eq!(
        open(base(), "hashivault:///transit-envelope/keys/k"),
        Ok(())
    );
    let e = open(base(), "hashivault:///team-b/transit/keys/k").unwrap_err();
    assert_eq!(e.0, ErrorKind::Configuration);
    assert!(e.1.contains("allowed_mounts"), "{}", e.1);
    // allowed_namespaces does not make a path namespace acceptable either.
    let e = open(
        base().allowed_namespaces(["team-b"]),
        "hashivault:///team-b/transit/keys/k",
    )
    .unwrap_err();
    assert_eq!(e.0, ErrorKind::Configuration);
    // An explicitly listed multi-segment mount opens.
    assert_eq!(
        open(
            base().allowed_mounts(["transit", "team-b/transit"]),
            "hashivault:///team-b/transit/keys/k"
        ),
        Ok(())
    );
    // Reserved mounts: refused by the URI parser (Configuration, A3(c)), in any position.
    for s in [
        "hashivault:///sys/keys/k",
        "hashivault:///auth/token/keys/k",
        "hashivault:///identity/keys/k",
        "hashivault:///cubbyhole/keys/k",
        "hashivault:///team-b/sys/keys/k",
    ] {
        assert_eq!(
            open(base(), s).unwrap_err().0,
            ErrorKind::Configuration,
            "{s}"
        );
    }
    // ... and cannot be listed in allowed_mounts.
    let e = TransitProvider::builder()
        .server("default", base().allowed_mounts(["sys"]))
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
}

#[tokio::test]
async fn non_standby_redirects_are_configuration() {
    let server = MockServer::start().await;
    for (name, status) in [("p301", 301), ("p308", 308), ("p302", 302)] {
        key_type(&server, name, "aes256-gcm96").await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/transit/encrypt/{name}")))
            .respond_with(
                ResponseTemplate::new(status).insert_header("Location", "https://elsewhere/"),
            )
            .mount(&server)
            .await;
    }
    let p = provider(&server, Flavor::Vault);
    for name in ["p301", "p308", "p302"] {
        let e = p
            .aead_key(uri(name))
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{name}: {e}");
        assert!(!e.is_retryable());
    }
}

// ---------------------------------------------------------------------------------------------
// anykms_core::Retry over the transit client

type SleepLog = Arc<std::sync::Mutex<Vec<Duration>>>;

/// A sleep function that records the requested delays and returns at once.
fn recording_sleep() -> (anykms_core::SleepFn, SleepLog) {
    let log = SleepLog::default();
    let l = log.clone();
    let sleep: anykms_core::SleepFn = Arc::new(move |d| {
        l.lock().unwrap().push(d);
        Box::pin(async {})
    });
    (sleep, log)
}

fn retrying(server: &MockServer, sleep: anykms_core::SleepFn) -> anykms_core::Retry<impl Aead> {
    anykms_core::RetryLayer::new(sleep)
        .wrap(provider(server, Flavor::Vault).aead_key(uri("k")).unwrap())
}

/// Answers `failures` times with `status` and `Retry-After`, then succeeds.
async fn flaky_encrypt(server: &MockServer, status: u16, retry_after: &str, failures: u64) {
    key_type(server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(status)
                .insert_header("Retry-After", retry_after)
                .set_body_json(json!({"errors": ["rate limit quota exceeded"]})),
        )
        .up_to_n_times(failures)
        .expect(failures)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"ciphertext": "vault:v1:AAAA"}})),
        )
        .mount(server)
        .await;
}

async fn encrypt_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/transit/encrypt/k")
        .count()
}

#[tokio::test]
async fn retry_honors_retry_after_floor_then_succeeds() {
    for status in [429, 503] {
        let server = MockServer::start().await;
        flaky_encrypt(&server, status, "2", 2).await;
        let (sleep, log) = recording_sleep();
        let ct = retrying(&server, sleep).encrypt(b"x", b"").await.unwrap();
        assert_eq!(ct.as_bytes(), b"vault:v1:AAAA");
        let delays = log.lock().unwrap().clone();
        assert_eq!(delays.len(), 2, "{status}: {delays:?}");
        for d in delays {
            // Retry-After is a floor; the extra spread is at most `base` (300 ms by default).
            assert!(
                d >= Duration::from_secs(2) && d <= Duration::from_millis(2300),
                "{status}: {d:?}"
            );
        }
        assert_eq!(encrypt_requests(&server).await, 3);
    }
}

#[tokio::test]
async fn retry_gives_up_throttled_when_retry_after_exceeds_cap() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "60")
                .set_body_json(json!({"errors": ["Vault is sealed"]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (sleep, log) = recording_sleep();
    let e = retrying(&server, sleep)
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled, "{e}");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(60)));
    assert!(log.lock().unwrap().is_empty(), "no sleep before giving up");
}

#[tokio::test]
async fn retry_does_not_retry_permanent_redirect() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(ResponseTemplate::new(301).insert_header("Location", "https://elsewhere/"))
        .expect(1)
        .mount(&server)
        .await;
    let (sleep, log) = recording_sleep();
    let e = retrying(&server, sleep)
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn public_key_versions_newer_than_the_node_carry_a_retry_hint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "ecdsa-p256",
            "latest_version": 2,
            "min_decryption_version": 2,
            "keys": {"2": {"name": "P-256", "public_key": "PEM"}}
        }})))
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault)
        .digest_signing_key(uri("k"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let lag = |e: &anykms_core::Error| e.retry_hint().is_some();
    // Above the node's latest version: possibly not replicated yet.
    let e = k
        .public_key_version(&KeyVersion::from_u64(3))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion);
    assert!(lag(&e));
    // A3: still the caller's, whatever the hint (a forged `kid` must not turn into a 503).
    assert_eq!(e.class(), anykms_core::ErrorClass::Caller);
    // Below the minimum decryption version: gone for good.
    let e = k
        .public_key_version(&KeyVersion::from_u64(1))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion);
    assert!(!lag(&e));
}

/// A public key the server lists below its own minimum decryption version is refused anyway.
#[tokio::test]
async fn public_keys_below_the_minimum_decryption_version_are_refused_even_if_listed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "ecdsa-p256",
            "latest_version": 2,
            "min_decryption_version": 2,
            "keys": {
                "1": {"name": "P-256", "public_key": "PEM"},
                "2": {"name": "P-256", "public_key": "PEM"}
            }
        }})))
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault)
        .digest_signing_key(uri("k"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let e = k
        .public_key_version(&KeyVersion::from_u64(1))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
}

/// Without a context, transit lists an empty public key for a derived Ed25519 key: that is the
/// usual derived-key `Unsupported`, not a missing version.
#[tokio::test]
async fn public_key_of_a_derived_key_is_unsupported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "ed25519",
            "latest_version": 1,
            "min_decryption_version": 1,
            "derived": true,
            "keys": {"1": {"name": "ed25519", "public_key": ""}}
        }})))
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault)
        .ed25519_key(uri("k"))
        .unwrap();
    let e = k.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
}

// ---------------------------------------------------------------------------------------------
// Errors name the key they are about

#[tokio::test]
async fn errors_name_the_key_and_never_secrets() {
    let server = MockServer::start().await;
    key_type(&server, "a", "aes256-gcm96").await;
    key_type(&server, "rsa", "rsa-2048").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/a"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errors": ["encryption key not found"]})),
        )
        .mount(&server)
        .await;
    let p = provider_with(
        ServerConfig::new(server.uri(), Flavor::Vault)
            .token("s.mock-token")
            .allowed_namespaces(["team-a"])
            .allow_loopback_http(),
    );
    let check = |e: &anykms_core::Error, want: &str| {
        assert_eq!(e.resource(), Some(want), "{e}");
        let shown = format!("{e}\n{e:?}");
        assert!(shown.contains(&format!("[{want}]")), "{shown}");
        assert!(
            !shown.contains("mock-token") && !shown.contains('?'),
            "{shown}"
        );
        // Named exactly once in Display and once in Debug: never double-annotated.
        assert_eq!(shown.matches("/keys/").count(), 2, "{shown}");
    };

    // Server errors: the key read of the type check (404), and the operation itself.
    let e = p
        .aead_key(uri("missing"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    check(&e, "hashivault://default/transit/keys/missing");
    // Opaque handles carry the same resource, for layers (metric labels).
    let reg = anykms_core::Registry::builder()
        .provider(p.clone())
        .build()
        .unwrap();
    let h = reg.aead(uri("missing")).unwrap();
    assert_eq!(
        h.resource(),
        Some("hashivault://default/transit/keys/missing")
    );
    let h = reg.key_wrap(uri("missing")).unwrap();
    assert_eq!(
        h.resource(),
        Some("hashivault://default/transit/keys/missing")
    );
    let e = p
        .aead_key(uri("a"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    check(&e, "hashivault://default/transit/keys/a");
    assert!(
        e.to_string()
            .starts_with("transit encrypt [hashivault://default/transit/keys/a]: not_found: "),
        "{e}"
    );

    // Locally detected: key-type mismatch, pre-I/O validation, sync ciphertext parsing.
    let e = p
        .aead_key(uri("rsa"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    check(&e, "hashivault://default/transit/keys/rsa");
    let k = p.aead_key(uri("v")).unwrap();
    let e = k
        .generate_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    check(&e, "hashivault://default/transit/keys/v");
    let e = k
        .ciphertext_version(&Ciphertext::from_bytes(b"nope".to_vec()))
        .unwrap_err();
    check(&e, "hashivault://default/transit/keys/v");
    let s = p
        .digest_signing_key(uri("s"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let e = s.sign_digest(&Digest::sha384(b"m")).await.unwrap_err();
    check(&e, "hashivault://default/transit/keys/s");

    // A namespace is shown, but not as a query string.
    let ns: KeyUri = "openbao:///transit/keys/v?namespace=team-a"
        .parse()
        .unwrap();
    let e = p
        .aead_key(&ns)
        .unwrap()
        .generate_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    check(&e, "openbao://default/transit/keys/v (namespace team-a)");

    // Open errors name the key as written; URI syntax errors are ParseUri.
    let unknown: KeyUri = "hashivault://nope/transit/keys/k?namespace=team-a"
        .parse()
        .unwrap();
    check(
        &p.aead_key(&unknown).unwrap_err(),
        "hashivault://nope/transit/keys/k",
    );
    let bad: KeyUri = "hashivault:///transit/keys/k?x=1".parse().unwrap();
    let e = p.aead_key(&bad).unwrap_err();
    assert_eq!(e.operation(), anykms_core::Operation::ParseUri, "{e}");
    // A3(c): URIs come from configuration.
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");

    // The Retry layer passes the resource through.
    let r =
        anykms_core::RetryLayer::new(recording_sleep().0).wrap(p.aead_key(uri("missing")).unwrap());
    let e = r.encrypt(b"x", b"").await.unwrap_err();
    check(&e, "hashivault://default/transit/keys/missing");
}

#[tokio::test]
async fn throttled_retry_keeps_the_resource() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "60")
                .set_body_json(json!({"errors": ["Vault is sealed"]})),
        )
        .mount(&server)
        .await;
    let e = retrying(&server, recording_sleep().0)
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Throttled, "{e}");
    assert_eq!(
        e.resource(),
        Some("hashivault://default/transit/keys/k"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------
// P1-4: only requests that addressed the handle's own key drop the cached key type

async fn requests_to(server: &MockServer, m: &str, p: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == m && r.url.path() == p)
        .count()
}

/// 100 distinct forged versions through verify, MAC verification and `public_key_version`
/// cause no extra key-type check: a version taken from input never drops the cached type, even
/// when the server answers "key not found".
#[tokio::test]
async fn forged_versions_do_not_flush_the_key_type_cache() {
    let server = MockServer::start().await;
    key_type(&server, "ec", "ecdsa-p256").await;
    key_type(&server, "mac", "hmac").await;
    for p in ["/v1/transit/verify/ec", "/v1/transit/verify/mac/sha2-256"] {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({"errors": ["signature verification key not found"]})),
            )
            .mount(&server)
            .await;
    }
    let p = provider(&server, Flavor::Vault);
    let ec = p
        .digest_signing_key(uri("ec"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let mac = p.mac_key(uri("mac"), MacAlgorithm::HmacSha256).unwrap();
    let digest = Digest::sha256(b"m");
    for v in 1000..1100 {
        let sig = Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(KeyVersion::from_u64(v)),
            vec![0x30; 70],
        );
        let e = ec.verify_digest(&digest, &sig).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
        let tag = Tag::from_parts(
            MacAlgorithm::HmacSha256,
            Some(KeyVersion::from_u64(v)),
            vec![0; 32],
        );
        let e = mac.verify_mac(b"m", &tag).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    }
    assert_eq!(requests_to(&server, "GET", "/v1/transit/keys/ec").await, 1);
    assert_eq!(requests_to(&server, "GET", "/v1/transit/keys/mac").await, 1);
    // `public_key_version` reads the key's metadata once per call (that read carries the public
    // keys), never more, and an unknown version leaves the cached type in place.
    for v in 2000..2100 {
        let e = ec
            .public_key_version(&KeyVersion::from_u64(v))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{e}");
    }
    assert_eq!(
        requests_to(&server, "GET", "/v1/transit/keys/ec").await,
        101
    );
    let sig = Signature::from_parts(
        SignatureAlgorithm::EcdsaP256Sha256,
        Some(KeyVersion::from_u64(1)),
        vec![0x30; 70],
    );
    ec.verify_digest(&digest, &sig).await.unwrap_err();
    assert_eq!(
        requests_to(&server, "GET", "/v1/transit/keys/ec").await,
        101
    );
}

/// A request that addressed the handle's own key and found it missing drops the cached type, so
/// the next operation checks the key again (it may have been recreated with another type).
#[tokio::test]
async fn a_missing_key_drops_the_cached_type() {
    let server = MockServer::start().await;
    key_type(&server, "k", "aes256-gcm96").await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errors": ["encryption key not found"]})),
        )
        .mount(&server)
        .await;
    let k = provider(&server, Flavor::Vault).aead_key(uri("k")).unwrap();
    for _ in 0..2 {
        let e = k.encrypt(b"x", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    }
    assert_eq!(requests_to(&server, "GET", "/v1/transit/keys/k").await, 2);
}

/// A3(c): a malformed version from input (`public_key_version`, a signature's or tag's version)
/// is `InvalidArgument` (caller class) before any request, never a `ParseUri` error.
#[tokio::test]
async fn input_versions_never_produce_parse_uri_errors() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let p = provider(&server, Flavor::Vault);
    let s = p
        .digest_signing_key(uri("ec"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let m = p.mac_key(uri("mac"), MacAlgorithm::HmacSha256).unwrap();
    let d = Digest::sha256(b"m");
    for bad in ["", "v1", "vault:v1", "-1", "abc", "../2", "1/x"] {
        let kv = KeyVersion::new(bad);
        let sig = Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(kv.clone()),
            vec![0x30; 70],
        );
        let tag = Tag::from_parts(MacAlgorithm::HmacSha256, Some(kv.clone()), vec![0; 32]);
        for e in [
            s.public_key_version(&kv).await.unwrap_err(),
            s.verify_digest(&d, &sig).await.unwrap_err(),
            m.verify_mac(b"x", &tag).await.unwrap_err(),
        ] {
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{bad:?}: {e}");
            assert_ne!(
                e.operation(),
                anykms_core::Operation::ParseUri,
                "{bad:?}: {e}"
            );
            assert!(e.is_caller_error(), "{bad:?}: {e}");
        }
    }
}

/// Every handle opened through a `Registry` declares the transit row of the semantics table
/// (architecture plan §3.2), the typed handles the same values, and describe handles none (the
/// key's family is unknown before its metadata is read). Opening sends no request. Transit
/// versions are not addressable in URIs, so `pin` is `Unsupported`.
#[tokio::test]
async fn semantics_through_the_registry() {
    use anykms_core::{
        DataKeyAad, DataKeySource, KeySemantics, StateScope, UnversionedVerify, Verification,
        VersionModel, VersionShape,
    };
    let server = MockServer::start().await;
    for flavor in [Flavor::Vault, Flavor::OpenBao] {
        let p = provider(&server, flavor);
        let reg = anykms_core::Registry::builder()
            .provider(p.clone())
            .build()
            .unwrap();
        let u = "hashivault:///transit/keys/k";
        let base = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric);
        let aad = match flavor {
            Flavor::Vault => DataKeyAad::Refused,
            _ => DataKeyAad::BoundOrRefused,
        };
        let aead = base
            .clone()
            .with_ciphertext_reveals_version(true)
            .with_data_keys(Some(DataKeySource::native(aad)));
        let hmac = base.clone().with_versions_listed(false);
        let p256 = SignatureAlgorithm::EcdsaP256Sha256;
        let ed = SignatureAlgorithm::Ed25519;
        assert_eq!(reg.aead(u).unwrap().semantics(), Some(&aead));
        assert_eq!(reg.data_keys(u).unwrap().semantics(), Some(&aead));
        // A KEK declares no data keys.
        let kek = aead.clone().with_data_keys(None);
        assert_eq!(reg.key_wrap(u).unwrap().semantics(), Some(&kek));
        assert_eq!(reg.digest_signer(u, p256).unwrap().semantics(), Some(&base));
        assert_eq!(
            reg.digest_verifier(u, p256).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(reg.message_signer(u, ed).unwrap().semantics(), Some(&base));
        assert_eq!(
            reg.message_verifier(u, ed).unwrap().semantics(),
            Some(&base)
        );
        assert_eq!(reg.public_keys(u, p256).unwrap().semantics(), Some(&base));
        assert_eq!(reg.public_keys(u, ed).unwrap().semantics(), Some(&base));
        let mac = reg.mac(u, MacAlgorithm::HmacSha256).unwrap();
        assert_eq!(mac.semantics(), Some(&hmac));
        assert_eq!(reg.describe(u).unwrap().semantics(), None);
        // The fields the table spells out, beyond the defaults compared above.
        assert_eq!(aead.state_scope(), StateScope::Key);
        assert_eq!(aead.unversioned_verify(), UnversionedVerify::Rejected);
        assert_eq!(aead.verification(), Verification::Backend);
        assert!(aead.primary_reported() && !aead.reports_used_primary());
        assert_eq!(aead.max_plaintext(), None);
        // Typed handles.
        let uri = uri("k");
        assert_eq!(p.aead_key(&uri).unwrap().semantics(), &aead);
        assert_eq!(p.digest_signing_key(&uri, p256).unwrap().semantics(), &base);
        assert_eq!(p.ed25519_key(&uri).unwrap().semantics(), &base);
        assert_eq!(
            p.mac_key(&uri, MacAlgorithm::HmacSha256)
                .unwrap()
                .semantics(),
            &hmac
        );
        let e = reg.pin(u, &KeyVersion::from_u64(1)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Preflight

async fn key_read(server: &MockServer, name: &str, t: &str, soft_deleted: bool) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/transit/keys/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": t, "latest_version": 1, "keys": {"1": 1}, "soft_deleted": soft_deleted
        }})))
        .mount(server)
        .await;
}

/// Preflight refuses a soft-deleted (OpenBao) key with `KeyStateInvalid` labelled `Describe`, on
/// every typed handle (under both key-type checks) and through the opaque handles.
#[tokio::test]
async fn preflight_refuses_a_soft_deleted_key() {
    use anykms_core::{OpenOptions, Operation, Provider as _};
    let server = MockServer::start().await;
    for (name, t) in [
        ("aes", "aes256-gcm96"),
        ("ec", "ecdsa-p256"),
        ("ed", "ed25519"),
        ("h", "hmac"),
    ] {
        key_read(&server, name, t, true).await;
    }
    let p = provider(&server, Flavor::OpenBao);
    let refused = |e: anykms_core::Error| {
        assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
        assert_eq!(e.operation(), Operation::Describe, "{e}");
    };
    let p256 = SignatureAlgorithm::EcdsaP256Sha256;
    for check in [KeyTypeCheck::default(), KeyTypeCheck::TrustCaller] {
        let aead = p.aead_key(uri("aes")).unwrap().with_key_type_check(check);
        refused(aead.preflight().await.unwrap_err());
        let digest = p.digest_signing_key(uri("ec"), p256).unwrap();
        refused(
            digest
                .with_key_type_check(check)
                .preflight()
                .await
                .unwrap_err(),
        );
        let ed = p.ed25519_key(uri("ed")).unwrap().with_key_type_check(check);
        refused(ed.preflight().await.unwrap_err());
        let mac = p.mac_key(uri("h"), MacAlgorithm::HmacSha256).unwrap();
        refused(
            mac.with_key_type_check(check)
                .preflight()
                .await
                .unwrap_err(),
        );
    }
    let opts = OpenOptions::default();
    refused(
        p.aead(&uri("aes"), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    refused(
        p.key_wrap(&uri("aes"), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    refused(
        p.data_keys(&uri("aes"), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );
    let signer = p.digest_signer(&uri("ec"), p256, &opts).unwrap();
    refused(signer.preflight().await.unwrap_err());
    let mac = p.mac(&uri("h"), MacAlgorithm::HmacSha256, &opts).unwrap();
    refused(mac.preflight().await.unwrap_err());
}

/// Preflight checks the key type even under `KeyTypeCheck::TrustCaller` (which only skips the
/// check before ordinary operations), labelled `Describe`; a usable key of the right type passes.
#[tokio::test]
async fn preflight_checks_the_type_under_trust_caller() {
    use anykms_core::{OpenOptions, Operation, Provider as _};
    let server = MockServer::start().await;
    key_read(&server, "h", "hmac", false).await;
    key_read(&server, "aes", "aes256-gcm96", false).await;
    let p = provider(&server, Flavor::Vault);
    let trust = KeyTypeCheck::TrustCaller;
    let mismatch = |e: anykms_core::Error| {
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
        assert_eq!(e.operation(), Operation::Describe, "{e}");
    };
    let aead = p.aead_key(uri("h")).unwrap().with_key_type_check(trust);
    mismatch(aead.preflight().await.unwrap_err());
    let mac = p.mac_key(uri("aes"), MacAlgorithm::HmacSha256).unwrap();
    mismatch(
        mac.with_key_type_check(trust)
            .preflight()
            .await
            .unwrap_err(),
    );
    let mut opts = OpenOptions::default();
    opts.key_type_check = trust;
    mismatch(
        p.aead(&uri("h"), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap_err(),
    );

    let aead = p.aead_key(uri("aes")).unwrap().with_key_type_check(trust);
    let info = aead.preflight().await.unwrap();
    assert!(
        info.backend_info::<anykms_transit::TransitKeyInfo>()
            .is_some()
    );
}

/// R-34 (review plan 3.10): concurrent first uses of a key, through handles opened separately
/// from one provider, share one metadata read and its result, a failure included.
#[tokio::test]
async fn concurrent_key_type_misses_share_one_read() {
    for status in [200, 503] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/transit/keys/k"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({"data": {"type": "aes256-gcm96", "latest_version": 1, "keys": {"1": 1}}}))
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/k"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data": {"ciphertext": "vault:v1:AAAA"}})),
            )
            .mount(&server)
            .await;
        let p = provider(&server, Flavor::Vault);
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let k = p.aead_key(uri("k")).unwrap();
                tokio::spawn(async move { k.encrypt(b"x", b"").await })
            })
            .collect();
        for t in tasks {
            match t.await.unwrap() {
                Ok(_) => assert_eq!(status, 200),
                Err(e) => {
                    assert_eq!(status, 503);
                    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
                    assert_eq!(e.operation(), anykms_core::Operation::Encrypt);
                }
            }
        }
        assert_eq!(
            requests_to(&server, "GET", "/v1/transit/keys/k").await,
            1,
            "{status}"
        );
        let encrypts = if status == 200 { 20 } else { 0 };
        assert_eq!(
            requests_to(&server, "POST", "/v1/transit/encrypt/k").await,
            encrypts
        );
    }
}

/// R-39: a typed opener's URI parse error names the key (the URI without its query string), as
/// the registry's does.
#[tokio::test]
async fn typed_open_parse_errors_name_the_uri() {
    let server = MockServer::start().await;
    let p = provider(&server, Flavor::Vault);
    for (s, want) in [
        (
            "hashivault:///transit/secrets/k?namespace=a",
            "hashivault:///transit/secrets/k",
        ),
        ("hashivault://default", "hashivault://default"),
    ] {
        let e = p.aead_key(s).unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Configuration, anykms_core::Operation::ParseUri),
            "{s}: {e}"
        );
        assert_eq!(e.resource(), Some(want), "{e}");
    }
}
