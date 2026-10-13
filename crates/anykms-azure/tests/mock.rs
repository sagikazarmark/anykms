//! Mock-server cases: every operation's request and response handling, and every row of the
//! error table (`docs/cloud/azure.md` §8), against wiremock. Each case pins one behavior.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anykms_azure::{
    AccessToken, AzureCredential, AzureOptions, AzureProvider, StaticToken, TestHost, framing,
};
use anykms_core::prelude::*;
use anykms_core::{
    BoxFuture, Ciphertext, DataKeySpec, Digest, ErrorKind, KeyState, KeyTypeCheck, KeyUri,
    KeyVersion, MacAlgorithm, OpenOptions, Preflight, Provider, Registry, Signature,
    SignatureAlgorithm,
};
use base64::Engine as _;
use serde_json::{Value, json};
use wiremock::matchers::{any, body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SCOPE: &str = "https://vault.azure.net/.default";
const V1: &str = "0123456789abcdef0123456789abcdef";
const V2: &str = "fedcba9876543210fedcba9876543210";
const OTHER_V: &str = "00000000000000000000000000000000";
const V3: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const API: &str = "2025-07-01";

/// The P-256 key of RFC 7515 A.3.
const EC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const EC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const EC_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64u(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

struct Env {
    server: MockServer,
    host: String,
}

impl Env {
    async fn new() -> Self {
        let server = MockServer::start().await;
        let host = server.address().to_string();
        Self { server, host }
    }

    fn kid(&self, name: &str, v: &str) -> String {
        format!("https://{}/keys/{name}/{v}", self.host)
    }

    fn uri(&self, name: &str) -> KeyUri {
        format!("azure-kv://{}/keys/{name}", self.host)
            .parse()
            .unwrap()
    }

    fn uri_v(&self, name: &str, v: &str) -> KeyUri {
        format!("azure-kv://{}/keys/{name}/{v}", self.host)
            .parse()
            .unwrap()
    }

    fn test_host(&self) -> TestHost {
        TestHost::loopback_http(&self.host, SCOPE)
    }

    fn provider(&self) -> AzureProvider {
        self.provider_with(StaticToken::new("tok-1"), false)
    }

    fn mhsm_provider(&self) -> AzureProvider {
        self.provider_with(StaticToken::new("tok-1"), true)
    }

    fn provider_with(&self, cred: impl AzureCredential + 'static, mhsm: bool) -> AzureProvider {
        let h = if mhsm {
            self.test_host().managed_hsm()
        } else {
            self.test_host()
        };
        AzureProvider::builder()
            .credential(cred)
            .test_host(h)
            .request_timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn ec_bundle(&self, name: &str, v: &str, ops: &[&str]) -> Value {
        json!({
            "key": {"kid": self.kid(name, v), "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "key_ops": ops},
            "attributes": {"enabled": true, "created": 1_700_000_000, "updated": 1_700_000_000, "recoveryLevel": "Recoverable+Purgeable", "recoverableDays": 90},
            "tags": {"team": "secret-tag-value"}
        })
    }

    fn rsa_bundle(&self, name: &str, v: &str, ops: &[&str]) -> Value {
        let (n, e) = rsa_ne();
        json!({
            "key": {"kid": self.kid(name, v), "kty": "RSA-HSM", "n": n, "e": e, "key_ops": ops},
            "attributes": {"enabled": true, "created": 1_700_000_000}
        })
    }

    fn oct_bundle(&self, name: &str, v: &str, ops: &[&str]) -> Value {
        json!({
            "key": {"kid": self.kid(name, v), "kty": "oct-HSM", "key_ops": ops},
            "attributes": {"enabled": true, "created": 1_700_000_000}
        })
    }

    /// Serves `GET /keys/<name>` and `GET /keys/<name>/<version>` with `bundle`, and a
    /// one-version list (at a lower priority than a test's own `/versions` mocks).
    async fn bundle(&self, name: &str, v: &str, bundle: Value) {
        for p in [format!("/keys/{name}"), format!("/keys/{name}/{v}")] {
            Mock::given(method("GET"))
                .and(path(p))
                .and(query_param("api-version", API))
                .respond_with(ResponseTemplate::new(200).set_body_json(bundle.clone()))
                .mount(&self.server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(format!("/keys/{name}/versions")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"kid": self.kid(name, v), "attributes": bundle["attributes"].clone()}]
            })))
            .with_priority(10)
            .mount(&self.server)
            .await;
    }

    async fn post(&self, p: &str, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path(p.to_owned()))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    async fn requests(&self, m: &str, p: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == m && r.url.path() == p)
            .collect()
    }
}

/// `n`, `e` (base64url) of the RSA-2048 test key in tests/data.
fn rsa_ne() -> (String, String) {
    let der = anykms_recipes::pem_to_der(include_str!("data/rsa_2048.spki.pem")).unwrap();
    let n = &der[der.len() - 5 - 256..der.len() - 5];
    (b64u(n), b64u(&[1, 0, 1]))
}

fn ec_sign(digest: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let sk = p256::ecdsa::SigningKey::from_slice(&unb64u(EC_D)).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).unwrap();
    sig.to_bytes().to_vec()
}

fn err_body(code: &str, inner: Option<&str>, message: &str) -> Value {
    match inner {
        Some(i) => {
            json!({"error": {"code": code, "message": message, "innererror": {"code": i}}})
        }
        None => json!({"error": {"code": code, "message": message}}),
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

#[tokio::test]
async fn ecdsa_sign_converts_raw_to_der_and_reads_the_version() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    let digest = Digest::sha256(b"hello");
    let raw = ec_sign(digest.as_bytes());
    Mock::given(method("POST"))
        .and(path("/keys/sig/sign"))
        .and(query_param("api-version", API))
        .and(header("authorization", "Bearer tok-1"))
        .and(body_partial_json(
            json!({"alg": "ES256", "value": b64u(digest.as_bytes())}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("sig", V1), "value": b64u(&raw)})),
        )
        .expect(1)
        .mount(&env.server)
        .await;
    let k = env
        .provider()
        .digest_signing_key(env.uri("sig"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let sig = k.sign_digest(&digest).await.unwrap();
    assert_eq!(sig.key_version().unwrap().as_str(), V1);
    assert_eq!(sig.as_bytes()[0], 0x30, "DER");
    assert_eq!(
        anykms_recipes::ecdsa_der::der_to_fixed(sig.as_bytes(), 32).unwrap(),
        raw
    );
    // The public key from the JWK verifies it locally.
    let pk = k.public_key().await.unwrap();
    assert_eq!(pk.key_version().unwrap().as_str(), V1);
    anykms_recipes::LocalVerifier::new(pk, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .verify_digest(&digest, &sig)
        .await
        .unwrap();
}

#[tokio::test]
async fn signature_sizes_and_response_kid_are_checked() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign", "verify"]))
        .await;
    let p = env.provider();
    // ECDSA r||s of the wrong size.
    env.post(
        "/keys/sig/sign",
        200,
        json!({"kid": env.kid("sig", V1), "value": b64u(&[1u8; 63])}),
    )
    .await;
    let e = p
        .digest_signing_key(env.uri("sig"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    assert!(e.resource().unwrap().starts_with("azure-kv://"), "{e}");
    // RSA signature of the wrong size for the modulus.
    env.post(
        "/keys/rsa/sign",
        200,
        json!({"kid": env.kid("rsa", V1), "value": b64u(&[1u8; 255])}),
    )
    .await;
    let e = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");

    // A response naming another key, or another host: fail closed.
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign", "verify"]))
        .await;
    env.post(
        "/keys/rsa/sign",
        200,
        json!({"kid": env.kid("other", V1), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let k = env
        .provider()
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPkcs1v15Sha256)
        .unwrap();
    let e = k.sign_digest(&Digest::sha256(b"x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    let env2 = Env::new().await;
    env2.bundle("rsa", V1, env2.rsa_bundle("rsa", V1, &["sign"]))
        .await;
    env2.post(
        "/keys/rsa/sign",
        200,
        json!({"kid": format!("https://evil.vault.azure.net/keys/rsa/{V1}"), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let e = env2
        .provider()
        .digest_signing_key(env2.uri("rsa"), SignatureAlgorithm::RsaPkcs1v15Sha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    // Undecodable success body.
    let env3 = Env::new().await;
    env3.bundle("rsa", V1, env3.rsa_bundle("rsa", V1, &["sign"]))
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/rsa/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"kid\":"))
        .mount(&env3.server)
        .await;
    let e = env3
        .provider()
        .digest_signing_key(env3.uri("rsa"), SignatureAlgorithm::RsaPkcs1v15Sha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
}

#[tokio::test]
async fn pinned_uris_and_versionless_fallback() {
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign", "verify"]))
        .await;
    // Pinned: the version is in the path; the response must name it.
    env.post(
        &format!("/keys/rsa/{V1}/sign"),
        200,
        json!({"kid": env.kid("rsa", V1), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let p = env.provider();
    let k = p
        .digest_signing_key(env.uri_v("rsa", V1), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    assert_eq!(
        k.sign_digest(&Digest::sha256(b"x"))
            .await
            .unwrap()
            .key_version()
            .unwrap()
            .as_str(),
        V1
    );

    // Unpinned, and the server refuses versionless operations (405): the current version is
    // read and named, from then on for every write of the provider.
    let env = Env::new().await;
    env.bundle("rsa", V2, env.rsa_bundle("rsa", V2, &["sign", "verify"]))
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/rsa/sign"))
        .respond_with(ResponseTemplate::new(405))
        .expect(1)
        .mount(&env.server)
        .await;
    env.post(
        &format!("/keys/rsa/{V2}/sign"),
        200,
        json!({"kid": env.kid("rsa", V2), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let p = env.provider();
    let k = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    for _ in 0..2 {
        let sig = k.sign_digest(&Digest::sha256(b"x")).await.unwrap();
        assert_eq!(sig.key_version().unwrap().as_str(), V2);
    }
    // The current version comes from the cached key bundle: one GET for the key-type check
    // and both writes, not one per write.
    assert_eq!(env.requests("GET", "/keys/rsa").await.len(), 1);
    assert_eq!(
        env.requests("POST", &format!("/keys/rsa/{V2}/sign"))
            .await
            .len(),
        2
    );

    // The cached current version is stale (the key rotated and the old version was disabled):
    // the key is read again once and the write names the new version.
    let env = Env::new().await;
    Mock::given(method("GET"))
        .and(path("/keys/rsa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(env.rsa_bundle(
            "rsa",
            V1,
            &["sign"],
        )))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&env.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/keys/rsa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(env.rsa_bundle(
            "rsa",
            V2,
            &["sign"],
        )))
        .with_priority(2)
        .mount(&env.server)
        .await;
    env.post("/keys/rsa/sign", 405, json!({})).await;
    env.post(
        &format!("/keys/rsa/{V1}/sign"),
        403,
        err_body(
            "Forbidden",
            Some("KeyDisabled"),
            "Operation sign is not allowed on a disabled key.",
        ),
    )
    .await;
    env.post(
        &format!("/keys/rsa/{V2}/sign"),
        200,
        json!({"kid": env.kid("rsa", V2), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let p = env.provider();
    let k = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    let sig = k.sign_digest(&Digest::sha256(b"x")).await.unwrap();
    assert_eq!(sig.key_version().unwrap().as_str(), V2);
    assert_eq!(env.requests("GET", "/keys/rsa").await.len(), 2);

    // The 405 is remembered per host: another host still gets versionless writes.
    let other = Env::new().await;
    other
        .bundle("rsa", V1, other.rsa_bundle("rsa", V1, &["sign"]))
        .await;
    other
        .post(
            "/keys/rsa/sign",
            200,
            json!({"kid": other.kid("rsa", V1), "value": b64u(&[1u8; 256])}),
        )
        .await;
    let both = AzureProvider::builder()
        .credential(StaticToken::new("tok-1"))
        .test_host(env.test_host())
        .test_host(other.test_host())
        .build()
        .unwrap();
    for e in [&env, &other] {
        both.digest_signing_key(e.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
            .unwrap()
            .sign_digest(&Digest::sha256(b"x"))
            .await
            .unwrap();
    }
    assert_eq!(other.requests("POST", "/keys/rsa/sign").await.len(), 1);
}

#[tokio::test]
async fn server_verify_sends_raw_rs_and_the_signature_version() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    let digest = Digest::sha256(b"m");
    let raw = ec_sign(digest.as_bytes());
    let der = anykms_recipes::ecdsa_der::fixed_to_der(&raw, 32).unwrap();
    Mock::given(method("POST"))
        .and(path(format!("/keys/sig/{V2}/verify")))
        .and(body_partial_json(json!({
            "alg": "ES256", "digest": b64u(digest.as_bytes()), "value": b64u(&raw)
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": true})))
        .expect(1)
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/sig/{V1}/verify")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": false})))
        .mount(&env.server)
        .await;
    let k = env
        .provider()
        .digest_signing_key(env.uri("sig"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let ok = Signature::from_parts(alg, Some(KeyVersion::new(V2)), der.clone());
    k.verify_digest(&digest, &ok).await.unwrap();
    let bad = Signature::from_parts(alg, Some(KeyVersion::new(V1)), der.clone());
    assert_eq!(
        k.verify_digest(&digest, &bad).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    // Local validation, before any request.
    let before = env.server.received_requests().await.unwrap().len();
    for (sig, kind) in [
        (
            Signature::from_parts(alg, None, der.clone()),
            ErrorKind::InvalidArgument,
        ),
        (
            Signature::from_parts(alg, Some(KeyVersion::new("abc")), der.clone()),
            ErrorKind::InvalidArgument,
        ),
        (
            Signature::from_parts(
                SignatureAlgorithm::EcdsaP384Sha384,
                Some(KeyVersion::new(V2)),
                der.clone(),
            ),
            ErrorKind::InvalidArgument,
        ),
        (
            Signature::from_parts(alg, Some(KeyVersion::new(V2)), vec![0x30, 0x00]),
            ErrorKind::VerificationFailed,
        ),
    ] {
        let e = k.verify_digest(&digest, &sig).await.unwrap_err();
        assert_eq!(e.kind(), kind, "{e}");
    }
    let e = k
        .verify_digest(&Digest::sha384(b"m"), &ok)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert_eq!(env.server.received_requests().await.unwrap().len(), before);
    // A pinned URI refuses another version's signature.
    let pinned = env
        .provider()
        .digest_signing_key(env.uri_v("sig", V1), alg)
        .unwrap();
    assert_eq!(
        pinned.verify_digest(&digest, &ok).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
}

#[tokio::test]
async fn local_verify_fetches_the_version_public_key_once() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    Mock::given(method("POST"))
        .and(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&env.server)
        .await;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let opts = OpenOptions::new().with_extension(AzureOptions::new().local_verify());
    let uri = env.uri("sig");
    let v = env.provider().digest_verifier(&uri, alg, &opts).unwrap();
    let digest = Digest::sha256(b"m");
    let der = anykms_recipes::ecdsa_der::fixed_to_der(&ec_sign(digest.as_bytes()), 32).unwrap();
    let sig = Signature::from_parts(alg, Some(KeyVersion::new(V1)), der);
    for _ in 0..3 {
        v.verify_digest(&digest, &sig).await.unwrap();
    }
    assert_eq!(
        env.requests("GET", &format!("/keys/sig/{V1}")).await.len(),
        1
    );
    assert_eq!(
        v.verify_digest(&Digest::sha256(b"other"), &sig)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::VerificationFailed
    );
    // A version the key does not have.
    let unknown = Signature::from_parts(alg, Some(KeyVersion::new(OTHER_V)), sig.as_bytes());
    assert_eq!(
        v.verify_digest(&digest, &unknown).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    // The registry handle reports it.
    let typed = env
        .provider()
        .digest_signing_key(env.uri("sig"), alg)
        .unwrap();
    assert!(!typed.verifies_locally());
}

#[tokio::test]
async fn public_keys_validate_versions_before_io_and_refuse_disabled_keys() {
    let env = Env::new().await;
    let mut disabled = env.rsa_bundle("rsa", V2, &["sign", "verify"]);
    disabled["attributes"]["enabled"] = json!(false);
    env.bundle("rsa", V2, disabled).await;
    let k = env
        .provider()
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    // A malformed version: InvalidArgument (never ParseUri), before any request.
    let e = k
        .public_key_version(&KeyVersion::new("../../secrets/x"))
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (
            ErrorKind::InvalidArgument,
            anykms_core::Operation::PublicKey
        )
    );
    assert!(env.server.received_requests().await.unwrap().is_empty());
    assert_eq!(
        k.public_key().await.unwrap_err().kind(),
        ErrorKind::KeyStateInvalid
    );
    assert_eq!(
        k.public_key_version(&KeyVersion::new(V2))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::KeyVersionUnusable
    );
    // A pinned URI serves its own version only, like verification: another version is
    // UnknownKeyVersion before any request.
    let env = Env::new().await;
    let k = env
        .provider()
        .digest_signing_key(env.uri_v("rsa", V1), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    let e = k
        .public_key_version(&KeyVersion::new(V2))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{e}");
    assert!(e.is_caller_error());
    assert!(env.server.received_requests().await.unwrap().is_empty());
    // A3(b): a disabled version the URI pins is the handle's choice: KeyStateInvalid (config),
    // through public_key(); the same version from input is KeyVersionUnusable (caller).
    let env = Env::new().await;
    let mut disabled = env.rsa_bundle("rsa", V2, &["sign", "verify"]);
    disabled["attributes"]["enabled"] = json!(false);
    env.bundle("rsa", V2, disabled).await;
    let k = env
        .provider()
        .digest_signing_key(env.uri_v("rsa", V2), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    let e = k.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
    assert!(e.is_config_error());
    let e = k
        .public_key_version(&KeyVersion::new(V2))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    assert!(e.is_caller_error());
    // A version from input the vault does not have: UnknownKeyVersion.
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["verify"]))
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/keys/rsa/{OTHER_V}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(err_body(
            "KeyNotFound",
            None,
            "not found",
        )))
        .mount(&env.server)
        .await;
    let k = env
        .provider()
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    let e = k
        .public_key_version(&KeyVersion::new(OTHER_V))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{e}");
    assert_eq!(e.detail().and_then(|d| d.http_status), Some(404));
    // The RSA SPKI matches the test key.
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["verify"]))
        .await;
    let pk = env
        .provider()
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap()
        .public_key()
        .await
        .unwrap();
    assert_eq!(
        pk.spki_der(),
        anykms_recipes::pem_to_der(include_str!("data/rsa_2048.spki.pem")).unwrap()
    );
    assert_eq!(
        pk.key_type(),
        anykms_core::AsymmetricKeyType::Rsa { bits: 2048 }
    );
}

#[tokio::test]
async fn key_type_check_refuses_mismatches_and_is_cached() {
    let env = Env::new().await;
    env.bundle("ec", V1, env.ec_bundle("ec", V1, &["sign", "verify"]))
        .await;
    env.bundle(
        "verifyonly",
        V1,
        env.ec_bundle("verifyonly", V1, &["verify"]),
    )
    .await;
    let mut k1 = env.ec_bundle("k1", V1, &["sign", "verify"]);
    k1["key"]["crv"] = json!("P-256K");
    env.bundle("k1", V1, k1).await;
    let (_, e) = rsa_ne();
    let small = json!({"key": {"kid": env.kid("small", V1), "kty": "RSA", "n": b64u(&[0xc5; 128]), "e": e, "key_ops": ["sign", "verify", "wrapKey", "unwrapKey"]}});
    env.bundle("small", V1, small).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&env.server)
        .await;
    let p = env.provider();
    let d = Digest::sha256(b"x");
    for (name, alg, why) in [
        ("ec", SignatureAlgorithm::RsaPssSha256, "EC as RSA"),
        ("ec", SignatureAlgorithm::EcdsaP384Sha384, "P-256 as P-384"),
        (
            "verifyonly",
            SignatureAlgorithm::EcdsaP256Sha256,
            "no sign op",
        ),
        ("k1", SignatureAlgorithm::EcdsaP256Sha256, "P-256K"),
        ("small", SignatureAlgorithm::RsaPssSha256, "RSA-1024"),
    ] {
        let sha = match alg {
            SignatureAlgorithm::EcdsaP384Sha384 => Digest::sha384(b"x"),
            _ => d,
        };
        let e = p
            .digest_signing_key(env.uri(name), alg)
            .unwrap()
            .sign_digest(&sha)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{why}: {e}");
    }
    let e = p
        .key_wrap_key(env.uri("ec"))
        .unwrap()
        .wrap_key(&[1; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
    let e = p
        .key_wrap_key(env.uri("small"))
        .unwrap()
        .wrap_key(&[1; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");

    // Cached: two operations, one key read. TrustCaller: no read at all.
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign", "verify"]))
        .await;
    env.post(
        "/keys/rsa/sign",
        200,
        json!({"kid": env.kid("rsa", V1), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let p = env.provider();
    let k = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    k.sign_digest(&d).await.unwrap();
    k.sign_digest(&d).await.unwrap();
    // A second handle of the same provider shares the cache.
    p.digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPkcs1v15Sha256)
        .unwrap()
        .sign_digest(&d)
        .await
        .unwrap();
    assert_eq!(env.requests("GET", "/keys/rsa").await.len(), 1);
    let env = Env::new().await;
    env.post(
        "/keys/rsa/sign",
        200,
        json!({"kid": env.kid("rsa", V1), "value": b64u(&[1u8; 256])}),
    )
    .await;
    let opts = OpenOptions::new().with_key_type_check(KeyTypeCheck::TrustCaller);
    let s = env
        .provider()
        .digest_signer(&env.uri("rsa"), SignatureAlgorithm::RsaPssSha256, &opts)
        .unwrap();
    s.sign_digest(&d).await.unwrap();
    assert!(env.requests("GET", "/keys/rsa").await.is_empty());
}

fn assert_describe_err(r: anykms_core::Result<anykms_core::KeyInfo>, kind: ErrorKind, why: &str) {
    let e = r.unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (kind, anykms_core::Operation::Describe),
        "{why}: {e}"
    );
}

/// COR-1, COR-6: preflight reads the key afresh, type-checks it even under TrustCaller (a KEK
/// needs `wrapKey` and `unwrapKey`; data keys need a key that can make them) and refuses a
/// disabled version in use, every error labelled `Describe`.
#[tokio::test]
async fn preflight_refuses_unusable_and_mismatched_keys() {
    let env = Env::new().await;
    let mut off = env.ec_bundle("off", V1, &["sign", "verify"]);
    off["attributes"]["enabled"] = json!(false);
    env.bundle("off", V1, off).await;
    env.bundle("wraponly", V1, env.rsa_bundle("wraponly", V1, &["wrapKey"]))
        .await;
    env.bundle("ec", V1, env.ec_bundle("ec", V1, &["sign", "verify"]))
        .await;
    env.bundle(
        "kek",
        V1,
        env.rsa_bundle("kek", V1, &["wrapKey", "unwrapKey"]),
    )
    .await;
    let p = env.provider();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    for check in [KeyTypeCheck::Describe, KeyTypeCheck::TrustCaller] {
        let opts = OpenOptions::new().with_key_type_check(check);
        // A disabled key.
        let k = p
            .digest_signing_key(env.uri("off"), alg)
            .unwrap()
            .with_key_type_check(check);
        assert_describe_err(k.preflight().await, ErrorKind::KeyStateInvalid, "typed");
        let s = p.digest_signer(&env.uri("off"), alg, &opts).unwrap();
        assert_describe_err(s.preflight().await, ErrorKind::KeyStateInvalid, "opaque");
        // A KEK whose key_ops do not allow unwrapKey.
        let k = p
            .key_wrap_key(env.uri("wraponly"))
            .unwrap()
            .with_key_type_check(check);
        assert_describe_err(k.preflight().await, ErrorKind::KeyMismatch, "kek typed");
        let k = p.key_wrap(&env.uri("wraponly"), &opts).unwrap();
        assert_describe_err(k.preflight().await, ErrorKind::KeyMismatch, "kek opaque");
        // An EC key as a KEK or a data-key source.
        let k = p.key_wrap(&env.uri("ec"), &opts).unwrap();
        assert_describe_err(k.preflight().await, ErrorKind::KeyMismatch, "ec kek");
        let k = p.data_keys(&env.uri("ec"), &opts).unwrap();
        assert_describe_err(k.preflight().await, ErrorKind::KeyMismatch, "ec data keys");
        // A good KEK passes, as a KEK and as a data-key source.
        p.key_wrap(&env.uri("kek"), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap();
        p.data_keys(&env.uri("kek"), &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap();
        // A signing key with the wrong algorithm.
        let k = p
            .digest_signing_key(env.uri("ec"), SignatureAlgorithm::RsaPssSha256)
            .unwrap()
            .with_key_type_check(check);
        assert_describe_err(k.preflight().await, ErrorKind::KeyMismatch, "EC as RSA");
    }
}

/// COR-1: the typed digest key cannot know whether it was opened to sign or to verify, so core's
/// check after the backend's preflight refuses an opaque signer of a verify-only key (no `sign`
/// in `key_ops`), while a verifier of the same key passes.
#[tokio::test]
async fn preflight_of_a_signer_needs_a_key_that_signs() {
    let env = Env::new().await;
    env.bundle("vonly", V1, env.ec_bundle("vonly", V1, &["verify"]))
        .await;
    let p = env.provider();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    for check in [KeyTypeCheck::Describe, KeyTypeCheck::TrustCaller] {
        let opts = OpenOptions::new().with_key_type_check(check);
        let s = p.digest_signer(&env.uri("vonly"), alg, &opts).unwrap();
        assert_describe_err(
            s.preflight().await,
            ErrorKind::KeyMismatch,
            "signer of a verify-only key",
        );
        p.digest_verifier(&env.uri("vonly"), alg, &opts)
            .unwrap()
            .preflight()
            .await
            .unwrap();
    }
}

/// COR-1, COR-4: a pinned handle's preflight checks the pinned version, not the current one.
#[tokio::test]
async fn preflight_of_a_pinned_uri_checks_the_pinned_version() {
    for (pinned_on, current_on) in [(false, true), (true, false)] {
        let env = Env::new().await;
        let mut v1 = env.ec_bundle("ec", V1, &["sign", "verify"]);
        v1["attributes"]["enabled"] = json!(pinned_on);
        let mut v2 = env.ec_bundle("ec", V2, &["sign", "verify"]);
        v2["attributes"]["enabled"] = json!(current_on);
        for (p, b) in [
            (format!("/keys/ec/{V1}"), &v1),
            ("/keys/ec".to_owned(), &v2),
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_json(b.clone()))
                .mount(&env.server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/keys/ec/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": [
                {"kid": env.kid("ec", V1), "attributes": v1["attributes"].clone()},
                {"kid": env.kid("ec", V2), "attributes": v2["attributes"].clone()},
            ]})))
            .mount(&env.server)
            .await;
        let k = env
            .provider()
            .digest_signing_key(env.uri_v("ec", V1), SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap();
        let r = k.preflight().await;
        if pinned_on {
            let info = r.unwrap();
            assert_eq!(info.state(), Some(&KeyState::Enabled));
            assert_eq!(info.primary_version().unwrap().as_str(), V2);
        } else {
            assert_describe_err(r, ErrorKind::KeyStateInvalid, "pinned disabled");
        }
    }
}

/// COR-6: Managed HSM data keys accept an `oct-HSM` key with encrypt and decrypt, or an RSA
/// key with wrapKey and unwrapKey; anything else fails preflight.
#[tokio::test]
async fn mhsm_data_keys_preflight_follows_the_key_type() {
    let env = Env::new().await;
    env.bundle(
        "aes",
        V1,
        env.oct_bundle("aes", V1, &["encrypt", "decrypt"]),
    )
    .await;
    env.bundle(
        "aeswrap",
        V1,
        env.oct_bundle("aeswrap", V1, &["wrapKey", "unwrapKey"]),
    )
    .await;
    env.bundle(
        "rsa",
        V1,
        env.rsa_bundle("rsa", V1, &["wrapKey", "unwrapKey"]),
    )
    .await;
    env.bundle("ec", V1, env.ec_bundle("ec", V1, &["sign", "verify"]))
        .await;
    let p = env.mhsm_provider();
    let o = OpenOptions::new();
    for ok in ["aes", "rsa"] {
        p.data_keys(&env.uri(ok), &o)
            .unwrap()
            .preflight()
            .await
            .unwrap();
    }
    for bad in ["aeswrap", "ec"] {
        let r = p.data_keys(&env.uri(bad), &o).unwrap().preflight().await;
        assert_describe_err(r, ErrorKind::KeyMismatch, bad);
    }
}

// ---------------------------------------------------------------------------------------------
// Describe

#[tokio::test]
async fn describe_pages_through_versions_on_the_same_host_only() {
    let env = Env::new().await;
    env.bundle(
        "rsa",
        V2,
        env.rsa_bundle("rsa", V2, &["wrapKey", "unwrapKey"]),
    )
    .await;
    let next = format!(
        "http://{}/keys/rsa/versions?api-version=1999-01-01&$skiptoken=page2",
        env.host
    );
    Mock::given(method("GET"))
        .and(path("/keys/rsa/versions"))
        .and(query_param("$skiptoken", "page2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{"kid": env.kid("rsa", V2), "attributes": {"enabled": true, "created": 2}}],
            "nextLink": "https://evil.example/keys/rsa/versions?x=1"
        })))
        .mount(&env.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/keys/rsa/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{"kid": env.kid("rsa", V1), "attributes": {"enabled": false, "created": 1}}],
            "nextLink": next
        })))
        .mount(&env.server)
        .await;
    let k = env.provider().key_wrap_key(env.uri("rsa")).unwrap();
    let info = k.describe().await.unwrap();
    assert_eq!(info.backend_key_type(), "RSA-HSM 2048");
    assert_eq!(info.primary_version().unwrap().as_str(), V2);
    assert_eq!(info.state(), Some(&KeyState::Enabled));
    assert!(
        info.capabilities()
            .contains(anykms_core::Capabilities::KEY_WRAP)
    );
    assert!(
        !info
            .capabilities()
            .contains(anykms_core::Capabilities::SIGN)
    );
    let vs: Vec<_> = info
        .versions()
        .iter()
        .map(|v| (v.version().as_str().to_owned(), v.state().clone()))
        .collect();
    assert_eq!(
        vs,
        [
            (V1.to_owned(), KeyState::Disabled),
            (V2.to_owned(), KeyState::Enabled)
        ]
    );
    let az = k
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_azure::AzureKeyInfo>()
        .unwrap()
        .clone();
    assert_eq!(az.versions.len(), 2);
    assert!(!az.versions_truncated);
    assert_eq!(az.vault_kind, anykms_azure::VaultKind::Vault);
    // Two pages per describe; the evil nextLink was not followed.
    let pages = env.requests("GET", "/keys/rsa/versions").await;
    assert_eq!(pages.len(), 4);
    // Every page uses the pinned api-version, never the one in the server's nextLink.
    for r in &pages {
        let versions: Vec<String> = r
            .url
            .query_pairs()
            .filter(|(k, _)| k == "api-version")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(versions, [API], "{}", r.url);
    }
}

#[tokio::test]
async fn describe_of_a_pinned_uri_reports_the_current_version_after_rotation() {
    // COR-4: the primary version is the current one (what an unversioned write uses); the state
    // is the pinned version's (the one this handle uses).
    let env = Env::new().await;
    // V1 is pinned and disabled; the key rotated to V2, which is enabled.
    let mut v1 = env.ec_bundle("ec", V1, &["sign", "verify"]);
    v1["attributes"]["enabled"] = json!(false);
    Mock::given(method("GET"))
        .and(path(format!("/keys/ec/{V1}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(v1.clone()))
        .mount(&env.server)
        .await;
    let v2 = env.ec_bundle("ec", V2, &["sign", "verify"]);
    Mock::given(method("GET"))
        .and(path("/keys/ec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(v2.clone()))
        .expect(2)
        .mount(&env.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/keys/ec/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": [
            {"kid": env.kid("ec", V1), "attributes": v1["attributes"].clone()},
            {"kid": env.kid("ec", V2), "attributes": v2["attributes"].clone()},
        ]})))
        .mount(&env.server)
        .await;
    let k = env
        .provider()
        .digest_signing_key(env.uri_v("ec", V1), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let info = k.describe().await.unwrap();
    assert_eq!(info.primary_version().unwrap().as_str(), V2);
    assert_eq!(info.state(), Some(&KeyState::Disabled));
    assert_eq!(info.versions().len(), 2);
    // The Azure view describes the pinned version and names the current one.
    let az = k
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_azure::AzureKeyInfo>()
        .unwrap()
        .clone();
    assert_eq!(az.version, V1);
    assert_eq!(az.enabled, Some(false));
    assert_eq!(az.current.as_ref().unwrap().version, V2);
    assert_eq!(az.current.as_ref().unwrap().enabled, Some(true));
}

#[tokio::test]
async fn describe_stops_after_ten_pages() {
    let env = Env::new().await;
    env.bundle("ec", V1, env.ec_bundle("ec", V1, &["sign"]))
        .await;
    let next = format!(
        "http://{}/keys/ec/versions?api-version={API}&$skiptoken=again",
        env.host
    );
    Mock::given(method("GET"))
        .and(path("/keys/ec/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{"kid": env.kid("ec", V1), "attributes": {"enabled": true}}],
            "nextLink": next
        })))
        .expect(10)
        .mount(&env.server)
        .await;
    let az = env
        .provider()
        .digest_signing_key(env.uri("ec"), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_azure::AzureKeyInfo>()
        .unwrap()
        .clone();
    assert!(az.versions_truncated);
    assert_eq!(az.versions.len(), 10);
    assert_eq!(az.tag_names, ["team"]);
}

// ---------------------------------------------------------------------------------------------
// Key wrap and data keys

#[tokio::test]
async fn rsa_wrap_frames_and_unwrap_uses_the_frame_version() {
    let env = Env::new().await;
    env.bundle(
        "kek",
        V2,
        env.rsa_bundle("kek", V2, &["wrapKey", "unwrapKey"]),
    )
    .await;
    let ct = [7u8; 256];
    Mock::given(method("POST"))
        .and(path("/keys/kek/wrapkey"))
        .and(body_partial_json(
            json!({"alg": "RSA-OAEP-256", "value": b64u(&[9u8; 32])}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("kek", V2), "value": b64u(&ct)})),
        )
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/kek/{V1}/unwrapkey")))
        .and(body_partial_json(
            json!({"alg": "RSA-OAEP-256", "value": b64u(&ct)}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("kek", V1), "value": b64u(&[9u8; 32])})),
        )
        .mount(&env.server)
        .await;
    let p = env.provider();
    let k = p.key_wrap_key(env.uri("kek")).unwrap();
    let wrapped = k.wrap_key(&[9u8; 32]).await.unwrap();
    let f = framing::parse(wrapped.as_bytes()).unwrap();
    assert_eq!(f.alg(), framing::FrameAlg::RsaOaep256);
    assert_eq!(f.version(), V2);
    assert_eq!(f.body(), &ct);
    assert_eq!(
        k.wrapped_key_version(&wrapped).unwrap().unwrap().as_str(),
        V2
    );
    // An old version's frame goes to that version.
    let old =
        Ciphertext::from_bytes(framing::encode(framing::FrameAlg::RsaOaep256, V1, &ct).unwrap());
    assert_eq!(&*k.unwrap_key(&old).await.unwrap(), &[9u8; 32]);

    // Local refusals, before any request.
    let before = env.server.received_requests().await.unwrap().len();
    assert_eq!(
        k.wrap_key(&[0u8; 191]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument,
        "above k - 66"
    );
    // A3(d): key-wrap errors name the key-wrap operations.
    let e = k.wrap_key(&[]).await.unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::InvalidArgument, anykms_core::Operation::WrapKey)
    );
    let e = k
        .unwrap_key(&Ciphertext::from_bytes(b"not a frame".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(e.operation(), anykms_core::Operation::UnwrapKey);
    for bad in [
        Ciphertext::from_bytes(b"not a frame".to_vec()),
        Ciphertext::from_bytes(
            framing::encode(framing::FrameAlg::RsaOaep256, V1, &[1; 255]).unwrap(),
        ),
        Ciphertext::from_bytes(framing::encode(framing::FrameAlg::RsaOaep256, "abc", &ct).unwrap()),
        Ciphertext::from_bytes(framing::encode_gcm(V1, &[0; 12], b"x", &[0; 16]).unwrap()),
        Ciphertext::from_bytes(framing::encode(framing::FrameAlg::A256Kw, V1, &[0; 40]).unwrap()),
    ] {
        let e = k.unwrap_key(&bad).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{e}");
    }
    assert_eq!(
        k.wrapped_key_version(&Ciphertext::from_bytes(b"x".to_vec()))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(env.server.received_requests().await.unwrap().len(), before);

    // Wrapped key of an unexpected size: Backend.
    let env = Env::new().await;
    env.bundle(
        "kek",
        V2,
        env.rsa_bundle("kek", V2, &["wrapKey", "unwrapKey"]),
    )
    .await;
    env.post(
        "/keys/kek/wrapkey",
        200,
        json!({"kid": env.kid("kek", V2), "value": b64u(&[7u8; 128])}),
    )
    .await;
    let e = env
        .provider()
        .key_wrap_key(env.uri("kek"))
        .unwrap()
        .wrap_key(&[1; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend);
}

#[tokio::test]
async fn unwrap_failures_that_depend_on_the_input_are_decrypt_failed() {
    let env = Env::new().await;
    env.bundle(
        "kek",
        V2,
        env.rsa_bundle("kek", V2, &["wrapKey", "unwrapKey"]),
    )
    .await;
    env.post(
        &format!("/keys/kek/{V1}/unwrapkey"),
        400,
        err_body("BadParameter", None, "decryption failed: secret echo"),
    )
    .await;
    env.post(
        &format!("/keys/kek/{OTHER_V}/unwrapkey"),
        404,
        err_body("KeyNotFound", None, "not found"),
    )
    .await;
    let p = env.provider();
    let k = p.key_wrap_key(env.uri("kek")).unwrap();
    for v in [V1, OTHER_V] {
        let w = Ciphertext::from_bytes(
            framing::encode(framing::FrameAlg::RsaOaep256, v, &[1; 256]).unwrap(),
        );
        let e = k.unwrap_key(&w).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{v}: {e}");
        assert!(!format!("{e:?}").contains("secret echo"));
    }
    // Under TrustCaller, a 404 is NotFound (the key may not exist).
    let opts = OpenOptions::new().with_key_type_check(KeyTypeCheck::TrustCaller);
    let k = p.key_wrap(&env.uri("kek"), &opts).unwrap();
    let w = Ciphertext::from_bytes(
        framing::encode(framing::FrameAlg::RsaOaep256, OTHER_V, &[1; 256]).unwrap(),
    );
    assert_eq!(
        k.unwrap_key(&w).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn vault_data_keys_refuse_aad_before_io_and_unwrap_with_the_kek() {
    let env = Env::new().await;
    env.bundle(
        "kek",
        V1,
        env.rsa_bundle("kek", V1, &["wrapKey", "unwrapKey"]),
    )
    .await;
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let c2 = captured.clone();
    let kid = env.kid("kek", V1);
    Mock::given(method("POST"))
        .and(path("/keys/kek/wrapkey"))
        .respond_with(move |req: &Request| {
            let v: Value = serde_json::from_slice(&req.body).unwrap();
            c2.lock()
                .unwrap()
                .push(unb64u(v["value"].as_str().unwrap()));
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": kid, "value": b64u(&[3u8; 256])}))
        })
        .mount(&env.server)
        .await;
    let p = env.provider();
    let uri = env.uri("kek");
    let dk = p.data_keys(&uri, &OpenOptions::new()).unwrap();
    let e = dk
        .generate_data_key(DataKeySpec::Aes256, b"aad")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported);
    assert!(env.requests("POST", "/keys/kek/wrapkey").await.is_empty());
    let key = dk
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_eq!(captured.lock().unwrap()[0], key.plaintext());
    let f = framing::parse(key.ciphertext().as_bytes()).unwrap();
    assert_eq!(f.version(), V1);
    // Describe through the data-keys handle.
    assert!(dk.preflight().await.is_ok());
    // No AEAD or MAC keys on vault hosts, without I/O.
    for e in [
        p.aead(&uri, &OpenOptions::new()).unwrap_err(),
        p.mac(&uri, MacAlgorithm::HmacSha256, &OpenOptions::new())
            .unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
    }
    // Message signing is not an Azure shape.
    assert_eq!(
        p.message_signer(&uri, SignatureAlgorithm::Ed25519, &OpenOptions::new())
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        p.message_signer(
            &uri,
            SignatureAlgorithm::EcdsaP256Sha256,
            &OpenOptions::new()
        )
        .unwrap_err()
        .kind(),
        ErrorKind::KeyMismatch
    );
    // A KEK opened through the registry has no rewrap: envelopes rewrap locally.
    let kek = p.key_wrap(&uri, &OpenOptions::new()).unwrap();
    assert!(!kek.supports_rewrap());
    assert!(kek.supports_describe());
}

// ---------------------------------------------------------------------------------------------
// Managed HSM (release B; facts to verify with T13)

#[tokio::test]
async fn mhsm_aes_gcm_frames_iv_and_tag() {
    let env = Env::new().await;
    env.bundle(
        "aes",
        V1,
        env.oct_bundle("aes", V1, &["encrypt", "decrypt", "wrapKey", "unwrapKey"]),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/keys/aes/encrypt"))
        .and(body_partial_json(
            json!({"alg": "A256GCM", "value": b64u(b"plain"), "aad": b64u(b"ctx")}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kid": env.kid("aes", V1), "value": b64u(b"CT"), "iv": b64u(&[1; 12]), "tag": b64u(&[2; 16])
        })))
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/aes/{V1}/decrypt")))
        .and(body_partial_json(json!({
            "alg": "A256GCM", "value": b64u(b"CT"), "iv": b64u(&[1; 12]), "tag": b64u(&[2; 16]), "aad": b64u(b"ctx")
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("aes", V1), "value": b64u(b"plain")})),
        )
        .mount(&env.server)
        .await;
    let p = env.mhsm_provider();
    let uri = env.uri("aes");
    let k = p.aead(&uri, &OpenOptions::new()).unwrap();
    let ct = k.encrypt(b"plain", b"ctx").await.unwrap();
    let f = framing::parse(ct.as_bytes()).unwrap();
    assert_eq!(f.alg(), framing::FrameAlg::A256Gcm);
    assert_eq!(
        f.gcm_parts().unwrap(),
        (&[1u8; 12][..], &b"CT"[..], &[2u8; 16][..])
    );
    assert_eq!(k.ciphertext_version(&ct).unwrap().unwrap().as_str(), V1);
    assert_eq!(&*k.decrypt(&ct, b"ctx").await.unwrap(), b"plain");
    // A wrapped key is not an AEAD ciphertext.
    let w =
        Ciphertext::from_bytes(framing::encode(framing::FrameAlg::A256Kw, V1, &[0; 40]).unwrap());
    assert_eq!(
        k.decrypt(&w, b"").await.unwrap_err().kind(),
        ErrorKind::DecryptFailed
    );
    // No rewrap; data keys emulated (AAD bound: the encrypt above needs aad = ctx).
    assert!(!k.supports_rewrap());
    assert!(k.supports_data_keys());

    // IV or tag of an unexpected size: Backend.
    let env = Env::new().await;
    env.bundle(
        "aes",
        V1,
        env.oct_bundle("aes", V1, &["encrypt", "decrypt"]),
    )
    .await;
    env.post(
        "/keys/aes/encrypt",
        200,
        json!({"kid": env.kid("aes", V1), "value": b64u(b"CT"), "iv": b64u(&[1; 16]), "tag": b64u(&[2; 16])}),
    )
    .await;
    let e = env
        .mhsm_provider()
        .aead_key(env.uri("aes"))
        .unwrap()
        .encrypt(b"p", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
}

#[tokio::test]
async fn mhsm_wrap_and_data_keys_follow_the_key_type() {
    let env = Env::new().await;
    env.bundle(
        "aes",
        V1,
        env.oct_bundle("aes", V1, &["encrypt", "decrypt", "wrapKey", "unwrapKey"]),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/keys/aes/wrapkey"))
        .and(body_partial_json(json!({"alg": "A256KW"})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("aes", V1), "value": b64u(&[5; 40])})),
        )
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/aes/encrypt"))
        .and(body_partial_json(json!({"alg": "A256GCM", "aad": b64u(b"bound")})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kid": env.kid("aes", V1), "value": b64u(&[6; 32]), "iv": b64u(&[1; 12]), "tag": b64u(&[2; 16])
        })))
        .expect(1)
        .mount(&env.server)
        .await;
    let p = env.mhsm_provider();
    let uri = env.uri("aes");
    let kek = p.key_wrap(&uri, &OpenOptions::new()).unwrap();
    let w = kek.wrap_key(&[1; 32]).await.unwrap();
    assert_eq!(
        framing::parse(w.as_bytes()).unwrap().alg(),
        framing::FrameAlg::A256Kw
    );
    assert_eq!(
        kek.wrap_key(&[1; 20]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument,
        "A256KW needs multiples of 8"
    );
    // Data keys from an AES key are AAD-bound (EmulatedDataKeys over A256GCM).
    let dk = p.data_keys(&uri, &OpenOptions::new()).unwrap();
    let key = dk
        .generate_data_key(DataKeySpec::Aes256, b"bound")
        .await
        .unwrap();
    assert_eq!(
        framing::parse(key.ciphertext().as_bytes()).unwrap().alg(),
        framing::FrameAlg::A256Gcm
    );
    let info = dk.preflight().await.unwrap();
    assert!(
        info.capabilities()
            .contains(anykms_core::Capabilities::AEAD)
    );
    // RSA keys on a Managed HSM wrap with RSA-OAEP-256.
    env.bundle(
        "rsa",
        V1,
        env.rsa_bundle("rsa", V1, &["wrapKey", "unwrapKey"]),
    )
    .await;
    env.post(
        "/keys/rsa/wrapkey",
        200,
        json!({"kid": env.kid("rsa", V1), "value": b64u(&[5; 256])}),
    )
    .await;
    let w = p
        .key_wrap_key(env.uri("rsa"))
        .unwrap()
        .wrap_key(&[1; 32])
        .await
        .unwrap();
    assert_eq!(
        framing::parse(w.as_bytes()).unwrap().alg(),
        framing::FrameAlg::RsaOaep256
    );
    let rsa_dk = p.data_keys(&env.uri("rsa"), &OpenOptions::new()).unwrap();
    assert_eq!(
        rsa_dk
            .generate_data_key(DataKeySpec::Aes256, b"aad")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    // An oct-HSM key never opens as a signer.
    let e = p
        .digest_signing_key(&uri, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
}

#[cfg(feature = "mhsm-hmac")]
#[tokio::test]
async fn mhsm_hmac_signs_the_message_and_verifies_on_the_server() {
    let env = Env::new().await;
    env.bundle("mac", V1, env.oct_bundle("mac", V1, &["sign", "verify"]))
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/mac/sign"))
        .and(body_partial_json(
            json!({"alg": "HS256", "value": b64u(b"msg")}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("mac", V1), "value": b64u(&[4; 32])})),
        )
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/mac/{V1}/verify")))
        .and(body_partial_json(
            json!({"alg": "HS256", "digest": b64u(b"msg"), "value": b64u(&[4; 32])}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": true})))
        .mount(&env.server)
        .await;
    let p = env.mhsm_provider();
    let k = p
        .mac(
            &env.uri("mac"),
            MacAlgorithm::HmacSha256,
            &OpenOptions::new(),
        )
        .unwrap();
    let tag = k.mac(b"msg").await.unwrap();
    assert_eq!(tag.key_version().unwrap().as_str(), V1);
    k.verify_mac(b"msg", &tag).await.unwrap();
    assert_eq!(
        k.mac(&vec![0; 64 * 1024 + 1]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}

// ---------------------------------------------------------------------------------------------
// Error table

async fn sign_error(status: u16, body: Value, headers: &[(&str, &str)]) -> anykms_core::Error {
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign", "verify"]))
        .await;
    let mut t = ResponseTemplate::new(status).set_body_json(body);
    for (k, v) in headers {
        t = t.insert_header(*k, *v);
    }
    Mock::given(method("POST"))
        .and(path("/keys/rsa/sign"))
        .respond_with(t)
        .mount(&env.server)
        .await;
    env.provider()
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err()
}

#[tokio::test]
async fn error_rows() {
    use ErrorKind::*;
    let rid = [("x-ms-request-id", "11111111-2222-3333-4444-555555555555")];
    let e = sign_error(
        403,
        err_body(
            "Forbidden",
            Some("ForbiddenByRbac"),
            "Caller oid=abc is not authorized",
        ),
        &rid,
    )
    .await;
    assert_eq!(e.kind(), PermissionDenied);
    let d = e.detail().unwrap();
    assert_eq!(d.code(), Some("ForbiddenByRbac"));
    assert_eq!(d.request_id(), Some("11111111-2222-3333-4444-555555555555"));
    assert_eq!(d.http_status, Some(403));
    assert!(!e.to_string().contains("oid=abc"));
    let e = sign_error(
        403,
        err_body(
            "Forbidden",
            Some("ForbiddenByFirewall"),
            "Client address 10.1.2.3",
        ),
        &[],
    )
    .await;
    assert_eq!(e.kind(), PermissionDenied);
    assert!(e.to_string().contains("network rule"));
    assert!(!format!("{e:?}").contains("10.1.2.3"));
    for (status, body, kind) in [
        (404, err_body("KeyNotFound", None, "x"), NotFound),
        (409, err_body("Conflict", None, "x"), KeyStateInvalid),
        (400, err_body("BadParameter", None, "x"), InvalidArgument),
        (413, json!({}), InvalidArgument),
        (500, json!({}), Unavailable),
        (502, json!({}), Unavailable),
        (503, json!({}), Unavailable),
        (504, json!({}), Unavailable),
        (418, json!({}), Backend),
    ] {
        let e = sign_error(status, body, &[]).await;
        assert_eq!(e.kind(), kind, "{status}: {e}");
        assert!(e.resource().is_some());
    }
    // 429 with and without Retry-After (seconds and HTTP date).
    let e = sign_error(
        429,
        err_body("Throttled", None, "x"),
        &[("Retry-After", "7")],
    )
    .await;
    assert_eq!(e.kind(), Throttled);
    assert_eq!(e.retry_after(), Some(Duration::from_secs(7)));
    let date = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(30));
    let e = sign_error(429, json!({}), &[("Retry-After", date.as_str())]).await;
    assert!(e.retry_after().unwrap() > Duration::from_secs(20));
    let e = sign_error(429, json!({}), &[]).await;
    assert_eq!((e.kind(), e.retry_after()), (Throttled, None));
    let e = sign_error(503, json!({}), &[("Retry-After", "2")]).await;
    assert_eq!(e.retry_after(), Some(Duration::from_secs(2)));
}

#[tokio::test]
async fn read_404_is_not_found_rbac_403_is_permission_denied_and_key_states_are_classified() {
    let env = Env::new().await;
    Mock::given(method("GET"))
        .and(path("/keys/gone"))
        .respond_with(ResponseTemplate::new(404).set_body_json(err_body("KeyNotFound", None, "x")))
        .mount(&env.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/keys/denied"))
        .respond_with(ResponseTemplate::new(403).set_body_json(err_body(
            "Forbidden",
            Some("ForbiddenByRbac"),
            "Caller is not authorized to perform action on resource.",
        )))
        .mount(&env.server)
        .await;
    // Key Vault reads a disabled key (200, `enabled: false`; §24.4 probe T3) but refuses to use
    // it: 403 with the inner code `KeyDisabled`.
    Mock::given(method("GET"))
        .and(path("/keys/off"))
        .respond_with(ResponseTemplate::new(403).set_body_json(err_body(
            "Forbidden",
            Some("KeyDisabled"),
            "Operation get is not allowed on a disabled key.",
        )))
        .mount(&env.server)
        .await;
    let p = env.provider();
    let e = p
        .key_wrap_key(env.uri("gone"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    let e = p
        .key_wrap_key(env.uri("denied"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    let e = p
        .key_wrap_key(env.uri("off"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
}

#[tokio::test]
async fn redirects_are_not_followed_and_no_token_leaks() {
    let target = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;
    for status in [301, 302, 307, 308] {
        let e = sign_error(
            status,
            json!({}),
            &[("Location", &format!("{}/keys/rsa/sign", target.uri()))],
        )
        .await;
        assert_eq!(e.kind(), ErrorKind::Configuration, "{status}");
    }
}

#[tokio::test]
async fn slow_server_times_out_and_oversize_responses_are_refused() {
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign"]))
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/rsa/sign"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&env.server)
        .await;
    let p = AzureProvider::builder()
        .credential(StaticToken::new("t"))
        .test_host(env.test_host())
        .request_timeout(Duration::from_millis(300))
        .max_response_bytes(64 * 1024)
        .build()
        .unwrap();
    let k = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    let e = k.sign_digest(&Digest::sha256(b"x")).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout, "{e}");
    assert!(e.is_retryable());
    let env = Env::new().await;
    Mock::given(method("GET"))
        .and(path("/keys/big"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(64 * 1024 + 1)))
        .mount(&env.server)
        .await;
    let p = AzureProvider::builder()
        .credential(StaticToken::new("t"))
        .test_host(env.test_host())
        .max_response_bytes(64 * 1024)
        .build()
        .unwrap();
    let e = p
        .key_wrap_key(env.uri("big"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "{e}");
    // Connection refused: Unavailable.
    let dead = TestHost::loopback_http("127.0.0.1:9", SCOPE);
    let p = AzureProvider::builder()
        .credential(StaticToken::new("t"))
        .test_host(dead)
        .build()
        .unwrap();
    let e = p
        .key_wrap_key("azure-kv://127.0.0.1:9/keys/k")
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
}

#[test]
fn host_allowlist_is_enforced_at_open() {
    let p = AzureProvider::builder()
        .credential(StaticToken::new("t"))
        .allowed_vaults(["prod.vault.azure.net"])
        .build()
        .unwrap();
    for (uri, kind) in [
        ("azure-kv://prod.vault.azure.net/keys/k", None),
        (
            "azure-kv://other.vault.azure.net/keys/k",
            Some(ErrorKind::Configuration),
        ),
        (
            "azure-kv://evil.example.com/keys/k",
            Some(ErrorKind::Configuration),
        ),
        (
            "azure-kv://127.0.0.1:8443/keys/k",
            Some(ErrorKind::Configuration),
        ),
        (
            "azure-kv://prod.vault.azure.net/secrets/k",
            Some(ErrorKind::Configuration),
        ),
    ] {
        let r = p.key_wrap_key(uri);
        match kind {
            None => assert!(r.is_ok(), "{uri}"),
            Some(k) => {
                let e = r.unwrap_err();
                assert_eq!(e.kind(), k, "{uri}");
                assert!(e.resource().is_some(), "{uri}");
            }
        }
    }
    // Every cloud's suffixes by default.
    let p = AzureProvider::builder()
        .credential(StaticToken::new("t"))
        .build()
        .unwrap();
    for ok in [
        "azure-kv://kv1.vault.azure.net/keys/k",
        "azure-kv://hsm1.managedhsm.azure.net/keys/k",
        "azure-kv://kv1.vault.azure.cn/keys/k",
        "azure-kv://kv1.vault.usgovcloudapi.net/keys/k",
    ] {
        assert!(p.key_wrap_key(ok).is_ok(), "{ok}");
    }
    // Builder validation.
    for b in [
        AzureProvider::builder(),
        AzureProvider::builder()
            .credential(StaticToken::new("t"))
            .allowed_vaults(["evil.example.com"]),
        AzureProvider::builder()
            .credential(StaticToken::new("t"))
            .ca_pem(b"x".to_vec()),
        AzureProvider::builder()
            .credential(StaticToken::new("t"))
            .test_host(TestHost::loopback_http("10.0.0.1:80", SCOPE)),
    ] {
        assert_eq!(b.build().unwrap_err().kind(), ErrorKind::Configuration);
    }
    // The registry routes azure-kv:// to the provider.
    let r = Registry::builder().provider(p).build().unwrap();
    assert!(r.key_wrap("azure-kv://kv1.vault.azure.net/keys/k").is_ok());
}

// ---------------------------------------------------------------------------------------------
// Tokens: refresh once on 401, scope from the host, tenant hint.

/// Hands out `token-<n>`, counting fetches and recording scopes.
#[derive(Debug, Default)]
struct Counting {
    fetches: AtomicUsize,
    scopes: std::sync::Mutex<Vec<String>>,
    tenant: Option<String>,
}

impl AzureCredential for Counting {
    fn token<'a>(&'a self, scope: &'a str) -> BoxFuture<'a, anykms_core::Result<AccessToken>> {
        let n = self.fetches.fetch_add(1, Ordering::SeqCst) + 1;
        self.scopes.lock().unwrap().push(scope.to_owned());
        Box::pin(async move { Ok(AccessToken::new(format!("token-{n}"), None)) })
    }

    fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_deref()
    }
}

#[tokio::test]
async fn a_401_refreshes_the_token_and_retries_once() {
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign"]))
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/rsa/sign"))
        .and(header("authorization", "Bearer token-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/rsa/sign"))
        .and(header("authorization", "Bearer token-2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": env.kid("rsa", V1), "value": b64u(&[1; 256])})),
        )
        .mount(&env.server)
        .await;
    // The GET of the key-type check happens with token-1 (any token is fine there).
    let cred = Arc::new(Counting::default());
    let p = env.provider_with(cred.clone(), false);
    let k = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    k.sign_digest(&Digest::sha256(b"x")).await.unwrap();
    assert_eq!(cred.fetches.load(Ordering::SeqCst), 2);
    // The scope always comes from the host policy.
    assert!(cred.scopes.lock().unwrap().iter().all(|s| s == SCOPE));
}

#[tokio::test]
async fn a_second_401_is_unauthenticated_with_a_tenant_hint() {
    let env = Env::new().await;
    Mock::given(method("GET"))
        .and(path("/keys/k"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "WWW-Authenticate",
            "Bearer authorization=\"https://login.microsoftonline.com/other-tenant\", resource=\"https://evil.example\"",
        ))
        .mount(&env.server)
        .await;
    let cred = Arc::new(Counting {
        tenant: Some("my-tenant".into()),
        ..Default::default()
    });
    let p = env.provider_with(cred.clone(), false);
    let e = p
        .key_wrap_key(env.uri("k"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated);
    assert!(e.to_string().contains("other-tenant"), "{e}");
    assert_eq!(env.requests("GET", "/keys/k").await.len(), 2, "one retry");
    // The challenge's resource never chose the scope.
    assert!(cred.scopes.lock().unwrap().iter().all(|s| s == SCOPE));
    // A static token cannot change: no retry.
    let p = env.provider();
    let before = env.requests("GET", "/keys/k").await.len();
    let e = p
        .key_wrap_key(env.uri("k"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated);
    assert!(
        !e.to_string().contains("other-tenant"),
        "no tenant configured"
    );
    assert_eq!(env.requests("GET", "/keys/k").await.len(), before + 1);
}

#[tokio::test]
async fn tokens_are_fetched_once_for_concurrent_operations() {
    let env = Env::new().await;
    env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign"]))
        .await;
    env.post(
        "/keys/rsa/sign",
        200,
        json!({"kid": env.kid("rsa", V1), "value": b64u(&[1; 256])}),
    )
    .await;
    #[derive(Debug, Default)]
    struct Slow(AtomicUsize);
    impl AzureCredential for Slow {
        fn token<'a>(&'a self, _: &'a str) -> BoxFuture<'a, anykms_core::Result<AccessToken>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(AccessToken::new(
                    "slow".to_owned(),
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                ))
            })
        }
    }
    let cred = Arc::new(Slow::default());
    let p = env.provider_with(cred.clone(), false);
    let k = p
        .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let k = k.clone();
        tasks.push(tokio::spawn(async move {
            k.sign_digest(&Digest::sha256(b"x")).await.unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(cred.0.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------------------------
// Input-version responses, undecodable success bodies, request ids.

#[tokio::test]
async fn verify_and_gcm_decrypt_failures_on_the_input_version() {
    // Verify: a 400 (malformed or wrong signature) and a 404 on the signature's version are
    // VerificationFailed; an RBAC 403 stays PermissionDenied; a disabled version
    // (403 `KeyDisabled`) is KeyVersionUnusable (the caller's version, A3).
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    env.post(
        &format!("/keys/sig/{V1}/verify"),
        400,
        err_body("BadParameter", None, "Invalid signature: secret echo"),
    )
    .await;
    env.post(
        &format!("/keys/sig/{OTHER_V}/verify"),
        404,
        err_body("KeyNotFound", None, "not found"),
    )
    .await;
    env.post(
        &format!("/keys/sig/{V2}/verify"),
        403,
        err_body("Forbidden", Some("ForbiddenByRbac"), "denied"),
    )
    .await;
    env.post(
        &format!("/keys/sig/{V3}/verify"),
        403,
        err_body(
            "Forbidden",
            Some("KeyDisabled"),
            "Operation verify is not allowed on a disabled key.",
        ),
    )
    .await;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let digest = Digest::sha256(b"m");
    let der = anykms_recipes::ecdsa_der::fixed_to_der(&ec_sign(digest.as_bytes()), 32).unwrap();
    let k = env
        .provider()
        .digest_signing_key(env.uri("sig"), alg)
        .unwrap();
    for (v, kind) in [
        (V1, ErrorKind::VerificationFailed),
        (OTHER_V, ErrorKind::VerificationFailed),
        (V2, ErrorKind::PermissionDenied),
        (V3, ErrorKind::KeyVersionUnusable),
    ] {
        let sig = Signature::from_parts(alg, Some(KeyVersion::new(v)), der.clone());
        let e = k.verify_digest(&digest, &sig).await.unwrap_err();
        assert_eq!(e.kind(), kind, "{v}: {e}");
        assert!(!format!("{e:?}").contains("secret echo"));
    }

    // Managed HSM AES-GCM decrypt: the same rows are DecryptFailed.
    let env = Env::new().await;
    env.bundle(
        "aes",
        V1,
        env.oct_bundle("aes", V1, &["encrypt", "decrypt"]),
    )
    .await;
    env.post(
        &format!("/keys/aes/{V1}/decrypt"),
        400,
        err_body("BadParameter", None, "tag mismatch"),
    )
    .await;
    env.post(
        &format!("/keys/aes/{OTHER_V}/decrypt"),
        404,
        err_body("KeyNotFound", None, "not found"),
    )
    .await;
    env.post(
        &format!("/keys/aes/{V2}/decrypt"),
        403,
        err_body("Forbidden", Some("ForbiddenByRbac"), "denied"),
    )
    .await;
    let k = env.mhsm_provider().aead_key(env.uri("aes")).unwrap();
    for (v, kind) in [
        (V1, ErrorKind::DecryptFailed),
        (OTHER_V, ErrorKind::DecryptFailed),
        (V2, ErrorKind::PermissionDenied),
    ] {
        let ct = Ciphertext::from_bytes(framing::encode_gcm(v, &[0; 12], b"ct", &[0; 16]).unwrap());
        let e = k.decrypt(&ct, b"").await.unwrap_err();
        assert_eq!(e.kind(), kind, "{v}: {e}");
    }
}

#[tokio::test]
async fn undecodable_success_bodies_are_backend() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    env.bundle(
        "kek",
        V1,
        env.rsa_bundle("kek", V1, &["wrapKey", "unwrapKey"]),
    )
    .await;
    let truncated = |p: String| {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"kid": "https://"#))
    };
    truncated("/keys/sig/sign".to_owned())
        .mount(&env.server)
        .await;
    truncated(format!("/keys/sig/{V1}/verify"))
        .mount(&env.server)
        .await;
    env.post(
        &format!("/keys/kek/{V1}/unwrapkey"),
        200,
        json!({"kid": env.kid("kek", V1), "value": 5}),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/keys/broken"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&env.server)
        .await;
    let p = env.provider();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let digest = Digest::sha256(b"m");
    let k = p.digest_signing_key(env.uri("sig"), alg).unwrap();
    let e = k.sign_digest(&digest).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "sign: {e}");
    let der = anykms_recipes::ecdsa_der::fixed_to_der(&ec_sign(digest.as_bytes()), 32).unwrap();
    let sig = Signature::from_parts(alg, Some(KeyVersion::new(V1)), der);
    let e = k.verify_digest(&digest, &sig).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "verify: {e}");
    let w = Ciphertext::from_bytes(
        framing::encode(framing::FrameAlg::RsaOaep256, V1, &[1; 256]).unwrap(),
    );
    let e = p
        .key_wrap_key(env.uri("kek"))
        .unwrap()
        .unwrap_key(&w)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "unwrap: {e}");
    let e = p
        .key_wrap_key(env.uri("broken"))
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend, "describe: {e}");
}

#[tokio::test]
async fn request_ids_are_kept_only_when_plausible() {
    for (id, kept) in [
        ("3f1c2a9e-0000-4c1b-9d7e-1234567890ab", true),
        ("has spaces", false),
        (&*"x".repeat(129), false),
    ] {
        let env = Env::new().await;
        env.bundle("rsa", V1, env.rsa_bundle("rsa", V1, &["sign"]))
            .await;
        Mock::given(method("POST"))
            .and(path("/keys/rsa/sign"))
            .respond_with(ResponseTemplate::new(503).insert_header("x-ms-request-id", id))
            .mount(&env.server)
            .await;
        let e = env
            .provider()
            .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
            .unwrap()
            .sign_digest(&Digest::sha256(b"x"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        let got = e.detail().unwrap().request_id();
        assert_eq!(got, kept.then_some(id), "{id}");
    }
}

// ---------------------------------------------------------------------------------------------
// Caches (P1-4, P1-13)

/// P1-4: versions from input never drop the cached key bundle. 100 forged versions through
/// server-side verify and `public_key_version` cause no extra key read; a `NotFound` for a
/// request of the handle's own key (a versionless sign) does.
#[tokio::test]
async fn forged_versions_never_drop_the_cached_bundle() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    env.post(
        "/keys/sig/sign",
        404,
        err_body(
            "KeyNotFound",
            None,
            "A key with (name/id) sig was not found",
        ),
    )
    .await;
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let k = env
        .provider()
        .digest_signing_key(env.uri("sig"), alg)
        .unwrap();
    k.preflight().await.unwrap();
    let reads = || async { env.requests("GET", "/keys/sig").await.len() };
    // Preflight reads the bundle once, fresh, and caches it for the key-type check.
    let base = reads().await;
    assert_eq!(base, 1);
    let digest = Digest::sha256(b"m");
    let der = anykms_recipes::ecdsa_der::fixed_to_der(&ec_sign(digest.as_bytes()), 32).unwrap();
    for i in 0..100u32 {
        let forged = KeyVersion::new(format!("{:032x}", 0xf000_0000u64 + u64::from(i)));
        let sig = Signature::from_parts(alg, Some(forged.clone()), der.clone());
        assert!(k.verify_digest(&digest, &sig).await.is_err());
        assert!(k.public_key_version(&forged).await.is_err());
    }
    assert_eq!(
        reads().await,
        base,
        "a version from input dropped the cached bundle"
    );
    // The handle's own key is gone: the bundle is read again.
    assert_eq!(
        k.sign_digest(&digest).await.unwrap_err().kind(),
        ErrorKind::NotFound
    );
    // Preflight reads it again (fresh, as always).
    k.preflight().await.unwrap();
    assert_eq!(reads().await, base + 1);
}

/// R-34: concurrent first uses of a key, through handles opened separately from one provider,
/// share one key read and its result, a failure included.
#[tokio::test]
async fn concurrent_bundle_misses_share_one_read() {
    for status in [200, 500] {
        let env = Env::new().await;
        let body = if status == 200 {
            env.rsa_bundle("rsa", V1, &["sign"])
        } else {
            err_body("InternalServerError", None, "boom")
        };
        Mock::given(method("GET"))
            .and(path("/keys/rsa"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(body)
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&env.server)
            .await;
        env.post(
            "/keys/rsa/sign",
            200,
            json!({"kid": env.kid("rsa", V1), "value": b64u(&[1; 256])}),
        )
        .await;
        let p = env.provider();
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let k = p
                    .digest_signing_key(env.uri("rsa"), SignatureAlgorithm::RsaPssSha256)
                    .unwrap();
                tokio::spawn(async move { k.sign_digest(&Digest::sha256(b"x")).await })
            })
            .collect();
        for t in tasks {
            match t.await.unwrap() {
                Ok(_) => assert_eq!(status, 200),
                Err(e) => {
                    assert_eq!(status, 500);
                    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
                    assert_eq!(e.operation(), anykms_core::Operation::Sign);
                }
            }
        }
        assert_eq!(env.requests("GET", "/keys/rsa").await.len(), 1, "{status}");
        let signs = if status == 200 { 20 } else { 0 };
        assert_eq!(env.requests("POST", "/keys/rsa/sign").await.len(), signs);
    }
}

/// P1-13: a local verifier trusts a version's public key for `key_cache_ttl` (jittered) from
/// its fetch, remembers unknown versions for the same time, and fails closed when the re-read
/// fails.
#[tokio::test]
async fn local_verifier_keys_expire_and_unknown_versions_are_remembered() {
    let env = Env::new().await;
    env.bundle("sig", V1, env.ec_bundle("sig", V1, &["sign", "verify"]))
        .await;
    let ttl = Duration::from_millis(400);
    let p = AzureProvider::builder()
        .credential(StaticToken::new("tok-1"))
        .test_host(env.test_host())
        .key_cache_ttl(ttl)
        .build()
        .unwrap();
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let opts = OpenOptions::new().with_extension(AzureOptions::new().local_verify());
    let v = p.digest_verifier(&env.uri("sig"), alg, &opts).unwrap();
    let digest = Digest::sha256(b"m");
    let der = anykms_recipes::ecdsa_der::fixed_to_der(&ec_sign(digest.as_bytes()), 32).unwrap();
    let sig = Signature::from_parts(alg, Some(KeyVersion::new(V1)), der.clone());
    let reads = |v: String| {
        let env = &env;
        async move { env.requests("GET", &format!("/keys/sig/{v}")).await.len() }
    };

    // Forged versions: one read each, then remembered.
    let forged: Vec<String> = (0..32u64).map(|i| format!("{:032x}", 0xe000 + i)).collect();
    for _ in 0..2 {
        for f in &forged {
            let s = Signature::from_parts(alg, Some(KeyVersion::new(f.as_str())), der.clone());
            assert_eq!(
                v.verify_digest(&digest, &s).await.unwrap_err().kind(),
                ErrorKind::VerificationFailed
            );
        }
    }
    for f in &forged {
        assert_eq!(reads(f.clone()).await, 1, "{f}");
    }

    v.verify_digest(&digest, &sig).await.unwrap();
    v.verify_digest(&digest, &sig).await.unwrap();
    assert_eq!(reads(V1.to_owned()).await, 1);
    // Expired: read again.
    tokio::time::sleep(ttl.mul_f64(1.2)).await;
    v.verify_digest(&digest, &sig).await.unwrap();
    assert_eq!(reads(V1.to_owned()).await, 2);
    // The version is disabled: once the entry expires, verification fails with the re-read's
    // error, and keeps failing with the same kind; the refusal is remembered for the TTL like
    // an unknown version (SEC-3: one read, not one per verify).
    let mut disabled = env.ec_bundle("sig", V1, &["sign", "verify"]);
    disabled["attributes"]["enabled"] = json!(false);
    Mock::given(method("GET"))
        .and(path(format!("/keys/sig/{V1}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(disabled))
        .with_priority(1)
        .mount(&env.server)
        .await;
    tokio::time::sleep(ttl.mul_f64(1.2)).await;
    for _ in 0..2 {
        let e = v.verify_digest(&digest, &sig).await.unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (
                ErrorKind::KeyVersionUnusable,
                anykms_core::Operation::Verify
            )
        );
    }
    assert_eq!(reads(V1.to_owned()).await, 3);
    // Once the refusal expires, the version is read again.
    tokio::time::sleep(ttl.mul_f64(1.2)).await;
    assert_eq!(
        v.verify_digest(&digest, &sig).await.unwrap_err().kind(),
        ErrorKind::KeyVersionUnusable
    );
    assert_eq!(reads(V1.to_owned()).await, 4);
}
