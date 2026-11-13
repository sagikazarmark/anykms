//! Alias URIs follow `UpdateAlias` (review finding M1): every handle opened on an alias adopts
//! the newest target it learns, from its own `DescribeKey`, a response's `KeyId`, or metadata
//! another handle on the same provider fetched; a stale cached target never overrides a newer
//! one.

mod support;

use std::time::Duration;

use anykms_core::{
    Digest, DigestSigner, DigestVerifier, ErrorKind, KeyTypeCheck, KeyVersion, KeyWrap, Preflight,
    PublicKeys, Signature, SignatureAlgorithm,
};
use serde_json::json;
use support::*;
use wiremock::matchers::{body_partial_json, header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALG: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;
const RSA_META: &str = "RSAES_OAEP_SHA_256";

fn sig(k: &str) -> Signature {
    Signature::from_parts(ALG, Some(KeyVersion::new(k)), b"sig".to_vec())
}

fn digest() -> Digest {
    Digest::sha256(b"m")
}

async fn rsa_alias_to(server: &MockServer, target: &str) {
    describe(
        server,
        ALIAS,
        "RSA_2048",
        "ENCRYPT_DECRYPT",
        json!({"Arn": target, "EncryptionAlgorithms": [RSA_META]}),
    )
    .await;
    for k in [RSA_WRAP, OTHER] {
        on(
            server,
            "GetPublicKey",
            Some(json!({"KeyId": k})),
            200,
            json!({"KeyId": k, "PublicKey": RSA_SPKI_B64, "KeySpec": "RSA_2048",
                   "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": [RSA_META]}),
        )
        .await;
    }
}

/// An EC signing alias naming `target`; `Verify` accepts anything, `DescribeKey` of the alias
/// answers after `delay`.
async fn ec_alias_to(server: &MockServer, target: &str, delay: Duration) {
    let meta = json!({
        "Arn": target, "KeyId": target.rsplit('/').next().unwrap(), "AWSAccountId": ACCOUNT,
        "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled",
        "CreationDate": 1_700_000_000.123, "SigningAlgorithms": ["ECDSA_SHA_256"],
    });
    Mock::given(method("POST"))
        .and(header("x-amz-target", "TrentService.DescribeKey"))
        .and(body_partial_json(json!({"KeyId": ALIAS})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(json!({"KeyMetadata": meta})),
        )
        .mount(server)
        .await;
    for k in [EC, OTHER] {
        describe(
            server,
            k,
            "ECC_NIST_P256",
            "SIGN_VERIFY",
            json!({"SigningAlgorithms": ["ECDSA_SHA_256"]}),
        )
        .await;
        on(
            server,
            "GetPublicKey",
            Some(json!({"KeyId": k})),
            200,
            json!({"KeyId": k, "PublicKey": b64(b"spki"), "KeySpec": "ECC_NIST_P256",
                   "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["ECDSA_SHA_256"]}),
        )
        .await;
    }
    on(
        server,
        "Verify",
        None,
        200,
        json!({"KeyId": target, "SignatureValid": true}),
    )
    .await;
}

/// The RSA wrap uses the public key of the target whose state it just checked, so a repoint
/// another handle observed reaches this handle's wraps.
#[tokio::test]
async fn rsa_wrap_follows_a_repoint_another_handle_observed() {
    let server = MockServer::start().await;
    rsa_alias_to(&server, RSA_WRAP).await;
    let p = provider(&server);
    let kek = p.key_wrap_key(uri(ALIAS)).unwrap();
    let probe = p.key_wrap_key(uri(ALIAS)).unwrap();

    kek.wrap_key(&[1u8; 32]).await.unwrap();
    let gpk = bodies(&server, "GetPublicKey").await;
    assert_eq!(gpk.len(), 1);
    assert_eq!(gpk[0]["KeyId"], RSA_WRAP);

    server.reset().await;
    rsa_alias_to(&server, OTHER).await;
    probe.preflight().await.unwrap(); // refreshes the shared metadata: the alias names OTHER

    kek.wrap_key(&[2u8; 32]).await.unwrap();
    let gpk = bodies(&server, "GetPublicKey").await;
    assert_eq!(
        gpk.len(),
        1,
        "the wrap must fetch the new target's public key"
    );
    assert_eq!(gpk[0]["KeyId"], OTHER);
}

/// A verifier adopts the target another handle described: the new key's signatures verify, the
/// old key's are refused before any request.
#[tokio::test]
async fn verifier_follows_a_repoint_another_handle_observed() {
    let server = MockServer::start().await;
    ec_alias_to(&server, EC, Duration::ZERO).await;
    let p = provider(&server);
    let verifier = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    let jwks = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    verifier.verify_digest(&digest(), &sig(EC)).await.unwrap();

    server.reset().await;
    ec_alias_to(&server, OTHER, Duration::ZERO).await;
    let pk = jwks.public_key().await.unwrap();
    assert_eq!(pk.key_version().unwrap().as_str(), OTHER);

    verifier
        .verify_digest(&digest(), &sig(OTHER))
        .await
        .unwrap();
    let old = verifier
        .verify_digest(&digest(), &sig(EC))
        .await
        .unwrap_err();
    assert_eq!(old.kind(), ErrorKind::VerificationFailed);
    let verify = bodies(&server, "Verify").await;
    assert_eq!(verify.len(), 1);
    assert_eq!(verify[0]["KeyId"], OTHER);
}

/// Two handles whose cache misses share one `DescribeKey`: the follower adopts the result too,
/// not only the handle that sent it.
#[tokio::test]
async fn shared_describe_flight_updates_every_handle() {
    let server = MockServer::start().await;
    ec_alias_to(&server, EC, Duration::ZERO).await;
    let p = provider(&server);
    let h1 = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    let h2 = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    h1.verify_digest(&digest(), &sig(EC)).await.unwrap();
    h2.verify_digest(&digest(), &sig(EC)).await.unwrap();

    // Repoint; a disabled-key refusal for the handle's own key drops the shared metadata, so
    // both handles miss together.
    server.reset().await;
    ec_alias_to(&server, OTHER, Duration::from_millis(300)).await;
    on(
        &server,
        "Sign",
        None,
        400,
        json!({"__type": "DisabledException"}),
    )
    .await;
    let e = h1.sign_digest(&digest()).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);

    let (d, s) = (digest(), sig(OTHER));
    let (a, b) = tokio::join!(h1.verify_digest(&d, &s), h2.verify_digest(&d, &s));
    assert_eq!(
        bodies(&server, "DescribeKey").await.len(),
        1,
        "one shared DescribeKey"
    );
    a.unwrap();
    b.unwrap();
}

/// A handle used only through `public_key_version` (a JWKS lookup by `kid`) follows a repoint.
#[tokio::test]
async fn public_key_version_follows_a_repoint() {
    let server = MockServer::start().await;
    ec_alias_to(&server, EC, Duration::ZERO).await;
    let p = provider(&server);
    let lookup = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    let probe = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    lookup
        .public_key_version(&KeyVersion::new(EC))
        .await
        .unwrap();

    server.reset().await;
    ec_alias_to(&server, OTHER, Duration::ZERO).await;
    probe.preflight().await.unwrap();

    let pk = lookup
        .public_key_version(&KeyVersion::new(OTHER))
        .await
        .unwrap();
    assert_eq!(pk.key_version().unwrap().as_str(), OTHER);
    let old = lookup
        .public_key_version(&KeyVersion::new(EC))
        .await
        .unwrap_err();
    assert_eq!(old.kind(), ErrorKind::UnknownKeyVersion);
}

/// Under `KeyTypeCheck::TrustCaller` (no key-type check, so no metadata read on the verify
/// path) the resolved target still follows the shared metadata.
#[tokio::test]
async fn trust_caller_verifier_follows_a_repoint() {
    let server = MockServer::start().await;
    ec_alias_to(&server, EC, Duration::ZERO).await;
    let p = provider(&server);
    let verifier = p
        .digest_signing_key(uri(ALIAS), ALG)
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller);
    let probe = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    verifier.verify_digest(&digest(), &sig(EC)).await.unwrap();

    server.reset().await;
    ec_alias_to(&server, OTHER, Duration::ZERO).await;
    probe.preflight().await.unwrap();

    verifier
        .verify_digest(&digest(), &sig(OTHER))
        .await
        .unwrap();
    let old = verifier
        .verify_digest(&digest(), &sig(EC))
        .await
        .unwrap_err();
    assert_eq!(old.kind(), ErrorKind::VerificationFailed);
}

/// A response's `KeyId` that is newer than the cached metadata wins: the stale cached target
/// never overrides it (no flapping back to the old key).
#[tokio::test]
async fn a_newer_response_target_is_not_overridden_by_stale_metadata() {
    let server = MockServer::start().await;
    ec_alias_to(&server, EC, Duration::ZERO).await;
    let p = provider(&server);
    let h = p.digest_signing_key(uri(ALIAS), ALG).unwrap();
    h.verify_digest(&digest(), &sig(EC)).await.unwrap(); // caches EC

    // The alias moved; Sign reports OTHER while the cached metadata still says EC.
    on(
        &server,
        "Sign",
        None,
        200,
        json!({"KeyId": OTHER, "Signature": b64(b"sig")}),
    )
    .await;
    let s = h.sign_digest(&digest()).await.unwrap();
    assert_eq!(s.key_version().unwrap().as_str(), OTHER);
    h.verify_digest(&digest(), &sig(OTHER)).await.unwrap();
    assert_eq!(bodies(&server, "DescribeKey").await.len(), 1);
}
