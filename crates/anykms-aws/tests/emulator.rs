//! AWS-specific end-to-end checks against a KMS emulator (Floci by default; see tests/e2e/mod.rs),
//! beyond the conformance suite: native encryption-context interop with a plain `Encrypt`,
//! signatures verified locally against `GetPublicKey`, local RSA-OAEP wraps unwrapped by the
//! service, alias repointing and an envelope through the registry. Each test passes vacuously
//! (with a note) when no emulator is running, unless `ANYKMS_REQUIRE_FIXTURE=1`.

mod e2e;

use std::fmt::Write as _;

use anykms_aws::{EncryptionContext, EncryptionContextAead};
use anykms_conformance::TestKeyKind;
use anykms_core::prelude::*;
use anykms_core::{Digest, ErrorKind, KeyUri, OpenOptions, Provider, Registry, SignatureAlgorithm};
use base64::Engine as _;
use e2e::AwsFixture;
use serde_json::json;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

async fn fixture() -> Option<AwsFixture> {
    match AwsFixture::emulator().await {
        Ok(f) => Some(f),
        Err(e) if std::env::var("ANYKMS_REQUIRE_FIXTURE").as_deref() == Ok("1") => panic!("{e}"),
        Err(e) => {
            eprintln!("skipped: {e}");
            None
        }
    }
}

async fn key(f: &AwsFixture, kind: TestKeyKind) -> (String, KeyUri) {
    let arn = f.create(kind, "e2e").await.unwrap();
    let uri = AwsFixture::uri_of(&arn);
    (arn, uri)
}

#[tokio::test]
async fn native_context_interop() {
    let Some(f) = fixture().await else { return };
    let (arn, uri) = key(&f, TestKeyKind::Aead).await;
    let k = Registry::builder()
        .provider(f.provider_handle().clone())
        .build()
        .unwrap()
        .aead(uri)
        .unwrap();
    // A ciphertext made by another AWS client with a context decrypts with that context.
    let r = f
        .admin(
            "Encrypt",
            json!({"KeyId": arn, "Plaintext": B64.encode(b"from another tool"), "EncryptionContext": {"tenant": "t1"}}),
        )
        .await
        .unwrap();
    let ct = anykms_core::Ciphertext::from_bytes(
        B64.decode(r["CiphertextBlob"].as_str().unwrap()).unwrap(),
    );
    let ctx = EncryptionContext::new().with("tenant", "t1");
    assert_eq!(
        &*k.decrypt_with_context(&ct, &ctx).await.unwrap(),
        b"from another tool"
    );
    let wrong = EncryptionContext::new().with("tenant", "t2");
    assert_eq!(
        k.decrypt_with_context(&ct, &wrong)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DecryptFailed
    );
    // And the other way: anykms encrypts, a plain Decrypt with the same context reads it.
    let ct = k
        .encrypt_with_context(b"to another tool", &ctx)
        .await
        .unwrap();
    let r = f
        .admin(
            "Decrypt",
            json!({"KeyId": arn, "CiphertextBlob": B64.encode(ct.as_bytes()), "EncryptionContext": {"tenant": "t1"}}),
        )
        .await
        .unwrap();
    assert_eq!(
        B64.decode(r["Plaintext"].as_str().unwrap()).unwrap(),
        b"to another tool"
    );
    // The portable AAD is Tink's context (`associatedData`, lowercase hex), so a client that
    // sends it the way Tink's AwsKmsAead does reads anykms ciphertexts, and the reverse.
    let ct = k.encrypt(b"portable", b"users/42").await.unwrap();
    let r = f
        .admin(
            "Decrypt",
            json!({"KeyId": arn, "CiphertextBlob": B64.encode(ct.as_bytes()), "EncryptionContext": {"associatedData": "75736572732f3432"}}),
        )
        .await
        .unwrap();
    assert_eq!(
        B64.decode(r["Plaintext"].as_str().unwrap()).unwrap(),
        b"portable"
    );
    let r = f
        .admin(
            "Encrypt",
            json!({"KeyId": arn, "Plaintext": B64.encode(b"from tink"), "EncryptionContext": {"associatedData": "75736572732f3432"}}),
        )
        .await
        .unwrap();
    let tink_ct = anykms_core::Ciphertext::from_bytes(
        B64.decode(r["CiphertextBlob"].as_str().unwrap()).unwrap(),
    );
    assert_eq!(
        &*k.decrypt(&tink_ct, b"users/42").await.unwrap(),
        b"from tink"
    );
    // Rewrap and data keys with a native context.
    let ct2 = k
        .rewrap_with_context(&ct, &EncryptionContext::new().with("anykms-x", "y"), &ctx)
        .await;
    assert_eq!(ct2.unwrap_err().kind(), ErrorKind::DecryptFailed);
    let dk = k
        .generate_data_key_with_context(anykms_core::DataKeySpec::Aes256, &ctx)
        .await
        .unwrap();
    assert_eq!(
        &*k.decrypt_with_context(dk.ciphertext(), &ctx).await.unwrap(),
        dk.plaintext()
    );
}

#[tokio::test]
async fn signatures_verify_locally() {
    let Some(f) = fixture().await else { return };
    let p = f.provider_handle();
    // ECDSA P-256 over a digest.
    let (arn, uri) = key(
        &f,
        TestKeyKind::Signing(SignatureAlgorithm::EcdsaP256Sha256),
    )
    .await;
    let k = p
        .digest_signing_key(uri, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let d = Digest::sha256(b"message");
    let sig = k.sign_digest(&d).await.unwrap();
    assert_eq!(sig.key_version().unwrap().as_str(), arn);
    let pk = k.public_key().await.unwrap();
    use p256::pkcs8::DecodePublicKey as _;
    use signature::hazmat::PrehashVerifier as _;
    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(pk.spki_der()).unwrap();
    let s = p256::ecdsa::Signature::from_der(sig.as_bytes()).unwrap();
    vk.verify_prehash(d.as_bytes(), &s).unwrap();
    k.verify_digest(&d, &sig).await.unwrap();
    // The verification path the recipes use for high volumes.
    let local = anykms_recipes::LocalVerifier::new(pk.clone(), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    local.verify_digest(&d, &sig).await.unwrap();

    // Ed25519 over the raw message.
    let (_, uri) = key(&f, TestKeyKind::Signing(SignatureAlgorithm::Ed25519)).await;
    let k = p.ed25519_key(uri).unwrap();
    let sig = k.sign_message(b"message").await.unwrap();
    let pk = k.public_key().await.unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_public_key_der(pk.spki_der()).unwrap();
    let s = ed25519_dalek::Signature::from_slice(sig.as_bytes()).unwrap();
    vk.verify_strict(b"message", &s).unwrap();
    k.verify_message(b"message", &sig).await.unwrap();
}

#[tokio::test]
async fn rsa_wrap_locally_unwrap_remotely() {
    let Some(f) = fixture().await else { return };
    let (arn, uri) = key(&f, TestKeyKind::KeyWrap).await;
    let kek = f
        .provider_handle()
        .key_wrap(&uri, &OpenOptions::new())
        .unwrap();
    let wrapped = kek.wrap_key(&[9u8; 32]).await.unwrap();
    assert_eq!(&*kek.unwrap_key(&wrapped).await.unwrap(), &[9u8; 32]);
    // The service decrypts it as RSAES_OAEP_SHA_256.
    let r = f
        .admin(
            "Decrypt",
            json!({"KeyId": arn, "CiphertextBlob": B64.encode(wrapped.as_bytes()), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"}),
        )
        .await
        .unwrap();
    assert_eq!(
        B64.decode(r["Plaintext"].as_str().unwrap()).unwrap(),
        [9u8; 32]
    );
    let rewrapped = kek.rewrap(&wrapped, b"").await.unwrap();
    assert_eq!(&*kek.unwrap_key(&rewrapped).await.unwrap(), &[9u8; 32]);
    // An envelope over it.
    let env = anykms_recipes::EnvelopeAead::new("rsa-kek", kek).unwrap();
    let ct = env.encrypt(&vec![1u8; 100_000], b"aad").await.unwrap();
    assert_eq!(env.decrypt(&ct, b"aad").await.unwrap().len(), 100_000);
}

#[tokio::test]
async fn alias_repoint_gives_the_hint() {
    let Some(f) = fixture().await else { return };
    let (a, _) = key(&f, TestKeyKind::Aead).await;
    let (b, _) = key(&f, TestKeyKind::Aead).await;
    let mut n = [0u8; 6];
    getrandom::fill(&mut n).unwrap();
    let name = n.iter().fold(String::new(), |mut s, x| {
        write!(s, "{x:02x}").unwrap();
        s
    });
    let alias = format!("alias/e2e-{name}");
    f.admin("CreateAlias", json!({"AliasName": alias, "TargetKeyId": a}))
        .await
        .unwrap();
    let account = a.split(':').nth(4).unwrap();
    let uri: KeyUri = format!("aws-kms://arn:aws:kms:us-east-1:{account}:{alias}")
        .parse()
        .unwrap();
    let k = f.provider_handle().aead_key(uri).unwrap();
    let ct = k.encrypt(b"before", b"").await.unwrap();
    f.admin("UpdateAlias", json!({"AliasName": alias, "TargetKeyId": b}))
        .await
        .unwrap();
    let e = k.decrypt(&ct, b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{e}");
    assert!(e.to_string().contains("EnvelopeKeyring"), "{e}");
    // The old key, opened by its own ARN, still decrypts.
    let old = f
        .provider_handle()
        .aead_key(AwsFixture::uri_of(&a))
        .unwrap();
    assert_eq!(&*old.decrypt(&ct, b"").await.unwrap(), b"before");
}

#[tokio::test]
async fn registry_envelope_and_describe() {
    let Some(f) = fixture().await else { return };
    let (_, uri) = key(&f, TestKeyKind::Aead).await;
    let r = Registry::builder()
        .provider(f.provider_handle().clone())
        .layer(anykms_core::RetryLayer::new(anykms_core::instant_sleep()))
        .build()
        .unwrap();
    let env = anykms_recipes::EnvelopeAead::new("kek", r.key_wrap(uri.clone()).unwrap()).unwrap();
    let ct = env.encrypt(&vec![2u8; 70_000], b"users/1").await.unwrap();
    assert_eq!(env.decrypt(&ct, b"users/1").await.unwrap().len(), 70_000);
    let info = r.describe(uri).unwrap().describe().await.unwrap();
    assert_eq!(info.backend_key_type(), "SYMMETRIC_DEFAULT");
    assert!(f.provider_handle().schemes().contains(&"aws-kms"));
}
