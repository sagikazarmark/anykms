//! End-to-end against Lowkey Vault (an Azure Key Vault emulator), beyond the conformance suite:
//! RSA-OAEP-256 interop with a local encryption, the ciphertext frame of real wraps, envelope
//! encryption over an Azure KEK, data keys, local verification, describe with versions, and the
//! error paths whose kinds do not depend on the emulator's messages.
//!
//! Start it with `docker compose --profile azure up -d lowkey-vault`. Without it each test
//! prints why and passes (fails with `ANYKMS_REQUIRE_FIXTURE=1`).

mod common;

use std::sync::Arc;

use anykms_azure::{AzureOptions, framing};
use anykms_core::prelude::*;
use anykms_core::{
    Ciphertext, DataKeySpec, Digest, ErrorKind, KeyState, KeyTypeCheck, KeyVersion, OpenOptions,
    Provider, Registry, Signature, SignatureAlgorithm,
};
use common::{AzureFixture, Spec};

fn fixture() -> Option<AzureFixture> {
    match AzureFixture::lowkey() {
        Ok(f) => Some(f),
        Err(e) if !common::require_fixture() => {
            eprintln!("skipped: {e}");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

#[tokio::test]
async fn rsa_oaep_256_interoperates_and_frames() {
    let Some(fx) = fixture() else { return };
    let (_, uri) = fx.create(Spec::RsaWrap(2048)).await.unwrap();
    let p = fx.provider_ref();
    let kek = p.key_wrap_key(&uri).unwrap();
    let dek = [0x42u8; 32];
    let wrapped = kek.wrap_key(&dek).await.unwrap();
    let f = framing::parse(wrapped.as_bytes()).unwrap();
    assert_eq!(f.alg(), framing::FrameAlg::RsaOaep256);
    assert_eq!(f.body().len(), 256);
    assert_eq!(f.version().len(), 32);
    assert_eq!(&*kek.unwrap_key(&wrapped).await.unwrap(), &dek);
    // RSA-OAEP with SHA-256 and MGF1-SHA-256: a local encryption with the key's public key
    // unwraps in the vault.
    let pk = p
        .digest_signing_key(&uri, SignatureAlgorithm::RsaPssSha256)
        .unwrap()
        .public_key()
        .await
        .unwrap();
    let local = anykms_recipes::rsa_oaep_sha256_encrypt(pk.spki_der(), &dek).unwrap();
    let framed = framing::encode(framing::FrameAlg::RsaOaep256, f.version(), &local).unwrap();
    assert_eq!(
        &*kek
            .unwrap_key(&Ciphertext::from_bytes(framed))
            .await
            .unwrap(),
        &dek
    );
    // Maximum input: modulus bytes - 66.
    kek.wrap_key(&[1u8; 190]).await.unwrap();
    assert_eq!(
        kek.wrap_key(&[1u8; 191]).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    // A damaged wrapped key is DecryptFailed.
    let mut bytes = wrapped.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        kek.unwrap_key(&Ciphertext::from_bytes(bytes))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DecryptFailed
    );
}

/// A KEK's public key (the `KeyWrapKey` public-key part) wraps a data key offline: RSA-OAEP-256
/// locally, framed with the published version (`framing::encode`, the wire format of
/// `docs/azure-ciphertext.md`), then unwrapped by the vault.
#[tokio::test]
async fn kek_public_keys_wrap_offline() {
    let Some(fx) = fixture() else { return };
    let (_, uri) = fx.create(Spec::RsaWrap(2048)).await.unwrap();
    let registry = Registry::builder()
        .provider(fx.provider_ref().clone())
        .build()
        .unwrap();
    let kek = registry.key_wrap(&uri).unwrap();
    assert!(kek.supports_public_keys());
    let pk = kek.public_key().await.unwrap();
    let version = pk
        .key_version()
        .expect("the public key names its version")
        .clone();
    let dek = [0x42u8; 32];
    let ct = anykms_recipes::rsa_oaep_sha256_encrypt(pk.spki_der(), &dek).unwrap();
    let framed = framing::encode(framing::FrameAlg::RsaOaep256, version.as_str(), &ct).unwrap();
    let out = kek
        .unwrap_key(&Ciphertext::from_bytes(framed))
        .await
        .unwrap();
    assert_eq!(*out, dek);
    // The raw, unframed ciphertext is not an Azure wrapped key.
    assert_eq!(
        kek.unwrap_key(&Ciphertext::from_bytes(ct))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DecryptFailed
    );
    assert_eq!(
        kek.public_key_version(&version).await.unwrap().spki_der(),
        pk.spki_der()
    );
}

#[tokio::test]
async fn envelopes_and_data_keys_over_an_azure_kek() {
    let Some(fx) = fixture() else { return };
    let (name, uri) = fx.create(Spec::RsaWrap(3072)).await.unwrap();
    let registry = Registry::builder()
        .provider(fx.provider_ref().clone())
        .build()
        .unwrap();
    let kek = registry.key_wrap(&uri).unwrap();
    let env = anykms_recipes::EnvelopeAead::new("azure-kek", kek.clone()).unwrap();
    let ct = env.encrypt(b"payload", b"users/42").await.unwrap();
    assert_eq!(&*env.decrypt(&ct, b"users/42").await.unwrap(), b"payload");
    // Rotation: the old envelope still opens, rewrap_local moves it to the new version.
    let v1 = env.ciphertext_version(&ct).unwrap();
    fx.admin().rotate(&name).await.unwrap();
    let ct2 = env.rewrap_local(&ct).await.unwrap();
    assert_ne!(env.ciphertext_version(&ct2).unwrap(), v1);
    assert_eq!(&*env.decrypt(&ct2, b"users/42").await.unwrap(), b"payload");
    // Data keys: AAD refused before I/O, unwrap with the KEK.
    let dk = registry.data_keys(&uri).unwrap();
    assert_eq!(
        dk.generate_data_key(DataKeySpec::Aes256, b"x")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    let key = dk
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_eq!(
        &*kek.unwrap_key(key.ciphertext()).await.unwrap(),
        key.plaintext()
    );
    let info = dk.preflight().await.unwrap();
    assert_eq!(info.backend_key_type(), "RSA 3072");
    assert_eq!(info.versions().len(), 2, "{info:?}");
}

#[tokio::test]
async fn signing_with_server_and_local_verification() {
    let Some(fx) = fixture() else { return };
    let p = fx.provider_ref();
    for (spec, algs) in [
        (
            Spec::Ec("P-256"),
            &[SignatureAlgorithm::EcdsaP256Sha256][..],
        ),
        (Spec::Ec("P-384"), &[SignatureAlgorithm::EcdsaP384Sha384]),
        (Spec::Ec("P-521"), &[SignatureAlgorithm::EcdsaP521Sha512]),
        (
            Spec::Rsa(2048),
            &[
                SignatureAlgorithm::RsaPssSha256,
                SignatureAlgorithm::RsaPssSha512,
                SignatureAlgorithm::RsaPkcs1v15Sha384,
            ],
        ),
    ] {
        let (_, uri) = fx.create(spec).await.unwrap();
        for &alg in algs {
            let h = alg.hash().unwrap();
            let d = Digest::compute(h, b"message");
            let s = p.digest_signing_key(&uri, alg).unwrap();
            let sig = s.sign_digest(&d).await.unwrap();
            s.verify_digest(&d, &sig).await.unwrap();
            assert_eq!(
                s.verify_digest(&Digest::compute(h, b"other"), &sig)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::VerificationFailed,
                "{alg}"
            );
            // Locally, with the public key of the signature's version (RFC 7518 PS* salt).
            let opts = OpenOptions::new().with_extension(AzureOptions::new().local_verify());
            let lv = p.digest_verifier(&uri, alg, &opts).unwrap();
            lv.verify_digest(&d, &sig).await.unwrap();
            let pk = s
                .public_key_version(sig.key_version().unwrap())
                .await
                .unwrap();
            anykms_recipes::LocalVerifier::new(pk, alg)
                .unwrap()
                .verify_digest(&d, &sig)
                .await
                .unwrap();
            // A signature naming a version this key does not have.
            let foreign = Signature::from_parts(
                alg,
                Some(KeyVersion::new("0123456789abcdef0123456789abcdef")),
                sig.as_bytes(),
            );
            assert_eq!(
                s.verify_digest(&d, &foreign).await.unwrap_err().kind(),
                ErrorKind::VerificationFailed
            );
        }
    }
}

#[tokio::test]
async fn describe_lists_versions_and_states() {
    let Some(fx) = fixture() else { return };
    let (name, uri) = fx.create(Spec::Ec("P-256")).await.unwrap();
    let v2 = fx.admin().rotate(&name).await.unwrap();
    let v1 = fx
        .admin()
        .versions(&name)
        .await
        .unwrap()
        .into_iter()
        .find(|v| *v != v2)
        .unwrap();
    fx.admin().set_enabled(&name, &v1, false).await.unwrap();
    let k = fx
        .provider_ref()
        .digest_signing_key(&uri, SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let info = k.describe().await.unwrap();
    assert_eq!(info.primary_version().unwrap().as_str(), v2);
    assert_eq!(info.state(), Some(&KeyState::Enabled));
    let mut states: Vec<_> = info
        .versions()
        .iter()
        .map(|v| (v.version().as_str().to_owned(), v.state().clone()))
        .collect();
    states.sort_by(|a, b| a.0.cmp(&b.0));
    let mut want = vec![
        (v1.clone(), KeyState::Disabled),
        (v2.clone(), KeyState::Enabled),
    ];
    want.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(states, want);
    let az = k
        .describe()
        .await
        .unwrap()
        .backend_info::<anykms_azure::AzureKeyInfo>()
        .unwrap()
        .clone();
    assert_eq!(az.key_type, anykms_azure::AzureKeyType::Ec);
    assert_eq!(az.curve.as_deref(), Some("P-256"));
    assert_eq!(
        az.key_ops.as_deref(),
        Some(&["sign".to_owned(), "verify".to_owned()][..])
    );
    // New signatures use the current version.
    let sig = k.sign_digest(&Digest::sha256(b"m")).await.unwrap();
    assert_eq!(sig.key_version().unwrap().as_str(), v2);
}

#[tokio::test]
async fn errors_that_do_not_depend_on_emulator_messages() {
    let Some(fx) = fixture() else { return };
    let p = fx.provider_ref();
    // A missing key.
    let missing = fx.uri("anykms-does-not-exist");
    let e = p
        .key_wrap_key(&missing)
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    let e = p
        .key_wrap_key(&missing)
        .unwrap()
        .wrap_key(&[1; 32])
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    // Key-type mismatches: by kty/curve and by key_ops.
    let (_, ec) = fx.create(Spec::Ec("P-256")).await.unwrap();
    let e = p
        .digest_signing_key(&ec, SignatureAlgorithm::RsaPssSha256)
        .unwrap()
        .sign_digest(&Digest::sha256(b"m"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    assert_eq!(
        p.key_wrap_key(&ec)
            .unwrap()
            .wrap_key(&[1; 32])
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::KeyMismatch
    );
    let (_, kek) = fx.create(Spec::RsaWrap(2048)).await.unwrap();
    assert_eq!(
        p.digest_signing_key(&kek, SignatureAlgorithm::RsaPssSha256)
            .unwrap()
            .sign_digest(&Digest::sha256(b"m"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::KeyMismatch,
        "a wrap-only key does not sign"
    );
    // Under TrustCaller the vault decides (Lowkey answers with its own error).
    let opts = OpenOptions::new().with_key_type_check(KeyTypeCheck::TrustCaller);
    let s = p
        .digest_signer(&kek, SignatureAlgorithm::RsaPssSha256, &opts)
        .unwrap();
    assert!(s.sign_digest(&Digest::sha256(b"m")).await.is_err());
    // A host outside the allowlist never receives a token.
    let e = p
        .key_wrap_key("azure-kv://vault.evil.example.com/keys/k")
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    let _ = Arc::new(());
}
