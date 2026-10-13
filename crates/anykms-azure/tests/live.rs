//! End-to-end against a real Azure key vault, gated on the environment:
//!
//! - `ANYKMS_AZURE_LIVE=1`, `ANYKMS_AZURE_VAULT_URL=https://<vault>.vault.azure.net`;
//! - a credential `credential_from_env` selects (`AZURE_*`; in CI, workload identity through
//!   GitHub OIDC);
//! - the pooled keys `scripts/azure-test-setup.sh` creates (`ANYKMS_AZURE_KEK_URI`,
//!   `ANYKMS_AZURE_EC_URI`, `ANYKMS_AZURE_RSA_URI`; `Key Vault Crypto User` suffices), else
//!   fresh keys (needs `Key Vault Crypto Officer`).
//!
//! Without them each test prints why and passes (fails with `ANYKMS_REQUIRE_FIXTURE=1`). The
//! error-message probe lives in `scripts/probe-azure.sh`.

mod common;

use anykms_azure::framing;
use anykms_core::prelude::*;
use anykms_core::{Digest, ErrorKind, KeyUri, OpenOptions, Provider, Registry, SignatureAlgorithm};
use common::{AzureFixture, Spec};

async fn fixture() -> Option<AzureFixture> {
    match AzureFixture::live(false).await {
        Ok(f) => Some(f),
        Err(e) if !common::require_fixture() => {
            eprintln!("skipped: {e}");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

/// A pooled key from `var`, or a fresh one.
async fn key(fx: &AzureFixture, var: &str, spec: Spec) -> KeyUri {
    match std::env::var(var) {
        Ok(u) if !u.is_empty() => u.parse().expect("key URI"),
        _ => fx.create(spec).await.expect("create key").1,
    }
}

#[tokio::test]
async fn live_key_wrap_envelope_and_data_keys() {
    let Some(fx) = fixture().await else { return };
    let uri = key(&fx, "ANYKMS_AZURE_KEK_URI", Spec::RsaWrap(2048)).await;
    let registry = Registry::builder()
        .provider(fx.provider_ref().clone())
        .build()
        .unwrap();
    let kek = registry.key_wrap(&uri).unwrap();
    let w = kek.wrap_key(&[7u8; 32]).await.unwrap();
    assert_eq!(
        framing::parse(w.as_bytes()).unwrap().alg(),
        framing::FrameAlg::RsaOaep256
    );
    assert_eq!(&*kek.unwrap_key(&w).await.unwrap(), &[7u8; 32]);
    let env = anykms_recipes::EnvelopeAead::new("kek", kek.clone()).unwrap();
    let ct = env.encrypt(b"live", b"aad").await.unwrap();
    assert_eq!(&*env.decrypt(&ct, b"aad").await.unwrap(), b"live");
    let dk = registry.data_keys(&uri).unwrap();
    let d = dk
        .generate_data_key(anykms_core::DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_eq!(
        &*kek.unwrap_key(d.ciphertext()).await.unwrap(),
        d.plaintext()
    );
    kek.preflight().await.unwrap();
    fx.cleanup().await;
}

#[tokio::test]
async fn live_signing() {
    let Some(fx) = fixture().await else { return };
    let p = fx.provider_ref();
    for (var, spec, alg) in [
        (
            "ANYKMS_AZURE_EC_URI",
            Spec::Ec("P-256"),
            SignatureAlgorithm::EcdsaP256Sha256,
        ),
        (
            "ANYKMS_AZURE_RSA_URI",
            Spec::Rsa(2048),
            SignatureAlgorithm::RsaPssSha256,
        ),
    ] {
        let uri = key(&fx, var, spec).await;
        let s = p.digest_signer(&uri, alg, &OpenOptions::new()).unwrap();
        let d = Digest::sha256(b"live message");
        let sig = s.sign_digest(&d).await.unwrap();
        s.verify_digest(&d, &sig).await.unwrap();
        // The independent local verifier accepts Azure's signature (pins the PS* salt length).
        let pk = s
            .public_key_version(sig.key_version().unwrap())
            .await
            .unwrap();
        anykms_recipes::LocalVerifier::new(pk, alg)
            .unwrap()
            .verify_digest(&d, &sig)
            .await
            .unwrap();
        assert_eq!(
            s.verify_digest(&Digest::sha256(b"other"), &sig)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::VerificationFailed
        );
    }
    fx.cleanup().await;
}

#[tokio::test]
async fn live_missing_key_is_not_found() {
    let Some(fx) = fixture().await else { return };
    let e = fx
        .provider_ref()
        .describe(&fx.uri("anykms-does-not-exist"), &OpenOptions::new())
        .unwrap()
        .describe()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
    assert!(
        e.detail().and_then(|d| d.request_id()).is_some(),
        "x-ms-request-id"
    );
}
