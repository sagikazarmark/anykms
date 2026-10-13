//! Live checks against real Cloud KMS that the conformance suite does not cover. Every test
//! returns early (and says so) unless `ANYKMS_GCP_LIVE=1`.
//!
//! - `ANYKMS_GCP_KEY_RING`: `projects/<p>/locations/<l>/keyRings/<r>` holding the pooled keys
//!   `scripts/gcp-test-setup.sh` creates (`aead`, `ec-p256`, `rsa-pss-2048`, `rsa-pkcs1-2048`,
//!   `ed25519`, `hmac-sha256`, `rsa-oaep-2048`, and `hsm-aead` when `ANYKMS_GCP_HSM=1`);
//! - credentials: Application Default Credentials;
//! - optional `ANYKMS_GCP_QUOTA_PROJECT` and `ANYKMS_GCP_REGIONAL=1` (the ring's location has
//!   a regional endpoint).

use anykms_core::prelude::*;
use anykms_core::{
    Capabilities, Digest, ErrorKind, KeyUri, KeyVersion, MacAlgorithm, OpenOptions, Preflight,
    Provider, SignatureAlgorithm,
};
use anykms_gcp::{Endpoint, GcpProvider};

/// The key ring, or `None` (test skipped).
fn ring() -> Option<String> {
    if std::env::var("ANYKMS_GCP_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: ANYKMS_GCP_LIVE is not 1");
        return None;
    }
    match std::env::var("ANYKMS_GCP_KEY_RING") {
        Ok(r) if !r.is_empty() => Some(r),
        _ => panic!("ANYKMS_GCP_LIVE=1 needs ANYKMS_GCP_KEY_RING"),
    }
}

fn provider(ring: &str) -> GcpProvider {
    let project = ring.split('/').nth(1).unwrap().to_owned();
    let mut b = GcpProvider::builder().allowed_projects([project]);
    if let Ok(q) = std::env::var("ANYKMS_GCP_QUOTA_PROJECT") {
        b = b.quota_project(q);
    }
    b.build().unwrap()
}

fn key(ring: &str, name: &str) -> String {
    format!("gcp-kms://{ring}/cryptoKeys/{name}")
}

fn v1(ring: &str, name: &str) -> String {
    format!("{}/cryptoKeyVersions/1", key(ring, name))
}

#[tokio::test]
async fn aead_roundtrip_describe_and_startup_check() {
    let Some(ring) = ring() else { return };
    let p = provider(&ring);
    let k = p.aead_key(key(&ring, "aead")).unwrap();
    k.preflight().await.unwrap();
    let ct = k.encrypt(b"live", b"aad").await.unwrap();
    let d = k.decrypt_with_info(&ct, b"aad").await.unwrap();
    assert_eq!(d.plaintext(), b"live");
    assert!(d.used_primary().is_some());
    assert_eq!(
        k.decrypt(&ct, b"other").await.unwrap_err().kind(),
        ErrorKind::DecryptFailed
    );
    let info = k.describe().await.unwrap();
    assert!(info.capabilities().contains(Capabilities::AEAD));
    assert_eq!(info.state(), None);
    assert!(info.primary_version().is_some());
}

#[tokio::test]
async fn version_rules_at_open() {
    let Some(ring) = ring() else { return };
    let p = provider(&ring);
    let o = OpenOptions::new();
    let uri = |s: String| s.parse::<KeyUri>().unwrap();
    assert_eq!(
        p.digest_signer(
            &uri(key(&ring, "ec-p256")),
            SignatureAlgorithm::EcdsaP256Sha256,
            &o
        )
        .unwrap_err()
        .kind(),
        ErrorKind::KeyMismatch
    );
    assert_eq!(
        p.aead(&uri(v1(&ring, "aead")), &o).unwrap_err().kind(),
        ErrorKind::KeyMismatch
    );
}

#[tokio::test]
async fn signing_and_pss_vs_pkcs1() {
    let Some(ring) = ring() else { return };
    let p = provider(&ring);
    for (name, alg) in [
        ("ec-p256", SignatureAlgorithm::EcdsaP256Sha256),
        ("rsa-pss-2048", SignatureAlgorithm::RsaPssSha256),
        ("rsa-pkcs1-2048", SignatureAlgorithm::RsaPkcs1v15Sha256),
    ] {
        let s = p.digest_signing_key(v1(&ring, name), alg).unwrap();
        let d = Digest::sha256(b"live");
        let sig = s.sign_digest(&d).await.unwrap();
        assert_eq!(sig.key_version(), Some(&KeyVersion::from_u64(1)));
        s.verify_digest(&d, &sig).await.unwrap();
    }
    // The server cannot tell PSS from PKCS#1; the key-type check does.
    let e = p
        .digest_signing_key(
            v1(&ring, "rsa-pss-2048"),
            SignatureAlgorithm::RsaPkcs1v15Sha256,
        )
        .unwrap()
        .sign_digest(&Digest::sha256(b"x"))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    let ed = p.ed25519_key(v1(&ring, "ed25519")).unwrap();
    let sig = ed.sign_message(b"live").await.unwrap();
    ed.verify_message(b"live", &sig).await.unwrap();
}

#[tokio::test]
async fn mac_and_rsa_kek() {
    let Some(ring) = ring() else { return };
    let p = provider(&ring);
    let m = p
        .mac_key(v1(&ring, "hmac-sha256"), MacAlgorithm::HmacSha256)
        .unwrap();
    let t = m.mac(b"live").await.unwrap();
    m.verify_mac(b"live", &t).await.unwrap();
    assert_eq!(
        m.verify_mac(b"other", &t).await.unwrap_err().kind(),
        ErrorKind::VerificationFailed
    );
    let kek = p
        .key_wrap(
            &v1(&ring, "rsa-oaep-2048").parse().unwrap(),
            &OpenOptions::new(),
        )
        .unwrap();
    let w = kek.wrap_key(&[3; 32]).await.unwrap();
    assert_eq!(&*kek.unwrap_key(&w).await.unwrap(), &[3; 32]);
}

#[tokio::test]
async fn regional_endpoint() {
    let Some(ring) = ring() else { return };
    if std::env::var("ANYKMS_GCP_REGIONAL").as_deref() != Ok("1") {
        eprintln!("skipped: ANYKMS_GCP_REGIONAL is not 1");
        return;
    }
    let p = GcpProvider::builder()
        .endpoint(Endpoint::Regional)
        .build()
        .unwrap();
    let k = p.aead_key(key(&ring, "aead")).unwrap();
    let ct = k.encrypt(b"regional", b"").await.unwrap();
    assert_eq!(&*k.decrypt(&ct, b"").await.unwrap(), b"regional");
}

#[tokio::test]
async fn hsm_limits() {
    let Some(ring) = ring() else { return };
    if std::env::var("ANYKMS_GCP_HSM").as_deref() != Ok("1") {
        eprintln!("skipped: ANYKMS_GCP_HSM is not 1");
        return;
    }
    let k = provider(&ring).aead_key(key(&ring, "hsm-aead")).unwrap();
    k.encrypt(&[1; 8 * 1024 - 64], b"").await.unwrap();
    assert_eq!(
        k.encrypt(&[1; 16 * 1024], b"").await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
}

#[tokio::test]
async fn missing_key_is_not_found() {
    let Some(ring) = ring() else { return };
    let e = provider(&ring)
        .aead_key(key(&ring, "does-not-exist"))
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    // NotFound needs cloudkms.cryptoKeys.get on the key ring; PermissionDenied otherwise.
    assert!(
        matches!(e.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied),
        "{e}"
    );
}
