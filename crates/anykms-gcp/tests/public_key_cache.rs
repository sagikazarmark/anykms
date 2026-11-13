//! The provider's public-key cache: revocation through `CachedVerifier` (M2) and the cost of
//! forged versions (L17).

mod common;

use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{Digest, ErrorKind, KeyVersion, Registry, SignatureAlgorithm};
use anykms_recipes::CachedVerifier;
use common::fake::FakeKms;
use common::{cached_builder, vuri};

const ALG: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;

/// M2: `CachedVerifier::invalidate()` drops the verifier's cache and, through
/// `PublicKeys::invalidate_public_keys`, the provider's public-key cache (`public_key_ttl`), so a
/// version disabled since is refused at once. Exercised through a registry handle, the path
/// `with_default_providers` users have (no provider clone to call).
#[tokio::test]
async fn invalidate_revokes_a_disabled_version_at_once_through_a_registry_handle() {
    let fake = FakeKms::start().await;
    // Default public_key_ttl (60 s).
    let p = cached_builder(&fake).build().unwrap();
    let reg = Registry::builder().provider(p).build().unwrap();
    let name = fake.create_key("EC_SIGN_P256_SHA256");
    let v1 = reg.digest_signer(vuri(&name, 1), ALG).unwrap();
    let d = Digest::sha256(b"m");
    let s1 = v1.sign_digest(&d).await.unwrap();
    fake.rotate(&name);
    let cv = CachedVerifier::new(reg.public_keys(vuri(&name, 2), ALG).unwrap(), ALG);
    cv.verify_digest(&d, &s1).await.unwrap();

    fake.set_state(&name, 1, "DISABLED");
    // Without invalidation, both caches still serve version 1.
    cv.verify_digest(&d, &s1).await.unwrap();
    // `invalidate` alone: the next verification re-reads the version's state and refuses it.
    cv.invalidate();
    let e = cv.verify_digest(&d, &s1).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    fake.set_state(&name, 1, "ENABLED");
    cv.invalidate();
    cv.verify_digest(&d, &s1).await.unwrap();
}

/// M2: `GcpProvider::invalidate_public_keys()` drops the provider's cache for every handle of
/// the provider and its clones.
#[tokio::test]
async fn provider_invalidation_reaches_every_handle() {
    let fake = FakeKms::start().await;
    let p = cached_builder(&fake).build().unwrap();
    let name = fake.create_key("EC_SIGN_P256_SHA256");
    let v1 = p.digest_signing_key(vuri(&name, 1), ALG).unwrap();
    v1.public_key().await.unwrap();
    fake.set_state(&name, 1, "DISABLED");
    // Served from the provider's cache.
    v1.public_key().await.unwrap();
    p.clone().invalidate_public_keys();
    let e = v1.public_key().await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyStateInvalid, "{e}");
}

/// L17: once a lookup finds an input version missing, the key's latest version is read (one
/// `cryptoKeyVersions.list`, at most once per `public_key_ttl`) and every version above it is
/// refused without a request until then, whatever the number of distinct forged versions (the
/// per-version negative cache holds only 64). Real versions keep working; a version created
/// after the read is accepted once the read expires.
#[tokio::test]
async fn forged_versions_above_the_latest_cost_one_read_per_ttl() {
    let fake = FakeKms::start().await;
    let ttl = Duration::from_millis(300);
    let p = cached_builder(&fake).public_key_ttl(ttl).build().unwrap();
    let name = fake.create_key("EC_SIGN_P256_SHA256");
    fake.rotate(&name);
    let h = p.digest_signing_key(vuri(&name, 2), ALG).unwrap();
    h.public_key().await.unwrap();
    let before = fake.requests();
    // Three rounds over 65 distinct versions: more than the negative cache holds.
    for _ in 0..3 {
        for v in 1000..1065u64 {
            let e = h
                .public_key_version(&KeyVersion::from_u64(v))
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::UnknownKeyVersion, "{e}");
            assert!(e.is_caller_error());
        }
    }
    let spent = fake.requests() - before;
    assert!(spent <= 2, "{spent} requests: one lookup and one list");
    // Real versions still work.
    h.public_key_version(&KeyVersion::from_u64(1))
        .await
        .unwrap();
    // A rotation is picked up once the read expires.
    fake.rotate(&name);
    tokio::time::sleep(ttl.mul_f64(1.2)).await;
    h.public_key_version(&KeyVersion::from_u64(3))
        .await
        .unwrap();
}
