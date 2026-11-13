//! The provider's public-key cache: revocation through `CachedVerifier` (M2) and the cost of
//! forged versions (L17).

mod common;

use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{Digest, ErrorKind, KeyVersion, SignatureAlgorithm};
use anykms_recipes::CachedVerifier;
use common::fake::FakeKms;
use common::{cached_builder, vuri};

const ALG: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;

/// M2: `CachedVerifier::invalidate()` drops the verifier's own cache only; the provider's
/// public-key cache (`public_key_ttl`) still serves a version disabled since. Calling
/// `GcpProvider::invalidate_public_keys()` as well makes the revocation immediate.
#[tokio::test]
async fn invalidating_both_caches_revokes_a_disabled_version_at_once() {
    let fake = FakeKms::start().await;
    // Default public_key_ttl (60 s).
    let p = cached_builder(&fake).build().unwrap();
    let name = fake.create_key("EC_SIGN_P256_SHA256");
    let v1 = p.digest_signing_key(vuri(&name, 1), ALG).unwrap();
    let d = Digest::sha256(b"m");
    let s1 = v1.sign_digest(&d).await.unwrap();
    fake.rotate(&name);
    let cv = CachedVerifier::new(p.digest_signing_key(vuri(&name, 2), ALG).unwrap(), ALG);
    cv.verify_digest(&d, &s1).await.unwrap();

    fake.set_state(&name, 1, "DISABLED");
    // The verifier's cache alone: the provider still holds version 1's public key, for up to
    // `public_key_ttl` (the documented stacked bound).
    cv.invalidate();
    cv.verify_digest(&d, &s1).await.unwrap();

    // Both caches: the next verification re-reads the version's state and refuses it.
    cv.invalidate();
    p.invalidate_public_keys();
    let e = cv.verify_digest(&d, &s1).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable, "{e}");
    // Clones of the provider share the cache.
    fake.set_state(&name, 1, "ENABLED");
    p.clone().invalidate_public_keys();
    cv.invalidate();
    cv.verify_digest(&d, &s1).await.unwrap();
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
