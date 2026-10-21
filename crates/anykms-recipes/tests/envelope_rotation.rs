//! Envelope KEK rotation and migration over real (in-process) keys from anykms-local, which
//! rotate and rewrap server-side: `rewrap_current` on `EnvelopeAead` and `EnvelopeKeyring`, the
//! keyring's `rewrap_local`, and the completion scan from the envelope module docs. anykms-local
//! is a path-only dev-dependency that `cargo publish` strips, so these tests live here.

use std::sync::Arc;

use anykms_core::{
    Aead, Ciphertext, Describe, ErrorKind, KeyVersion, KeyWrapKey, Operation, Registry, Result,
};
use anykms_local::{Fault, LocalKeyset, LocalProvider};
use anykms_recipes::{Envelope, EnvelopeAead, EnvelopeKeyring};

const AAD: &[u8] = b"users/42/ssn";

fn registry(ks: &LocalKeyset) -> Registry {
    Registry::builder()
        .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys())
        .build()
        .unwrap()
}

fn kek(reg: &Registry, name: &str) -> KeyWrapKey {
    reg.key_wrap(format!("local://default/{name}")).unwrap()
}

/// The same local key as a `KeyWrapKey` without a rewrap part, as a GCP or Azure KEK is.
fn kek_without_rewrap(ks: &LocalKeyset, name: &str) -> KeyWrapKey {
    KeyWrapKey::new("local", Arc::new(ks.aead_key(name).into_key_wrap()))
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "builds the Option<KeyVersion> that assertions compare against"
)]
fn v(n: u64) -> Option<KeyVersion> {
    Some(KeyVersion::from_u64(n))
}

/// The completion scan from the envelope module docs.
fn needs_rewrap(
    ring: &EnvelopeKeyring,
    current: Option<&KeyVersion>,
    ct: &Ciphertext,
) -> Result<bool> {
    if Envelope::parse(ct.as_bytes())?.kek_id() != ring.primary_id() {
        return Ok(true);
    }
    Ok(match (ring.ciphertext_version(ct)?, current) {
        (Some(v), Some(c)) => &v != c,
        _ => false,
    })
}

async fn assert_same_envelope<A: Aead>(env: &A, before: &Ciphertext, after: &Ciphertext) {
    assert_eq!(
        Envelope::parse(after.as_bytes()).unwrap().payload(),
        Envelope::parse(before.as_bytes()).unwrap().payload(),
        "a rewrap never touches the payload"
    );
    assert_eq!(&*env.decrypt(after, AAD).await.unwrap(), b"secret");
}

/// A KEK that rewraps server-side does so; one without rewrap falls back to the local rewrap.
/// Either way the envelope moves to the rotated KEK's current version.
#[tokio::test]
async fn rewrap_current_moves_to_the_current_version() {
    let ks = LocalKeyset::builder().aead("kek").build();
    let reg = registry(&ks);
    let server = EnvelopeAead::new("app-kek", kek(&reg, "kek")).unwrap();
    assert!(server.kek().supports_rewrap());
    let local = EnvelopeAead::new("app-kek", kek_without_rewrap(&ks, "kek")).unwrap();
    let ct = server.encrypt(b"secret", AAD).await.unwrap();
    assert_eq!(server.ciphertext_version(&ct).unwrap(), v(1));
    ks.rotate("kek").unwrap();

    // The server-side path is taken: a fault on the KMS rewrap surfaces as is.
    ks.inject_on(Operation::Rewrap, Fault::permission_denied(1));
    let e = server.rewrap_current(&ct).await.unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::PermissionDenied, Operation::Rewrap)
    );
    let r = server.rewrap_current(&ct).await.unwrap();
    assert_eq!(server.ciphertext_version(&r).unwrap(), v(2));
    assert_same_envelope(&server, &ct, &r).await;

    // Without a rewrap part the KEK is never asked to rewrap (the fault stays armed) and the
    // data key is rewrapped locally.
    let e = local.rewrap(&ct).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unsupported);
    assert!(e.message().contains("rewrap_local"), "{e}");
    ks.inject_on(Operation::Rewrap, Fault::permission_denied(1));
    let r = local.rewrap_current(&ct).await.unwrap();
    assert_eq!(local.ciphertext_version(&r).unwrap(), v(2));
    assert_same_envelope(&local, &ct, &r).await;
    ks.clear_faults();

    // A KMS that answers `Unsupported` falls back too.
    ks.inject_on(Operation::Rewrap, Fault::of_kind(ErrorKind::Unsupported, 1));
    let r = server.rewrap_current(&ct).await.unwrap();
    assert_eq!(server.ciphertext_version(&r).unwrap(), v(2));
    assert_same_envelope(&server, &ct, &r).await;
}

/// A migration from KEK `old` to the primary `new`, which also rotates mid-way: the keyring's
/// `rewrap_current` moves envelopes off `old` and off older versions of `new`, and the
/// completion scan finds exactly the envelopes it still has to move.
#[tokio::test]
async fn keyring_rewrap_current_finishes_a_migration() {
    let ks = LocalKeyset::builder().aead("old").aead("new").build();
    let reg = registry(&ks);
    let primary = kek(&reg, "new");
    let ring = EnvelopeKeyring::new("old-kek", kek(&reg, "old"))
        .unwrap()
        .with_kek("new-kek", primary.clone())
        .unwrap()
        .with_primary("new-kek")
        .unwrap();
    assert_eq!(ring.primary_id(), b"new-kek");
    assert_eq!(
        ring.kek_ids().collect::<Vec<_>>(),
        [&b"old-kek"[..], &b"new-kek"[..]]
    );

    let on_old = EnvelopeAead::new("old-kek", kek(&reg, "old"))
        .unwrap()
        .encrypt(b"secret", AAD)
        .await
        .unwrap();
    let on_new_v1 = ring.encrypt(b"secret", AAD).await.unwrap();
    ks.rotate("new").unwrap();
    let on_new_v2 = ring.encrypt(b"secret", AAD).await.unwrap();
    let rows = [on_old, on_new_v1, on_new_v2];

    let info = primary.describe().await.unwrap();
    assert_eq!(info.primary_version(), v(2).as_ref());
    let current = info.primary_version();
    let pending: Vec<bool> = rows
        .iter()
        .map(|ct| needs_rewrap(&ring, current, ct).unwrap())
        .collect();
    assert_eq!(pending, [true, true, false]);

    // The envelope on the primary's older version is rewrapped server-side.
    ks.inject_on(Operation::Rewrap, Fault::permission_denied(1));
    let e = ring.rewrap_current(&rows[1]).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);

    let mut migrated = Vec::new();
    for ct in &rows {
        let r = ring.rewrap_current(ct).await.unwrap();
        assert_eq!(Envelope::parse(r.as_bytes()).unwrap().kek_id(), b"new-kek");
        assert_eq!(ring.ciphertext_version(&r).unwrap(), v(2));
        assert_same_envelope(&ring, ct, &r).await;
        assert!(!needs_rewrap(&ring, current, &r).unwrap());
        migrated.push(r);
    }

    // `rewrap_local` does the same locally, for every KEK type: the older primary version too.
    for ct in &rows {
        let r = ring.rewrap_local(ct).await.unwrap();
        assert_eq!(Envelope::parse(r.as_bytes()).unwrap().kek_id(), b"new-kek");
        assert_eq!(ring.ciphertext_version(&r).unwrap(), v(2));
        assert_same_envelope(&ring, ct, &r).await;
    }

    // Once the scan is clean the old KEK can leave the ring; migrated envelopes still open.
    let ring = EnvelopeKeyring::new("new-kek", primary).unwrap();
    for ct in &migrated {
        assert_eq!(&*ring.decrypt(ct, AAD).await.unwrap(), b"secret");
    }
    // A leftover would have failed, naming the KEK the keyring no longer has.
    let e = ring.decrypt(&rows[0], AAD).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DecryptFailed);
    assert!(e.message().contains("old-kek"), "{e}");
}

/// An AEAD key adapted with `.into_key_wrap()` keeps its server-side rewrap in a keyring; a
/// KEK without one is rewrapped locally.
#[tokio::test]
async fn keyring_keks_keep_their_rewrap() {
    let ks = LocalKeyset::builder().aead("kek").build();
    let reg = registry(&ks);
    for (adapted, server_side) in [
        (
            EnvelopeKeyring::new(
                "k",
                reg.aead("local://default/kek").unwrap().into_key_wrap(),
            )
            .unwrap(),
            true,
        ),
        (
            EnvelopeKeyring::new("k", Arc::new(ks.aead_key("kek").into_key_wrap())).unwrap(),
            false,
        ),
    ] {
        let ct = adapted.encrypt(b"secret", AAD).await.unwrap();
        ks.inject_on(Operation::Rewrap, Fault::permission_denied(1));
        let r = adapted.rewrap_current(&ct).await;
        ks.clear_faults();
        assert_eq!(r.is_err(), server_side, "{r:?}");
    }
}
