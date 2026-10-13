//! Envelope padding through the public API, over a real (in-process) KEK from anykms-local.

use anykms_core::{Aead, AeadKeyWrap, Ciphertext, ErrorKind, Operation};
use anykms_local::{LocalAeadKey, LocalKeyset};
use anykms_recipes::envelope::Padding;
use anykms_recipes::{Envelope, EnvelopeAead, EnvelopeKeyring};

fn local_kek() -> (LocalKeyset, AeadKeyWrap<LocalAeadKey>) {
    let ks = LocalKeyset::builder().aead("kek").build();
    let key = ks.aead_key("kek");
    (ks, key.into_key_wrap())
}

fn payload_len(ct: &Ciphertext) -> usize {
    Envelope::parse(ct.as_bytes()).unwrap().payload().len()
}

#[tokio::test]
async fn block_padding_hides_the_plaintext_length_within_a_block() {
    let (_ks, kek) = local_kek();
    let env = EnvelopeAead::new("kek", kek)
        .unwrap()
        .with_padding(Padding::block(16));
    // The marker byte always fits: 0..=15 bytes take one 16-byte block, 16..=31 bytes two.
    for (pt, padded) in [
        (&b""[..], 16),
        (b"123-45-6789", 16),
        (b"123456789012345", 16),
        (b"1234567890123456", 32),
    ] {
        let ct = env.encrypt(pt, b"row").await.unwrap();
        assert_eq!(&*env.decrypt(&ct, b"row").await.unwrap(), pt);
        assert_eq!(payload_len(&ct), padded + 16, "{} bytes", pt.len());
    }
}

#[tokio::test]
async fn readers_unpad_by_the_envelope_flag_not_their_own_policy() {
    let (_ks, kek) = local_kek();
    let plain = EnvelopeAead::new("kek", kek.clone()).unwrap();
    let padded = plain.clone().with_padding(Padding::length(64));
    let from_padded = padded.encrypt(b"secret", b"row").await.unwrap();
    let from_plain = plain.encrypt(b"secret", b"row").await.unwrap();
    assert!(Envelope::parse(from_padded.as_bytes()).unwrap().is_padded());
    assert!(!Envelope::parse(from_plain.as_bytes()).unwrap().is_padded());
    for reader in [&plain, &padded] {
        for ct in [&from_padded, &from_plain] {
            assert_eq!(&*reader.decrypt(ct, b"row").await.unwrap(), b"secret");
        }
    }
}

#[tokio::test]
async fn length_padding_hides_every_length_up_to_the_bound() {
    let (_ks, kek) = local_kek();
    let env = EnvelopeAead::new("kek", kek)
        .unwrap()
        .with_padding(Padding::length(8));
    for pt in [&b""[..], b"1", b"12345678"] {
        let ct = env.encrypt(pt, b"").await.unwrap();
        assert_eq!(payload_len(&ct), 9 + 16, "{} bytes", pt.len());
        assert_eq!(&*env.decrypt(&ct, b"").await.unwrap(), pt);
    }
    let e = env.encrypt(b"123456789", b"").await.unwrap_err();
    assert_eq!(
        (e.kind(), e.operation()),
        (ErrorKind::InvalidArgument, Operation::Encrypt)
    );
}

#[tokio::test]
async fn a_keyring_pads_with_its_policy_and_rewraps_keep_the_padding() {
    let ks = LocalKeyset::builder().aead("old").aead("new").build();
    let ring = EnvelopeKeyring::new("old", ks.aead_key("old").into_key_wrap())
        .unwrap()
        .with_kek("new", ks.aead_key("new").into_key_wrap())
        .unwrap()
        .with_padding(Padding::block(32));
    let ct = ring.encrypt(b"secret", b"row").await.unwrap();
    assert_eq!(payload_len(&ct), 32 + 16);

    let ring = ring.with_primary("new").unwrap();
    for moved in [
        ring.rewrap_local(&ct).await.unwrap(),
        ring.rewrap_verified(&ct, b"row").await.unwrap(),
        ring.rewrap_current(&ct).await.unwrap(),
    ] {
        let env = Envelope::parse(moved.as_bytes()).unwrap();
        assert_eq!(env.kek_id(), b"new");
        assert!(env.is_padded());
        assert_eq!(
            env.payload(),
            Envelope::parse(ct.as_bytes()).unwrap().payload()
        );
        assert_eq!(&*ring.decrypt(&moved, b"row").await.unwrap(), b"secret");
    }
}
