//! `KeyWrapDataKeys`, `EmulatedDataKeys` and `ClientRewrap` over real (in-process) keys from
//! anykms-local, through the public API. anykms-local is a path-only dev-dependency that
//! `cargo publish` strips, so these tests live here rather than in `src/` (whose unit tests the
//! packaged crate must still build).

use anykms_core::{
    Aead, AeadKeyWrap, DataKeySpec, DataKeys, ErrorKind, KeyWrap, Operation, Rewrap,
};
use anykms_local::{LocalAeadKey, LocalKeyset};
use anykms_recipes::{ClientRewrap, EmulatedDataKeys, KeyWrapDataKeys};

fn local_kek() -> (LocalKeyset, AeadKeyWrap<LocalAeadKey>) {
    let ks = LocalKeyset::builder().aead("kek").build();
    let key = ks.aead_key("kek");
    (ks, key.into_key_wrap())
}

#[tokio::test]
async fn round_trip_through_unwrap_key() {
    let (_ks, kek) = local_kek();
    let dk = KeyWrapDataKeys::new(kek);
    let k = dk
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_eq!(k.spec(), DataKeySpec::Aes256);
    assert_eq!(k.plaintext().len(), 32);
    let unwrapped = dk.inner().unwrap_key(k.ciphertext()).await.unwrap();
    assert_eq!(&unwrapped[..], k.plaintext());

    let k2 = dk
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    assert_ne!(k.plaintext(), k2.plaintext());
}

#[tokio::test]
async fn wrap_errors_report_generate_data_key() {
    let (ks, kek) = local_kek();
    ks.disable("kek").unwrap();
    let err = KeyWrapDataKeys::new(kek)
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap_err();
    assert_eq!(err.operation(), Operation::GenerateDataKey);
}

#[tokio::test]
async fn emulated_data_keys_bind_aad() {
    let (_ks, kek) = local_kek();
    let aead = kek.into_inner();
    let dk = EmulatedDataKeys::new(aead.clone());
    let k = dk
        .generate_data_key(DataKeySpec::Aes256, b"ctx")
        .await
        .unwrap();
    let pt = aead.decrypt(k.ciphertext(), b"ctx").await.unwrap();
    assert_eq!(&pt[..], k.plaintext());
    assert!(aead.decrypt(k.ciphertext(), b"other").await.is_err());
}

#[tokio::test]
async fn rewraps_to_the_current_version_keeping_aad() {
    let ks = LocalKeyset::builder().aead("k").build();
    let key = ks.aead_key("k");
    let ct = key.encrypt(b"secret", b"ctx").await.unwrap();
    ks.rotate("k").unwrap();

    let rw = ClientRewrap::new(key.clone());
    let new = rw.rewrap(&ct, b"ctx").await.unwrap();
    assert_ne!(new.as_bytes(), ct.as_bytes());
    let v_old = key.ciphertext_version(&ct).unwrap().unwrap();
    let v_new = key.ciphertext_version(&new).unwrap().unwrap();
    assert_ne!(v_old, v_new);
    assert_eq!(&key.decrypt(&new, b"ctx").await.unwrap()[..], b"secret");
    assert!(key.decrypt(&new, b"other").await.is_err());
}

#[tokio::test]
async fn wrong_aad_fails_as_rewrap() {
    let ks = LocalKeyset::builder().aead("k").build();
    let key = ks.aead_key("k");
    let ct = key.encrypt(b"secret", b"ctx").await.unwrap();
    let err = ClientRewrap::new(key)
        .rewrap(&ct, b"other")
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    assert_eq!(err.operation(), Operation::Rewrap);
}
