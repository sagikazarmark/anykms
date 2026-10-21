//! Wrapped-only data keys, data-key sources (`Provider::data_keys`) and the `KeyWrapDataKeys`
//! recipe.

use anykms_core::prelude::*;
use anykms_core::{Capabilities, Ciphertext, DataKeySpec, ErrorKind, Zeroizing};
use anykms_recipes::KeyWrapDataKeys;

use super::aead::{aad_refused, data_key_aad};
use crate::ctx::{CaseResult, Check, Ctx, ensure, expect_kind, require_semantics};
use crate::fixture::{Feature, Fixture, TestKeyKind};

/// A wrapped-only data key is a 32-byte key wrapped like a `DataKeys` ciphertext: it decrypts
/// with the AEAD key under the same AAD.
pub(crate) async fn wrapped_only<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    ensure!(
        k.supports_wrapped_data_keys(),
        "AEAD key does not support wrapped data keys"
    );
    let ct = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
        .await
        .ctx("generate_wrapped_data_key")?;
    let dek = k.decrypt(&ct, b"").await.ctx("decrypt wrapped data key")?;
    ensure!(dek.len() == 32, "data key has {} bytes", dek.len());
    let other = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"")
        .await
        .ctx("generate_wrapped_data_key again")?;
    ensure!(
        *k.decrypt(&other, b"").await.ctx("decrypt")? != *dek,
        "two wrapped data keys hold the same key"
    );
    Ok(())
}

/// AAD on wrapped-only data keys follows the handle's data-key source
/// ([`KeySemantics::data_keys`](anykms_core::KeySemantics::data_keys)).
pub(crate) async fn wrapped_only_aad<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let aad = data_key_aad(&require_semantics(k.semantics(), key.kind)?)?;
    let r = k
        .generate_wrapped_data_key(DataKeySpec::Aes256, b"ctx")
        .await;
    if aad_refused(aad, &r) {
        expect_kind(
            r,
            ErrorKind::Unsupported,
            "generate_wrapped_data_key with AAD",
        )?;
    } else {
        let ct = r.ctx("generate_wrapped_data_key with AAD")?;
        ensure!(
            k.decrypt(&ct, b"ctx").await.ctx("decrypt with AAD")?.len() == 32,
            "wrapped data key is not 32 bytes"
        );
        expect_kind(
            k.decrypt(&ct, b"other").await,
            ErrorKind::DecryptFailed,
            "wrapped data key under the wrong AAD",
        )?;
        expect_kind(
            k.decrypt(&ct, b"").await,
            ErrorKind::DecryptFailed,
            "wrapped data key not bound to AAD",
        )?;
    }
    Ok(())
}

/// The kind of key data-key sources are opened from: AEAD keys where the fixture has them, else
/// key-wrapping keys.
fn source_kind<F: Fixture>(c: &Ctx<F>) -> TestKeyKind {
    if c.caps.has(Feature::Aead) {
        TestKeyKind::Aead
    } else {
        TestKeyKind::KeyWrap
    }
}

/// Unwraps a data key's ciphertext with the key it came from.
async fn unwrap<F: Fixture>(
    c: &Ctx<F>,
    kind: TestKeyKind,
    uri: &anykms_core::KeyUri,
    ct: &Ciphertext,
    aad: &[u8],
) -> anykms_core::Result<Zeroizing<Vec<u8>>> {
    match kind {
        TestKeyKind::Aead => c.aead(uri)?.decrypt(ct, aad).await,
        _ => c.key_wrap(uri)?.unwrap_key(ct).await,
    }
}

/// A data-key source (`Provider::data_keys`) hands out 32-byte keys whose ciphertext unwraps
/// with the key it was opened from, and is described like that key.
pub(crate) async fn source_roundtrip<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let kind = source_kind(&c);
    let key = c.key(kind).await?;
    let src = c.data_keys(&key.uri).ctx("open data_keys")?;
    let dk = src
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .ctx("generate_data_key")?;
    ensure!(
        dk.plaintext().len() == 32,
        "data key has {} bytes",
        dk.plaintext().len()
    );
    let back = unwrap(&c, kind, &key.uri, dk.ciphertext(), b"")
        .await
        .ctx("unwrap the data key")?;
    ensure!(*back == *dk.plaintext(), "unwrapped data key differs");
    ensure!(
        src.supports_describe() == c.caps.has(Feature::Describe),
        "data-key source {src:?} disagrees with the declaration (describe {})",
        c.caps.has(Feature::Describe)
    );
    if src.supports_describe() {
        let info = src.describe().await.ctx("describe")?;
        let need = if kind == TestKeyKind::Aead {
            Capabilities::DATA_KEYS
        } else {
            Capabilities::KEY_WRAP
        };
        ensure!(
            info.capabilities().contains(need),
            "data-key source capabilities {:?} lack {need:?}",
            info.capabilities()
        );
    }
    Ok(())
}

/// AAD on a data-key source: bound or refused, as the source's semantics declare
/// ([`KeySemantics::data_keys`](anykms_core::KeySemantics::data_keys)).
pub(crate) async fn source_aad<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let kind = source_kind(&c);
    let key = c.key(kind).await?;
    let src = c.data_keys(&key.uri).ctx("open data_keys")?;
    let aad = data_key_aad(&require_semantics(src.semantics(), kind)?)?;
    let r = src.generate_data_key(DataKeySpec::Aes256, b"ctx").await;
    if aad_refused(aad, &r) {
        expect_kind(r, ErrorKind::Unsupported, "generate_data_key with AAD")?;
    } else {
        let dk = r.ctx("generate_data_key with AAD")?;
        ensure!(
            *unwrap(&c, kind, &key.uri, dk.ciphertext(), b"ctx")
                .await
                .ctx("unwrap with AAD")?
                == *dk.plaintext(),
            "differs"
        );
        expect_kind(
            unwrap(&c, kind, &key.uri, dk.ciphertext(), b"").await,
            ErrorKind::DecryptFailed,
            "data key not bound to AAD",
        )?;
    }
    Ok(())
}

/// `KeyWrapDataKeys` over a KEK of `kind` (an AEAD key as a KEK, or a native key-wrapping key):
/// the data key unwraps with `unwrap_key`, and AAD, which the recipe cannot bind, is
/// `Unsupported` before any request.
pub(crate) async fn keywrap_data_keys<F: Fixture>(c: Ctx<F>, kind: TestKeyKind) -> CaseResult {
    let key = c.key(kind).await?;
    let kek = c.key_wrap(&key.uri).ctx("open")?;
    let dks = KeyWrapDataKeys::new(kek.clone());
    let dk = dks
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .ctx("generate_data_key")?;
    ensure!(
        dk.plaintext().len() == 32,
        "data key has {} bytes",
        dk.plaintext().len()
    );
    ensure!(
        *kek.unwrap_key(dk.ciphertext()).await.ctx("unwrap_key")? == *dk.plaintext(),
        "unwrapped data key differs"
    );
    let r = if c.caps.has(Feature::RequestCount) {
        let (cc, requests) = c.counting()?;
        let before = requests();
        let r = KeyWrapDataKeys::new(cc.key_wrap(&key.uri).ctx("open counted")?)
            .generate_data_key(DataKeySpec::Aes256, b"ctx")
            .await;
        ensure!(
            requests() == before,
            "KeyWrapDataKeys sent a request for a data key with AAD"
        );
        r
    } else {
        dks.generate_data_key(DataKeySpec::Aes256, b"ctx").await
    };
    expect_kind(r, ErrorKind::Unsupported, "KeyWrapDataKeys with AAD")?;
    Ok(())
}
