//! Aead, Rewrap, DataKeys and Describe cases.

use anykms_core::prelude::*;
use anykms_core::{
    Capabilities, DataKeyAad, DataKeySpec, ErrorKind, KeyInfo, KeySemantics, KeyState, KeyVersion,
    Operation, StateScope, VersionModel,
};

use super::util::{tamper, truncate, two};
use crate::ctx::{CaseResult, Check, Ctx, ensure, expect_kind, require_semantics};
use crate::fixture::{Feature, Fixture, TestKey, TestKeyKind};

/// Whether only versions have a state ([`StateScope::VersionOnly`]).
pub(crate) fn state_per_version(s: &KeySemantics) -> bool {
    s.state_scope() == StateScope::VersionOnly
}

/// The version a write through `key`'s handle uses, where known: the version the URI pins for a
/// [`VersionModel::Pinned`] handle (whatever `describe` reports as primary), else the primary
/// version `describe` reports, if it reports one.
pub(crate) fn written_version<'a>(
    s: &KeySemantics,
    key: &'a TestKey,
    info: &'a KeyInfo,
) -> Result<Option<&'a KeyVersion>, String> {
    if s.version_model() == VersionModel::Pinned {
        return key.version.as_ref().map(Some).ok_or_else(|| {
            format!(
                "the {:?} handle is pinned, but the fixture's key names no version",
                key.kind
            )
        });
    }
    Ok(if s.primary_reported() {
        Some(
            info.primary_version()
                .ok_or("describe reports no primary version")?,
        )
    } else {
        None
    })
}

/// What the handle does with data-key AAD: its [`KeySemantics::data_keys`] source's AAD. A
/// handle whose semantics declare no data-key source fails the case (the fixture declares data
/// keys).
pub(crate) fn data_key_aad(s: &KeySemantics) -> Result<DataKeyAad, String> {
    s.data_keys().map(|d| d.aad()).ok_or_else(|| {
        "the fixture declares data keys, but the handle's semantics declare no data-key source"
            .to_owned()
    })
}

/// Whether a data-key request with non-empty AAD must be (or, for
/// [`DataKeyAad::BoundOrRefused`], was) refused; otherwise the key must be bound to the AAD.
/// AAD is never ignored either way.
pub(crate) fn aad_refused<T>(aad: DataKeyAad, r: &anykms_core::Result<T>) -> bool {
    match aad {
        DataKeyAad::Refused => true,
        DataKeyAad::BoundOrRefused => {
            matches!(r, Err(e) if e.kind() == ErrorKind::Unsupported)
        }
        _ => false,
    }
}

/// The largest plaintext `roundtrip` encrypts, unless the backend's limit is lower.
const ROUNDTRIP_MAX: usize = 64 * 1024;

pub(crate) async fn roundtrip<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let big = require_semantics(k.semantics(), key.kind)?
        .max_plaintext()
        .map_or(ROUNDTRIP_MAX, |m| m.min(ROUNDTRIP_MAX));
    for pt in [vec![7u8], vec![0xab; big]] {
        let ct = k.encrypt(&pt, b"aad-1").await.ctx("encrypt")?;
        let back = k.decrypt(&ct, b"aad-1").await.ctx("decrypt")?;
        ensure!(
            *back == pt,
            "round trip of {} bytes returned different plaintext",
            pt.len()
        );
    }
    let a = k.encrypt(b"same", b"").await.ctx("encrypt")?;
    let b = k.encrypt(b"same", b"").await.ctx("encrypt")?;
    ensure!(a != b, "encryption is deterministic");
    Ok(())
}

/// An empty plaintext round-trips ([`Feature::EmptyPlaintext`]).
pub(crate) async fn roundtrip_empty<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let ct = k.encrypt(b"", b"aad-1").await.ctx("encrypt empty")?;
    ensure!(
        k.decrypt(&ct, b"aad-1")
            .await
            .ctx("decrypt empty")?
            .is_empty(),
        "empty round trip returned a plaintext"
    );
    Ok(())
}

pub(crate) async fn authentication_failures<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let [ka, kb] = two(c.keys(TestKeyKind::Aead, 2).await?);
    let a = c.aead(&ka.uri).ctx("open a")?;
    let b = c.aead(&kb.uri).ctx("open b")?;
    let ct = a.encrypt(b"secret", b"aad").await.ctx("encrypt")?;
    expect_kind(
        a.decrypt(&ct, b"other").await,
        ErrorKind::DecryptFailed,
        "wrong AAD",
    )?;
    expect_kind(
        a.decrypt(&ct, b"").await,
        ErrorKind::DecryptFailed,
        "missing AAD",
    )?;
    expect_kind(
        a.decrypt(&tamper(&ct), b"aad").await,
        ErrorKind::DecryptFailed,
        "tampered ciphertext",
    )?;
    expect_kind(
        a.decrypt(&truncate(&ct), b"aad").await,
        ErrorKind::DecryptFailed,
        "truncated ciphertext",
    )?;
    expect_kind(
        b.decrypt(&ct, b"aad").await,
        ErrorKind::DecryptFailed,
        "another key's ciphertext",
    )?;
    Ok(())
}

/// The version a fresh ciphertext of `k` is on: its `ciphertext_version`, else the primary
/// version from `describe`.
async fn current_version(k: &anykms_core::AeadKey) -> Result<KeyVersion, String> {
    let ct = k.encrypt(b"probe", b"").await.ctx("encrypt probe")?;
    if let Some(v) = k.ciphertext_version(&ct).ctx("ciphertext_version")? {
        return Ok(v);
    }
    let none = || "neither the ciphertext nor describe reveals the current version".to_owned();
    if !k.supports_describe() {
        return Err(none());
    }
    k.describe()
        .await
        .ctx("describe")?
        .primary_version()
        .cloned()
        .ok_or_else(none)
}

pub(crate) async fn rotation<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let sem = require_semantics(k.semantics(), key.kind)?;
    let ct1 = k.encrypt(b"before", b"x").await.ctx("encrypt v1")?;
    let v1 = k.ciphertext_version(&ct1).ctx("ciphertext_version")?;
    c.fx.rotate(&key).await.ctx("fixture rotate")?;
    ensure!(
        *k.decrypt(&ct1, b"x").await.ctx("decrypt old version")? == *b"before",
        "old ciphertext changed"
    );
    let k = &k;
    let v1 = &v1;
    let (ct2, v2) = c
        .settled(move || async move {
            let ct2 = k.encrypt(b"after", b"x").await.ctx("encrypt v2")?;
            let v2 = k.ciphertext_version(&ct2).ctx("ciphertext_version")?;
            if let (Some(a), Some(b)) = (v1, &v2) {
                ensure!(a != b, "new ciphertext still uses version {a}");
            }
            Ok((ct2, v2))
        })
        .await?;
    ensure!(
        *k.decrypt(&ct2, b"x").await.ctx("decrypt new version")? == *b"after",
        "new ciphertext does not decrypt"
    );
    if sem.ciphertext_reveals_version() {
        ensure!(
            v1.is_some() && v2.is_some(),
            "ciphertext_version returned {v1:?} / {v2:?}, but the backend reports versions"
        );
    } else {
        ensure!(
            v1.is_none() && v2.is_none(),
            "ciphertext_version returned {v1:?} / {v2:?}, but the handle declares that \
             ciphertexts do not reveal their version"
        );
    }
    if let (Some(v1), Some(v2)) = (v1, &v2) {
        if let (Some(a), Some(b)) = (v1.as_u64(), v2.as_u64()) {
            ensure!(b > a, "version did not increase ({a} -> {b})");
        }
        if k.supports_describe() && sem.primary_reported() {
            let info = k.describe().await.ctx("describe")?;
            ensure!(
                info.primary_version() == Some(v2),
                "describe primary {:?} != {v2}",
                info.primary_version()
            );
        }
    }
    Ok(())
}

pub(crate) async fn min_decryption_version<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let ct1 = k.encrypt(b"old", b"").await.ctx("encrypt v1")?;
    c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let ct2 = k.encrypt(b"new", b"").await.ctx("encrypt v2")?;
    let v2 = match k.ciphertext_version(&ct2).ctx("ciphertext_version")? {
        Some(v) => v,
        None => current_version(&k).await?,
    };
    c.fx.set_min_decryption_version(&key, &v2)
        .await
        .ctx("fixture set_min_decryption_version")?;
    let (k, ct1) = (&k, &ct1);
    c.settled(move || async move {
        expect_kind(
            k.decrypt(ct1, b"").await,
            ErrorKind::KeyVersionUnusable,
            "decrypt below min version",
        )
        .map(drop)
    })
    .await?;
    ensure!(
        *k.decrypt(&ct2, b"").await.ctx("decrypt current")? == *b"new",
        "wrong plaintext"
    );
    Ok(())
}

/// Checks that `describe` reports the key disabled: the key-level state, or, where state is
/// per version, every version.
pub(crate) fn ensure_disabled(info: &KeyInfo, per_version: bool) -> CaseResult {
    if per_version {
        ensure!(
            info.state().is_none(),
            "key-level state {:?}, but the handle declares state per version",
            info.state()
        );
        ensure!(
            info.versions()
                .iter()
                .all(|v| *v.state() != KeyState::Enabled),
            "a disabled key lists enabled versions: {:?}",
            info.versions()
        );
    } else {
        ensure!(
            matches!(
                info.state(),
                Some(KeyState::Disabled | KeyState::PendingDeletion)
            ),
            "describe reports state {:?} for a disabled key",
            info.state()
        );
    }
    Ok(())
}

pub(crate) async fn disabled_key<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let per_version = state_per_version(&require_semantics(k.semantics(), key.kind)?);
    let ct = k.encrypt(b"x", b"").await.ctx("encrypt")?;
    c.fx.disable(&key).await.ctx("fixture disable")?;
    let (k, ct) = (&k, &ct);
    c.settled(move || async move {
        let info = k.describe().await.ctx("describe disabled key")?;
        ensure_disabled(&info, per_version)?;
        expect_kind(
            k.encrypt(b"x", b"").await,
            ErrorKind::KeyStateInvalid,
            "encrypt with disabled key",
        )?;
        expect_kind(
            k.decrypt(ct, b"").await,
            ErrorKind::KeyStateInvalid,
            "decrypt with disabled key",
        )?;
        Ok(())
    })
    .await
}

/// A disabled native key-wrapping key refuses to wrap with `KeyStateInvalid`, once `describe`
/// has refreshed what the handle knows of it: an RSA key-wrapping key that wraps locally with
/// its public key checks the key state it read, so it never wraps a data key that only a
/// disabled (or soon deleted) key could unwrap.
pub(crate) async fn key_wrap_disabled_key<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::KeyWrap).await?;
    let kw = c.key_wrap(&key.uri).ctx("open")?;
    let per_version = state_per_version(&require_semantics(kw.semantics(), key.kind)?);
    kw.wrap_key(&[7; 32]).await.ctx("wrap_key")?;
    c.fx.disable(&key).await.ctx("fixture disable")?;
    let kw = &kw;
    c.settled(move || async move {
        let info = kw.describe().await.ctx("describe disabled key")?;
        ensure_disabled(&info, per_version)?;
        expect_kind(
            kw.wrap_key(&[7; 32]).await,
            ErrorKind::KeyStateInvalid,
            "wrap_key with a disabled key",
        )?;
        Ok(())
    })
    .await
}

/// Checks that `describe` lists `version` as disabled.
pub(crate) fn ensure_version_disabled(
    info: &KeyInfo,
    version: &KeyVersion,
    per_version: bool,
) -> CaseResult {
    let entry = info
        .versions()
        .iter()
        .find(|v| v.version() == version)
        .ok_or_else(|| {
            format!(
                "describe versions {:?} lack the disabled version {version}",
                info.versions()
            )
        })?;
    ensure!(
        matches!(entry.state(), KeyState::Disabled),
        "disabled version {version} has state {:?}",
        entry.state()
    );
    if per_version {
        ensure!(
            info.state().is_none(),
            "key-level state {:?}, but the fixture reports state per version",
            info.state()
        );
    }
    Ok(())
}

/// A disabled old version: its ciphertexts fail with `KeyVersionUnusable` (caller class: the
/// ciphertext chose the version), while the primary version keeps working.
pub(crate) async fn disabled_version<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let per_version = state_per_version(&require_semantics(k.semantics(), key.kind)?);
    let v1 = current_version(&k).await?;
    let ct1 = k.encrypt(b"old", b"").await.ctx("encrypt v1")?;
    c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let k = &k;
    let v1 = &v1;
    c.settled(move || async move {
        ensure!(
            current_version(k).await? != *v1,
            "rotation did not move the primary version off {v1}"
        );
        Ok(())
    })
    .await?;
    c.fx.disable_version(&key, v1)
        .await
        .ctx("fixture disable_version")?;
    let ct1 = &ct1;
    c.settled(move || async move {
        let e = expect_kind(
            k.decrypt(ct1, b"").await,
            ErrorKind::KeyVersionUnusable,
            "decrypt on a disabled version",
        )?;
        ensure!(
            !e.is_config_error(),
            "decrypt on a disabled version: {e} is a config error, but the ciphertext chose \
             the version"
        );
        Ok(())
    })
    .await?;
    let ct2 = k.encrypt(b"new", b"").await.ctx("encrypt on the primary")?;
    ensure!(
        *k.decrypt(&ct2, b"").await.ctx("decrypt on the primary")? == *b"new",
        "wrong plaintext"
    );
    if c.caps.has(Feature::Describe) {
        let info = k.describe().await.ctx("describe")?;
        ensure_version_disabled(&info, v1, per_version)?;
    }
    Ok(())
}

/// A disabled primary version: encrypting fails with `KeyStateInvalid`, a deployment problem
/// (config class: the handle chose the version).
pub(crate) async fn disabled_primary_version<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let per_version = state_per_version(&require_semantics(k.semantics(), key.kind)?);
    let v = current_version(&k).await?;
    c.fx.disable_version(&key, &v)
        .await
        .ctx("fixture disable_version")?;
    let k = &k;
    c.settled(move || async move {
        let e = expect_kind(
            k.encrypt(b"x", b"").await,
            ErrorKind::KeyStateInvalid,
            "encrypt with a disabled primary version",
        )?;
        ensure!(
            e.is_config_error(),
            "encrypt with a disabled primary version: {e} is not a config error"
        );
        Ok(())
    })
    .await?;
    if c.caps.has(Feature::Describe) {
        let info = k.describe().await.ctx("describe")?;
        ensure_version_disabled(&info, &v, per_version)?;
    }
    Ok(())
}

pub(crate) async fn oversize_plaintext<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let n = c
        .caps
        .oversize_plaintext
        .ok_or("oversize_plaintext not set")?;
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    expect_kind(
        k.encrypt(&vec![0x5a; n], b"").await,
        ErrorKind::InvalidArgument,
        "oversize plaintext",
    )?;
    Ok(())
}

pub(crate) async fn native_ciphertext<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let ct =
        c.fx.encrypt_natively(&key, b"legacy")
            .await
            .ctx("fixture encrypt_natively")?
            .ok_or("no native ciphertext")?;
    ensure!(
        *k.decrypt(&ct, b"").await.ctx("decrypt native ciphertext")? == *b"legacy",
        "wrong plaintext"
    );
    Ok(())
}

pub(crate) async fn ciphertext_version<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let ct = k.encrypt(b"x", b"").await.ctx("encrypt")?;
    // Provided trait methods must be forwarded through the dyn layer, not defaulted to None.
    let v = k.ciphertext_version(&ct).ctx("ciphertext_version")?;
    let sem = require_semantics(k.semantics(), key.kind)?;
    if !sem.ciphertext_reveals_version() {
        ensure!(
            v.is_none(),
            "ciphertext_version {v:?}, but the handle declares that ciphertexts do not reveal \
             their version"
        );
        return Ok(());
    }
    let v = v.ok_or(
        "ciphertext_version returned None although the backend reports versions \
         (provided method defaulted instead of forwarded?)",
    )?;
    // A fresh key encrypts with its first version.
    ensure!(
        v.as_u64() == Some(1) || v.as_u64().is_none(),
        "fresh key's ciphertext has version {v}"
    );
    ensure!(k.supports_describe(), "AEAD key does not support describe");
    let info = k.describe().await.ctx("describe")?;
    if let Some(want) = written_version(&sem, &key, &info)? {
        ensure!(
            *want == v,
            "ciphertext_version {v} != the version writes use ({want})"
        );
    } else {
        ensure!(
            info.versions().iter().any(|x| *x.version() == v),
            "describe versions {:?} lack the ciphertext's version {v}",
            info.versions()
        );
    }
    // (`aead::rotation` checks forwarding across versions.)
    Ok(())
}

/// `decrypt_with_info` is forwarded through the dyn layer: it returns the plaintext and the
/// ciphertext's version, and never says a ciphertext on the primary version is not.
pub(crate) async fn decrypt_with_info<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let ct = k.encrypt(b"info", b"aad").await.ctx("encrypt")?;
    let d = k
        .decrypt_with_info(&ct, b"aad")
        .await
        .ctx("decrypt_with_info")?;
    ensure!(d.plaintext() == b"info", "wrong plaintext");
    let v = k.ciphertext_version(&ct).ctx("ciphertext_version")?;
    if v.is_some() {
        ensure!(
            d.key_version() == v.as_ref(),
            "decrypt_with_info reports version {:?}, the ciphertext has {v:?}",
            d.key_version()
        );
    }
    if require_semantics(k.semantics(), key.kind)?.reports_used_primary() {
        ensure!(
            d.used_primary() == Some(true),
            "used_primary {:?} for a ciphertext on the primary version",
            d.used_primary()
        );
    } else {
        ensure!(
            d.used_primary() != Some(false),
            "used_primary Some(false) for a ciphertext on the primary version"
        );
    }
    expect_kind(
        k.decrypt_with_info(&ct, b"other").await,
        ErrorKind::DecryptFailed,
        "decrypt_with_info with the wrong AAD",
    )?;
    Ok(())
}

/// After a rotation, `used_primary` tells old ciphertexts (due for a rewrap) from new ones.
pub(crate) async fn used_primary_after_rotation<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let v1 = current_version(&k).await?;
    let ct1 = k.encrypt(b"old", b"").await.ctx("encrypt v1")?;
    c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let (k, v1) = (&k, &v1);
    let ct2 = c
        .settled(move || async move {
            ensure!(
                current_version(k).await? != *v1,
                "rotation did not move the primary version off {v1}"
            );
            k.encrypt(b"new", b"").await.ctx("encrypt v2")
        })
        .await?;
    let old = k
        .decrypt_with_info(&ct1, b"")
        .await
        .ctx("decrypt_with_info old")?;
    ensure!(
        old.used_primary() == Some(false),
        "used_primary {:?} for a ciphertext on the old version",
        old.used_primary()
    );
    let new = k
        .decrypt_with_info(&ct2, b"")
        .await
        .ctx("decrypt_with_info new")?;
    ensure!(
        new.used_primary() == Some(true),
        "used_primary {:?} for a ciphertext on the new primary version",
        new.used_primary()
    );
    Ok(())
}

pub(crate) async fn rewrap<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    ensure!(k.supports_rewrap(), "AEAD key does not support rewrap");
    let ct1 = k.encrypt(b"payload", b"").await.ctx("encrypt")?;
    c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let ct2 = k.rewrap(&ct1, b"").await.ctx("rewrap")?;
    let probe = k.encrypt(b"probe", b"").await.ctx("encrypt probe")?;
    ensure!(
        k.ciphertext_version(&ct2).ctx("version")?
            == k.ciphertext_version(&probe).ctx("version")?,
        "rewrapped ciphertext is not on the primary version"
    );
    ensure!(
        *k.decrypt(&ct2, b"").await.ctx("decrypt rewrapped")? == *b"payload",
        "wrong plaintext"
    );
    Ok(())
}

pub(crate) async fn rewrap_with_aad<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let ct = k.encrypt(b"payload", b"bound").await.ctx("encrypt")?;
    if c.caps.has(Feature::RewrapWithAad) {
        let ct2 = k.rewrap(&ct, b"bound").await.ctx("rewrap with AAD")?;
        ensure!(
            *k.decrypt(&ct2, b"bound").await.ctx("decrypt")? == *b"payload",
            "wrong plaintext"
        );
        expect_kind(
            k.decrypt(&ct2, b"").await,
            ErrorKind::DecryptFailed,
            "rewrapped ciphertext lost its AAD binding",
        )?;
    } else {
        expect_kind(
            k.rewrap(&ct, b"bound").await,
            ErrorKind::Unsupported,
            "rewrap with AAD",
        )?;
    }
    Ok(())
}

pub(crate) async fn datakey_roundtrip<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    ensure!(
        k.supports_data_keys(),
        "AEAD key does not support data keys"
    );
    let dk = k
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .ctx("generate_data_key")?;
    ensure!(
        dk.plaintext().len() == 32,
        "data key has {} bytes",
        dk.plaintext().len()
    );
    let back = k
        .decrypt(dk.ciphertext(), b"")
        .await
        .ctx("decrypt data key")?;
    ensure!(*back == *dk.plaintext(), "unwrapped data key differs");
    ensure!(
        !format!("{dk:?}").contains(&format!("{:?}", dk.plaintext())),
        "DataKey Debug leaks the key"
    );
    Ok(())
}

pub(crate) async fn datakey_aad<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let aad = data_key_aad(&require_semantics(k.semantics(), key.kind)?)?;
    let r = k.generate_data_key(DataKeySpec::Aes256, b"ctx").await;
    if aad_refused(aad, &r) {
        expect_kind(r, ErrorKind::Unsupported, "generate_data_key with AAD")?;
    } else {
        let dk = r.ctx("generate_data_key with AAD")?;
        ensure!(
            *k.decrypt(dk.ciphertext(), b"ctx")
                .await
                .ctx("decrypt with AAD")?
                == *dk.plaintext(),
            "differs"
        );
        expect_kind(
            k.decrypt(dk.ciphertext(), b"").await,
            ErrorKind::DecryptFailed,
            "data key not bound to AAD",
        )?;
    }
    Ok(())
}

/// `preflight` accepts a key that fits the handle and refuses, before any operation, a key opened
/// for an operation it cannot do.
pub(crate) async fn preflight<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let info = c
        .aead(&key.uri)
        .ctx("open")?
        .preflight()
        .await
        .ctx("preflight")?;
    ensure!(
        info.capabilities().contains(Capabilities::AEAD),
        "capabilities {:?} lack AEAD",
        info.capabilities()
    );
    // The AEAD key opened as a signer: refused at open (backends that know the key type then) or
    // by the preflight, never only on first use.
    let alg = anykms_core::SignatureAlgorithm::EcdsaP256Sha256;
    match c.digest_signer(&key.uri, alg) {
        Ok(signer) => {
            let e = expect_kind(
                signer.preflight().await,
                ErrorKind::KeyMismatch,
                "preflight of an AEAD key as a signer",
            )?;
            ensure!(
                e.operation() == Operation::Describe,
                "preflight of an AEAD key as a signer: the refusal is labelled {:?}, expected \
                 Describe",
                e.operation()
            );
        }
        Err(e) => {
            expect_kind(
                Err::<(), _>(e),
                ErrorKind::KeyMismatch,
                "open an AEAD key as a signer",
            )?;
        }
    }
    Ok(())
}

/// Checks the key-level state and the primary (or, where none is reported, some enabled)
/// version of a usable key.
pub(crate) fn ensure_usable_versions(
    info: &KeyInfo,
    reports_primary: bool,
    per_version: bool,
) -> CaseResult {
    ensure!(
        // Backends without key-level state report `None`.
        matches!(info.state(), None | Some(KeyState::Enabled)),
        "state {:?}",
        info.state()
    );
    if per_version {
        ensure!(
            info.state().is_none(),
            "key-level state {:?}, but the handle declares state per version",
            info.state()
        );
    }
    if reports_primary {
        let primary = info.primary_version().ok_or("no primary version")?;
        let entry = info
            .versions()
            .iter()
            .find(|v| v.version() == primary)
            .ok_or_else(|| {
                format!(
                    "describe versions {:?} lack the primary version {primary}",
                    info.versions()
                )
            })?;
        ensure!(
            *entry.state() == KeyState::Enabled,
            "primary version state {:?}",
            entry.state()
        );
    } else {
        ensure!(
            info.versions()
                .iter()
                .any(|v| *v.state() == KeyState::Enabled),
            "describe lists no enabled version: {:?}",
            info.versions()
        );
    }
    Ok(())
}

/// A native key-wrapping key is described with `KEY_WRAP`, its versions, and wraps.
pub(crate) async fn describe_key_wrap<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::KeyWrap).await?;
    let sem = c.semantics(&key)?;
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    ensure!(
        info.capabilities().contains(Capabilities::KEY_WRAP),
        "capabilities {:?} lack KEY_WRAP",
        info.capabilities()
    );
    ensure!(
        !info.capabilities().contains(Capabilities::SIGN)
            && !info.capabilities().contains(Capabilities::MAC),
        "key-wrapping key reports capabilities {:?}",
        info.capabilities()
    );
    ensure_usable_versions(&info, sem.primary_reported(), state_per_version(&sem))?;
    ensure!(
        !info.backend_key_type().is_empty(),
        "empty backend key type"
    );
    let kw = c.key_wrap(&key.uri).ctx("open key_wrap")?;
    let w = kw.wrap_key(&[7; 32]).await.ctx("wrap_key")?;
    if let Some(v) = kw.wrapped_key_version(&w).ctx("wrapped_key_version")? {
        ensure!(
            info.versions().iter().any(|x| *x.version() == v),
            "describe versions {:?} lack the wrapped key's version {v}",
            info.versions()
        );
        if let Some(want) = written_version(&sem, &key, &info)? {
            ensure!(
                *want == v,
                "wrapped with version {v}, but writes use version {want}"
            );
        }
    }
    ensure!(
        *kw.unwrap_key(&w).await.ctx("unwrap_key")? == [7; 32],
        "unwrap_key returned another key"
    );
    Ok(())
}

pub(crate) async fn describe<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let sem = c.semantics(&key)?;
    let d = c.describe_key(&key).ctx("open describe")?;
    let info = d.describe().await.ctx("describe")?;
    ensure!(
        info.capabilities().contains(Capabilities::AEAD),
        "capabilities {:?} lack AEAD",
        info.capabilities()
    );
    ensure_usable_versions(&info, sem.primary_reported(), state_per_version(&sem))?;
    ensure!(
        !info.backend_key_type().is_empty(),
        "empty backend key type"
    );
    // KEY_WRAP is reported exactly when the key opens as a key-wrapping key that wraps.
    let wraps = match c.key_wrap(&key.uri) {
        Ok(kw) => {
            let w = kw.wrap_key(&[7; 32]).await.ctx("wrap_key")?;
            ensure!(
                *kw.unwrap_key(&w).await.ctx("unwrap_key")? == [7; 32],
                "unwrap_key returned another key"
            );
            true
        }
        Err(e) if e.kind() == ErrorKind::Unsupported => false,
        Err(e) => return Err(format!("open key_wrap: {e}")),
    };
    ensure!(
        info.capabilities().contains(Capabilities::KEY_WRAP) == wraps,
        "capabilities {:?} disagree with key_wrap (wraps: {wraps})",
        info.capabilities()
    );
    Ok(())
}
