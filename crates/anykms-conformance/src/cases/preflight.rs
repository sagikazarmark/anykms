//! Preflight against keys and versions that cannot be used.

use anykms_core::prelude::*;
use std::sync::Arc;

use anykms_core::{
    DescribeKey, ErrorKind, KeyInfo, KeyVersion, MacAlgorithm, Operation, SignatureAlgorithm,
    VersionModel,
};

use super::aead::written_version;
use crate::ctx::{CaseResult, Check, Ctx, ensure, expect_kind};
use crate::fixture::{Feature, Fixture, TestKey, TestKeyKind};

/// The key kinds the fixture declares, one per family: AEAD, native key wrapping, HMAC-SHA-256,
/// and the first digest and the first message signing algorithm it supports.
fn declared_kinds<F: Fixture>(c: &Ctx<F>) -> Vec<TestKeyKind> {
    let has = |f| c.caps.has(f);
    let mut kinds = Vec::new();
    if has(Feature::Aead) {
        kinds.push(TestKeyKind::Aead);
    }
    if has(Feature::KeyWrap) {
        kinds.push(TestKeyKind::KeyWrap);
    }
    if has(Feature::Mac) {
        kinds.push(TestKeyKind::Hmac(MacAlgorithm::HmacSha256));
    }
    for message in [false, true] {
        if let Some(&alg) = SignatureAlgorithm::ALL
            .iter()
            .find(|a| a.is_message_signing() == message && has(Feature::Signing(**a)))
        {
            kinds.push(TestKeyKind::Signing(alg));
        }
    }
    kinds
}

/// Opens the handle of `key`'s kind on this path (an AEAD key, a key-wrapping key, a MAC key or
/// a signer) and runs its `preflight()`.
async fn preflight_of<F: Fixture>(c: &Ctx<F>, key: &TestKey) -> anykms_core::Result<KeyInfo> {
    let uri = &key.uri;
    match key.kind {
        TestKeyKind::Aead => c.aead(uri)?.preflight().await,
        TestKeyKind::KeyWrap => c.key_wrap(uri)?.preflight().await,
        TestKeyKind::Hmac(alg) => c.mac(uri, alg)?.preflight().await,
        TestKeyKind::Signing(alg) if alg.is_message_signing() => {
            c.message_signer(uri, alg)?.preflight().await
        }
        TestKeyKind::Signing(alg) => c.digest_signer(uri, alg)?.preflight().await,
    }
}

/// Checks that `preflight()` of `key`'s handle refuses it with `KeyStateInvalid`, labelled
/// `Operation::Describe`, within the settle time.
async fn expect_refused<F: Fixture>(c: &Ctx<F>, key: &TestKey, what: &str) -> CaseResult {
    c.settled(|| async {
        let e = expect_kind(
            preflight_of(c, key).await,
            ErrorKind::KeyStateInvalid,
            &format!("preflight of a {:?} key {what}", key.kind),
        )?;
        ensure!(
            e.operation() == Operation::Describe,
            "preflight of a {:?} key {what}: the refusal is labelled {:?}, expected Describe",
            key.kind,
            e.operation()
        );
        Ok(())
    })
    .await
}

/// `preflight()` refuses a disabled key with `KeyStateInvalid` (a deployment problem found at
/// startup, not on first use), for every key family the fixture declares. On the typed path the
/// check is the typed handle's own `Preflight` where it has one.
pub(crate) async fn preflight_disabled<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let kinds = declared_kinds(&c);
    ensure!(!kinds.is_empty(), "the fixture declares no key kind");
    for kind in kinds {
        let key = c.fresh_key(kind).await?;
        preflight_of(&c, &key)
            .await
            .ctx(&format!("preflight of an enabled {kind:?} key"))?;
        c.fx.disable(&key).await.ctx("fixture disable")?;
        expect_refused(&c, &key, "after it was disabled").await?;
    }
    Ok(())
}

/// The version a write through `key`'s handle uses (see [`written_version`]); a floating handle
/// whose `describe` reports no primary version fails the case.
async fn write_version<F: Fixture>(c: &Ctx<F>, key: &TestKey) -> Result<KeyVersion, String> {
    let sem = c.semantics(key)?;
    let info = c
        .describe_key(key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    written_version(&sem, key, &info)?.cloned().ok_or_else(|| {
        format!(
            "describe reports no primary version of the {:?} key, so the version its writes use \
             cannot be disabled",
            key.kind
        )
    })
}

/// `preflight()` refuses a key whose write version (the version its URI pins, or the primary
/// version) is disabled, with `KeyStateInvalid`, even where state is per version only.
pub(crate) async fn preflight_disabled_version<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let kinds = declared_kinds(&c);
    ensure!(!kinds.is_empty(), "the fixture declares no key kind");
    for kind in kinds {
        let key = c.fresh_key(kind).await?;
        preflight_of(&c, &key)
            .await
            .ctx(&format!("preflight of an enabled {kind:?} key"))?;
        let v = write_version(&c, &key).await?;
        c.fx.disable_version(&key, &v)
            .await
            .ctx("fixture disable_version")?;
        expect_refused(&c, &key, &format!("whose write version {v} was disabled")).await?;
    }
    Ok(())
}

/// The generic `preflight()`, of a handle with a describe part and no backend `Preflight` part
/// (a bridged or third-party handle), refuses a key whose primary version is disabled, from the
/// version state `describe()` lists. Floating key kinds whose describe reports the primary only:
/// a pinned handle writes with its pin, which the generic check cannot see.
pub(crate) async fn generic_preflight_disabled_primary<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let mut checked = 0;
    for kind in declared_kinds(&c) {
        let key = c.fresh_key(kind).await?;
        let sem = c.semantics(&key)?;
        if sem.version_model() == VersionModel::Pinned || !sem.primary_reported() {
            continue;
        }
        // A describe handle over this path's describe handle: no `Preflight` part, so its
        // preflight is core's generic check.
        let generic = || -> anykms_core::Result<DescribeKey> {
            let d = c.describe_key(&key)?;
            Ok(DescribeKey::new(d.backend_name(), Arc::new(d)))
        };
        generic()
            .ctx("open describe")?
            .preflight()
            .await
            .ctx(&format!("generic preflight of an enabled {kind:?} key"))?;
        let v = write_version(&c, &key).await?;
        c.fx.disable_version(&key, &v)
            .await
            .ctx("fixture disable_version")?;
        c.settled(|| async {
            let what = format!(
                "generic preflight of a {kind:?} key whose primary version {v} was disabled"
            );
            let e = expect_kind(
                generic().ctx("open describe")?.preflight().await,
                ErrorKind::KeyStateInvalid,
                &what,
            )?;
            ensure!(
                e.operation() == Operation::Describe,
                "{what}: the refusal is labelled {:?}, expected Describe",
                e.operation()
            );
            Ok(())
        })
        .await?;
        checked += 1;
    }
    ensure!(
        checked > 0,
        "no declared key kind is floating with a reported primary version; declare \
         DisableVersion not applicable"
    );
    Ok(())
}
