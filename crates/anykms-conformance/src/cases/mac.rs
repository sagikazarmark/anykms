//! MAC cases, run for every algorithm.

use anykms_core::prelude::*;
use anykms_core::{
    Capabilities, Digest, ErrorKind, KeyState, MacAlgorithm, SignatureAlgorithm, Tag,
    UnversionedVerify, VersionShape,
};

use super::aead::{ensure_version_disabled, state_per_version};
use super::util::two;
use crate::ctx::{CaseResult, Check, Ctx, ensure, expect_kind};
use crate::fixture::{Feature, Fixture, TestKeyKind};

const DATA: &[u8] = b"token-id-1234";

pub(crate) async fn roundtrip<F: Fixture>(c: Ctx<F>, alg: MacAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Hmac(alg)).await?;
    let m = c.mac(&key.uri, alg).ctx("open")?;
    ensure!(
        m.mac_algorithm() == alg,
        "handle reports {}",
        m.mac_algorithm()
    );
    let tag = m.mac(DATA).await.ctx("mac")?;
    ensure!(tag.algorithm() == alg, "tag labeled {}", tag.algorithm());
    ensure!(
        tag.as_bytes().len() == alg.tag_len(),
        "tag length {} != {}",
        tag.as_bytes().len(),
        alg.tag_len()
    );
    ensure!(tag.key_version().is_some(), "tag has no key version");
    if let Some(v) = &key.version {
        ensure!(
            tag.key_version() == Some(v),
            "the key's URI pins version {v}, but the tag has {:?}",
            tag.key_version()
        );
    }
    m.verify_mac(DATA, &tag).await.ctx("verify_mac")?;
    let again = m.mac(DATA).await.ctx("mac again")?;
    ensure!(
        again.as_bytes() == tag.as_bytes(),
        "HMAC is not deterministic"
    );
    Ok(())
}

pub(crate) async fn failures<F: Fixture>(c: Ctx<F>, alg: MacAlgorithm) -> CaseResult {
    let [ka, kb] = two(c.keys(TestKeyKind::Hmac(alg), 2).await?);
    let a = c.mac(&ka.uri, alg).ctx("open a")?;
    let b = c.mac(&kb.uri, alg).ctx("open b")?;
    let sem = c.semantics_or_caps(a.semantics(), ka.kind)?;
    let tag = a.mac(DATA).await.ctx("mac")?;
    expect_kind(
        a.verify_mac(b"other", &tag).await,
        ErrorKind::VerificationFailed,
        "tampered data",
    )?;
    let mut bytes = tag.as_bytes().to_vec();
    bytes[0] ^= 1;
    let flipped = Tag::from_parts(alg, tag.key_version().cloned(), bytes);
    expect_kind(
        a.verify_mac(DATA, &flipped).await,
        ErrorKind::VerificationFailed,
        "tampered tag",
    )?;
    let truncated = Tag::from_parts(
        alg,
        tag.key_version().cloned(),
        tag.as_bytes()[..16].to_vec(),
    );
    expect_kind(
        a.verify_mac(DATA, &truncated).await,
        ErrorKind::VerificationFailed,
        "truncated tag",
    )?;
    // Another key's tag, labeled with that key's version: `VerificationFailed` where versions
    // are numbered per key (the label names one of this key's versions), and where they are
    // unique across keys (the label names a version this key does not have; A3(a)).
    let theirs = b.mac(DATA).await.ctx("mac with another key")?;
    match sem.version_shape() {
        VersionShape::Opaque => {
            let e = expect_kind(
                a.verify_mac(DATA, &theirs).await,
                ErrorKind::VerificationFailed,
                "another key's tag",
            )?;
            ensure!(
                e.is_caller_error(),
                "another key's tag: {e} is not a caller error"
            );
        }
        _ => {
            expect_kind(
                b.verify_mac(DATA, &tag).await,
                ErrorKind::VerificationFailed,
                "another key's tag",
            )?;
        }
    }
    let other = MacAlgorithm::ALL
        .iter()
        .copied()
        .find(|x| *x != alg)
        .expect("several algorithms");
    let relabeled = Tag::from_parts(other, tag.key_version().cloned(), tag.as_bytes().to_vec());
    expect_kind(
        a.verify_mac(DATA, &relabeled).await,
        ErrorKind::InvalidArgument,
        "tag of another algorithm",
    )?;
    let unversioned = Tag::from_parts(alg, None, tag.as_bytes().to_vec());
    match sem.unversioned_verify() {
        UnversionedVerify::UsesCurrent => a
            .verify_mac(DATA, &unversioned)
            .await
            .ctx("verify unversioned tag (uses the current version)")?,
        _ => {
            expect_kind(
                a.verify_mac(DATA, &unversioned).await,
                ErrorKind::InvalidArgument,
                "unversioned tag",
            )?;
        }
    }
    if let Some(v) = c.fx.malformed_version() {
        let odd = Tag::from_parts(alg, Some(v), tag.as_bytes().to_vec());
        expect_kind(
            a.verify_mac(DATA, &odd).await,
            ErrorKind::InvalidArgument,
            "malformed tag version",
        )?;
    }
    Ok(())
}

pub(crate) async fn rotation<F: Fixture>(c: Ctx<F>, alg: MacAlgorithm) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Hmac(alg)).await?;
    let m = c.mac(&key.uri, alg).ctx("open")?;
    let t1 = m.mac(DATA).await.ctx("mac v1")?;
    let new = c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let m2 = c.mac(&new.uri, alg).ctx("open after rotation")?;
    let (m2r, v1) = (&m2, t1.key_version().cloned());
    let t2 = c
        .settled(move || {
            let v1 = v1.clone();
            async move {
                let t2 = m2r.mac(DATA).await.ctx("mac v2")?;
                ensure!(
                    t2.key_version() != v1.as_ref(),
                    "tag version did not change after rotation"
                );
                Ok(t2)
            }
        })
        .await?;
    ensure!(
        t1.as_bytes() != t2.as_bytes(),
        "rotation did not change the key"
    );
    if new.uri != key.uri {
        // The URIs pin versions: the old one keeps using its version.
        let again = m.mac(DATA).await.ctx("mac with the old URI")?;
        ensure!(
            again.key_version() == t1.key_version(),
            "the old URI MACs with version {:?} after rotation, not its pinned {:?}",
            again.key_version(),
            t1.key_version()
        );
    }
    m.verify_mac(DATA, &t1)
        .await
        .ctx("verify pre-rotation tag")?;
    m2.verify_mac(DATA, &t2)
        .await
        .ctx("verify post-rotation tag")?;
    Ok(())
}

/// Input of the backend's maximum length is MACed; one byte more is `InvalidArgument`.
pub(crate) async fn input_limit<F: Fixture>(c: Ctx<F>, alg: MacAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Hmac(alg)).await?;
    let m = c.mac(&key.uri, alg).ctx("open")?;
    let n = c
        .semantics_or_caps(m.semantics(), key.kind)?
        .max_mac_input()
        .ok_or("MacInputLimit is declared, but the MAC handle declares no max_mac_input")?;
    let data = vec![0x42; n];
    let tag = m.mac(&data).await.ctx("mac of the maximum length")?;
    m.verify_mac(&data, &tag)
        .await
        .ctx("verify_mac of the maximum length")?;
    expect_kind(
        m.mac(&vec![0x42; n + 1]).await,
        ErrorKind::InvalidArgument,
        "mac over the maximum length",
    )?;
    Ok(())
}

/// Empty input is MACed and verified ([`Feature::EmptyMessage`]).
pub(crate) async fn empty_input<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    let m = c.mac(&key.uri, MacAlgorithm::HmacSha256).ctx("open")?;
    let tag = m.mac(b"").await.ctx("mac of empty input")?;
    m.verify_mac(b"", &tag)
        .await
        .ctx("verify_mac of empty input")?;
    expect_kind(
        m.verify_mac(DATA, &tag).await,
        ErrorKind::VerificationFailed,
        "the empty input's tag over other data",
    )?;
    Ok(())
}

/// A disabled version: MACing with it fails with `KeyStateInvalid` (the handle chose the
/// version: config class), verifying its tags with `KeyVersionUnusable` (caller class), and
/// describe lists it disabled.
pub(crate) async fn disabled_version<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c
        .fresh_key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256))
        .await?;
    let m = c.mac(&key.uri, MacAlgorithm::HmacSha256).ctx("open")?;
    let sem = c.semantics_or_caps(m.semantics(), key.kind)?;
    let tag = m.mac(DATA).await.ctx("mac")?;
    let v = tag
        .key_version()
        .cloned()
        .ok_or("tag carries no key version")?;
    c.fx.disable_version(&key, &v)
        .await
        .ctx("fixture disable_version")?;
    let (mr, tagr) = (&m, &tag);
    c.settled(move || async move {
        let e = expect_kind(
            mr.mac(DATA).await,
            ErrorKind::KeyStateInvalid,
            "mac with a disabled version",
        )?;
        ensure!(
            e.is_config_error(),
            "mac with a disabled version: {e} is not a config error"
        );
        let e = expect_kind(
            mr.verify_mac(DATA, tagr).await,
            ErrorKind::KeyVersionUnusable,
            "verify a tag of a disabled version",
        )?;
        ensure!(
            e.is_caller_error(),
            "verify a tag of a disabled version: {e} is not a caller error"
        );
        Ok(())
    })
    .await?;
    if c.caps.has(Feature::Describe) && sem.versions_listed() {
        let info = c
            .describe_key(&key)
            .ctx("open describe")?
            .describe()
            .await
            .ctx("describe")?;
        ensure_version_disabled(&info, &v, state_per_version(&sem))?;
    }
    Ok(())
}

pub(crate) async fn describe<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    let sem = c.semantics(&key)?;
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    ensure!(
        info.capabilities().contains(Capabilities::MAC),
        "capabilities {:?} lack MAC",
        info.capabilities()
    );
    ensure!(
        !info.capabilities().contains(Capabilities::AEAD)
            && !info.capabilities().contains(Capabilities::SIGN),
        "HMAC key reports capabilities {:?}",
        info.capabilities()
    );
    ensure!(
        // Backends without key-level state report `None`.
        matches!(info.state(), None | Some(KeyState::Enabled)),
        "state {:?}",
        info.state()
    );
    if state_per_version(&sem) {
        ensure!(
            info.state().is_none(),
            "key-level state {:?}, but the handle declares state per version",
            info.state()
        );
    }
    ensure!(
        info.signature_algorithms().is_empty(),
        "HMAC key lists signature algorithms {:?}",
        info.signature_algorithms()
    );
    ensure!(
        !info.backend_key_type().is_empty(),
        "empty backend key type"
    );
    let tag = c
        .mac(&key.uri, MacAlgorithm::HmacSha256)
        .ctx("open mac")?
        .mac(DATA)
        .await
        .ctx("mac")?;
    let current = tag.key_version().ok_or("tag has no key version")?;
    if sem.primary_reported() && key.version.is_none() {
        let primary = info.primary_version().ok_or("no primary version")?;
        ensure!(
            current == primary,
            "tag version {current} != primary version {primary}"
        );
    }
    // Transit lists no versions for HMAC keys (KeySemantics::versions_listed).
    if sem.versions_listed() {
        let entry = info
            .versions()
            .iter()
            .find(|v| v.version() == current)
            .ok_or_else(|| {
                format!(
                    "describe versions {:?} lack the tag's version {current}",
                    info.versions()
                )
            })?;
        ensure!(
            *entry.state() == KeyState::Enabled,
            "the tag's version state {:?}",
            entry.state()
        );
    }
    Ok(())
}

/// Using a key of the wrong type is a deployment problem (`KeyMismatch`), not bad input. An AEAD
/// key opened as a MAC key:
pub(crate) async fn aead_key_as_mac<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let aead = c.key(TestKeyKind::Aead).await?;
    let r = match c.mac(&aead.uri, MacAlgorithm::HmacSha256) {
        Ok(m) => m.mac(DATA).await.map(|_| ()),
        Err(e) => Err(e),
    };
    expect_kind(r, ErrorKind::KeyMismatch, "AEAD key opened as a MAC key")?;
    Ok(())
}

/// An HMAC key opened as an AEAD key is `KeyMismatch`.
pub(crate) async fn hmac_key_as_aead<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let hmac = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    let r = match c.aead(&hmac.uri) {
        Ok(k) => k.encrypt(DATA, b"").await.map(|_| ()),
        Err(e) => Err(e),
    };
    expect_kind(r, ErrorKind::KeyMismatch, "HMAC key opened as an AEAD key")?;
    Ok(())
}

/// A signing key opened as a MAC key, and an HMAC key opened as a signer, are `KeyMismatch`.
pub(crate) async fn signing_key_as_mac<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let signing = c.key(TestKeyKind::Signing(alg)).await?;
    let r = match c.mac(&signing.uri, MacAlgorithm::HmacSha256) {
        Ok(m) => m.mac(DATA).await.map(|_| ()),
        Err(e) => Err(e),
    };
    expect_kind(r, ErrorKind::KeyMismatch, "signing key opened as a MAC key")?;
    let hmac = c.key(TestKeyKind::Hmac(MacAlgorithm::HmacSha256)).await?;
    let r = match c.digest_signer(&hmac.uri, alg) {
        Ok(s) => s.sign_digest(&Digest::sha256(DATA)).await.map(|_| ()),
        Err(e) => Err(e),
    };
    expect_kind(r, ErrorKind::KeyMismatch, "HMAC key opened as a signer")?;
    Ok(())
}

/// Describe's per-version algorithms (`KeyVersionInfo::mac_algorithm`), where the backend
/// reports them (GCP; the others leave them `None`): every version of a key asked for
/// HMAC-SHA256 reports it or nothing, all versions alike, and none reports a signature algorithm.
pub(crate) async fn version_algorithms<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let alg = MacAlgorithm::HmacSha256;
    let key = c.key(TestKeyKind::Hmac(alg)).await?;
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    let reported: Vec<_> = info.versions().iter().map(|v| v.mac_algorithm()).collect();
    ensure!(
        reported.iter().all(|a| a.is_none()) || reported.iter().all(|a| *a == Some(alg)),
        "{alg} key versions report the MAC algorithms {reported:?}"
    );
    ensure!(
        info.versions()
            .iter()
            .all(|v| v.signature_algorithm().is_none()),
        "{alg} key versions report a signature algorithm: {:?}",
        info.versions()
    );
    Ok(())
}
