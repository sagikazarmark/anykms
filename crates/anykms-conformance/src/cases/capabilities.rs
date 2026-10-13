//! The handles a fixture's provider returns have exactly the parts its declaration says.

use anykms_core::prelude::*;
use anykms_core::{
    Capabilities, DataKeySpec, Digest, ErrorKind, KeyInfo, MacAlgorithm, SignatureAlgorithm,
    VersionModel,
};

use crate::ctx::{CaseResult, Check, Ctx, RequestCounter, ensure, expect_kind};
use crate::fixture::{Feature, Fixture, TestKeyKind};

/// For every key kind the fixture declares, the handle's [`KeySemantics`] agree with the
/// declared features the harness gates on (they cannot come from the handle, which does not
/// exist yet when cases are gated):
///
/// - `UsedPrimary` declared ⇔ the AEAD handle's `reports_used_primary()` (other kinds: `false`);
/// - `MacInputLimit` declared ⇔ each HMAC handle's `max_mac_input().is_some()`;
/// - `MessageInputLimit` declared ⇔ each message-signing handle's
///   `max_signed_message().is_some()`;
/// - the version model follows the URI: `Pinned` exactly when the key's URI names a version;
/// - an AEAD handle that declares a data-key source has the data-keys part;
/// - a key-wrapping handle (native, or the AEAD key as a KEK) declares no data-key source and no
///   plaintext limit;
/// - every handle declares its semantics (`Semantics::semantics` is `Some`).
///
/// [`KeySemantics`]: anykms_core::KeySemantics
pub(crate) async fn semantics_match_caps<F: Fixture>(c: Ctx<F>) -> CaseResult {
    use Feature::*;
    let has = |f| c.caps.has(f);
    let mut kinds = Vec::new();
    if has(Aead) {
        kinds.push(TestKeyKind::Aead);
    }
    if has(KeyWrap) {
        kinds.push(TestKeyKind::KeyWrap);
    }
    if has(Mac) {
        kinds.extend(MacAlgorithm::ALL.iter().map(|&a| TestKeyKind::Hmac(a)));
    }
    kinds.extend(
        SignatureAlgorithm::ALL
            .iter()
            .filter(|&&a| has(Signing(a)))
            .map(|&a| TestKeyKind::Signing(a)),
    );
    ensure!(!kinds.is_empty(), "the fixture declares no key kind");
    for kind in kinds {
        let key = c.key(kind).await?;
        let Some(s) = c
            .declared_semantics(&key)
            .ctx(&format!("open the {kind:?} key"))?
        else {
            return Err(format!(
                "the {kind:?} handle declares no KeySemantics (Semantics::semantics is None)"
            ));
        };
        let what = format!("{kind:?} handle (semantics {s:?})");
        let used_primary = kind == TestKeyKind::Aead && has(UsedPrimary);
        ensure!(
            s.reports_used_primary() == used_primary,
            "{what}: reports_used_primary() is {}, but the fixture {} Feature::UsedPrimary",
            s.reports_used_primary(),
            if used_primary {
                "supports"
            } else if kind == TestKeyKind::Aead {
                "does not support"
            } else {
                "has no decrypt on this kind, whatever it declares for"
            }
        );
        if matches!(kind, TestKeyKind::Hmac(_)) {
            ensure!(
                s.max_mac_input().is_some() == has(MacInputLimit),
                "{what}: max_mac_input() is {:?}, but Feature::MacInputLimit is {:?}",
                s.max_mac_input(),
                c.caps.support(MacInputLimit)
            );
        }
        if matches!(kind, TestKeyKind::Signing(a) if a.is_message_signing()) {
            ensure!(
                s.max_signed_message().is_some() == has(MessageInputLimit),
                "{what}: max_signed_message() is {:?}, but Feature::MessageInputLimit is {:?}",
                s.max_signed_message(),
                c.caps.support(MessageInputLimit)
            );
        }
        if kind == TestKeyKind::Aead {
            let k = c.aead(&key.uri).ctx("open aead")?;
            ensure!(
                s.data_keys().is_none() || k.supports_data_keys(),
                "{what}: data_keys() is {:?}, but the AEAD handle has no data-keys part",
                s.data_keys()
            );
            let kw = c.key_wrap(&key.uri).ctx("open the AEAD key as a KEK")?;
            if let Some(ks) = kw.semantics() {
                kek_semantics(ks, &format!("the AEAD key as a KEK (semantics {ks:?})"))?;
            }
        }
        if kind == TestKeyKind::KeyWrap {
            kek_semantics(&s, &what)?;
        }
        ensure!(
            (s.version_model() == VersionModel::Pinned) == key.version.is_some(),
            "{what}: the version model is {:?}, but the key's URI {} a version",
            s.version_model(),
            if key.version.is_some() {
                "names"
            } else {
                "names no"
            }
        );
    }
    Ok(())
}

/// A key-wrapping handle makes no data keys and encrypts no plaintexts: its semantics declare
/// neither (`KeyWrapKey` has no such parts, whatever the key behind it can do).
fn kek_semantics(s: &anykms_core::KeySemantics, what: &str) -> CaseResult {
    ensure!(
        s.data_keys().is_none() && s.max_plaintext().is_none(),
        "{what}: a key-wrapping handle declares data_keys() {:?} and max_plaintext() {:?}, \
         expected None for both",
        s.data_keys(),
        s.max_plaintext()
    );
    Ok(())
}

/// For every declared key family: the handle's `supports_*` match the declared features, a part
/// the fixture does not declare supported is `Unsupported` (before any request, where the
/// fixture counts them), and `describe`'s capability bits agree with the declaration. A
/// backend whose handles claim parts it lacks, or lack parts it has, fails here.
pub(crate) async fn handles_match_declaration<F: Fixture>(c: Ctx<F>) -> CaseResult {
    use Feature::*;
    // Probes of missing parts go through a counted provider where there is one.
    let (cc, requests): (Ctx<F>, Option<RequestCounter>) = if c.caps.has(RequestCount) {
        let (cc, r) = c.counting()?;
        (cc, Some(r))
    } else {
        (c.clone(), None)
    };
    let count = || requests.as_ref().map(|r| r());
    let has = |f| c.caps.has(f);
    let mut checked = Vec::new();

    if has(Aead) {
        checked.push("aead");
        let key = c.key(TestKeyKind::Aead).await?;
        let k = c.aead(&key.uri).ctx("open aead")?;
        ensure!(
            k.supports_rewrap() == has(Rewrap)
                && k.supports_data_keys() == has(DataKeys)
                && k.supports_wrapped_data_keys() == has(WrappedDataKeys)
                && k.supports_describe() == has(Describe),
            "AEAD handle {k:?} disagrees with the declaration (rewrap {}, data keys {}, \
             wrapped data keys {}, describe {})",
            has(Rewrap),
            has(DataKeys),
            has(WrappedDataKeys),
            has(Describe)
        );
        let ct = k.encrypt(b"x", b"").await.ctx("encrypt")?;
        let kc = cc.aead(&key.uri).ctx("open counted aead")?;
        let before = count();
        if !has(Rewrap) {
            expect_kind(kc.rewrap(&ct, b"").await, ErrorKind::Unsupported, "rewrap")?;
        }
        if !has(DataKeys) {
            expect_kind(
                kc.generate_data_key(DataKeySpec::Aes256, b"").await,
                ErrorKind::Unsupported,
                "generate_data_key",
            )?;
        }
        if !has(WrappedDataKeys) {
            expect_kind(
                kc.generate_wrapped_data_key(DataKeySpec::Aes256, b"").await,
                ErrorKind::Unsupported,
                "generate_wrapped_data_key",
            )?;
        }
        if !has(Describe) {
            expect_kind(kc.describe().await, ErrorKind::Unsupported, "describe")?;
        }
        ensure!(
            count() == before,
            "a part the AEAD key lacks sent requests before failing"
        );
        if has(Describe) {
            let info = k.describe().await.ctx("describe")?;
            bits(&info, Capabilities::AEAD, true, "AEAD key")?;
            bits(&info, Capabilities::REWRAP, has(Rewrap), "AEAD key")?;
            bits(&info, Capabilities::DATA_KEYS, has(DataKeys), "AEAD key")?;
        }
        // The AEAD key as a KEK keeps the AEAD key's rewrap and describe parts.
        let kw = c.key_wrap(&key.uri).ctx("open the AEAD key as a KEK")?;
        ensure!(
            kw.supports_rewrap() == has(Rewrap) && kw.supports_describe() == has(Describe),
            "the AEAD key as a KEK {kw:?} disagrees with the declaration"
        );
    }

    if has(KeyWrap) {
        checked.push("key_wrap");
        let key = c.key(TestKeyKind::KeyWrap).await?;
        let kw = c.key_wrap(&key.uri).ctx("open key_wrap")?;
        ensure!(
            kw.supports_rewrap() == has(KeyWrapRewrap) && kw.supports_describe() == has(Describe),
            "key-wrapping handle {kw:?} disagrees with the declaration (rewrap {}, describe {})",
            has(KeyWrapRewrap),
            has(Describe)
        );
        let wrapped = kw.wrap_key(&[7; 32]).await.ctx("wrap_key")?;
        let kc = cc.key_wrap(&key.uri).ctx("open counted key_wrap")?;
        let before = count();
        if !has(KeyWrapRewrap) {
            expect_kind(
                kc.rewrap(&wrapped, b"").await,
                ErrorKind::Unsupported,
                "rewrap of a wrapped key",
            )?;
        }
        if !has(Describe) {
            expect_kind(kc.describe().await, ErrorKind::Unsupported, "describe")?;
        }
        ensure!(
            count() == before,
            "a part the key-wrapping key lacks sent requests before failing"
        );
        if has(Describe) {
            let info = kw.describe().await.ctx("describe")?;
            bits(&info, Capabilities::KEY_WRAP, true, "key-wrapping key")?;
            bits(
                &info,
                Capabilities::REWRAP,
                has(KeyWrapRewrap),
                "key-wrapping key",
            )?;
        }
    }

    if has(Mac) {
        checked.push("mac");
        let key = c
            .key(TestKeyKind::Hmac(anykms_core::MacAlgorithm::HmacSha256))
            .await?;
        let alg = anykms_core::MacAlgorithm::HmacSha256;
        let m = c.mac(&key.uri, alg).ctx("open mac")?;
        ensure!(
            m.supports_describe() == has(Describe),
            "MAC handle {m:?} disagrees with the declaration (describe {})",
            has(Describe)
        );
        if has(Describe) {
            let info = m.describe().await.ctx("describe")?;
            bits(&info, Capabilities::MAC, true, "HMAC key")?;
        } else {
            let mc = cc.mac(&key.uri, alg).ctx("open counted mac")?;
            let before = count();
            expect_kind(mc.describe().await, ErrorKind::Unsupported, "describe")?;
            ensure!(count() == before, "describe sent requests before failing");
        }
    }

    // One digest and one message signing algorithm, where declared.
    for alg in [
        SignatureAlgorithm::ALL
            .iter()
            .copied()
            .find(|a| !a.is_message_signing() && has(Signing(*a))),
        SignatureAlgorithm::ALL
            .iter()
            .copied()
            .find(|a| a.is_message_signing() && has(Signing(*a))),
    ]
    .into_iter()
    .flatten()
    {
        checked.push(alg.as_str());
        let key = c.key(TestKeyKind::Signing(alg)).await?;
        let (verifier, public_keys, describe) = if alg.is_message_signing() {
            let s = c.message_signer(&key.uri, alg).ctx("open signer")?;
            s.sign_message(b"m").await.ctx("sign")?;
            (
                s.supports_verifier(),
                s.supports_public_keys(),
                s.supports_describe(),
            )
        } else {
            let s = c.digest_signer(&key.uri, alg).ctx("open signer")?;
            s.sign_digest(&Digest::compute(alg.hash().expect("digest"), b"m"))
                .await
                .ctx("sign")?;
            (
                s.supports_verifier(),
                s.supports_public_keys(),
                s.supports_describe(),
            )
        };
        ensure!(
            verifier && public_keys && describe == has(Describe),
            "{alg} signer disagrees with the declaration (verifier {verifier}, public keys \
             {public_keys}, describe {describe}; declared describe {})",
            has(Describe)
        );
        if has(Describe) {
            let info = c
                .describe_key(&key)
                .ctx("open describe")?
                .describe()
                .await
                .ctx("describe")?;
            let what = format!("{alg} key");
            bits(&info, Capabilities::SIGN, true, &what)?;
            bits(&info, Capabilities::VERIFY, true, &what)?;
            bits(&info, Capabilities::PUBLIC_KEY, true, &what)?;
            bits(&info, Capabilities::AEAD, false, &what)?;
        }
    }
    ensure!(!checked.is_empty(), "the fixture declares no key family");
    Ok(())
}

/// Checks that `info` has `bit` exactly when `expected`.
fn bits(info: &KeyInfo, bit: Capabilities, expected: bool, what: &str) -> CaseResult {
    ensure!(
        info.capabilities().contains(bit) == expected,
        "{what}: describe capabilities {:?} {} {bit:?}, but the declaration says {}",
        info.capabilities(),
        if expected { "lack" } else { "include" },
        if expected { "it has it" } else { "it does not" }
    );
    Ok(())
}

/// `describe()` and `preflight()` of a key's handles carry the backend's own metadata, of the
/// type the fixture names (`Fixture::backend_info_type`). Checked on the first family the
/// fixture declares (AEAD, key wrapping, then P-256 signing), through the registry and the typed
/// path alike.
pub(crate) async fn backend_info<F: Fixture>(c: Ctx<F>) -> CaseResult {
    use Feature::*;
    let want = c
        .fx
        .backend_info_type()
        .ok_or("the fixture supports BackendInfo but names no type (Fixture::backend_info_type)")?;
    let p256 = anykms_core::SignatureAlgorithm::EcdsaP256Sha256;
    let kind = if c.caps.has(Aead) {
        TestKeyKind::Aead
    } else if c.caps.has(KeyWrap) {
        TestKeyKind::KeyWrap
    } else if c.caps.has(Signing(p256)) {
        TestKeyKind::Signing(p256)
    } else {
        return Err("the fixture declares no AEAD, key-wrapping or P-256 signing keys".into());
    };
    let key = c.key(kind).await?;
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    ensure!(
        info.backend_info_type_id() == Some(want),
        "describe() attaches no backend metadata of the fixture's type"
    );
    let info = match kind {
        TestKeyKind::Aead => c.aead(&key.uri).ctx("open aead")?.preflight().await,
        TestKeyKind::KeyWrap => c.key_wrap(&key.uri).ctx("open key_wrap")?.preflight().await,
        _ => {
            c.digest_signer(&key.uri, p256)
                .ctx("open digest signer")?
                .preflight()
                .await
        }
    }
    .ctx("preflight")?;
    ensure!(
        info.backend_info_type_id() == Some(want),
        "preflight() attaches no backend metadata of the fixture's type"
    );
    Ok(())
}

/// A key-wrapping key's public key wraps a data key offline (RSA-OAEP-SHA-256 with
/// `anykms_recipes::rsa_oaep_sha256_encrypt`), and the backend unwraps it; the published key is
/// labeled with a version the handle accepts back.
pub(crate) async fn key_wrap_public_key_wraps<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::KeyWrap).await?;
    let kw = c.key_wrap(&key.uri).ctx("open key_wrap")?;
    ensure!(
        kw.supports_public_keys(),
        "the fixture declares KeyWrapPublicKeys, but the KeyWrap handle has no public-key part"
    );
    let pk = kw.public_key().await.ctx("public_key")?;
    let dek = [0x5a_u8; 32];
    let wrapped = anykms_recipes::rsa_oaep_sha256_encrypt(pk.spki_der(), &dek)
        .map_err(|e| format!("wrap locally: {e}"))?;
    let out = kw
        .unwrap_key(&anykms_core::Ciphertext::from_bytes(wrapped))
        .await
        .ctx("unwrap_key")?;
    ensure!(*out == dek, "unwrap_key returned another key");
    if let Some(v) = pk.key_version() {
        let again = kw.public_key_version(v).await.ctx("public_key_version")?;
        ensure!(
            again.spki_der() == pk.spki_der(),
            "public_key_version of the published version returned another key"
        );
    }
    Ok(())
}
