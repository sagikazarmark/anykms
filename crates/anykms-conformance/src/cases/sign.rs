//! Signing, verification and public-key cases, run for every algorithm the backend supports.

use anykms_core::prelude::*;
use anykms_core::{
    Capabilities, Digest, ErrorKind, HashAlgorithm, KeyState, KeyVersion, Signature,
    SignatureAlgorithm, UnversionedVerify, VersionShape,
};
use anykms_recipes::LocalVerifier;

use super::aead::{ensure_usable_versions, ensure_version_disabled, state_per_version};
use super::util::two;
use crate::ctx::{CaseResult, Check, Ctx, Path, ensure, expect_kind};
use crate::fixture::{Feature, Fixture, TestKey, TestKeyKind};

const MSG: &[u8] = b"anykms conformance message";

/// Signs `msg` with the right trait for `alg`.
async fn sign<F: Fixture>(
    c: &Ctx<F>,
    key: &TestKey,
    alg: SignatureAlgorithm,
    msg: &[u8],
) -> anykms_core::Result<Signature> {
    if alg.is_message_signing() {
        c.message_signer(&key.uri, alg)?.sign_message(msg).await
    } else {
        let d = Digest::compute(alg.hash().expect("digest algorithm"), msg);
        c.digest_signer(&key.uri, alg)?.sign_digest(&d).await
    }
}

/// Verifies with the backend verifier.
async fn verify<F: Fixture>(
    c: &Ctx<F>,
    key: &TestKey,
    alg: SignatureAlgorithm,
    msg: &[u8],
    sig: &Signature,
) -> anykms_core::Result<()> {
    if alg.is_message_signing() {
        c.message_verifier(&key.uri, alg)?
            .verify_message(msg, sig)
            .await
    } else {
        let d = Digest::compute(alg.hash().expect("digest algorithm"), msg);
        c.digest_verifier(&key.uri, alg)?
            .verify_digest(&d, sig)
            .await
    }
}

/// Verifies with the independent RustCrypto verifier, using the public key of the signature's
/// version.
async fn verify_locally<F: Fixture>(
    c: &Ctx<F>,
    key: &TestKey,
    alg: SignatureAlgorithm,
    msg: &[u8],
    sig: &Signature,
) -> anykms_core::Result<()> {
    let pks = c.public_keys(&key.uri, alg)?;
    let pk = match sig.key_version() {
        Some(v) => pks.public_key_version(v).await?,
        None => pks.public_key().await?,
    };
    let v = LocalVerifier::new(pk, alg)?;
    if alg.is_message_signing() {
        v.verify_message(msg, sig).await
    } else {
        v.verify_digest(
            &Digest::compute(alg.hash().expect("digest algorithm"), msg),
            sig,
        )
        .await
    }
}

pub(crate) async fn roundtrip<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    ensure!(
        sig.algorithm() == alg,
        "signature labeled {} instead of {alg}",
        sig.algorithm()
    );
    ensure!(sig.key_version().is_some(), "signature has no key version");
    if let Some(v) = &key.version {
        ensure!(
            sig.key_version() == Some(v),
            "the key's URI pins version {v}, but the signature has {:?}",
            sig.key_version()
        );
    }
    verify(&c, &key, alg, MSG, &sig)
        .await
        .ctx("backend verify")?;
    // Interop: an independent implementation must accept the backend's signature (this also
    // enforces RSA-PSS salt length == hash length).
    verify_locally(&c, &key, alg, MSG, &sig)
        .await
        .ctx("local verify")?;
    Ok(())
}

pub(crate) async fn tampered<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    expect_kind(
        verify(&c, &key, alg, b"other message", &sig).await,
        ErrorKind::VerificationFailed,
        "backend verify of another message",
    )?;
    expect_kind(
        verify_locally(&c, &key, alg, b"other message", &sig).await,
        ErrorKind::VerificationFailed,
        "local verify of another message",
    )?;
    let mut bytes = sig.as_bytes().to_vec();
    let i = bytes.len() - 1;
    bytes[i] ^= 0x01;
    let bad = Signature::from_parts(alg, sig.key_version().cloned(), bytes);
    expect_kind(
        verify(&c, &key, alg, MSG, &bad).await,
        ErrorKind::VerificationFailed,
        "backend verify of tampered signature",
    )?;
    Ok(())
}

/// Structurally malformed signatures (not DER for ECDSA, wrong length, garbage) with the right
/// algorithm and key version are a verification failure, not a backend or argument error:
/// callers treat any `VerificationFailed` as "reject", and an attacker controls these bytes.
pub(crate) async fn malformed<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    let version = sig.key_version().cloned();
    // Deterministic pseudo-random bytes of the real signature's length (an xorshift stream).
    let mut x = 0x9e37_79b9_7f4a_7c15_u64;
    let garbage: Vec<u8> = (0..sig.as_bytes().len())
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // The low byte of the state.
            x.to_le_bytes()[0]
        })
        .collect();
    let candidates: [(&str, Vec<u8>); 3] = [
        ("garbage bytes", garbage),
        // A DER SEQUENCE header whose length runs past the end.
        ("truncated DER", vec![0x30, 0x45, 0x02, 0x21, 0x00]),
        ("a single zero byte", vec![0x00]),
    ];
    for (what, bytes) in candidates {
        let bad = Signature::from_parts(alg, version.clone(), bytes);
        expect_kind(
            verify(&c, &key, alg, MSG, &bad).await,
            ErrorKind::VerificationFailed,
            &format!("backend verify of {what}"),
        )?;
        expect_kind(
            verify_locally(&c, &key, alg, MSG, &bad).await,
            ErrorKind::VerificationFailed,
            &format!("local verify of {what}"),
        )?;
    }
    Ok(())
}

pub(crate) async fn input_validation<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sem = c.semantics(&key)?;
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    let unversioned = Signature::from_parts(alg, None, sig.as_bytes().to_vec());
    match sem.unversioned_verify() {
        UnversionedVerify::UsesCurrent => verify(&c, &key, alg, MSG, &unversioned)
            .await
            .ctx("verify unversioned signature (uses the current version)")?,
        _ => {
            expect_kind(
                verify(&c, &key, alg, MSG, &unversioned).await,
                ErrorKind::InvalidArgument,
                "unversioned signature",
            )?;
        }
    }
    if let Some(v) = c.fx.malformed_version() {
        let odd = Signature::from_parts(alg, Some(v), sig.as_bytes().to_vec());
        expect_kind(
            verify(&c, &key, alg, MSG, &odd).await,
            ErrorKind::InvalidArgument,
            "malformed key version",
        )?;
    }
    if sem.version_shape() == VersionShape::Opaque {
        // Another key's (well-formed) version never selects that key.
        let [_, other] = two(c.keys(TestKeyKind::Signing(alg), 2).await?);
        let theirs = sign(&c, &other, alg, MSG)
            .await
            .ctx("sign with another key")?;
        let foreign =
            Signature::from_parts(alg, theirs.key_version().cloned(), sig.as_bytes().to_vec());
        let e = expect_kind(
            verify(&c, &key, alg, MSG, &foreign).await,
            ErrorKind::VerificationFailed,
            "signature labeled with another key's version",
        )?;
        ensure!(
            e.is_caller_error(),
            "signature labeled with another key's version: {e} is not a caller error"
        );
    }
    // A digest of the wrong length cannot even be constructed.
    for h in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ] {
        for len in [0, h.output_len() - 1, h.output_len() + 1] {
            expect_kind(
                Digest::new(h, &vec![0x11; len]),
                ErrorKind::InvalidArgument,
                &format!("{h:?} digest of {len} bytes"),
            )?;
        }
    }
    if let Some(h) = alg.hash() {
        // A digest of the wrong hash algorithm is rejected (servers do not check this).
        let other = if h == HashAlgorithm::Sha256 {
            HashAlgorithm::Sha512
        } else {
            HashAlgorithm::Sha256
        };
        let d = Digest::compute(other, MSG);
        let signer = c.digest_signer(&key.uri, alg).ctx("open signer")?;
        expect_kind(
            signer.sign_digest(&d).await,
            ErrorKind::InvalidArgument,
            "sign digest of wrong algorithm",
        )?;
        let verifier = c.digest_verifier(&key.uri, alg).ctx("open verifier")?;
        expect_kind(
            verifier.verify_digest(&d, &sig).await,
            ErrorKind::InvalidArgument,
            "verify digest of wrong algorithm",
        )?;
        // A signature labeled with another algorithm is rejected.
        let relabeled = Signature::from_parts(
            other_alg(alg),
            sig.key_version().cloned(),
            sig.as_bytes().to_vec(),
        );
        expect_kind(
            verifier
                .verify_digest(&Digest::compute(h, MSG), &relabeled)
                .await,
            ErrorKind::InvalidArgument,
            "signature labeled with another algorithm",
        )?;
        // Ed25519-style message opening of a digest key is refused. The typed API cannot express
        // it (`ed25519_key` takes no algorithm).
        if c.path == Path::Registry {
            expect_kind(
                c.message_signer(&key.uri, alg).map(|_| ()),
                ErrorKind::KeyMismatch,
                "open digest key as message signer",
            )?;
        }
    } else {
        expect_kind(
            c.digest_signer(&key.uri, alg).map(|_| ()),
            ErrorKind::KeyMismatch,
            "open Ed25519 as digest signer",
        )?;
    }
    Ok(())
}

/// Inputs that fail local validation must be rejected before any request is sent (§8: "rejected
/// with zero requests").
pub(crate) async fn rejected_before_io<F: Fixture>(
    c: Ctx<F>,
    alg: SignatureAlgorithm,
) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    let sem = c.semantics(&key)?;
    let (cc, requests) = c.counting()?;
    let before = requests();
    if sem.unversioned_verify() == UnversionedVerify::Rejected {
        let unversioned = Signature::from_parts(alg, None, sig.as_bytes().to_vec());
        expect_kind(
            verify(&cc, &key, alg, MSG, &unversioned).await,
            ErrorKind::InvalidArgument,
            "unversioned signature",
        )?;
    }
    if let Some(v) = c.fx.malformed_version() {
        let odd = Signature::from_parts(alg, Some(v), sig.as_bytes().to_vec());
        expect_kind(
            verify(&cc, &key, alg, MSG, &odd).await,
            ErrorKind::InvalidArgument,
            "malformed key version",
        )?;
    }
    let relabeled = Signature::from_parts(
        other_alg(alg),
        sig.key_version().cloned(),
        sig.as_bytes().to_vec(),
    );
    expect_kind(
        verify(&cc, &key, alg, MSG, &relabeled).await,
        ErrorKind::InvalidArgument,
        "signature labeled with another algorithm",
    )?;
    if let Some(h) = alg.hash() {
        let other = if h == HashAlgorithm::Sha256 {
            HashAlgorithm::Sha512
        } else {
            HashAlgorithm::Sha256
        };
        let d = Digest::compute(other, MSG);
        expect_kind(
            cc.digest_signer(&key.uri, alg)
                .ctx("open signer")?
                .sign_digest(&d)
                .await,
            ErrorKind::InvalidArgument,
            "sign digest of wrong algorithm",
        )?;
        expect_kind(
            cc.digest_verifier(&key.uri, alg)
                .ctx("open verifier")?
                .verify_digest(&d, &sig)
                .await,
            ErrorKind::InvalidArgument,
            "verify digest of wrong algorithm",
        )?;
    }
    let after = requests();
    ensure!(
        after == before,
        "{} request(s) sent for inputs that fail local validation",
        after - before
    );
    // The counter must see real traffic, or the check above proves nothing.
    verify(&cc, &key, alg, MSG, &sig)
        .await
        .ctx("verify through the counting provider")?;
    ensure!(
        requests() > after,
        "the fixture's request counter did not count a real request"
    );
    Ok(())
}

/// An algorithm of a different key family than `alg` (another curve for P-384 and P-521, ECDSA
/// P-256 for everything else).
fn other_alg(alg: SignatureAlgorithm) -> SignatureAlgorithm {
    use SignatureAlgorithm::{EcdsaP256Sha256, EcdsaP384Sha384};
    match alg {
        EcdsaP256Sha256 => EcdsaP384Sha384,
        _ => EcdsaP256Sha256,
    }
}

pub(crate) async fn key_type_mismatch<F: Fixture>(
    c: Ctx<F>,
    alg: SignatureAlgorithm,
) -> CaseResult {
    // Servers happily sign with a key of another type (a P-384 key signs a "P-256" request), so
    // handles must check the key type before using it.
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let wrong = other_alg(alg);
    let d = Digest::compute(wrong.hash().expect("digest algorithm"), MSG);
    let r = match c.digest_signer(&key.uri, wrong) {
        Ok(s) => s.sign_digest(&d).await.map(|_| ()),
        Err(e) => Err(e),
    };
    expect_kind(
        r,
        ErrorKind::KeyMismatch,
        &format!("{alg} key opened as {wrong}"),
    )?;
    Ok(())
}

pub(crate) async fn rotation<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Signing(alg)).await?;
    let sig1 = sign(&c, &key, alg, MSG).await.ctx("sign v1")?;
    let new = c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let (cr, new_ref, v1) = (&c, &new, sig1.key_version().cloned());
    let sig2 = c
        .settled(move || {
            let v1 = v1.clone();
            async move {
                let sig2 = sign(cr, new_ref, alg, MSG).await.ctx("sign v2")?;
                ensure!(
                    sig2.key_version() != v1.as_ref(),
                    "signature version did not change after rotation"
                );
                Ok(sig2)
            }
        })
        .await?;
    if new.uri != key.uri {
        // The URIs pin versions: the old one keeps signing with its version.
        ensure!(
            new.version.is_some() && sig2.key_version() == new.version.as_ref(),
            "rotate returned {:?} pinning {:?}, but its signature has version {:?}",
            new.uri.to_string(),
            new.version,
            sig2.key_version()
        );
        let again = sign(&c, &key, alg, MSG)
            .await
            .ctx("sign with the old URI")?;
        ensure!(
            again.key_version() == sig1.key_version(),
            "the old URI signs with version {:?} after rotation, not its pinned {:?}",
            again.key_version(),
            sig1.key_version()
        );
    }
    verify(&c, &key, alg, MSG, &sig1)
        .await
        .ctx("backend verify of pre-rotation signature")?;
    verify(&c, &new, alg, MSG, &sig2)
        .await
        .ctx("backend verify of post-rotation signature")?;
    verify_locally(&c, &key, alg, MSG, &sig1)
        .await
        .ctx("local verify of pre-rotation signature")?;
    verify_locally(&c, &new, alg, MSG, &sig2)
        .await
        .ctx("local verify of post-rotation signature")?;
    // The old version's public key must not verify the new signature.
    let pks = c.public_keys(&key.uri, alg).ctx("open public keys")?;
    let old = pks
        .public_key_version(sig1.key_version().expect("versioned"))
        .await
        .ctx("public key v1")?;
    let unversioned = Signature::from_parts(alg, None, sig2.as_bytes().to_vec());
    let v = LocalVerifier::new(old, alg).ctx("local verifier")?;
    let r = if alg.is_message_signing() {
        v.verify_message(MSG, &unversioned).await
    } else {
        v.verify_digest(
            &Digest::compute(alg.hash().expect("digest"), MSG),
            &unversioned,
        )
        .await
    };
    expect_kind(
        r,
        ErrorKind::VerificationFailed,
        "old public key verifying new signature",
    )?;
    Ok(())
}

pub(crate) async fn min_decryption_version<F: Fixture>(
    c: Ctx<F>,
    alg: SignatureAlgorithm,
) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Signing(alg)).await?;
    let sig1 = sign(&c, &key, alg, MSG).await.ctx("sign v1")?;
    let key = c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let sig2 = sign(&c, &key, alg, MSG).await.ctx("sign v2")?;
    let (Some(v1), Some(v2)) = (sig1.key_version().cloned(), sig2.key_version().cloned()) else {
        return Err("signatures carry no key version".into());
    };
    c.fx.set_min_decryption_version(&key, &v2)
        .await
        .ctx("fixture set_min_decryption_version")?;
    let (cr, keyr, sig1r) = (&c, &key, &sig1);
    c.settled(move || async move {
        expect_kind(
            verify(cr, keyr, alg, MSG, sig1r).await,
            ErrorKind::KeyVersionUnusable,
            "verify below min version",
        )
        .map(drop)
    })
    .await?;
    verify(&c, &key, alg, MSG, &sig2)
        .await
        .ctx("verify current version")?;
    // A revoked version's public key must not be served either, or a local verifier would
    // keep accepting what the backend refuses. Describe and the public-key path must agree:
    // a version describe no longer lists is `UnknownKeyVersion`; one it lists must not be
    // enabled and fails with `KeyVersionUnusable`.
    let pks = c.public_keys(&key.uri, alg).ctx("open public keys")?;
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    let old = pks.public_key_version(&v1).await;
    match info.versions().iter().find(|v| *v.version() == v1) {
        None => {
            expect_kind(
                old,
                ErrorKind::UnknownKeyVersion,
                "public key below min version",
            )?;
        }
        Some(vi) => {
            ensure!(
                *vi.state() != KeyState::Enabled,
                "describe lists version {v1} below the minimum as enabled"
            );
            expect_kind(
                old,
                ErrorKind::KeyVersionUnusable,
                "public key below min version",
            )?;
        }
    }
    let current = pks.public_key().await.ctx("public key")?;
    ensure!(
        current.key_version() == Some(&v2),
        "public_key() returned version {:?}, expected {v2}",
        current.key_version()
    );
    pks.public_key_version(&v2)
        .await
        .ctx("public key of the current version")?;
    Ok(())
}

pub(crate) async fn disabled_key<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Signing(alg)).await?;
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    let v = sig
        .key_version()
        .cloned()
        .ok_or("signature carries no key version")?;
    c.fx.disable(&key).await.ctx("fixture disable")?;
    let (cr, keyr, sigr, vr) = (&c, &key, &sig, &v);
    c.settled(move || async move {
        expect_kind(
            sign(cr, keyr, alg, MSG).await,
            ErrorKind::KeyStateInvalid,
            "sign with disabled key",
        )?;
        expect_kind(
            verify(cr, keyr, alg, MSG, sigr).await,
            ErrorKind::KeyStateInvalid,
            "verify with disabled key",
        )?;
        // Every operation fails on a disabled key, public-key reads included (A3(f): also where
        // the server would serve them, as AWS does), so local verification stops when the
        // backend's does.
        let pks = cr.public_keys(&keyr.uri, alg).ctx("open public keys")?;
        let e = expect_kind(
            pks.public_key().await,
            ErrorKind::KeyStateInvalid,
            "public key of disabled key",
        )?;
        ensure!(
            e.is_config_error(),
            "public key of disabled key: {e} is not a config error"
        );
        expect_kind(
            pks.public_key_version(vr).await,
            ErrorKind::KeyStateInvalid,
            "versioned public key of disabled key",
        )?;
        Ok(())
    })
    .await
}

/// A disabled version: signing with it fails with `KeyStateInvalid` (the handle chose the
/// version: a deployment problem, config class); verifying its signatures and reading its public
/// key by version fail with `KeyVersionUnusable` (the input chose it: caller class); describe
/// lists it disabled.
pub(crate) async fn disabled_version<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Signing(alg)).await?;
    let per_version = state_per_version(&c.semantics(&key)?);
    let sig = sign(&c, &key, alg, MSG).await.ctx("sign")?;
    let v = sig
        .key_version()
        .cloned()
        .ok_or("signature carries no key version")?;
    c.fx.disable_version(&key, &v)
        .await
        .ctx("fixture disable_version")?;
    let (cr, keyr, sigr, vr) = (&c, &key, &sig, &v);
    c.settled(move || async move {
        let e = expect_kind(
            sign(cr, keyr, alg, MSG).await,
            ErrorKind::KeyStateInvalid,
            "sign with a disabled version",
        )?;
        ensure!(
            e.is_config_error(),
            "sign with a disabled version: {e} is not a config error"
        );
        let e = expect_kind(
            verify(cr, keyr, alg, MSG, sigr).await,
            ErrorKind::KeyVersionUnusable,
            "verify a signature of a disabled version",
        )?;
        ensure!(
            e.is_caller_error(),
            "verify a signature of a disabled version: {e} is not a caller error"
        );
        let pks = cr.public_keys(&keyr.uri, alg).ctx("open public keys")?;
        let e = expect_kind(
            pks.public_key_version(vr).await,
            ErrorKind::KeyVersionUnusable,
            "public key of a disabled version",
        )?;
        ensure!(
            e.is_caller_error(),
            "public key of a disabled version: {e} is not a caller error"
        );
        Ok(())
    })
    .await?;
    if c.caps.has(Feature::Describe) {
        let info = c
            .describe_key(&key)
            .ctx("open describe")?
            .describe()
            .await
            .ctx("describe")?;
        ensure_version_disabled(&info, &v, per_version)?;
    }
    Ok(())
}

pub(crate) async fn public_key<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let pk = c
        .public_keys(&key.uri, alg)
        .ctx("open")?
        .public_key()
        .await
        .ctx("public_key")?;
    ensure!(
        alg.is_compatible_with(&pk.key_type()),
        "public key type {:?} incompatible with {alg}",
        pk.key_type()
    );
    ensure!(pk.key_version().is_some(), "public key has no version");
    let parsed = anykms_recipes::spki_key_type(pk.spki_der()).ctx("parse SPKI")?;
    ensure!(
        parsed == pk.key_type(),
        "SPKI type {parsed:?} != declared {:?}",
        pk.key_type()
    );
    if let Some(v) = &key.version {
        ensure!(
            pk.key_version() == Some(v),
            "the key's URI pins version {v}, but its public key has {:?}",
            pk.key_version()
        );
    }
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    let sem = c.semantics(&key)?;
    let reports_primary = sem.primary_reported();
    ensure_usable_versions(&info, reports_primary, state_per_version(&sem))?;
    let primary = info
        .versions()
        .iter()
        .find(|v| Some(v.version()) == pk.key_version())
        .ok_or_else(|| {
            format!(
                "describe versions {:?} lack the public key's version {:?}",
                info.versions(),
                pk.key_version()
            )
        })?;
    ensure!(
        *primary.state() == KeyState::Enabled,
        "primary version state {:?}",
        primary.state()
    );
    // VERIFY means the handle verifies, on the backend or locally with the public key.
    ensure!(
        info.capabilities()
            .contains(Capabilities::SIGN | Capabilities::VERIFY | Capabilities::PUBLIC_KEY),
        "capabilities {:?} lack SIGN, VERIFY or PUBLIC_KEY",
        info.capabilities()
    );
    ensure!(
        info.signature_algorithms().contains(&alg),
        "describe does not list {alg}: {:?}",
        info.signature_algorithms()
    );
    if reports_primary && key.version.is_none() {
        ensure!(
            info.primary_version() == pk.key_version(),
            "describe primary {:?} != public key version {:?}",
            info.primary_version(),
            pk.key_version()
        );
    }
    Ok(())
}

/// Versions this key does not have, including other keys' identifiers and path-like strings, are
/// `UnknownKeyVersion` (or `InvalidArgument` where malformed for the backend), both caller class:
/// a version must never select another key (e.g. through a JWT `kid` that `CachedVerifier` passes
/// on). Another key's real version is exactly `UnknownKeyVersion`.
pub(crate) async fn foreign_versions<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let [key, other] = two(c.keys(TestKeyKind::Signing(alg), 2).await?);
    let pks = c.public_keys(&key.uri, alg).ctx("open")?;
    let own: Vec<KeyVersion> = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?
        .versions()
        .iter()
        .map(|v| v.version().clone())
        .collect();
    let foreign: Vec<KeyVersion> = [
        "999999",
        "../1",
        "1/../2",
        "",
        "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "https://vault.example/keys/k/0123456789abcdef0123456789abcdef",
    ]
    .into_iter()
    .map(KeyVersion::new)
    .collect();
    // Where version identifiers are unique across keys (cloud KMSs), the other key's version
    // must not be accepted either. Transit numbers every key's versions from 1, so there it is
    // one of this key's versions and skipped.
    let theirs = c
        .public_keys(&other.uri, alg)
        .ctx("open other")?
        .public_key()
        .await
        .ctx("other public_key")?;
    for v in foreign.iter().filter(|v| !own.contains(v)) {
        match pks.public_key_version(v).await {
            Ok(_) => return Err(format!("public_key_version({:?}) succeeded", v.as_str())),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::UnknownKeyVersion | ErrorKind::InvalidArgument
                ) =>
            {
                ensure!(
                    e.is_caller_error() && e.class() == anykms_core::ErrorClass::Caller,
                    "public_key_version({:?}): {e} is not caller class",
                    v.as_str()
                );
            }
            Err(e) => {
                return Err(format!(
                    "public_key_version({:?}): expected unknown_key_version or invalid_argument, got {}: {e}",
                    v.as_str(),
                    e.kind()
                ));
            }
        }
    }
    if let Some(v) = theirs.key_version().filter(|v| !own.contains(v)) {
        let e = expect_kind(
            pks.public_key_version(v).await,
            ErrorKind::UnknownKeyVersion,
            "public key of another key's version",
        )?;
        ensure!(
            e.class() == anykms_core::ErrorClass::Caller,
            "public key of another key's version: class {:?}, expected Caller",
            e.class()
        );
    }
    Ok(())
}

/// A message of the backend's maximum length is signed; one byte more is `InvalidArgument`.
pub(crate) async fn input_limit<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let n = c.semantics(&key)?.max_signed_message().ok_or(
        "MessageInputLimit is declared, but the signing handle declares no max_signed_message",
    )?;
    let msg = vec![0x42; n];
    let sig = sign(&c, &key, alg, &msg)
        .await
        .ctx("sign a message of the maximum length")?;
    verify(&c, &key, alg, &msg, &sig)
        .await
        .ctx("verify a message of the maximum length")?;
    expect_kind(
        sign(&c, &key, alg, &vec![0x42; n + 1]).await,
        ErrorKind::InvalidArgument,
        "sign a message over the maximum length",
    )?;
    Ok(())
}

/// An empty message is signed and verified ([`Feature::EmptyMessage`]).
pub(crate) async fn empty_message<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sig = sign(&c, &key, alg, b"").await.ctx("sign empty message")?;
    verify(&c, &key, alg, b"", &sig)
        .await
        .ctx("verify empty message")?;
    verify_locally(&c, &key, alg, b"", &sig)
        .await
        .ctx("local verify of empty message")?;
    expect_kind(
        verify(&c, &key, alg, MSG, &sig).await,
        ErrorKind::VerificationFailed,
        "the empty message's signature over another message",
    )?;
    Ok(())
}

/// Describe's per-version algorithms (`KeyVersionInfo::signature_algorithm`), where the backend
/// reports them (GCP; the others leave them `None`): every version of a P-256 key reports
/// ECDSA P-256 or nothing, all versions alike, and none reports a MAC algorithm.
pub(crate) async fn version_algorithms<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let info = c
        .describe_key(&key)
        .ctx("open describe")?
        .describe()
        .await
        .ctx("describe")?;
    let reported: Vec<_> = info
        .versions()
        .iter()
        .map(anykms_core::KeyVersionInfo::signature_algorithm)
        .collect();
    ensure!(
        reported.iter().all(std::option::Option::is_none)
            || reported.iter().all(|a| *a == Some(alg)),
        "{alg} key versions report the signature algorithms {reported:?}"
    );
    ensure!(
        info.versions().iter().all(|v| v.mac_algorithm().is_none()),
        "{alg} key versions report a MAC algorithm: {:?}",
        info.versions()
    );
    Ok(())
}
