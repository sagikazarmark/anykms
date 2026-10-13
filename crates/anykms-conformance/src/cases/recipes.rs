//! Recipes over every backend, typed and through the Registry.

use anykms_core::prelude::*;
use anykms_core::{Ciphertext, DataKeySpec, ErrorKind, SignatureAlgorithm};
use anykms_recipes::serde_json;
use anykms_recipes::{
    CachedVerifier, EmulatedDataKeys, Envelope, EnvelopeAead, EnvelopeKeyring, LocalVerifier, jose,
};
use base64::Engine as _;

use super::util::two;
use crate::ctx::{CaseResult, Check, Ctx, ensure, expect_kind};
use crate::fixture::{Fixture, TestKeyKind};

/// An envelope over a KEK of `kind`: an AEAD key used as a KEK (`KeyWrapKey::from_aead`, and
/// `into_key_wrap`), or a native key-wrapping key.
pub(crate) async fn envelope_roundtrip<F: Fixture>(c: Ctx<F>, kind: TestKeyKind) -> CaseResult {
    let [k1, k2] = two(c.keys(kind, 2).await?);
    let env = EnvelopeAead::new("conf-kek", c.key_wrap(&k1.uri).ctx("open")?).ctx("envelope")?;
    for pt in [vec![], vec![1u8], vec![0x5a; 256 * 1024]] {
        let ct = env.encrypt(&pt, b"row-1").await.ctx("envelope encrypt")?;
        ensure!(
            *env.decrypt(&ct, b"row-1").await.ctx("envelope decrypt")? == pt,
            "round trip differs"
        );
    }
    let ct = env.encrypt(b"payload", b"row-1").await.ctx("encrypt")?;
    expect_kind(
        env.decrypt(&ct, b"row-2").await,
        ErrorKind::DecryptFailed,
        "wrong AAD",
    )?;
    let mut tampered = ct.as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    expect_kind(
        env.decrypt(&Ciphertext::from_bytes(tampered), b"row-1")
            .await,
        ErrorKind::DecryptFailed,
        "tampered payload",
    )?;
    let other_id = EnvelopeAead::new("other", c.key_wrap(&k1.uri).ctx("open")?).ctx("envelope")?;
    expect_kind(
        other_id.decrypt(&ct, b"row-1").await,
        ErrorKind::DecryptFailed,
        "kek_id mismatch",
    )?;
    let other_kek = match kind {
        // An AEAD key adapted explicitly.
        TestKeyKind::Aead => {
            EnvelopeAead::new("conf-kek", c.aead(&k2.uri).ctx("open")?.into_key_wrap())
                .ctx("envelope")?
                .decrypt(&ct, b"row-1")
                .await
        }
        _ => {
            EnvelopeAead::new("conf-kek", c.key_wrap(&k2.uri).ctx("open")?)
                .ctx("envelope")?
                .decrypt(&ct, b"row-1")
                .await
        }
    };
    expect_kind(other_kek, ErrorKind::DecryptFailed, "another KEK")?;
    let wrapped = Envelope::parse(ct.as_bytes()).ctx("parse")?.wrapped_dek();
    let wrapped_version = env
        .kek()
        .wrapped_key_version(&wrapped)
        .ctx("wrapped version")?;
    ensure!(
        env.ciphertext_version(&ct).ctx("version")? == wrapped_version,
        "envelope ciphertext_version differs from the wrapped key's version"
    );
    if kind == TestKeyKind::Aead {
        // The key-wrapping key wraps with empty AAD under the same key as the AEAD handle.
        let aead = c.aead(&k1.uri).ctx("open aead")?;
        ensure!(
            aead.ciphertext_version(&wrapped).ctx("aead version")? == wrapped_version,
            "wrapped_key_version differs from the AEAD key's ciphertext_version"
        );
        ensure!(
            aead.decrypt(&wrapped, b"")
                .await
                .ctx("decrypt wrapped key")?
                .len()
                == 32,
            "the wrapped data key does not decrypt with empty AAD"
        );
    } else {
        ensure!(
            env.kek()
                .unwrap_key(&wrapped)
                .await
                .ctx("unwrap_key")?
                .len()
                == 32,
            "the wrapped data key does not unwrap to 32 bytes"
        );
    }
    Ok(())
}

/// Decodes an envelope from this backend with an independent implementation of the v1 format
/// (`docs/envelope-format.md`): the committed test vectors pin the format with a fixed local KEK,
/// and this case checks that envelopes wrapped by every backend's KEK follow the same layout.
pub(crate) async fn envelope_format<F: Fixture>(c: Ctx<F>, kind: TestKeyKind) -> CaseResult {
    use aes_gcm::aead::{Aead as _, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit as _};

    let key = c.key(kind).await?;
    let (pt, aad) = (b"envelope format check".as_slice(), b"row-7".as_slice());
    let ct = match kind {
        TestKeyKind::Aead => {
            let kek = c.aead(&key.uri).ctx("open")?;
            EnvelopeAead::new("conf-kek", (&kek).into_key_wrap())
                .ctx("envelope")?
                .encrypt(pt, aad)
                .await
        }
        _ => {
            EnvelopeAead::new("conf-kek", c.key_wrap(&key.uri).ctx("open")?)
                .ctx("envelope")?
                .encrypt(pt, aad)
                .await
        }
    }
    .ctx("envelope encrypt")?;
    let b = ct.as_bytes();

    // Header: magic, version, flags, commitment, nonce.
    ensure!(b.len() > 49, "envelope of {} bytes", b.len());
    ensure!(&b[..3] == b"AKE", "magic {:02x?}", &b[..3]);
    ensure!(
        b[3] == 0x01 && b[4] == 0x00,
        "version/flags {:02x?}",
        &b[3..5]
    );
    let (header, commit, nonce) = (&b[..49], &b[5..37], &b[37..49]);
    // Key-wrapping slot.
    let kid_len = b[49] as usize;
    let mut i = 50;
    ensure!(
        b.get(i..i + kid_len) == Some(b"conf-kek".as_slice()),
        "kek_id slot"
    );
    i += kid_len;
    let wlen = b
        .get(i..i + 2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]) as usize)
        .ok_or("truncated before wrapped_dek_len")?;
    i += 2;
    ensure!((1..=4096).contains(&wlen), "wrapped_dek_len {wlen}");
    let wrapped = b.get(i..i + wlen).ok_or("truncated wrapped_dek")?;
    let payload = &b[i + wlen..];
    ensure!(
        payload.len() == pt.len() + 16,
        "payload of {} bytes for a {}-byte plaintext",
        payload.len(),
        pt.len()
    );
    let parsed = Envelope::parse(b).ctx("parse")?;
    ensure!(
        parsed.kek_id() == b"conf-kek"
            && parsed.wrapped_dek().as_bytes() == wrapped
            && parsed.payload() == payload,
        "Envelope::parse disagrees with the layout"
    );

    // The slot holds the KEK's wrapping of a 32-byte DEK: for an AEAD key, its native ciphertext
    // with empty AAD.
    let wrapped = Ciphertext::from_bytes(wrapped.to_vec());
    let dek = match kind {
        TestKeyKind::Aead => c
            .aead(&key.uri)
            .ctx("open")?
            .decrypt(&wrapped, b"")
            .await
            .ctx("unwrap DEK with empty AAD")?,
        _ => c
            .key_wrap(&key.uri)
            .ctx("open")?
            .unwrap_key(&wrapped)
            .await
            .ctx("unwrap DEK")?,
    };
    ensure!(dek.len() == 32, "DEK of {} bytes", dek.len());
    let mut okm = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &dek)
        .expand(b"anykms/envelope/v1", &mut okm)
        .map_err(|_| "HKDF expand".to_owned())?;
    ensure!(&okm[32..] == commit, "commitment does not match the DEK");
    let mut gcm_aad = header.to_vec();
    gcm_aad.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    gcm_aad.extend_from_slice(aad);
    let cipher = Aes256Gcm::new_from_slice(&okm[..32]).map_err(|_| "AES key".to_owned())?;
    let n = aes_gcm::Nonce::try_from(nonce).map_err(|_| "nonce".to_owned())?;
    let opened = cipher
        .decrypt(
            &n,
            Payload {
                msg: payload,
                aad: &gcm_aad,
            },
        )
        .map_err(|_| "independent AES-256-GCM decryption failed".to_owned())?;
    ensure!(opened == pt, "independently decrypted plaintext differs");
    Ok(())
}

/// How [`envelope_rewrap`] moves the data key to the KEK's new version.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RewrapVia {
    /// `EnvelopeAead::rewrap`: the KEK rewraps server-side.
    Server,
    /// `EnvelopeAead::rewrap_local`: unwrap and wrap again in this process.
    Local,
    /// `EnvelopeAead::rewrap_current`: server-side where the KEK can, otherwise locally.
    Current,
}

/// Rotates the KEK (unless `rotate` is false: a KEK that never rotates still rewraps, to its
/// current version), rewraps an envelope `via` the server or locally, and checks the payload is
/// unchanged and still decrypts.
pub(crate) async fn envelope_rewrap<F: Fixture>(
    c: Ctx<F>,
    kind: TestKeyKind,
    via: RewrapVia,
    rotate: bool,
) -> CaseResult {
    let key = c.fresh_key(kind).await?;
    // `KeyWrapKey` from the Registry implements Rewrap, so this must compile (the CryptBox
    // path).
    let kek = c.key_wrap(&key.uri).ctx("open")?;
    if kind == TestKeyKind::Aead {
        ensure!(
            kek.supports_rewrap() == c.aead(&key.uri).ctx("open aead")?.supports_rewrap(),
            "the key-wrapping key and the AEAD key disagree on rewrap"
        );
    }
    let env: EnvelopeAead<anykms_core::KeyWrapKey> =
        EnvelopeAead::new("kek", kek).ctx("envelope")?;
    let ct = env.encrypt(b"rotate me", b"aad").await.ctx("encrypt")?;
    let v1 = env.ciphertext_version(&ct).ctx("version")?;
    if rotate {
        c.fx.rotate(&key).await.ctx("fixture rotate")?;
    }
    let (envr, ctr, v1r) = (&env, &ct, &v1);
    let ct2 = c
        .settled(move || async move {
            let ct2 = match via {
                RewrapVia::Server => envr.rewrap(ctr).await.ctx("rewrap")?,
                RewrapVia::Local => envr.rewrap_local(ctr).await.ctx("rewrap_local")?,
                RewrapVia::Current => envr.rewrap_current(ctr).await.ctx("rewrap_current")?,
            };
            let v2 = envr.ciphertext_version(&ct2).ctx("version")?;
            ensure!(
                !rotate || v1r.is_none() || *v1r != v2,
                "{via:?} rewrap did not move the data key to the new KEK version"
            );
            Ok(ct2)
        })
        .await?;
    ensure!(
        Envelope::parse(ct2.as_bytes()).ctx("parse")?.payload()
            == Envelope::parse(ct.as_bytes()).ctx("parse")?.payload(),
        "{via:?} rewrap changed the payload"
    );
    ensure!(
        *env.decrypt(&ct2, b"aad").await.ctx("decrypt")? == *b"rotate me",
        "{via:?} rewrap broke the envelope"
    );
    Ok(())
}

pub(crate) async fn envelope_rewrap_to_and_keyring<F: Fixture>(
    c: Ctx<F>,
    kind: TestKeyKind,
) -> CaseResult {
    let [k1, k2] = two(c.keys(kind, 2).await?);
    let old = EnvelopeAead::new("old", c.key_wrap(&k1.uri).ctx("open")?).ctx("envelope")?;
    let ct = old.encrypt(b"migrate me", b"aad").await.ctx("encrypt")?;
    // Both ways of holding a KEK where the key is an AEAD key: a key-wrapping key and an AEAD
    // key adapted explicitly.
    let (moved, ring) = match kind {
        TestKeyKind::Aead => {
            let new = EnvelopeAead::new("new", c.aead(&k2.uri).ctx("open")?.into_key_wrap())
                .ctx("envelope")?;
            let moved = old.rewrap_to(&ct, &new).await.ctx("rewrap_to")?;
            ensure!(
                *new.decrypt(&moved, b"aad").await.ctx("decrypt moved")? == *b"migrate me",
                "wrong plaintext"
            );
            let ring = EnvelopeKeyring::new("old", c.key_wrap(&k1.uri).ctx("open")?)
                .ctx("envelope")?
                .with_kek("new", c.aead(&k2.uri).ctx("open")?.into_key_wrap())
                .ctx("add KEK")?;
            (moved, ring)
        }
        _ => {
            let new = EnvelopeAead::new("new", c.key_wrap(&k2.uri).ctx("open")?).ctx("envelope")?;
            let moved = old.rewrap_to(&ct, &new).await.ctx("rewrap_to")?;
            ensure!(
                *new.decrypt(&moved, b"aad").await.ctx("decrypt moved")? == *b"migrate me",
                "wrong plaintext"
            );
            let ring = EnvelopeKeyring::new("old", c.key_wrap(&k1.uri).ctx("open")?)
                .ctx("envelope")?
                .with_kek("new", c.key_wrap(&k2.uri).ctx("open")?)
                .ctx("add KEK")?;
            (moved, ring)
        }
    };
    expect_kind(
        old.decrypt(&moved, b"aad").await,
        ErrorKind::DecryptFailed,
        "old KEK on moved envelope",
    )?;
    let ring = ring.with_primary("new").ctx("primary")?;
    ensure!(
        *ring.decrypt(&ct, b"aad").await.ctx("keyring decrypt old")? == *b"migrate me",
        "routing old"
    );
    ensure!(
        *ring
            .decrypt(&moved, b"aad")
            .await
            .ctx("keyring decrypt new")?
            == *b"migrate me",
        "routing new"
    );
    let to_primary = ring
        .rewrap_current(&ct)
        .await
        .ctx("keyring rewrap_current")?;
    ensure!(
        Envelope::parse(to_primary.as_bytes())
            .ctx("parse")?
            .kek_id()
            == b"new",
        "not moved to primary"
    );
    // Relabel the moved envelope to claim the other real KEK: routing must not bypass the
    // commitment.
    let env = Envelope::parse(moved.as_bytes()).ctx("parse")?;
    let mut relabeled = moved.as_bytes()[..49].to_vec();
    relabeled.push(3);
    relabeled.extend_from_slice(b"old");
    let w = env.wrapped_dek();
    relabeled.extend_from_slice(&(w.len() as u16).to_be_bytes());
    relabeled.extend_from_slice(w.as_bytes());
    relabeled.extend_from_slice(env.payload());
    expect_kind(
        ring.decrypt(&Ciphertext::from_bytes(relabeled), b"aad")
            .await,
        ErrorKind::DecryptFailed,
        "relabeled kek_id",
    )?;
    Ok(())
}

pub(crate) async fn emulated_data_keys<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    let dk = EmulatedDataKeys::new(k.clone())
        .generate_data_key(DataKeySpec::Aes256, b"ctx")
        .await
        .ctx("generate")?;
    ensure!(dk.plaintext().len() == 32, "length");
    ensure!(
        *k.decrypt(dk.ciphertext(), b"ctx").await.ctx("unwrap")? == *dk.plaintext(),
        "differs"
    );
    expect_kind(
        k.decrypt(dk.ciphertext(), b"").await,
        ErrorKind::DecryptFailed,
        "emulated data key not bound to AAD",
    )?;
    Ok(())
}

pub(crate) async fn cached_verifier<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.fresh_key(TestKeyKind::Signing(alg)).await?;
    let sign =
        async |key: &crate::fixture::TestKey| -> anykms_core::Result<anykms_core::Signature> {
            if alg.is_message_signing() {
                c.message_signer(&key.uri, alg)?.sign_message(b"m").await
            } else {
                anykms_recipes::sign_message_hashed(&c.digest_signer(&key.uri, alg)?, b"m").await
            }
        };
    let s1 = sign(&key).await.ctx("sign v1")?;
    let new = c.fx.rotate(&key).await.ctx("fixture rotate")?;
    let s2 = sign(&new).await.ctx("sign v2")?;
    ensure!(
        s1.key_version() != s2.key_version(),
        "signature version did not change after rotation"
    );
    // Over the current key: where URIs pin versions, the old URI's latest version is the old
    // one, and the cached verifier refuses versions above it.
    let v = CachedVerifier::new(c.public_keys(&new.uri, alg).ctx("open public keys")?, alg);
    for (label, s) in [("v1", &s1), ("v2", &s2)] {
        let r = if alg.is_message_signing() {
            v.verify_message(b"m", s).await
        } else {
            anykms_recipes::verify_message_hashed(&v, b"m", s).await
        };
        r.ctx(&format!("cached verify {label}"))?;
    }
    let r = if alg.is_message_signing() {
        v.verify_message(b"x", &s1).await
    } else {
        anykms_recipes::verify_message_hashed(&v, b"x", &s1).await
    };
    expect_kind(
        r,
        ErrorKind::VerificationFailed,
        "cached verify of another message",
    )?;
    Ok(())
}

pub(crate) async fn jws<F: Fixture>(c: Ctx<F>, alg: SignatureAlgorithm) -> CaseResult {
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let pk = c
        .public_keys(&key.uri, alg)
        .ctx("open")?
        .public_key()
        .await
        .ctx("public key")?;
    let kid = jose::kid_for(&key.name, &pk);
    let jwt = if alg.is_message_signing() {
        jose::sign_jws_message(
            &c.message_signer(&key.uri, alg).ctx("open")?,
            &kid,
            br#"{"sub":"42"}"#,
        )
        .await
    } else {
        jose::sign_jws(
            &c.digest_signer(&key.uri, alg).ctx("open")?,
            &kid,
            br#"{"sub":"42"}"#,
        )
        .await
    }
    .ctx("sign JWS")?;
    // The recipe signs and does not verify (relying parties use a JWT library): check the JWS
    // signature under the public key directly.
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decode = |part: &str| {
        url.decode(part)
            .map_err(|e| format!("JWS is not base64url: {e}"))
    };
    let parts: Vec<&str> = jwt.split('.').collect();
    ensure!(parts.len() == 3, "JWS is not compact: {jwt}");
    let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])?)
        .map_err(|e| format!("JWS header is not JSON: {e}"))?;
    ensure!(
        header["kid"] == kid.as_str() && alg.jws_alg().is_some_and(|a| header["alg"] == a),
        "JWS header: {header}"
    );
    ensure!(
        decode(parts[1])? == br#"{"sub":"42"}"#,
        "JWS payload differs"
    );
    let mut raw = decode(parts[2])?;
    if let Some(n) = anykms_recipes::ecdsa_der::ecdsa_scalar_len(alg) {
        raw = anykms_recipes::ecdsa_der::fixed_to_der(&raw, n).ctx("JWS signature")?;
    }
    verify_with(
        &LocalVerifier::new(pk.clone(), alg).ctx("verifier")?,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &anykms_core::Signature::from_parts(alg, None, raw),
    )
    .await
    .ctx("verify JWS signature")?;
    let jwk = jose::to_jwk(&pk, &kid, alg).ctx("JWK")?;
    ensure!(
        alg.jws_alg().is_some_and(|a| jwk["alg"] == a) && jwk["kid"] == kid.as_str(),
        "JWK fields: {jwk}"
    );
    Ok(())
}

/// Verifies `sig` over `msg` with the trait its algorithm needs (hashing for digest algorithms).
async fn verify_with<V: DigestVerifier + MessageVerifier>(
    v: &V,
    msg: &[u8],
    sig: &anykms_core::Signature,
) -> anykms_core::Result<()> {
    match sig.algorithm().hash() {
        None => v.verify_message(msg, sig).await,
        Some(h) => {
            v.verify_digest(&anykms_core::Digest::compute(h, msg), sig)
                .await
        }
    }
}

/// A backend signature verifies locally only under the algorithm the verifier is pinned to:
/// relabeled as any other algorithm, `LocalVerifier` and `CachedVerifier` refuse it with
/// `InvalidArgument` before any cryptography (for RSA keys, this keeps the signature from choosing
/// among six paddings and hashes), and a verifier pinned to another algorithm of the same key
/// type never accepts it.
pub(crate) async fn algorithm_pinning<F: Fixture>(
    c: Ctx<F>,
    alg: SignatureAlgorithm,
) -> CaseResult {
    const MSG: &[u8] = b"pinned";
    let key = c.key(TestKeyKind::Signing(alg)).await?;
    let sig = if alg.is_message_signing() {
        c.message_signer(&key.uri, alg)
            .ctx("open")?
            .sign_message(MSG)
            .await
    } else {
        anykms_recipes::sign_message_hashed(&c.digest_signer(&key.uri, alg).ctx("open")?, MSG).await
    }
    .ctx("sign")?;
    let pks = c.public_keys(&key.uri, alg).ctx("open public keys")?;
    let pk = match sig.key_version() {
        Some(v) => pks.public_key_version(v).await,
        None => pks.public_key().await,
    }
    .ctx("public key")?;
    let local = LocalVerifier::new(pk.clone(), alg).ctx("local verifier")?;
    let cached = CachedVerifier::new(pks, alg);
    verify_with(&local, MSG, &sig).await.ctx("local verify")?;
    verify_with(&cached, MSG, &sig).await.ctx("cached verify")?;
    for &other in SignatureAlgorithm::ALL.iter().filter(|o| **o != alg) {
        let relabeled = anykms_core::Signature::from_parts(
            other,
            sig.key_version().cloned(),
            sig.as_bytes().to_vec(),
        );
        expect_kind(
            verify_with(&local, MSG, &relabeled).await,
            ErrorKind::InvalidArgument,
            &format!("local verifier pinned to {alg}, signature labeled {other}"),
        )?;
        expect_kind(
            verify_with(&cached, MSG, &relabeled).await,
            ErrorKind::InvalidArgument,
            &format!("cached verifier pinned to {alg}, signature labeled {other}"),
        )?;
        if other.is_compatible_with(&pk.key_type()) {
            let theirs =
                LocalVerifier::new(pk.clone(), other).ctx("verifier for another algorithm")?;
            ensure!(
                verify_with(&theirs, MSG, &relabeled).await.is_err(),
                "a {alg} signature verified as {other}"
            );
        } else {
            expect_kind(
                LocalVerifier::new(pk.clone(), other),
                ErrorKind::KeyMismatch,
                &format!("{other} verifier for a {alg} key"),
            )?;
        }
    }
    Ok(())
}
