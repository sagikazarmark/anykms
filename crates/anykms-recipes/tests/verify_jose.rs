//! Local verification and JOSE helpers against in-process keys. The RSA cases run with whichever
//! RSA backend the crate features select (or check `Unsupported` without one); the JOSE cases
//! need the `jose` feature.

#[cfg(feature = "jose")]
use std::sync::atomic::{AtomicUsize, Ordering};

use anykms_core::{
    AsymmetricKeyType, Digest, DigestSigner, ErrorKind, KeyVersion, PublicKey, PublicKeys, Result,
    Signature, SignatureAlgorithm,
};
#[cfg(feature = "jose")]
use anykms_recipes::jose;
use anykms_recipes::{CachedVerifier, LocalVerifier, verify_message_hashed};
use p256::pkcs8::EncodePublicKey as _;
use rsa::rand_core::UnwrapErr;
use rsa::signature::RandomizedSigner as _;
use signature::hazmat::PrehashSigner as _;

/// One 2048-bit RSA key for all tests (key generation is slow in debug builds).
fn rsa_key() -> &'static rsa::RsaPrivateKey {
    static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut UnwrapErr(getrandom::SysRng), 2048).unwrap())
}

fn rsa_public_key(key: &rsa::RsaPrivateKey) -> PublicKey {
    use rsa::pkcs8::EncodePublicKey as _;
    let der = key.to_public_key().to_public_key_der().unwrap();
    PublicKey::new(
        AsymmetricKeyType::Rsa { bits: 2048 },
        der.as_bytes().to_vec(),
        None,
    )
}

const RSA_ALGS: [SignatureAlgorithm; 6] = [
    SignatureAlgorithm::RsaPssSha256,
    SignatureAlgorithm::RsaPssSha384,
    SignatureAlgorithm::RsaPssSha512,
    SignatureAlgorithm::RsaPkcs1v15Sha256,
    SignatureAlgorithm::RsaPkcs1v15Sha384,
    SignatureAlgorithm::RsaPkcs1v15Sha512,
];

/// Signs `msg` with the shared RSA key under `alg` (PSS with salt length = hash length).
#[cfg_attr(
    not(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs")),
    allow(dead_code)
)]
fn rsa_sign(alg: SignatureAlgorithm, msg: &[u8]) -> Signature {
    use SignatureAlgorithm::*;
    use rsa::signature::Signer as _;
    use sha2::{Sha256, Sha384, Sha512};
    let k = rsa_key().clone();
    let rng = &mut UnwrapErr(getrandom::SysRng);
    let bytes: Box<[u8]> = match alg {
        RsaPssSha256 => rsa::pss::SigningKey::<Sha256>::new(k)
            .sign_with_rng(rng, msg)
            .into(),
        RsaPssSha384 => rsa::pss::SigningKey::<Sha384>::new(k)
            .sign_with_rng(rng, msg)
            .into(),
        RsaPssSha512 => rsa::pss::SigningKey::<Sha512>::new(k)
            .sign_with_rng(rng, msg)
            .into(),
        RsaPkcs1v15Sha256 => rsa::pkcs1v15::SigningKey::<Sha256>::new(k).sign(msg).into(),
        RsaPkcs1v15Sha384 => rsa::pkcs1v15::SigningKey::<Sha384>::new(k).sign(msg).into(),
        RsaPkcs1v15Sha512 => rsa::pkcs1v15::SigningKey::<Sha512>::new(k).sign(msg).into(),
        _ => unreachable!(),
    };
    Signature::from_parts(alg, None, bytes.into_vec())
}

/// LocalVerifier accepts RSA-PSS only with salt length equal to the hash length (§5.3).
#[cfg(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs"))]
#[tokio::test]
async fn rsa_pss_rejects_other_salt_lengths() {
    let alg = SignatureAlgorithm::RsaPssSha256;
    let verifier = LocalVerifier::new(rsa_public_key(rsa_key()), alg).unwrap();
    let msg = b"pss salt length";
    let sign = |salt_len: usize| {
        let s =
            rsa::pss::SigningKey::<sha2::Sha256>::new_with_salt_len(rsa_key().clone(), salt_len)
                .sign_with_rng(&mut UnwrapErr(getrandom::SysRng), msg);
        Signature::from_parts(alg, None, Box::<[u8]>::from(s).into_vec())
    };
    // Control: salt length = hash length (32) verifies.
    verify_message_hashed(&verifier, msg, &sign(32))
        .await
        .unwrap();
    for salt_len in [0usize, 20, 31, 33, 64] {
        let e = verify_message_hashed(&verifier, msg, &sign(salt_len))
            .await
            .unwrap_err();
        assert_eq!(
            e.kind(),
            ErrorKind::VerificationFailed,
            "salt_len={salt_len}"
        );
    }
}

/// Every RSA algorithm verifies with a verifier pinned to it, and only with that one: a
/// signature relabeled as another padding or hash is refused before any RSA operation, and a
/// verifier pinned to one algorithm never checks a signature of another.
#[cfg(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs"))]
#[tokio::test]
async fn rsa_verification_is_pinned_to_one_algorithm() {
    use anykms_core::DigestVerifier as _;
    let pk = rsa_public_key(rsa_key());
    let msg = b"pinned";
    for alg in RSA_ALGS {
        let verifier = LocalVerifier::new(pk.clone(), alg).unwrap();
        assert_eq!(verifier.algorithm(), alg);
        let sig = rsa_sign(alg, msg);
        verify_message_hashed(&verifier, msg, &sig).await.unwrap();
        let e = verify_message_hashed(&verifier, b"other", &sig)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed, "{alg}");
        for other in RSA_ALGS.into_iter().filter(|o| *o != alg) {
            // The signature claims another algorithm: refused by the pinned verifier, whatever
            // digest the caller computed.
            let relabeled = Signature::from_parts(other, None, sig.as_bytes().to_vec());
            let digest = Digest::compute(other.hash().unwrap(), msg);
            let e = verifier
                .verify_digest(&digest, &relabeled)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{alg} as {other}");
            // `verify_message_hashed` refuses it before hashing.
            let e = verify_message_hashed(&verifier, msg, &relabeled)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{alg} as {other}");
            // A verifier pinned to the other algorithm does not accept this signature.
            let theirs = LocalVerifier::new(pk.clone(), other).unwrap();
            assert!(
                verify_message_hashed(&theirs, msg, &relabeled)
                    .await
                    .is_err(),
                "{alg} verified as {other}"
            );
        }
    }
    // RSA keys have no implied algorithm; incompatible algorithms are a key mismatch.
    let e = LocalVerifier::for_key(pk.clone()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = LocalVerifier::new(pk, ALG).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
}

/// Without an RSA backend, RSA keys still parse and publish JWKs, but verifying fails with
/// `Unsupported` naming the features; other key types are unaffected.
#[cfg(not(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs")))]
#[tokio::test]
async fn rsa_without_a_backend_is_unsupported() {
    let pk = rsa_public_key(rsa_key());
    let der = pk.spki_der().to_vec();
    let parsed = anykms_recipes::public_key_from_spki_der(&der, None).unwrap();
    assert_eq!(parsed.key_type(), AsymmetricKeyType::Rsa { bits: 2048 });
    #[cfg(feature = "jose")]
    {
        let jwk = jose::to_jwk(&pk, "k", SignatureAlgorithm::RsaPssSha256).unwrap();
        assert_eq!(jwk["kty"], "RSA");
    }
    for alg in RSA_ALGS {
        let e = LocalVerifier::new(pk.clone(), alg).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{alg}");
        assert!(e.message().contains("rsa-aws-lc-rs"), "{}", e.message());
    }
    let key = EcKey::new(1);
    let sig = anykms_recipes::sign_message_hashed(&key.version(1), b"m")
        .await
        .unwrap();
    let v = LocalVerifier::for_key(key.pk(1)).unwrap();
    verify_message_hashed(&v, b"m", &sig).await.unwrap();
}

/// The JWK of an RSA key carries its modulus and exponent (parsed without any RSA backend).
#[cfg(feature = "jose")]
#[test]
fn rsa_jwk_has_modulus_and_exponent() {
    use base64::Engine as _;
    use rsa::traits::PublicKeyParts as _;
    let key = rsa_key().to_public_key();
    let jwk = jose::to_jwk(
        &rsa_public_key(rsa_key()),
        "k.1",
        SignatureAlgorithm::RsaPkcs1v15Sha256,
    )
    .unwrap();
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    assert_eq!(jwk["n"], b64(&key.n().to_be_bytes_trimmed_vartime()));
    assert_eq!(jwk["e"], b64(&key.e().to_be_bytes_trimmed_vartime()));
    assert_eq!(jwk["alg"], "RS256");
}

/// An in-process P-256 key with several versions; `lie` makes `public_key_version` answer with
/// the wrong version.
struct EcKey {
    keys: Vec<p256::ecdsa::SigningKey>,
    lie: bool,
}

impl EcKey {
    fn new(n: u8) -> Self {
        let keys = (1..=n)
            .map(|i| p256::ecdsa::SigningKey::from_slice(&[i; 32]).unwrap())
            .collect();
        Self { keys, lie: false }
    }

    fn pk(&self, v: usize) -> PublicKey {
        let der = self.keys[v - 1]
            .verifying_key()
            .to_public_key_der()
            .unwrap();
        PublicKey::new(
            AsymmetricKeyType::EcP256,
            der.as_bytes().to_vec(),
            Some(KeyVersion::from_u64(v as u64)),
        )
    }

    /// Signs with version `v`.
    fn version(&self, v: usize) -> EcSigner<'_> {
        EcSigner { key: self, v }
    }
}

struct EcSigner<'a> {
    key: &'a EcKey,
    v: usize,
}

impl DigestSigner for EcSigner<'_> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let s: p256::ecdsa::Signature = self.key.keys[self.v - 1]
            .sign_prehash(digest.as_bytes())
            .unwrap();
        Ok(Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(KeyVersion::from_u64(self.v as u64)),
            s.to_der().as_bytes().to_vec(),
        ))
    }
}

impl PublicKeys for EcKey {
    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.pk(self.keys.len()))
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        let v = usize::try_from(version.as_u64().unwrap()).unwrap();
        Ok(self.pk(if self.lie { self.keys.len() } else { v }))
    }
}

const ALG: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;

/// `verify_message_hashed` takes the algorithm from the verifier, so the signature never picks
/// the hash; a verifier with no algorithm of its own names it with `verify_message_hashed_as`.
#[tokio::test]
async fn hashed_verification_takes_the_verifiers_algorithm() {
    use anykms_recipes::{PinnedVerifier as _, verify_message_hashed_as};
    let key = EcKey::new(1);
    let sig = anykms_recipes::sign_message_hashed(&key.version(1), b"m")
        .await
        .unwrap();
    let local = LocalVerifier::for_key(key.pk(1)).unwrap();
    assert_eq!(local.pinned_algorithm(), ALG);
    verify_message_hashed(&local, b"m", &sig).await.unwrap();
    let cached = CachedVerifier::new(EcKey::new(1), ALG);
    assert_eq!(cached.pinned_algorithm(), ALG);
    // Wrappers forward the pinned algorithm, so a retried or shared verifier keeps the short
    // form.
    let retried = anykms_core::RetryLayer::new(anykms_core::instant_sleep()).wrap(cached);
    assert_eq!(retried.pinned_algorithm(), ALG);
    verify_message_hashed(&retried, b"m", &sig).await.unwrap();
    let shared = std::sync::Arc::new(LocalVerifier::for_key(key.pk(1)).unwrap());
    verify_message_hashed(&shared, b"m", &sig).await.unwrap();
    verify_message_hashed(&&*shared, b"m", &sig).await.unwrap();

    // The signature claims another algorithm: refused before hashing, whoever names the
    // algorithm.
    let relabeled = Signature::from_parts(
        SignatureAlgorithm::EcdsaP384Sha384,
        None,
        sig.as_bytes().to_vec(),
    );
    let e = verify_message_hashed(&local, b"m", &relabeled)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);

    let unpinned: std::sync::Arc<dyn anykms_core::DynDigestVerifier> = std::sync::Arc::new(local);
    verify_message_hashed_as(&unpinned, ALG, b"m", &sig)
        .await
        .unwrap();
    let e = verify_message_hashed_as(&unpinned, ALG, b"m", &relabeled)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = verify_message_hashed_as(&unpinned, SignatureAlgorithm::Ed25519, b"m", &sig)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
}

/// RSA keys below 2048 bits are refused when parsed and when building a verifier.
#[test]
fn rsa_keys_below_2048_bits_are_refused() {
    use rsa::pkcs8::EncodePublicKey as _;
    let mut rng = UnwrapErr(getrandom::SysRng);
    let small = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    // Needs no RSA backend.
    let der = small.to_public_key().to_public_key_der().unwrap();
    let e = anykms_recipes::public_key_from_spki_der(der.as_bytes(), None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    let pem = small
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::default())
        .unwrap();
    let e = anykms_recipes::public_key_from_pem(&pem, None).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    let pk = PublicKey::new(
        AsymmetricKeyType::Rsa { bits: 1024 },
        der.as_bytes().to_vec(),
        None,
    );
    let e = LocalVerifier::new(pk, SignatureAlgorithm::RsaPssSha256).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch);
}

/// High-S ECDSA signatures verify by default (KMS backends produce them) and are rejected only
/// with `require_low_s`.
#[tokio::test]
async fn high_s_is_accepted_by_default_and_rejected_when_strict() {
    use anykms_core::DigestVerifier as _;
    let key = EcKey::new(1);
    let digest = Digest::sha256(b"malleable");
    let low: p256::ecdsa::Signature = key.keys[0].sign_prehash(digest.as_bytes()).unwrap();
    let low = low.normalize_s();
    let high = p256::ecdsa::Signature::from_scalars(low.r(), -low.s()).unwrap();
    assert_ne!(low, high);
    let sig = |s: p256::ecdsa::Signature| {
        Signature::from_parts(ALG, None, s.to_der().as_bytes().to_vec())
    };
    let lenient = LocalVerifier::for_key(key.pk(1)).unwrap();
    let strict = LocalVerifier::for_key(key.pk(1)).unwrap().require_low_s();
    lenient.verify_digest(&digest, &sig(low)).await.unwrap();
    lenient.verify_digest(&digest, &sig(high)).await.unwrap();
    strict.verify_digest(&digest, &sig(low)).await.unwrap();
    let e = strict.verify_digest(&digest, &sig(high)).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::VerificationFailed);
    // CachedVerifier passes the setting on.
    let cached = CachedVerifier::new(EcKey::new(1), ALG).require_low_s();
    cached.verify_digest(&digest, &sig(low)).await.unwrap();
    let e = cached.verify_digest(&digest, &sig(high)).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::VerificationFailed);
}

/// Checks the signature of a compact JWS under `pk` and returns its `(kid, payload)`. Just enough
/// to test the signing side: the module does not verify tokens (relying parties use a JWT
/// library; see tests/jose_interop.rs).
#[cfg(feature = "jose")]
async fn check_jws(pk: &PublicKey, jws: &str) -> (String, Vec<u8>) {
    try_check_jws(pk, jws).await.unwrap()
}

/// [`check_jws`], with a signature that does not verify as an error.
#[cfg(feature = "jose")]
async fn try_check_jws(pk: &PublicKey, jws: &str) -> Result<(String, Vec<u8>)> {
    use anykms_core::MessageVerifier as _;
    use anykms_recipes::ecdsa_der::{ecdsa_scalar_len, fixed_to_der};
    use base64::Engine as _;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let verifier = LocalVerifier::for_key(pk.clone()).unwrap();
    let alg = verifier.algorithm();
    let header = protected_header(jws);
    let name = header["alg"].as_str().unwrap();
    assert!(
        Some(name) == alg.jws_alg() || (alg == SignatureAlgorithm::Ed25519 && name == "Ed25519"),
        "{header}"
    );
    let (input, sig) = jws.rsplit_once('.').unwrap();
    let mut sig = url.decode(sig).unwrap();
    if let Some(n) = ecdsa_scalar_len(alg) {
        sig = fixed_to_der(&sig, n).unwrap();
    }
    let sig = Signature::from_parts(alg, None, sig);
    if alg.is_message_signing() {
        verifier.verify_message(input.as_bytes(), &sig).await?;
    } else {
        verify_message_hashed(&verifier, input.as_bytes(), &sig).await?;
    }
    let payload = url.decode(input.split_once('.').unwrap().1).unwrap();
    Ok((header["kid"].as_str().unwrap().to_owned(), payload))
}

/// A JWS's kid names the version that signed it, and the signature checks only under that
/// version's public key.
#[cfg(feature = "jose")]
#[tokio::test]
async fn sign_jws_with_versioned_kids() {
    let key = EcKey::new(2);
    for v in [1, 2] {
        let kid = jose::kid("release", &KeyVersion::from_u64(v as u64));
        let jws = jose::sign_jws(&key.version(v), &kid, b"{}").await.unwrap();
        let (got, payload) = check_jws(&key.pk(v), &jws).await;
        assert_eq!(
            (got.as_str(), payload.as_slice()),
            (kid.as_str(), &b"{}"[..])
        );
        // Under the other version's key it does not verify.
        let e = try_check_jws(&key.pk(3 - v), &jws).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed, "v{v}");
    }
}

/// A kid keeps a key name containing `.` whole: the version is the last segment.
#[cfg(feature = "jose")]
#[test]
fn kids_keep_dotted_key_names() {
    let v1 = KeyVersion::from_u64(1);
    assert_eq!(jose::kid("my.key", &v1), "my.key.1");
    assert_eq!(jose::kid_for("my.key", &EcKey::new(1).pk(1)), "my.key.1");
    assert_eq!(jose::kid_for("my.key", &Unversioned::new().pk()), "my.key");
}

#[cfg(feature = "jose")]
#[tokio::test]
async fn jwks_from_versions_checks_returned_version() {
    let v1 = [KeyVersion::from_u64(1)];
    let honest = EcKey::new(2);
    let jwks = jose::jwks_from_versions(&honest, "release", ALG, &v1)
        .await
        .unwrap();
    assert_eq!(jwks["keys"][0]["kid"], "release.1");

    let lying = EcKey {
        lie: true,
        ..EcKey::new(2)
    };
    let e = jose::jwks_from_versions(&lying, "release", ALG, &v1)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Backend);
}

#[cfg(feature = "jose")]
impl anykms_core::Describe for EcKey {
    async fn describe(&self) -> Result<anykms_core::KeyInfo> {
        use anykms_core::{Capabilities, KeyInfo, KeyState, KeyVersionInfo};
        // Version 1 is disabled; the rest are enabled.
        let versions = (1..=self.keys.len() as u64)
            .map(|v| {
                let state = if v == 1 {
                    KeyState::Disabled
                } else {
                    KeyState::Enabled
                };
                KeyVersionInfo::new(KeyVersion::from_u64(v), state)
            })
            .collect();
        Ok(KeyInfo::new("ecdsa-p256", Capabilities::SIGN)
            .with_state(Some(KeyState::Enabled))
            .with_primary_version(Some(KeyVersion::from_u64(self.keys.len() as u64)))
            .with_versions(versions))
    }
}

#[cfg(feature = "jose")]
#[tokio::test]
async fn jwks_publishes_enabled_versions_from_one_handle() {
    let jwks = jose::jwks(&EcKey::new(3), "release", ALG).await.unwrap();
    let kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids, ["release.2", "release.3"]);
}

/// A key whose backend exposes no versions (like AWS KMS).
#[cfg(feature = "jose")]
struct Unversioned(p256::ecdsa::SigningKey);

#[cfg(feature = "jose")]
impl Unversioned {
    fn new() -> Self {
        Self(p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap())
    }

    fn pk(&self) -> PublicKey {
        let der = self.0.verifying_key().to_public_key_der().unwrap();
        PublicKey::new(AsymmetricKeyType::EcP256, der.as_bytes().to_vec(), None)
    }
}

#[cfg(feature = "jose")]
impl PublicKeys for Unversioned {
    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.pk())
    }

    async fn public_key_version(&self, _: &KeyVersion) -> Result<PublicKey> {
        Err(anykms_core::Error::new(
            anykms_core::ErrorKind::Unsupported,
            "test",
            anykms_core::Operation::PublicKey,
            "no versions",
        ))
    }
}

#[cfg(feature = "jose")]
impl anykms_core::Describe for Unversioned {
    async fn describe(&self) -> Result<anykms_core::KeyInfo> {
        Ok(anykms_core::KeyInfo::new(
            "ECC_NIST_P256",
            anykms_core::Capabilities::SIGN,
        ))
    }
}

#[cfg(feature = "jose")]
impl DigestSigner for Unversioned {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        ALG
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let s: p256::ecdsa::Signature = self.0.sign_prehash(digest.as_bytes()).unwrap();
        Ok(Signature::from_parts(
            ALG,
            None,
            s.to_der().as_bytes().to_vec(),
        ))
    }
}

#[cfg(feature = "jose")]
#[tokio::test]
async fn unversioned_keys_work_with_kid_jwks_and_cached_verifier() {
    let key = Unversioned::new();
    let kid = jose::kid_for("alias/release", &key.pk());
    assert_eq!(kid, "alias/release");
    let jwks = jose::jwks(&key, "alias/release", ALG).await.unwrap();
    assert_eq!(jwks["keys"][0]["kid"], "alias/release");

    // An unversioned signature verifies against the current public key.
    let cached = CachedVerifier::new(Unversioned::new(), ALG);
    let sig = anykms_recipes::sign_message_hashed(&key, b"m")
        .await
        .unwrap();
    verify_message_hashed(&cached, b"m", &sig).await.unwrap();
    let jwt = jose::sign_jws(&key, &kid, b"{}").await.unwrap();
    let (got, _) = check_jws(&key.pk(), &jwt).await;
    assert_eq!(got, "alias/release");
}

/// Options for a token that expires in five minutes.
#[cfg(feature = "jose")]
fn ttl() -> jose::JwtOptions {
    jose::JwtOptions::new().with_ttl(std::time::Duration::from_secs(300))
}

/// A `JwtSigner` publishes its JWKS under its own key name and its signer's algorithm, and its
/// tokens verify against it.
#[cfg(feature = "jose")]
#[tokio::test]
async fn jwt_signers_publish_their_jwks() {
    let claims = serde_json::json!({"sub": "1"});
    let opts = ttl();

    let signer = jose::JwtSigner::new(Unversioned::new(), "alias/release");
    let jwks = signer.jwks().await.unwrap();
    assert_eq!(
        jwks,
        jose::jwks(&Unversioned::new(), "alias/release", ALG)
            .await
            .unwrap()
    );
    assert_eq!(
        (
            jwks["keys"][0]["kid"].as_str(),
            jwks["keys"][0]["alg"].as_str()
        ),
        (Some("alias/release"), Some("ES256"))
    );
    let jwt = signer.sign(&claims, &opts).await.unwrap();
    let (kid, _) = check_jws(&Unversioned::new().pk(), &jwt).await;
    assert_eq!(kid, "alias/release");

    let key = EdKey(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
    let pk = key.pk();
    let signer = jose::JwtSigner::new(key, "ed");
    let jwks = signer.jwks_message().await.unwrap();
    assert_eq!(
        (
            jwks["keys"][0]["kid"].as_str(),
            jwks["keys"][0]["alg"].as_str()
        ),
        (Some("ed.1"), Some("EdDSA"))
    );
    let jwt = signer.sign_message(&claims, &opts).await.unwrap();
    let (kid, _) = check_jws(&pk, &jwt).await;
    assert_eq!(kid, jwks["keys"][0]["kid"]);
}

/// The protected header of a compact JWS, as JSON.
#[cfg(feature = "jose")]
fn protected_header(jws: &str) -> serde_json::Value {
    use base64::Engine as _;
    let h = jws.split('.').next().unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(h)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[cfg(feature = "jose")]
#[tokio::test]
async fn sign_jws_with_custom_header() {
    let key = EcKey::new(1);
    let header = jose::JwsHeader::new("release.1")
        .with_typ(Some("at+jwt"))
        .with_field("x5t", "abc");
    let jws = jose::sign_jws_with(&key.version(1), &header, b"{}")
        .await
        .unwrap();
    check_jws(&key.pk(1), &jws).await;
    let h = protected_header(&jws);
    assert_eq!(
        (h["typ"].as_str(), h["x5t"].as_str()),
        (Some("at+jwt"), Some("abc"))
    );
    assert_eq!(h["alg"], "ES256");
    let untyped = jose::JwsHeader::new("k").with_typ(None);
    let jws = jose::sign_jws_with(&key.version(1), &untyped, b"{}")
        .await
        .unwrap();
    check_jws(&key.pk(1), &jws).await;
    for reserved in ["alg", "kid", "typ", "crit", "b64"] {
        let h = jose::JwsHeader::new("k").with_field(reserved, "x");
        let e = jose::sign_jws_with(&key.version(1), &h, b"{}")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{reserved}");
    }
}

/// An in-process Ed25519 key.
#[cfg(feature = "jose")]
struct EdKey(ed25519_dalek::SigningKey);

#[cfg(feature = "jose")]
impl EdKey {
    fn pk(&self) -> PublicKey {
        use ed25519_dalek::pkcs8::EncodePublicKey as _;
        let der = self.0.verifying_key().to_public_key_der().unwrap();
        PublicKey::new(
            AsymmetricKeyType::Ed25519,
            der.as_bytes().to_vec(),
            Some(KeyVersion::from_u64(1)),
        )
    }
}

#[cfg(feature = "jose")]
impl anykms_core::MessageSigner for EdKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        use ed25519_dalek::Signer as _;
        Ok(Signature::from_parts(
            SignatureAlgorithm::Ed25519,
            Some(KeyVersion::from_u64(1)),
            self.0.sign(msg).to_bytes().to_vec(),
        ))
    }
}

#[cfg(feature = "jose")]
impl PublicKeys for EdKey {
    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.pk())
    }

    async fn public_key_version(&self, _: &KeyVersion) -> Result<PublicKey> {
        Ok(self.pk())
    }
}

#[cfg(feature = "jose")]
impl anykms_core::Describe for EdKey {
    async fn describe(&self) -> Result<anykms_core::KeyInfo> {
        Ok(anykms_core::KeyInfo::new(
            "ed25519",
            anykms_core::Capabilities::SIGN,
        ))
    }
}

/// Ed25519 signing emits `"EdDSA"` by default and the fully-specified `"Ed25519"` (RFC 9864) on
/// request.
#[cfg(feature = "jose")]
#[tokio::test]
async fn ed25519_signs_under_either_alg_name() {
    let key = EdKey(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
    let classic = jose::sign_jws_message(&key, "ed.1", b"{}").await.unwrap();
    let header = jose::JwsHeader::new("ed.1").fully_specified_alg();
    let modern = jose::sign_jws_message_with(&key, &header, b"{}")
        .await
        .unwrap();
    for (jws, name) in [(&classic, "EdDSA"), (&modern, "Ed25519")] {
        check_jws(&key.pk(), jws).await;
        assert_eq!(protected_header(jws)["alg"], name);
    }
    // The JWT helpers can emit it too.
    let jwt = jose::sign_jwt_message(
        &key,
        "ed",
        &serde_json::json!({"sub": "1"}),
        &ttl().fully_specified_alg(),
    )
    .await
    .unwrap();
    let (kid, _) = check_jws(&key.pk(), &jwt).await;
    assert_eq!(
        (protected_header(&jwt)["alg"].as_str(), kid.as_str()),
        (Some("Ed25519"), "ed.1")
    );
}

/// A plain JWS carries no `typ` (it is not necessarily a JWT); JWTs are labelled `"JWT"` unless
/// the options say otherwise.
#[cfg(feature = "jose")]
#[tokio::test]
async fn only_jwts_are_typed_jwt() {
    let key = EcKey::new(1);
    let jws = jose::sign_jws(&key.version(1), "release.1", b"{}")
        .await
        .unwrap();
    assert!(
        protected_header(&jws).get("typ").is_none(),
        "{}",
        protected_header(&jws)
    );
    let h = jose::JwsHeader::new("release.1");
    let jws = jose::sign_jws_with(&key.version(1), &h, b"{}")
        .await
        .unwrap();
    assert!(
        protected_header(&jws).get("typ").is_none(),
        "{}",
        protected_header(&jws)
    );
    let ed = EdKey(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
    let jws = jose::sign_jws_message(&ed, "ed.1", b"{}").await.unwrap();
    assert!(
        protected_header(&jws).get("typ").is_none(),
        "{}",
        protected_header(&jws)
    );

    let claims = serde_json::json!({"sub": "1"});
    let signer = jose::JwtSigner::new(RotatingKey::new(1, 1), "release");
    let jwt = signer.sign(&claims, &ttl()).await.unwrap();
    assert_eq!(protected_header(&jwt)["typ"], "JWT");
    let jwt = jose::sign_jwt_message(&ed, "ed", &claims, &ttl())
        .await
        .unwrap();
    assert_eq!(protected_header(&jwt)["typ"], "JWT");
    let options = ttl().with_typ(None);
    let jwt = signer.sign(&claims, &options).await.unwrap();
    assert!(
        protected_header(&jwt).get("typ").is_none(),
        "{}",
        protected_header(&jwt)
    );
}

/// A P-256 key whose signing version can be rotated, counting public-key reads.
#[cfg(feature = "jose")]
struct RotatingKey {
    key: EcKey,
    current: AtomicUsize,
    reads: AtomicUsize,
}

#[cfg(feature = "jose")]
impl RotatingKey {
    fn new(versions: u8, current: usize) -> Self {
        Self {
            key: EcKey::new(versions),
            current: current.into(),
            reads: 0.into(),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "jose")]
impl DigestSigner for RotatingKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        ALG
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let v = self.current.load(Ordering::SeqCst);
        self.key.version(v).sign_digest(digest).await
    }
}

#[cfg(feature = "jose")]
impl PublicKeys for RotatingKey {
    async fn public_key(&self) -> Result<PublicKey> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.key.pk(self.current.load(Ordering::SeqCst)))
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.key.public_key_version(version).await
    }
}

#[cfg(feature = "jose")]
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Claims {
    sub: String,
    scope: Vec<String>,
}

/// `JwtSigner` reads the kid once, follows rotations by re-signing once with the new version's
/// kid, and its tokens verify and carry the typed claims.
#[cfg(feature = "jose")]
#[tokio::test]
async fn jwt_signer_caches_the_kid_and_follows_rotations() {
    const NOW: u64 = 1_000_000;
    let signer = jose::JwtSigner::new(RotatingKey::new(2, 1), "release");
    let claims = Claims {
        sub: "42".into(),
        scope: vec!["read".into()],
    };
    let options = jose::JwtOptions::new()
        .with_now(NOW)
        .with_ttl(std::time::Duration::from_secs(300))
        .with_typ(Some("at+jwt"));
    // Checks the signature under the version its kid names: a kid naming another version than
    // the one that signed fails.
    let keys = EcKey::new(2);
    let verify = async |jwt: &str| {
        let header = protected_header(jwt);
        assert_eq!(header["typ"], "at+jwt");
        let kid = header["kid"].as_str().unwrap();
        let v: usize = kid.strip_prefix("release.").unwrap().parse().unwrap();
        check_jws(&keys.pk(v), jwt).await
    };
    for _ in 0..3 {
        let jwt = signer.sign(&claims, &options).await.unwrap();
        let (kid, payload) = verify(&jwt).await;
        let got: Claims = serde_json::from_slice(&payload).unwrap();
        assert_eq!((kid.as_str(), &got), ("release.1", &claims));
    }
    assert_eq!(signer.signer().reads(), 1);
    // The claims carry iat and exp.
    let jwt = signer.sign(&claims, &options).await.unwrap();
    let (_, payload) = verify(&jwt).await;
    let got: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        (got["iat"].as_u64(), got["exp"].as_u64()),
        (Some(NOW), Some(NOW + 300))
    );

    // Rotation: the first token comes back signed by v2, is re-signed with kid release.2, and
    // the new kid is kept, all without another public-key read.
    signer.signer().current.store(2, Ordering::SeqCst);
    for _ in 0..2 {
        let jwt = signer.sign(&claims, &options).await.unwrap();
        let (kid, _) = verify(&jwt).await;
        assert_eq!(kid, "release.2");
    }
    assert_eq!(signer.signer().reads(), 1);

    // Claims must serialize to an object and may not already hold what the options set.
    let e = signer.sign(&[1, 2], &options).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = signer
        .sign(&serde_json::json!({"exp": 1}), &options)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
}

/// `sign_jwt` reads the kid for every token. Without a TTL or an `exp` claim it refuses before any
/// KMS request, and a token that never expires (here a release statement) needs `without_expiry`.
#[cfg(feature = "jose")]
#[tokio::test]
async fn sign_jwt_reads_the_kid_each_time() {
    let key = RotatingKey::new(1, 1);
    let claims = serde_json::json!({"sub": "1"});
    let e = jose::sign_jwt(&key, "release", &claims, &jose::JwtOptions::new())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert_eq!(key.reads(), 0);
    for _ in 0..2 {
        let options = jose::JwtOptions::new().without_expiry();
        let jwt = jose::sign_jwt(&key, "release", &claims, &options)
            .await
            .unwrap();
        let (kid, payload) = check_jws(&key.key.pk(1), &jwt).await;
        assert_eq!(kid, "release.1");
        let got: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(got, claims);
    }
    assert_eq!(key.reads(), 2);
}
