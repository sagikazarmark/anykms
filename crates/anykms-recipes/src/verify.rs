//! Local signature verification from public keys.
//!
//! **Emulates:** the backend's verify operation. **Enforced by:** this process, using RustCrypto
//! implementations independent of the backend (for RSA, the backend the crate features select:
//! AWS-LC by default, or RustCrypto `rsa`). Local verification is cheaper than a KMS round trip
//! and needs no verify permission.

use anykms_core::{
    AsymmetricKeyType, Digest, DigestVerifier, Error, ErrorKind, MessageVerifier, Operation,
    PublicKey, Result, Signature, SignatureAlgorithm,
};
use signature::hazmat::PrehashVerifier;
use spki::{DecodePublicKey, ObjectIdentifier, SubjectPublicKeyInfoRef};

use crate::rsa_backend::{RsaVerifier, parse_rsa_spki};

const BACKEND: &str = "local-verify";

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

fn invalid(m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, Operation::Verify, m)
}

/// `verify_message` on a verifier of a digest-signing algorithm (ECDSA, RSA). Message verifiers
/// are Ed25519-only, as on every backend; the message names the helper that hashes with the
/// verifier's own algorithm.
pub(crate) const DIGEST_ALG_WITH_MESSAGE: &str = "digest-signing algorithm used with a message: \
     hash it first, e.g. with anykms_recipes::verify_message_hashed (which hashes with the \
     verifier's algorithm)";

pub(crate) fn failed() -> Error {
    Error::new(
        ErrorKind::VerificationFailed,
        BACKEND,
        Operation::Verify,
        "signature does not match",
    )
}

/// Smallest RSA modulus accepted for verification, in bits.
pub const MIN_RSA_BITS: u32 = 2048;

/// Parses an RSA key and checks its size, without any RSA backend.
fn check_rsa_key(spki_der: &[u8], op: Operation) -> Result<()> {
    let parts = parse_rsa_spki(spki_der).ok_or_else(|| invalid("malformed RSA public key"))?;
    if parts.bits() < MIN_RSA_BITS {
        return Err(Error::new(
            ErrorKind::KeyMismatch,
            BACKEND,
            op,
            "RSA key is smaller than 2048 bits",
        ));
    }
    Ok(())
}

/// Determines the key type of a SubjectPublicKeyInfo DER structure.
pub fn spki_key_type(spki_der: &[u8]) -> Result<AsymmetricKeyType> {
    use spki::der::Decode;
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|_| invalid("malformed SubjectPublicKeyInfo"))?;
    let oid = spki.algorithm.oid;
    if oid == OID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters_oid()
            .map_err(|_| invalid("EC key without curve parameters"))?;
        return match curve {
            c if c == OID_P256 => Ok(AsymmetricKeyType::EcP256),
            c if c == OID_P384 => Ok(AsymmetricKeyType::EcP384),
            c if c == OID_P521 => Ok(AsymmetricKeyType::EcP521),
            _ => Err(invalid("unsupported EC curve")),
        };
    }
    if oid == OID_ED25519 {
        return Ok(AsymmetricKeyType::Ed25519);
    }
    if oid == OID_RSA {
        let parts = parse_rsa_spki(spki_der).ok_or_else(|| invalid("malformed RSA public key"))?;
        return Ok(AsymmetricKeyType::Rsa { bits: parts.bits() });
    }
    Err(invalid("unsupported public key algorithm"))
}

/// Builds a [`PublicKey`] from SPKI DER, detecting its type. RSA keys smaller than
/// [`MIN_RSA_BITS`] fail with `KeyMismatch`. Needs no RSA backend.
pub fn public_key_from_spki_der(
    spki_der: &[u8],
    version: Option<anykms_core::KeyVersion>,
) -> Result<PublicKey> {
    let key_type = spki_key_type(spki_der)?;
    if let AsymmetricKeyType::Rsa { .. } = key_type {
        check_rsa_key(spki_der, Operation::PublicKey)?;
    }
    Ok(PublicKey::new(key_type, spki_der.to_vec(), version))
}

/// Builds a [`PublicKey`] from a PEM `PUBLIC KEY` block (same checks as
/// [`public_key_from_spki_der`]).
pub fn public_key_from_pem(
    pem: &str,
    version: Option<anykms_core::KeyVersion>,
) -> Result<PublicKey> {
    let der = pem_to_der(pem)?;
    public_key_from_spki_der(&der, version)
}

/// Decodes a single PEM `PUBLIC KEY` block to DER.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let pem = pem.trim();
    let body = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|s| s.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or_else(|| invalid("not a PEM PUBLIC KEY block"))?;
    let b64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| invalid("malformed PEM base64"))
}

/// The only signature algorithm a key of this type can produce, or `None` when there are several
/// (RSA: PSS or PKCS#1 v1.5, each with three hashes).
pub(crate) fn implied_algorithm(key_type: &AsymmetricKeyType) -> Option<SignatureAlgorithm> {
    match key_type {
        AsymmetricKeyType::EcP256 => Some(SignatureAlgorithm::EcdsaP256Sha256),
        AsymmetricKeyType::EcP384 => Some(SignatureAlgorithm::EcdsaP384Sha384),
        AsymmetricKeyType::EcP521 => Some(SignatureAlgorithm::EcdsaP521Sha512),
        AsymmetricKeyType::Ed25519 => Some(SignatureAlgorithm::Ed25519),
        _ => None,
    }
}

/// Parsed keys are immutable; shared so a [`LocalVerifier`] clones cheaply.
enum Inner {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    Rsa(RsaVerifier),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// Verifies signatures of **one** algorithm locally from a [`PublicKey`].
///
/// Supports ECDSA P-256/P-384/P-521 (DER signatures), RSA PKCS#1 v1.5 and RSA-PSS with salt length
/// exactly equal to the hash length, and pure Ed25519. RSA keys must have at least
/// [`MIN_RSA_BITS`] bits and need an RSA backend (crate features `rsa-aws-lc-rs`, the default,
/// or `rsa-rustcrypto`; without one, RSA keys fail with `Unsupported`).
///
/// # Algorithm pinning
///
/// The verifier is bound to the algorithm given at construction, as a KMS verify handle is. A
/// signature carrying any other algorithm fails with `InvalidArgument` before any cryptography:
/// the algorithm a [`Signature`] names usually comes from the same untrusted input as its bytes,
/// and an RSA key could otherwise be checked under six paddings and hashes the signer never
/// used. ECDSA and Ed25519 keys imply their algorithm ([`LocalVerifier::for_key`]); RSA keys need
/// it spelled out ([`LocalVerifier::new`]).
///
/// # Key versions
///
/// When both the public key and the signature carry a [`KeyVersion`](anykms_core::KeyVersion)
/// and they differ, verification fails with `VerificationFailed` without checking the signature:
/// a signature by another version never verifies under this key. That is the common case for a
/// verifier pinned to an old public key meeting a token signed after a rotation; use
/// [`CachedVerifier`](crate::CachedVerifier) to follow rotations. The error message says that the
/// versions differ.
///
/// # ECDSA malleability
///
/// ECDSA signatures are malleable: if `(r, s)` verifies, so does `(r, n - s)`. By default both
/// forms are accepted, because KMS backends do not normalize: Vault and OpenBao transit return a
/// high-S signature about half the time (measured: 18/40 P-256 and 21/40 P-384 signatures on
/// Vault 2.1, 20/40 and 25/40 on OpenBao 2.7), so rejecting high-S would reject genuine
/// signatures. Do not use an ECDSA signature's bytes as an identifier (e.g. for replay detection
/// or deduplication); use the signed message instead. Where every signer is known to produce
/// low-S signatures, [`require_low_s`](Self::require_low_s) rejects the high-S form.
///
/// Cheap to clone: the parsed key is shared.
#[derive(Clone)]
pub struct LocalVerifier {
    key: PublicKey,
    alg: SignatureAlgorithm,
    inner: std::sync::Arc<Inner>,
    require_low_s: bool,
}

impl std::fmt::Debug for LocalVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVerifier")
            .field("key", &self.key)
            .field("algorithm", &self.alg)
            .field("require_low_s", &self.require_low_s)
            .finish()
    }
}

impl LocalVerifier {
    /// Verifies `alg` signatures with `key`.
    ///
    /// Fails with `InvalidArgument` if the key is malformed or its SPKI does not match its
    /// declared key type, with `KeyMismatch` if `alg` is not an algorithm of the key's type or
    /// for RSA keys smaller than [`MIN_RSA_BITS`], and with `Unsupported` for RSA keys when no RSA
    /// backend is compiled in.
    pub fn new(key: PublicKey, alg: SignatureAlgorithm) -> Result<Self> {
        let der = key.spki_der();
        let actual = spki_key_type(der)?;
        if actual != key.key_type() {
            return Err(invalid(
                "public key type does not match its SubjectPublicKeyInfo",
            ));
        }
        if !alg.is_compatible_with(&actual) {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                Operation::Verify,
                "signature algorithm does not match the public key type",
            ));
        }
        let bad = |_| invalid("malformed public key");
        let inner = match actual {
            AsymmetricKeyType::EcP256 => {
                Inner::P256(p256::ecdsa::VerifyingKey::from_public_key_der(der).map_err(bad)?)
            }
            AsymmetricKeyType::EcP384 => {
                Inner::P384(p384::ecdsa::VerifyingKey::from_public_key_der(der).map_err(bad)?)
            }
            AsymmetricKeyType::EcP521 => {
                Inner::P521(p521::ecdsa::VerifyingKey::from_public_key_der(der).map_err(bad)?)
            }
            AsymmetricKeyType::Rsa { .. } => {
                check_rsa_key(der, Operation::Verify)?;
                Inner::Rsa(RsaVerifier::new(der, alg)?)
            }
            AsymmetricKeyType::Ed25519 => {
                Inner::Ed25519(ed25519_dalek::VerifyingKey::from_public_key_der(der).map_err(bad)?)
            }
            _ => return Err(invalid("unsupported public key type")),
        };
        Ok(Self {
            key,
            alg,
            inner: std::sync::Arc::new(inner),
            require_low_s: false,
        })
    }

    /// Verifies with `key` using the one algorithm its type implies: ECDSA with the curve's hash
    /// (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512) or Ed25519. RSA keys have several
    /// algorithms and fail with `InvalidArgument`; use [`new`](Self::new). Otherwise as `new`.
    pub fn for_key(key: PublicKey) -> Result<Self> {
        let alg = implied_algorithm(&key.key_type()).ok_or_else(|| {
            invalid("RSA keys have several signature algorithms; name one with LocalVerifier::new")
        })?;
        Self::new(key, alg)
    }

    /// Rejects ECDSA signatures whose `s` is in the upper half of the curve order (fails with
    /// `VerificationFailed`), making signatures non-malleable. **Only enable this when every
    /// signer normalizes to low-S**: Vault and OpenBao transit do not (see the
    /// [type docs](Self#ecdsa-malleability)). No effect on RSA and Ed25519 (Ed25519 is always
    /// verified strictly).
    pub fn require_low_s(mut self) -> Self {
        self.require_low_s = true;
        self
    }

    /// The public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// The only signature algorithm this verifier accepts.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    fn check_signature(&self, sig: &Signature) -> Result<()> {
        if sig.algorithm() != self.alg {
            return Err(invalid(
                "signature algorithm does not match the verifier's algorithm",
            ));
        }
        if let (Some(sv), Some(kv)) = (sig.key_version(), self.key.key_version())
            && sv != kv
        {
            return Err(Error::new(
                ErrorKind::VerificationFailed,
                BACKEND,
                Operation::Verify,
                "signature names another key version than the public key",
            ));
        }
        Ok(())
    }

    fn check_low_s(&self, is_low: bool) -> Result<()> {
        if self.require_low_s && !is_low {
            return Err(Error::new(
                ErrorKind::VerificationFailed,
                BACKEND,
                Operation::Verify,
                "high-S ECDSA signature rejected (low-S required)",
            ));
        }
        Ok(())
    }

    fn verify_prehash(&self, prehash: &[u8], sig: &[u8]) -> Result<()> {
        match &*self.inner {
            Inner::P256(k) => {
                let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| failed())?;
                self.check_low_s(s == s.normalize_s())?;
                k.verify_prehash(prehash, &s).map_err(|_| failed())
            }
            Inner::P384(k) => {
                let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| failed())?;
                self.check_low_s(s == s.normalize_s())?;
                k.verify_prehash(prehash, &s).map_err(|_| failed())
            }
            Inner::P521(k) => {
                let s = p521::ecdsa::Signature::from_der(sig).map_err(|_| failed())?;
                self.check_low_s(s == s.normalize_s())?;
                k.verify_prehash(prehash, &s).map_err(|_| failed())
            }
            Inner::Rsa(k) => k.verify_prehash(prehash, sig),
            Inner::Ed25519(_) => Err(invalid("message-signing algorithm used with a digest")),
        }
    }
}

impl crate::PinnedVerifier for LocalVerifier {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl DigestVerifier for LocalVerifier {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        self.check_signature(sig)?;
        match self.alg.hash() {
            None => return Err(invalid("message-signing algorithm used with a digest")),
            Some(h) if h != digest.algorithm() => {
                return Err(invalid(
                    "digest algorithm does not match the signature algorithm",
                ));
            }
            Some(_) => {}
        }
        self.verify_prehash(digest.as_bytes(), sig.as_bytes())
    }
}

impl MessageVerifier for LocalVerifier {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.check_signature(sig)?;
        match &*self.inner {
            Inner::Ed25519(k) => {
                let s =
                    ed25519_dalek::Signature::from_slice(sig.as_bytes()).map_err(|_| failed())?;
                k.verify_strict(msg, &s).map_err(|_| failed())
            }
            _ => Err(invalid(DIGEST_ALG_WITH_MESSAGE)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER length octets.
    fn der_len(n: usize) -> Vec<u8> {
        match n {
            0..=0x7f => vec![n as u8],
            0x80..=0xff => vec![0x81, n as u8],
            _ => vec![0x82, (n >> 8) as u8, n as u8],
        }
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(der_len(body.len()));
        v.extend_from_slice(body);
        v
    }

    /// An RSA SubjectPublicKeyInfo whose modulus has exactly `bits` bits, e = 65537. Not a real
    /// key: enough for parsing and size checks.
    fn rsa_spki(bits: usize) -> Vec<u8> {
        let len = bits.div_ceil(8);
        let mut n = vec![0xffu8; len];
        n[0] = (1u8 << ((bits - 1) % 8)) | 0x01;
        let rsa_key = tlv(
            0x30,
            &[tlv(0x02, &n), tlv(0x02, &[0x01, 0x00, 0x01])].concat(),
        );
        let alg = tlv(
            0x30,
            &[
                tlv(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                ),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let bit_string = tlv(0x03, &[&[0u8][..], &rsa_key].concat());
        tlv(0x30, &[alg, bit_string].concat())
    }

    #[test]
    fn rsa_key_sizes_are_exact_bits() {
        let der = rsa_spki(3071);
        assert_eq!(
            spki_key_type(&der).unwrap(),
            AsymmetricKeyType::Rsa { bits: 3071 }
        );
        let pk = public_key_from_spki_der(&der, None).unwrap();
        assert_eq!(pk.key_type(), AsymmetricKeyType::Rsa { bits: 3071 });
        #[cfg(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs"))]
        LocalVerifier::new(pk, SignatureAlgorithm::RsaPssSha256).unwrap();
        // 2047 bits is below the minimum, although the modulus has 256 bytes.
        let e = public_key_from_spki_der(&rsa_spki(2047), None).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    }

    fn p256_verifier() -> LocalVerifier {
        use p256::pkcs8::EncodePublicKey as _;
        let sk = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let der = sk.verifying_key().to_public_key_der().unwrap();
        LocalVerifier::for_key(public_key_from_spki_der(der.as_bytes(), None).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn message_verification_of_digest_algorithms_names_the_helper() {
        let v = p256_verifier();
        let sig = Signature::from_parts(SignatureAlgorithm::EcdsaP256Sha256, None, vec![0; 8]);
        let e = v.verify_message(b"m", &sig).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert!(e.message().contains("verify_message_hashed"), "{e}");
    }

    #[test]
    fn clones_share_the_parsed_key() {
        let v = p256_verifier();
        let c = v.clone().require_low_s();
        assert!(std::sync::Arc::ptr_eq(&v.inner, &c.inner));
        assert!(!v.require_low_s && c.require_low_s);
    }
}
