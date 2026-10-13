//! RSA public keys: parsing (backend-independent, `spki`/`der`) and signature verification with
//! the backend the crate features select (see the `rsa-rustcrypto` and `rsa-aws-lc-rs` features
//! in `Cargo.toml`). With both features, `rsa-aws-lc-rs` is used; with neither, verification fails
//! with `Unsupported`.
//!
//! Every backend verifies RSA-PSS with a salt length equal to the hash length only, and checks a
//! precomputed digest (ring is not an option for that reason).

use anykms_core::{Error, ErrorKind, Operation, Result, SignatureAlgorithm};
use spki::der::asn1::UintRef;
use spki::der::{Decode as _, Reader as _, SliceReader};

const BACKEND: &str = "local-verify";

/// The modulus and public exponent of an RSA public key (big-endian, no leading zeros).
pub(crate) struct RsaParts<'a> {
    pub(crate) n: &'a [u8],
    /// Read by the JWK only; parsing still checks it.
    #[cfg_attr(not(feature = "jose"), allow(dead_code))]
    pub(crate) e: &'a [u8],
}

impl RsaParts<'_> {
    /// The exact modulus size in bits.
    pub(crate) fn bits(&self) -> u32 {
        match self.n.first() {
            None => 0,
            Some(b) => (self.n.len() as u32 - 1) * 8 + (8 - b.leading_zeros()),
        }
    }
}

/// Parses the `RSAPublicKey` (RFC 8017) inside an RSA SubjectPublicKeyInfo. The caller has
/// checked the algorithm OID.
pub(crate) fn parse_rsa_spki(spki_der: &[u8]) -> Option<RsaParts<'_>> {
    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der).ok()?;
    let raw = spki.subject_public_key.as_bytes()?;
    let mut r = SliceReader::new(raw).ok()?;
    let (n, e) = r
        .sequence(|r| {
            let n: UintRef<'_> = r.decode()?;
            let e: UintRef<'_> = r.decode()?;
            Ok::<_, spki::der::Error>((n.as_bytes(), e.as_bytes()))
        })
        .ok()?;
    r.finish().ok()?;
    // A zero modulus or exponent, or an even exponent, is no RSA key.
    if n.is_empty() || e.last().is_none_or(|b| b & 1 == 0) {
        return None;
    }
    Some(RsaParts { n, e })
}

fn failed() -> Error {
    crate::verify::failed()
}

#[cfg(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs"))]
fn invalid(m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, Operation::Verify, m)
}

/// A RustCrypto RSA verifying key for one padding and hash, built once in [`RsaVerifier::new`]
/// (instead of cloning the key's big integers on every verify).
#[cfg(all(feature = "rsa-rustcrypto", not(feature = "rsa-aws-lc-rs")))]
enum RustCryptoKey {
    PssSha256(rsa::pss::VerifyingKey<sha2::Sha256>),
    PssSha384(rsa::pss::VerifyingKey<sha2::Sha384>),
    PssSha512(rsa::pss::VerifyingKey<sha2::Sha512>),
    Pkcs1Sha256(rsa::pkcs1v15::VerifyingKey<sha2::Sha256>),
    Pkcs1Sha384(rsa::pkcs1v15::VerifyingKey<sha2::Sha384>),
    Pkcs1Sha512(rsa::pkcs1v15::VerifyingKey<sha2::Sha512>),
}

/// An RSA public key bound to one signature algorithm, ready to verify.
#[cfg_attr(
    not(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs")),
    allow(dead_code)
)]
pub(crate) struct RsaVerifier {
    #[cfg(feature = "rsa-aws-lc-rs")]
    key: aws_lc_rs::signature::ParsedPublicKey,
    #[cfg(all(feature = "rsa-rustcrypto", not(feature = "rsa-aws-lc-rs")))]
    key: RustCryptoKey,
    /// The RustCrypto key already encodes the algorithm.
    #[cfg(any(feature = "rsa-aws-lc-rs", not(feature = "rsa-rustcrypto")))]
    alg: SignatureAlgorithm,
}

impl RsaVerifier {
    /// Parses `spki_der` (an RSA key whose size the caller has checked) for verifying `alg`.
    /// Fails with `Unsupported` when no RSA backend is compiled in.
    pub(crate) fn new(spki_der: &[u8], alg: SignatureAlgorithm) -> Result<Self> {
        #[cfg(feature = "rsa-aws-lc-rs")]
        {
            use SignatureAlgorithm::*;
            use aws_lc_rs::signature::{self as sig, RsaParameters};
            let params: &'static RsaParameters = match alg {
                RsaPssSha256 => &sig::RSA_PSS_2048_8192_SHA256,
                RsaPssSha384 => &sig::RSA_PSS_2048_8192_SHA384,
                RsaPssSha512 => &sig::RSA_PSS_2048_8192_SHA512,
                RsaPkcs1v15Sha256 => &sig::RSA_PKCS1_2048_8192_SHA256,
                RsaPkcs1v15Sha384 => &sig::RSA_PKCS1_2048_8192_SHA384,
                RsaPkcs1v15Sha512 => &sig::RSA_PKCS1_2048_8192_SHA512,
                _ => return Err(invalid("not an RSA signature algorithm")),
            };
            let key = sig::ParsedPublicKey::new(params, spki_der)
                .map_err(|_| invalid("malformed or unsupported RSA public key"))?;
            Ok(Self { key, alg })
        }
        #[cfg(all(feature = "rsa-rustcrypto", not(feature = "rsa-aws-lc-rs")))]
        {
            use SignatureAlgorithm::*;
            use rsa::{pkcs1v15, pss};
            use spki::DecodePublicKey as _;
            let k = rsa::RsaPublicKey::from_public_key_der(spki_der)
                .map_err(|_| invalid("malformed or unsupported RSA public key"))?;
            let key = match alg {
                RsaPssSha256 => RustCryptoKey::PssSha256(pss::VerifyingKey::new(k)),
                RsaPssSha384 => RustCryptoKey::PssSha384(pss::VerifyingKey::new(k)),
                RsaPssSha512 => RustCryptoKey::PssSha512(pss::VerifyingKey::new(k)),
                RsaPkcs1v15Sha256 => RustCryptoKey::Pkcs1Sha256(pkcs1v15::VerifyingKey::new(k)),
                RsaPkcs1v15Sha384 => RustCryptoKey::Pkcs1Sha384(pkcs1v15::VerifyingKey::new(k)),
                RsaPkcs1v15Sha512 => RustCryptoKey::Pkcs1Sha512(pkcs1v15::VerifyingKey::new(k)),
                _ => return Err(invalid("not an RSA signature algorithm")),
            };
            Ok(Self { key })
        }
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs")))]
        {
            let _ = (spki_der, alg);
            Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                Operation::Verify,
                "RSA verification needs an RSA backend: enable the `rsa-aws-lc-rs` or \
                 `rsa-rustcrypto` feature (of anykms, a cloud backend or anykms-recipes)",
            ))
        }
    }

    /// Verifies `sig` over the precomputed digest `prehash` (whose length the caller has checked
    /// against the algorithm's hash).
    pub(crate) fn verify_prehash(&self, prehash: &[u8], sig: &[u8]) -> Result<()> {
        #[cfg(feature = "rsa-aws-lc-rs")]
        {
            use aws_lc_rs::digest;
            let alg = match self.alg.hash() {
                Some(anykms_core::HashAlgorithm::Sha256) => &digest::SHA256,
                Some(anykms_core::HashAlgorithm::Sha384) => &digest::SHA384,
                Some(anykms_core::HashAlgorithm::Sha512) => &digest::SHA512,
                _ => return Err(invalid("unsupported hash algorithm")),
            };
            let d = digest::Digest::import_less_safe(prehash, alg)
                .map_err(|_| invalid("digest length does not match the hash algorithm"))?;
            self.key.verify_digest_sig(&d, sig).map_err(|_| failed())
        }
        #[cfg(all(feature = "rsa-rustcrypto", not(feature = "rsa-aws-lc-rs")))]
        {
            use signature::hazmat::PrehashVerifier as _;
            let pss = || rsa::pss::Signature::try_from(sig);
            let pkcs1 = || rsa::pkcs1v15::Signature::try_from(sig);
            let res = match &self.key {
                RustCryptoKey::PssSha256(k) => pss().and_then(|s| k.verify_prehash(prehash, &s)),
                RustCryptoKey::PssSha384(k) => pss().and_then(|s| k.verify_prehash(prehash, &s)),
                RustCryptoKey::PssSha512(k) => pss().and_then(|s| k.verify_prehash(prehash, &s)),
                RustCryptoKey::Pkcs1Sha256(k) => {
                    pkcs1().and_then(|s| k.verify_prehash(prehash, &s))
                }
                RustCryptoKey::Pkcs1Sha384(k) => {
                    pkcs1().and_then(|s| k.verify_prehash(prehash, &s))
                }
                RustCryptoKey::Pkcs1Sha512(k) => {
                    pkcs1().and_then(|s| k.verify_prehash(prehash, &s))
                }
            };
            res.map_err(|_| failed())
        }
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs")))]
        {
            // `new` never builds one without a backend.
            let _ = (prehash, sig, self.alg);
            Err(failed())
        }
    }
}

const OAEP: &str = "local-rsa-oaep";

/// RSAES-OAEP with SHA-256 fits `k - 2 * 32 - 2` message bytes in a `k`-byte modulus.
const OAEP_SHA256_OVERHEAD: usize = 2 * 32 + 2;

/// Encrypts (wraps) `msg` locally with an RSA public key: RSAES-OAEP with SHA-256, MGF1-SHA-256
/// and an empty label (RFC 8017), the padding the cloud KMSs call `RSA_DECRYPT_OAEP_*_SHA256`
/// (GCP), `RSAES_OAEP_SHA_256` (AWS) and `RSA-OAEP-256` (Azure).
///
/// **Emulates:** the KMS's public-key encrypt. **Enforced by:** this process, with the public key
/// only; the KMS enforces the private-key decrypt.
///
/// For RSA decryption keys without a server-side encrypt (GCP `asymmetricDecrypt`), or where a
/// local wrap saves a round trip (AWS): wrap here with the key's cached, pinned public key and
/// unwrap with the KMS. The output is randomized and as long as the modulus.
///
/// `spki_der` is a DER SubjectPublicKeyInfo. Errors (operation `Encrypt`, no I/O):
/// - `InvalidArgument`: malformed DER, or `msg` longer than the modulus size in bytes minus 66;
/// - `KeyMismatch`: not an RSA key, or an RSA key smaller than [`MIN_RSA_BITS`](crate::MIN_RSA_BITS);
/// - `Unsupported`: no RSA backend compiled in (crate features `rsa-aws-lc-rs`, the default,
///   or `rsa-rustcrypto`; with both, `rsa-aws-lc-rs` is used);
/// - `Backend`: the RSA backend or the OS RNG failed.
pub fn rsa_oaep_sha256_encrypt(spki_der: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let err = |kind, m: &'static str| Error::new(kind, OAEP, Operation::Encrypt, m);
    match crate::spki_key_type(spki_der).map_err(|_| {
        err(
            ErrorKind::InvalidArgument,
            "malformed or unsupported SubjectPublicKeyInfo",
        )
    })? {
        anykms_core::AsymmetricKeyType::Rsa { bits } if bits >= crate::MIN_RSA_BITS => {}
        anykms_core::AsymmetricKeyType::Rsa { .. } => {
            return Err(err(
                ErrorKind::KeyMismatch,
                "RSA key is smaller than 2048 bits",
            ));
        }
        _ => return Err(err(ErrorKind::KeyMismatch, "not an RSA public key")),
    }
    let parts = parse_rsa_spki(spki_der)
        .ok_or_else(|| err(ErrorKind::InvalidArgument, "malformed RSA public key"))?;
    if msg.len() + OAEP_SHA256_OVERHEAD > parts.n.len() {
        return Err(err(
            ErrorKind::InvalidArgument,
            "message too long for RSA-OAEP-SHA-256 with this key",
        ));
    }
    #[cfg(feature = "rsa-aws-lc-rs")]
    {
        use aws_lc_rs::rsa::{
            OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey,
        };
        let key = PublicEncryptingKey::from_der(spki_der)
            .ok()
            .and_then(|k| OaepPublicEncryptingKey::new(k).ok())
            .ok_or_else(|| {
                err(
                    ErrorKind::InvalidArgument,
                    "malformed or unsupported RSA public key",
                )
            })?;
        let mut out = vec![0u8; key.ciphertext_size()];
        let n = key
            .encrypt(&OAEP_SHA256_MGF1SHA256, msg, &mut out, None)
            .map_err(|_| err(ErrorKind::Backend, "RSA-OAEP encryption failed"))?
            .len();
        out.truncate(n);
        Ok(out)
    }
    #[cfg(all(feature = "rsa-rustcrypto", not(feature = "rsa-aws-lc-rs")))]
    {
        use spki::DecodePublicKey as _;
        let key = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|_| {
            err(
                ErrorKind::InvalidArgument,
                "malformed or unsupported RSA public key",
            )
        })?;
        // `rsa` takes an infallible RNG: check the OS RNG first, so a failure is `Backend` here
        // rather than a panic inside `UnwrapErr`.
        let mut probe = [0u8; 1];
        getrandom::fill(&mut probe)
            .map_err(|_| err(ErrorKind::Backend, "operating system RNG failed"))?;
        let mut rng = rsa::rand_core::UnwrapErr(getrandom::SysRng);
        key.encrypt(&mut rng, rsa::Oaep::<sha2::Sha256>::new(), msg)
            .map_err(|_| err(ErrorKind::Backend, "RSA-OAEP encryption failed"))
    }
    #[cfg(not(any(feature = "rsa-rustcrypto", feature = "rsa-aws-lc-rs")))]
    {
        Err(err(
            ErrorKind::Unsupported,
            "RSA-OAEP encryption needs an RSA backend: enable the `rsa-aws-lc-rs` or \
             `rsa-rustcrypto` feature (of anykms, a cloud backend or anykms-recipes)",
        ))
    }
}
