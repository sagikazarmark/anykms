//! Value types shared by every backend.

use std::fmt;
use std::ops::{BitOr, BitOrAssign};
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Operation, Result};

const CORE: &str = "core";

/// An opaque key version identifier.
///
/// Transit and GCP use decimal numbers (`"3"`) and Azure uses 32 hex characters. AWS exposes
/// none for symmetric keys, and the resolved key ARN for asymmetric and HMAC keys. A handle's
/// [`KeySemantics`](crate::KeySemantics) states which shape its versions have, and
/// [`Registry::pin`](crate::Registry::pin) names one version of a key in its URI. A version only ever names a version of its own key (see
/// [`PublicKeys::public_key_version`](crate::PublicKeys::public_key_version)). Compare versions only for equality; use [`KeyVersion::as_u64`] where a backend
/// defines numeric ordering.
///
/// Deliberately not `Ord`: ordering the string form would put `"10"` before `"9"`.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyVersion(Arc<str>);

impl KeyVersion {
    /// Creates a version from its string form.
    pub fn new(version: impl Into<Arc<str>>) -> Self {
        Self(version.into())
    }

    /// Creates a numeric version.
    pub fn from_u64(version: u64) -> Self {
        Self(version.to_string().into())
    }

    /// The string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The numeric value, if the version is a canonical decimal number.
    pub fn as_u64(&self) -> Option<u64> {
        let s = self.as_str();
        if s.is_empty()
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        s.parse().ok()
    }
}

impl fmt::Debug for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyVersion({:?})", &*self.0)
    }
}

impl fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<u64> for KeyVersion {
    fn from(v: u64) -> Self {
        Self::from_u64(v)
    }
}

impl From<&str> for KeyVersion {
    fn from(v: &str) -> Self {
        Self::new(v)
    }
}

/// Backend-native ciphertext bytes, opaque to callers.
///
/// Transit ciphertexts are the ASCII string `vault:vN:...`; ciphertexts produced by other Vault or
/// OpenBao clients are accepted unchanged.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Wraps raw ciphertext bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the ciphertext and returns its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the ciphertext is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The bytes as standard base64 (RFC 4648 §4 alphabet `A-Z a-z 0-9 + /`, padded with `=`),
    /// for text columns and JSON. Transit ciphertexts are already ASCII (`vault:v1:...`); this
    /// encodes them once more, so always decode with [`from_base64`](Self::from_base64).
    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.0)
    }

    /// Parses [`to_base64`](Self::to_base64) output: standard alphabet, padding required.
    ///
    /// Anything else is `DecryptFailed` (operation [`Operation::Decrypt`]), the error a decrypt
    /// of corrupt ciphertext bytes gives, so a corrupt stored value is handled like a tampered one
    /// (a [caller error](crate::Error::is_caller_error)) without a special case.
    pub fn from_base64(s: &str) -> Result<Self> {
        decode_b64(&STANDARD, s).map(Self)
    }

    /// The bytes as URL-safe base64 (RFC 4648 §5 alphabet `A-Z a-z 0-9 - _`) **without**
    /// padding, for URLs, cookies and file names.
    pub fn to_base64_url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    /// Parses [`to_base64_url`](Self::to_base64_url) output: URL-safe alphabet, no padding.
    /// Anything else is `DecryptFailed`, as for [`from_base64`](Self::from_base64).
    pub fn from_base64_url(s: &str) -> Result<Self> {
        decode_b64(&URL_SAFE_NO_PAD, s).map(Self)
    }
}

/// Decodes base64 ciphertext; errors are `DecryptFailed` / `Decrypt`.
fn decode_b64(engine: &base64::engine::GeneralPurpose, s: &str) -> Result<Vec<u8>> {
    engine.decode(s).map_err(|_| {
        Error::new(
            ErrorKind::DecryptFailed,
            CORE,
            Operation::Decrypt,
            "invalid base64 ciphertext",
        )
    })
}

/// Decodes a base64 signature or tag; errors are `VerificationFailed` / `op`.
fn decode_stored(
    engine: &base64::engine::GeneralPurpose,
    s: &str,
    op: Operation,
) -> Result<Vec<u8>> {
    engine
        .decode(s)
        .map_err(|_| Error::new(ErrorKind::VerificationFailed, CORE, op, "invalid base64"))
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext({} bytes)", self.0.len())
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for Ciphertext {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash algorithms used for digests.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Output length in bytes.
    pub fn output_len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Lowercase name (`"sha256"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A message digest tagged with its algorithm. The length is validated on construction.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest {
    alg: HashAlgorithm,
    bytes: [u8; 64],
    len: u8,
}

impl Digest {
    /// Wraps a digest computed elsewhere. Fails with `InvalidArgument` (operation
    /// [`Operation::Construct`]) when the length does not match the algorithm; use
    /// [`Error::with_operation`] to re-label it for the operation the digest was meant for.
    pub fn new(alg: HashAlgorithm, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != alg.output_len() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                CORE,
                Operation::Construct,
                "digest length does not match its hash algorithm",
            ));
        }
        let mut buf = [0u8; 64];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            alg,
            bytes: buf,
            len: bytes.len() as u8,
        })
    }

    /// The hash algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.alg
    }

    /// The digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Hashes `msg` with `alg`.
    #[cfg(feature = "digest")]
    pub fn compute(alg: HashAlgorithm, msg: &[u8]) -> Self {
        use sha2::Digest as _;
        match alg {
            HashAlgorithm::Sha256 => Self::new(alg, &sha2::Sha256::digest(msg)),
            HashAlgorithm::Sha384 => Self::new(alg, &sha2::Sha384::digest(msg)),
            HashAlgorithm::Sha512 => Self::new(alg, &sha2::Sha512::digest(msg)),
        }
        .expect("hash output length matches its algorithm")
    }

    /// SHA-256 of `msg`.
    #[cfg(feature = "digest")]
    pub fn sha256(msg: &[u8]) -> Self {
        Self::compute(HashAlgorithm::Sha256, msg)
    }

    /// SHA-384 of `msg`.
    #[cfg(feature = "digest")]
    pub fn sha384(msg: &[u8]) -> Self {
        Self::compute(HashAlgorithm::Sha384, msg)
    }

    /// SHA-512 of `msg`.
    #[cfg(feature = "digest")]
    pub fn sha512(msg: &[u8]) -> Self {
        Self::compute(HashAlgorithm::Sha512, msg)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({}, ", self.alg)?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// Asymmetric key types.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AsymmetricKeyType {
    EcP256,
    EcP384,
    EcP521,
    Rsa {
        /// Modulus size in bits.
        bits: u32,
    },
    Ed25519,
}

/// Signature algorithms.
///
/// Signature bytes are ASN.1 DER for ECDSA and raw for RSA and Ed25519. RSA-PSS always uses a salt
/// length equal to the hash length.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha512,
    /// Pure Ed25519 over the message (no pre-hashing).
    Ed25519,
}

/// What a signer takes as input: a digest computed by the caller (ECDSA, RSA) or the whole
/// message (Ed25519). See [`SignatureAlgorithm::shape`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningShape {
    /// [`DigestSigner`](crate::DigestSigner) / [`DigestVerifier`](crate::DigestVerifier).
    Digest,
    /// [`MessageSigner`](crate::MessageSigner) / [`MessageVerifier`](crate::MessageVerifier).
    Message,
}

impl SignatureAlgorithm {
    /// All algorithms. New algorithms may be appended in any release.
    pub const ALL: &'static [SignatureAlgorithm] = &[
        SignatureAlgorithm::EcdsaP256Sha256,
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP521Sha512,
        SignatureAlgorithm::RsaPssSha256,
        SignatureAlgorithm::RsaPssSha384,
        SignatureAlgorithm::RsaPssSha512,
        SignatureAlgorithm::RsaPkcs1v15Sha256,
        SignatureAlgorithm::RsaPkcs1v15Sha384,
        SignatureAlgorithm::RsaPkcs1v15Sha512,
        SignatureAlgorithm::Ed25519,
    ];

    /// The hash the algorithm signs, or `None` for Ed25519 (message signing).
    pub fn hash(&self) -> Option<HashAlgorithm> {
        use SignatureAlgorithm::*;
        match self {
            EcdsaP256Sha256 | RsaPssSha256 | RsaPkcs1v15Sha256 => Some(HashAlgorithm::Sha256),
            EcdsaP384Sha384 | RsaPssSha384 | RsaPkcs1v15Sha384 => Some(HashAlgorithm::Sha384),
            EcdsaP521Sha512 | RsaPssSha512 | RsaPkcs1v15Sha512 => Some(HashAlgorithm::Sha512),
            Ed25519 => None,
        }
    }

    /// Whether the algorithm signs messages rather than digests.
    pub fn is_message_signing(&self) -> bool {
        self.hash().is_none()
    }

    /// What a signer of this algorithm takes as input.
    pub fn shape(&self) -> SigningShape {
        if self.is_message_signing() {
            SigningShape::Message
        } else {
            SigningShape::Digest
        }
    }

    /// Refuses this algorithm for a handle of the other shape (a digest-signing algorithm opened
    /// as a message signer, or the reverse) with `KeyMismatch` on [`Operation::Open`], labelled
    /// with `backend`: the check every [`Provider`](crate::Provider) makes when opening signers,
    /// verifiers and public-key sources of one shape.
    pub fn require_shape(&self, shape: SigningShape, backend: &'static str) -> Result<()> {
        if self.shape() == shape {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::KeyMismatch,
            backend,
            Operation::Open,
            match shape {
                SigningShape::Message => "digest-signing algorithm opened as a message signer",
                SigningShape::Digest => {
                    "message-signing algorithm (Ed25519) opened as a digest signer; open it as \
                     a message signer"
                }
            },
        ))
    }

    /// Whether a key of type `key_type` can produce signatures of this algorithm.
    pub fn is_compatible_with(&self, key_type: &AsymmetricKeyType) -> bool {
        use SignatureAlgorithm::*;
        match self {
            EcdsaP256Sha256 => *key_type == AsymmetricKeyType::EcP256,
            EcdsaP384Sha384 => *key_type == AsymmetricKeyType::EcP384,
            EcdsaP521Sha512 => *key_type == AsymmetricKeyType::EcP521,
            RsaPssSha256 | RsaPssSha384 | RsaPssSha512 | RsaPkcs1v15Sha256 | RsaPkcs1v15Sha384
            | RsaPkcs1v15Sha512 => matches!(key_type, AsymmetricKeyType::Rsa { .. }),
            Ed25519 => *key_type == AsymmetricKeyType::Ed25519,
        }
    }

    /// The JOSE `alg` value, where one exists.
    pub fn jws_alg(&self) -> Option<&'static str> {
        use SignatureAlgorithm::*;
        Some(match self {
            EcdsaP256Sha256 => "ES256",
            EcdsaP384Sha384 => "ES384",
            EcdsaP521Sha512 => "ES512",
            RsaPssSha256 => "PS256",
            RsaPssSha384 => "PS384",
            RsaPssSha512 => "PS512",
            RsaPkcs1v15Sha256 => "RS256",
            RsaPkcs1v15Sha384 => "RS384",
            RsaPkcs1v15Sha512 => "RS512",
            Ed25519 => "EdDSA",
        })
    }

    /// Stable lowercase name (`"ecdsa-p256-sha256"`).
    pub fn as_str(&self) -> &'static str {
        use SignatureAlgorithm::*;
        match self {
            EcdsaP256Sha256 => "ecdsa-p256-sha256",
            EcdsaP384Sha384 => "ecdsa-p384-sha384",
            EcdsaP521Sha512 => "ecdsa-p521-sha512",
            RsaPssSha256 => "rsa-pss-sha256",
            RsaPssSha384 => "rsa-pss-sha384",
            RsaPssSha512 => "rsa-pss-sha512",
            RsaPkcs1v15Sha256 => "rsa-pkcs1v15-sha256",
            RsaPkcs1v15Sha384 => "rsa-pkcs1v15-sha384",
            RsaPkcs1v15Sha512 => "rsa-pkcs1v15-sha512",
            Ed25519 => "ed25519",
        }
    }

    /// Parses [`SignatureAlgorithm::as_str`] output.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.as_str() == name)
    }

    /// Parses a JOSE `alg` value ([`jws_alg`](Self::jws_alg)); `"Ed25519"` (RFC 9864) is
    /// accepted next to `"EdDSA"`.
    pub fn from_jws_alg(alg: &str) -> Option<Self> {
        if alg == "Ed25519" {
            return Some(SignatureAlgorithm::Ed25519);
        }
        Self::ALL.iter().copied().find(|a| a.jws_alg() == Some(alg))
    }

    /// The storage code (see [`crate::encoding`]). Codes are explicit, stable and never reused:
    /// a new variant gets the next unused code, wherever it is declared.
    pub(crate) fn code(&self) -> u8 {
        use SignatureAlgorithm::*;
        match self {
            EcdsaP256Sha256 => 1,
            EcdsaP384Sha384 => 2,
            EcdsaP521Sha512 => 3,
            RsaPssSha256 => 4,
            RsaPssSha384 => 5,
            RsaPssSha512 => 6,
            RsaPkcs1v15Sha256 => 7,
            RsaPkcs1v15Sha384 => 8,
            RsaPkcs1v15Sha512 => 9,
            Ed25519 => 10,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.code() == code)
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses a stable name ([`SignatureAlgorithm::as_str`], `"ecdsa-p256-sha256"`) or a JOSE `alg`
/// ([`SignatureAlgorithm::from_jws_alg`], `"ES256"`), for algorithms read from configuration.
/// Anything else is `InvalidArgument`.
impl FromStr for SignatureAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_name(s)
            .or_else(|| Self::from_jws_alg(s))
            .ok_or_else(|| unknown_algorithm("signature", s))
    }
}

fn unknown_algorithm(what: &str, s: &str) -> Error {
    // The input comes from configuration, not from a secret, so naming it is safe and useful.
    Error::new(
        ErrorKind::InvalidArgument,
        "anykms",
        Operation::Construct,
        format!("unknown {what} algorithm {s:?}"),
    )
}

/// MAC algorithms. Tags are full length (never truncated).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MacAlgorithm {
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl MacAlgorithm {
    /// All algorithms. New algorithms may be appended in any release.
    pub const ALL: &'static [MacAlgorithm] = &[
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ];

    /// The underlying hash.
    pub fn hash(&self) -> HashAlgorithm {
        match self {
            MacAlgorithm::HmacSha256 => HashAlgorithm::Sha256,
            MacAlgorithm::HmacSha384 => HashAlgorithm::Sha384,
            MacAlgorithm::HmacSha512 => HashAlgorithm::Sha512,
        }
    }

    /// Tag length in bytes.
    pub fn tag_len(&self) -> usize {
        self.hash().output_len()
    }

    /// Stable lowercase name (`"hmac-sha256"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            MacAlgorithm::HmacSha256 => "hmac-sha256",
            MacAlgorithm::HmacSha384 => "hmac-sha384",
            MacAlgorithm::HmacSha512 => "hmac-sha512",
        }
    }

    /// Parses [`MacAlgorithm::as_str`] output.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.as_str() == name)
    }

    /// The storage code (see [`crate::encoding`]); explicit, stable and never reused.
    pub(crate) fn code(&self) -> u8 {
        match self {
            MacAlgorithm::HmacSha256 => 1,
            MacAlgorithm::HmacSha384 => 2,
            MacAlgorithm::HmacSha512 => 3,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.code() == code)
    }
}

impl fmt::Display for MacAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses [`MacAlgorithm::as_str`] output (`"hmac-sha256"`); anything else is `InvalidArgument`.
impl FromStr for MacAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_name(s).ok_or_else(|| unknown_algorithm("MAC", s))
    }
}

/// A signature, tagged with its algorithm and, where the backend has one, the key version that
/// produced it.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    alg: SignatureAlgorithm,
    key_version: Option<KeyVersion>,
    bytes: Vec<u8>,
}

impl Signature {
    /// Builds a signature from its parts, e.g. for verify-only callers.
    pub fn from_parts(
        alg: SignatureAlgorithm,
        key_version: Option<KeyVersion>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            alg,
            key_version,
            bytes: bytes.into(),
        }
    }

    /// The algorithm.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    /// The key version that produced the signature, if known.
    pub fn key_version(&self) -> Option<&KeyVersion> {
        self.key_version.as_ref()
    }

    /// The signature bytes (DER for ECDSA, raw otherwise).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the signature and returns its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The canonical storage encoding ([`encoding::encode_signature`](crate::encoding::encode_signature):
    /// algorithm, key version and bytes) as standard base64 (padded), for text columns and JSON.
    /// Decode with [`from_base64`](Self::from_base64).
    ///
    /// Fails with `InvalidArgument` only for a key version longer than 255 bytes, which no
    /// backend issues (see the [`encoding`](crate::encoding) docs).
    pub fn to_base64(&self) -> Result<String> {
        Ok(STANDARD.encode(crate::encoding::encode_signature(self)?))
    }

    /// Parses [`to_base64`](Self::to_base64) output. Anything else (bad base64 or a bad
    /// encoding) is `VerificationFailed` (operation [`Operation::Verify`]), as for a signature
    /// that does not verify.
    pub fn from_base64(s: &str) -> Result<Self> {
        crate::encoding::decode_signature(&decode_stored(&STANDARD, s, Operation::Verify)?)
    }

    /// Like [`to_base64`](Self::to_base64), with the URL-safe alphabet and no padding, for URLs,
    /// cookies and file names.
    pub fn to_base64_url(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(crate::encoding::encode_signature(self)?))
    }

    /// Parses [`to_base64_url`](Self::to_base64_url) output; errors as for
    /// [`from_base64`](Self::from_base64).
    pub fn from_base64_url(s: &str) -> Result<Self> {
        crate::encoding::decode_signature(&decode_stored(&URL_SAFE_NO_PAD, s, Operation::Verify)?)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("alg", &self.alg)
            .field("key_version", &self.key_version)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A MAC tag, tagged with its algorithm and key version.
///
/// `PartialEq` is **not** constant-time: verify tags with [`Mac::verify_mac`](crate::Mac::verify_mac),
/// never with `==`.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Tag {
    alg: MacAlgorithm,
    key_version: Option<KeyVersion>,
    bytes: Vec<u8>,
}

impl Tag {
    /// Builds a tag from its parts.
    pub fn from_parts(
        alg: MacAlgorithm,
        key_version: Option<KeyVersion>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            alg,
            key_version,
            bytes: bytes.into(),
        }
    }

    /// The algorithm.
    pub fn algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    /// The key version that produced the tag, if known.
    pub fn key_version(&self) -> Option<&KeyVersion> {
        self.key_version.as_ref()
    }

    /// The raw MAC bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The canonical storage encoding ([`encoding::encode_tag`](crate::encoding::encode_tag):
    /// algorithm, key version and bytes) as standard base64 (padded), for text columns and JSON.
    /// Decode with [`from_base64`](Self::from_base64).
    ///
    /// Fails with `InvalidArgument` only for a key version longer than 255 bytes, which no
    /// backend issues (see the [`encoding`](crate::encoding) docs).
    pub fn to_base64(&self) -> Result<String> {
        Ok(STANDARD.encode(crate::encoding::encode_tag(self)?))
    }

    /// Parses [`to_base64`](Self::to_base64) output. Anything else (bad base64 or a bad
    /// encoding) is `VerificationFailed` (operation [`Operation::VerifyMac`]), as for a tag that
    /// does not verify.
    pub fn from_base64(s: &str) -> Result<Self> {
        crate::encoding::decode_tag(&decode_stored(&STANDARD, s, Operation::VerifyMac)?)
    }

    /// Like [`to_base64`](Self::to_base64), with the URL-safe alphabet and no padding, for URLs,
    /// cookies and file names.
    pub fn to_base64_url(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(crate::encoding::encode_tag(self)?))
    }

    /// Parses [`to_base64_url`](Self::to_base64_url) output; errors as for
    /// [`from_base64`](Self::from_base64).
    pub fn from_base64_url(s: &str) -> Result<Self> {
        crate::encoding::decode_tag(&decode_stored(&URL_SAFE_NO_PAD, s, Operation::VerifyMac)?)
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tag")
            .field("alg", &self.alg)
            .field("key_version", &self.key_version)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A public key in SubjectPublicKeyInfo DER form.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    key_type: AsymmetricKeyType,
    spki_der: Vec<u8>,
    version: Option<KeyVersion>,
}

impl PublicKey {
    /// Builds a public key from its parts.
    pub fn new(
        key_type: AsymmetricKeyType,
        spki_der: impl Into<Vec<u8>>,
        version: Option<KeyVersion>,
    ) -> Self {
        Self {
            key_type,
            spki_der: spki_der.into(),
            version,
        }
    }

    /// The key type.
    pub fn key_type(&self) -> AsymmetricKeyType {
        self.key_type
    }

    /// SubjectPublicKeyInfo DER.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The key version, if known.
    pub fn key_version(&self) -> Option<&KeyVersion> {
        self.version.as_ref()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("key_type", &self.key_type)
            .field("version", &self.version)
            .field("spki_len", &self.spki_der.len())
            .finish()
    }
}

/// Data key specifications.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataKeySpec {
    /// A 256-bit AES key.
    Aes256,
}

impl DataKeySpec {
    /// Key length in bytes.
    pub fn len(&self) -> usize {
        match self {
            DataKeySpec::Aes256 => 32,
        }
    }

    /// Always `false`; present for API symmetry with `len`.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// A data key: the plaintext key (zeroized on drop) and the same key wrapped by the KMS key.
///
/// Deliberately not `Clone` and not serializable; `Debug` does not reveal the plaintext.
///
/// Not boxed: the plaintext already lives on the heap in a `Zeroizing<Vec<u8>>`, so moving a
/// `DataKey` copies only pointers and lengths, never key bytes.
#[non_exhaustive]
pub struct DataKey {
    spec: DataKeySpec,
    plaintext: Zeroizing<Vec<u8>>,
    ciphertext: Ciphertext,
}

impl DataKey {
    /// Builds a data key, checking the plaintext length against `spec`.
    pub fn new(
        spec: DataKeySpec,
        plaintext: Zeroizing<Vec<u8>>,
        ciphertext: Ciphertext,
    ) -> Result<Self> {
        if plaintext.len() != spec.len() {
            return Err(Error::new(
                ErrorKind::Backend,
                CORE,
                Operation::GenerateDataKey,
                "data key has the wrong length for its spec",
            ));
        }
        Ok(Self {
            spec,
            plaintext,
            ciphertext,
        })
    }

    /// The spec.
    pub fn spec(&self) -> DataKeySpec {
        self.spec
    }

    /// The plaintext key. Do not store it.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// The wrapped key, decryptable with the KMS key's `Aead::decrypt` and the same AAD.
    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    /// Splits the data key into its parts.
    pub fn into_parts(self) -> (Zeroizing<Vec<u8>>, Ciphertext) {
        (self.plaintext, self.ciphertext)
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataKey")
            .field("spec", &self.spec)
            .field("plaintext", &"<redacted>")
            .field("ciphertext", &self.ciphertext)
            .finish()
    }
}

/// A decrypted plaintext with what the backend revealed about how it was decrypted, from
/// [`Aead::decrypt_with_info`](crate::Aead::decrypt_with_info).
///
/// `Debug` does not reveal the plaintext.
#[non_exhaustive]
pub struct Decrypted {
    plaintext: Zeroizing<Vec<u8>>,
    version: Option<KeyVersion>,
    used_primary: Option<bool>,
}

impl Decrypted {
    /// A plaintext with no version information.
    pub fn new(plaintext: Zeroizing<Vec<u8>>) -> Self {
        Self {
            plaintext,
            version: None,
            used_primary: None,
        }
    }

    /// Sets the key version that decrypted the ciphertext.
    pub fn with_version(mut self, version: Option<KeyVersion>) -> Self {
        self.version = version;
        self
    }

    /// Sets whether that version is the key's primary (current) version.
    pub fn with_used_primary(mut self, used_primary: Option<bool>) -> Self {
        self.used_primary = used_primary;
        self
    }

    /// The plaintext.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Consumes the value and returns the plaintext.
    pub fn into_plaintext(self) -> Zeroizing<Vec<u8>> {
        self.plaintext
    }

    /// The key version that decrypted the ciphertext, or `None` where the backend does not reveal
    /// it (see [`Aead::ciphertext_version`](crate::Aead::ciphertext_version)).
    pub fn key_version(&self) -> Option<&KeyVersion> {
        self.version.as_ref()
    }

    /// Whether the ciphertext was decrypted with the key's primary version: `Some(false)` means
    /// the data is on an old version and should be rewrapped. `None` where the backend does not
    /// say (the default implementation never knows).
    pub fn used_primary(&self) -> Option<bool> {
        self.used_primary
    }
}

impl fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decrypted")
            .field("plaintext", &"<redacted>")
            .field("version", &self.version)
            .field("used_primary", &self.used_primary)
            .finish()
    }
}

/// A set of capabilities a key supports.
///
/// Capabilities describe operation families, not every option of them. In particular
/// [`DATA_KEYS`](Self::DATA_KEYS) does not imply that data keys can be bound to AAD: Vault
/// transit generates data keys but refuses non-empty AAD for them (`Unsupported`), while OpenBao
/// 2.5+ binds it. Use emulated data keys where AAD binding is required.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capabilities(u32);

impl Capabilities {
    pub const NONE: Capabilities = Capabilities(0);
    pub const AEAD: Capabilities = Capabilities(1 << 0);
    pub const DATA_KEYS: Capabilities = Capabilities(1 << 1);
    pub const REWRAP: Capabilities = Capabilities(1 << 2);
    pub const SIGN: Capabilities = Capabilities(1 << 3);
    pub const VERIFY: Capabilities = Capabilities(1 << 4);
    pub const MAC: Capabilities = Capabilities(1 << 5);
    pub const PUBLIC_KEY: Capabilities = Capabilities(1 << 6);
    /// Wraps and unwraps key material: the key opens as a [`KeyWrapKey`](crate::KeyWrapKey)
    /// ([`Provider::key_wrap`](crate::Provider::key_wrap)), e.g. as an envelope KEK. Natively
    /// (RSA-OAEP, AES key wrap; then usually without [`AEAD`](Self::AEAD)) or, for the AEAD keys
    /// of the built-in backends, by encrypting with empty AAD
    /// ([`AeadKeyWrap`](crate::AeadKeyWrap)).
    pub const KEY_WRAP: Capabilities = Capabilities(1 << 7);

    const NAMES: [(Capabilities, &'static str); 8] = [
        (Self::AEAD, "AEAD"),
        (Self::DATA_KEYS, "DATA_KEYS"),
        (Self::REWRAP, "REWRAP"),
        (Self::SIGN, "SIGN"),
        (Self::VERIFY, "VERIFY"),
        (Self::MAC, "MAC"),
        (Self::PUBLIC_KEY, "PUBLIC_KEY"),
        (Self::KEY_WRAP, "KEY_WRAP"),
    ];

    /// Whether all capabilities in `other` are present.
    pub fn contains(&self, other: Capabilities) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether no capability is present.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl BitOr for Capabilities {
    type Output = Capabilities;
    fn bitor(self, rhs: Self) -> Self {
        Capabilities(self.0 | rhs.0)
    }
}

impl BitOrAssign for Capabilities {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Debug for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = Self::NAMES
            .iter()
            .filter(|(c, _)| self.contains(*c))
            .map(|(_, n)| *n)
            .collect();
        write!(f, "Capabilities({})", names.join(" | "))
    }
}

/// Key (or key version) state.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyState {
    Enabled,
    Disabled,
    /// Scheduled for deletion or soft-deleted; may be restorable.
    PendingDeletion,
    Destroyed,
    /// A backend state with no portable equivalent.
    Unknown(String),
}

/// Information about one key version.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyVersionInfo {
    version: KeyVersion,
    state: KeyState,
    created_at: Option<u64>,
    signature_algorithm: Option<SignatureAlgorithm>,
    mac_algorithm: Option<MacAlgorithm>,
}

impl KeyVersionInfo {
    /// Creates version info.
    pub fn new(version: KeyVersion, state: KeyState) -> Self {
        Self {
            version,
            state,
            created_at: None,
            signature_algorithm: None,
            mac_algorithm: None,
        }
    }

    /// Sets the creation time as Unix seconds.
    pub fn with_created_at(mut self, created_at: Option<u64>) -> Self {
        self.created_at = created_at;
        self
    }

    /// The version.
    pub fn version(&self) -> &KeyVersion {
        &self.version
    }

    /// Its state.
    pub fn state(&self) -> &KeyState {
        &self.state
    }

    /// Creation time as Unix seconds, if known.
    pub fn created_at(&self) -> Option<u64> {
        self.created_at
    }

    /// Sets the signature algorithm of this version, for backends where it is per version
    /// (GCP).
    pub fn with_signature_algorithm(mut self, alg: Option<SignatureAlgorithm>) -> Self {
        self.signature_algorithm = alg;
        self
    }

    /// The signature algorithm of this version, where the backend reports one per version
    /// (GCP); `None` otherwise (see [`KeyInfo::signature_algorithms`] for the key's).
    pub fn signature_algorithm(&self) -> Option<SignatureAlgorithm> {
        self.signature_algorithm
    }

    /// Sets the MAC algorithm of this version, for backends where it is per version (GCP).
    pub fn with_mac_algorithm(mut self, alg: Option<MacAlgorithm>) -> Self {
        self.mac_algorithm = alg;
        self
    }

    /// The MAC algorithm of this version, where the backend reports one per version (GCP);
    /// `None` otherwise (see [`KeyInfo::mac_algorithm`] for the key's).
    pub fn mac_algorithm(&self) -> Option<MacAlgorithm> {
        self.mac_algorithm
    }
}

/// Portable key metadata. Backend-specific metadata lives on backend types.
///
/// Backends differ in their versioning model: Vault and OpenBao transit keys have a primary
/// (latest) version that new operations use, while GCP asymmetric and MAC keys have no primary
/// version at all (each operation names a version) and keep state only per version. Fields a
/// backend has no notion of are `None`.
///
/// The backend's own metadata (e.g. `AwsKeyInfo`) rides along:
/// [`backend_info`](Self::backend_info). Equality ignores it.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct KeyInfo {
    backend_key_type: String,
    capabilities: Capabilities,
    signature_algorithms: Vec<SignatureAlgorithm>,
    mac_algorithm: Option<MacAlgorithm>,
    state: Option<KeyState>,
    primary_version: Option<KeyVersion>,
    versions: Vec<KeyVersionInfo>,
    backend: Option<Arc<dyn BackendInfo>>,
}

/// Backend metadata carried by a [`KeyInfo`].
trait BackendInfo: std::any::Any + Send + Sync + fmt::Debug {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: std::any::Any + Send + Sync + fmt::Debug> BackendInfo for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PartialEq for KeyInfo {
    fn eq(&self, other: &Self) -> bool {
        self.backend_key_type == other.backend_key_type
            && self.capabilities == other.capabilities
            && self.signature_algorithms == other.signature_algorithms
            && self.mac_algorithm == other.mac_algorithm
            && self.state == other.state
            && self.primary_version == other.primary_version
            && self.versions == other.versions
    }
}

impl Eq for KeyInfo {}

impl KeyInfo {
    /// Creates key info for a backend key type, with no key-level state and no primary version.
    pub fn new(backend_key_type: impl Into<String>, capabilities: Capabilities) -> Self {
        Self {
            backend_key_type: backend_key_type.into(),
            capabilities,
            signature_algorithms: Vec::new(),
            mac_algorithm: None,
            state: None,
            primary_version: None,
            versions: Vec::new(),
            backend: None,
        }
    }

    /// Attaches the backend's own metadata (`TransitKeyInfo`, `AwsKeyInfo`, ...), read back with
    /// [`backend_info`](Self::backend_info). It must carry no policy documents, credentials or
    /// secrets: `KeyInfo`'s `Debug` prints it.
    pub fn with_backend_info<T: std::any::Any + Send + Sync + fmt::Debug>(
        mut self,
        info: T,
    ) -> Self {
        self.backend = Some(Arc::new(info));
        self
    }

    /// The backend's own metadata, if it is a `T`.
    pub fn backend_info<T: std::any::Any>(&self) -> Option<&T> {
        self.backend.as_deref()?.as_any().downcast_ref()
    }

    /// The type of the backend's metadata, if any (e.g. to check which backend described a key).
    pub fn backend_info_type_id(&self) -> Option<std::any::TypeId> {
        self.backend.as_deref().map(|b| b.as_any().type_id())
    }

    /// Sets the signature algorithms the key supports.
    pub fn with_signature_algorithms(mut self, algs: Vec<SignatureAlgorithm>) -> Self {
        self.signature_algorithms = algs;
        self
    }

    /// Sets the MAC algorithm of a MAC key.
    pub fn with_mac_algorithm(mut self, alg: Option<MacAlgorithm>) -> Self {
        self.mac_algorithm = alg;
        self
    }

    /// Sets the key-level state.
    pub fn with_state(mut self, state: Option<KeyState>) -> Self {
        self.state = state;
        self
    }

    /// Sets the primary version.
    pub fn with_primary_version(mut self, v: Option<KeyVersion>) -> Self {
        self.primary_version = v;
        self
    }

    /// Sets the version list.
    pub fn with_versions(mut self, versions: Vec<KeyVersionInfo>) -> Self {
        self.versions = versions;
        self
    }

    /// The backend's native key type (e.g. `"aes256-gcm96"`).
    pub fn backend_key_type(&self) -> &str {
        &self.backend_key_type
    }

    /// Supported capabilities.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Supported signature algorithms (empty for non-signing keys).
    pub fn signature_algorithms(&self) -> &[SignatureAlgorithm] {
        &self.signature_algorithms
    }

    /// The MAC algorithm of a MAC key: the one the handle was opened for, or the one the key
    /// fixes. `None` for other keys and where the backend cannot tell.
    pub fn mac_algorithm(&self) -> Option<MacAlgorithm> {
        self.mac_algorithm
    }

    /// The key-level state, or `None` where the backend keeps state only per version (see
    /// [`versions`](Self::versions)) or does not report it.
    pub fn state(&self) -> Option<&KeyState> {
        self.state.as_ref()
    }

    /// The version new operations use by default, or `None` where the backend has no such
    /// version (e.g. GCP asymmetric and MAC keys, which always operate on a pinned version) or
    /// does not report it.
    pub fn primary_version(&self) -> Option<&KeyVersion> {
        self.primary_version.as_ref()
    }

    /// Known versions. Backends may omit versions they hide (e.g. transit omits versions below
    /// the minimum decryption version, and HMAC keys report none).
    pub fn versions(&self) -> &[KeyVersionInfo] {
        &self.versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_info_algorithms() {
        let v = KeyVersionInfo::new(KeyVersion::from_u64(1), KeyState::Enabled);
        assert_eq!((v.signature_algorithm(), v.mac_algorithm()), (None, None));
        let v = v
            .with_signature_algorithm(Some(SignatureAlgorithm::EcdsaP256Sha256))
            .with_mac_algorithm(Some(MacAlgorithm::HmacSha256));
        assert_eq!(
            v.signature_algorithm(),
            Some(SignatureAlgorithm::EcdsaP256Sha256)
        );
        assert_eq!(v.mac_algorithm(), Some(MacAlgorithm::HmacSha256));
    }

    #[test]
    fn algorithms_parse_from_names_and_jose() {
        for a in SignatureAlgorithm::ALL {
            assert_eq!(a.as_str().parse::<SignatureAlgorithm>().unwrap(), *a);
            assert_eq!(
                a.jws_alg().unwrap().parse::<SignatureAlgorithm>().unwrap(),
                *a
            );
        }
        assert_eq!(
            "Ed25519".parse::<SignatureAlgorithm>().unwrap(),
            SignatureAlgorithm::Ed25519
        );
        let e = "es256".parse::<SignatureAlgorithm>().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        for a in MacAlgorithm::ALL {
            assert_eq!(a.as_str().parse::<MacAlgorithm>().unwrap(), *a);
        }
        assert!("HS256".parse::<MacAlgorithm>().is_err());
    }

    #[test]
    fn signing_shape() {
        let ec = SignatureAlgorithm::EcdsaP256Sha256;
        let ed = SignatureAlgorithm::Ed25519;
        assert_eq!(ec.shape(), SigningShape::Digest);
        assert_eq!(ed.shape(), SigningShape::Message);
        ec.require_shape(SigningShape::Digest, "b").unwrap();
        ed.require_shape(SigningShape::Message, "b").unwrap();
        for e in [
            ec.require_shape(SigningShape::Message, "b").unwrap_err(),
            ed.require_shape(SigningShape::Digest, "b").unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.backend(), e.operation()),
                (ErrorKind::KeyMismatch, "b", Operation::Open)
            );
        }
    }

    #[test]
    fn key_version_numeric() {
        assert_eq!(KeyVersion::from(3).as_u64(), Some(3));
        assert_eq!(KeyVersion::new("03").as_u64(), None);
        assert_eq!(KeyVersion::new("abc").as_u64(), None);
        assert_eq!(KeyVersion::new("").as_u64(), None);
    }

    #[test]
    fn digest_length_validated() {
        let e = Digest::new(HashAlgorithm::Sha384, &[0; 32]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert_eq!(e.operation(), Operation::Construct);
        let d = Digest::new(HashAlgorithm::Sha512, &[1; 64]).unwrap();
        assert_eq!(d.as_bytes().len(), 64);
    }

    #[cfg(feature = "digest")]
    #[test]
    fn digest_compute() {
        assert_eq!(Digest::sha256(b"abc").as_bytes().len(), 32);
        assert_eq!(Digest::sha512(b"abc").algorithm(), HashAlgorithm::Sha512);
    }

    #[test]
    fn data_key_debug_redacts() {
        let k = DataKey::new(
            DataKeySpec::Aes256,
            Zeroizing::new(vec![0x41; 32]),
            Ciphertext::from_bytes(b"c".to_vec()),
        )
        .unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("redacted") && !s.contains("65") && !s.contains("AAAA"));
        assert!(
            DataKey::new(
                DataKeySpec::Aes256,
                Zeroizing::new(vec![0; 16]),
                Ciphertext::from_bytes(vec![])
            )
            .is_err()
        );
    }

    #[test]
    fn algorithm_codes_roundtrip() {
        for &a in SignatureAlgorithm::ALL {
            assert_eq!(SignatureAlgorithm::from_code(a.code()), Some(a));
            assert_eq!(SignatureAlgorithm::from_name(a.as_str()), Some(a));
        }
        assert_eq!(SignatureAlgorithm::from_code(0), None);
        for &a in MacAlgorithm::ALL {
            assert_eq!(MacAlgorithm::from_code(a.code()), Some(a));
        }
        assert_eq!(MacAlgorithm::from_code(0), None);
    }

    /// Stored signatures and tags carry these codes: they must never change.
    #[test]
    fn algorithm_codes_are_pinned() {
        use SignatureAlgorithm::*;
        let sig = [
            (EcdsaP256Sha256, 1),
            (EcdsaP384Sha384, 2),
            (EcdsaP521Sha512, 3),
            (RsaPssSha256, 4),
            (RsaPssSha384, 5),
            (RsaPssSha512, 6),
            (RsaPkcs1v15Sha256, 7),
            (RsaPkcs1v15Sha384, 8),
            (RsaPkcs1v15Sha512, 9),
            (Ed25519, 10),
        ];
        assert_eq!(sig.len(), SignatureAlgorithm::ALL.len());
        for (a, code) in sig {
            assert_eq!(a.code(), code, "{a}");
            assert_eq!(SignatureAlgorithm::from_code(code), Some(a));
        }
        let mac = [
            (MacAlgorithm::HmacSha256, 1),
            (MacAlgorithm::HmacSha384, 2),
            (MacAlgorithm::HmacSha512, 3),
        ];
        assert_eq!(mac.len(), MacAlgorithm::ALL.len());
        for (a, code) in mac {
            assert_eq!(a.code(), code, "{a}");
            assert_eq!(MacAlgorithm::from_code(code), Some(a));
        }
    }

    #[test]
    fn capabilities() {
        let c = Capabilities::AEAD | Capabilities::REWRAP;
        assert!(c.contains(Capabilities::AEAD));
        assert!(!c.contains(Capabilities::MAC));
        assert_eq!(format!("{c:?}"), "Capabilities(AEAD | REWRAP)");
        assert_eq!(
            format!("{:?}", Capabilities::AEAD | Capabilities::KEY_WRAP),
            "Capabilities(AEAD | KEY_WRAP)"
        );
    }

    #[test]
    fn ciphertext_base64() {
        let ct = Ciphertext::from_bytes(vec![0xfb, 0xff, 0x00]);
        assert_eq!(ct.to_base64(), "+/8A");
        assert_eq!(ct.to_base64_url(), "-_8A");
        assert_eq!(Ciphertext::from_base64("+/8A").unwrap(), ct);
        assert_eq!(Ciphertext::from_base64_url("-_8A").unwrap(), ct);
        let one = Ciphertext::from_bytes(vec![1]);
        assert_eq!(one.to_base64(), "AQ==");
        assert_eq!(one.to_base64_url(), "AQ");
        // Corrupt encodings fail like corrupt ciphertext: one caller-error kind for both.
        for bad in ["AQ", "-_8A", "!!!!"] {
            let e = Ciphertext::from_base64(bad).unwrap_err();
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::DecryptFailed, Operation::Decrypt),
                "{bad}"
            );
            assert!(e.is_caller_error());
        }
        let e = Ciphertext::from_base64_url("AQ==").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DecryptFailed);
    }

    #[test]
    fn signature_and_tag_base64() {
        let sig = Signature::from_parts(
            SignatureAlgorithm::EcdsaP256Sha256,
            Some(KeyVersion::from(2)),
            vec![0xfb, 0xff],
        );
        let b64 = sig.to_base64().unwrap();
        assert_eq!(b64, "QUtTAQEBMvv/");
        assert_eq!(Signature::from_base64(&b64).unwrap(), sig);
        let url = sig.to_base64_url().unwrap();
        assert_eq!(url, "QUtTAQEBMvv_");
        assert_eq!(Signature::from_base64_url(&url).unwrap(), sig);
        let tag = Tag::from_parts(MacAlgorithm::HmacSha256, None, vec![7; 32]);
        assert_eq!(Tag::from_base64(&tag.to_base64().unwrap()).unwrap(), tag);
        assert_eq!(
            Tag::from_base64_url(&tag.to_base64_url().unwrap()).unwrap(),
            tag
        );
        // A tag does not decode as a signature, and corrupt values fail like forged ones.
        for e in [
            Signature::from_base64(&tag.to_base64().unwrap()).unwrap_err(),
            Signature::from_base64("!!!!").unwrap_err(),
            Signature::from_base64_url(&b64).unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.operation()),
                (ErrorKind::VerificationFailed, Operation::Verify)
            );
        }
        let e = Tag::from_base64("AQ").unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::VerificationFailed, Operation::VerifyMac)
        );
        assert!(e.is_caller_error());
    }

    #[test]
    fn decrypted_debug_redacts() {
        let d = Decrypted::new(Zeroizing::new(b"AAAA".to_vec()))
            .with_version(Some(KeyVersion::from(2)))
            .with_used_primary(Some(false));
        let s = format!("{d:?}");
        assert!(s.contains("redacted") && !s.contains("AAAA") && !s.contains("65"));
        assert_eq!(d.key_version(), Some(&KeyVersion::from(2)));
        assert_eq!(d.used_primary(), Some(false));
        assert_eq!(&*d.into_plaintext(), b"AAAA");
    }
}
