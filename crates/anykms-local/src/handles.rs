//! Typed key handles over a [`LocalKeyset`].

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _};
use anykms_core::{
    Aead, AsymmetricKeyType, Capabilities, Ciphertext, DataKey, DataKeySpec, DataKeys, Describe,
    Digest, DigestSigner, DigestVerifier, Error, ErrorKind, KeyInfo, KeyVersion, KeyVersionInfo,
    Mac, MacAlgorithm, MessageSigner, MessageVerifier, Operation, PublicKey, PublicKeys, Result,
    Rewrap, Signature, SignatureAlgorithm, Tag, WrappedDataKeys,
};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use spki::EncodePublicKey;
use zeroize::Zeroizing;

use crate::keyset::{BACKEND, KeyEntry, LocalKeyKind, LocalKeyset, Material, random_bytes};

/// Maximum plaintext accepted by local `Aead::encrypt`, mirroring server request-size limits.
pub const MAX_PLAINTEXT: usize = 4 * 1024 * 1024;

const PREFIX: &[u8] = b"local:v";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn invalid(op: Operation, m: &'static str) -> Error {
    Error::new(ErrorKind::InvalidArgument, BACKEND, op, m)
}

fn decrypt_failed(op: Operation) -> Error {
    Error::new(ErrorKind::DecryptFailed, BACKEND, op, "decryption failed")
}

/// Labels an error with the key's `local://<keyset>/<name>` URI, as remote backends label theirs.
/// Errors from [`LocalKeyset::with_key`] are labeled already; this is for checks made before it.
fn label(ks: &LocalKeyset, name: &str, e: Error) -> Error {
    e.with_resource(ks.resource(name))
}

fn verification_failed(op: Operation) -> Error {
    Error::new(
        ErrorKind::VerificationFailed,
        BACKEND,
        op,
        "verification failed",
    )
}

/// Formats `local:v<N>:` + nonce + ciphertext + tag.
pub(crate) fn frame(version: u64, nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    let v = version.to_string();
    let mut out = Vec::with_capacity(PREFIX.len() + v.len() + 1 + nonce.len() + ct.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(v.as_bytes());
    out.push(b':');
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

/// Parses `local:v<N>:` framing. Returns `(version, nonce, ciphertext||tag)`.
pub fn parse_local_ciphertext(bytes: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let rest = bytes.strip_prefix(PREFIX)?;
    let colon = rest.iter().position(|&b| b == b':')?;
    let (digits, rest) = rest.split_at(colon);
    // u64::MAX has 20 digits; `parse` rejects overflow.
    if digits.is_empty() || digits.len() > 20 || (digits.len() > 1 && digits[0] == b'0') {
        return None;
    }
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let version: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    if version == 0 {
        return None;
    }
    let rest = &rest[1..];
    if rest.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    Some((version, nonce, ct))
}

fn aes_encrypt(key: &[u8; 32], version: u64, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = aes_gcm::Nonce::try_from(&nonce_bytes[..]).expect("12-byte nonce");
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::Backend,
                BACKEND,
                Operation::Encrypt,
                "encryption failed",
            )
        })?;
    Ok(Ciphertext::from_bytes(frame(
        version,
        &nonce_bytes[..],
        &ct,
    )))
}

fn aes_decrypt(
    entry: &KeyEntry,
    ct: &Ciphertext,
    aad: &[u8],
    op: Operation,
) -> Result<Zeroizing<Vec<u8>>> {
    let (version, nonce, body) =
        parse_local_ciphertext(ct.as_bytes()).ok_or_else(|| decrypt_failed(op))?;
    let Material::Aes(key) = entry.for_read(version, op)? else {
        return Err(decrypt_failed(op));
    };
    let cipher = Aes256Gcm::new_from_slice(&key[..]).expect("32-byte key");
    let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| decrypt_failed(op))?;
    cipher
        .decrypt(&nonce, Payload { msg: body, aad })
        .map(Zeroizing::new)
        .map_err(|_| decrypt_failed(op))
}

/// `KeyMismatch` naming both kinds (`LocalKeyKind::as_str`) unless the key is a `kind` key.
fn require_kind(entry: &KeyEntry, kind: LocalKeyKind, op: Operation) -> Result<()> {
    if entry.kind != kind {
        return Err(Error::new(
            ErrorKind::KeyMismatch,
            BACKEND,
            op,
            format!(
                "key type does not support this operation: the key is {}, the operation needs {}",
                entry.kind.as_str(),
                kind.as_str()
            ),
        ));
    }
    Ok(())
}

fn describe(ks: &LocalKeyset, name: &str) -> Result<KeyInfo> {
    ks.with_key(name, Operation::Describe, |k| {
        let caps = match k.kind {
            LocalKeyKind::Aes256Gcm => {
                Capabilities::AEAD
                    | Capabilities::REWRAP
                    | Capabilities::DATA_KEYS
                    | Capabilities::KEY_WRAP
            }
            LocalKeyKind::Hmac => Capabilities::MAC,
            _ => Capabilities::SIGN | Capabilities::VERIFY | Capabilities::PUBLIC_KEY,
        };
        let algs = match k.kind {
            LocalKeyKind::EcdsaP256 => vec![SignatureAlgorithm::EcdsaP256Sha256],
            LocalKeyKind::EcdsaP384 => vec![SignatureAlgorithm::EcdsaP384Sha384],
            LocalKeyKind::EcdsaP521 => vec![SignatureAlgorithm::EcdsaP521Sha512],
            LocalKeyKind::Ed25519 => vec![SignatureAlgorithm::Ed25519],
            _ => vec![],
        };
        // Like transit, versions below the minimum decryption version are not listed: they can
        // no longer be used, and their public keys are not served either.
        let versions = k
            .versions
            .iter()
            .enumerate()
            .map(|(i, (_, created))| (i as u64 + 1, created))
            .filter(|(v, _)| *v >= k.min_decryption_version)
            .map(|(v, created)| {
                KeyVersionInfo::new(KeyVersion::from_u64(v), k.state.clone())
                    .with_created_at(Some(*created))
            })
            .collect();
        Ok(KeyInfo::new(k.kind.as_str(), caps)
            .with_state(Some(k.state.clone()))
            .with_signature_algorithms(algs)
            .with_primary_version(Some(KeyVersion::from_u64(k.latest())))
            .with_versions(versions))
    })
}

fn numeric_version(v: Option<&KeyVersion>, op: Operation) -> Result<u64> {
    v.and_then(KeyVersion::as_u64)
        .ok_or_else(|| invalid(op, "signature or tag has no numeric key version"))
}

// ---------------------------------------------------------------------------------------------
// AEAD

/// An AES-256-GCM key: `Aead`, `Rewrap` (including with AAD), `DataKeys` and `WrappedDataKeys`
/// (with AAD), `Describe`.
#[derive(Clone, Debug)]
pub struct LocalAeadKey {
    pub(crate) ks: LocalKeyset,
    pub(crate) name: String,
}

impl Aead for LocalAeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        let op = Operation::Encrypt;
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(label(
                &self.ks,
                &self.name,
                invalid(op, "plaintext exceeds the maximum size"),
            ));
        }
        self.ks.with_key(&self.name, op, |k| {
            require_kind(k, LocalKeyKind::Aes256Gcm, op)?;
            let (v, m) = k.primary(op)?;
            let Material::Aes(key) = m else {
                unreachable!("kind checked")
            };
            aes_encrypt(key, v, plaintext, aad)
        })
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let op = Operation::Decrypt;
        self.ks.with_key(&self.name, op, |k| {
            require_kind(k, LocalKeyKind::Aes256Gcm, op)?;
            aes_decrypt(k, ct, aad, op)
        })
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        parse_local_ciphertext(ct.as_bytes())
            .map(|(v, _, _)| Some(KeyVersion::from_u64(v)))
            .ok_or_else(|| {
                label(
                    &self.ks,
                    &self.name,
                    invalid(Operation::Decrypt, "not a local ciphertext"),
                )
            })
    }
}

impl Rewrap for LocalAeadKey {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        let op = Operation::Rewrap;
        self.ks.with_key(&self.name, op, |k| {
            require_kind(k, LocalKeyKind::Aes256Gcm, op)?;
            let pt = aes_decrypt(k, ct, aad, op)?;
            let (v, m) = k.primary(op)?;
            let Material::Aes(key) = m else {
                unreachable!("kind checked")
            };
            aes_encrypt(key, v, &pt, aad).map_err(|e| e.with_operation(op))
        })
    }
}

impl LocalAeadKey {
    /// A fresh data key and its wrapped form under the primary version, bound to `aad`.
    fn data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<(Zeroizing<[u8; 32]>, Ciphertext)> {
        let op = Operation::GenerateDataKey;
        let DataKeySpec::Aes256 = spec else {
            return Err(label(
                &self.ks,
                &self.name,
                Error::new(ErrorKind::Unsupported, BACKEND, op, "data key spec"),
            ));
        };
        let dek = random_bytes::<32>();
        let ct = self.ks.with_key(&self.name, op, |k| {
            require_kind(k, LocalKeyKind::Aes256Gcm, op)?;
            let (v, m) = k.primary(op)?;
            let Material::Aes(key) = m else {
                unreachable!("kind checked")
            };
            aes_encrypt(key, v, &dek[..], aad)
        })?;
        Ok((dek, ct))
    }
}

impl DataKeys for LocalAeadKey {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        let (dek, ct) = self.data_key(spec, aad)?;
        DataKey::new(spec, Zeroizing::new(dek.to_vec()), ct)
    }
}

/// The data key is generated, wrapped and wiped; only the wrapped form is returned.
impl WrappedDataKeys for LocalAeadKey {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        self.data_key(spec, aad).map(|(_, ct)| ct)
    }
}

impl Describe for LocalAeadKey {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.ks, &self.name)
    }
}

// ---------------------------------------------------------------------------------------------
// ECDSA

/// An ECDSA key used with one asserted algorithm: `DigestSigner`, `DigestVerifier`, `PublicKeys`,
/// `Describe`.
#[derive(Clone, Debug)]
pub struct LocalDigestKey {
    pub(crate) ks: LocalKeyset,
    pub(crate) name: String,
    pub(crate) alg: SignatureAlgorithm,
}

fn kind_for(alg: SignatureAlgorithm) -> Option<LocalKeyKind> {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => Some(LocalKeyKind::EcdsaP256),
        SignatureAlgorithm::EcdsaP384Sha384 => Some(LocalKeyKind::EcdsaP384),
        SignatureAlgorithm::EcdsaP521Sha512 => Some(LocalKeyKind::EcdsaP521),
        SignatureAlgorithm::Ed25519 => Some(LocalKeyKind::Ed25519),
        _ => None,
    }
}

/// `KeyMismatch` naming the key's kind and the kind `alg` needs, unless they match.
fn check_alg_kind(entry: &KeyEntry, alg: SignatureAlgorithm, op: Operation) -> Result<()> {
    let needs = match kind_for(alg) {
        Some(kind) if kind == entry.kind => return Ok(()),
        Some(kind) => kind.as_str(),
        None => "a kind local keys do not have",
    };
    Err(Error::new(
        ErrorKind::KeyMismatch,
        BACKEND,
        op,
        format!(
            "key type does not match the asserted signature algorithm: the key is {}, {alg} needs \
             {needs}",
            entry.kind.as_str()
        ),
    ))
}

fn ecdsa_sign(m: &Material, prehash: &[u8]) -> Result<Vec<u8>> {
    let fail = |_| {
        Error::new(
            ErrorKind::Backend,
            BACKEND,
            Operation::Sign,
            "signing failed",
        )
    };
    Ok(match m {
        Material::P256(k) => PrehashSigner::<p256::ecdsa::Signature>::sign_prehash(&**k, prehash)
            .map_err(fail)?
            .to_der()
            .as_bytes()
            .to_vec(),
        Material::P384(k) => PrehashSigner::<p384::ecdsa::Signature>::sign_prehash(&**k, prehash)
            .map_err(fail)?
            .to_der()
            .as_bytes()
            .to_vec(),
        Material::P521(k) => PrehashSigner::<p521::ecdsa::Signature>::sign_prehash(&**k, prehash)
            .map_err(fail)?
            .to_der()
            .as_bytes()
            .to_vec(),
        _ => {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                Operation::Sign,
                "key type does not support this operation",
            ));
        }
    })
}

fn ecdsa_verify(m: &Material, prehash: &[u8], der: &[u8]) -> Result<()> {
    let op = Operation::Verify;
    let ok = match m {
        Material::P256(k) => p256::ecdsa::Signature::from_der(der)
            .ok()
            .map(|s| k.verifying_key().verify_prehash(prehash, &s).is_ok()),
        Material::P384(k) => p384::ecdsa::Signature::from_der(der)
            .ok()
            .map(|s| k.verifying_key().verify_prehash(prehash, &s).is_ok()),
        Material::P521(k) => p521::ecdsa::Signature::from_der(der)
            .ok()
            .map(|s| k.verifying_key().verify_prehash(prehash, &s).is_ok()),
        _ => {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                op,
                "key type does not support this operation",
            ));
        }
    };
    if ok == Some(true) {
        Ok(())
    } else {
        Err(verification_failed(op))
    }
}

fn spki(m: &Material) -> (AsymmetricKeyType, Vec<u8>) {
    let der = match m {
        Material::P256(k) => k.verifying_key().to_public_key_der(),
        Material::P384(k) => k.verifying_key().to_public_key_der(),
        Material::P521(k) => k.verifying_key().to_public_key_der(),
        Material::Ed25519(k) => k.verifying_key().to_public_key_der(),
        _ => unreachable!("kind checked"),
    }
    .expect("public key encodes");
    let t = match m {
        Material::P256(_) => AsymmetricKeyType::EcP256,
        Material::P384(_) => AsymmetricKeyType::EcP384,
        Material::P521(_) => AsymmetricKeyType::EcP521,
        _ => AsymmetricKeyType::Ed25519,
    };
    (t, der.as_bytes().to_vec())
}

fn public_key(
    ks: &LocalKeyset,
    name: &str,
    alg: SignatureAlgorithm,
    version: Option<&KeyVersion>,
) -> Result<PublicKey> {
    let op = Operation::PublicKey;
    ks.with_key(name, op, |k| {
        check_alg_kind(k, alg, op)?;
        let (v, m) = match version {
            None => k.primary(op)?,
            Some(ver) => {
                let v = ver
                    .as_u64()
                    .ok_or_else(|| invalid(op, "key version is not numeric"))?;
                (v, k.for_public_key(v, op)?)
            }
        };
        let (t, der) = spki(m);
        Ok(PublicKey::new(t, der, Some(KeyVersion::from_u64(v))))
    })
}

/// The algorithm the handle was opened for.
impl anykms_core::PinnedVerifier for LocalDigestKey {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl DigestSigner for LocalDigestKey {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let op = Operation::Sign;
        if Some(digest.algorithm()) != self.alg.hash() {
            return Err(label(
                &self.ks,
                &self.name,
                invalid(
                    op,
                    "digest algorithm does not match the signature algorithm",
                ),
            ));
        }
        self.ks.with_key(&self.name, op, |k| {
            check_alg_kind(k, self.alg, op)?;
            let (v, m) = k.primary(op)?;
            let der = ecdsa_sign(m, digest.as_bytes())?;
            Ok(Signature::from_parts(
                self.alg,
                Some(KeyVersion::from_u64(v)),
                der,
            ))
        })
    }
}

impl DigestVerifier for LocalDigestKey {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        let op = Operation::Verify;
        let l = |e| label(&self.ks, &self.name, e);
        if sig.algorithm() != self.alg {
            return Err(l(invalid(
                op,
                "signature algorithm does not match the key handle",
            )));
        }
        if Some(digest.algorithm()) != self.alg.hash() {
            return Err(l(invalid(
                op,
                "digest algorithm does not match the signature algorithm",
            )));
        }
        let v = numeric_version(sig.key_version(), op).map_err(l)?;
        self.ks.with_key(&self.name, op, |k| {
            check_alg_kind(k, self.alg, op)?;
            let m = k.for_read(v, op)?;
            ecdsa_verify(m, digest.as_bytes(), sig.as_bytes())
        })
    }
}

impl PublicKeys for LocalDigestKey {
    async fn public_key(&self) -> Result<PublicKey> {
        public_key(&self.ks, &self.name, self.alg, None)
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        public_key(&self.ks, &self.name, self.alg, Some(version))
    }
}

impl Describe for LocalDigestKey {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.ks, &self.name)
    }
}

// ---------------------------------------------------------------------------------------------
// Ed25519

/// An Ed25519 key: `MessageSigner`, `MessageVerifier`, `PublicKeys`, `Describe`.
#[derive(Clone, Debug)]
pub struct LocalEd25519Key {
    pub(crate) ks: LocalKeyset,
    pub(crate) name: String,
}

/// The algorithm the handle was opened for.
impl anykms_core::PinnedVerifier for LocalEd25519Key {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

impl MessageSigner for LocalEd25519Key {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        let op = Operation::Sign;
        self.ks.with_key(&self.name, op, |k| {
            check_alg_kind(k, SignatureAlgorithm::Ed25519, op)?;
            let (v, m) = k.primary(op)?;
            let Material::Ed25519(sk) = m else {
                unreachable!("kind checked")
            };
            let sig = signature::Signer::<ed25519_dalek::Signature>::sign(&**sk, msg);
            Ok(Signature::from_parts(
                SignatureAlgorithm::Ed25519,
                Some(KeyVersion::from_u64(v)),
                sig.to_bytes().to_vec(),
            ))
        })
    }
}

impl MessageVerifier for LocalEd25519Key {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let op = Operation::Verify;
        let l = |e| label(&self.ks, &self.name, e);
        if sig.algorithm() != SignatureAlgorithm::Ed25519 {
            return Err(l(invalid(
                op,
                "signature algorithm does not match the key handle",
            )));
        }
        let v = numeric_version(sig.key_version(), op).map_err(l)?;
        self.ks.with_key(&self.name, op, |k| {
            check_alg_kind(k, SignatureAlgorithm::Ed25519, op)?;
            let Material::Ed25519(sk) = k.for_read(v, op)? else {
                unreachable!("kind checked")
            };
            let s = ed25519_dalek::Signature::from_slice(sig.as_bytes())
                .map_err(|_| verification_failed(op))?;
            sk.verifying_key()
                .verify_strict(msg, &s)
                .map_err(|_| verification_failed(op))
        })
    }
}

impl PublicKeys for LocalEd25519Key {
    async fn public_key(&self) -> Result<PublicKey> {
        public_key(&self.ks, &self.name, SignatureAlgorithm::Ed25519, None)
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        public_key(
            &self.ks,
            &self.name,
            SignatureAlgorithm::Ed25519,
            Some(version),
        )
    }
}

impl Describe for LocalEd25519Key {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.ks, &self.name)
    }
}

// ---------------------------------------------------------------------------------------------
// HMAC

/// An HMAC key used with one asserted algorithm: `Mac`, `Describe`.
#[derive(Clone, Debug)]
pub struct LocalMacKey {
    pub(crate) ks: LocalKeyset,
    pub(crate) name: String,
    pub(crate) alg: MacAlgorithm,
}

/// Whether local HMAC keys implement `alg`. `MacAlgorithm` is `#[non_exhaustive]`, so variants
/// added later are refused with `Unsupported` (at open through [`LocalProvider`], at use through
/// the infallible typed accessor) instead of reaching a panic.
///
/// [`LocalProvider`]: crate::LocalProvider
pub(crate) fn mac_algorithm_supported(alg: MacAlgorithm) -> bool {
    matches!(
        alg,
        MacAlgorithm::HmacSha256 | MacAlgorithm::HmacSha384 | MacAlgorithm::HmacSha512
    )
}

pub(crate) fn unsupported_mac(op: Operation) -> Error {
    Error::new(
        ErrorKind::Unsupported,
        BACKEND,
        op,
        "MAC algorithm not supported by local keys",
    )
}

fn hmac_compute(key: &[u8], alg: MacAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use hmac::{KeyInit, Mac as _};
    macro_rules! go {
        ($h:ty) => {{
            let mut m = <hmac::Hmac<$h> as KeyInit>::new_from_slice(key).expect("any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }};
    }
    Ok(match alg {
        MacAlgorithm::HmacSha256 => go!(sha2::Sha256),
        MacAlgorithm::HmacSha384 => go!(sha2::Sha384),
        MacAlgorithm::HmacSha512 => go!(sha2::Sha512),
        _ => return Err(unsupported_mac(Operation::Mac)),
    })
}

fn hmac_verify(key: &[u8], alg: MacAlgorithm, data: &[u8], tag: &[u8]) -> Result<bool> {
    use hmac::{KeyInit, Mac as _};
    macro_rules! go {
        ($h:ty) => {{
            let mut m = <hmac::Hmac<$h> as KeyInit>::new_from_slice(key).expect("any key length");
            m.update(data);
            // Constant time, full length (never truncated).
            m.verify_slice(tag).is_ok()
        }};
    }
    Ok(match alg {
        MacAlgorithm::HmacSha256 => go!(sha2::Sha256),
        MacAlgorithm::HmacSha384 => go!(sha2::Sha384),
        MacAlgorithm::HmacSha512 => go!(sha2::Sha512),
        _ => return Err(unsupported_mac(Operation::VerifyMac)),
    })
}

impl Mac for LocalMacKey {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        let op = Operation::Mac;
        if !mac_algorithm_supported(self.alg) {
            return Err(label(&self.ks, &self.name, unsupported_mac(op)));
        }
        self.ks.with_key(&self.name, op, |k| {
            require_kind(k, LocalKeyKind::Hmac, op)?;
            let (v, m) = k.primary(op)?;
            let Material::Hmac(key) = m else {
                unreachable!("kind checked")
            };
            Ok(Tag::from_parts(
                self.alg,
                Some(KeyVersion::from_u64(v)),
                hmac_compute(&key[..], self.alg, data)?,
            ))
        })
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        let op = Operation::VerifyMac;
        let l = |e| label(&self.ks, &self.name, e);
        if !mac_algorithm_supported(self.alg) {
            return Err(l(unsupported_mac(op)));
        }
        if tag.algorithm() != self.alg {
            return Err(l(invalid(
                op,
                "tag algorithm does not match the key handle",
            )));
        }
        let v = numeric_version(tag.key_version(), op).map_err(l)?;
        self.ks.with_key(&self.name, op, |k| {
            require_kind(k, LocalKeyKind::Hmac, op)?;
            let Material::Hmac(key) = k.for_read(v, op)? else {
                unreachable!("kind checked")
            };
            if hmac_verify(&key[..], self.alg, data, tag.as_bytes())? {
                Ok(())
            } else {
                Err(verification_failed(op))
            }
        })
    }
}

impl Describe for LocalMacKey {
    async fn describe(&self) -> Result<KeyInfo> {
        Ok(describe(&self.ks, &self.name)?.with_mac_algorithm(Some(self.alg)))
    }
}

// ---------------------------------------------------------------------------------------------
// Semantics

/// The [`KeySemantics`](anykms_core::KeySemantics) of local handles, by key family (architecture
/// plan §3.2, local column): floating, numeric versions with a key-level state, backend (here:
/// in-process) verification of versioned signatures and tags.
fn semantics_of(family: Family) -> &'static anykms_core::KeySemantics {
    use anykms_core::{
        DataKeyAad, DataKeySource, KeySemantics, UnversionedVerify, VersionModel, VersionShape,
    };
    use std::sync::OnceLock;
    static AEAD: OnceLock<KeySemantics> = OnceLock::new();
    static OTHER: OnceLock<KeySemantics> = OnceLock::new();
    let base = || {
        KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
            .with_unversioned_verify(UnversionedVerify::Rejected)
    };
    match family {
        Family::Aead => AEAD.get_or_init(|| {
            base()
                .with_ciphertext_reveals_version(true)
                .with_data_keys(Some(DataKeySource::native(DataKeyAad::Bound)))
                .with_max_plaintext(Some(MAX_PLAINTEXT))
        }),
        Family::Other => OTHER.get_or_init(base),
    }
}

/// The key families whose handles differ in [`semantics_of`].
#[derive(Clone, Copy)]
enum Family {
    /// AEAD keys (also as data-key sources and KEKs).
    Aead,
    /// Signing and HMAC keys.
    Other,
}

/// Implements the inherent `semantics()` and [`Semantics`](anykms_core::Semantics) of a typed
/// handle.
macro_rules! semantics {
    ($($Handle:ident => $family:ident),* $(,)?) => {$(
        impl $Handle {
            /// What this handle does where backends differ; see
            /// [`KeySemantics`](anykms_core::KeySemantics).
            pub fn semantics(&self) -> &anykms_core::KeySemantics {
                semantics_of(Family::$family)
            }
        }

        impl anykms_core::Semantics for $Handle {
            fn semantics(&self) -> Option<&anykms_core::KeySemantics> {
                Some(semantics_of(Family::$family))
            }
        }
    )*};
}

semantics! {
    LocalAeadKey => Aead,
    LocalDigestKey => Other,
    LocalEd25519Key => Other,
    LocalMacKey => Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn public_keys_follow_min_decryption_version_and_state() {
        let ks = LocalKeyset::builder().ecdsa_p256("sig").build();
        ks.rotate("sig").unwrap();
        let k = ks.digest_signing_key("sig", SignatureAlgorithm::EcdsaP256Sha256);
        let v1 = KeyVersion::from_u64(1);
        assert!(k.public_key_version(&v1).await.is_ok());
        ks.set_min_decryption_version("sig", 2).unwrap();
        assert_eq!(
            k.public_key_version(&v1).await.unwrap_err().kind(),
            ErrorKind::UnknownKeyVersion
        );
        let info = k.describe().await.unwrap();
        let listed: Vec<_> = info
            .versions()
            .iter()
            .map(|v| v.version().clone())
            .collect();
        assert_eq!(listed, vec![KeyVersion::from_u64(2)]);
        ks.disable("sig").unwrap();
        let v2 = KeyVersion::from_u64(2);
        assert_eq!(
            k.public_key_version(&v2).await.unwrap_err().kind(),
            ErrorKind::KeyStateInvalid
        );
        assert_eq!(
            k.public_key().await.unwrap_err().kind(),
            ErrorKind::KeyStateInvalid
        );
    }

    #[test]
    fn framing_roundtrip_and_rejects() {
        let f = frame(12, &[1; 12], &[2; 20]);
        let (v, n, c) = parse_local_ciphertext(&f).unwrap();
        assert_eq!((v, n, c.len()), (12, &[1u8; 12][..], 20));
        let f = frame(u64::MAX, &[1; 12], &[2; 16]);
        assert_eq!(parse_local_ciphertext(&f).unwrap().0, u64::MAX);
        assert!(
            parse_local_ciphertext(b"local:v18446744073709551616:aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_none()
        );
        for bad in [
            &b"local:v0:"[..],
            b"local:v01:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"local:v:x",
            b"local:vx:",
            b"vault:v1:",
            b"local:v1:short",
        ] {
            assert!(parse_local_ciphertext(bad).is_none(), "{bad:?}");
        }
    }
}
