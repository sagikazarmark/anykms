//! An Azure-Key-Vault-(standard)-shaped provider and fixture over local keys.
//!
//! - No AEAD and no MAC keys. Key-wrapping keys (`azure-shaped://<name>`) are local AES keys
//!   exposed only through `Provider::key_wrap`, with a native-style framing: the wrapped key is
//!   the 32-character version followed by the local ciphertext. Data keys come from the
//!   `KeyWrapDataKeys` recipe over them (`Provider::data_keys`), which refuses AAD.
//! - ECDSA signing keys only; `describe` reports the primary (current) version, as Azure does.
//! - Versions are opaque 32-hex strings, unique across keys; an unversioned signature is
//!   `InvalidArgument` before any request, as on Azure.
//! - Keys are disabled as a whole. Error messages are declared to come from an emulator.
//! - Handles declare the Azure vault row of the semantics table for unversioned URIs
//!   (architecture plan §3.2). Versioned URIs (and so `Provider::pin`) are not modelled.

use std::sync::Arc;

use anykms_conformance::{
    DigestKeyHandles, Feature, Fixture, FixtureCaps, KeyUse, KeyWrapKeyHandles, TestKey,
    TestKeyKind, TypedHandles,
};
use anykms_core::{
    Aead, Capabilities, Ciphertext, DataKeyAad, DataKeySource, DataKeysKey, Describe, DescribeKey,
    Digest, DigestSigner, DigestSignerKey, DigestVerifier, DigestVerifierKey, ErrorKind, KeyInfo,
    KeySemantics, KeyUri, KeyVersion, KeyVersionInfo, KeyWrap, KeyWrapKey, MessageSignerKey,
    MessageVerifierKey, OpenOptions, Operation, Provider, PublicKey, PublicKeys, PublicKeysKey,
    Result, Semantics, Signature, SignatureAlgorithm, SigningShape, VersionModel, Zeroizing,
};
use anykms_local::{LocalKeyKind, LocalKeyset, parse_local_ciphertext};
use anykms_recipes::KeyWrapDataKeys;
use sha2::{Digest as _, Sha256};

use super::{err, segments};

pub const BACKEND: &str = "azure-shaped";
pub const SCHEME: &str = "azure-shaped";
/// Length of an opaque version.
const VERSION_LEN: usize = 32;

/// The opaque version of local version `n` of key `name`.
fn opaque(name: &str, n: u64) -> String {
    let h = Sha256::digest(format!("{name}:{n}").as_bytes());
    h.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .chars()
        .take(VERSION_LEN)
        .collect()
}

fn is_opaque(v: &str) -> bool {
    v.len() == VERSION_LEN
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn uri(name: &str) -> KeyUri {
    format!("{SCHEME}://{name}").parse().expect("valid URI")
}

/// The Azure vault row for an unversioned URI: floating, opaque versions with a primary,
/// signatures verified by the backend and naming their version.
fn base_semantics() -> KeySemantics {
    KeySemantics::new(VersionModel::Floating, anykms_core::VersionShape::Opaque)
}

/// Key-wrapping keys: the wrapped key's frame names its version.
fn key_wrap_semantics() -> &'static KeySemantics {
    static S: std::sync::OnceLock<KeySemantics> = std::sync::OnceLock::new();
    S.get_or_init(|| base_semantics().with_ciphertext_reveals_version(true))
}

/// Signing keys.
fn sign_semantics() -> &'static KeySemantics {
    static S: std::sync::OnceLock<KeySemantics> = std::sync::OnceLock::new();
    S.get_or_init(base_semantics)
}

/// Data keys from `KeyWrapDataKeys` over a key-wrapping key: emulated, AAD refused.
fn data_keys_semantics() -> KeySemantics {
    key_wrap_semantics()
        .clone()
        .with_data_keys(Some(DataKeySource::emulated(DataKeyAad::Refused)))
}

/// A key: its name, and its URI for errors.
#[derive(Clone, Debug)]
struct Target {
    ks: LocalKeyset,
    name: String,
    resource: String,
}

impl Target {
    fn parse(ks: &LocalKeyset, uri: &KeyUri) -> Result<Self> {
        let s = segments(BACKEND, SCHEME, uri)?;
        let [name] = s.as_slice() else {
            return Err(err(
                BACKEND,
                ErrorKind::Configuration,
                Operation::ParseUri,
                &uri.to_string(),
                "malformed key URI",
            ));
        };
        Ok(Self {
            ks: ks.clone(),
            name: (*name).to_owned(),
            resource: uri.to_string(),
        })
    }

    fn err(&self, kind: ErrorKind, op: Operation, msg: &'static str) -> anykms_core::Error {
        err(BACKEND, kind, op, &self.resource, msg)
    }

    /// The number of local versions (`NotFound` for a missing key).
    async fn latest(&self) -> Result<u64> {
        let info = self.ks.aead_key(&self.name).describe().await?;
        Ok(info.versions().len() as u64)
    }

    /// The local version an opaque version (taken from input) names. A3(a): one this key does
    /// not have (another key's included) is `UnknownKeyVersion`; verification turns it into
    /// `VerificationFailed`.
    async fn local_version(&self, v: &KeyVersion, op: Operation) -> Result<u64> {
        if !is_opaque(v.as_str()) {
            return Err(self.err(ErrorKind::InvalidArgument, op, "malformed key version"));
        }
        let latest = self.latest().await?;
        (1..=latest)
            .find(|n| opaque(&self.name, *n) == v.as_str())
            .ok_or_else(|| self.err(ErrorKind::UnknownKeyVersion, op, "key version not found"))
    }

    fn version(&self, local: &KeyVersion) -> KeyVersion {
        KeyVersion::new(opaque(&self.name, local.as_u64().unwrap_or(0)))
    }

    /// The local describe with opaque versions; `primary` keeps the primary version.
    async fn describe(&self, caps: Option<Capabilities>, primary: bool) -> Result<KeyInfo> {
        let base = self.ks.aead_key(&self.name).describe().await?;
        let versions = base
            .versions()
            .iter()
            .map(|v| KeyVersionInfo::new(self.version(v.version()), v.state().clone()))
            .collect();
        Ok(
            KeyInfo::new(base.backend_key_type(), caps.unwrap_or(base.capabilities()))
                .with_signature_algorithms(base.signature_algorithms().to_vec())
                .with_state(base.state().cloned())
                .with_primary_version(if primary {
                    base.primary_version().map(|v| self.version(v))
                } else {
                    None
                })
                .with_versions(versions),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Key wrapping

#[derive(Clone)]
pub struct AzKeyWrap(Target);

impl KeyWrap for AzKeyWrap {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        let ct = self.0.ks.aead_key(&self.0.name).encrypt(key, b"").await?;
        let (n, _, _) = parse_local_ciphertext(ct.as_bytes()).ok_or_else(|| {
            self.0.err(
                ErrorKind::Backend,
                Operation::Encrypt,
                "unexpected local ciphertext",
            )
        })?;
        let mut out = opaque(&self.0.name, n).into_bytes();
        out.extend_from_slice(ct.as_bytes());
        Ok(Ciphertext::from_bytes(out))
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        let op = Operation::Decrypt;
        if !self.0.ks.contains(&self.0.name) {
            return Err(self.0.err(ErrorKind::NotFound, op, "key not found"));
        }
        let failed = || self.0.err(ErrorKind::DecryptFailed, op, "unwrap failed");
        let b = wrapped.as_bytes();
        let (version, ct) = b.split_at_checked(VERSION_LEN).ok_or_else(failed)?;
        let version = std::str::from_utf8(version).map_err(|_| failed())?;
        if !is_opaque(version) {
            return Err(failed());
        }
        let latest = self.0.latest().await?;
        // Another key's wrapped key does not decrypt: its version is unknown here.
        let n = (1..=latest)
            .find(|n| opaque(&self.0.name, *n) == version)
            .ok_or_else(failed)?;
        if parse_local_ciphertext(ct).map(|(v, _, _)| v) != Some(n) {
            return Err(failed());
        }
        self.0
            .ks
            .aead_key(&self.0.name)
            .decrypt(&Ciphertext::from_bytes(ct.to_vec()), b"")
            .await
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        match wrapped
            .as_bytes()
            .get(..VERSION_LEN)
            .and_then(|v| std::str::from_utf8(v).ok())
        {
            Some(v) if is_opaque(v) => Ok(Some(KeyVersion::new(v))),
            _ => Err(self.0.err(
                ErrorKind::InvalidArgument,
                Operation::Decrypt,
                "not a wrapped key",
            )),
        }
    }
}

impl Semantics for AzKeyWrap {
    fn semantics(&self) -> Option<&KeySemantics> {
        Some(key_wrap_semantics())
    }
}

impl Describe for AzKeyWrap {
    async fn describe(&self) -> Result<KeyInfo> {
        let caps = match self.0.ks.kind(&self.0.name) {
            Some(LocalKeyKind::Aes256Gcm) => Some(Capabilities::KEY_WRAP),
            _ => None,
        };
        self.0.describe(caps, true).await
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

#[derive(Clone)]
pub struct AzSign {
    t: Target,
    alg: SignatureAlgorithm,
}

impl AzSign {
    fn local(&self) -> anykms_local::LocalDigestKey {
        self.t.ks.digest_signing_key(&self.t.name, self.alg)
    }

    fn relabel_pk(&self, pk: PublicKey) -> PublicKey {
        let v = pk.key_version().map(|v| self.t.version(v));
        PublicKey::new(pk.key_type(), pk.spki_der().to_vec(), v)
    }
}

impl DigestSigner for AzSign {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let sig = self.local().sign_digest(digest).await?;
        let v = sig.key_version().map(|v| self.t.version(v));
        Ok(Signature::from_parts(sig.algorithm(), v, sig.into_bytes()))
    }
}

impl DigestVerifier for AzSign {
    /// An unversioned signature is `InvalidArgument` before any request.
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        let v = sig.key_version().ok_or_else(|| {
            self.t.err(
                ErrorKind::InvalidArgument,
                Operation::Verify,
                "signature has no key version",
            )
        })?;
        let n = self
            .t
            .local_version(v, Operation::Verify)
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::UnknownKeyVersion {
                    self.t.err(
                        ErrorKind::VerificationFailed,
                        Operation::Verify,
                        "signature verification failed",
                    )
                } else {
                    e
                }
            })?;
        let local = Signature::from_parts(
            sig.algorithm(),
            Some(KeyVersion::from_u64(n)),
            sig.as_bytes().to_vec(),
        );
        self.local().verify_digest(digest, &local).await
    }
}

impl PublicKeys for AzSign {
    async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.relabel_pk(self.local().public_key().await?))
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        let n = self.t.local_version(version, Operation::PublicKey).await?;
        Ok(self.relabel_pk(
            self.local()
                .public_key_version(&KeyVersion::from_u64(n))
                .await?,
        ))
    }
}

impl Describe for AzSign {
    async fn describe(&self) -> Result<KeyInfo> {
        self.t.describe(None, true).await
    }
}

impl Semantics for AzSign {
    fn semantics(&self) -> Option<&KeySemantics> {
        Some(sign_semantics())
    }
}

/// Describes any key.
#[derive(Clone)]
struct AzDescribe(Target);

impl Describe for AzDescribe {
    async fn describe(&self) -> Result<KeyInfo> {
        match self.0.ks.kind(&self.0.name) {
            Some(LocalKeyKind::Aes256Gcm) | None => AzKeyWrap(self.0.clone()).describe().await,
            Some(_) => self.0.describe(None, true).await,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Provider and typed handles

pub struct AzProvider(pub LocalKeyset);

impl AzProvider {
    fn key_wrap_key(&self, uri: &KeyUri) -> Result<AzKeyWrap> {
        Ok(AzKeyWrap(Target::parse(&self.0, uri)?))
    }

    fn sign_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<AzSign> {
        alg.require_shape(SigningShape::Digest, BACKEND)?;
        Ok(AzSign {
            t: Target::parse(&self.0, uri)?,
            alg,
        })
    }

    fn data_keys_key(&self, uri: &KeyUri, backend: &'static str) -> Result<DataKeysKey> {
        let kw = self.key_wrap_key(uri)?;
        Ok(
            DataKeysKey::new(backend, Arc::new(KeyWrapDataKeys::new(kw.clone())))
                .with_describe(Arc::new(kw))
                .with_semantics(data_keys_semantics()),
        )
    }
}

/// A digest algorithm is `KeyMismatch`; Ed25519 is `Unsupported` (no such keys here).
fn no_message_signing(alg: SignatureAlgorithm) -> anykms_core::Error {
    match alg.require_shape(SigningShape::Message, BACKEND) {
        Err(e) => e,
        Ok(()) => anykms_core::Error::new(
            ErrorKind::Unsupported,
            BACKEND,
            Operation::Open,
            "no Ed25519 keys in this shape",
        ),
    }
}

impl Provider for AzProvider {
    fn schemes(&self) -> &[&'static str] {
        &[SCHEME]
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    fn key_wrap(&self, uri: &KeyUri, _: &OpenOptions) -> Result<KeyWrapKey> {
        let k = Arc::new(self.key_wrap_key(uri)?);
        Ok(KeyWrapKey::new(BACKEND, k.clone())
            .with_describe(k.clone())
            .with_semantics(key_wrap_semantics().clone())
            .with_concrete(k))
    }

    /// Data keys wrapped by a key-wrapping key (no AAD).
    fn data_keys(&self, uri: &KeyUri, _: &OpenOptions) -> Result<DataKeysKey> {
        self.data_keys_key(uri, BACKEND)
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        Ok(DigestSignerKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(sign_semantics().clone()))
    }

    fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<DigestVerifierKey> {
        Ok(DigestVerifierKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(sign_semantics().clone()))
    }

    fn message_signer(
        &self,
        _: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<MessageSignerKey> {
        Err(no_message_signing(alg))
    }

    fn message_verifier(
        &self,
        _: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<MessageVerifierKey> {
        Err(no_message_signing(alg))
    }

    fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<PublicKeysKey> {
        Ok(PublicKeysKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(sign_semantics().clone()))
    }

    fn describe(&self, uri: &KeyUri, _: &OpenOptions) -> Result<DescribeKey> {
        Ok(DescribeKey::full(
            BACKEND,
            AzDescribe(Target::parse(&self.0, uri)?),
        ))
    }
}

/// The typed path: the shaped handles bridged with exactly their parts.
struct AzTyped(AzProvider);

impl TypedHandles for AzTyped {
    fn key_wrap(&self, uri: &KeyUri) -> Result<KeyWrapKeyHandles> {
        Ok(
            KeyWrapKeyHandles::bridge(Arc::new(self.0.key_wrap_key(uri)?))
                .with_semantics(key_wrap_semantics().clone()),
        )
    }

    fn data_keys(&self, uri: &KeyUri) -> Result<DataKeysKey> {
        self.0.data_keys_key(uri, "typed")
    }

    fn digest_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<DigestKeyHandles> {
        Ok(
            DigestKeyHandles::bridge(Arc::new(self.0.sign_key(uri, alg)?))
                .with_semantics(sign_semantics().clone()),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture

pub struct AzFixture {
    ks: LocalKeyset,
    run: anykms_conformance::RunId,
}

impl AzFixture {
    pub fn new() -> Self {
        Self {
            ks: LocalKeyset::builder().build(),
            run: anykms_conformance::RunId::new(),
        }
    }
}

fn signing_kind(alg: SignatureAlgorithm) -> Option<LocalKeyKind> {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => Some(LocalKeyKind::EcdsaP256),
        SignatureAlgorithm::EcdsaP384Sha384 => Some(LocalKeyKind::EcdsaP384),
        SignatureAlgorithm::EcdsaP521Sha512 => Some(LocalKeyKind::EcdsaP521),
        _ => None,
    }
}

fn fixture_err(msg: &'static str) -> anykms_core::Error {
    anykms_core::Error::new(ErrorKind::Unsupported, "fixture", Operation::Configure, msg)
}

impl Fixture for AzFixture {
    fn name(&self) -> &str {
        "azure-shaped"
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::*;
        let mut caps = FixtureCaps::new()
            .not_applicable(Feature::BackendInfo, "local keys carry no backend metadata")
            .not_applicable(Feature::KeyWrapPublicKeys, "no RSA key-wrapping keys")
            .supports_all(&[
                KeyWrap,
                DataKeys,
                Describe,
                RotateSigning,
                Disable,
                PreflightState,
            ])
            .not_applicable(
                Feature::UsedPrimary,
                "decrypt does not report whether the primary version was used",
            )
            .with_emulated_errors("azure-shaped proof fixture")
            .not_applicable_all(
                &[Aead, Rewrap, WrappedDataKeys, Rotate, Mac, RotateMac],
                "Azure standard vaults have no AEAD or HMAC keys",
            )
            .not_applicable(KeyWrapRewrap, "Azure has no server-side rewrap")
            // Azure keys rotate, but whether a rotated key-wrapping key keeps unwrapping its old
            // versions' keys is the Azure backend's to show; the proof fixture stays
            // conservative.
            .not_applicable(
                RotateKeyWrap,
                "key-wrapping key rotation is not modelled by the proof fixture",
            )
            .not_applicable(Extension, "no backend extension calls")
            .not_applicable(DisableVersion, "not modelled by the proof fixture")
            .not_applicable_all(
                &[
                    MinDecryptionVersion,
                    Throttle,
                    OversizePlaintext,
                    NativeCiphertext,
                    UnauthorizedProvider,
                    RequestCount,
                ],
                "not modelled by the proof fixture",
            )
            .not_applicable_all(
                &[
                    EmptyPlaintext,
                    EmptyMessage,
                    MacInputLimit,
                    MessageInputLimit,
                ],
                "no AEAD, MAC or message-signing keys",
            );
        for &alg in SignatureAlgorithm::ALL {
            caps = match signing_kind(alg) {
                Some(_) => caps.supports(Signing(alg)),
                None => caps.not_applicable(Signing(alg), "ECDSA keys only in this shape"),
            };
        }
        caps
    }

    async fn create_key(&self, kind: TestKeyKind, _: KeyUse) -> Result<TestKey> {
        let name = self.run.name("k");
        let local = match kind {
            TestKeyKind::KeyWrap => LocalKeyKind::Aes256Gcm,
            TestKeyKind::Signing(alg) => {
                signing_kind(alg).ok_or_else(|| fixture_err("ECDSA keys only"))?
            }
            _ => return Err(fixture_err("no such key kind in this shape")),
        };
        self.ks.insert(name.clone(), local);
        Ok(TestKey::new(uri(&name), name, kind))
    }

    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        self.ks.rotate(&key.name)?;
        Ok(key.clone())
    }

    async fn disable(&self, key: &TestKey) -> Result<()> {
        self.ks.disable(&key.name)
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        uri("does-not-exist")
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(AzProvider(self.ks.clone()))
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(AzTyped(AzProvider(self.ks.clone())))
    }
}
