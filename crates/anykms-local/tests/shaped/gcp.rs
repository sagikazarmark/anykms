//! A GCP-Cloud-KMS-shaped provider and fixture over local keys.
//!
//! - AEAD keys (`gcp-shaped://<name>`): encrypt/decrypt and describe only (no rewrap, no data
//!   keys); ciphertexts do not reveal their version; `decrypt_with_info` reports `used_primary`;
//!   plaintext limited to 64 KiB and never empty; the primary version moves on rotation.
//! - Signing and HMAC keys are addressed per version (`gcp-shaped://<name>/v/<n>`): rotation adds
//!   a version with a new URI, and the old URI keeps using its version. Each version is a separate
//!   local key `<name>-v<n>`. Describe reports no primary version.
//! - An HMAC key is bound to one algorithm, chosen at creation (`TestKeyKind::Hmac(alg)`): a MAC
//!   handle for another algorithm fails with `KeyMismatch`, and describe reports the key's.
//! - State is per version only (`describe().state() == None`); versions are disabled one by one,
//!   which takes effect after a short propagation delay.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anykms_conformance::{
    AeadKeyHandles, DigestKeyHandles, Feature, Fixture, FixtureCaps, KeyUse, MacKeyHandles,
    MessageKeyHandles, TestKey, TestKeyKind, TypedHandles,
};
use anykms_core::{
    Aead, AeadKey, Capabilities, Ciphertext, Decrypted, Describe, DescribeKey, Digest,
    DigestSigner, DigestSignerKey, DigestVerifier, DigestVerifierKey, ErrorKind, KeyInfo,
    KeySemantics, KeyState, KeyUri, KeyVersion, KeyVersionInfo, KeyWrapKey, Mac, MacAlgorithm,
    MacKey, MessageSigner, MessageSignerKey, MessageVerifier, MessageVerifierKey, OpenOptions,
    Operation, PinnedVerify, Provider, PublicKey, PublicKeys, PublicKeysKey, Result, Signature,
    SignatureAlgorithm, SigningShape, StateScope, Tag, UnversionedVerify, Verification,
    VersionModel, VersionShape, Zeroizing,
};
use anykms_local::{LocalKeyKind, LocalKeyset};

use super::{err, segments};

pub const BACKEND: &str = "gcp-shaped";
pub const SCHEME: &str = "gcp-shaped";
/// The largest plaintext, MAC input and signed message.
pub const MAX_INPUT: usize = 64 * 1024;
/// How long disabling a version takes to reach the data plane.
const PROPAGATION: Duration = Duration::from_millis(100);

/// Keys and their GCP-shaped state.
pub struct State {
    ks: LocalKeyset,
    /// The latest version of each version-addressed (signing, HMAC) key.
    latest: Mutex<HashMap<String, u64>>,
    /// Disabled versions, with the time the change takes effect.
    disabled: Mutex<HashMap<(String, u64), Instant>>,
    /// The algorithm each HMAC key is bound to.
    mac_algs: Mutex<HashMap<String, MacAlgorithm>>,
}

impl State {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ks: LocalKeyset::builder().build(),
            latest: Mutex::default(),
            disabled: Mutex::default(),
            mac_algs: Mutex::default(),
        })
    }

    fn latest(&self, name: &str) -> Option<u64> {
        self.latest.lock().unwrap().get(name).copied()
    }

    /// Adds a version to a version-addressed key (creating it) and returns its number.
    fn add_version(&self, name: &str, kind: LocalKeyKind) -> u64 {
        let mut latest = self.latest.lock().unwrap();
        let n = latest.get(name).copied().unwrap_or(0) + 1;
        self.ks.insert(local_name(name, n), kind);
        latest.insert(name.to_owned(), n);
        n
    }

    fn mac_alg(&self, name: &str) -> Option<MacAlgorithm> {
        self.mac_algs.lock().unwrap().get(name).copied()
    }

    fn disable(&self, name: &str, version: u64) {
        self.disabled
            .lock()
            .unwrap()
            .insert((name.to_owned(), version), Instant::now() + PROPAGATION);
    }

    fn is_disabled(&self, name: &str, version: u64) -> bool {
        self.disabled
            .lock()
            .unwrap()
            .get(&(name.to_owned(), version))
            .is_some_and(|t| Instant::now() >= *t)
    }

    fn version_state(&self, name: &str, version: u64) -> KeyState {
        if self.is_disabled(name, version) {
            KeyState::Disabled
        } else {
            KeyState::Enabled
        }
    }
}

fn local_name(name: &str, version: u64) -> String {
    format!("{name}-v{version}")
}

pub fn uri(name: &str) -> KeyUri {
    format!("{SCHEME}://{name}").parse().expect("valid URI")
}

pub fn versioned_uri(name: &str, version: u64) -> KeyUri {
    format!("{SCHEME}://{name}/v/{version}")
        .parse()
        .expect("valid URI")
}

/// A key a URI names: `<name>` or `<name>/v/<n>`.
#[derive(Clone, Debug)]
struct Target {
    name: String,
    version: Option<u64>,
    resource: String,
}

impl Target {
    fn parse(uri: &KeyUri) -> Result<Self> {
        let s = segments(BACKEND, SCHEME, uri)?;
        let version = match s.as_slice() {
            [_] => None,
            [_, "v", n] => Some(n.parse::<u64>().map_err(|_| {
                err(
                    BACKEND,
                    ErrorKind::Configuration,
                    Operation::ParseUri,
                    &uri.to_string(),
                    "malformed key version in the URI",
                )
            })?),
            _ => {
                return Err(err(
                    BACKEND,
                    ErrorKind::Configuration,
                    Operation::ParseUri,
                    &uri.to_string(),
                    "malformed key URI",
                ));
            }
        };
        Ok(Self {
            name: s[0].to_owned(),
            version,
            resource: uri.to_string(),
        })
    }

    /// The local key of a key that is not version-addressed (AEAD keys, missing keys).
    fn plain(&self) -> String {
        match self.version {
            Some(v) => local_name(&self.name, v),
            None => self.name.clone(),
        }
    }

    fn err(&self, kind: ErrorKind, op: Operation, msg: &'static str) -> anykms_core::Error {
        err(BACKEND, kind, op, &self.resource, msg)
    }
}

/// The local key an operation uses: one version of a version-addressed key, or a plain local key
/// (whose own errors then apply).
enum Local {
    Version { local: String, version: u64 },
    Plain(String),
}

impl Local {
    fn name(&self) -> &str {
        match self {
            Local::Version { local, .. } | Local::Plain(local) => local,
        }
    }

    fn version(&self) -> Option<u64> {
        match self {
            Local::Version { version, .. } => Some(*version),
            Local::Plain(_) => None,
        }
    }
}

/// The version the handle chose (the URI's, or the latest): signing, MAC, `public_key()`. A3: a
/// disabled one is `KeyStateInvalid`, a missing one `NotFound`.
fn writing(st: &State, t: &Target, op: Operation) -> Result<Local> {
    let Some(latest) = st.latest(&t.name) else {
        return Ok(Local::Plain(t.plain()));
    };
    let version = t.version.unwrap_or(latest);
    version_of(st, t, version, op, false)
}

/// One version of a version-addressed key taken from input (a signature's or tag's version,
/// `public_key_version`). A3: a disabled one is `KeyVersionUnusable`, a missing one
/// `UnknownKeyVersion` (verification turns it into `VerificationFailed`).
fn reading(st: &State, t: &Target, version: u64, op: Operation) -> Result<Local> {
    version_of(st, t, version, op, true)
}

fn version_of(st: &State, t: &Target, version: u64, op: Operation, input: bool) -> Result<Local> {
    let Some(latest) = st.latest(&t.name) else {
        return Ok(Local::Plain(t.plain()));
    };
    if version == 0 || version > latest {
        let kind = if input {
            ErrorKind::UnknownKeyVersion
        } else {
            ErrorKind::NotFound
        };
        return Err(t.err(kind, op, "key version not found"));
    }
    if st.is_disabled(&t.name, version) {
        let kind = if input {
            ErrorKind::KeyVersionUnusable
        } else {
            ErrorKind::KeyStateInvalid
        };
        return Err(t.err(kind, op, "key version is disabled"));
    }
    Ok(Local::Version {
        local: local_name(&t.name, version),
        version,
    })
}

/// A3(a): verifying with a version this key does not have is `VerificationFailed`.
fn unknown_fails_verification(e: anykms_core::Error) -> anykms_core::Error {
    if e.kind() == ErrorKind::UnknownKeyVersion {
        err(
            BACKEND,
            ErrorKind::VerificationFailed,
            e.operation(),
            e.resource().unwrap_or_default(),
            "the key version does not exist",
        )
    } else {
        e
    }
}

/// The numeric version a signature or tag names.
fn named_version(t: &Target, v: Option<&KeyVersion>, op: Operation) -> Result<u64> {
    let v = v.ok_or_else(|| t.err(ErrorKind::InvalidArgument, op, "no key version"))?;
    v.as_u64()
        .ok_or_else(|| t.err(ErrorKind::InvalidArgument, op, "malformed key version"))
}

/// Describes a key: versions with their states, no key-level state, and no primary version for
/// version-addressed keys.
async fn describe(st: &State, t: &Target) -> Result<KeyInfo> {
    let Some(latest) = st.latest(&t.name) else {
        let base = st.ks.aead_key(&t.plain()).describe().await?;
        let caps = if base.capabilities().contains(Capabilities::AEAD) {
            // No rewrap, no data keys.
            Capabilities::AEAD | Capabilities::KEY_WRAP
        } else {
            base.capabilities()
        };
        let versions = base
            .versions()
            .iter()
            .map(|v| {
                let n = v.version().as_u64().unwrap_or(0);
                KeyVersionInfo::new(v.version().clone(), st.version_state(&t.plain(), n))
            })
            .collect();
        return Ok(KeyInfo::new(base.backend_key_type(), caps)
            .with_signature_algorithms(base.signature_algorithms().to_vec())
            .with_mac_algorithm(base.mac_algorithm())
            .with_state(None)
            .with_primary_version(base.primary_version().cloned())
            .with_versions(versions));
    };
    let base = st
        .ks
        .aead_key(&local_name(&t.name, latest))
        .describe()
        .await?;
    let versions = (1..=latest)
        .map(|n| KeyVersionInfo::new(KeyVersion::from_u64(n), st.version_state(&t.name, n)))
        .collect();
    Ok(KeyInfo::new(base.backend_key_type(), base.capabilities())
        .with_signature_algorithms(base.signature_algorithms().to_vec())
        .with_mac_algorithm(st.mac_alg(&t.name).or(base.mac_algorithm()))
        .with_state(None)
        .with_primary_version(None)
        .with_versions(versions))
}

// ---------------------------------------------------------------------------------------------
// AEAD

#[derive(Clone)]
pub struct GcpAead {
    st: Arc<State>,
    t: Target,
}

impl GcpAead {
    fn inner(&self) -> anykms_local::LocalAeadKey {
        self.st.ks.aead_key(&self.t.plain())
    }

    async fn primary(&self) -> Option<u64> {
        let info = self.inner().describe().await.ok()?;
        info.primary_version()?.as_u64()
    }
}

impl Aead for GcpAead {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        let op = Operation::Encrypt;
        if plaintext.is_empty() {
            return Err(self
                .t
                .err(ErrorKind::InvalidArgument, op, "empty plaintext"));
        }
        if plaintext.len() > MAX_INPUT {
            return Err(self
                .t
                .err(ErrorKind::InvalidArgument, op, "plaintext over 64 KiB"));
        }
        if let Some(p) = self.primary().await
            && self.st.is_disabled(&self.t.plain(), p)
        {
            return Err(self.t.err(
                ErrorKind::KeyStateInvalid,
                op,
                "the primary version is disabled",
            ));
        }
        self.inner().encrypt(plaintext, aad).await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if let Ok(Some(v)) = self.inner().ciphertext_version(ct)
            && v.as_u64()
                .is_some_and(|n| self.st.is_disabled(&self.t.plain(), n))
        {
            return Err(self.t.err(
                ErrorKind::KeyVersionUnusable,
                Operation::Decrypt,
                "the ciphertext's key version is disabled",
            ));
        }
        self.inner().decrypt(ct, aad).await
    }

    /// GCP ciphertexts do not reveal their version.
    fn ciphertext_version(&self, _: &Ciphertext) -> Result<Option<KeyVersion>> {
        Ok(None)
    }

    async fn decrypt_with_info(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted> {
        let pt = self.decrypt(ct, aad).await?;
        let version = self.inner().ciphertext_version(ct).ok().flatten();
        let primary = self.primary().await.map(KeyVersion::from_u64);
        Ok(Decrypted::new(pt).with_used_primary(Some(version.is_some() && version == primary)))
    }
}

impl Describe for GcpAead {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.st, &self.t).await
    }
}

// ---------------------------------------------------------------------------------------------
// MAC

#[derive(Clone)]
pub struct GcpMac {
    st: Arc<State>,
    t: Target,
    alg: MacAlgorithm,
}

impl GcpMac {
    /// The key is bound to one algorithm: a handle for another is `KeyMismatch`.
    fn check_alg(&self, op: Operation) -> Result<()> {
        match self.st.mac_alg(&self.t.name) {
            Some(bound) if bound != self.alg => Err(self.t.err(
                ErrorKind::KeyMismatch,
                op,
                "the HMAC key is bound to another algorithm",
            )),
            _ => Ok(()),
        }
    }
}

impl Mac for GcpMac {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.alg
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        let op = Operation::Mac;
        if data.len() > MAX_INPUT {
            return Err(self
                .t
                .err(ErrorKind::InvalidArgument, op, "MAC input over 64 KiB"));
        }
        self.check_alg(op)?;
        let local = writing(&self.st, &self.t, op)?;
        let tag = self.st.ks.mac_key(local.name(), self.alg).mac(data).await?;
        Ok(match local.version() {
            Some(v) => Tag::from_parts(
                self.alg,
                Some(KeyVersion::from_u64(v)),
                tag.as_bytes().to_vec(),
            ),
            None => tag,
        })
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        let op = Operation::VerifyMac;
        if tag.algorithm() != self.alg {
            return Err(self
                .t
                .err(ErrorKind::InvalidArgument, op, "tag of another algorithm"));
        }
        self.check_alg(op)?;
        let n = named_version(&self.t, tag.key_version(), op)?;
        let local = reading(&self.st, &self.t, n, op).map_err(unknown_fails_verification)?;
        let tag = match local {
            Local::Version { .. } => Tag::from_parts(
                self.alg,
                Some(KeyVersion::from_u64(1)),
                tag.as_bytes().to_vec(),
            ),
            Local::Plain(_) => tag.clone(),
        };
        self.st
            .ks
            .mac_key(local.name(), self.alg)
            .verify_mac(data, &tag)
            .await
    }
}

impl Describe for GcpMac {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.st, &self.t).await
    }
}

// ---------------------------------------------------------------------------------------------
// Signing

#[derive(Clone)]
pub struct GcpSign {
    st: Arc<State>,
    t: Target,
    alg: SignatureAlgorithm,
}

fn relabel(sig: Signature, version: Option<u64>) -> Signature {
    match version {
        Some(v) => Signature::from_parts(
            sig.algorithm(),
            Some(KeyVersion::from_u64(v)),
            sig.into_bytes(),
        ),
        None => sig,
    }
}

impl GcpSign {
    /// The local key verifying `sig`, and `sig` as that key labels it.
    fn verifying(&self, sig: &Signature) -> Result<(Local, Signature)> {
        let op = Operation::Verify;
        let n = named_version(&self.t, sig.key_version(), op)?;
        let local = reading(&self.st, &self.t, n, op).map_err(unknown_fails_verification)?;
        let sig = match local {
            Local::Version { .. } => Signature::from_parts(
                sig.algorithm(),
                Some(KeyVersion::from_u64(1)),
                sig.as_bytes().to_vec(),
            ),
            Local::Plain(_) => sig.clone(),
        };
        Ok((local, sig))
    }

    async fn public_key_of(&self, local: Local) -> Result<PublicKey> {
        let pk = if self.alg.is_message_signing() {
            self.st.ks.ed25519_key(local.name()).public_key().await?
        } else {
            self.st
                .ks
                .digest_signing_key(local.name(), self.alg)
                .public_key()
                .await?
        };
        Ok(match local.version() {
            Some(v) => PublicKey::new(
                pk.key_type(),
                pk.spki_der().to_vec(),
                Some(KeyVersion::from_u64(v)),
            ),
            None => pk,
        })
    }
}

impl DigestSigner for GcpSign {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        let local = writing(&self.st, &self.t, Operation::Sign)?;
        let sig = self
            .st
            .ks
            .digest_signing_key(local.name(), self.alg)
            .sign_digest(digest)
            .await?;
        Ok(relabel(sig, local.version()))
    }
}

impl DigestVerifier for GcpSign {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        let (local, sig) = self.verifying(sig)?;
        self.st
            .ks
            .digest_signing_key(local.name(), self.alg)
            .verify_digest(digest, &sig)
            .await
    }
}

impl MessageSigner for GcpSign {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        let op = Operation::Sign;
        if msg.len() > MAX_INPUT {
            return Err(self
                .t
                .err(ErrorKind::InvalidArgument, op, "message over 64 KiB"));
        }
        let local = writing(&self.st, &self.t, op)?;
        let sig = self
            .st
            .ks
            .ed25519_key(local.name())
            .sign_message(msg)
            .await?;
        Ok(relabel(sig, local.version()))
    }
}

impl MessageVerifier for GcpSign {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let (local, sig) = self.verifying(sig)?;
        self.st
            .ks
            .ed25519_key(local.name())
            .verify_message(msg, &sig)
            .await
    }
}

impl PublicKeys for GcpSign {
    async fn public_key(&self) -> Result<PublicKey> {
        let local = writing(&self.st, &self.t, Operation::PublicKey)?;
        self.public_key_of(local).await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        let op = Operation::PublicKey;
        let n = named_version(&self.t, Some(version), op)?;
        let local = reading(&self.st, &self.t, n, op)?;
        self.public_key_of(local).await
    }
}

impl Describe for GcpSign {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.st, &self.t).await
    }
}

/// Describes any key.
#[derive(Clone)]
struct GcpDescribe {
    st: Arc<State>,
    t: Target,
}

impl Describe for GcpDescribe {
    async fn describe(&self) -> Result<KeyInfo> {
        describe(&self.st, &self.t).await
    }
}

// ---------------------------------------------------------------------------------------------
// Provider and typed handles

pub struct GcpProvider(pub Arc<State>);

impl GcpProvider {
    fn aead_key(&self, uri: &KeyUri) -> Result<GcpAead> {
        Ok(GcpAead {
            st: self.0.clone(),
            t: Target::parse(uri)?,
        })
    }

    fn sign_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<GcpSign> {
        Ok(GcpSign {
            st: self.0.clone(),
            t: Target::parse(uri)?,
            alg,
        })
    }

    fn mac_key(&self, uri: &KeyUri, alg: MacAlgorithm) -> Result<GcpMac> {
        Ok(GcpMac {
            st: self.0.clone(),
            t: Target::parse(uri)?,
            alg,
        })
    }
}

/// The GCP row of the semantics table, as this proof fixture behaves (it verifies through the
/// local keyset, so verification is `Backend`).
fn semantics(kind: Kind) -> KeySemantics {
    let base = |m| {
        KeySemantics::new(m, VersionShape::Numeric)
            .with_state_scope(StateScope::VersionOnly)
            .with_versions_listed(true)
            .with_ciphertext_reveals_version(false)
            .with_unversioned_verify(UnversionedVerify::Rejected)
            .with_pinned_verify(PinnedVerify::AnyVersion)
            .with_verification(Verification::Backend)
    };
    let pinned = || base(VersionModel::Pinned).with_primary_reported(false);
    match kind {
        Kind::Aead => base(VersionModel::Floating)
            .with_primary_reported(true)
            .with_reports_used_primary(true)
            .with_max_plaintext(Some(MAX_INPUT)),
        Kind::Digest => pinned(),
        Kind::Message => pinned().with_max_signed_message(Some(MAX_INPUT)),
        Kind::Mac => pinned().with_max_mac_input(Some(MAX_INPUT)),
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Aead,
    Digest,
    Message,
    Mac,
}

fn semantics_kind(alg: SignatureAlgorithm) -> Kind {
    if alg.is_message_signing() {
        Kind::Message
    } else {
        Kind::Digest
    }
}

impl Provider for GcpProvider {
    fn schemes(&self) -> &[&'static str] {
        &[SCHEME]
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    fn aead(&self, uri: &KeyUri, _: &OpenOptions) -> Result<AeadKey> {
        let k = Arc::new(self.aead_key(uri)?);
        Ok(AeadKey::new(BACKEND, k.clone())
            .with_describe(k.clone())
            .with_concrete(k)
            .with_semantics(semantics(Kind::Aead)))
    }

    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        self.aead(uri, opts).map(KeyWrapKey::from_aead)
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        alg.require_shape(SigningShape::Digest, BACKEND)?;
        Ok(DigestSignerKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(semantics(Kind::Digest)))
    }

    fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<DigestVerifierKey> {
        alg.require_shape(SigningShape::Digest, BACKEND)?;
        Ok(DigestVerifierKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(semantics(Kind::Digest)))
    }

    fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<MessageSignerKey> {
        alg.require_shape(SigningShape::Message, BACKEND)?;
        Ok(MessageSignerKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(semantics(Kind::Message)))
    }

    fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<MessageVerifierKey> {
        alg.require_shape(SigningShape::Message, BACKEND)?;
        Ok(MessageVerifierKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(semantics(Kind::Message)))
    }

    fn mac(&self, uri: &KeyUri, alg: MacAlgorithm, _: &OpenOptions) -> Result<MacKey> {
        Ok(MacKey::full(BACKEND, self.mac_key(uri, alg)?).with_semantics(semantics(Kind::Mac)))
    }

    fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _: &OpenOptions,
    ) -> Result<PublicKeysKey> {
        Ok(PublicKeysKey::full(BACKEND, self.sign_key(uri, alg)?)
            .with_semantics(semantics(semantics_kind(alg))))
    }

    fn describe(&self, uri: &KeyUri, _: &OpenOptions) -> Result<DescribeKey> {
        Ok(DescribeKey::full(
            BACKEND,
            GcpDescribe {
                st: self.0.clone(),
                t: Target::parse(uri)?,
            },
        ))
    }
}

/// The typed path: the shaped handles bridged with exactly their parts.
struct GcpTyped(GcpProvider);

impl TypedHandles for GcpTyped {
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        Ok(AeadKeyHandles::bridge(Arc::new(self.0.aead_key(uri)?))
            .with_semantics(semantics(Kind::Aead)))
    }

    fn digest_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<DigestKeyHandles> {
        alg.require_shape(SigningShape::Digest, BACKEND)?;
        Ok(
            DigestKeyHandles::bridge(Arc::new(self.0.sign_key(uri, alg)?))
                .with_semantics(semantics(Kind::Digest)),
        )
    }

    fn message_key(&self, uri: &KeyUri) -> Result<MessageKeyHandles> {
        Ok(
            MessageKeyHandles::bridge(Arc::new(self.0.sign_key(uri, SignatureAlgorithm::Ed25519)?))
                .with_semantics(semantics(Kind::Message)),
        )
    }

    fn mac_key(&self, uri: &KeyUri, alg: MacAlgorithm) -> Result<MacKeyHandles> {
        Ok(MacKeyHandles::bridge(Arc::new(self.0.mac_key(uri, alg)?))
            .with_semantics(semantics(Kind::Mac)))
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture

pub struct GcpFixture {
    st: Arc<State>,
    run: anykms_conformance::RunId,
}

impl GcpFixture {
    pub fn new() -> Self {
        Self {
            st: State::new(),
            run: anykms_conformance::RunId::new(),
        }
    }
}

fn signing_kind(alg: SignatureAlgorithm) -> Option<LocalKeyKind> {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => Some(LocalKeyKind::EcdsaP256),
        SignatureAlgorithm::EcdsaP384Sha384 => Some(LocalKeyKind::EcdsaP384),
        SignatureAlgorithm::EcdsaP521Sha512 => Some(LocalKeyKind::EcdsaP521),
        SignatureAlgorithm::Ed25519 => Some(LocalKeyKind::Ed25519),
        _ => None,
    }
}

fn fixture_err(msg: &'static str) -> anykms_core::Error {
    anykms_core::Error::new(ErrorKind::Unsupported, "fixture", Operation::Configure, msg)
}

impl Fixture for GcpFixture {
    fn name(&self) -> &'static str {
        "gcp-shaped"
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::{
            Aead, DataKeys, Describe, DescribeVersionState, Disable, DisableVersion, EmptyMessage,
            EmptyPlaintext, Extension, KeyWrap, KeyWrapRewrap, Mac, MinDecryptionVersion,
            NativeCiphertext, PreflightState, RequestCount, Rewrap, Rotate, RotateKeyWrap,
            RotateMac, RotateSigning, ServerErrorMessages, Signing, Throttle, UnauthorizedProvider,
            WrappedDataKeys,
        };
        let mut caps = FixtureCaps::new()
            .not_applicable(Feature::BackendInfo, "local keys carry no backend metadata")
            .not_applicable(Feature::KeyWrapPublicKeys, "no RSA key-wrapping keys")
            .supports_all(&[
                Aead,
                Mac,
                Describe,
                Rotate,
                RotateMac,
                RotateSigning,
                DisableVersion,
                DescribeVersionState,
                EmptyMessage,
                ServerErrorMessages,
            ])
            .supports(Feature::UsedPrimary)
            .with_oversize_plaintext(MAX_INPUT + 1)
            .supports(Feature::MacInputLimit)
            .supports(Feature::MessageInputLimit)
            .with_settle_time(Duration::from_secs(2))
            .not_applicable_all(
                &[Rewrap, DataKeys, WrappedDataKeys],
                "GCP has no rewrap and no data keys",
            )
            .not_applicable_all(
                &[KeyWrap, KeyWrapRewrap, RotateKeyWrap],
                "no native key-wrapping keys in this shape",
            )
            .not_applicable(Extension, "no backend extension calls")
            .not_applicable_all(
                &[Disable, MinDecryptionVersion],
                "GCP disables versions, not keys, and has no minimum version",
            )
            .not_applicable(
                PreflightState,
                "like Cloud KMS, the shaped HMAC preflight reads the key type, not the state of \
                 the pinned version",
            )
            .not_applicable_all(
                &[
                    Throttle,
                    NativeCiphertext,
                    UnauthorizedProvider,
                    RequestCount,
                ],
                "not modelled by the proof fixture",
            )
            .not_applicable(EmptyPlaintext, "the shaped AEAD refuses empty plaintexts");
        for &alg in SignatureAlgorithm::ALL {
            caps = match signing_kind(alg) {
                Some(_) => caps.supports(Signing(alg)),
                None => caps.not_applicable(Signing(alg), "no RSA keys over the local backend"),
            };
        }
        caps
    }

    async fn create_key(&self, kind: TestKeyKind, _: KeyUse) -> Result<TestKey> {
        let name = self.run.name("k");
        let local = match kind {
            TestKeyKind::Aead => {
                self.st.ks.insert(name.clone(), LocalKeyKind::Aes256Gcm);
                return Ok(TestKey::new(uri(&name), name, kind));
            }
            TestKeyKind::Hmac(alg) => {
                self.st.mac_algs.lock().unwrap().insert(name.clone(), alg);
                LocalKeyKind::Hmac
            }
            TestKeyKind::Signing(alg) => {
                signing_kind(alg).ok_or_else(|| fixture_err("no RSA keys"))?
            }
            _ => return Err(fixture_err("no such key kind in this shape")),
        };
        let v = self.st.add_version(&name, local);
        Ok(TestKey::new(versioned_uri(&name, v), name, kind).with_version(KeyVersion::from_u64(v)))
    }

    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        if key.kind == TestKeyKind::Aead {
            self.st.ks.rotate(&key.name)?;
            return Ok(key.clone());
        }
        let latest = self
            .st
            .latest(&key.name)
            .ok_or_else(|| fixture_err("unknown key"))?;
        let local = self
            .st
            .ks
            .kind(&local_name(&key.name, latest))
            .ok_or_else(|| fixture_err("unknown key"))?;
        let v = self.st.add_version(&key.name, local);
        Ok(
            TestKey::new(versioned_uri(&key.name, v), key.name.clone(), key.kind)
                .with_version(KeyVersion::from_u64(v)),
        )
    }

    /// Takes effect after a propagation delay, like the real service: the suite waits.
    async fn disable_version(&self, key: &TestKey, version: &KeyVersion) -> Result<()> {
        let n = version
            .as_u64()
            .ok_or_else(|| fixture_err("non-numeric version"))?;
        // AEAD keys number their local versions; version-addressed keys their local keys.
        self.st.disable(&key.name, n);
        Ok(())
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        uri("does-not-exist")
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(GcpProvider(self.st.clone()))
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(GcpTyped(GcpProvider(self.st.clone())))
    }
}
