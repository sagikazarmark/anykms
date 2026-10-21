//! A minimal anykms backend that passes the conformance suite.
//!
//! The "service" is a toy in-memory KMS of AES-256-GCM keys with numbered versions. The backend
//! has the three pieces every backend has:
//!
//! - a **typed handle** (`ToyAeadKey`) implementing the capability traits its keys support
//!   (`Aead`, `Describe`) and declaring its `KeySemantics`;
//! - a **provider** (`ToyProvider`) that parses key URIs (`toykms://<name>`) without I/O and
//!   opens them as typed handles and, through the `Provider` trait, as opaque handles;
//! - a **fixture** (`MinimalFixture`) that creates and rotates keys for the suite and declares
//!   in `probe()` what the backend supports, and what it lacks by design: nothing is stubbed.
//!
//! A real backend replaces `ToyKms` with requests to its service and maps the service's errors
//! to the kinds the `Provider` and capability-trait docs list under "Errors"; the shape stays.
//!
//! Run it (it is also a test target, so `cargo test -p anykms-conformance` runs it too):
//!
//! ```sh
//! ANYKMS_FAIL_ON_SKIP=1 cargo run -p anykms-conformance --example minimal_backend
//! ```

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _};
use anykms_conformance::{
    AeadKeyHandles, Feature, Fixture, FixtureCaps, KeyUse, TestKey, TestKeyKind, TypedHandles,
};
use anykms_core::{
    Aead, AeadKey, Capabilities, Ciphertext, Describe, DescribeKey, Error, ErrorKind, IntoKeyUri,
    KeyInfo, KeySemantics, KeyState, KeyUri, KeyVersion, KeyVersionInfo, KeyWrapKey, OpenOptions,
    Operation, Provider, Result, Semantics, SignatureAlgorithm, VersionModel, VersionShape,
};
use zeroize::Zeroizing;

const BACKEND: &str = "toykms";
const NONCE_LEN: usize = 12;

/// The toy service: named keys, each a list of versions (version `n` at index `n - 1`; the last
/// one is the primary version).
#[derive(Clone, Default)]
struct ToyKms(Arc<Mutex<HashMap<String, Vec<Material>>>>);

/// One version's AES-256 key.
type Material = Zeroizing<[u8; 32]>;

impl ToyKms {
    /// Creates the key, or adds a version to it (rotation).
    fn add_version(&self, name: &str) {
        let mut material = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut material[..]).expect("operating system RNG");
        let mut keys = self.0.lock().expect("lock");
        keys.entry(name.to_owned()).or_default().push(material);
    }

    fn versions(&self, name: &str) -> Option<Vec<Material>> {
        self.0.lock().expect("lock").get(name).cloned()
    }
}

/// The typed handle of a toy AEAD key. Opening it did no I/O, so a missing key shows on the
/// first operation, as `NotFound`.
#[derive(Clone)]
struct ToyAeadKey {
    kms: ToyKms,
    name: String,
    uri: String,
    semantics: KeySemantics,
}

impl ToyAeadKey {
    /// An error naming the key (`Error::resource`), as every operation error must.
    fn err(&self, kind: ErrorKind, op: Operation, msg: &'static str) -> Error {
        Error::new(kind, BACKEND, op, msg).with_resource(self.uri.as_str())
    }

    fn versions(&self, op: Operation) -> Result<Vec<Material>> {
        self.kms
            .versions(&self.name)
            .ok_or_else(|| self.err(ErrorKind::NotFound, op, "key not found"))
    }
}

fn cipher(material: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(material).expect("32-byte key")
}

/// Splits a ciphertext into its version (4 bytes, big-endian, at least 1), nonce and body.
fn split(ct: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    let (v, rest) = ct.split_first_chunk::<4>()?;
    let v = u32::from_be_bytes(*v);
    (v >= 1 && rest.len() >= NONCE_LEN + 16).then(|| (v, &rest[..NONCE_LEN], &rest[NONCE_LEN..]))
}

impl Aead for ToyAeadKey {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        let versions = self.versions(Operation::Encrypt)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("operating system RNG");
        let primary = versions.last().expect("a key has a version");
        let body = cipher(primary)
            .encrypt(
                &aes_gcm::Nonce::try_from(&nonce[..]).expect("12-byte nonce"),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| self.err(ErrorKind::Backend, Operation::Encrypt, "encryption failed"))?;
        let version = u32::try_from(versions.len()).map_err(|_| {
            self.err(
                ErrorKind::Backend,
                Operation::Encrypt,
                "too many key versions",
            )
        })?;
        let mut out = version.to_be_bytes().to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(Ciphertext::from_bytes(out))
    }

    /// Every authentication failure (wrong AAD, another key, a tampered, truncated or foreign
    /// ciphertext, a version this key does not have) is the same `DecryptFailed`.
    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let versions = self.versions(Operation::Decrypt)?;
        let failed = || {
            self.err(
                ErrorKind::DecryptFailed,
                Operation::Decrypt,
                "decryption failed",
            )
        };
        let (v, nonce, body) = split(ct.as_bytes()).ok_or_else(failed)?;
        let material = versions.get(v as usize - 1).ok_or_else(failed)?;
        let nonce = aes_gcm::Nonce::try_from(nonce).map_err(|_| failed())?;
        cipher(material)
            .decrypt(&nonce, Payload { msg: body, aad })
            .map(Zeroizing::new)
            .map_err(|_| failed())
    }

    /// Provided methods that a backend can answer better must be implemented, and the opaque
    /// handles forward them.
    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        let (v, ..) = split(ct.as_bytes()).ok_or_else(|| {
            self.err(
                ErrorKind::InvalidArgument,
                Operation::Decrypt,
                "not a toykms ciphertext",
            )
        })?;
        Ok(Some(KeyVersion::from_u64(v.into())))
    }
}

impl Describe for ToyAeadKey {
    async fn describe(&self) -> Result<KeyInfo> {
        let n = self.versions(Operation::Describe)?.len() as u64;
        let versions = (1..=n)
            .map(|v| KeyVersionInfo::new(KeyVersion::from_u64(v), KeyState::Enabled))
            .collect();
        // An AEAD key also serves as a KEK (`KeyWrapKey::from_aead`), so it reports KEY_WRAP.
        Ok(
            KeyInfo::new("AES256_GCM", Capabilities::AEAD | Capabilities::KEY_WRAP)
                .with_state(Some(KeyState::Enabled))
                .with_primary_version(Some(KeyVersion::from_u64(n)))
                .with_versions(versions),
        )
    }
}

impl Semantics for ToyAeadKey {
    fn semantics(&self) -> Option<&KeySemantics> {
        Some(&self.semantics)
    }
}

/// The provider: holds the "connection" and opens `toykms://<name>` URIs.
#[derive(Clone)]
struct ToyProvider {
    kms: ToyKms,
}

impl ToyProvider {
    /// The typed constructor. A URI the grammar refuses is `Configuration` with
    /// `Operation::ParseUri`; nothing is read from the service.
    fn aead_key(&self, uri: impl IntoKeyUri) -> Result<ToyAeadKey> {
        let uri = uri.into_key_uri()?;
        let name = (uri.scheme() == BACKEND)
            .then_some(uri.rest())
            .and_then(|rest| rest.strip_prefix("//"))
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Configuration,
                    BACKEND,
                    Operation::ParseUri,
                    "expected toykms://<name>, the name made of ASCII letters, digits and '-'",
                )
                .with_resource(uri.to_string())
            })?;
        Ok(ToyAeadKey {
            kms: self.kms.clone(),
            name: name.to_owned(),
            uri: uri.to_string(),
            semantics: KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
                .with_ciphertext_reveals_version(true),
        })
    }
}

/// The opaque handles: every part the typed handle has, its semantics, and the typed handle
/// itself as the concrete key (`downcast_ref`). Purposes not implemented stay `Unsupported`.
impl Provider for ToyProvider {
    fn schemes(&self) -> &[&'static str] {
        &[BACKEND]
    }

    fn aead(&self, uri: &KeyUri, _: &OpenOptions) -> Result<AeadKey> {
        let k = Arc::new(self.aead_key(uri)?);
        let s = k.semantics.clone();
        Ok(AeadKey::new(BACKEND, k.clone())
            .with_describe(k.clone())
            .with_concrete(k)
            .with_semantics(s))
    }

    /// AEAD keys serve as KEKs, wrapping with empty AAD.
    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        self.aead(uri, opts).map(KeyWrapKey::from_aead)
    }

    fn describe(&self, uri: &KeyUri, _: &OpenOptions) -> Result<DescribeKey> {
        let k = Arc::new(self.aead_key(uri)?);
        let s = k.semantics.clone();
        Ok(DescribeKey::new(BACKEND, k.clone())
            .with_concrete(k)
            .with_semantics(s))
    }
}

/// The typed path: the provider's typed constructor, bridged by the suite.
struct ToyTyped(ToyProvider);

impl TypedHandles for ToyTyped {
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        let k = Arc::new(self.0.aead_key(uri)?);
        let s = k.semantics.clone();
        Ok(AeadKeyHandles::bridge(k).with_semantics(s))
    }
}

/// The fixture: key management for the suite, outside the anykms API.
#[derive(Default)]
struct MinimalFixture {
    kms: ToyKms,
    next: AtomicU64,
}

impl Fixture for MinimalFixture {
    fn name(&self) -> &'static str {
        "minimal"
    }

    /// Every feature is declared: supported, or absent by design with the reason.
    async fn probe(&self) -> FixtureCaps {
        use Feature::{
            Aead, BackendInfo, DataKeys, Describe, DescribeVersionState, Disable, DisableVersion,
            EmptyMessage, EmptyPlaintext, Extension, KeyWrap, KeyWrapPublicKeys, KeyWrapRewrap,
            Mac, MacInputLimit, MessageInputLimit, MinDecryptionVersion, NativeCiphertext,
            OversizePlaintext, PreflightState, RequestCount, Rewrap, RewrapWithAad, Rotate,
            RotateKeyWrap, RotateMac, RotateSigning, ServerErrorMessages, Signing, Throttle,
            UnauthorizedProvider, UsedPrimary, WrappedDataKeys,
        };
        let mut caps = FixtureCaps::new()
            .supports_all(&[Aead, Describe, Rotate, EmptyPlaintext])
            .not_applicable_all(
                &[Rewrap, RewrapWithAad, DataKeys, WrappedDataKeys],
                "no server-side rewrap or data keys (the recipes emulate both)",
            )
            .not_applicable_all(
                &[KeyWrap, KeyWrapRewrap, RotateKeyWrap, KeyWrapPublicKeys],
                "no native key-wrapping keys (AEAD keys serve as KEKs)",
            )
            .not_applicable_all(
                &[Mac, RotateMac, MacInputLimit, EmptyMessage],
                "no MAC keys",
            )
            .not_applicable_all(&[RotateSigning, MessageInputLimit], "no signing keys")
            .not_applicable_all(
                &[
                    Disable,
                    DisableVersion,
                    PreflightState,
                    DescribeVersionState,
                    MinDecryptionVersion,
                ],
                "toy keys and versions are always enabled",
            )
            .not_applicable_all(
                &[
                    Throttle,
                    ServerErrorMessages,
                    UnauthorizedProvider,
                    RequestCount,
                ],
                "no server: no quotas, server messages, credentials or requests",
            )
            .not_applicable_all(
                &[
                    Extension,
                    BackendInfo,
                    UsedPrimary,
                    OversizePlaintext,
                    NativeCiphertext,
                ],
                "not implemented by this minimal backend",
            );
        for &alg in SignatureAlgorithm::ALL {
            caps = caps.not_applicable(Signing(alg), "no signing keys");
        }
        caps
    }

    async fn create_key(&self, kind: TestKeyKind, _: KeyUse) -> Result<TestKey> {
        if kind != TestKeyKind::Aead {
            return Err(Error::unsupported(format!(
                "{kind:?} keys are declared n/a"
            )));
        }
        let name = format!("k{}", self.next.fetch_add(1, Ordering::Relaxed));
        self.kms.add_version(&name);
        let uri = KeyUri::parse(&format!("toykms://{name}"))?;
        Ok(TestKey::new(uri, name, kind))
    }

    /// The URI follows the primary version, so the rotated key is the same `TestKey`.
    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        self.kms.add_version(&key.name);
        Ok(key.clone())
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        KeyUri::parse("toykms://missing").expect("valid URI")
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(ToyProvider {
            kms: self.kms.clone(),
        })
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(ToyTyped(ToyProvider {
            kms: self.kms.clone(),
        }))
    }
}

fn main() -> ExitCode {
    anykms_conformance::run(async || MinimalFixture::default())
}
