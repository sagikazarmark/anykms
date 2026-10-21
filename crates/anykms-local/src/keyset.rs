//! In-memory, versioned key material and fault injection.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use anykms_core::{Error, ErrorKind, KeyState, Operation, Result};
use zeroize::Zeroizing;

pub(crate) const BACKEND: &str = "local";

/// Kinds of keys a [`LocalKeyset`] can hold.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocalKeyKind {
    /// AES-256-GCM: `Aead`, `Rewrap`, `DataKeys`.
    Aes256Gcm,
    /// HMAC (algorithm chosen per handle): `Mac`.
    Hmac,
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// Ed25519.
    Ed25519,
}

impl LocalKeyKind {
    /// Native type name reported by `describe`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LocalKeyKind::Aes256Gcm => "aes256-gcm",
            LocalKeyKind::Hmac => "hmac",
            LocalKeyKind::EcdsaP256 => "ecdsa-p256",
            LocalKeyKind::EcdsaP384 => "ecdsa-p384",
            LocalKeyKind::EcdsaP521 => "ecdsa-p521",
            LocalKeyKind::Ed25519 => "ed25519",
        }
    }
}

/// A fault to inject into the next operations, for testing retry and error handling.
///
/// Besides the transient kinds a retry policy reacts to, the faults cover the kinds application
/// code usually maps to its own errors (a missing key, a revoked policy, a disabled key), and
/// [`Fault::Kind`] injects any other [`ErrorKind`] (`Unauthenticated`, `DecryptFailed`,
/// `InvalidArgument`, ...), so that mapping can be tested without a real backend. Each fault
/// fails the next `times` operations with an error of that kind. Queue one with
/// [`LocalKeyset::inject`], [`inject_for_key`](LocalKeyset::inject_for_key) (one key) or
/// [`inject_on`](LocalKeyset::inject_on) (one operation); an error with a `Retry-After` or a retry
/// hint goes through [`inject_error`](LocalKeyset::inject_error).
///
/// The variants are `#[non_exhaustive]`: build them with the constructors
/// ([`Fault::throttled`], ..., [`Fault::of_kind`]) and match them with `..`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The next `times` operations fail with `Throttled` ([`Fault::throttled`]).
    #[non_exhaustive]
    Throttled { times: u32 },
    /// The next `times` operations fail with `Unavailable` ([`Fault::unavailable`]).
    #[non_exhaustive]
    Unavailable { times: u32 },
    /// The next `times` operations fail with `Timeout` ([`Fault::timeout`]).
    #[non_exhaustive]
    Timeout { times: u32 },
    /// The next `times` operations fail with `PermissionDenied` ([`Fault::permission_denied`]).
    #[non_exhaustive]
    PermissionDenied { times: u32 },
    /// The next `times` operations fail with `NotFound` ([`Fault::not_found`]).
    #[non_exhaustive]
    NotFound { times: u32 },
    /// The next `times` operations fail with `KeyStateInvalid` ([`Fault::key_state_invalid`]).
    #[non_exhaustive]
    KeyStateInvalid { times: u32 },
    /// The next `times` operations fail with `KeyVersionUnusable`
    /// ([`Fault::key_version_unusable`]).
    #[non_exhaustive]
    KeyVersionUnusable { times: u32 },
    /// The next `times` operations fail with `Backend` ([`Fault::backend`]).
    #[non_exhaustive]
    Backend { times: u32 },
    /// The next `times` operations fail with `kind`, any [`ErrorKind`] ([`Fault::of_kind`]).
    #[non_exhaustive]
    Kind { kind: ErrorKind, times: u32 },
}

impl Fault {
    /// [`Fault::Throttled`].
    pub fn throttled(times: u32) -> Self {
        Fault::Throttled { times }
    }

    /// [`Fault::Unavailable`].
    pub fn unavailable(times: u32) -> Self {
        Fault::Unavailable { times }
    }

    /// [`Fault::Timeout`].
    pub fn timeout(times: u32) -> Self {
        Fault::Timeout { times }
    }

    /// [`Fault::PermissionDenied`].
    pub fn permission_denied(times: u32) -> Self {
        Fault::PermissionDenied { times }
    }

    /// [`Fault::NotFound`].
    pub fn not_found(times: u32) -> Self {
        Fault::NotFound { times }
    }

    /// [`Fault::KeyStateInvalid`].
    pub fn key_state_invalid(times: u32) -> Self {
        Fault::KeyStateInvalid { times }
    }

    /// [`Fault::KeyVersionUnusable`].
    pub fn key_version_unusable(times: u32) -> Self {
        Fault::KeyVersionUnusable { times }
    }

    /// [`Fault::Backend`].
    pub fn backend(times: u32) -> Self {
        Fault::Backend { times }
    }

    /// [`Fault::Kind`]: the next `times` operations fail with `kind`, whatever its class.
    pub fn of_kind(kind: ErrorKind, times: u32) -> Self {
        Fault::Kind { kind, times }
    }

    /// The kind of the errors this fault injects.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Fault::Throttled { .. } => ErrorKind::Throttled,
            Fault::Unavailable { .. } => ErrorKind::Unavailable,
            Fault::Timeout { .. } => ErrorKind::Timeout,
            Fault::PermissionDenied { .. } => ErrorKind::PermissionDenied,
            Fault::NotFound { .. } => ErrorKind::NotFound,
            Fault::KeyStateInvalid { .. } => ErrorKind::KeyStateInvalid,
            Fault::KeyVersionUnusable { .. } => ErrorKind::KeyVersionUnusable,
            Fault::Backend { .. } => ErrorKind::Backend,
            Fault::Kind { kind, .. } => *kind,
        }
    }

    /// How many operations this fault fails.
    pub fn times(&self) -> u32 {
        match *self {
            Fault::Throttled { times }
            | Fault::Unavailable { times }
            | Fault::Timeout { times }
            | Fault::PermissionDenied { times }
            | Fault::NotFound { times }
            | Fault::KeyStateInvalid { times }
            | Fault::KeyVersionUnusable { times }
            | Fault::Backend { times }
            | Fault::Kind { times, .. } => times,
        }
    }
}

/// A queued fault: the error it injects, the operations it targets, and how many more it fails.
struct Pending {
    key: Option<String>,
    op: Option<Operation>,
    error: Injected,
    times: u32,
}

enum Injected {
    Kind(ErrorKind),
    Error(Error),
}

impl Pending {
    fn new(key: Option<String>, op: Option<Operation>, fault: Fault) -> Self {
        Self {
            key,
            op,
            error: Injected::Kind(fault.kind()),
            times: fault.times(),
        }
    }

    fn matches(&self, op: Operation, key: &str) -> bool {
        self.key.as_deref().is_none_or(|k| k == key) && self.op.is_none_or(|o| o == op)
    }
}

pub(crate) enum Material {
    Aes(Zeroizing<[u8; 32]>),
    Hmac(Zeroizing<[u8; 64]>),
    P256(Box<p256::ecdsa::SigningKey>),
    P384(Box<p384::ecdsa::SigningKey>),
    P521(Box<p521::ecdsa::SigningKey>),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

pub(crate) fn random_bytes<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::fill(&mut b[..]).expect("operating system RNG failed");
    b
}

impl Material {
    fn generate(kind: LocalKeyKind) -> Self {
        match kind {
            LocalKeyKind::Aes256Gcm => Material::Aes(random_bytes::<32>()),
            LocalKeyKind::Hmac => Material::Hmac(random_bytes::<64>()),
            LocalKeyKind::EcdsaP256 => loop {
                if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&random_bytes::<32>()[..]) {
                    break Material::P256(Box::new(k));
                }
            },
            LocalKeyKind::EcdsaP384 => loop {
                if let Ok(k) = p384::ecdsa::SigningKey::from_slice(&random_bytes::<48>()[..]) {
                    break Material::P384(Box::new(k));
                }
            },
            LocalKeyKind::EcdsaP521 => loop {
                let mut b = random_bytes::<66>();
                b[0] &= 0x01;
                if let Ok(k) = p521::ecdsa::SigningKey::from_slice(&b[..]) {
                    break Material::P521(Box::new(k));
                }
            },
            LocalKeyKind::Ed25519 => Material::Ed25519(Box::new(
                ed25519_dalek::SigningKey::from_bytes(&random_bytes::<32>()),
            )),
        }
    }
}

pub(crate) struct KeyEntry {
    pub(crate) kind: LocalKeyKind,
    /// Index `i` holds version `i + 1`.
    pub(crate) versions: Vec<(Material, u64)>,
    pub(crate) state: KeyState,
    pub(crate) min_decryption_version: u64,
}

impl KeyEntry {
    pub(crate) fn latest(&self) -> u64 {
        self.versions.len() as u64
    }

    pub(crate) fn usable(&self, op: Operation) -> Result<()> {
        match &self.state {
            KeyState::Enabled => Ok(()),
            _ => Err(Error::new(
                ErrorKind::KeyStateInvalid,
                BACKEND,
                op,
                "key is not enabled",
            )),
        }
    }

    /// Material of `version` for operations on existing data (decrypt, verify).
    pub(crate) fn for_read(&self, version: u64, op: Operation) -> Result<&Material> {
        self.usable(op)?;
        if version == 0 || version > self.latest() {
            let kind = if op == Operation::Decrypt || op == Operation::Rewrap {
                ErrorKind::DecryptFailed
            } else {
                ErrorKind::VerificationFailed
            };
            return Err(Error::new(kind, BACKEND, op, "unknown key version"));
        }
        if version < self.min_decryption_version {
            return Err(Error::new(
                ErrorKind::KeyVersionUnusable,
                BACKEND,
                op,
                "key version is below the minimum decryption version",
            ));
        }
        Ok(&self.versions[version as usize - 1].0)
    }

    /// Material of `version` (taken from input) for public-key reads: a version this key does
    /// not have is `UnknownKeyVersion` (A3(a)). Like transit, versions below the minimum
    /// decryption version are no longer published (`UnknownKeyVersion` too), and `describe`
    /// omits them.
    pub(crate) fn for_public_key(&self, version: u64, op: Operation) -> Result<&Material> {
        self.usable(op)?;
        if version == 0 || version > self.latest() || version < self.min_decryption_version {
            return Err(Error::new(
                ErrorKind::UnknownKeyVersion,
                BACKEND,
                op,
                "key version not found (or below the minimum decryption version)",
            ));
        }
        Ok(&self.versions[version as usize - 1].0)
    }

    pub(crate) fn primary(&self, op: Operation) -> Result<(u64, &Material)> {
        self.usable(op)?;
        let v = self.latest();
        Ok((v, &self.versions[v as usize - 1].0))
    }
}

pub(crate) struct Inner {
    pub(crate) name: String,
    pub(crate) keys: Mutex<HashMap<String, KeyEntry>>,
    faults: Mutex<VecDeque<Pending>>,
}

/// An in-memory set of versioned keys. Cloning is cheap and shares the keys.
///
/// **Not for production.** Keys live in process memory with no persistence and vanish when the
/// process exits; data encrypted under them is lost. Use it for tests and development.
#[derive(Clone)]
pub struct LocalKeyset {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Debug for LocalKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<String> = self.lock().keys().cloned().collect();
        f.debug_struct("LocalKeyset")
            .field("name", &self.inner.name)
            .field("keys", &keys)
            .finish()
    }
}

/// Builds a [`LocalKeyset`].
#[derive(Debug, Default)]
pub struct LocalKeysetBuilder {
    name: Option<String>,
    keys: Vec<(String, LocalKeyKind)>,
}

impl LocalKeysetBuilder {
    /// Names the keyset (the `<keyset>` segment of `local://<keyset>/<name>`). Defaults to
    /// `"default"`.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds a key of `kind`.
    pub fn key(mut self, name: impl Into<String>, kind: LocalKeyKind) -> Self {
        self.keys.push((name.into(), kind));
        self
    }

    /// Adds an AES-256-GCM key.
    pub fn aead(self, name: impl Into<String>) -> Self {
        self.key(name, LocalKeyKind::Aes256Gcm)
    }

    /// Adds an HMAC key.
    pub fn hmac(self, name: impl Into<String>) -> Self {
        self.key(name, LocalKeyKind::Hmac)
    }

    /// Adds an ECDSA P-256 key.
    pub fn ecdsa_p256(self, name: impl Into<String>) -> Self {
        self.key(name, LocalKeyKind::EcdsaP256)
    }

    /// Adds an ECDSA P-384 key.
    pub fn ecdsa_p384(self, name: impl Into<String>) -> Self {
        self.key(name, LocalKeyKind::EcdsaP384)
    }

    /// Adds an ECDSA P-521 key.
    pub fn ecdsa_p521(self, name: impl Into<String>) -> Self {
        self.key(name, LocalKeyKind::EcdsaP521)
    }

    /// Adds an Ed25519 key.
    pub fn ed25519(self, name: impl Into<String>) -> Self {
        self.key(name, LocalKeyKind::Ed25519)
    }

    /// Builds the keyset, generating fresh key material.
    pub fn build(self) -> LocalKeyset {
        let ks = LocalKeyset {
            inner: Arc::new(Inner {
                name: self.name.unwrap_or_else(|| "default".to_owned()),
                keys: Mutex::new(HashMap::new()),
                faults: Mutex::new(VecDeque::new()),
            }),
        };
        for (name, kind) in self.keys {
            ks.insert(name, kind);
        }
        ks
    }
}

fn not_found(op: Operation) -> Error {
    Error::new(ErrorKind::NotFound, BACKEND, op, "key not found")
}

impl LocalKeyset {
    /// Starts building a keyset.
    pub fn builder() -> LocalKeysetBuilder {
        LocalKeysetBuilder::default()
    }

    /// The keyset name.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, HashMap<String, KeyEntry>> {
        self.inner.keys.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Adds (or replaces) a key with fresh material at version 1.
    pub fn insert(&self, name: impl Into<String>, kind: LocalKeyKind) {
        let entry = KeyEntry {
            kind,
            versions: vec![(Material::generate(kind), now())],
            state: KeyState::Enabled,
            min_decryption_version: 1,
        };
        self.lock().insert(name.into(), entry);
    }

    /// Whether a key exists.
    pub fn contains(&self, name: &str) -> bool {
        self.lock().contains_key(name)
    }

    /// The kind of a key.
    pub fn kind(&self, name: &str) -> Option<LocalKeyKind> {
        self.lock().get(name).map(|k| k.kind)
    }

    /// Adds a new primary version to a key.
    pub fn rotate(&self, name: &str) -> Result<()> {
        let mut keys = self.lock();
        let k = keys
            .get_mut(name)
            .ok_or_else(|| not_found(Operation::Configure))?;
        let m = Material::generate(k.kind);
        k.versions.push((m, now()));
        Ok(())
    }

    /// Disables a key: every operation fails with `KeyStateInvalid`.
    pub fn disable(&self, name: &str) -> Result<()> {
        self.set_state(name, KeyState::Disabled)
    }

    /// Re-enables a key.
    pub fn enable(&self, name: &str) -> Result<()> {
        self.set_state(name, KeyState::Enabled)
    }

    fn set_state(&self, name: &str, state: KeyState) -> Result<()> {
        let mut keys = self.lock();
        keys.get_mut(name)
            .ok_or_else(|| not_found(Operation::Configure))?
            .state = state;
        Ok(())
    }

    /// Versions below `version` can no longer decrypt or verify (`KeyVersionUnusable`); their
    /// public keys are no longer served (`UnknownKeyVersion`) and `describe` omits them, as on
    /// transit.
    pub fn set_min_decryption_version(&self, name: &str, version: u64) -> Result<()> {
        let mut keys = self.lock();
        let k = keys
            .get_mut(name)
            .ok_or_else(|| not_found(Operation::Configure))?;
        if version == 0 || version > k.latest() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                BACKEND,
                Operation::Configure,
                "version out of range",
            ));
        }
        k.min_decryption_version = version;
        Ok(())
    }

    /// Queues a fault for the next operations on any key of this keyset.
    pub fn inject(&self, fault: Fault) {
        self.queue(Pending::new(None, None, fault));
    }

    /// Queues a fault for the next operations on one key only.
    pub fn inject_for_key(&self, name: impl Into<String>, fault: Fault) {
        self.queue(Pending::new(Some(name.into()), None, fault));
    }

    /// Queues a fault for the next `op` operations only (e.g. [`Operation::Decrypt`]), on any key;
    /// other operations pass it by.
    pub fn inject_on(&self, op: Operation, fault: Fault) {
        self.queue(Pending::new(None, Some(op), fault));
    }

    /// Queues a fully formed error for the next `times` operations on any key, for what a
    /// [`Fault`] does not carry: a `Retry-After` ([`Error::with_retry_after`]), a retry hint
    /// ([`Error::with_retry_hint`]), a message or a source. Each operation fails with a clone of
    /// `error`, relabelled with that operation and, like every local error, the key's URI.
    pub fn inject_error(&self, error: Error, times: u32) {
        self.queue(Pending {
            key: None,
            op: None,
            error: Injected::Error(error),
            times,
        });
    }

    fn queue(&self, fault: Pending) {
        self.inner
            .faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(fault);
    }

    /// Removes all queued faults.
    pub fn clear_faults(&self) {
        self.inner
            .faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Consumes one pending fault that targets `op` on `key`, if any, and returns its error.
    pub(crate) fn take_fault(&self, op: Operation, key: &str) -> Result<()> {
        let mut faults = self.inner.faults.lock().unwrap_or_else(|p| p.into_inner());
        // Faults with no remaining count never fire and never hide the next one.
        faults.retain(|f| f.times > 0);
        let Some(idx) = faults.iter().position(|f| f.matches(op, key)) else {
            return Ok(());
        };
        let fault = &mut faults[idx];
        fault.times -= 1;
        let e = match &fault.error {
            Injected::Kind(kind) => Error::new(*kind, BACKEND, op, "injected fault"),
            Injected::Error(e) => e.clone().with_operation(op),
        };
        if fault.times == 0 {
            faults.remove(idx);
        }
        Err(e)
    }

    /// The `local://<keyset>/<name>` URI of key `name`, as errors name it.
    pub(crate) fn resource(&self, name: &str) -> String {
        format!("local://{}/{name}", self.name())
    }

    /// Runs `f` on a key after fault injection and existence checks. Every error, injected or
    /// from `f`, is labeled with the key's URI ([`Error::resource`]), as remote backends do.
    pub(crate) fn with_key<T>(
        &self,
        name: &str,
        op: Operation,
        f: impl FnOnce(&KeyEntry) -> Result<T>,
    ) -> Result<T> {
        let r = self.take_fault(op, name).and_then(|()| {
            let keys = self.lock();
            let k = keys.get(name).ok_or_else(|| not_found(op))?;
            f(k)
        });
        r.map_err(|e| e.with_resource(self.resource(name)))
    }
}

fn now() -> u64 {
    anykms_core::time::unix_now().as_secs()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn zero_count_faults_neither_fire_nor_hide_others() {
        let ks = LocalKeyset::builder().aead("k").build();
        ks.inject(Fault::throttled(0));
        ks.inject(Fault::unavailable(1));
        assert_eq!(
            ks.take_fault(Operation::Encrypt, "k").unwrap_err().kind(),
            ErrorKind::Unavailable
        );
        assert!(ks.take_fault(Operation::Encrypt, "k").is_ok());
        ks.inject_for_key("other", Fault::timeout(1));
        assert!(ks.take_fault(Operation::Encrypt, "k").is_ok());
        assert_eq!(
            ks.take_fault(Operation::Encrypt, "other")
                .unwrap_err()
                .kind(),
            ErrorKind::Timeout
        );
        ks.inject_error(
            Error::new(ErrorKind::Throttled, BACKEND, Operation::Encrypt, "x"),
            0,
        );
        assert!(ks.take_fault(Operation::Encrypt, "k").is_ok());
    }

    #[test]
    fn every_fault_injects_its_kind() {
        let ks = LocalKeyset::builder().aead("k").build();
        for fault in [
            Fault::throttled(2),
            Fault::unavailable(2),
            Fault::timeout(2),
            Fault::permission_denied(2),
            Fault::not_found(2),
            Fault::key_state_invalid(2),
            Fault::key_version_unusable(2),
            Fault::backend(2),
            // Caller-class kinds and Unauthenticated, which no named variant covers.
            Fault::of_kind(ErrorKind::Unauthenticated, 2),
            Fault::of_kind(ErrorKind::DecryptFailed, 2),
            Fault::of_kind(ErrorKind::InvalidArgument, 2),
        ] {
            assert_eq!(fault.times(), 2);
            ks.inject(fault);
            for _ in 0..2 {
                let e = ks.take_fault(Operation::Decrypt, "k").unwrap_err();
                assert_eq!(e.kind(), fault.kind(), "{fault:?}");
                assert_eq!(e.operation(), Operation::Decrypt, "{fault:?}");
            }
            assert!(ks.take_fault(Operation::Decrypt, "k").is_ok(), "{fault:?}");
        }
    }

    /// `inject_on` fires on its operation only; other operations neither consume it nor are
    /// blocked by it.
    #[test]
    fn operation_faults_target_one_operation() {
        let ks = LocalKeyset::builder().aead("k").build();
        ks.inject_on(Operation::Decrypt, Fault::throttled(1));
        ks.inject(Fault::unavailable(1));
        assert_eq!(
            ks.take_fault(Operation::Encrypt, "k").unwrap_err().kind(),
            ErrorKind::Unavailable
        );
        assert!(ks.take_fault(Operation::Encrypt, "k").is_ok());
        let e = ks.take_fault(Operation::Decrypt, "j").unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Throttled, Operation::Decrypt)
        );
        assert!(ks.take_fault(Operation::Decrypt, "k").is_ok());
    }

    /// `inject_error` returns the error as given (kind, message, Retry-After, retry hint),
    /// relabelled with the failing operation.
    #[test]
    fn injected_errors_keep_their_hints() {
        let ks = LocalKeyset::builder().aead("k").build();
        let throttled = Error::new(
            ErrorKind::Throttled,
            BACKEND,
            Operation::Encrypt,
            "slow down",
        )
        .with_retry_after(Duration::from_secs(2));
        let hinted = Error::new(
            ErrorKind::NotFound,
            BACKEND,
            Operation::Encrypt,
            "replicating",
        )
        .with_retry_hint(Duration::from_millis(500));
        ks.inject_error(throttled, 2);
        ks.inject_error(hinted, 1);
        for _ in 0..2 {
            let e = ks.take_fault(Operation::Decrypt, "k").unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Throttled);
            assert_eq!(e.operation(), Operation::Decrypt);
            assert_eq!(e.message(), "slow down");
            assert_eq!(e.retry_after(), Some(Duration::from_secs(2)));
        }
        let e = ks.take_fault(Operation::Sign, "k").unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::NotFound, Operation::Sign)
        );
        assert_eq!(e.retry_hint(), Some(Duration::from_millis(500)));
        assert!(ks.take_fault(Operation::Encrypt, "k").is_ok());
    }

    /// Through a handle: the fault fires on the targeted operation, labelled with the key's URI.
    #[tokio::test]
    async fn operation_faults_reach_the_handles() {
        use anykms_core::Aead;
        let ks = LocalKeyset::builder().aead("k").build();
        let k = ks.aead_key("k");
        ks.inject_on(
            Operation::Decrypt,
            Fault::of_kind(ErrorKind::DecryptFailed, 1),
        );
        let ct = k.encrypt(b"pt", b"").await.unwrap();
        let e = k.decrypt(&ct, b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DecryptFailed, "{e}");
        assert_eq!(e.resource(), Some("local://default/k"));
        assert_eq!(&*k.decrypt(&ct, b"").await.unwrap(), b"pt");
    }
}
