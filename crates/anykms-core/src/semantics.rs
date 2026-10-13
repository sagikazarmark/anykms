//! What a handle does where backends legitimately differ: [`KeySemantics`].

use std::sync::Arc;
use std::time::Duration;

/// Where backends legitimately differ, what this handle does. Known at open (no I/O) and
/// constant for the handle's life: every field states a contract that holds before any request.
///
/// Read it through [`Semantics::semantics`] (or the handles' inherent `semantics()`). `None`
/// from `semantics()` means undeclared (third-party backends); a handle that declares no
/// `KeySemantics` fails the conformance case.
///
/// Build one with [`new`](Self::new) and the `with_*` methods; every field not set keeps the
/// default its method documents.
///
/// ```
/// use anykms_core::{DataKeyAad, DataKeySource, KeySemantics, VersionModel, VersionShape};
///
/// let s = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric)
///     .with_ciphertext_reveals_version(true)
///     .with_data_keys(Some(DataKeySource::native(DataKeyAad::Bound)));
/// assert_eq!(s.version_model(), VersionModel::Floating);
/// assert!(s.primary_reported());
/// assert_eq!(s.max_plaintext(), None);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySemantics {
    version_model: VersionModel,
    version_shape: VersionShape,
    primary_reported: bool,
    state_scope: StateScope,
    versions_listed: bool,
    ciphertext_reveals_version: bool,
    reports_used_primary: bool,
    unversioned_verify: UnversionedVerify,
    pinned_verify: PinnedVerify,
    verification: Verification,
    data_keys: Option<DataKeySource>,
    max_plaintext: Option<usize>,
    max_mac_input: Option<usize>,
    max_signed_message: Option<usize>,
}

impl KeySemantics {
    /// Semantics with the given version model and shape, and every other field at its default.
    pub fn new(version_model: VersionModel, version_shape: VersionShape) -> Self {
        Self {
            version_model,
            version_shape,
            primary_reported: true,
            state_scope: StateScope::Key,
            versions_listed: true,
            ciphertext_reveals_version: false,
            reports_used_primary: false,
            unversioned_verify: UnversionedVerify::Rejected,
            pinned_verify: PinnedVerify::PinnedOnly,
            verification: Verification::Backend,
            data_keys: None,
            max_plaintext: None,
            max_mac_input: None,
            max_signed_message: None,
        }
    }

    /// Whether `describe()` reports the primary (current) version. Default `true`.
    pub fn with_primary_reported(mut self, v: bool) -> Self {
        self.primary_reported = v;
        self
    }

    /// Whether key state is per key or per version only. Default [`StateScope::Key`].
    pub fn with_state_scope(mut self, s: StateScope) -> Self {
        self.state_scope = s;
        self
    }

    /// Whether `describe()` lists the key's versions. Default `true`.
    pub fn with_versions_listed(mut self, v: bool) -> Self {
        self.versions_listed = v;
        self
    }

    /// Whether a ciphertext (or wrapped key) names the version that produced it, without I/O
    /// (`ciphertext_version` returns `Some`). Default `false`.
    pub fn with_ciphertext_reveals_version(mut self, v: bool) -> Self {
        self.ciphertext_reveals_version = v;
        self
    }

    /// Whether decrypting reports whether the primary version was used
    /// ([`Decrypted`](crate::Decrypted)). Default `false`.
    pub fn with_reports_used_primary(mut self, v: bool) -> Self {
        self.reports_used_primary = v;
        self
    }

    /// What verifying a signature that names no version does. Default
    /// [`UnversionedVerify::Rejected`].
    pub fn with_unversioned_verify(mut self, u: UnversionedVerify) -> Self {
        self.unversioned_verify = u;
        self
    }

    /// Which versions a pinned handle verifies. Default [`PinnedVerify::PinnedOnly`]; read only
    /// for [`VersionModel::Pinned`].
    pub fn with_pinned_verify(mut self, p: PinnedVerify) -> Self {
        self.pinned_verify = p;
        self
    }

    /// Where signatures are verified. Default [`Verification::Backend`].
    pub fn with_verification(mut self, v: Verification) -> Self {
        self.verification = v;
        self
    }

    /// How the handle's data keys are made. Default `None` (no `DataKeys` part).
    pub fn with_data_keys(mut self, d: Option<DataKeySource>) -> Self {
        self.data_keys = d;
        self
    }

    /// The largest plaintext the handle encrypts, below the request size. `None` = no such
    /// limit, or the handle has no such operation. Large plaintexts go through `EnvelopeAead`.
    /// Default `None`.
    pub fn with_max_plaintext(mut self, n: Option<usize>) -> Self {
        self.max_plaintext = n;
        self
    }

    /// The largest MAC input, below the request size. `None` = no such limit, or the handle has
    /// no such operation. Default `None`.
    pub fn with_max_mac_input(mut self, n: Option<usize>) -> Self {
        self.max_mac_input = n;
        self
    }

    /// The largest message the handle signs, below the request size. `None` = no such limit,
    /// or the handle has no such operation. Default `None`.
    pub fn with_max_signed_message(mut self, n: Option<usize>) -> Self {
        self.max_signed_message = n;
        self
    }

    /// How writes choose a version; see [`VersionModel`].
    pub fn version_model(&self) -> VersionModel {
        self.version_model
    }

    /// The form of the key's versions; see [`VersionShape`].
    pub fn version_shape(&self) -> VersionShape {
        self.version_shape
    }

    /// See [`with_primary_reported`](Self::with_primary_reported).
    pub fn primary_reported(&self) -> bool {
        self.primary_reported
    }

    /// See [`with_state_scope`](Self::with_state_scope).
    pub fn state_scope(&self) -> StateScope {
        self.state_scope
    }

    /// See [`with_versions_listed`](Self::with_versions_listed).
    pub fn versions_listed(&self) -> bool {
        self.versions_listed
    }

    /// See [`with_ciphertext_reveals_version`](Self::with_ciphertext_reveals_version).
    pub fn ciphertext_reveals_version(&self) -> bool {
        self.ciphertext_reveals_version
    }

    /// See [`with_reports_used_primary`](Self::with_reports_used_primary).
    pub fn reports_used_primary(&self) -> bool {
        self.reports_used_primary
    }

    /// See [`with_unversioned_verify`](Self::with_unversioned_verify).
    pub fn unversioned_verify(&self) -> UnversionedVerify {
        self.unversioned_verify
    }

    /// See [`with_pinned_verify`](Self::with_pinned_verify).
    pub fn pinned_verify(&self) -> PinnedVerify {
        self.pinned_verify
    }

    /// See [`with_verification`](Self::with_verification).
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// See [`with_data_keys`](Self::with_data_keys).
    pub fn data_keys(&self) -> Option<DataKeySource> {
        self.data_keys
    }

    /// See [`with_max_plaintext`](Self::with_max_plaintext).
    pub fn max_plaintext(&self) -> Option<usize> {
        self.max_plaintext
    }

    /// See [`with_max_mac_input`](Self::with_max_mac_input).
    pub fn max_mac_input(&self) -> Option<usize> {
        self.max_mac_input
    }

    /// See [`with_max_signed_message`](Self::with_max_signed_message).
    pub fn max_signed_message(&self) -> Option<usize> {
        self.max_signed_message
    }
}

/// How writes choose a key version.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionModel {
    /// Writes use the current version, which rotation moves (transit, local, GCP AEAD,
    /// unversioned Azure URIs).
    Floating,
    /// The URI names one version; every write uses it (GCP signing/MAC/RSA KEK, versioned
    /// Azure).
    Pinned,
    /// One key identity, no addressable versions; rotation (if any) is inside it (AWS). An alias
    /// URI resolves to a key per request: repointing the alias moves writes to another key.
    Single,
}

/// Which versions a [`Pinned`](VersionModel::Pinned) handle verifies.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedVerify {
    /// A pinned handle verifies only its pinned version (Azure).
    PinnedOnly,
    /// A pinned handle verifies signatures of any version of the same key (GCP: signing keys
    /// must be pinned, so verification across rotation needs this).
    AnyVersion,
}

/// The form of a key's versions ([`KeyVersion`](crate::KeyVersion)).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionShape {
    /// Canonical decimal numbers, ordered by [`KeyVersion::as_u64`](crate::KeyVersion::as_u64).
    Numeric,
    /// Opaque strings, compared only for equality (an ARN, 32 hex characters).
    Opaque,
}

/// Where key state lives.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateScope {
    /// A key-level state, which on Azure is the current (or pinned) version's enabled flag
    /// (Azure has no key-level flag).
    Key,
    /// Only versions have a state: [`KeyInfo::state`](crate::KeyInfo::state) is `None`.
    VersionOnly,
}

/// What verifying a signature that names no version does.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnversionedVerify {
    /// Refused: the signature must name its version.
    Rejected,
    /// Verified with the current version.
    UsesCurrent,
}

/// Where signatures are verified.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// By the backend, per request.
    Backend,
    /// Verified in this process with the version's public key. A version the backend stops
    /// serving keeps verifying for at most `revocation_lag` (cache TTL × 1.1, counted from when
    /// the backend starts refusing).
    #[non_exhaustive]
    Local {
        /// How long a version the backend stops serving keeps verifying.
        revocation_lag: Duration,
    },
}

impl Verification {
    /// [`Verification::Local`] with the given revocation lag.
    pub fn local(revocation_lag: Duration) -> Self {
        Self::Local { revocation_lag }
    }
}

/// How a handle's data keys are made.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataKeySource {
    /// By the backend's own data-key operation.
    #[non_exhaustive]
    Native {
        /// What happens to the data key's AAD.
        aad: DataKeyAad,
    },
    /// In this process: a fresh random key, wrapped by the backend.
    #[non_exhaustive]
    Emulated {
        /// What happens to the data key's AAD.
        aad: DataKeyAad,
    },
}

impl DataKeySource {
    /// [`DataKeySource::Native`] with the given AAD handling.
    pub fn native(aad: DataKeyAad) -> Self {
        Self::Native { aad }
    }

    /// [`DataKeySource::Emulated`] with the given AAD handling.
    pub fn emulated(aad: DataKeyAad) -> Self {
        Self::Emulated { aad }
    }

    /// What happens to the data key's AAD, whatever the source.
    pub fn aad(&self) -> DataKeyAad {
        match *self {
            Self::Native { aad } | Self::Emulated { aad } => aad,
        }
    }
}

/// What a data-key operation does with non-empty AAD.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataKeyAad {
    /// The wrapped key is bound to the AAD.
    Bound,
    /// Non-empty AAD is `Unsupported` (never ignored).
    Refused,
    /// Bound where the server or key supports it, otherwise `Unsupported`; never ignored. For
    /// handles that cannot know which at open (OpenBao before the first request; Managed HSM
    /// `DataKeysKey`, whose key type is read lazily).
    BoundOrRefused,
}

/// Handles that report their [`KeySemantics`].
///
/// Implemented by the opaque handles ([`AeadKey`](crate::AeadKey), ...), which carry the value
/// their provider set, and by typed handles, which always know it.
///
/// # Forwarding
///
/// A wrapper forwards `Semantics` only if it changes no behavior that `KeySemantics` describes.
/// [`Retry`](crate::Retry), [`Observed`](crate::Observed), `Arc`, `Box` and `&T` forward.
/// Wrappers that change such a behavior do not implement it: `EnvelopeAead` (no plaintext
/// limit), `CachedVerifier` (turns backend verification into local), `AeadKeyWrap`,
/// `KeyWrapDataKeys`, `EmulatedDataKeys` and `CachingKeyWrap`. A [`Layer`](crate::Layer) must
/// not change a behavior that `KeySemantics` describes, and layers cannot replace the value.
pub trait Semantics {
    /// What this handle does where backends differ; `None` when undeclared.
    fn semantics(&self) -> Option<&KeySemantics>;
}

impl<T: Semantics + ?Sized> Semantics for Arc<T> {
    fn semantics(&self) -> Option<&KeySemantics> {
        (**self).semantics()
    }
}

impl<T: Semantics + ?Sized> Semantics for Box<T> {
    fn semantics(&self) -> Option<&KeySemantics> {
        (**self).semantics()
    }
}

impl<T: Semantics + ?Sized> Semantics for &T {
    fn semantics(&self) -> Option<&KeySemantics> {
        (**self).semantics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let s = KeySemantics::new(VersionModel::Single, VersionShape::Opaque);
        assert_eq!(s.version_model(), VersionModel::Single);
        assert_eq!(s.version_shape(), VersionShape::Opaque);
        assert!(s.primary_reported());
        assert_eq!(s.state_scope(), StateScope::Key);
        assert!(s.versions_listed());
        assert!(!s.ciphertext_reveals_version());
        assert!(!s.reports_used_primary());
        assert_eq!(s.unversioned_verify(), UnversionedVerify::Rejected);
        assert_eq!(s.pinned_verify(), PinnedVerify::PinnedOnly);
        assert_eq!(s.verification(), Verification::Backend);
        assert_eq!(s.data_keys(), None);
        assert_eq!(s.max_plaintext(), None);
        assert_eq!(s.max_mac_input(), None);
        assert_eq!(s.max_signed_message(), None);
    }

    #[test]
    fn builders_set_every_field() {
        let lag = Duration::from_secs(66);
        let s = KeySemantics::new(VersionModel::Pinned, VersionShape::Numeric)
            .with_primary_reported(false)
            .with_state_scope(StateScope::VersionOnly)
            .with_versions_listed(false)
            .with_ciphertext_reveals_version(true)
            .with_reports_used_primary(true)
            .with_unversioned_verify(UnversionedVerify::UsesCurrent)
            .with_pinned_verify(PinnedVerify::AnyVersion)
            .with_verification(Verification::local(lag))
            .with_data_keys(Some(DataKeySource::emulated(DataKeyAad::BoundOrRefused)))
            .with_max_plaintext(Some(1))
            .with_max_mac_input(Some(2))
            .with_max_signed_message(Some(3));
        assert_eq!(s.version_model(), VersionModel::Pinned);
        assert_eq!(s.version_shape(), VersionShape::Numeric);
        assert!(!s.primary_reported());
        assert_eq!(s.state_scope(), StateScope::VersionOnly);
        assert!(!s.versions_listed());
        assert!(s.ciphertext_reveals_version());
        assert!(s.reports_used_primary());
        assert_eq!(s.unversioned_verify(), UnversionedVerify::UsesCurrent);
        assert_eq!(s.pinned_verify(), PinnedVerify::AnyVersion);
        assert_eq!(
            s.verification(),
            Verification::Local {
                revocation_lag: lag
            }
        );
        let dk = s.data_keys().unwrap();
        assert_eq!(
            dk,
            DataKeySource::Emulated {
                aad: DataKeyAad::BoundOrRefused
            }
        );
        assert_eq!(dk.aad(), DataKeyAad::BoundOrRefused);
        assert_eq!(
            DataKeySource::native(DataKeyAad::Refused).aad(),
            DataKeyAad::Refused
        );
        assert_eq!(s.max_plaintext(), Some(1));
        assert_eq!(s.max_mac_input(), Some(2));
        assert_eq!(s.max_signed_message(), Some(3));
    }

    struct Declared(KeySemantics);
    impl Semantics for Declared {
        fn semantics(&self) -> Option<&KeySemantics> {
            Some(&self.0)
        }
    }

    #[test]
    fn smart_pointers_and_references_forward() {
        fn get<S: Semantics>(s: S) -> Option<KeySemantics> {
            s.semantics().cloned()
        }
        let s = KeySemantics::new(VersionModel::Floating, VersionShape::Numeric);
        let d = Declared(s.clone());
        assert_eq!(get(&d), Some(s.clone()));
        assert_eq!(get(Box::new(Declared(s.clone()))), Some(s.clone()));
        assert_eq!(get(Arc::new(Declared(s.clone()))), Some(s.clone()));
        let dyn_box: Box<dyn Semantics> = Box::new(Declared(s.clone()));
        assert_eq!(get(dyn_box), Some(s));
    }
}
