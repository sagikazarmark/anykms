//! The [`Fixture`] trait backends implement to run the suite.

use std::collections::HashMap;
use std::fmt;
use std::future::{Future, ready};
use std::sync::Arc;
use std::time::Duration;

use anykms_core::KeySemantics;
use anykms_core::{
    Aead, AeadKey, Ciphertext, DataKeys, DataKeysKey, Describe, DigestSigner, DigestVerifier,
    DynDescribe, DynDigestSigner, DynDigestVerifier, DynMac, DynMessageSigner, DynMessageVerifier,
    DynPreflight, DynPublicKeys, Error, ErrorKind, KeyUri, KeyVersion, KeyWrap, KeyWrapKey, Mac,
    MacAlgorithm, MessageSigner, MessageVerifier, Operation, Preflight, Provider, PublicKeys,
    Result, Rewrap, SignatureAlgorithm, WrappedDataKeys,
};

/// Something a case may need from the backend or the fixture.
///
/// Every feature a case requires must be declared by [`Fixture::probe`]: [`supports`]
/// (`Yes`), [`not_applicable`] (absent by design) or [`lacks`] (unavailable here). A feature a
/// case requires that the fixture left undeclared fails that case, whatever
/// `ANYKMS_FAIL_ON_SKIP` says, and the `conformance::declarations` trial lists every such feature:
/// a capability added to the suite later then fails a fixture loudly instead of silently dropping
/// coverage.
///
/// [`supports`]: FixtureCaps::supports
/// [`not_applicable`]: FixtureCaps::not_applicable
/// [`lacks`]: FixtureCaps::lacks
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Feature {
    /// AEAD keys (`Provider::aead`, [`TestKeyKind::Aead`]).
    Aead,
    /// AEAD keys rewrap ciphertexts server-side (the `rewrap` part of `AeadKey`).
    Rewrap,
    /// Keys generate data keys: AEAD keys with [`Feature::Aead`] (the `data_keys` part of
    /// `AeadKey`, and `Provider::data_keys`), otherwise native key-wrapping keys through
    /// `Provider::data_keys` (e.g. the `KeyWrapDataKeys` recipe).
    DataKeys,
    /// AEAD keys generate data keys returned only wrapped (the `wrapped_data_keys` part of
    /// `AeadKey`).
    WrappedDataKeys,
    /// HMAC keys (`Provider::mac`, [`TestKeyKind::Hmac`]). Cases ask for a key per
    /// [`MacAlgorithm`]: a fixture whose keys serve every algorithm may return the same kind of
    /// key for each, one whose keys are bound to an algorithm (AWS, GCP, Azure Managed HSM)
    /// creates the key for the algorithm asked.
    Mac,
    /// Keys are described (the `describe` part of every handle, `Provider::describe`).
    Describe,
    /// Native key-wrapping keys ([`TestKeyKind::KeyWrap`]: RSA-OAEP, AES key wrap) opened with
    /// `Provider::key_wrap`. Not about AEAD keys used as KEKs (`KeyWrapKey::from_aead`), which
    /// every `Aead` fixture provides.
    KeyWrap,
    /// Native key-wrapping keys rewrap wrapped keys server-side (the `rewrap` part of a native
    /// `KeyWrapKey`).
    KeyWrapRewrap,
    /// The fixture performs a backend extension call through an `AeadKey`
    /// ([`Fixture::extension_call`]), so the suite can check that the handle's layers apply to
    /// it.
    Extension,
    /// `describe()` and `preflight()` attach the backend's own metadata to the `KeyInfo`
    /// (`KeyInfo::backend_info`), of the type [`Fixture::backend_info_type`] names.
    BackendInfo,
    /// Key-wrapping keys publish their public key (`KeyWrapKey::supports_public_keys`), so data
    /// keys can be wrapped offline (RSA-OAEP-SHA-256) and unwrapped by the backend.
    KeyWrapPublicKeys,
    /// AEAD keys can be rotated: the primary version of the same URI moves
    /// ([`Fixture::rotate`]).
    Rotate,
    /// Native key-wrapping keys ([`TestKeyKind::KeyWrap`]) can be rotated
    /// ([`Fixture::rotate`]). Not applicable where those keys never rotate (AWS RSA keys).
    RotateKeyWrap,
    /// HMAC keys can be rotated ([`Fixture::rotate`]).
    RotateMac,
    /// Signing keys can be rotated ([`Fixture::rotate`]).
    RotateSigning,
    /// Keys can be disabled (or soft-deleted) as a whole ([`Fixture::disable`]).
    Disable,
    /// One version of a key can be disabled ([`Fixture::disable_version`]): operations that
    /// choose it (the primary version a handle writes with) fail with `KeyStateInvalid`, inputs
    /// naming it with `KeyVersionUnusable`.
    DisableVersion,
    /// `preflight()` refuses a disabled key ([`Feature::Disable`]), and a key whose write version
    /// (the version its URI pins, or the primary version) is disabled
    /// ([`Feature::DisableVersion`]), with `KeyStateInvalid` labelled `Operation::Describe`, also
    /// where state is per version only; and `describe()` reads a disabled key's state, so a
    /// key-wrapping handle refuses to wrap to a disabled key once described. Gates
    /// `describe::preflight_disabled`, `describe::preflight_disabled_version` and
    /// `keywrap::disabled_key`. Declare it [`not_applicable`](FixtureCaps::not_applicable) where
    /// the backend documents that it cannot tell (e.g. the service refuses to read a disabled
    /// key, or the backend's preflight does not read version state).
    PreflightState,
    /// `describe()` reads a key whose primary version is disabled ([`Feature::DisableVersion`])
    /// and lists that version with its state; a service that answers the read with 404 cannot.
    /// Gates `describe::generic_preflight_disabled_primary`: core's generic `preflight()` (a
    /// handle with a describe part and no backend `Preflight` part) refuses such a key with
    /// `KeyStateInvalid`.
    DescribeVersionState,
    /// A minimum decryption version can be set.
    MinDecryptionVersion,
    /// The fixture can throttle a key.
    Throttle,
    /// The backend rejects oversize plaintexts (see [`FixtureCaps::oversize_plaintext`]).
    OversizePlaintext,
    /// The fixture can produce native ciphertexts without anykms (migration check).
    NativeCiphertext,
    /// The fixture provides a provider with credentials that are denied.
    UnauthorizedProvider,
    /// The backend supports keys for this signature algorithm.
    Signing(SignatureAlgorithm),
    /// The backend can rewrap ciphertexts that were encrypted with AAD. A behavior declaration,
    /// not a gate: `Yes` expects success, anything else expects `Unsupported`.
    RewrapWithAad,
    /// The fixture can count the backend requests of a dedicated provider
    /// ([`Fixture::counting`]), so cases can assert that local validation happens before any I/O.
    RequestCount,
    /// AEAD keys encrypt an empty plaintext (AWS `Encrypt` rejects it).
    EmptyPlaintext,
    /// MAC keys and message signers accept an empty message (AWS `GenerateMac` and `Sign`
    /// reject it).
    EmptyMessage,
    /// MAC input is limited. The limit is the MAC handle's
    /// [`KeySemantics::max_mac_input`]: a handle that declares semantics without one fails the
    /// `input_limit` cases, and `capabilities::semantics_match_caps` checks the declaration
    /// against the handle.
    MacInputLimit,
    /// The message of a message signer is limited: the limit is the signer's
    /// [`KeySemantics::max_signed_message`] (see [`Feature::MacInputLimit`]).
    MessageInputLimit,
    /// `decrypt_with_info` reports whether the primary version decrypted
    /// (`Decrypted::used_primary`). A behavior declaration consulted by `aead::decrypt_with_info`
    /// (anything but `Yes` accepts `None`) and a gate for `aead::used_primary_after_rotation`.
    /// `capabilities::semantics_match_caps` checks it against the AEAD handle's
    /// [`KeySemantics::reports_used_primary`].
    UsedPrimary,
    /// The error kinds the backend derives from server error messages can be checked: the
    /// messages come from the real service. Declare it [`not_applicable`] (see
    /// [`FixtureCaps::with_emulated_errors`]) against an emulator whose error texts differ, so
    /// the cases that depend on them (key and version state: `*::disabled_key`,
    /// `*::disabled_version`, `*::disabled_primary_version`, `*::min_decryption_version`) are
    /// ignored there.
    ///
    /// [`not_applicable`]: FixtureCaps::not_applicable
    ServerErrorMessages,
}

/// How available a feature is.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Support {
    /// Available: the case runs.
    Yes,
    /// The backend lacks this by design (documented); the case is ignored as `n/a`.
    NotApplicable(String),
    /// The fixture cannot provide it in this environment; the case is ignored as `skip`.
    FixtureLacks(String),
    /// The fixture did not declare the feature: a case that requires it fails.
    Undeclared,
}

/// Capabilities a fixture reports once, at the start of a run.
///
/// # Semantics
///
/// Where backends legitimately differ, cases read the [`KeySemantics`] of the handle they opened
/// (`Semantics::semantics`); a handle that declares none fails the case. The features stay: the
/// harness gates cases before any handle exists, so [`Feature::UsedPrimary`],
/// [`Feature::MacInputLimit`] and [`Feature::MessageInputLimit`] remain declarations, which
/// `capabilities::semantics_match_caps` checks against the handles (the limits' values come from
/// the handles).
#[derive(Clone, Debug)]
pub struct FixtureCaps {
    features: HashMap<Feature, Support>,
    /// A plaintext size the backend must reject with `InvalidArgument`.
    pub oversize_plaintext: Option<usize>,
    /// Throttled errors carry `retry_after` (e.g. rate-limit response headers are enabled).
    pub throttle_retry_after: bool,
    /// How long a state change ([`Fixture::rotate`], [`Fixture::disable`], ...) may take to
    /// reach every data-plane operation after the fixture method returned. Cases retry their
    /// expectations for up to this long. Default zero: the change is visible at once.
    pub settle_time: Duration,
}

impl Default for FixtureCaps {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureCaps {
    /// No features declared (a case requiring any feature fails until it is declared).
    pub fn new() -> Self {
        Self {
            features: HashMap::new(),
            oversize_plaintext: None,
            throttle_retry_after: false,
            settle_time: Duration::ZERO,
        }
    }

    /// Declares a feature available.
    pub fn supports(mut self, f: Feature) -> Self {
        self.features.insert(f, Support::Yes);
        self
    }

    /// Declares a feature absent by design.
    pub fn not_applicable(mut self, f: Feature, reason: impl Into<String>) -> Self {
        self.features
            .insert(f, Support::NotApplicable(reason.into()));
        self
    }

    /// Declares every feature in `features` absent by design, for one reason.
    pub fn not_applicable_all(mut self, features: &[Feature], reason: &str) -> Self {
        for &f in features {
            self = self.not_applicable(f, reason);
        }
        self
    }

    /// Declares a feature the fixture cannot provide here.
    pub fn lacks(mut self, f: Feature, reason: impl Into<String>) -> Self {
        self.features
            .insert(f, Support::FixtureLacks(reason.into()));
        self
    }

    /// Declares that throttled errors carry `retry_after`.
    pub fn with_throttle_retry_after(mut self, v: bool) -> Self {
        self.throttle_retry_after = v;
        self
    }

    /// Whether `decrypt_with_info` reports `used_primary` ([`Feature::UsedPrimary`]).
    pub fn reports_used_primary(&self) -> bool {
        self.has(Feature::UsedPrimary)
    }

    /// Declares that error messages come from an emulator ([`Feature::ServerErrorMessages`] not
    /// applicable), with the emulator's name.
    pub fn with_emulated_errors(self, emulator: &str) -> Self {
        self.not_applicable(
            Feature::ServerErrorMessages,
            format!("error messages come from an emulator ({emulator})"),
        )
    }

    /// Sets how long state changes may take to propagate (see [`settle_time`](Self::settle_time)).
    pub fn with_settle_time(mut self, t: Duration) -> Self {
        self.settle_time = t;
        self
    }

    /// Sets the oversize plaintext length (and declares `OversizePlaintext`).
    pub fn with_oversize_plaintext(mut self, len: usize) -> Self {
        self.oversize_plaintext = Some(len);
        self.supports(Feature::OversizePlaintext)
    }

    /// Declares every feature in `features` available.
    pub fn supports_all(mut self, features: &[Feature]) -> Self {
        for &f in features {
            self = self.supports(f);
        }
        self
    }

    /// Support for a feature ([`Support::Undeclared`] when the fixture did not declare it).
    pub fn support(&self, f: Feature) -> Support {
        self.features
            .get(&f)
            .cloned()
            .unwrap_or(Support::Undeclared)
    }

    /// Whether a feature is available.
    pub fn has(&self, f: Feature) -> bool {
        self.support(f) == Support::Yes
    }
}

/// The kind of key a case needs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TestKeyKind {
    /// A symmetric AEAD key.
    Aead,
    /// An HMAC key the case uses with the given algorithm. Where a backend binds the algorithm
    /// to the key, the fixture creates a key for it; elsewhere one kind of key serves every
    /// algorithm and the fixture may ignore it.
    Hmac(MacAlgorithm),
    /// An asymmetric key for the given signature algorithm.
    Signing(SignatureAlgorithm),
    /// A native key-wrapping key ([`Feature::KeyWrap`]): RSA-OAEP or AES key wrap, opened with
    /// `Provider::key_wrap`. The fixture chooses the key type.
    KeyWrap,
}

/// Whether a case may share a key with other cases.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyUse {
    /// The case only uses the key: the fixture may return a pooled, long-lived key (e.g.
    /// provisioned for CI), the same one to several cases.
    Shared,
    /// The case changes the key (rotates, disables, throttles it, sets a minimum version) or
    /// relies on a fresh key's state: the fixture must create a new key.
    Fresh,
}

/// A key a fixture created or picked for a case.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct TestKey {
    /// The key's URI. Cases use it as is: they never add or strip a version.
    pub uri: KeyUri,
    /// Backend-specific key name.
    pub name: String,
    /// Its kind.
    pub kind: TestKeyKind,
    /// The version the URI pins, if it names one (e.g. GCP signing and MAC keys): handles opened
    /// from it keep using that version after a rotation.
    pub version: Option<KeyVersion>,
}

impl TestKey {
    /// A key whose URI names no version.
    pub fn new(uri: KeyUri, name: impl Into<String>, kind: TestKeyKind) -> Self {
        Self {
            uri,
            name: name.into(),
            kind,
            version: None,
        }
    }

    /// Records the version the URI pins.
    pub fn with_version(mut self, version: KeyVersion) -> Self {
        self.version = Some(version);
        self
    }
}

/// The parts of a digest-signing (ECDSA, RSA) key, bridged into the dyn layer: build them with
/// [`bridge`](Self::bridge) and the `with_*` methods (see [`TypedHandles`]).
#[derive(Clone)]
pub struct DigestKeyHandles {
    pub(crate) signer: Arc<dyn DynDigestSigner>,
    pub(crate) verifier: Arc<dyn DynDigestVerifier>,
    pub(crate) public_keys: Arc<dyn DynPublicKeys>,
    /// `None`: the key is not described.
    pub(crate) describe: Option<Arc<dyn DynDescribe>>,
    /// `None`: undeclared.
    pub(crate) semantics: Option<KeySemantics>,
    /// `None`: the handles run core's generic preflight (describe and check).
    pub(crate) preflight: Option<Arc<dyn DynPreflight>>,
}

impl fmt::Debug for DigestKeyHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestKeyHandles").finish_non_exhaustive()
    }
}

impl DigestKeyHandles {
    /// Bridges one typed handle. It is shared as an `Arc<K>` (the `impl X for Arc<T>` bridge) and
    /// erased into each `dyn DynX` (the blanket impl); cases call the static method names on the
    /// result (the `impl X for dyn DynX` bridge), which reach the typed handle's own trait impls.
    pub fn bridge<K>(key: Arc<K>) -> Self
    where
        K: DigestSigner + DigestVerifier + PublicKeys + Describe + 'static,
    {
        Self {
            describe: Some(Arc::new(key.clone())),
            ..Self::bridge_without_describe(key)
        }
    }

    /// Like [`bridge`](Self::bridge), for a key that is not described.
    pub fn bridge_without_describe<K>(key: Arc<K>) -> Self
    where
        K: DigestSigner + DigestVerifier + PublicKeys + 'static,
    {
        Self {
            signer: Arc::new(key.clone()),
            verifier: Arc::new(key.clone()),
            public_keys: Arc::new(key),
            describe: None,
            semantics: None,
            preflight: None,
        }
    }

    /// Records the typed handle's semantics (`key.semantics().clone()`), which the suite
    /// carries onto the handles it assembles; a typed path without them is undeclared.
    pub fn with_semantics(mut self, semantics: KeySemantics) -> Self {
        self.semantics = Some(semantics);
        self
    }

    /// Records the typed handle's own [`Preflight`] check (the typed handle shared as an `Arc`),
    /// which the suite carries onto the handles it assembles, so that their `preflight()` runs
    /// the backend's check rather than core's generic one.
    pub fn with_preflight(mut self, preflight: impl Preflight + 'static) -> Self {
        self.preflight = Some(Arc::new(preflight));
        self
    }
}

/// The parts of a message-signing (Ed25519) key, bridged into the dyn layer (see
/// [`DigestKeyHandles`]).
#[derive(Clone)]
pub struct MessageKeyHandles {
    pub(crate) signer: Arc<dyn DynMessageSigner>,
    pub(crate) verifier: Arc<dyn DynMessageVerifier>,
    pub(crate) public_keys: Arc<dyn DynPublicKeys>,
    pub(crate) describe: Option<Arc<dyn DynDescribe>>,
    pub(crate) semantics: Option<KeySemantics>,
    pub(crate) preflight: Option<Arc<dyn DynPreflight>>,
}

impl fmt::Debug for MessageKeyHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageKeyHandles").finish_non_exhaustive()
    }
}

impl MessageKeyHandles {
    /// Bridges one typed handle (see [`DigestKeyHandles::bridge`]).
    pub fn bridge<K>(key: Arc<K>) -> Self
    where
        K: MessageSigner + MessageVerifier + PublicKeys + Describe + 'static,
    {
        Self {
            describe: Some(Arc::new(key.clone())),
            ..Self::bridge_without_describe(key)
        }
    }

    /// Like [`bridge`](Self::bridge), for a key that is not described.
    pub fn bridge_without_describe<K>(key: Arc<K>) -> Self
    where
        K: MessageSigner + MessageVerifier + PublicKeys + 'static,
    {
        Self {
            signer: Arc::new(key.clone()),
            verifier: Arc::new(key.clone()),
            public_keys: Arc::new(key),
            describe: None,
            semantics: None,
            preflight: None,
        }
    }

    /// Records the typed handle's semantics (see [`DigestKeyHandles::with_semantics`]).
    pub fn with_semantics(mut self, semantics: KeySemantics) -> Self {
        self.semantics = Some(semantics);
        self
    }

    /// Records the typed handle's own [`Preflight`] check (see
    /// [`DigestKeyHandles::with_preflight`]).
    pub fn with_preflight(mut self, preflight: impl Preflight + 'static) -> Self {
        self.preflight = Some(Arc::new(preflight));
        self
    }
}

/// The parts of an HMAC key, bridged into the dyn layer (see [`DigestKeyHandles`]).
#[derive(Clone)]
pub struct MacKeyHandles {
    pub(crate) mac: Arc<dyn DynMac>,
    pub(crate) describe: Option<Arc<dyn DynDescribe>>,
    pub(crate) semantics: Option<KeySemantics>,
    pub(crate) preflight: Option<Arc<dyn DynPreflight>>,
}

impl fmt::Debug for MacKeyHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacKeyHandles").finish_non_exhaustive()
    }
}

impl MacKeyHandles {
    /// Bridges one typed handle (see [`DigestKeyHandles::bridge`]).
    pub fn bridge<K>(key: Arc<K>) -> Self
    where
        K: Mac + Describe + 'static,
    {
        Self {
            describe: Some(Arc::new(key.clone())),
            ..Self::bridge_without_describe(key)
        }
    }

    /// Like [`bridge`](Self::bridge), for a key that is not described.
    pub fn bridge_without_describe<K>(key: Arc<K>) -> Self
    where
        K: Mac + 'static,
    {
        Self {
            mac: Arc::new(key),
            describe: None,
            semantics: None,
            preflight: None,
        }
    }

    /// Records the typed handle's semantics (see [`DigestKeyHandles::with_semantics`]).
    pub fn with_semantics(mut self, semantics: KeySemantics) -> Self {
        self.semantics = Some(semantics);
        self
    }

    /// Records the typed handle's own [`Preflight`] check (see
    /// [`DigestKeyHandles::with_preflight`]).
    pub fn with_preflight(mut self, preflight: impl Preflight + 'static) -> Self {
        self.preflight = Some(Arc::new(preflight));
        self
    }
}

/// The backend name of the composite handles the typed path assembles from bridged parts.
pub(crate) const TYPED: &str = "typed";

/// The parts of an AEAD key, bridged into the dyn layer. [`bridge`](Self::bridge) takes the
/// `Aead` and `describe` parts; add exactly the other parts the typed handle implements, so a
/// part added to `AeadKey` later never forces a stub:
///
/// ```ignore
/// let k = Arc::new(provider.aead_key(uri)?);
/// let s = k.semantics().clone();
/// AeadKeyHandles::bridge(k.clone())
///     .with_rewrap(k.clone())
///     .with_data_keys(k.clone())
///     .with_semantics(s)
///     .with_preflight(k)
/// ```
///
/// The typed handle is also the concrete key of the handle the suite assembles.
#[derive(Clone)]
pub struct AeadKeyHandles {
    key: AeadKey,
}

impl fmt::Debug for AeadKeyHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadKeyHandles").field(&self.key).finish()
    }
}

impl AeadKeyHandles {
    /// Bridges one typed handle (see [`DigestKeyHandles::bridge`]): its `Aead` and `describe`
    /// parts.
    pub fn bridge<K>(key: Arc<K>) -> Self
    where
        K: Aead + Describe + 'static,
    {
        let describe = Arc::new(key.clone());
        let h = Self::bridge_without_describe(key);
        Self {
            key: h.key.with_describe(describe),
        }
    }

    /// Like [`bridge`](Self::bridge), for a key that is not described.
    pub fn bridge_without_describe<K>(key: Arc<K>) -> Self
    where
        K: Aead + 'static,
    {
        Self {
            key: AeadKey::new(TYPED, Arc::new(key.clone())).with_concrete(key),
        }
    }

    /// Adds the `rewrap` part (the typed handle shared as an `Arc`).
    pub fn with_rewrap(mut self, rewrap: impl Rewrap + 'static) -> Self {
        self.key = self.key.with_rewrap(Arc::new(rewrap));
        self
    }

    /// Adds the `data_keys` part (the typed handle shared as an `Arc`, or a recipe over it).
    pub fn with_data_keys(mut self, data_keys: impl DataKeys + 'static) -> Self {
        self.key = self.key.with_data_keys(Arc::new(data_keys));
        self
    }

    /// Adds the `wrapped_data_keys` part (the typed handle shared as an `Arc`).
    pub fn with_wrapped_data_keys(
        mut self,
        wrapped_data_keys: impl WrappedDataKeys + 'static,
    ) -> Self {
        self.key = self.key.with_wrapped_data_keys(Arc::new(wrapped_data_keys));
        self
    }

    /// Records the typed handle's semantics (see [`DigestKeyHandles::with_semantics`]).
    pub fn with_semantics(mut self, semantics: KeySemantics) -> Self {
        self.key = self.key.with_semantics(semantics);
        self
    }

    /// Adds the typed handle's own [`Preflight`] check (see
    /// [`DigestKeyHandles::with_preflight`]).
    pub fn with_preflight(mut self, preflight: impl Preflight + 'static) -> Self {
        self.key = self.key.with_preflight(Arc::new(preflight));
        self
    }

    /// The handle the suite assembles.
    pub(crate) fn into_key(self) -> AeadKey {
        self.key
    }
}

/// The parts of a native key-wrapping key, bridged into the dyn layer (see
/// [`AeadKeyHandles`]): `bridge` takes the `KeyWrap` and `describe` parts, and `with_rewrap`,
/// `with_public_keys`, `with_semantics` and `with_preflight` add the others.
#[derive(Clone)]
pub struct KeyWrapKeyHandles {
    key: KeyWrapKey,
}

impl fmt::Debug for KeyWrapKeyHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyWrapKeyHandles").field(&self.key).finish()
    }
}

impl KeyWrapKeyHandles {
    /// Bridges one typed handle (see [`DigestKeyHandles::bridge`]): its `KeyWrap` and `describe`
    /// parts.
    pub fn bridge<K>(key: Arc<K>) -> Self
    where
        K: KeyWrap + Describe + 'static,
    {
        let describe = Arc::new(key.clone());
        let h = Self::bridge_without_describe(key);
        Self {
            key: h.key.with_describe(describe),
        }
    }

    /// Like [`bridge`](Self::bridge), for a key that is not described.
    pub fn bridge_without_describe<K>(key: Arc<K>) -> Self
    where
        K: KeyWrap + 'static,
    {
        Self {
            key: KeyWrapKey::new(TYPED, Arc::new(key.clone())).with_concrete(key),
        }
    }

    /// An AEAD key's parts as a key-wrapping key's, wrapping with empty AAD
    /// ([`KeyWrapKey::from_aead`]); the default of [`TypedHandles::key_wrap`].
    pub fn from_aead(aead: AeadKeyHandles) -> Self {
        Self {
            key: KeyWrapKey::from_aead(aead.key),
        }
    }

    /// Adds the `rewrap` part (server-side rewrap of wrapped keys).
    pub fn with_rewrap(mut self, rewrap: impl Rewrap + 'static) -> Self {
        self.key = self.key.with_rewrap(Arc::new(rewrap));
        self
    }

    /// Adds the `public_keys` part (RSA key-wrapping keys).
    pub fn with_public_keys(mut self, public_keys: impl PublicKeys + 'static) -> Self {
        self.key = self.key.with_public_keys(Arc::new(public_keys));
        self
    }

    /// Records the typed handle's semantics (see [`DigestKeyHandles::with_semantics`]).
    pub fn with_semantics(mut self, semantics: KeySemantics) -> Self {
        self.key = self.key.with_semantics(semantics);
        self
    }

    /// Adds the typed handle's own [`Preflight`] check (see
    /// [`DigestKeyHandles::with_preflight`]).
    pub fn with_preflight(mut self, preflight: impl Preflight + 'static) -> Self {
        self.key = self.key.with_preflight(Arc::new(preflight));
        self
    }

    /// The handle the suite assembles.
    pub(crate) fn into_key(self) -> KeyWrapKey {
        self.key
    }
}

/// The backend's typed (static) API, used by the `typed::` cases instead of the [`Provider`].
///
/// Implementations open each key with the backend's own typed constructors (for example
/// `TransitProvider::aead_key`) and bridge the typed handle, shared as an `Arc`, into the
/// handles of its key family: `*KeyHandles::bridge(k.clone())`, then the `with_*` methods for
/// the other parts it implements, its [`KeySemantics`] (`with_semantics`) and, where it
/// implements [`Preflight`], its own check (`with_preflight`):
///
/// ```ignore
/// let k = Arc::new(provider.digest_signing_key(uri, alg)?);
/// let s = k.semantics().clone();
/// Ok(DigestKeyHandles::bridge(k.clone()).with_semantics(s).with_preflight(k))
/// ```
///
/// The shared case bodies then exercise the typed handles and the static→dyn bridges, not the
/// backend's `Provider` implementation.
///
/// Every method defaults to `Unsupported`: implement those of the key families the fixture
/// declares ([`Feature::Aead`], [`Feature::Mac`], [`Feature::Signing`], [`Feature::KeyWrap`]).
/// Cases call a method only when its family is declared supported.
pub trait TypedHandles: Send + Sync {
    /// An AEAD key ([`Feature::Aead`]).
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        let _ = uri;
        Err(not_declared("aead"))
    }

    /// A key-wrapping key. Defaults to the [`aead`](Self::aead) key wrapping with empty AAD
    /// ([`KeyWrapKeyHandles::from_aead`]); override it for keys with a native wrap operation
    /// ([`Feature::KeyWrap`]).
    fn key_wrap(&self, uri: &KeyUri) -> Result<KeyWrapKeyHandles> {
        self.aead(uri).map(KeyWrapKeyHandles::from_aead)
    }

    /// A data-key source ([`Feature::DataKeys`]). Defaults to the [`aead`](Self::aead) key,
    /// when it has the data-keys part; override it where data keys come from elsewhere (e.g. a
    /// key-wrapping key and the `KeyWrapDataKeys` recipe).
    fn data_keys(&self, uri: &KeyUri) -> Result<DataKeysKey> {
        let k = self.aead(uri)?.into_key();
        if !k.supports_data_keys() {
            return Err(not_declared("data_keys"));
        }
        let mut h = DataKeysKey::new(TYPED, Arc::new(k.clone()));
        if let Some(s) = k.semantics() {
            h = h.with_semantics(s.clone());
        }
        Ok(if k.supports_describe() {
            h.with_describe(Arc::new(k))
        } else {
            h
        })
    }

    /// A digest-signing key used with `alg` ([`Feature::Signing`]). Return the typed
    /// constructor's error for a message-signing `alg`.
    fn digest_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<DigestKeyHandles> {
        let _ = (uri, alg);
        Err(not_declared("digest_key"))
    }

    /// A message-signing (Ed25519) key ([`Feature::Signing`]).
    fn message_key(&self, uri: &KeyUri) -> Result<MessageKeyHandles> {
        let _ = uri;
        Err(not_declared("message_key"))
    }

    /// An HMAC key used with `alg` ([`Feature::Mac`]).
    fn mac_key(&self, uri: &KeyUri, alg: MacAlgorithm) -> Result<MacKeyHandles> {
        let _ = (uri, alg);
        Err(not_declared("mac_key"))
    }
}

/// A dedicated provider whose backend requests are counted (see [`Fixture::counting`]). Build it
/// with [`Counting::new`].
#[non_exhaustive]
#[derive(Clone)]
pub struct Counting {
    /// The provider. Nothing else uses it, so the count is exact.
    pub provider: Arc<dyn Provider>,
    /// Typed handles over the same counted connection.
    pub typed: Arc<dyn TypedHandles>,
    /// The number of requests sent so far.
    pub requests: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl Counting {
    /// A counted provider, typed handles over the same counted connection, and the request
    /// count so far.
    pub fn new(
        provider: Arc<dyn Provider>,
        typed: Arc<dyn TypedHandles>,
        requests: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            provider,
            typed,
            requests,
        }
    }
}

impl fmt::Debug for Counting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Counting")
            .field("requests", &(self.requests)())
            .finish_non_exhaustive()
    }
}

/// A backend under test.
///
/// Key management lives here, outside the public anykms API: fixtures use admin credentials to
/// create, rotate and disable keys.
///
/// Only [`name`](Fixture::name), [`probe`](Fixture::probe), [`create_key`](Fixture::create_key),
/// [`missing_key_uri`](Fixture::missing_key_uri), [`provider`](Fixture::provider) and
/// [`typed`](Fixture::typed) are required. The other methods default to "not available" (an
/// `Unsupported` error, `None` or nothing). Every case that calls one is gated on a [`Feature`],
/// so override a method exactly when [`probe`](Fixture::probe) declares its feature
/// [`Support::Yes`], and declare the rest [`not_applicable`](FixtureCaps::not_applicable) (absent
/// by design, such as throttling or a minimum decryption version on a cloud KMS) or
/// [`lacks`](FixtureCaps::lacks) (unavailable in this environment). A case requiring a feature
/// the fixture left undeclared fails.
///
/// State changes ([`rotate`](Fixture::rotate), [`disable`](Fixture::disable),
/// [`disable_version`](Fixture::disable_version), ...) return once the data plane shows them, as
/// far as the fixture can tell (e.g. by polling until an operation is refused); cases then allow
/// the bounded extra time of [`FixtureCaps::with_settle_time`] for propagation.
#[trait_variant::make(Send)]
pub trait Fixture: Send + Sync + 'static {
    /// A short name for reports.
    fn name(&self) -> &str;

    /// Reports capabilities. Called once per run.
    async fn probe(&self) -> FixtureCaps;

    /// A key of `kind` for one case. With [`KeyUse::Fresh`] it must be a new key; with
    /// [`KeyUse::Shared`] it may be a pooled key that other cases use too.
    async fn create_key(&self, kind: TestKeyKind, key_use: KeyUse) -> Result<TestKey>;

    // The optional methods below are written as `fn -> impl Future` because `trait_variant` does
    // not accept default bodies on `async fn`; implement them with plain `async fn`.

    /// Rotates a fresh key ([`Feature::Rotate`] for AEAD keys, [`Feature::RotateKeyWrap`],
    /// [`Feature::RotateMac`], [`Feature::RotateSigning`]) and returns the key to use for the new
    /// version: `key` itself when its URI follows the primary version, or the new version's URI
    /// ([`TestKey::with_version`]) when the URI pins a version (the old URI keeps using the old
    /// version).
    fn rotate(&self, key: &TestKey) -> impl Future<Output = Result<TestKey>> + Send {
        let _ = key;
        ready(Err(not_implemented("rotate")))
    }

    /// Disables (or soft-deletes) a fresh key as a whole ([`Feature::Disable`]): every
    /// operation then fails with `KeyStateInvalid`.
    fn disable(&self, key: &TestKey) -> impl Future<Output = Result<()>> + Send {
        let _ = key;
        ready(Err(not_implemented("disable")))
    }

    /// Disables one version of a fresh key ([`Feature::DisableVersion`]): operations on that
    /// version then fail (`KeyStateInvalid` where the handle chose it, `KeyVersionUnusable` where
    /// the input names it), and the key's other versions keep working.
    fn disable_version(
        &self,
        key: &TestKey,
        version: &KeyVersion,
    ) -> impl Future<Output = Result<()>> + Send {
        let _ = (key, version);
        ready(Err(not_implemented("disable_version")))
    }

    /// Makes versions older than `version` undecryptable ([`Feature::MinDecryptionVersion`]).
    fn set_min_decryption_version(
        &self,
        key: &TestKey,
        version: &KeyVersion,
    ) -> impl Future<Output = Result<()>> + Send {
        let _ = (key, version);
        ready(Err(not_implemented("set_min_decryption_version")))
    }

    /// Makes data-plane calls on `key` fail with throttling until [`Fixture::unthrottle`]
    /// ([`Feature::Throttle`]).
    fn throttle(&self, key: &TestKey) -> impl Future<Output = Result<()>> + Send {
        let _ = key;
        ready(Err(not_implemented("throttle")))
    }

    /// Removes throttling. The default does nothing.
    fn unthrottle(&self, key: &TestKey) -> impl Future<Output = Result<()>> + Send {
        let _ = key;
        ready(Ok(()))
    }

    /// Encrypts `plaintext` without anykms and without AAD, the way an existing (non-anykms)
    /// client would ([`Feature::NativeCiphertext`]). Returns `None` (the default) when
    /// unsupported.
    fn encrypt_natively(
        &self,
        key: &TestKey,
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Option<Ciphertext>>> + Send {
        let _ = (key, plaintext);
        ready(Ok(None))
    }

    /// Performs one backend extension call through `key` ([`Feature::Extension`]): an operation
    /// of the backend's own extension trait on [`AeadKey`], which runs through
    /// `AeadKey::call_extension` and so through the handle's layers. The suite layers `key` and
    /// checks that every layer sees the call.
    fn extension_call(&self, key: &AeadKey) -> impl Future<Output = Result<()>> + Send {
        let _ = key;
        ready(Err(not_implemented("extension_call")))
    }

    /// The type of the backend metadata that `describe()` attaches to `KeyInfo`
    /// ([`Feature::BackendInfo`]), e.g. `TypeId::of::<AwsKeyInfo>()`. `None` (the default) for
    /// a backend that attaches none.
    fn backend_info_type(&self) -> Option<std::any::TypeId> {
        None
    }

    /// A key version that is malformed for this backend, so verifying a signature or tag
    /// labeled with it fails with `InvalidArgument` before any request. Defaults to `"abc"`,
    /// which no built-in or planned backend accepts (numbers, ARNs, 32-hex strings); return
    /// `None` if every string is a well-formed version here.
    fn malformed_version(&self) -> Option<KeyVersion> {
        Some(KeyVersion::new("abc"))
    }

    /// A URI naming a key of `kind` that does not exist, in the form a URI of that kind takes
    /// (e.g. with a version where the backend opens such keys only with one).
    fn missing_key_uri(&self, kind: TestKeyKind) -> KeyUri;

    /// The provider under test (data-plane credentials).
    fn provider(&self) -> Arc<dyn Provider>;

    /// The backend's typed API, over the same backend and credentials as
    /// [`provider`](Fixture::provider), for the `typed::` cases.
    fn typed(&self) -> Arc<dyn TypedHandles>;

    /// A fresh provider whose requests are counted, when the backend sends requests (declare
    /// [`Feature::RequestCount`]). Every call returns a new, unshared counter. Default `None`.
    fn counting(&self) -> Option<Counting> {
        None
    }

    /// Secrets the fixture holds (such as tokens) that must never appear in error output.
    /// Default: none.
    fn secret_markers(&self) -> Vec<String> {
        Vec::new()
    }

    /// A provider whose credentials are denied, if the fixture can build one
    /// ([`Feature::UnauthorizedProvider`]). Default `None`.
    fn unauthorized_provider(&self) -> Option<Arc<dyn Provider>> {
        None
    }
}

/// The error of a [`Fixture`] method the fixture does not implement. Cases calling such a method
/// are gated on a feature, so this surfaces only when a fixture declares a feature `Yes` without
/// implementing it.
fn not_implemented(method: &'static str) -> Error {
    Error::new(
        ErrorKind::Unsupported,
        "conformance",
        Operation::Configure,
        format!(
            "the fixture does not implement {method}; declare the feature not applicable in probe()"
        ),
    )
}

/// The error of a [`TypedHandles`] method the fixture does not implement.
fn not_declared(method: &'static str) -> Error {
    Error::new(
        ErrorKind::Unsupported,
        TYPED,
        Operation::Open,
        format!(
            "TypedHandles::{method} is not implemented; declare its key family not applicable in probe()"
        ),
    )
}
