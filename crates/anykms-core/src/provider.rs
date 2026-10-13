//! Config-driven key opening: the [`Provider`] trait and the [`Registry`].

use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::dynamic::*;
use crate::error::{Error, ErrorKind, Operation, Result};
use crate::types::{KeyVersion, MacAlgorithm, SignatureAlgorithm};
use crate::uri::{IntoKeyUri, KeyUri};

/// How a handle confirms that the key behind it has the type the caller asserted.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyTypeCheck {
    /// Describe the key once (cached) before the first operation and refuse mismatches.
    #[default]
    Describe,
    /// Trust the caller's assertion. Use only where the credentials cannot read key metadata; a
    /// mismatched key may then silently produce mislabeled signatures or non-AEAD ciphertext.
    TrustCaller,
}

/// Options for opening a key through a [`Provider`].
///
/// Portable options are fields; backend-specific options travel as typed extensions
/// ([`with_extension`](Self::with_extension)), so they need no change here:
///
/// ```
/// use anykms_core::OpenOptions;
///
/// /// A backend's own option type (e.g. defined by an AWS backend crate).
/// #[derive(Debug, PartialEq)]
/// struct GrantTokens(Vec<String>);
///
/// let opts = OpenOptions::new().with_extension(GrantTokens(vec!["t".into()]));
/// // In the provider:
/// assert_eq!(opts.extension::<GrantTokens>(), Some(&GrantTokens(vec!["t".into()])));
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    /// The key-type check policy.
    pub key_type_check: KeyTypeCheck,
    extensions: Extensions,
}

/// Backend-specific open options, at most one value per type.
#[derive(Clone, Default)]
struct Extensions(Vec<(TypeId, Arc<dyn Extension>)>);

/// An extension value: `Any` for the downcast, `Debug` for `OpenOptions`'s `Debug`.
trait Extension: Any + Send + Sync + fmt::Debug {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any + Send + Sync + fmt::Debug> Extension for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(_, v)| v))
            .finish()
    }
}

impl OpenOptions {
    /// Default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the key-type check policy.
    pub fn with_key_type_check(mut self, check: KeyTypeCheck) -> Self {
        self.key_type_check = check;
        self
    }

    /// Attaches a backend-specific option, replacing an earlier value of the same type.
    ///
    /// Backends define their own option types and read them with
    /// [`extension`](Self::extension); other backends ignore them, so one `OpenOptions` can
    /// carry options for several backends. Values are shared (not cloned) when the options are
    /// cloned, and appear in `Debug` output: never put secrets in them.
    pub fn with_extension<T: Any + Send + Sync + fmt::Debug>(mut self, value: T) -> Self {
        let id = TypeId::of::<T>();
        self.extensions.0.retain(|(t, _)| *t != id);
        self.extensions.0.push((id, Arc::new(value)));
        self
    }

    /// The backend-specific option of type `T`, if one was attached.
    pub fn extension<T: Any>(&self) -> Option<&T> {
        let id = TypeId::of::<T>();
        self.extensions
            .0
            .iter()
            .find(|(t, _)| *t == id)
            .and_then(|(_, v)| (**v).as_any().downcast_ref())
    }
}

fn unsupported(backend: &'static str, op: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported, backend, Operation::Open, op)
}

/// The single list of [`Provider`] open methods. Every place that names them all (the trait's
/// defaults, `impl Provider for Arc<P>`, [`forward_provider!`]) is generated from it, so adding a
/// purpose updates every forwarder at once and none silently falls back to `Unsupported`.
///
/// Invokes `$cb! { $extra ; <entries> }`, each entry being
/// `#[doc] name(alg: Type)? -> Handle : "unsupported message";`.
#[doc(hidden)]
#[macro_export]
macro_rules! __provider_openers {
    ($($cb:ident)::+ ! { $($extra:tt)* }) => {
        $($cb)::+ ! { $($extra)* ;
            /// Opens a symmetric AEAD key.
            aead() -> $crate::AeadKey : "provider does not open AEAD keys";
            /// Opens a key-wrapping key (an envelope KEK).
            ///
            /// Keys with a native wrap operation fill the key-wrap part directly. A provider whose
            /// AEAD keys can serve as KEKs (wrapping with empty AAD) opens them with
            /// `self.aead(uri, opts).map(KeyWrapKey::from_aead)`; such keys report
            /// [`Capabilities::KEY_WRAP`](crate::Capabilities::KEY_WRAP).
            key_wrap() -> $crate::KeyWrapKey : "provider does not open key-wrapping keys";
            /// Opens a data-key source: a key that hands out data keys
            /// ([`DataKeys`](crate::DataKeys)) and nothing else.
            ///
            /// Backends with native data keys open their AEAD keys this way; a backend without
            /// them may back the handle with a recipe over a key-wrapping key. A provider's
            /// key-wrapping handles ([`key_wrap`](Self::key_wrap)) do not hand out data keys
            /// themselves: a KEK stays dedicated to wrapping.
            data_keys() -> $crate::DataKeysKey : "provider does not open data-key sources";
            /// Opens a digest signer.
            digest_signer(alg: $crate::SignatureAlgorithm) -> $crate::DigestSignerKey
                : "provider does not open digest signers";
            /// Opens a digest verifier.
            digest_verifier(alg: $crate::SignatureAlgorithm) -> $crate::DigestVerifierKey
                : "provider does not open digest verifiers";
            /// Opens a message signer.
            message_signer(alg: $crate::SignatureAlgorithm) -> $crate::MessageSignerKey
                : "provider does not open message signers";
            /// Opens a message verifier.
            message_verifier(alg: $crate::SignatureAlgorithm) -> $crate::MessageVerifierKey
                : "provider does not open message verifiers";
            /// Opens a MAC key.
            mac(alg: $crate::MacAlgorithm) -> $crate::MacKey : "provider does not open MAC keys";
            /// Opens a public-key source.
            public_keys(alg: $crate::SignatureAlgorithm) -> $crate::PublicKeysKey
                : "provider does not open public keys";
            /// Opens a describe handle.
            describe() -> $crate::DescribeKey : "provider does not describe keys";
        }
    };
}

/// Implements every open method of [`Provider`] inside an `impl Provider for ...` block, for
/// decorators and placeholders. The methods come from the same list as the trait's, so a purpose
/// added in a later release is forwarded too instead of silently falling back to the trait's
/// `Unsupported` default. [`pin`](Provider::pin) is covered too. Write `schemes` by hand.
///
/// Two forms:
///
/// - `forward_provider!(self => target)` forwards each method, and [`name`](Provider::name), to
///   `target`, an expression that borrows the inner provider (`&self.inner`, `&**self`).
/// - `forward_provider!(self, uri => body)` makes every open method and `pin` evaluate `body`,
///   which may use `self` and `uri` (the [`KeyUri`]) and must have type `Result<T>` for any `T`
///   (typically an `Err`). Write `name` by hand if the default does not fit.
///
/// ```
/// use anykms_core::{forward_provider, KeyUri, Provider, Result};
///
/// /// Counts opens, then delegates.
/// struct Counting<P> {
///     inner: P,
///     opens: std::sync::atomic::AtomicUsize,
/// }
///
/// impl<P: Provider> Counting<P> {
///     fn inner(&self) -> &P {
///         self.opens.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
///         &self.inner
///     }
/// }
///
/// impl<P: Provider> Provider for Counting<P> {
///     fn schemes(&self) -> &[&'static str] {
///         self.inner.schemes()
///     }
///     forward_provider!(self => self.inner());
/// }
///
/// /// Refuses every open with a fixed reason.
/// struct Disabled;
///
/// impl Disabled {
///     fn refuse<T>(&self, uri: &KeyUri) -> Result<T> {
///         Err(anykms_core::Error::unsupported(format!("{} is disabled", uri.scheme())))
///     }
/// }
///
/// impl Provider for Disabled {
///     fn schemes(&self) -> &[&'static str] {
///         &["off"]
///     }
///     forward_provider!(self, uri => self.refuse(uri));
/// }
/// ```
#[macro_export]
macro_rules! forward_provider {
    ($this:ident => $target:expr) => {
        fn name(&$this) -> &'static str {
            $crate::Provider::name($target)
        }
        fn pin(
            &$this,
            uri: &$crate::KeyUri,
            version: &$crate::KeyVersion,
        ) -> $crate::Result<$crate::KeyUri> {
            $crate::Provider::pin($target, uri, version)
        }
        $crate::__provider_openers! { $crate::__forward_provider_to! { $this => $target } }
    };
    ($this:ident, $uri:ident => $body:expr) => {
        fn pin(
            &$this,
            $uri: &$crate::KeyUri,
            version: &$crate::KeyVersion,
        ) -> $crate::Result<$crate::KeyUri> {
            let _ = version;
            $body
        }
        $crate::__provider_openers! { $crate::__forward_provider_with! { $this, $uri => $body } }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __forward_provider_to {
    ($this:ident => $target:expr ;
        $( $(#[$meta:meta])* $name:ident ( $($alg:ident : $A:ty)? ) -> $H:ty : $msg:literal ; )*
    ) => {
        $(
            fn $name(
                &$this,
                uri: &$crate::KeyUri,
                $($alg: $A,)?
                opts: &$crate::OpenOptions,
            ) -> $crate::Result<$H> {
                $crate::Provider::$name($target, uri, $($alg,)? opts)
            }
        )*
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __forward_provider_with {
    ($this:ident, $uri:ident => $body:expr ;
        $( $(#[$meta:meta])* $name:ident ( $($alg:ident : $A:ty)? ) -> $H:ty : $msg:literal ; )*
    ) => {
        $(
            fn $name(
                &$this,
                $uri: &$crate::KeyUri,
                $($alg: $A,)?
                opts: &$crate::OpenOptions,
            ) -> $crate::Result<$H> {
                let _ = ($($alg,)? opts);
                $body
            }
        )*
    };
}

// The trait, with an `Unsupported` default for every open method in `__provider_openers!`.
macro_rules! provider_trait {
    ( ;
        $( $(#[$meta:meta])* $name:ident ( $($alg:ident : $A:ty)? ) -> $H:ty : $msg:literal ; )*
    ) => {
        /// A backend that opens keys from URIs. Object-safe; third-party backends implement it too.
        ///
        /// Every method defaults to `Unsupported`, so adding a purpose later is not a breaking
        /// change. Decorators and placeholders implement the open methods with
        /// [`forward_provider!`](crate::forward_provider), which covers purposes added later too.
        ///
        /// Signers, verifiers and public-key sources take the [`SignatureAlgorithm`] and MAC keys
        /// the [`MacAlgorithm`] they will be used with: a parameter rather than an option, because
        /// opening them without one cannot succeed. Refuse an algorithm of the wrong shape (a
        /// digest-signing algorithm opened as a message signer, or the reverse) with `KeyMismatch`
        /// ([`SignatureAlgorithm::require_shape`]).
        ///
        /// Opening does no I/O. The open methods return opaque handles ([`AeadKey`],
        /// [`DigestSignerKey`], ...); fill in every optional part the backend supports (e.g. with
        /// `full`) and pass the backend's name, which appears in errors. Give each handle its
        /// [`KeySemantics`](crate::KeySemantics) (`with_semantics`) and its typed handle
        /// (`with_concrete`), so `downcast_ref` reaches it.
        ///
        /// A complete toy backend (a typed handle, this trait and a conformance fixture, about
        /// 250 lines) that passes `anykms-conformance` is its
        /// [`minimal_backend` example](https://github.com/sagikazarmark/anykms/blob/main/crates/anykms-conformance/examples/minimal_backend.rs).
        ///
        /// # Errors
        ///
        /// The contract for implementations, as the conformance suite checks it (case names in
        /// parentheses). The capability traits list the kinds specific to their operations
        /// under "Errors" ([`Aead`](crate::Aead#errors), [`Mac`](crate::Mac#errors), ...).
        ///
        /// Opening does no I/O, so the open methods fail only on what the URI, the algorithm and
        /// the provider's configuration show:
        ///
        /// - a URI the provider's grammar refuses (no key name, a path that climbs out of the key
        ///   namespace, an invalid component): [`Configuration`](crate::ErrorKind::Configuration)
        ///   with [`Operation::ParseUri`], naming the URI ([`Error::with_resource`]); never
        ///   `InvalidArgument`, because key URIs come from configuration
        ///   (`errors::parse_uri_is_configuration::*`);
        /// - a well-formed URI that the configuration refuses (an unknown server alias, an
        ///   account, project, vault or mount outside an allowlist): `Configuration` with
        ///   [`Operation::Open`];
        /// - a purpose or algorithm the URI already rules out (an algorithm of the wrong shape, a
        ///   versioned URI for a purpose that takes none):
        ///   [`KeyMismatch`](crate::ErrorKind::KeyMismatch);
        /// - a purpose the provider does not open: [`Unsupported`](crate::ErrorKind::Unsupported)
        ///   (the default methods).
        ///
        /// What needs the service shows on the handle's first operation (or its
        /// [`Preflight`](crate::Preflight), whose refusals are labelled `Operation::Describe`).
        /// Every operation's errors carry its [`Operation`] and name the key
        /// ([`Error::with_resource`]), never contain plaintext, AAD, key material or credentials
        /// (`hygiene::*`), and use these kinds:
        ///
        /// - the key (or mount) does not exist: [`NotFound`](crate::ErrorKind::NotFound), from
        ///   every operation, `describe` included (`errors::missing_key::*`);
        /// - the service rejects the credentials:
        ///   [`Unauthenticated`](crate::ErrorKind::Unauthenticated); its policy denies the
        ///   operation: [`PermissionDenied`](crate::ErrorKind::PermissionDenied)
        ///   (`errors::unauthorized::*`);
        /// - the key's type cannot do the operation or algorithm: `KeyMismatch`, checked before
        ///   use where the service would not refuse it (`sign::*::key_type_mismatch`,
        ///   `mac::*_as_*`, `describe::preflight`);
        /// - the key is disabled or pending deletion, or the version the handle chose itself (its
        ///   URI pin, or the primary version) is unusable:
        ///   [`KeyStateInvalid`](crate::ErrorKind::KeyStateInvalid); a version taken from the
        ///   input (the version of a ciphertext) that is disabled, destroyed or below the minimum
        ///   decryption version: [`KeyVersionUnusable`](crate::ErrorKind::KeyVersionUnusable)
        ///   (`*::disabled_key`, `*::disabled_version`, `*::min_decryption_version`);
        /// - malformed input, input over a declared limit, or an option the backend cannot honor
        ///   for this input: [`InvalidArgument`](crate::ErrorKind::InvalidArgument) or
        ///   `Unsupported`, before any request where it can be checked locally;
        /// - rate limiting: [`Throttled`](crate::ErrorKind::Throttled), with the server's
        ///   `Retry-After` ([`Error::with_retry_after`](crate::Error::with_retry_after))
        ///   (`errors::throttled`); a sealed, standby or unreachable service:
        ///   [`Unavailable`](crate::ErrorKind::Unavailable); a client-side timeout:
        ///   [`Timeout`](crate::ErrorKind::Timeout);
        /// - a server error no mapping recognizes, or a response that cannot be used:
        ///   [`Backend`](crate::ErrorKind::Backend).
        ///
        /// # Retries
        ///
        /// Handles must **not** retry internally: retrying is the caller's choice, made once with
        /// a [`RetryLayer`](crate::RetryLayer), so attempts do not multiply (6 retried attempts
        /// over a handle that itself tries 3 times would hit a struggling backend 18 times). The
        /// one exception is a single retry after refreshing expired credentials, which is part of
        /// authenticating rather than a retry of a failed operation. Surface `Retry-After` with
        /// [`Error::with_retry_after`](crate::Error::with_retry_after) instead of sleeping on it.
        pub trait Provider: Send + Sync {
            /// The URI schemes this provider owns.
            fn schemes(&self) -> &[&'static str];

            /// The backend name for errors from the default methods (e.g. `"transit"`). Defaults
            /// to the first scheme; override it to match the name the provider's handles use.
            fn name(&self) -> &'static str {
                self.schemes().first().copied().unwrap_or("provider")
            }

            /// For configuration: the URI naming exactly `version` of the key at `uri`.
            ///
            /// Built structurally (parse, set the version, serialize), keeping the query. No
            /// I/O: the version is not checked to exist, and the purpose is unknown (a GCP AEAD
            /// URI pinned here is refused by `aead()` with `KeyMismatch`). The same version as
            /// the URI's returns the URI unchanged; another version already in the URI is
            /// `Configuration`. A malformed version is `Configuration` with [`Operation::Open`]
            /// (never `ParseUri`): `pin` builds configuration, so a bad input is a config-class
            /// error, like a bad URI. `Unsupported` (the default) where versions are not
            /// addressable (transit, local, AWS).
            ///
            /// Never pin a token's `kid`: verify through the handle and let the signature carry
            /// the version. Pinning input would turn a disabled version into a config-class
            /// `KeyStateInvalid`.
            fn pin(&self, uri: &KeyUri, version: &KeyVersion) -> Result<KeyUri> {
                let _ = (uri, version);
                Err(unsupported(
                    self.name(),
                    "provider does not address key versions in URIs",
                ))
            }

            $(
                $(#[$meta])*
                fn $name(
                    &self,
                    uri: &KeyUri,
                    $($alg: $A,)?
                    opts: &OpenOptions,
                ) -> Result<$H> {
                    let _ = (uri, $($alg,)? opts);
                    Err(unsupported(self.name(), $msg))
                }
            )*
        }
    };
}

crate::__provider_openers! { provider_trait! {} }

impl<P: Provider + ?Sized> Provider for Arc<P> {
    fn schemes(&self) -> &[&'static str] {
        (**self).schemes()
    }
    crate::forward_provider!(self => &**self);
}

/// Routes key URIs to providers by scheme.
///
/// The open methods accept any [`IntoKeyUri`] (`&str`, `String`, `KeyUri`, `&KeyUri`) and come
/// in two forms: `aead(uri)` with default [`OpenOptions`], and `aead_with(uri, &opts)`. Signers,
/// verifiers and public-key sources take their [`SignatureAlgorithm`] and MAC keys their
/// [`MacAlgorithm`] as a parameter (`digest_signer(uri, alg)`, `mac_with(uri, alg, &opts)`).
/// Open errors carry the key URI (without its query string) as their
/// [`resource`](Error::resource).
///
/// Layers added with [`RegistryBuilder::layer`] wrap every handle the registry opens.
#[non_exhaustive]
#[derive(Clone)]
pub struct Registry {
    providers: BTreeMap<&'static str, Arc<dyn Provider>>,
    layers: Vec<Arc<dyn Layer>>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("schemes", &self.providers.keys().collect::<Vec<_>>())
            .field("layers", &self.layers.len())
            .finish()
    }
}

/// Builds a [`Registry`].
#[non_exhaustive]
#[derive(Default)]
pub struct RegistryBuilder {
    providers: Vec<Arc<dyn Provider>>,
    layers: Vec<Arc<dyn Layer>>,
}

impl fmt::Debug for RegistryBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryBuilder")
            .field("providers", &self.providers.len())
            .field("layers", &self.layers.len())
            .finish()
    }
}

impl RegistryBuilder {
    /// Adds a provider.
    pub fn provider(mut self, provider: impl Provider + 'static) -> Self {
        self.providers.push(Arc::new(provider));
        self
    }

    /// Adds a shared provider.
    pub fn provider_arc(mut self, provider: Arc<dyn Provider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Wraps every handle the registry opens with `layer` (see [`Layer`]), e.g. a
    /// [`RetryLayer`](crate::RetryLayer) so every key retries. Layers added later wrap earlier
    /// ones. A `RetryLayer` added here gives every handle of the registry one shared budget.
    pub fn layer(mut self, layer: impl Layer + 'static) -> Self {
        self.layers.push(Arc::new(layer));
        self
    }

    /// Builds the registry. Fails with `Configuration` when two providers claim the same scheme.
    pub fn build(self) -> Result<Registry> {
        let mut providers = BTreeMap::new();
        for p in self.providers {
            for scheme in p.schemes() {
                if providers.insert(*scheme, p.clone()).is_some() {
                    return Err(Error::new(
                        ErrorKind::Configuration,
                        "registry",
                        Operation::Configure,
                        format!("two providers claim the scheme {scheme:?}"),
                    ));
                }
            }
        }
        Ok(Registry {
            providers,
            layers: self.layers,
        })
    }
}

// The open methods of `Registry`: `$name(uri[, alg])` with default options and
// `$with(uri[, alg], &opts)`.
macro_rules! registry_open {
    ($( $(#[$meta:meta])* $name:ident / $with:ident ( $($alg:ident : $A:ty)? ) -> $H:ident; )*) => {
        $(
            $(#[$meta])*
            #[doc = ""]
            #[doc = concat!("Uses default [`OpenOptions`]; see [`", stringify!($with), "`](Self::", stringify!($with), ").")]
            pub fn $name(&self, uri: impl IntoKeyUri $(, $alg: $A)?) -> Result<$H> {
                self.$with(uri $(, $alg)?, &OpenOptions::new())
            }

            $(#[$meta])*
            #[doc = ""]
            #[doc = "With explicit options."]
            pub fn $with(&self, uri: impl IntoKeyUri $(, $alg: $A)?, opts: &OpenOptions) -> Result<$H> {
                self.open(uri, |p, u| p.$name(u $(, $alg)?, opts))
            }
        )*
    };
}

impl Registry {
    /// Starts building a registry.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::default()
    }

    /// The registered schemes.
    pub fn schemes(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.providers.keys().copied()
    }

    /// The provider of `uri`'s scheme; an error labeled with the URI if none is registered.
    fn route(&self, uri: &KeyUri) -> Result<&dyn Provider> {
        match self.providers.get(uri.scheme()) {
            Some(p) => Ok(&**p),
            None => {
                let registered: Vec<_> = self.schemes().collect();
                Err(label(
                    Error::new(
                        ErrorKind::Configuration,
                        "registry",
                        Operation::Open,
                        format!(
                            "no provider registered for scheme {:?} (registered: {}){}",
                            uri.scheme(),
                            if registered.is_empty() {
                                "none".to_owned()
                            } else {
                                registered.join(", ")
                            },
                            foreign_uri_hint(uri).unwrap_or_default(),
                        ),
                    ),
                    uri,
                ))
            }
        }
    }

    /// For configuration: the URI naming exactly `version` of the key at `uri`, from the
    /// provider of its scheme ([`Provider::pin`]). No I/O, and no layer is involved.
    ///
    /// Use it to build the URI a pinned handle opens (GCP signing and MAC keys must be pinned).
    /// `Unsupported` where the backend's versions are not addressable (transit, local, AWS);
    /// errors carry the key URI (without its query) as their [`resource`](Error::resource).
    /// Never pin a token's `kid`: verify through the handle and let the signature carry the
    /// version.
    pub fn pin(&self, uri: impl IntoKeyUri, version: &KeyVersion) -> Result<KeyUri> {
        let uri = uri.into_key_uri()?;
        self.route(&uri)?
            .pin(&uri, version)
            .map_err(|e| label(e, &uri))
    }

    /// Routes `uri` to its provider, opens the handle with `f`, applies the layers and labels
    /// errors with the URI.
    fn open<H: OpaqueHandle>(
        &self,
        uri: impl IntoKeyUri,
        f: impl FnOnce(&dyn Provider, &KeyUri) -> Result<H>,
    ) -> Result<H> {
        let uri = uri.into_key_uri()?;
        let provider = self.route(&uri)?;
        let mut handle = f(provider, &uri).map_err(|e| label(e, &uri))?;
        if handle.resource().is_none() {
            handle = handle.with_resource(uri.without_query().into());
        }
        Ok(self
            .layers
            .iter()
            .fold(handle, |h, layer| h.layer_shared(layer.clone())))
    }

    registry_open! {
        /// Opens a symmetric AEAD key.
        aead / aead_with() -> AeadKey;
        /// Opens a key-wrapping key, e.g. the KEK of an `EnvelopeAead`.
        key_wrap / key_wrap_with() -> KeyWrapKey;
        /// Opens a data-key source ([`Provider::data_keys`]).
        data_keys / data_keys_with() -> DataKeysKey;
        /// Opens a digest signer for `alg`.
        digest_signer / digest_signer_with(alg: SignatureAlgorithm) -> DigestSignerKey;
        /// Opens a digest verifier for `alg`.
        digest_verifier / digest_verifier_with(alg: SignatureAlgorithm) -> DigestVerifierKey;
        /// Opens a message signer for `alg` (e.g. Ed25519).
        message_signer / message_signer_with(alg: SignatureAlgorithm) -> MessageSignerKey;
        /// Opens a message verifier for `alg` (e.g. Ed25519).
        message_verifier / message_verifier_with(alg: SignatureAlgorithm) -> MessageVerifierKey;
        /// Opens a MAC key for `alg`.
        mac / mac_with(alg: MacAlgorithm) -> MacKey;
        /// Opens a public-key source for a key that signs with `alg`.
        public_keys / public_keys_with(alg: SignatureAlgorithm) -> PublicKeysKey;
        /// Opens a describe handle.
        describe / describe_with() -> DescribeKey;
    }
}

/// For a URI with no provider: a hint when it is a cloud's own key reference rather than a key
/// URI (a Key Vault key identifier, a Cloud KMS REST URL, a bare AWS KMS ARN), naming the key URI
/// to write instead. Recognized by host or prefix only; the hint is the same whether or not that
/// backend is registered.
fn foreign_uri_hint(uri: &KeyUri) -> Option<&'static str> {
    const AZURE_HOSTS: &[&str] = &[
        ".vault.azure.net",
        ".managedhsm.azure.net",
        ".vault.azure.cn",
        ".managedhsm.azure.cn",
        ".vault.usgovcloudapi.net",
        ".managedhsm.usgovcloudapi.net",
    ];
    let rest = uri.rest();
    match uri.scheme() {
        "https" | "http" => {
            let authority = rest.strip_prefix("//")?.split(['/', '?', '#']).next()?;
            let host = authority
                .rsplit_once(':')
                .map_or(authority, |(h, _)| h)
                .to_ascii_lowercase();
            if AZURE_HOSTS.iter().any(|s| host.ends_with(s)) {
                Some(
                    "; a Key Vault key identifier https://<host>/keys/<name>[/<version>] is opened \
                     as azure-kv://<host>/keys/<name>[/<version>]",
                )
            } else if host == "cloudkms.googleapis.com" {
                Some(
                    "; a Cloud KMS REST URL https://cloudkms.googleapis.com/v1/projects/... is \
                     opened as gcp-kms://projects/...",
                )
            } else {
                None
            }
        }
        "arn"
            if ["aws:kms:", "aws-cn:kms:", "aws-us-gov:kms:"]
                .iter()
                .any(|p| rest.starts_with(p)) =>
        {
            Some("; an AWS KMS ARN is opened as aws-kms://arn:aws:kms:...")
        }
        _ => None,
    }
}

/// Labels an error with the key URI (without its query) unless it names a resource already.
fn label(e: Error, uri: &KeyUri) -> Error {
    match e.resource() {
        Some(_) => e,
        None => e.with_resource(uri.without_query()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct P(&'static [&'static str]);
    impl Provider for P {
        fn schemes(&self) -> &[&'static str] {
            self.0
        }
    }

    #[test]
    fn duplicate_scheme_rejected() {
        let e = Registry::builder()
            .provider(P(&["a", "b"]))
            .provider(P(&["b"]))
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
    }

    #[test]
    fn unknown_scheme_and_unsupported() {
        let r = Registry::builder()
            .provider(P(&["a"]))
            .provider(P(&["b"]))
            .build()
            .unwrap();
        let e = r.aead("x://y").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert_eq!(e.resource(), Some("x://y"));
        assert!(e.message().contains("registered: a, b"), "{e}");
        let owned: KeyUri = "a://y".parse().unwrap();
        let e = r.aead_with(&owned, &OpenOptions::new()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        // Default provider methods name the provider, not "provider".
        assert_eq!(e.backend(), "a");
        assert_eq!(
            e.to_string(),
            "a open [a://y]: unsupported: provider does not open AEAD keys"
        );
        // Every URI form is accepted; a bad string is a ParseUri error, config class.
        assert!(r.aead(owned).is_err() && r.aead(String::from("a://y")).is_err());
        let e = r.aead("no scheme").unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Configuration, Operation::ParseUri)
        );
        // Query strings never reach the error.
        let e = r.aead("x://y?token=abc").unwrap_err();
        assert_eq!(e.resource(), Some("x://y"));
    }

    /// R-39: a cloud's own key reference opened as a URI gets a hint naming the key URI to
    /// write; other unknown schemes get none.
    #[test]
    fn unknown_scheme_hints_at_cloud_key_references() {
        let r = Registry::builder().provider(P(&["a"])).build().unwrap();
        let msg = |uri: &str| r.aead(uri).unwrap_err().message().to_owned();
        for (uri, hint) in [
            (
                "https://contoso.vault.azure.net/keys/app-kek/0123456789abcdef0123456789abcdef",
                "is opened as azure-kv://<host>/keys/<name>[/<version>]",
            ),
            (
                "https://hsm1.managedhsm.azure.net:443/keys/k",
                "is opened as azure-kv://",
            ),
            (
                "https://cloudkms.googleapis.com/v1/projects/p/locations/global/keyRings/r/cryptoKeys/k",
                "is opened as gcp-kms://projects/...",
            ),
            (
                "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                "is opened as aws-kms://arn:aws:kms:...",
            ),
        ] {
            let m = msg(uri);
            assert!(m.starts_with("no provider registered for scheme"), "{m}");
            assert!(m.contains(hint), "{uri}: {m}");
        }
        for uri in [
            "https://example.com/keys/k",
            "https://vault.azure.net.example.com/keys/k",
            "arn:aws:iam::111122223333:role/r",
            "x://contoso.vault.azure.net/keys/k",
        ] {
            assert!(msg(uri).ends_with("(registered: a)"), "{uri}");
        }
    }

    /// Opens `uri` for every purpose and returns the errors.
    fn open_all(r: &Registry, uri: &str) -> Vec<Error> {
        let s = SignatureAlgorithm::EcdsaP256Sha256;
        let m = SignatureAlgorithm::Ed25519;
        vec![
            r.aead(uri).unwrap_err(),
            r.key_wrap(uri).unwrap_err(),
            r.data_keys(uri).unwrap_err(),
            r.digest_signer(uri, s).unwrap_err(),
            r.digest_verifier(uri, s).unwrap_err(),
            r.message_signer(uri, m).unwrap_err(),
            r.message_verifier(uri, m).unwrap_err(),
            r.mac(uri, MacAlgorithm::HmacSha256).unwrap_err(),
            r.public_keys(uri, s).unwrap_err(),
            r.describe(uri).unwrap_err(),
        ]
    }

    /// Fails every open with its own error, through `forward_provider!`'s body form.
    struct Refusing;
    impl Refusing {
        fn refuse<T>(&self, uri: &KeyUri) -> Result<T> {
            Err(Error::app(ErrorKind::KeyMismatch, format!("refused {uri}")))
        }
    }
    impl Provider for Refusing {
        fn schemes(&self) -> &[&'static str] {
            &["r"]
        }
        crate::forward_provider!(self, uri => self.refuse(uri));
    }

    /// Delegates through `forward_provider!`'s target form.
    struct Wrapping(Refusing);
    impl Provider for Wrapping {
        fn schemes(&self) -> &[&'static str] {
            self.0.schemes()
        }
        crate::forward_provider!(self => &self.0);
    }

    /// Names itself and pins by appending `@<version>`; wrapped to test the target form's
    /// `name` and `pin`.
    struct Named;
    impl Provider for Named {
        fn schemes(&self) -> &[&'static str] {
            &["n"]
        }
        fn name(&self) -> &'static str {
            "named"
        }
        fn pin(&self, uri: &KeyUri, version: &KeyVersion) -> Result<KeyUri> {
            if version.as_str().is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    self.name(),
                    Operation::Open,
                    "empty version",
                ));
            }
            format!("{}@{}", uri.without_query(), version.as_str()).parse()
        }
    }
    struct WrappingNamed(Named);
    impl Provider for WrappingNamed {
        fn schemes(&self) -> &[&'static str] {
            self.0.schemes()
        }
        crate::forward_provider!(self => &self.0);
    }

    #[test]
    fn forwarders_cover_every_open_method() {
        let registry = |p: Arc<dyn Provider>| Registry::builder().provider_arc(p).build().unwrap();
        for r in [
            registry(Arc::new(Refusing)),
            registry(Arc::new(Wrapping(Refusing))),
            // `impl Provider for Arc<P>`.
            registry(Arc::new(Arc::new(Wrapping(Refusing)))),
        ] {
            for e in open_all(&r, "r://k") {
                assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
                assert_eq!(e.message(), "refused r://k");
            }
            // `pin` is forwarded by both forms (the body form evaluates the body).
            let e = r.pin("r://k", &KeyVersion::from_u64(1)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");
            assert_eq!(e.message(), "refused r://k");
        }
        // The target form forwards `name` and `pin`; so does `impl Provider for Arc<P>`.
        let v = KeyVersion::from_u64(7);
        for p in [
            Arc::new(WrappingNamed(Named)) as Arc<dyn Provider>,
            Arc::new(Arc::new(WrappingNamed(Named))),
            Arc::new(Arc::new(Named)),
        ] {
            assert_eq!(p.name(), "named");
            assert_eq!(
                p.pin(&"n://k".parse().unwrap(), &v).unwrap().to_string(),
                "n://k@7"
            );
            // Default open methods name the inner provider.
            let r = registry(p);
            for e in open_all(&r, "n://k") {
                assert_eq!(
                    (e.kind(), e.backend()),
                    (ErrorKind::Unsupported, "named"),
                    "{e}"
                );
            }
            assert_eq!(r.pin("n://k", &v).unwrap().to_string(), "n://k@7");
        }
        // A provider with no open methods refuses every purpose with the default.
        let r = Registry::builder().provider(P(&["p"])).build().unwrap();
        for e in open_all(&r, "p://k") {
            assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
            assert!(e.message().starts_with("provider does not"), "{e}");
        }
        let e = r.pin("p://k", &KeyVersion::from_u64(1)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        assert_eq!(
            e.to_string(),
            "p open [p://k]: unsupported: provider does not address key versions in URIs"
        );
    }

    /// `Registry::pin` routes by scheme, labels errors with the URI and involves no layer.
    #[test]
    fn registry_pin() {
        #[derive(Clone)]
        struct Panics;
        impl Layer for Panics {
            fn part(&self, _: &LayerCx<'_>, _: Part<'_>) {
                panic!("pin applies no layer")
            }
        }
        let r = Registry::builder()
            .provider_arc(Arc::new(Named))
            .layer(Panics)
            .build()
            .unwrap();
        let pinned = r.pin("n://k?x=1", &KeyVersion::new("abc")).unwrap();
        assert_eq!(pinned.to_string(), "n://k@abc");
        let owned: KeyUri = "n://k".parse().unwrap();
        assert!(r.pin(&owned, &KeyVersion::new("v")).is_ok());
        // The provider's own errors gain the resource, without the query.
        let e = r.pin("n://k?token=s", &KeyVersion::new("")).unwrap_err();
        assert_eq!(
            (e.kind(), e.operation(), e.resource()),
            (ErrorKind::InvalidArgument, Operation::Open, Some("n://k"))
        );
        // Unknown schemes and bad URIs fail as for the open methods.
        let e = r.pin("x://k", &KeyVersion::new("v")).unwrap_err();
        assert_eq!(
            (e.kind(), e.resource()),
            (ErrorKind::Configuration, Some("x://k"))
        );
        let e = r.pin("no scheme", &KeyVersion::new("v")).unwrap_err();
        assert_eq!(e.operation(), Operation::ParseUri);
    }

    #[test]
    fn open_options_extensions() {
        #[derive(Debug, PartialEq)]
        struct A(u32);
        #[derive(Debug)]
        struct B;
        let o = OpenOptions::new().with_extension(A(1)).with_extension(B);
        assert_eq!(o.extension::<A>(), Some(&A(1)));
        assert!(o.extension::<B>().is_some());
        assert!(o.extension::<u8>().is_none());
        let o = o.with_extension(A(2));
        assert_eq!(o.clone().extension::<A>(), Some(&A(2)));
        assert!(format!("{o:?}").contains("A(2)"));
    }

    #[test]
    fn algorithms_reach_the_provider() {
        struct Algs;
        impl Provider for Algs {
            fn schemes(&self) -> &[&'static str] {
                &["algs"]
            }
            fn digest_signer(
                &self,
                _: &KeyUri,
                alg: SignatureAlgorithm,
                _: &OpenOptions,
            ) -> Result<DigestSignerKey> {
                Err(Error::app(ErrorKind::KeyMismatch, format!("{alg:?}")))
            }
            fn mac(&self, _: &KeyUri, alg: MacAlgorithm, _: &OpenOptions) -> Result<MacKey> {
                Err(Error::app(ErrorKind::KeyMismatch, format!("{alg:?}")))
            }
        }
        let r = Registry::builder().provider(Algs).build().unwrap();
        let e = r
            .digest_signer("algs://k", SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap_err();
        assert_eq!(e.message(), "EcdsaP256Sha256");
        let e = r
            .mac_with("algs://k", MacAlgorithm::HmacSha256, &OpenOptions::new())
            .unwrap_err();
        assert_eq!(e.message(), "HmacSha256");
        // Unimplemented purposes stay `Unsupported`.
        let e = r
            .public_keys("algs://k", SignatureAlgorithm::Ed25519)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
        let e = r.key_wrap("algs://k").unwrap_err();
        assert_eq!(
            e.to_string(),
            "algs open [algs://k]: unsupported: provider does not open key-wrapping keys"
        );
        let e = r.data_keys("algs://k").unwrap_err();
        assert_eq!(
            e.to_string(),
            "algs open [algs://k]: unsupported: provider does not open data-key sources"
        );
    }
}
