//! anykms: one interface for key-management services that keeps their differences visible.
//!
//! **When to use this crate.** This is the crate applications depend on: it re-exports the
//! others, and its [Cargo features](#cargo-features) choose the backends. Depend on a member crate
//! directly only to implement a backend (`anykms-core`, checked with `anykms-conformance`), to
//! compile only some recipes (`anykms-recipes`), or for a feature the facade does not forward
//! (`anykms-azure`'s experimental `mhsm-hmac`). A library depends on this crate with
//! `default-features = false` (see [Cargo features](#cargo-features)).
//!
//! This facade re-exports `anykms-core` at the root and the other crates as modules:
//!
//! | Module | Crate | Feature |
//! |---|---|---|
//! | (root) | `anykms-core`: traits, types, errors, [`Registry`], [`RetryLayer`] | always |
//! | [`recipes`] | `anykms-recipes`: envelope encryption, emulated data keys, local verification, JOSE | `recipes` (default) |
//! | [`transit`] | `anykms-transit`: HashiCorp Vault and OpenBao transit | `transit` |
//! | [`aws`] | `anykms-aws`: AWS KMS | `aws` |
//! | [`gcp`] | `anykms-gcp`: Google Cloud KMS | `gcp` |
//! | [`azure`] | `anykms-azure`: Azure Key Vault and Managed HSM | `azure` |
//! | [`local`] | `anykms-local`: in-memory software keys, **tests only** | `local` |
//!
//! The [glossary] defines the terms these docs use: typed and opaque handles, parts, layers,
//! providers, KEKs (key-wrapping keys), data keys and more.
//!
//! [glossary]: https://github.com/sagikazarmark/anykms/blob/main/docs/glossary.md
//!
//! ```no_run
//! # #[cfg(all(feature = "transit", feature = "recipes"))]
//! # async fn demo() -> anykms::Result<()> {
//! use anykms::prelude::*;
//! use anykms::recipes::EnvelopeAead;
//!
//! // Every handle the registry opens retries transient failures (tokio sleep and clock).
//! let registry = anykms::with_default_providers()?
//!     .layer(anykms::retry_layer())
//!     .build()?;
//! let kek = registry.key_wrap("hashivault:///transit/keys/app-kek")?;
//! let envelope = EnvelopeAead::new("app-kek", kek)?;
//! let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
//! let pt = envelope.decrypt(&ct, b"users/42/ssn").await?;
//! # Ok(()) }
//! ```
//!
//! **Envelope status:** the envelope format (v1) is frozen and always decrypts; its external
//! review is pending, so it is not yet recommended for long-lived data. The release that completes
//! the review announces the promotion in its release notes (see the `recipes::envelope` docs).
//!
//! The HTTP backends (transit, aws, gcp, azure) need a tokio runtime. Their TLS crypto provider is
//! aws-lc-rs through the default `rustls-aws-lc-rs` feature (a C compiler is needed); for ring use
//! `default-features = false` with `rustls-ring` (plus the other features you need). With neither,
//! they use the process-wide rustls default (see each backend's crate docs).
//!
//! Application code that should be testable with in-memory keys should depend on the traits,
//! [`AeadKey`] or the [`Registry`], never on a backend's typed handles.
//!
//! Without Vault, enable the `local` feature and open `local://` keys from a `LocalKeyset`
//! (in-memory keys that vanish with the process: development and tests only):
//!
//! ```
//! # #[cfg(feature = "local")]
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> anykms::Result<()> {
//! use anykms::local::{LocalKeyset, LocalProvider};
//! use anykms::prelude::*;
//!
//! let keyset = LocalKeyset::builder().aead("app-kek").build();
//! let registry = anykms::Registry::builder()
//!     .provider(LocalProvider::new(keyset).allow_ephemeral_local_keys()) // explicit opt-in
//!     .build()?;
//! let kek = registry.aead("local://default/app-kek")?;
//! let ct = kek.encrypt(b"123-45-6789", b"users/42/ssn").await?;
//! assert_eq!(&*kek.decrypt_utf8(&ct, b"users/42/ssn").await?, "123-45-6789");
//! # Ok(()) }
//! # #[cfg(not(feature = "local"))]
//! # fn main() {}
//! ```
//!
//! # Cargo features
//!
//! Features choose backends and crypto implementations. Cargo unifies features across a build,
//! so enabling both alternatives (`rustls-*`, `rsa-*`) is not an error: a fixed priority picks
//! one.
//!
//! | Feature | Default | What |
//! |---|---|---|
//! | `recipes` | yes | every recipe: envelope encryption, emulated data keys, local verification, JOSE ([`recipes`]) |
//! | `tokio` | yes | `retry_layer()`, `tokio_sleep()`, `tokio_clock()` (tokio's timer only, no runtime flavor) |
//! | `transit` | | Vault and OpenBao transit ([`transit`], `hashivault://`, `openbao://`) |
//! | `aws` | | AWS KMS ([`aws`], `aws-kms://arn:...`) |
//! | `aws-sdk-credentials` | | credentials from the AWS SDK for `aws` (`anykms_aws::credentials::SdkCredentials` over an `aws-config` provider: SSO, role chaining, `credential_process`) |
//! | `gcp` | | Google Cloud KMS ([`gcp`], `gcp-kms://projects/...`) |
//! | `gcp-service-account-key` | yes | service-account key files for `gcp` (they sign with aws-lc-rs, so a C toolchain is needed even with `rustls-ring` and `rsa-rustcrypto`); without it a service-account credential is a `Configuration` error naming the feature; no effect without `gcp` |
//! | `gcp-google-cloud-auth` | | access tokens from Google's `google-cloud-auth` for `gcp` (`Credentials::google_cloud_auth`, for the credential types not built in) |
//! | `azure` | | Azure Key Vault and Managed HSM ([`azure`], `azure-kv://<host>/keys/...`); for Managed HSM HMAC (experimental `mhsm-hmac`), depend on `anykms-azure` directly |
//! | `azure-identity` | | credentials from the Azure SDK for `azure` (`anykms_azure::AzureIdentity` over an `azure_identity` credential: the Azure CLI, certificates, ...) |
//! | `http2` | | allow HTTP/2 on every enabled HTTP backend |
//! | `local` | | in-memory keys ([`local`], `local://`), development and tests only |
//! | `tracing` | | spans and events (no secrets) |
//! | `serde` | | `Serialize`/`Deserialize` for `Ciphertext`, `Signature` and `Tag` (base64 in text formats, bytes in binary ones) |
//! | `rustls-aws-lc-rs` | yes | TLS for every HTTP backend (transit, aws, gcp, azure) with aws-lc-rs (needs a C toolchain); wins over `rustls-ring` when both are on |
//! | `rustls-ring` | | TLS for every HTTP backend with ring |
//! | `rsa-aws-lc-rs` | yes | local RSA verification and local RSA-OAEP wrapping (AWS, GCP, Azure, `recipes`) with AWS-LC (needs a C toolchain); implies `recipes` |
//! | `rsa-rustcrypto` | | the same with RustCrypto's pure-Rust `rsa` (a 0.10 release candidate); `rsa-aws-lc-rs` wins when both are on; implies `recipes` |
//!
//! - An HTTP backend uses the TLS provider configured on it if any, else the process-wide rustls
//!   default, else the `rustls-*` feature's provider; with none of these it fails with
//!   `Configuration`.
//! - With neither `rsa-*` feature, RSA keys fail with `Unsupported` in the local verifiers; ECDSA
//!   and Ed25519 need no backend.
//! - Without a C toolchain (no AWS-LC):
//!   `default-features = false, features = ["transit", "rustls-ring", "recipes", "rsa-rustcrypto", "tokio"]`
//!   (leave out `gcp-service-account-key`, which always signs with aws-lc-rs).
//! - To compile only some recipes, depend on `anykms-recipes` directly with
//!   `default-features = false` and its `jose`, `envelope` and `rsa-*` features.
//! - **Library authors** depend on this crate with `default-features = false` and only the
//!   features their own code needs, and let the application choose the TLS (`rustls-*`) and RSA
//!   (`rsa-*`) backends: features unify across the build, so a library's defaults would be forced
//!   on every application that uses it.
//!
// The feature-gated modules are linked only when they exist, so docs build warning-free with any
// feature set; otherwise the links point at the crates on docs.rs.
#![cfg_attr(feature = "recipes", doc = "[`recipes`]: crate::recipes")]
#![cfg_attr(
    not(feature = "recipes"),
    doc = "[`recipes`]: <https://docs.rs/anykms-recipes>"
)]
#![cfg_attr(feature = "transit", doc = "[`transit`]: crate::transit")]
#![cfg_attr(
    not(feature = "transit"),
    doc = "[`transit`]: <https://docs.rs/anykms-transit>"
)]
#![cfg_attr(feature = "aws", doc = "[`aws`]: crate::aws")]
#![cfg_attr(not(feature = "aws"), doc = "[`aws`]: <https://docs.rs/anykms-aws>")]
#![cfg_attr(feature = "gcp", doc = "[`gcp`]: crate::gcp")]
#![cfg_attr(not(feature = "gcp"), doc = "[`gcp`]: <https://docs.rs/anykms-gcp>")]
#![cfg_attr(feature = "azure", doc = "[`azure`]: crate::azure")]
#![cfg_attr(
    not(feature = "azure"),
    doc = "[`azure`]: <https://docs.rs/anykms-azure>"
)]
#![cfg_attr(feature = "local", doc = "[`local`]: crate::local")]
#![cfg_attr(
    not(feature = "local"),
    doc = "[`local`]: <https://docs.rs/anykms-local>"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub use anykms_core::*;

use std::sync::Arc;

#[cfg(feature = "aws")]
#[doc(inline)]
pub use anykms_aws as aws;
#[cfg(feature = "azure")]
#[doc(inline)]
pub use anykms_azure as azure;
#[cfg(feature = "gcp")]
#[doc(inline)]
pub use anykms_gcp as gcp;
#[cfg(feature = "local")]
#[doc(inline)]
pub use anykms_local as local;
#[cfg(feature = "recipes")]
#[doc(inline)]
pub use anykms_recipes as recipes;
#[cfg(feature = "transit")]
#[doc(inline)]
pub use anykms_transit as transit;

/// Every provider that can be configured from the environment, as a [`DefaultProviders`]
/// builder:
///
/// - `transit` feature: a Vault server when `VAULT_ADDR` is set, otherwise an OpenBao server when
///   `BAO_ADDR` is set (see `anykms_transit::EnvConfig`). With both set, Vault wins (and, with the
///   `tracing` feature, a warning says so). With neither, transit is skipped: it has no address.
/// - `aws` feature: AWS KMS (`anykms_aws::AwsProvider::from_env`), always. It needs no variable
///   (the region comes from each key ARN).
/// - `gcp` feature: Google Cloud KMS (`anykms_gcp::GcpProvider::from_env`), always.
/// - `azure` feature: Azure Key Vault and Managed HSM (`anykms_azure::AzureProvider::from_env`),
///   always, unless `ANYKMS_AZURE_CREDENTIAL=none` opts out.
///
/// Cloud key URIs are fully addressed and building a cloud provider sends no request (it reads the
/// environment and the system trust store), so every cloud provider whose feature is on is
/// registered: credentials are resolved on the first operation, and a missing credential is a
/// `Configuration` error then, naming the variables to set. The exception is a system trust store
/// without a usable root certificate (an empty or unreadable store, `SSL_CERT_FILE` naming an
/// empty file, ...): a cloud provider cannot build its TLS client then, and is skipped with
/// [`SkipCause::TlsRoots`], so an application that uses other backends still starts. A cloud
/// provider built explicitly (`AwsProvider::from_env()`, a builder) still fails with
/// `Configuration` there.
///
/// Every HTTP backend registered here shares one built-in transport
/// (`anykms_http::ReqwestTransport` with its defaults; the TLS roots are loaded once), except
/// where the environment configures one of its own: transit's `VAULT_CACERT`, `VAULT_CAPATH` or
/// client certificate, and `AWS_CA_BUNDLE`. Without the `reqwest` feature there is no transport
/// to share, and every HTTP backend is skipped with [`SkipCause::FeatureDisabled`].
///
/// A **malformed** variable (`AWS_USE_FIPS_ENDPOINT=maybe`, an unparsable `ANYKMS_GCP_ENDPOINT`,
/// `ANYKMS_AZURE_CREDENTIAL=bogus`, a transit address without a token source, ...) is an error
/// returned from this function, never a silent skip.
///
/// A skipped provider is not an error: [`DefaultProviders::skipped`] says which and why (with a
/// [`SkipCause`] to filter on), the `tracing` feature logs it, and opening a key of a skipped
/// provider's scheme fails with `Configuration` naming the reason
/// (`... (transit: VAULT_ADDR/BAO_ADDR not set)`) instead of the registry's generic "no provider"
/// error. A backend whose feature is off is skipped with a reason naming the feature, so opening a
/// `hashivault://`, `openbao://`, `aws-kms://`, `gcp-kms://` or `azure-kv://` key says which feature
/// (`transit`, `aws`, `gcp`, `azure`) to enable.
///
/// The local backend is never registered here: in-memory keys require an explicit
/// `LocalProvider::allow_ephemeral_local_keys()`.
///
/// [`with_default_providers_from`] does the same with variables from a lookup function.
pub fn with_default_providers() -> Result<DefaultProviders> {
    defaults(None)
}

/// Like [`with_default_providers`], reading every variable from `lookup` instead of the process
/// environment (`None` is unset). Each backend gets the lookup through its `from_env_with`, so
/// variables a backend reads later (transit's `*_TOKEN`, GCP's Application Default Credentials
/// variables) come from it too, and nothing falls back to the process environment. Files the
/// variables name are still read from the file system.
///
/// ```no_run
/// # fn demo() -> anykms::Result<()> {
/// let vars = std::collections::HashMap::from([
///     ("BAO_ADDR".to_owned(), "https://bao.example:8200".to_owned()),
///     ("BAO_TOKEN_FILE".to_owned(), "/run/secrets/bao-token".to_owned()),
/// ]);
/// let registry = anykms::with_default_providers_from(move |k| vars.get(k).cloned())?.build()?;
/// # Ok(()) }
/// ```
pub fn with_default_providers_from(
    lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
) -> Result<DefaultProviders> {
    let lookup: Lookup = Arc::new(lookup);
    defaults(Some(&lookup))
}

/// An environment lookup shared by the backends.
type Lookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// [`with_default_providers`] (`lookup` is `None`: the process environment) and
/// [`with_default_providers_from`].
#[allow(
    clippy::unnecessary_wraps,
    reason = "fallible whenever a backend feature is enabled; infallible only without any"
)]
fn defaults(lookup: Option<&Lookup>) -> Result<DefaultProviders> {
    // A backend's `from_env_with` takes its own copy of the lookup.
    #[allow(dead_code)] // unused without any backend feature
    fn share(l: &Lookup) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static + use<> {
        let l = l.clone();
        move |k| l(k)
    }
    let mut d = DefaultProviders {
        builder: Registry::builder(),
        claimed: Vec::new(),
        skipped: Vec::new(),
    };
    // One built-in transport for every HTTP backend (its TLS roots are loaded once).
    #[cfg(any(
        feature = "transit",
        feature = "aws",
        feature = "gcp",
        feature = "azure"
    ))]
    let shared = shared_transport()?;
    #[cfg(any(
        feature = "transit",
        feature = "aws",
        feature = "gcp",
        feature = "azure"
    ))]
    let _ = &shared; // unused with `transit` alone and no `reqwest`
    #[cfg(all(feature = "transit", not(feature = "reqwest")))]
    d.skipped.push(SkippedProvider {
        backend: "transit",
        reason: NO_TRANSPORT,
        cause: SkipCause::FeatureDisabled,
        schemes: anykms_transit::SCHEMES,
    });
    #[cfg(all(feature = "transit", feature = "reqwest"))]
    {
        let set = |v: &str| {
            match lookup {
                Some(l) => l(v),
                None => std::env::var(v).ok(),
            }
            .is_some_and(|x| !x.is_empty())
        };
        if set("VAULT_ADDR") {
            #[cfg(feature = "tracing")]
            if set("BAO_ADDR") {
                tracing::warn!(
                    backend = "transit",
                    "both VAULT_ADDR and BAO_ADDR are set; using VAULT_ADDR (Vault) and ignoring \
                     BAO_ADDR"
                );
            }
            d = d.transit(&anykms_transit::EnvConfig::vault(), lookup, &shared)?;
        } else if set("BAO_ADDR") {
            d = d.transit(&anykms_transit::EnvConfig::openbao(), lookup, &shared)?;
        } else {
            d.skipped.push(SkippedProvider {
                backend: "transit",
                reason: "VAULT_ADDR/BAO_ADDR not set",
                cause: SkipCause::NotConfigured,
                schemes: anykms_transit::SCHEMES,
            });
        }
    }
    #[cfg(not(feature = "transit"))]
    d.skipped.push(SkippedProvider {
        backend: "transit",
        reason: "the anykms `transit` feature is not enabled",
        cause: SkipCause::FeatureDisabled,
        // anykms_transit::SCHEMES, which is not compiled in.
        schemes: &["hashivault", "openbao"],
    });
    #[cfg(feature = "aws")]
    {
        let built = match lookup {
            None => anykms_aws::AwsProviderBuilder::from_env(),
            Some(l) => anykms_aws::AwsProviderBuilder::from_env_with(share(l)),
        };
        // `AWS_CA_BUNDLE` configures a transport of its own (the builder keeps it); the shared one
        // is for a builder without.
        d = d.cloud("aws", anykms_aws::SCHEMES, &shared, built, |b, t| {
            if b.has_http_transport() {
                b
            } else {
                b.http_transport(t)
            }
        })?;
    }
    #[cfg(not(feature = "aws"))]
    d.skipped.push(SkippedProvider {
        backend: "aws",
        reason: "the anykms `aws` feature is not enabled",
        cause: SkipCause::FeatureDisabled,
        // anykms_aws::SCHEMES, which is not compiled in.
        schemes: &["aws-kms"],
    });
    #[cfg(feature = "gcp")]
    {
        let built = match lookup {
            None => anykms_gcp::GcpProviderBuilder::from_env(),
            Some(l) => anykms_gcp::GcpProviderBuilder::from_env_with(share(l)),
        };
        d = d.cloud("gcp", anykms_gcp::SCHEMES, &shared, built, |b, t| {
            b.http_transport(t)
        })?;
    }
    #[cfg(not(feature = "gcp"))]
    d.skipped.push(SkippedProvider {
        backend: "gcp",
        reason: "the anykms `gcp` feature is not enabled",
        cause: SkipCause::FeatureDisabled,
        // anykms_gcp::SCHEMES, which is not compiled in.
        schemes: &["gcp-kms"],
    });
    #[cfg(feature = "azure")]
    {
        // A malformed ANYKMS_AZURE_CREDENTIAL is an error; `none` is the explicit opt-out.
        let kind = match lookup {
            None => anykms_azure::env_credential_kind()?,
            Some(l) => anykms_azure::env_credential_kind_with(share(l))?,
        };
        if let Some(anykms_azure::EnvCredentialKind::Disabled) = kind {
            d.skipped.push(SkippedProvider {
                backend: "azure",
                reason: "disabled by ANYKMS_AZURE_CREDENTIAL=none",
                cause: SkipCause::OptedOut,
                schemes: anykms_azure::SCHEMES,
            });
        } else {
            let built = match lookup {
                None => anykms_azure::AzureProviderBuilder::from_env(),
                Some(l) => anykms_azure::AzureProviderBuilder::from_env_with(share(l)),
            };
            d = d.cloud("azure", anykms_azure::SCHEMES, &shared, built, |b, t| {
                b.http_transport(t)
            })?;
        }
    }
    #[cfg(not(feature = "azure"))]
    d.skipped.push(SkippedProvider {
        backend: "azure",
        reason: "the anykms `azure` feature is not enabled",
        cause: SkipCause::FeatureDisabled,
        // anykms_azure::SCHEMES, which is not compiled in.
        schemes: &["azure-kv"],
    });
    #[cfg(feature = "tracing")]
    for s in &d.skipped {
        if s.cause == SkipCause::TlsRoots {
            // Not a choice of the application: its environment lacks what the provider needs.
            tracing::warn!(
                backend = s.backend,
                cause = ?s.cause,
                reason = s.reason,
                "default provider not registered"
            );
        } else {
            tracing::info!(
                backend = s.backend,
                cause = ?s.cause,
                reason = s.reason,
                "default provider not registered"
            );
        }
    }
    let _ = lookup; // unused without any backend feature
    Ok(d)
}

/// A provider that [`with_default_providers`] did not register, and why.
#[derive(Clone, Debug)]
pub struct SkippedProvider {
    backend: &'static str,
    cause: SkipCause,
    reason: &'static str,
    schemes: &'static [&'static str],
}

impl SkippedProvider {
    /// The backend (e.g. `transit`).
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// Why it was skipped, to filter on: a backend whose feature is off
    /// ([`SkipCause::FeatureDisabled`]) or that the environment opts out of
    /// ([`SkipCause::OptedOut`]) was the application's choice, unlike one the environment does not
    /// configure ([`SkipCause::NotConfigured`]) or cannot support ([`SkipCause::TlsRoots`]).
    pub fn cause(&self) -> SkipCause {
        self.cause
    }

    /// Why it was skipped, in words (e.g. `VAULT_ADDR/BAO_ADDR not set`, or that its feature is
    /// not enabled), as opening its keys reports it.
    pub fn reason(&self) -> &'static str {
        self.reason
    }

    /// The URI schemes it would have handled.
    pub fn schemes(&self) -> &'static [&'static str] {
        self.schemes
    }
}

/// Why [`with_default_providers`] skipped a provider ([`SkippedProvider::cause`]).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SkipCause {
    /// The backend's anykms feature is not enabled.
    FeatureDisabled,
    /// The environment does not configure the backend: transit without `VAULT_ADDR` or
    /// `BAO_ADDR`.
    NotConfigured,
    /// The environment opts out of the backend: `ANYKMS_AZURE_CREDENTIAL=none`.
    OptedOut,
    /// The system trust store holds no usable root certificate, so a cloud provider cannot build
    /// its TLS client (see [`with_default_providers`]).
    TlsRoots,
}

/// Without the `reqwest` feature the HTTP backends have no transport to be built on.
#[cfg(any(
    feature = "transit",
    feature = "aws",
    feature = "gcp",
    feature = "azure"
))]
#[cfg_attr(feature = "reqwest", allow(dead_code))]
const NO_TRANSPORT: &str = "the anykms `reqwest` feature is not enabled (no HTTP transport)";

/// The built-in transport the default cloud providers share, or why none could be built.
#[cfg(any(
    feature = "transit",
    feature = "aws",
    feature = "gcp",
    feature = "azure"
))]
#[allow(
    dead_code,
    reason = "which variant and fields are read depends on the backend and `reqwest` features"
)]
enum SharedTransport {
    Ready(std::sync::Arc<dyn anykms_http::HttpTransport>),
    Skip {
        cause: SkipCause,
        reason: &'static str,
    },
}

/// Builds the shared transport: a missing trust store is a skip, not an error; so is a missing
/// `reqwest` feature. Anything else is `Configuration`.
#[cfg(any(
    feature = "transit",
    feature = "aws",
    feature = "gcp",
    feature = "azure"
))]
fn shared_transport() -> Result<SharedTransport> {
    #[cfg(feature = "reqwest")]
    {
        match anykms_http::ReqwestTransport::new() {
            Ok(t) => Ok(SharedTransport::Ready(std::sync::Arc::new(t))),
            Err(e) if anykms_http::tls::is_missing_system_roots(&e) => Ok(SharedTransport::Skip {
                cause: SkipCause::TlsRoots,
                reason: "no trusted CA certificates (system roots unavailable)",
            }),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(feature = "reqwest"))]
    Ok(SharedTransport::Skip {
        cause: SkipCause::FeatureDisabled,
        reason: NO_TRANSPORT,
    })
}

/// The cloud builders' `build()`, for [`DefaultProviders::cloud`].
#[cfg(any(feature = "aws", feature = "gcp", feature = "azure"))]
trait BuildProvider<P> {
    fn build_provider(self) -> Result<P>;
}

#[cfg(feature = "aws")]
impl BuildProvider<anykms_aws::AwsProvider> for anykms_aws::AwsProviderBuilder {
    fn build_provider(self) -> Result<anykms_aws::AwsProvider> {
        self.build()
    }
}

#[cfg(feature = "gcp")]
impl BuildProvider<anykms_gcp::GcpProvider> for anykms_gcp::GcpProviderBuilder {
    fn build_provider(self) -> Result<anykms_gcp::GcpProvider> {
        self.build()
    }
}

#[cfg(feature = "azure")]
impl BuildProvider<anykms_azure::AzureProvider> for anykms_azure::AzureProviderBuilder {
    fn build_provider(self) -> Result<anykms_azure::AzureProvider> {
        self.build()
    }
}

/// A [`RegistryBuilder`] from [`with_default_providers`] that remembers which default providers
/// were skipped.
///
/// [`build`](Self::build) registers a placeholder for each skipped provider's schemes that no
/// added provider claims, so opening such a key fails with `Configuration` and the skip reason.
/// The placeholder's schemes therefore appear in [`Registry::schemes`]; use
/// [`into_builder`](Self::into_builder) to build without placeholders.
pub struct DefaultProviders {
    builder: RegistryBuilder,
    claimed: Vec<&'static str>,
    skipped: Vec<SkippedProvider>,
}

impl std::fmt::Debug for DefaultProviders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultProviders")
            .field("schemes", &self.claimed)
            .field("skipped", &self.skipped)
            .finish()
    }
}

impl DefaultProviders {
    /// Adds a provider ([`RegistryBuilder::provider`]).
    pub fn provider(self, provider: impl Provider + 'static) -> Self {
        self.provider_arc(std::sync::Arc::new(provider))
    }

    /// Adds a shared provider ([`RegistryBuilder::provider_arc`]).
    pub fn provider_arc(mut self, provider: std::sync::Arc<dyn Provider>) -> Self {
        self.claimed.extend(provider.schemes());
        self.builder = self.builder.provider_arc(provider);
        self
    }

    /// Wraps every handle the registry opens ([`RegistryBuilder::layer`]).
    pub fn layer(mut self, layer: impl Layer + 'static) -> Self {
        self.builder = self.builder.layer(layer);
        self
    }

    /// The default providers that were not registered, and why.
    pub fn skipped(&self) -> &[SkippedProvider] {
        &self.skipped
    }

    /// Registers the transit server `env` configures, over the shared transport unless the
    /// variables configured one of their own (`VAULT_CACERT`, a client certificate: `EnvConfig`
    /// then builds it) or the shared one could not be built (the server then builds its default,
    /// which a plain-HTTP loopback address does not need roots for).
    #[cfg(all(feature = "transit", feature = "reqwest"))]
    fn transit(
        self,
        env: &anykms_transit::EnvConfig,
        lookup: Option<&Lookup>,
        shared: &SharedTransport,
    ) -> Result<Self> {
        let mut server = match lookup {
            None => env.load()?,
            Some(l) => {
                let l = l.clone();
                env.load_with(move |k| l(k))?
            }
        };
        if let SharedTransport::Ready(t) = shared
            && !server.has_http_transport()
        {
            server = server.http_transport(t.clone());
        }
        let provider = anykms_transit::TransitProvider::builder()
            .server("default", server)
            .build()?;
        Ok(self.provider(provider))
    }

    /// Registers a cloud provider configured from the environment (`builder`) over the shared
    /// transport (`with` attaches it). Without a shared transport: no `reqwest` feature skips it
    /// ([`SkipCause::FeatureDisabled`]); no system TLS roots lets the builder try its own default
    /// (a loopback `http://` emulator or a CA bundle of its own needs none) and skips it only when
    /// that fails for the same reason ([`SkipCause::TlsRoots`]). A malformed environment is an
    /// error.
    #[cfg(any(feature = "aws", feature = "gcp", feature = "azure"))]
    fn cloud<B, P: Provider + 'static>(
        self,
        backend: &'static str,
        schemes: &'static [&'static str],
        shared: &SharedTransport,
        builder: Result<B>,
        with: impl FnOnce(B, std::sync::Arc<dyn anykms_http::HttpTransport>) -> B,
    ) -> Result<Self>
    where
        B: BuildProvider<P>,
    {
        let builder = builder?;
        let skip = |mut d: Self, cause: SkipCause, reason: &'static str| {
            d.skipped.push(SkippedProvider {
                backend,
                cause,
                reason,
                schemes,
            });
            d
        };
        match shared {
            SharedTransport::Ready(t) => {
                Ok(self.provider(with(builder, t.clone()).build_provider()?))
            }
            // Only the built-in transport can fail for want of roots.
            #[cfg(feature = "reqwest")]
            SharedTransport::Skip {
                cause: SkipCause::TlsRoots,
                reason,
            } => match builder.build_provider() {
                Ok(p) => Ok(self.provider(p)),
                Err(e) if anykms_http::tls::is_missing_system_roots(&e) => {
                    Ok(skip(self, SkipCause::TlsRoots, reason))
                }
                Err(e) => Err(e),
            },
            SharedTransport::Skip { cause, reason } => Ok(skip(self, *cause, reason)),
        }
    }

    /// The plain builder, without placeholders for skipped providers.
    pub fn into_builder(self) -> RegistryBuilder {
        self.builder
    }

    /// Builds the registry ([`RegistryBuilder::build`]), with placeholders that explain skipped
    /// providers.
    pub fn build(self) -> Result<Registry> {
        let mut b = self.builder;
        for s in self.skipped {
            let schemes: Vec<&'static str> = s
                .schemes
                .iter()
                .copied()
                .filter(|scheme| !self.claimed.contains(scheme))
                .collect();
            if !schemes.is_empty() {
                b = b.provider(Unconfigured { schemes, skip: s });
            }
        }
        b.build()
    }
}

/// Claims a skipped provider's schemes and fails every open with the skip reason.
struct Unconfigured {
    schemes: Vec<&'static str>,
    skip: SkippedProvider,
}

impl Unconfigured {
    fn err<T>(&self, uri: &KeyUri) -> Result<T> {
        Err(Error::new(
            ErrorKind::Configuration,
            "registry",
            Operation::Open,
            format!(
                "no provider registered for scheme {:?} ({}: {})",
                uri.scheme(),
                self.skip.backend,
                self.skip.reason
            ),
        ))
    }
}

impl Provider for Unconfigured {
    fn schemes(&self) -> &[&'static str] {
        &self.schemes
    }
    // Every open method, including ones added later, fails with the skip reason.
    forward_provider!(self, uri => self.err(uri));
}

/// A [`SleepFn`] for [`RetryLayer`] backed by `tokio::time::sleep`.
#[cfg(feature = "tokio")]
pub fn tokio_sleep() -> SleepFn {
    std::sync::Arc::new(|d| Box::pin(tokio::time::sleep(d)))
}

/// A [`ClockFn`] for [`RetryLayer`] backed by `tokio::time::Instant`, so the retry deadline follows
/// tokio's clock: under `#[tokio::test(start_paused = true)]` (tokio's `test-util` feature) a
/// whole retry schedule, deadline included, runs without waiting.
#[cfg(feature = "tokio")]
pub fn tokio_clock() -> ClockFn {
    let origin = std::sync::OnceLock::new();
    std::sync::Arc::new(move || {
        let origin = *origin.get_or_init(tokio::time::Instant::now);
        tokio::time::Instant::now().saturating_duration_since(origin)
    })
}

/// A [`RetryLayer`] with the default policy, tokio sleeping and the tokio clock: the way to
/// retry with tokio. Adjust it with [`RetryLayer::with_policy`] and [`RetryLayer::with_budget`],
/// then apply it once:
///
/// - to every handle of a registry: `Registry::builder().layer(retry_layer())`
///   ([`RegistryBuilder::layer`], [`DefaultProviders::layer`]), the usual choice: one budget for
///   every handle, shared by every backend behind the registry;
/// - to one handle: `key.layer(&retry_layer())`, which keeps the handle type and parts
///   (see [`Layer`]) and is skipped when the handle already retries (e.g. its registry has a
///   retry layer), so retries never nest;
/// - to any other future: `retry_layer().call(|| fut)` ([`RetryLayer::call`]), e.g. a backend's
///   extension method on its typed key, or `CachedVerifier::with_retry` in the recipes.
///
/// Each call creates its own [`RetryBudget`]; to bound retries per backend across several
/// layers, give them one budget with [`RetryLayer::with_budget`].
#[cfg(feature = "tokio")]
pub fn retry_layer() -> RetryLayer {
    RetryLayer::new(tokio_sleep()).with_clock(tokio_clock())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Claims(&'static [&'static str]);
    impl Provider for Claims {
        fn schemes(&self) -> &[&'static str] {
            self.0
        }
    }

    fn skipped_transit() -> DefaultProviders {
        DefaultProviders {
            builder: Registry::builder(),
            claimed: Vec::new(),
            skipped: vec![SkippedProvider {
                backend: "transit",
                reason: "VAULT_ADDR/BAO_ADDR not set",
                cause: SkipCause::NotConfigured,
                schemes: &["hashivault", "openbao"],
            }],
        }
    }

    #[test]
    fn skipped_provider_is_explained_when_opening() {
        let d = skipped_transit();
        assert_eq!(d.skipped()[0].reason(), "VAULT_ADDR/BAO_ADDR not set");
        assert_eq!(d.skipped()[0].cause(), SkipCause::NotConfigured);
        let r = d.build().unwrap();
        let uri: KeyUri = "hashivault:///transit/keys/k".parse().unwrap();
        let e = r.aead(&uri).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        // Every purpose gets the reason, not the trait's `Unsupported` default.
        let s = SignatureAlgorithm::EcdsaP256Sha256;
        let m = SignatureAlgorithm::Ed25519;
        for e in [
            r.key_wrap(&uri).unwrap_err(),
            r.digest_signer(&uri, s).unwrap_err(),
            r.digest_verifier(&uri, s).unwrap_err(),
            r.message_signer(&uri, m).unwrap_err(),
            r.message_verifier(&uri, m).unwrap_err(),
            r.mac(&uri, MacAlgorithm::HmacSha256).unwrap_err(),
            r.public_keys(&uri, s).unwrap_err(),
            r.describe(&uri).unwrap_err(),
        ] {
            assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
            assert!(e.message().contains("VAULT_ADDR/BAO_ADDR not set"), "{e}");
        }
        assert!(
            e.to_string()
                .contains("no provider registered for scheme \"hashivault\" (transit: VAULT_ADDR/BAO_ADDR not set)"),
            "{e}"
        );

        // A provider added later for one of the schemes replaces the placeholder for it.
        let r = skipped_transit()
            .provider(Claims(&["hashivault"]))
            .build()
            .unwrap();
        let e = r.aead(&uri).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported, "{e}");
        let bao: KeyUri = "openbao:///transit/keys/k".parse().unwrap();
        let e = r.aead(&bao).unwrap_err();
        assert!(e.to_string().contains("(transit: "), "{e}");

        // Without placeholders the registry knows nothing about transit.
        let r = skipped_transit().into_builder().build().unwrap();
        assert_eq!(r.schemes().count(), 0);
    }

    /// Runs the calling test `name` (without the `tests::` prefix) again in a child process whose
    /// environment holds only `vars` (plus what a process needs to start), and runs `body` there:
    /// [`with_default_providers`] reads the process environment, which tests may not change
    /// (`set_var` is unsafe and this crate forbids `unsafe`), and must not depend on the
    /// developer's or CI's cloud variables.
    fn isolated(name: &str, vars: &[(&str, &str)], body: impl FnOnce()) {
        const CHILD: &str = "ANYKMS_FACADE_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            return body();
        }
        let keep = [
            "PATH",
            "SystemRoot",
            "LD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
        ];
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([&format!("tests::{name}"), "--exact", "--test-threads=1"])
            .env_clear()
            .envs(keep.iter().filter_map(|k| Some((k, std::env::var_os(k)?))))
            .env(CHILD, "1")
            .envs(vars.iter().copied())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success() && text.contains("1 passed"),
            "{name} with {vars:?}:\n{text}"
        );
    }

    /// Azure is not under test: keeps an Azure build without credentials out of the way.
    const NO_AZURE: (&str, &str) = ("ANYKMS_AZURE_CREDENTIAL", "none");

    /// Opening `uri` from the default registry fails with `Configuration` containing `needle`.
    fn open_explains(d: DefaultProviders, uri: &str, needle: &str) {
        let r = d.build().unwrap();
        let uri: KeyUri = uri.parse().unwrap();
        let e = r.aead(&uri).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(e.to_string().contains(needle), "{e}");
    }

    // Unused in some feature combinations (e.g. `gcp` without a `rustls-*` feature).
    #[allow(dead_code)]
    const AWS_URI: &str = "aws-kms://arn:aws:kms:us-east-1:111122223333:alias/k";
    #[allow(dead_code)]
    const GCP_URI: &str = "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k";
    #[allow(dead_code)]
    const AZURE_URI: &str = "azure-kv://kv1.vault.azure.net/keys/k";

    /// A lookup over `vars` only.
    fn lookup(
        vars: &[(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static + use<> {
        let vars = vars.to_vec();
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    /// `with_default_providers_from` reads the lookup only: whatever the test process's own
    /// environment holds (a developer's VAULT_ADDR, cloud credentials) is not consulted, so no
    /// child process is needed.
    #[test]
    fn defaults_from_a_lookup_ignore_the_process_environment() {
        let d = with_default_providers_from(lookup(&[NO_AZURE])).unwrap();
        let reason = |b: &str| {
            d.skipped()
                .iter()
                .find(|s| s.backend() == b)
                .map(|s| (s.cause(), s.reason()))
        };
        if cfg!(all(feature = "transit", feature = "reqwest")) {
            assert_eq!(
                reason("transit"),
                Some((SkipCause::NotConfigured, "VAULT_ADDR/BAO_ADDR not set"))
            );
        }
        if cfg!(all(feature = "azure", feature = "reqwest")) {
            assert_eq!(
                reason("azure"),
                Some((
                    SkipCause::OptedOut,
                    "disabled by ANYKMS_AZURE_CREDENTIAL=none"
                ))
            );
        }
        // Without the `reqwest` feature there is no transport: every HTTP backend is skipped as a
        // disabled feature, naming `reqwest`.
        let no_transport = !cfg!(feature = "reqwest");
        for b in ["transit", "aws", "gcp", "azure"] {
            if let Some((cause, why)) = reason(b) {
                let enabled = match b {
                    "transit" => cfg!(feature = "transit"),
                    "aws" => cfg!(feature = "aws"),
                    "gcp" => cfg!(feature = "gcp"),
                    _ => cfg!(feature = "azure"),
                } && !no_transport;
                // The Azure opt-out is decided before the transport is looked at.
                if cause != SkipCause::OptedOut {
                    assert_eq!(cause == SkipCause::FeatureDisabled, !enabled, "{b}");
                }
                if enabled {
                    assert!(!why.contains("`reqwest`"), "{b}: {why}");
                }
            }
        }
        if cfg!(all(feature = "aws", feature = "reqwest")) {
            assert_eq!(reason("aws"), None);
        }
        if cfg!(all(feature = "gcp", feature = "reqwest")) {
            assert_eq!(reason("gcp"), None);
        }
        if no_transport {
            for b in ["transit", "aws", "gcp"] {
                let on = match b {
                    "transit" => cfg!(feature = "transit"),
                    "aws" => cfg!(feature = "aws"),
                    _ => cfg!(feature = "gcp"),
                };
                if on {
                    let (cause, why) = reason(b).unwrap();
                    assert_eq!(cause, SkipCause::FeatureDisabled, "{b}");
                    assert!(why.contains("`reqwest`"), "{b}: {why}");
                }
            }
        }
    }

    /// Polls `fut` to completion on this thread, with no Tokio runtime.
    #[allow(dead_code)] // unused without any HTTP backend feature
    fn block_on<F: Future>(fut: F) -> F::Output {
        struct Unpark(std::thread::Thread);
        impl std::task::Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Arc::new(Unpark(std::thread::current())).into();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            std::thread::park();
        }
    }

    /// R-35: called outside a Tokio runtime, every HTTP backend fails with `Configuration` naming
    /// the fix instead of panicking, before its credential fetch (a transit token, the AWS
    /// default chain, GCP's metadata server, Azure managed identity), so no request is sent.
    #[cfg(all(
        feature = "reqwest",
        any(
            feature = "transit",
            feature = "aws",
            feature = "gcp",
            feature = "azure"
        )
    ))]
    #[test]
    fn http_backends_outside_a_runtime_fail_with_configuration() {
        let d = with_default_providers_from(lookup(&[
            ("BAO_ADDR", "https://127.0.0.1:1"),
            ("BAO_TOKEN", "t"),
            ("ANYKMS_AZURE_MANAGED_IDENTITY", "1"),
        ]))
        .unwrap();
        let skipped: Vec<_> = d
            .skipped()
            .iter()
            .map(super::SkippedProvider::backend)
            .collect();
        let r = d.build().unwrap();
        let mut tested = Vec::new();
        for (backend, uri) in [
            ("transit", "openbao:///transit/keys/k"),
            ("aws", AWS_URI),
            ("gcp", GCP_URI),
            ("azure", AZURE_URI),
        ] {
            if skipped.contains(&backend) {
                continue;
            }
            let k = r.key_wrap(uri).unwrap();
            let e = block_on(k.wrap_key(&[7; 32])).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{backend}: {e}");
            assert_eq!(e.backend(), backend, "{e}");
            assert!(e.resource().is_some(), "{e}");
            assert!(
                e.message()
                    .starts_with("anykms HTTP backends must run inside a Tokio runtime; "),
                "{backend}: {e}"
            );
            tested.push(backend);
        }
        assert_eq!(tested.contains(&"transit"), cfg!(feature = "transit"));
    }

    #[cfg(all(feature = "transit", feature = "reqwest"))]
    #[test]
    fn transit_from_a_lookup() {
        let addr = ("BAO_ADDR", "https://bao.example:8200");
        let d = with_default_providers_from(lookup(&[NO_AZURE, addr, ("BAO_TOKEN", "t")])).unwrap();
        assert!(d.skipped().iter().all(|s| s.backend() != "transit"));
        let r = d.build().unwrap();
        r.aead("openbao:///transit/keys/k").unwrap();
        // A renamed variable is refused, even next to its new name.
        let e = with_default_providers_from(lookup(&[
            NO_AZURE,
            addr,
            ("BAO_TOKEN", "t"),
            ("ANYKMS_NO_TOKEN", "1"),
            ("ANYKMS_TRANSIT_NO_TOKEN", "1"),
        ]))
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(
            e.message()
                .contains("ANYKMS_NO_TOKEN was renamed to ANYKMS_TRANSIT_NO_TOKEN"),
            "{e}"
        );
    }

    /// A malformed variable from the lookup is an error, as from the environment.
    #[cfg(feature = "aws")]
    #[test]
    fn aws_malformed_lookup_is_an_error() {
        let vars = [NO_AZURE, ("AWS_USE_FIPS_ENDPOINT", "maybe")];
        let e = with_default_providers_from(lookup(&vars)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(e.message().contains("AWS_USE_FIPS_ENDPOINT"), "{e}");
    }

    #[cfg(all(feature = "transit", feature = "reqwest"))]
    #[test]
    fn transit_without_address_is_skipped() {
        isolated("transit_without_address_is_skipped", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            let s = d.skipped().iter().find(|s| s.backend() == "transit");
            assert_eq!(s.unwrap().reason(), "VAULT_ADDR/BAO_ADDR not set");
            open_explains(
                d,
                "openbao:///transit/keys/k",
                "(transit: VAULT_ADDR/BAO_ADDR not set)",
            );
        });
    }

    #[cfg(not(feature = "transit"))]
    #[test]
    fn missing_transit_feature_is_named() {
        isolated("missing_transit_feature_is_named", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            assert_eq!(d.skipped()[0].backend(), "transit");
            open_explains(d, "openbao:///transit/keys/k", "`transit` feature");
        });
    }

    #[cfg(not(feature = "aws"))]
    #[test]
    fn missing_aws_feature_is_named() {
        isolated("missing_aws_feature_is_named", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            let s = d.skipped().iter().find(|s| s.backend() == "aws").unwrap();
            assert_eq!(s.schemes(), ["aws-kms"]);
            open_explains(d, AWS_URI, "(aws: the anykms `aws` feature is not enabled)");
        });
    }

    /// AWS is always registered: no variable needed, no I/O at construction or open.
    #[cfg(all(feature = "aws", feature = "reqwest"))]
    #[test]
    fn aws_is_registered() {
        isolated("aws_is_registered", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            assert!(d.skipped().iter().all(|s| s.backend() != "aws"));
            let r = d.build().unwrap();
            assert!(r.schemes().any(|s| s == "aws-kms"));
            r.aead(AWS_URI).unwrap();
        });
    }

    /// A malformed AWS variable is an error, not a skip.
    #[cfg(feature = "aws")]
    #[test]
    fn aws_malformed_env_is_an_error() {
        let vars = [NO_AZURE, ("AWS_USE_FIPS_ENDPOINT", "maybe")];
        isolated("aws_malformed_env_is_an_error", &vars, || {
            let e = with_default_providers().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
            assert!(e.to_string().contains("AWS_USE_FIPS_ENDPOINT"), "{e}");
        });
    }

    #[cfg(not(feature = "gcp"))]
    #[test]
    fn missing_gcp_feature_is_named() {
        isolated("missing_gcp_feature_is_named", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            let s = d.skipped().iter().find(|s| s.backend() == "gcp").unwrap();
            assert_eq!(s.schemes(), ["gcp-kms"]);
            open_explains(d, GCP_URI, "(gcp: the anykms `gcp` feature is not enabled)");
        });
    }

    /// GCP is always registered without any environment (credentials are lazy), and opening a
    /// key does no I/O.
    #[cfg(all(
        feature = "gcp",
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn gcp_is_registered() {
        isolated("gcp_is_registered", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            assert!(d.skipped().iter().all(|s| s.backend() != "gcp"));
            let r = d.build().unwrap();
            assert!(r.schemes().any(|s| s == "gcp-kms"));
            r.aead(GCP_URI).unwrap();
        });
    }

    /// A malformed `ANYKMS_GCP_*` variable is an error, not a skip.
    #[cfg(feature = "gcp")]
    #[test]
    fn gcp_malformed_env_is_an_error() {
        let vars = [NO_AZURE, ("ANYKMS_GCP_ENDPOINT", "not a url")];
        isolated("gcp_malformed_env_is_an_error", &vars, || {
            let e = with_default_providers().unwrap_err();
            assert_eq!(e.backend(), "gcp", "{e}");
        });
    }

    #[cfg(not(feature = "azure"))]
    #[test]
    fn missing_azure_feature_is_named() {
        isolated("missing_azure_feature_is_named", &[], || {
            let d = with_default_providers().unwrap();
            let s = d.skipped().iter().find(|s| s.backend() == "azure").unwrap();
            assert_eq!(s.schemes(), ["azure-kv"]);
            open_explains(
                d,
                AZURE_URI,
                "(azure: the anykms `azure` feature is not enabled)",
            );
        });
    }

    /// Azure is always registered, even with no credential in the environment: the credential
    /// fails with `Configuration` on the first operation, and opening a key does no I/O.
    ///
    /// Needs `AzureProvider::from_env` to succeed without a credential (shared.md §6.2).
    #[cfg(all(
        feature = "azure",
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn azure_is_registered_without_credentials() {
        isolated("azure_is_registered_without_credentials", &[], || {
            let d = with_default_providers().unwrap();
            assert!(d.skipped().iter().all(|s| s.backend() != "azure"));
            let r = d.build().unwrap();
            assert!(r.schemes().any(|s| s == "azure-kv"));
            r.key_wrap(AZURE_URI).unwrap();
        });
    }

    /// With a credential configured, Azure is registered.
    #[cfg(all(
        feature = "azure",
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn azure_is_registered_with_credentials() {
        let vars = [
            ("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000"),
            ("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000"),
            ("AZURE_CLIENT_SECRET", "not-a-secret"),
        ];
        isolated("azure_is_registered_with_credentials", &vars, || {
            let d = with_default_providers().unwrap();
            assert!(d.skipped().iter().all(|s| s.backend() != "azure"));
            d.build().unwrap().key_wrap(AZURE_URI).unwrap();
        });
    }

    /// `ANYKMS_AZURE_CREDENTIAL=none` is the explicit opt-out, and opening says so.
    #[cfg(feature = "azure")]
    #[test]
    fn azure_none_is_skipped() {
        isolated("azure_none_is_skipped", &[NO_AZURE], || {
            let d = with_default_providers().unwrap();
            let s = d.skipped().iter().find(|s| s.backend() == "azure").unwrap();
            assert_eq!(s.schemes(), ["azure-kv"]);
            open_explains(
                d,
                AZURE_URI,
                "(azure: disabled by ANYKMS_AZURE_CREDENTIAL=none)",
            );
        });
    }

    /// A malformed `ANYKMS_AZURE_CREDENTIAL` is an error, not a skip.
    #[cfg(feature = "azure")]
    #[test]
    fn azure_malformed_env_is_an_error() {
        let vars = [("ANYKMS_AZURE_CREDENTIAL", "bogus")];
        isolated("azure_malformed_env_is_an_error", &vars, || {
            let e = with_default_providers().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
            assert_eq!(e.backend(), "azure", "{e}");
        });
    }

    /// Without a usable system root certificate (`SSL_CERT_FILE` naming an empty file), every
    /// cloud provider is skipped with `TlsRoots` instead of failing the registry, opening its
    /// keys says why, and a provider built explicitly still fails.
    #[cfg(all(
        any(feature = "aws", feature = "gcp", feature = "azure"),
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn missing_tls_roots_skip_cloud_providers() {
        let vars = [("SSL_CERT_FILE", "/dev/null")];
        isolated("missing_tls_roots_skip_cloud_providers", &vars, || {
            let d = with_default_providers().unwrap();
            let skipped: Vec<_> = d
                .skipped()
                .iter()
                .filter(|s| s.cause() == SkipCause::TlsRoots)
                .map(super::SkippedProvider::backend)
                .collect();
            let enabled: Vec<_> = [
                ("aws", cfg!(feature = "aws")),
                ("gcp", cfg!(feature = "gcp")),
                ("azure", cfg!(feature = "azure")),
            ]
            .into_iter()
            .filter_map(|(b, on)| on.then_some(b))
            .collect();
            assert_eq!(skipped, enabled);
            #[cfg(feature = "aws")]
            {
                let e = anykms_aws::AwsProvider::from_env().unwrap_err();
                assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
                assert!(anykms_http::tls::is_missing_system_roots(&e), "{e}");
            }
            let (uri, backend) = if cfg!(feature = "aws") {
                (AWS_URI, "aws")
            } else if cfg!(feature = "gcp") {
                (GCP_URI, "gcp")
            } else {
                (AZURE_URI, "azure")
            };
            open_explains(
                d,
                uri,
                &format!("({backend}: no trusted CA certificates (system roots unavailable))"),
            );
        });
    }

    /// Without system roots, a cloud provider whose configuration needs none (a loopback
    /// `http://` emulator endpoint) is still registered: the builder's own default transport
    /// serves it.
    #[cfg(all(
        feature = "aws",
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn missing_tls_roots_keep_a_loopback_aws_emulator() {
        let vars = [
            NO_AZURE,
            ("SSL_CERT_FILE", "/dev/null"),
            ("AWS_ENDPOINT_URL_KMS", "http://127.0.0.1:4566"),
            ("ANYKMS_AWS_ALLOW_LOOPBACK_HTTP", "1"),
        ];
        isolated(
            "missing_tls_roots_keep_a_loopback_aws_emulator",
            &vars,
            || {
                let d = with_default_providers().unwrap();
                assert!(
                    d.skipped().iter().all(|s| s.backend() != "aws"),
                    "{:?}",
                    d.skipped()
                );
                d.build().unwrap().aead(AWS_URI).unwrap();
            },
        );
    }

    /// Transit is configured by its address, so without TLS roots it keeps failing.
    #[cfg(all(
        feature = "transit",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn missing_tls_roots_fail_a_configured_transit() {
        let vars = [
            NO_AZURE,
            ("SSL_CERT_FILE", "/dev/null"),
            ("VAULT_ADDR", "https://vault.example:8200"),
            ("VAULT_TOKEN", "t"),
        ];
        isolated("missing_tls_roots_fail_a_configured_transit", &vars, || {
            let e = with_default_providers().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
            assert_eq!(e.backend(), "transit", "{e}");
            assert!(e.message().contains("no trusted CA certificates"), "{e}");
        });
    }
}
