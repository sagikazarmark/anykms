//! The GCP provider.

use std::sync::Arc;
use std::time::Duration;

use anykms_core::{
    AeadKey, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, Error, ErrorKind,
    IntoKeyUri, KeyTypeCheck, KeyUri, KeyVersion, KeyWrapKey, MacAlgorithm, MacKey,
    MessageSignerKey, MessageVerifierKey, OpenOptions, Operation, Provider, PublicKeysKey, Result,
    SignatureAlgorithm, SigningShape,
};

use crate::BACKEND;
use crate::auth::{AuthCtx, AuthEndpoints, Credentials, EnvVars};
use crate::client::Client;
use crate::config::{Endpoint, HttpVersion, Proxy, config_err, split_list};
use crate::handles::{
    GcpAeadKey, GcpDescribeKey, GcpDigestKey, GcpEd25519Key, GcpKeyWrapKey, GcpMacKey, KeyCtx,
    Shared,
};
use crate::uri::{GcpKeyRef, SCHEMES, location_ok, parse_version, project_ok};

/// Opens `gcp-kms://` keys on Cloud KMS.
///
/// Building a provider does no I/O beyond loading the system TLS roots: credentials are resolved
/// on the first operation. One provider holds one credential and one endpoint; keys in projects
/// that need other credentials go through a second provider under its own
/// [`Registry`](anykms_core::Registry) (both claim the `gcp-kms` scheme).
#[derive(Clone)]
pub struct GcpProvider {
    shared: Arc<Shared>,
    endpoint: Endpoint,
    custom_base: Option<url::Url>,
    allowed_projects: Option<Vec<String>>,
    allowed_locations: Option<Vec<String>>,
}

impl std::fmt::Debug for GcpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpProvider")
            .field("endpoint", &self.endpoint)
            .field("credentials", &self.shared.client.creds)
            .field("allowed_projects", &self.allowed_projects)
            .field("allowed_locations", &self.allowed_locations)
            .finish()
    }
}

/// Builds a [`GcpProvider`].
#[derive(Clone)]
pub struct GcpProviderBuilder {
    credentials: Credentials,
    endpoint: Endpoint,
    auth_endpoints: AuthEndpoints,
    quota_project: Option<String>,
    allowed_projects: Option<Vec<String>>,
    allowed_locations: Option<Vec<String>>,
    connect_timeout: Duration,
    request_timeout: Duration,
    pool_idle_timeout: Duration,
    tcp_keepalive: Duration,
    http_version: HttpVersion,
    proxy: Proxy,
    crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    ca_pem: Option<Vec<u8>>,
    public_key_ttl: Duration,
    allow_loopback_http: bool,
    max_response_bytes: usize,
    env: EnvVars,
}

impl std::fmt::Debug for GcpProviderBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpProviderBuilder")
            .field("credentials", &self.credentials)
            .field("endpoint", &self.endpoint)
            .field("quota_project", &self.quota_project)
            .field("allowed_projects", &self.allowed_projects)
            .field("allowed_locations", &self.allowed_locations)
            .field("proxy", &self.proxy)
            .field("public_key_ttl", &self.public_key_ttl)
            .finish_non_exhaustive()
    }
}

impl Default for GcpProviderBuilder {
    fn default() -> Self {
        Self {
            credentials: Credentials::adc(),
            endpoint: Endpoint::Global,
            auth_endpoints: AuthEndpoints::google(),
            quota_project: None,
            allowed_projects: None,
            allowed_locations: None,
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(50),
            tcp_keepalive: Duration::from_secs(30),
            http_version: HttpVersion::Http1,
            proxy: Proxy::None,
            crypto_provider: None,
            ca_pem: None,
            public_key_ttl: Duration::from_secs(60),
            allow_loopback_http: false,
            max_response_bytes: 4 * 1024 * 1024,
            env: EnvVars::default(),
        }
    }
}

fn quota_project_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 100
        && p.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b':' | b'.')
        })
}

impl GcpProviderBuilder {
    /// The credentials (default [`Credentials::adc`]).
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// The Cloud KMS endpoint (default [`Endpoint::Global`]).
    pub fn endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Where tokens are fetched (default [`AuthEndpoints::google`]). Anything else is for tests
    /// and emulators only; a plain `http://` origin also needs
    /// [`allow_loopback_http`](Self::allow_loopback_http).
    pub fn auth_endpoints(mut self, endpoints: AuthEndpoints) -> Self {
        self.auth_endpoints = endpoints;
        self
    }

    /// The project billed for requests and charged their quota (`x-goog-user-project`). Needed
    /// with user credentials (`authorized_user`); wins over a credential file's
    /// `quota_project_id`.
    pub fn quota_project(mut self, project: impl Into<String>) -> Self {
        self.quota_project = Some(project.into());
        self
    }

    /// Only keys in these projects open; others fail with `Configuration`. Strongly recommended:
    /// without it, a key URI injected through configuration could name an attacker's key that
    /// grants everyone encrypt rights, and data would be encrypted under it. An empty list is a
    /// `Configuration` error at [`build`](Self::build).
    pub fn allowed_projects<I: IntoIterator<Item = S>, S: Into<String>>(mut self, p: I) -> Self {
        self.allowed_projects = Some(p.into_iter().map(Into::into).collect());
        self
    }

    /// Only keys in these locations open; others fail with `Configuration`. An empty list is a
    /// `Configuration` error at [`build`](Self::build).
    pub fn allowed_locations<I: IntoIterator<Item = S>, S: Into<String>>(mut self, l: I) -> Self {
        self.allowed_locations = Some(l.into_iter().map(Into::into).collect());
        self
    }

    /// Timeout for establishing a connection (TCP and TLS); default 2 s.
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Timeout for one request, from sending to the end of the response; default 10 s. The
    /// overall deadline across retries belongs to `Retry`.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// How long idle pooled connections are kept; default 50 s.
    pub fn pool_idle_timeout(mut self, d: Duration) -> Self {
        self.pool_idle_timeout = d;
        self
    }

    /// TCP keepalive interval; default 30 s.
    pub fn tcp_keepalive(mut self, d: Duration) -> Self {
        self.tcp_keepalive = d;
        self
    }

    /// The HTTP version (default HTTP/1.1).
    pub fn http_version(mut self, v: HttpVersion) -> Self {
        self.http_version = v;
        self
    }

    /// A proxy for Cloud KMS and token endpoints (default none; environment proxy variables are
    /// ignored). The metadata server is always reached directly.
    pub fn proxy(mut self, p: Proxy) -> Self {
        self.proxy = p;
        self
    }

    /// The rustls crypto provider (first in the precedence of the crate docs).
    pub fn crypto_provider(mut self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Trusts only these CA certificates (PEM) instead of the system roots, for Cloud KMS and
    /// token endpoints (e.g. behind a TLS-inspecting proxy).
    pub fn ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_pem = Some(pem.into());
        self
    }

    /// How long a version's public key is cached for local verification and the key-type check;
    /// default 60 s (Cloud KMS's disable propagation). `Duration::ZERO` disables the cache.
    pub fn public_key_ttl(mut self, ttl: Duration) -> Self {
        self.public_key_ttl = ttl;
        self
    }

    /// Allows a plain `http://` [`Endpoint::Custom`] and [`AuthEndpoints::custom`] on a literal
    /// loopback IP (tests, emulators).
    pub fn allow_loopback_http(mut self) -> Self {
        self.allow_loopback_http = true;
        self
    }

    /// The largest response accepted (default 4 MiB, at least 64 KiB:
    /// [`MIN_RESPONSE_BYTES`](anykms_http::client::MIN_RESPONSE_BYTES)).
    pub fn max_response_bytes(mut self, n: usize) -> Self {
        self.max_response_bytes = n;
        self
    }

    /// Validates the configuration and builds the HTTP clients. No credential is resolved.
    pub fn build(self) -> Result<GcpProvider> {
        if self.connect_timeout.is_zero() || self.request_timeout.is_zero() {
            return Err(config_err(
                "connect_timeout and request_timeout must be greater than zero",
            ));
        }
        if self.max_response_bytes < anykms_http::client::MIN_RESPONSE_BYTES {
            return Err(config_err("max_response_bytes must be at least 64 KiB"));
        }
        // An empty list would refuse every key, which nobody means.
        if let Some(p) = &self.allowed_projects {
            if p.is_empty() {
                return Err(config_err(
                    "allowed_projects is empty: omit it to allow every project",
                ));
            }
            if !p.iter().all(|p| project_ok(p)) {
                return Err(config_err(
                    "invalid project ID in allowed_projects: 6 to 30 lowercase letters, digits and \
                     hyphens, starting with a letter and not ending with a hyphen (domain-scoped: \
                     <domain>:<id>)",
                ));
            }
        }
        if let Some(l) = &self.allowed_locations {
            if l.is_empty() {
                return Err(config_err(
                    "allowed_locations is empty: omit it to allow every location",
                ));
            }
            if !l.iter().all(|l| location_ok(l)) {
                return Err(config_err("invalid location in allowed_locations"));
            }
        }
        if let Some(q) = &self.quota_project
            && !quota_project_ok(q)
        {
            return Err(config_err("invalid quota project"));
        }
        let custom_base = match &self.endpoint {
            Endpoint::Custom(u) => Some(Endpoint::validate_custom(u, self.allow_loopback_http)?),
            _ => None,
        };
        if self.auth_endpoints.is_plain_http() && !self.allow_loopback_http {
            return Err(config_err(
                "plain http:// auth endpoints (AuthEndpoints::custom) require \
                 GcpProviderBuilder::allow_loopback_http()",
            ));
        }
        let plain_http = custom_base.as_ref().is_some_and(|u| u.scheme() == "http");
        if (plain_http || self.auth_endpoints.is_plain_http()) && self.proxy != Proxy::None {
            return Err(config_err(
                "a proxy cannot be used with a plain http:// endpoint",
            ));
        }
        if self.http_version == HttpVersion::Http2 && !cfg!(feature = "http2") {
            return Err(config_err(
                "HttpVersion::Http2 needs the anykms-gcp `http2` feature",
            ));
        }
        let tls = || {
            anykms_http::tls::TlsOptions::new()
                .ca_pem(self.ca_pem.as_deref())
                .crypto_provider(
                    self.crypto_provider.clone(),
                    "GcpProviderBuilder::crypto_provider",
                )
                .require_roots(!plain_http)
                .http2(self.http_version == HttpVersion::Http2 && !plain_http)
                .build(BACKEND)
        };
        let proxy = match &self.proxy {
            Proxy::None => None,
            Proxy::Url(u) => Some(u.clone()),
        };
        let http = anykms_http::client::ClientOptions::new()
            .connect_timeout(self.connect_timeout)
            .request_timeout(self.request_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
            .tcp_keepalive(self.tcp_keepalive)
            .http2(self.http_version == HttpVersion::Http2 && !plain_http)
            .proxy(proxy)
            .build(BACKEND, tls()?)?;
        // The metadata server: plain HTTP on a link-local address, a short connect timeout, never
        // a proxy.
        let metadata_http = anykms_http::client::ClientOptions::new()
            .connect_timeout(Duration::from_secs(1))
            .request_timeout(self.request_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
            .build(BACKEND, tls()?)?;
        let ctx = AuthCtx {
            http: http.clone(),
            metadata_http,
            endpoints: self.auth_endpoints,
            env: self.env,
        };
        let creds = self.credentials.into_source(&ctx)?;
        let client = Client {
            http,
            creds,
            quota_project: self.quota_project,
            max_response: self.max_response_bytes,
        };
        Ok(GcpProvider {
            shared: Arc::new(Shared::new(client, self.public_key_ttl)),
            endpoint: self.endpoint,
            custom_base,
            allowed_projects: self.allowed_projects,
            allowed_locations: self.allowed_locations,
        })
    }

    /// The configuration from the environment, on top of the defaults (no I/O; credentials stay
    /// lazy):
    ///
    /// | Variable | Effect |
    /// |---|---|
    /// | `GOOGLE_APPLICATION_CREDENTIALS` | read by ADC on first use (see [`Credentials::adc`]) |
    /// | `ANYKMS_GCP_ENDPOINT` | `global` (default), `regional`, or a custom `https://` URL |
    /// | `ANYKMS_GCP_QUOTA_PROJECT`, else `GOOGLE_CLOUD_QUOTA_PROJECT` | [`quota_project`](Self::quota_project) |
    /// | `ANYKMS_GCP_ALLOWED_PROJECTS` | comma-separated [`allowed_projects`](Self::allowed_projects) |
    /// | `ANYKMS_GCP_ALLOWED_LOCATIONS` | comma-separated [`allowed_locations`](Self::allowed_locations) |
    /// | `GCE_METADATA_HOST` | the metadata server's `host[:port]` (read on first use) |
    ///
    /// An allowlist variable that is set but lists nothing (empty, or only commas and spaces)
    /// makes [`build`](Self::build) fail with `Configuration`: unset it to allow everything.
    pub fn from_env() -> Result<Self> {
        Self::from_vars(&|v| std::env::var(v).ok(), EnvVars::default())
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment. The variables read on first use (`GOOGLE_APPLICATION_CREDENTIALS`,
    /// `CLOUDSDK_CONFIG`, `HOME`/`APPDATA` for the gcloud ADC file, `GCE_METADATA_HOST`) go
    /// through the same lookup, so nothing falls back to the process environment. The files they
    /// name are still read from the file system.
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        let lookup: crate::auth::EnvLookup = Arc::new(lookup);
        Self::from_vars(&*lookup, EnvVars::lookup(lookup.clone()))
    }

    fn from_vars(get: &dyn Fn(&str) -> Option<String>, env: EnvVars) -> Result<Self> {
        let var = |v: &str| get(v).filter(|s| !s.trim().is_empty());
        let mut b = Self {
            env,
            ..Self::default()
        };
        if let Some(e) = var("ANYKMS_GCP_ENDPOINT") {
            b = b.endpoint(Endpoint::parse(&e)?);
        }
        if let Some(q) =
            var("ANYKMS_GCP_QUOTA_PROJECT").or_else(|| var("GOOGLE_CLOUD_QUOTA_PROJECT"))
        {
            b = b.quota_project(q.trim());
        }
        // Set but empty is kept (and refused by `build`), not taken as unset.
        if let Some(p) = get("ANYKMS_GCP_ALLOWED_PROJECTS") {
            b = b.allowed_projects(split_list(&p));
        }
        if let Some(l) = get("ANYKMS_GCP_ALLOWED_LOCATIONS") {
            b = b.allowed_locations(split_list(&l));
        }
        Ok(b)
    }
}

/// Which version rule an opener applies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Versions {
    /// AEAD: the URI must not name a version.
    Forbidden,
    /// Signing, MAC, RSA KEKs: the URI must name one.
    Required,
    /// Describe.
    Any,
}

fn open_err(kind: ErrorKind, m: &'static str) -> Error {
    Error::new(kind, BACKEND, Operation::Open, m)
}

/// RSA verification and wrapping need an RSA backend in anykms-recipes.
fn require_rsa_backend(rsa: bool) -> Result<()> {
    if rsa && !cfg!(any(feature = "rsa-aws-lc-rs", feature = "rsa-rustcrypto")) {
        return Err(open_err(
            ErrorKind::Configuration,
            "RSA keys need an RSA backend: enable the anykms-gcp `rsa-aws-lc-rs` or \
             `rsa-rustcrypto` feature",
        ));
    }
    Ok(())
}

fn is_rsa(alg: SignatureAlgorithm) -> bool {
    !matches!(
        alg,
        SignatureAlgorithm::EcdsaP256Sha256
            | SignatureAlgorithm::EcdsaP384Sha384
            | SignatureAlgorithm::EcdsaP521Sha512
            | SignatureAlgorithm::Ed25519
    )
}

impl GcpProvider {
    /// Starts building a provider.
    pub fn builder() -> GcpProviderBuilder {
        GcpProviderBuilder::default()
    }

    /// A provider configured from the environment (see [`GcpProviderBuilder::from_env`]), with
    /// Application Default Credentials.
    pub fn from_env() -> Result<Self> {
        GcpProviderBuilder::from_env()?.build()
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment (see [`GcpProviderBuilder::from_env_with`]).
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        GcpProviderBuilder::from_env_with(lookup)?.build()
    }

    fn resolve(
        &self,
        uri: impl IntoKeyUri,
        versions: Versions,
        check: KeyTypeCheck,
    ) -> Result<KeyCtx> {
        let uri = uri.into_key_uri()?;
        let r = GcpKeyRef::parse(&uri).map_err(|e| e.with_resource(uri.without_query()))?;
        let resource: Arc<str> = r.to_string().into();
        self.resolve_inner(r, versions, check, resource.clone())
            .map_err(|e| e.with_resource(&*resource))
    }

    fn resolve_inner(
        &self,
        r: GcpKeyRef,
        versions: Versions,
        check: KeyTypeCheck,
        resource: Arc<str>,
    ) -> Result<KeyCtx> {
        if let Some(p) = &self.allowed_projects
            && !p.iter().any(|p| p == r.project())
        {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                backend = BACKEND,
                project = r.project(),
                "key URI refused: project not in allowed_projects"
            );
            return Err(open_err(
                ErrorKind::Configuration,
                "the key's project is not in allowed_projects",
            ));
        }
        if let Some(l) = &self.allowed_locations
            && !l.iter().any(|l| l == r.location())
        {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                backend = BACKEND,
                location = r.location(),
                "key URI refused: location not in allowed_locations"
            );
            return Err(open_err(
                ErrorKind::Configuration,
                "the key's location is not in allowed_locations",
            ));
        }
        match (versions, r.version()) {
            // `KeyMismatch`, like any key opened for an operation it cannot do: a version names
            // an asymmetric or MAC key's version, never what an AEAD handle needs, and an
            // unversioned asymmetric or MAC key cannot sign or MAC.
            (Versions::Forbidden, Some(_)) => {
                return Err(open_err(
                    ErrorKind::KeyMismatch,
                    "AEAD keys are opened without a version (encrypt uses the primary; decrypt \
                     cannot take a version): remove /cryptoKeyVersions/N",
                ));
            }
            (Versions::Required, None) => {
                return Err(open_err(
                    ErrorKind::KeyMismatch,
                    "signing, MAC and RSA key-wrapping keys need a version: append \
                     /cryptoKeyVersions/N (Cloud KMS asymmetric and MAC keys have no primary \
                     version)",
                ));
            }
            _ => {}
        }
        let base = self
            .endpoint
            .base_for(r.location(), self.custom_base.as_ref())?;
        Ok(KeyCtx {
            shared: self.shared.clone(),
            key: r,
            base: Arc::new(base),
            check,
            resource,
        })
    }

    /// Opens an `ENCRYPT_DECRYPT` key (unversioned URI). No I/O; the key type is checked before
    /// the first operation.
    pub fn aead_key(&self, uri: impl IntoKeyUri) -> Result<GcpAeadKey> {
        Ok(GcpAeadKey {
            k: self.resolve(uri, Versions::Forbidden, KeyTypeCheck::Describe)?,
        })
    }

    /// Opens an ECDSA or RSA signing key version for `alg` (versioned URI).
    pub fn digest_signing_key(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
    ) -> Result<GcpDigestKey> {
        let uri = uri.into_key_uri()?;
        let label = |e: Error| e.with_resource(uri.without_query());
        alg.require_shape(SigningShape::Digest, BACKEND)
            .map_err(label)?;
        require_rsa_backend(is_rsa(alg)).map_err(label)?;
        if matches!(
            alg,
            SignatureAlgorithm::EcdsaP521Sha512
                | SignatureAlgorithm::RsaPssSha384
                | SignatureAlgorithm::RsaPkcs1v15Sha384
        ) {
            return Err(label(open_err(
                ErrorKind::KeyMismatch,
                "Cloud KMS has no key with this signature algorithm",
            )));
        }
        Ok(GcpDigestKey {
            k: self.resolve(&uri, Versions::Required, KeyTypeCheck::Describe)?,
            alg,
        })
    }

    /// Opens an Ed25519 key version (versioned URI).
    pub fn ed25519_key(&self, uri: impl IntoKeyUri) -> Result<GcpEd25519Key> {
        Ok(GcpEd25519Key {
            k: self.resolve(uri, Versions::Required, KeyTypeCheck::Describe)?,
        })
    }

    /// Opens an HMAC key version for `alg` (versioned URI).
    pub fn mac_key(&self, uri: impl IntoKeyUri, alg: MacAlgorithm) -> Result<GcpMacKey> {
        Ok(GcpMacKey {
            k: self.resolve(uri, Versions::Required, KeyTypeCheck::Describe)?,
            alg,
        })
    }

    /// Opens an `RSA_DECRYPT_OAEP_*_SHA256` key version as a key-wrapping key (versioned URI):
    /// local wrap, server unwrap. No I/O; the algorithm is checked before the first operation.
    /// (An `ENCRYPT_DECRYPT` key wraps through [`aead_key`](Self::aead_key) or
    /// [`Provider::key_wrap`] with an unversioned URI.)
    pub fn key_wrap_key(&self, uri: impl IntoKeyUri) -> Result<GcpKeyWrapKey> {
        let uri = uri.into_key_uri()?;
        require_rsa_backend(true).map_err(|e| e.with_resource(uri.without_query()))?;
        Ok(GcpKeyWrapKey {
            k: self.resolve(&uri, Versions::Required, KeyTypeCheck::Describe)?,
        })
    }

    /// A describe-only handle for any key (with or without a version). No I/O.
    pub fn describe_key(&self, uri: impl IntoKeyUri) -> Result<GcpDescribeKey> {
        Ok(GcpDescribeKey {
            k: self.resolve(uri, Versions::Any, KeyTypeCheck::Describe)?,
        })
    }
}

impl Provider for GcpProvider {
    fn schemes(&self) -> &[&'static str] {
        SCHEMES
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    /// An `ENCRYPT_DECRYPT` key: `Aead` and `Describe`. `Rewrap` and `DataKeys` are not native
    /// to Cloud KMS: they report `Unsupported` before any I/O.
    fn aead(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<AeadKey> {
        let k = Arc::new(self.aead_key(uri)?.with_key_type_check(opts.key_type_check));
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(AeadKey::new(BACKEND, k.clone())
            .with_describe(k.clone())
            .with_preflight(k.clone())
            .with_concrete(k)
            .with_resource(r)
            .with_semantics(sem))
    }

    /// An unversioned URI: an `ENCRYPT_DECRYPT` key as a KEK, wrapping with empty AAD
    /// (`KeyWrapKey::from_aead`). A versioned URI: an `RSA_DECRYPT_OAEP_*_SHA256` key version
    /// (local wrap, server unwrap; see [`GcpKeyWrapKey`]).
    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        let r = GcpKeyRef::parse(uri)?;
        if r.version().is_none() {
            return Ok(KeyWrapKey::from_aead(self.aead(uri, opts)?));
        }
        let k = Arc::new(
            self.key_wrap_key(uri)?
                .with_key_type_check(opts.key_type_check),
        );
        let res = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(KeyWrapKey::new(BACKEND, k.clone())
            .with_describe(k.clone())
            .with_preflight(k.clone())
            .with_public_keys(k.clone())
            .with_concrete(k)
            .with_resource(res)
            .with_semantics(sem))
    }

    /// Cloud KMS has no native data keys: `Unsupported`. Wrap an AEAD key in
    /// `anykms_recipes::EmulatedDataKeys` explicitly.
    fn data_keys(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<DataKeysKey> {
        Err(open_err(
            ErrorKind::Unsupported,
            "Cloud KMS has no native data keys; wrap an AEAD key in \
             anykms_recipes::EmulatedDataKeys",
        )
        .with_resource(uri.without_query()))
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        let k = self
            .digest_signing_key(uri, alg)?
            .with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(DigestSignerKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestVerifierKey> {
        let k = self
            .digest_signing_key(uri, alg)?
            .with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(DigestVerifierKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<MessageSignerKey> {
        alg.require_shape(SigningShape::Message, BACKEND)
            .map_err(|e| e.with_resource(uri.without_query()))?;
        let k = self
            .ed25519_key(uri)?
            .with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(MessageSignerKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<MessageVerifierKey> {
        alg.require_shape(SigningShape::Message, BACKEND)
            .map_err(|e| e.with_resource(uri.without_query()))?;
        let k = self
            .ed25519_key(uri)?
            .with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(MessageVerifierKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    fn mac(&self, uri: &KeyUri, alg: MacAlgorithm, opts: &OpenOptions) -> Result<MacKey> {
        let k = self
            .mac_key(uri, alg)?
            .with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(MacKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<PublicKeysKey> {
        let check = opts.key_type_check;
        if alg.is_message_signing() {
            let k = self.ed25519_key(uri)?.with_key_type_check(check);
            let r = k.k.resource.clone();
            let sem = k.semantics().clone();
            Ok(PublicKeysKey::full(BACKEND, k.clone())
                .with_preflight(Arc::new(k))
                .with_resource(r)
                .with_semantics(sem))
        } else {
            let k = self
                .digest_signing_key(uri, alg)?
                .with_key_type_check(check);
            let r = k.k.resource.clone();
            let sem = k.semantics().clone();
            Ok(PublicKeysKey::full(BACKEND, k.clone())
                .with_preflight(Arc::new(k))
                .with_resource(r)
                .with_semantics(sem))
        }
    }

    /// The URI naming `version` (`/cryptoKeyVersions/<n>`). No I/O: the version is not checked
    /// to exist, and an AEAD URI pinned here is refused by `aead()`. The URI's own version
    /// returns it unchanged; another version, or a version that is not a positive decimal, is
    /// `Configuration` (`pin` builds configuration).
    fn pin(&self, uri: &KeyUri, version: &KeyVersion) -> Result<KeyUri> {
        let bad = |m: &'static str| {
            open_err(ErrorKind::Configuration, m).with_resource(uri.without_query())
        };
        let r = GcpKeyRef::parse(uri)?;
        let v = parse_version(version.as_str())
            .ok_or_else(|| bad("a GCP key version is a positive decimal number"))?;
        match r.version() {
            Some(have) if have == v => Ok(uri.clone()),
            Some(_) => Err(bad("the URI already names another key version")),
            None => KeyUri::parse(&r.at_version(v).to_string()),
        }
    }

    /// Describes any key, with or without a version in the URI (a version is only used to pick
    /// the reported algorithm). `opts` has no effect.
    fn describe(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<DescribeKey> {
        let k = self.describe_key(uri)?;
        let r = k.k.resource.clone();
        Ok(DescribeKey::new(BACKEND, Arc::new(k)).with_resource(r))
    }
}

#[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
mod tests {
    use super::*;

    fn provider() -> GcpProvider {
        GcpProvider::builder()
            .credentials(Credentials::none())
            .endpoint(Endpoint::custom("http://127.0.0.1:9"))
            .allow_loopback_http()
            .allowed_projects(["my-project"])
            .build()
            .unwrap()
    }

    const KEY: &str = "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/k";

    #[test]
    fn version_rules_at_open() {
        let p = provider();
        let o = OpenOptions::new();
        let uri = |s: &str| s.parse::<KeyUri>().unwrap();
        let v1 = uri(&format!("{KEY}/cryptoKeyVersions/1"));
        let k = uri(KEY);
        assert!(p.aead(&k, &o).is_ok());
        let e = p.aead(&v1, &o).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch);
        assert_eq!(e.resource(), Some(v1.to_string().as_str()));
        let e = p
            .digest_signer(&k, SignatureAlgorithm::EcdsaP256Sha256, &o)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch);
        assert!(e.to_string().contains("cryptoKeyVersions/N"), "{e}");
        assert!(
            p.digest_signer(&v1, SignatureAlgorithm::EcdsaP256Sha256, &o)
                .is_ok()
        );
        assert!(p.mac(&k, MacAlgorithm::HmacSha256, &o).is_err());
        assert!(p.mac(&v1, MacAlgorithm::HmacSha256, &o).is_ok());
        assert!(p.describe(&k, &o).is_ok());
        assert!(p.describe(&v1, &o).is_ok());
        assert!(p.key_wrap(&k, &o).is_ok());
        assert_eq!(
            p.digest_signer(&v1, SignatureAlgorithm::EcdsaP521Sha512, &o)
                .unwrap_err()
                .kind(),
            ErrorKind::KeyMismatch
        );
        assert_eq!(
            p.message_signer(&v1, SignatureAlgorithm::EcdsaP256Sha256, &o)
                .unwrap_err()
                .kind(),
            ErrorKind::KeyMismatch
        );
        assert_eq!(
            p.data_keys(&k, &o).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    /// R-39: a typed opener's URI parse error names the key (the URI without its query string),
    /// and a refused project ID states the rules.
    #[test]
    fn typed_open_parse_errors_name_the_uri_and_the_rules() {
        let uri = "gcp-kms://projects/p/locations/global/keyRings/r/cryptoKeys/k";
        let e = provider().aead_key(format!("{uri}?x=1")).unwrap_err();
        assert_eq!(
            (e.kind(), e.operation()),
            (ErrorKind::Configuration, Operation::ParseUri),
            "{e}"
        );
        assert_eq!(e.resource(), Some(uri));
        let e = provider().aead_key(uri).unwrap_err();
        assert_eq!(e.resource(), Some(uri));
        assert_eq!(
            e.message(),
            "invalid GCP project ID: 6 to 30 lowercase letters, digits and hyphens, starting \
             with a letter and not ending with a hyphen (domain-scoped: <domain>:<id>)"
        );
        let e = GcpProvider::builder()
            .credentials(Credentials::none())
            .allowed_projects(["p"])
            .build()
            .unwrap_err();
        assert!(e.message().contains("6 to 30 lowercase letters"), "{e}");
    }

    #[test]
    fn allowlists_and_endpoints() {
        let p = provider();
        let e = p
            .aead_key("gcp-kms://projects/other-project/locations/global/keyRings/r/cryptoKeys/k")
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        let p = GcpProvider::builder()
            .credentials(Credentials::none())
            .endpoint(Endpoint::Regional)
            .allowed_locations(["europe-west1"])
            .build()
            .unwrap();
        assert!(p.aead_key(KEY).is_err());
        let k = p
            .aead_key(
                "gcp-kms://projects/my-project/locations/europe-west1/keyRings/r/cryptoKeys/k",
            )
            .unwrap();
        assert_eq!(
            k.k.base.as_str(),
            "https://cloudkms.europe-west1.rep.googleapis.com/"
        );
        for b in [
            GcpProvider::builder().allowed_projects(["Bad"]),
            GcpProvider::builder().allowed_locations(["a/b"]),
            GcpProvider::builder().quota_project("a b"),
            GcpProvider::builder().endpoint(Endpoint::custom("http://127.0.0.1:1")),
            // Plain-HTTP auth endpoints need the same opt-in.
            GcpProvider::builder()
                .auth_endpoints(AuthEndpoints::custom("http://127.0.0.1:1").unwrap()),
            GcpProvider::builder()
                .endpoint(Endpoint::custom("https://kms.test"))
                .auth_endpoints(AuthEndpoints::custom("http://127.0.0.1:1").unwrap()),
            GcpProvider::builder().request_timeout(Duration::ZERO),
            GcpProvider::builder().max_response_bytes(64 * 1024 - 1),
        ] {
            assert_eq!(b.build().unwrap_err().kind(), ErrorKind::Configuration);
        }
    }

    /// P1-10: an empty allowlist, set in code or in the environment, fails at `build`.
    #[test]
    fn empty_allowlists_are_refused() {
        let e = GcpProvider::builder()
            .allowed_projects(Vec::<String>::new())
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(e.to_string().contains("allowed_projects is empty"), "{e}");
        let e = GcpProvider::builder()
            .allowed_locations(Vec::<String>::new())
            .build()
            .unwrap_err();
        assert!(e.to_string().contains("allowed_locations is empty"), "{e}");
        for (var, value) in [
            ("ANYKMS_GCP_ALLOWED_PROJECTS", ""),
            ("ANYKMS_GCP_ALLOWED_PROJECTS", " , "),
            ("ANYKMS_GCP_ALLOWED_LOCATIONS", ""),
        ] {
            let b =
                GcpProviderBuilder::from_env_with(move |v| (v == var).then(|| value.to_owned()))
                    .unwrap();
            let e = b.build().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{var}={value:?}");
            assert!(e.to_string().contains("is empty"), "{e}");
        }
        let b = GcpProviderBuilder::from_env_with(|v| {
            (v == "ANYKMS_GCP_ALLOWED_PROJECTS").then(|| "my-project".to_owned())
        })
        .unwrap();
        assert!(b.build().is_ok());
    }
}
