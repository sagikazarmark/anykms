//! The Azure provider and its builder.

use std::sync::Arc;
use std::time::Duration;

use anykms_core::{
    AeadKey, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, Error, ErrorKind,
    IntoKeyUri, KeyTypeCheck, KeyUri, KeyVersion, KeyWrapKey, OpenOptions, Operation, Provider,
    PublicKeysKey, Result, SignatureAlgorithm, SigningShape,
};

use crate::BACKEND;
use crate::client::Client;
use crate::config::{
    ApiVersion, AzureCloud, AzureOptions, HostPolicy, HttpVersion, Proxy, TestHost, VaultKind,
    config_err,
};
use crate::credential::{AzureCredential, Tokens};
use crate::handles::{
    AzureAeadKey, AzureDigestKey, AzureKeyWrapKey, DescribeCache, KeyCtx, LocalVerifiers,
    MhsmDataKeys,
};
use crate::semantics;
use crate::uri::{AzureKeyRef, SCHEMES};

/// Opens `azure-kv://` keys in Azure Key Vault and Managed HSM.
///
/// Cheap to clone (shared client, token cache and key-type cache). Opening a key does no I/O.
#[derive(Clone)]
pub struct AzureProvider {
    client: Arc<Client>,
    policy: Arc<HostPolicy>,
    cache: Arc<DescribeCache>,
}

impl std::fmt::Debug for AzureProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureProvider")
            .field("credential", &self.client.tokens.credential().kind())
            .field("clouds", &self.policy.clouds)
            .field("allowed_vaults", &self.policy.allowed_vaults)
            .field(
                "test_hosts",
                &self
                    .policy
                    .test_hosts
                    .iter()
                    .map(|t| t.host.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Builds an [`AzureProvider`]. No I/O happens at build beyond loading the system's root
/// certificates.
#[derive(Clone)]
pub struct AzureProviderBuilder {
    credential: Option<Arc<dyn AzureCredential>>,
    policy: HostPolicy,
    api_version: ApiVersion,
    connect_timeout: Duration,
    request_timeout: Duration,
    pool_idle_timeout: Duration,
    tcp_keepalive: Duration,
    proxy: Proxy,
    http_version: HttpVersion,
    crypto_provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    ca_pem: Option<Vec<u8>>,
    max_response_bytes: usize,
    key_cache_ttl: Duration,
    request_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl std::fmt::Debug for AzureProviderBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureProviderBuilder")
            .field("credential", &self.credential.as_ref().map(|c| c.kind()))
            .field("policy", &self.policy)
            .field("api_version", &self.api_version)
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl Default for AzureProviderBuilder {
    fn default() -> Self {
        Self {
            credential: None,
            policy: HostPolicy::default(),
            api_version: ApiVersion::default(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(50),
            tcp_keepalive: Duration::from_secs(30),
            proxy: Proxy::None,
            http_version: HttpVersion::Http1,
            crypto_provider: None,
            ca_pem: None,
            max_response_bytes: 1024 * 1024,
            key_cache_ttl: Duration::from_secs(600),
            request_counter: None,
        }
    }
}

impl AzureProviderBuilder {
    /// A builder configured from the environment, to adjust before [`build`](Self::build):
    ///
    /// - the credential [`credential_from_env`] selects. With none configured the provider still
    ///   builds, and its first operation is `Configuration` naming the variables (credentials are
    ///   lazy, as on AWS and GCP). A malformed selection (an unknown `ANYKMS_AZURE_CREDENTIAL`, a
    ///   selected credential missing its settings) and `ANYKMS_AZURE_CREDENTIAL=none` are
    ///   `Configuration` here;
    /// - `ANYKMS_AZURE_ALLOWED_VAULTS` (comma-separated exact hosts) narrowing the allowlist.
    ///
    /// Reads environment variables only.
    ///
    /// [`credential_from_env`]: crate::credential_from_env
    pub fn from_env() -> Result<Self> {
        Self::from_get(&crate::cred::process_env)
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment: the credential selection and the selected credential's `AZURE_*` and
    /// `IDENTITY_*` settings come from the lookup too. Every variable is read here; files they
    /// name (`AZURE_FEDERATED_TOKEN_FILE`) are read from the file system on use.
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::from_get(&lookup)
    }

    fn from_get(get: crate::cred::EnvGet<'_>) -> Result<Self> {
        let credential: Arc<dyn AzureCredential> = match crate::cred::kind_from(get)? {
            None => Arc::new(crate::cred::Unconfigured),
            Some(_) => crate::cred::credential_from(get)?,
        };
        let mut b = Self::default().credential_arc(credential);
        if let Some(v) = get("ANYKMS_AZURE_ALLOWED_VAULTS") {
            let hosts: Vec<String> = v
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(str::to_owned)
                .collect();
            if !hosts.is_empty() {
                b = b.allowed_vaults(hosts);
            }
        }
        Ok(b)
    }

    /// The credential (required): [`WorkloadIdentity`](crate::WorkloadIdentity),
    /// [`ManagedIdentity`](crate::ManagedIdentity), [`ClientSecret`](crate::ClientSecret),
    /// [`StaticToken`](crate::StaticToken) or your own [`AzureCredential`].
    pub fn credential(self, credential: impl AzureCredential + 'static) -> Self {
        self.credential_arc(Arc::new(credential))
    }

    /// A shared credential.
    pub fn credential_arc(mut self, credential: Arc<dyn AzureCredential>) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Allows only the host suffixes of `cloud` (callable several times; default: every cloud's
    /// suffixes). A credential mints tokens for its own cloud only: use one provider per cloud.
    pub fn cloud(mut self, cloud: AzureCloud) -> Self {
        if !self.policy.clouds.contains(&cloud) {
            self.policy.clouds.push(cloud);
        }
        self
    }

    /// Narrows the allowlist to these exact hosts (`contoso-prod.vault.azure.net`), each still
    /// under an allowed suffix. Recommended when key URIs come from shared configuration.
    pub fn allowed_vaults<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.policy.allowed_vaults = Some(
            hosts
                .into_iter()
                .map(|h| h.into().to_ascii_lowercase())
                .collect(),
        );
        self
    }

    /// Allows a non-Azure host for tests (Lowkey Vault, a mock server). See [`TestHost`].
    pub fn test_host(mut self, host: TestHost) -> Self {
        self.policy.test_hosts.push(host);
        self
    }

    /// Trusts only the certificates in `pem` for **test hosts** (Azure hosts always use the
    /// system roots). Needs at least one test host.
    pub fn ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_pem = Some(pem.into());
        self
    }

    /// The REST API version (one supported value in 0.x).
    pub fn api_version(mut self, v: ApiVersion) -> Self {
        self.api_version = v;
        self
    }

    /// Connect timeout per attempt (default 2 s).
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Whole-request timeout per attempt (default 10 s). The overall deadline belongs to
    /// `Retry`.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// How long idle connections are kept (default 50 s).
    pub fn pool_idle_timeout(mut self, d: Duration) -> Self {
        self.pool_idle_timeout = d;
        self
    }

    /// TCP keepalive (default 30 s).
    pub fn tcp_keepalive(mut self, d: Duration) -> Self {
        self.tcp_keepalive = d;
        self
    }

    /// The proxy for vault requests (default none; environment variables are ignored).
    pub fn proxy(mut self, p: Proxy) -> Self {
        self.proxy = p;
        self
    }

    /// The HTTP version (default HTTP/1.1; HTTP/2 needs the `http2` feature).
    pub fn http_version(mut self, v: HttpVersion) -> Self {
        self.http_version = v;
        self
    }

    /// The rustls crypto provider (first in the precedence; see the crate docs).
    pub fn crypto_provider(mut self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// The largest response body accepted (default 1 MiB; at least 64 KiB, `Configuration` at
    /// [`build`](Self::build) otherwise).
    pub fn max_response_bytes(mut self, n: usize) -> Self {
        self.max_response_bytes = n;
        self
    }

    /// How long a key bundle read for the key-type check is trusted (default 10 minutes, ±10%
    /// jitter; zero: read before every operation). On a host that refuses versionless
    /// operations, writes on unversioned URIs name the current version from this cache, so they
    /// follow a rotation within this time. Local verification
    /// ([`AzureOptions::local_verify`]) trusts a version's public key for the same time,
    /// counted from its fetch (a disabled version stops verifying within it), and remembers
    /// versions that came back unknown for it too.
    pub fn key_cache_ttl(mut self, ttl: Duration) -> Self {
        self.key_cache_ttl = ttl;
        self
    }

    /// Counts every vault request in `counter` (conformance fixtures). Not part of the public API.
    #[doc(hidden)]
    pub fn __count_requests(mut self, counter: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.request_counter = Some(counter);
        self
    }

    /// Validates the configuration and builds the HTTP clients.
    pub fn build(self) -> Result<AzureProvider> {
        let credential = self
            .credential
            .ok_or_else(|| config_err("no credential configured"))?;
        if self.connect_timeout.is_zero() || self.request_timeout.is_zero() {
            return Err(config_err(
                "connect_timeout and request_timeout must be greater than zero",
            ));
        }
        if self.max_response_bytes < anykms_http::client::MIN_RESPONSE_BYTES {
            return Err(config_err(
                "max_response_bytes must be at least 64 KiB (anykms_http::client::MIN_RESPONSE_BYTES)",
            ));
        }
        if self.http_version == HttpVersion::Http2 && !cfg!(feature = "http2") {
            return Err(config_err(
                "HttpVersion::Http2 requires the `http2` feature",
            ));
        }
        for t in &self.policy.test_hosts {
            t.validate()?;
        }
        if self.ca_pem.is_some() && self.policy.test_hosts.is_empty() {
            return Err(config_err(
                "ca_pem applies to test hosts only, and none is configured",
            ));
        }
        if let Some(v) = &self.policy.allowed_vaults {
            if v.is_empty() {
                return Err(config_err("allowed_vaults is empty"));
            }
            for h in v {
                let parsed = crate::uri::parse_host(h)
                    .map_err(|_| config_err("invalid host in allowed_vaults"))?;
                if self.policy.resolve(&parsed).is_none() {
                    return Err(config_err(format!(
                        "allowed vault {h} is not under an allowed Key Vault or Managed HSM suffix"
                    )));
                }
            }
        }
        let setting = "AzureProviderBuilder::crypto_provider";
        let tls = anykms_http::tls::TlsOptions::new()
            .crypto_provider(self.crypto_provider.clone(), setting)
            .http2(self.http_version == HttpVersion::Http2)
            .build(BACKEND)?;
        let opts = anykms_http::client::ClientOptions::new()
            .connect_timeout(self.connect_timeout)
            .request_timeout(self.request_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
            .tcp_keepalive(self.tcp_keepalive);
        let http = opts
            .clone()
            .http2(self.http_version == HttpVersion::Http2)
            .proxy(match &self.proxy {
                Proxy::None => None,
                Proxy::Url(u) => Some(u.clone()),
            })
            .build(BACKEND, tls)?;
        let test_http = if self.policy.test_hosts.is_empty() {
            None
        } else {
            let tls = anykms_http::tls::TlsOptions::new()
                .ca_pem(self.ca_pem.as_deref())
                .crypto_provider(self.crypto_provider.clone(), setting)
                .require_roots(false)
                .build(BACKEND)?;
            Some(opts.build(BACKEND, tls)?)
        };
        let mut client = Client::new(
            http,
            test_http,
            Tokens::new(credential),
            self.api_version,
            self.max_response_bytes,
            self.key_cache_ttl,
        );
        client.requests = self.request_counter;
        Ok(AzureProvider {
            client: Arc::new(client),
            policy: Arc::new(self.policy),
            cache: Arc::default(),
        })
    }
}

fn open_err(kind: ErrorKind, m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(kind, BACKEND, Operation::Open, m)
}

impl AzureProvider {
    /// Starts building a provider.
    pub fn builder() -> AzureProviderBuilder {
        AzureProviderBuilder::default()
    }

    /// A provider configured from the environment ([`AzureProviderBuilder::from_env`]), built.
    pub fn from_env() -> Result<Self> {
        AzureProviderBuilder::from_env()?.build()
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment ([`AzureProviderBuilder::from_env_with`]), built.
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        AzureProviderBuilder::from_env_with(lookup)?.build()
    }

    /// Resolves a URI to a key context: syntax, then the host allowlist. No I/O.
    fn resolve(&self, uri: impl IntoKeyUri, check: KeyTypeCheck) -> Result<KeyCtx> {
        let uri = uri.into_key_uri()?;
        let written = uri.without_query().to_owned();
        let parsed = AzureKeyRef::parse(&uri).map_err(|e| e.with_resource(&*written))?;
        let resource: Arc<str> = parsed.to_string().into();
        let target = self.policy.resolve(parsed.host()).ok_or_else(|| {
            open_err(
                ErrorKind::Configuration,
                format!(
                    "host {} is not an allowed Key Vault or Managed HSM host",
                    parsed.host()
                ),
            )
            .with_resource(&*resource)
        })?;
        if target.test {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                backend = BACKEND,
                host = %target.host,
                "opening a key on a test host"
            );
        }
        Ok(KeyCtx {
            client: self.client.clone(),
            target: Arc::new(target),
            uri: parsed,
            check,
            cache: self.cache.clone(),
            resource,
        })
    }

    /// Opens an RSA or EC key for `alg` (signing, server-side verification, public keys).
    pub fn digest_signing_key(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
    ) -> Result<AzureDigestKey> {
        self.digest_signing_key_with(uri, alg, &OpenOptions::new())
    }

    /// [`digest_signing_key`](Self::digest_signing_key) with open options: the key-type check
    /// policy, and [`AzureOptions::local_verify`] as an extension (local verification with the
    /// version's public key instead of the vault's `verify`).
    ///
    /// Local verification of an RSA algorithm needs an RSA backend (feature `rsa-aws-lc-rs`, the
    /// default, or `rsa-rustcrypto`); without one it is `Configuration` here.
    pub fn digest_signing_key_with(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<AzureDigestKey> {
        // Parsed first, so every open-time error names the key (P1-6).
        let k = self.resolve(uri, opts.key_type_check)?;
        let named = |e: Error| e.with_resource(&*k.resource);
        alg.require_shape(SigningShape::Digest, BACKEND)
            .map_err(named)?;
        let local_verify = opts
            .extension::<AzureOptions>()
            .is_some_and(|o| o.local_verify);
        let rsa = !matches!(
            alg,
            SignatureAlgorithm::EcdsaP256Sha256
                | SignatureAlgorithm::EcdsaP384Sha384
                | SignatureAlgorithm::EcdsaP521Sha512
        );
        if local_verify && rsa && !cfg!(any(feature = "rsa-aws-lc-rs", feature = "rsa-rustcrypto"))
        {
            return Err(named(open_err(
                ErrorKind::Configuration,
                "local RSA verification needs an RSA backend: enable the anykms-azure \
                 `rsa-aws-lc-rs` or `rsa-rustcrypto` feature",
            )));
        }
        let local = local_verify.then(|| Arc::new(LocalVerifiers::new(self.client.cache_ttl)));
        let sem = semantics::digest(&k, local_verify.then_some(self.client.cache_ttl));
        Ok(AzureDigestKey { k, alg, local, sem })
    }

    /// Opens a key-wrapping key (RSA-OAEP-256; `A256KW` for Managed HSM `oct-HSM` keys).
    pub fn key_wrap_key(&self, uri: impl IntoKeyUri) -> Result<AzureKeyWrapKey> {
        let k = self.resolve(uri, KeyTypeCheck::Describe)?;
        let sem = semantics::key_wrap(&k);
        Ok(AzureKeyWrapKey { k, sem })
    }

    /// Opens a Managed HSM `oct-HSM` AES-256 key. Vault hosts are `Unsupported` (Premium-vault
    /// `oct-HSM` keys are a preview and not opened).
    pub fn aead_key(&self, uri: impl IntoKeyUri) -> Result<AzureAeadKey> {
        let k = self.resolve(uri, KeyTypeCheck::Describe)?;
        require_mhsm(&k, "AES-GCM")?;
        let sem = semantics::aead(&k);
        Ok(AzureAeadKey { k, sem })
    }

    /// Opens a Managed HSM `oct-HSM` HMAC key for `alg` (experimental, feature `mhsm-hmac`).
    #[cfg(feature = "mhsm-hmac")]
    pub fn mac_key(
        &self,
        uri: impl IntoKeyUri,
        alg: anykms_core::MacAlgorithm,
    ) -> Result<crate::AzureMacKey> {
        let k = self.resolve(uri, KeyTypeCheck::Describe)?;
        require_mhsm(&k, "HMAC")?;
        let sem = semantics::mac(&k);
        Ok(crate::AzureMacKey { k, alg, sem })
    }
}

fn require_mhsm(k: &KeyCtx, what: &str) -> Result<()> {
    if k.target.kind == VaultKind::ManagedHsm {
        return Ok(());
    }
    Err(open_err(
        ErrorKind::Unsupported,
        format!(
            "{what} keys are opened on Managed HSM only (Premium-vault oct-HSM keys are a preview)"
        ),
    )
    .with_resource(&*k.resource))
}

fn no_message_signing(uri: &KeyUri, alg: SignatureAlgorithm) -> Error {
    let e = match alg.require_shape(SigningShape::Message, BACKEND) {
        Err(e) => e,
        Ok(()) => open_err(
            ErrorKind::Unsupported,
            "Azure Key Vault has no Ed25519 keys",
        ),
    };
    e.with_resource(uri.without_query())
}

impl Provider for AzureProvider {
    fn schemes(&self) -> &[&'static str] {
        SCHEMES
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        let k = self.digest_signing_key_with(uri, alg, opts)?;
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
        let k = self.digest_signing_key_with(uri, alg, opts)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(DigestVerifierKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    /// Azure has no message-signing (Ed25519) keys: a digest algorithm is `KeyMismatch` (open
    /// it with `digest_signer`), Ed25519 `Unsupported`.
    fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<anykms_core::MessageSignerKey> {
        Err(no_message_signing(uri, alg))
    }

    /// See [`message_signer`](Self::message_signer).
    fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<anykms_core::MessageVerifierKey> {
        Err(no_message_signing(uri, alg))
    }

    fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<PublicKeysKey> {
        let k = self.digest_signing_key_with(uri, alg, opts)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(PublicKeysKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    /// The URI naming `version` (`.../keys/<name>/<version>`). No I/O: the version is not
    /// checked to exist. The URI's own version returns it unchanged; another version, or one
    /// that is not 32 hexadecimal characters, is `Configuration` (`pin` builds configuration,
    /// like the URI it extends).
    fn pin(&self, uri: &KeyUri, version: &KeyVersion) -> Result<KeyUri> {
        let bad = |m: &'static str| {
            open_err(ErrorKind::Configuration, m).with_resource(uri.without_query())
        };
        let r = AzureKeyRef::parse(uri)?;
        let v = crate::uri::parse_version(version.as_str())
            .ok_or_else(|| bad("an Azure key version is 32 hexadecimal characters"))?;
        match r.version() {
            Some(have) if have == v => Ok(uri.clone()),
            Some(_) => Err(bad("the URI already names another key version")),
            None => KeyUri::parse(&r.without_version().with_version(&v)?.to_string()),
        }
    }

    /// Describes any key. `opts` has no effect: describing never runs the key-type check.
    fn describe(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<DescribeKey> {
        let k = self.key_wrap_key(uri)?;
        let r = k.k.resource.clone();
        Ok(DescribeKey::new(BACKEND, Arc::new(k)).with_resource(r))
    }

    /// A key-wrapping key with native wrapping (no rewrap: Azure has no server-side
    /// re-encrypt; envelopes use `rewrap_local`).
    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        let k = Arc::new(
            self.key_wrap_key(uri)?
                .with_key_type_check(opts.key_type_check),
        );
        let sem = k.semantics().clone();
        Ok(KeyWrapKey::new(BACKEND, k.clone())
            .with_describe(k.clone())
            .with_preflight(k.clone())
            .with_public_keys(k.clone())
            .with_resource(k.k.resource.clone())
            .with_concrete(k)
            .with_semantics(sem))
    }

    /// Data keys: on a vault, `KeyWrapDataKeys` over the RSA key's RSA-OAEP-256 wrap (non-empty
    /// AAD is `Unsupported` before any I/O; unwrap with [`key_wrap`](Self::key_wrap) on the same
    /// key). On a Managed HSM, by key type: `EmulatedDataKeys` over AES-GCM for `oct-HSM` keys
    /// (AAD bound; decrypt with [`aead`](Self::aead)), the RSA recipe otherwise.
    fn data_keys(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<DataKeysKey> {
        let wrap = self
            .key_wrap_key(uri)?
            .with_key_type_check(opts.key_type_check);
        let r = wrap.k.resource.clone();
        match wrap.k.target.kind {
            VaultKind::Vault => {
                let dk = anykms_recipes::KeyWrapDataKeys::new(wrap.clone());
                let sem = semantics::data_keys(&wrap.k, false);
                let wrap = Arc::new(wrap);
                Ok(DataKeysKey::new(BACKEND, Arc::new(dk))
                    .with_describe(wrap.clone())
                    .with_preflight(wrap)
                    .with_resource(r)
                    .with_semantics(sem))
            }
            VaultKind::ManagedHsm => {
                let aead = AzureAeadKey {
                    sem: semantics::aead(&wrap.k),
                    k: wrap.k.clone(),
                };
                let sem = semantics::data_keys(&wrap.k, true);
                let dk = MhsmDataKeys { aead, wrap };
                Ok(DataKeysKey::full(BACKEND, dk.clone())
                    .with_preflight(Arc::new(dk))
                    .with_resource(r)
                    .with_semantics(sem))
            }
        }
    }

    /// A Managed HSM AES-GCM key, with data keys from `EmulatedDataKeys` (AAD bound). No
    /// rewrap. Vault hosts: `Unsupported`.
    fn aead(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<AeadKey> {
        let k = Arc::new(self.aead_key(uri)?.with_key_type_check(opts.key_type_check));
        Ok(AeadKey::new(BACKEND, k.clone())
            .with_data_keys(Arc::new(anykms_recipes::EmulatedDataKeys::new(
                (*k).clone(),
            )))
            .with_describe(k.clone())
            .with_preflight(k.clone())
            .with_resource(k.k.resource.clone())
            .with_semantics(k.semantics().clone())
            .with_concrete(k))
    }

    #[cfg(feature = "mhsm-hmac")]
    fn mac(
        &self,
        uri: &KeyUri,
        alg: anykms_core::MacAlgorithm,
        opts: &OpenOptions,
    ) -> Result<anykms_core::MacKey> {
        let k = self
            .mac_key(uri, alg)?
            .with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(anykms_core::MacKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    #[cfg(not(feature = "mhsm-hmac"))]
    fn mac(
        &self,
        uri: &KeyUri,
        _alg: anykms_core::MacAlgorithm,
        _opts: &OpenOptions,
    ) -> Result<anykms_core::MacKey> {
        Err(open_err(
            ErrorKind::Unsupported,
            "Azure MAC keys need the anykms-azure `mhsm-hmac` feature (experimental: HS* input \
             semantics not yet verified)",
        )
        .with_resource(uri.without_query()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `from_env_with`: the selection and the credential's settings come from the lookup only.
    #[test]
    fn from_env_with_reads_the_lookup() {
        fn vars(
            pairs: &[(&'static str, &'static str)],
        ) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static + use<> {
            let pairs = pairs.to_vec();
            move |k| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        }
        let ids = [
            ("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000001"),
            ("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000002"),
        ];
        let kind = |pairs: &[(&'static str, &'static str)]| {
            let b = AzureProviderBuilder::from_env_with(vars(pairs)).unwrap();
            b.credential.as_ref().unwrap().kind()
        };
        assert_eq!(kind(&[]), "unconfigured");
        let mut secret = ids.to_vec();
        secret.push(("AZURE_CLIENT_SECRET", "s"));
        assert_eq!(kind(&secret), "client_secret");
        let mut workload = ids.to_vec();
        workload.push(("AZURE_FEDERATED_TOKEN_FILE", "/var/run/token"));
        assert_eq!(kind(&workload), "workload_identity");
        assert_eq!(
            kind(&[("ANYKMS_AZURE_MANAGED_IDENTITY", "1")]),
            "managed_identity"
        );
        // A selected credential missing its settings, an unknown selection, and `none`.
        for pairs in [
            &[("AZURE_CLIENT_SECRET", "s")][..],
            &[("ANYKMS_AZURE_CREDENTIAL", "bogus")],
            &[("ANYKMS_AZURE_CREDENTIAL", "none")],
            &[("IDENTITY_ENDPOINT", "http://127.0.0.1:1/")],
        ] {
            let e = AzureProviderBuilder::from_env_with(vars(pairs)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{pairs:?}: {e}");
        }
        assert_eq!(
            crate::env_credential_kind_with(vars(&[("ANYKMS_AZURE_CREDENTIAL", "none")])).unwrap(),
            Some(crate::EnvCredentialKind::Disabled)
        );
        let p = AzureProvider::from_env_with(vars(&[(
            "ANYKMS_AZURE_ALLOWED_VAULTS",
            "contoso.vault.azure.net",
        )]))
        .unwrap();
        assert!(
            p.digest_signing_key(
                "azure-kv://contoso.vault.azure.net/keys/k",
                SignatureAlgorithm::EcdsaP256Sha256
            )
            .is_ok()
        );
        let e = p
            .digest_signing_key(
                "azure-kv://fabrikam.vault.azure.net/keys/k",
                SignatureAlgorithm::EcdsaP256Sha256,
            )
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
    }

    #[test]
    fn local_rsa_verification_needs_an_rsa_backend() {
        let p = AzureProvider::builder()
            .credential(crate::StaticToken::new("t"))
            .build()
            .unwrap();
        let uri = "azure-kv://contoso.vault.azure.net/keys/k";
        let local = OpenOptions::new().with_extension(AzureOptions::new().local_verify());
        let r = p.digest_signing_key_with(uri, SignatureAlgorithm::RsaPssSha256, &local);
        if cfg!(any(feature = "rsa-aws-lc-rs", feature = "rsa-rustcrypto")) {
            assert!(r.unwrap().verifies_locally());
        } else {
            assert_eq!(r.unwrap_err().kind(), ErrorKind::Configuration);
        }
        // ECDSA and server-side verification need no RSA backend.
        let ec = p.digest_signing_key_with(uri, SignatureAlgorithm::EcdsaP256Sha256, &local);
        assert!(ec.unwrap().verifies_locally());
        let server = p.digest_signing_key(uri, SignatureAlgorithm::RsaPssSha256);
        assert!(!server.unwrap().verifies_locally());
    }

    /// P1-6: open-time errors after the URI is parsed name the key.
    #[test]
    fn open_errors_name_the_key() {
        let p = AzureProvider::builder()
            .credential(crate::StaticToken::new("t"))
            .build()
            .unwrap();
        let uri: KeyUri = "azure-kv://contoso.vault.azure.net/keys/k?x=1"
            .parse()
            .unwrap();
        let opts = OpenOptions::new();
        for e in [
            p.digest_signer(&uri, SignatureAlgorithm::Ed25519, &opts)
                .unwrap_err(),
            p.public_keys(&uri, SignatureAlgorithm::Ed25519, &opts)
                .unwrap_err(),
            p.message_signer(&uri, SignatureAlgorithm::EcdsaP256Sha256, &opts)
                .unwrap_err(),
        ] {
            assert_eq!(
                e.resource(),
                Some("azure-kv://contoso.vault.azure.net/keys/k"),
                "{e:?}"
            );
        }
    }

    /// P1-11: limits below 64 KiB break key bundle and token responses.
    #[test]
    fn max_response_bytes_has_a_floor() {
        let b = || AzureProvider::builder().credential(crate::StaticToken::new("t"));
        let e = b()
            .max_response_bytes(anykms_http::client::MIN_RESPONSE_BYTES - 1)
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        b().max_response_bytes(anykms_http::client::MIN_RESPONSE_BYTES)
            .build()
            .unwrap();
    }
}
