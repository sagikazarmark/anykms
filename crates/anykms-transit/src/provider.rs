//! The transit provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use anykms_core::{
    AeadKey, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, Error, ErrorKind,
    IntoKeyUri, KeyTypeCheck, KeyUri, KeyWrapKey, MacAlgorithm, MacKey, MessageSignerKey,
    MessageVerifierKey, OpenOptions, Operation, Provider, PublicKeysKey, Result,
    SignatureAlgorithm, SigningShape,
};

use crate::BACKEND;
use crate::client::Server;
use crate::config::{EnvConfig, ServerConfig};
use crate::handles::{
    KeyCtx, TransitAeadKey, TransitDigestKey, TransitEd25519Key, TransitMacKey, TypeCache,
    mac_path, transit_hash,
};
use crate::uri::{SCHEMES, TransitKeyRef};

/// Opens `hashivault://` and `openbao://` keys on configured Vault and OpenBao servers.
#[derive(Clone)]
pub struct TransitProvider {
    servers: BTreeMap<String, Arc<Server>>,
    default: Option<String>,
    cache: Arc<TypeCache>,
}

impl std::fmt::Debug for TransitProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitProvider")
            .field("servers", &self.servers.values().collect::<Vec<_>>())
            .field("default", &self.default)
            .finish()
    }
}

/// Builds a [`TransitProvider`].
#[derive(Debug, Default)]
pub struct TransitProviderBuilder {
    servers: Vec<(String, ServerConfig)>,
    default: Option<String>,
}

fn config_err(m: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

impl TransitProviderBuilder {
    /// Adds a server under `alias` (the authority of key URIs: `hashivault://<alias>/...`).
    pub fn server(mut self, alias: impl Into<String>, config: ServerConfig) -> Self {
        self.servers.push((alias.into(), config));
        self
    }

    /// The server used by URIs with an empty alias (`hashivault:///...`). Defaults to the server
    /// named `default`, or the only server.
    pub fn default_server(mut self, alias: impl Into<String>) -> Self {
        self.default = Some(alias.into());
        self
    }

    /// Validates the configuration and builds the HTTP clients.
    pub fn build(self) -> Result<TransitProvider> {
        let mut servers = BTreeMap::new();
        for (alias, cfg) in self.servers {
            if alias.is_empty()
                || !alias
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            {
                return Err(config_err(
                    "server aliases must be non-empty and use A-Z a-z 0-9 _ -",
                ));
            }
            let server = Server::new(alias.clone(), cfg)?;
            if servers.insert(alias, Arc::new(server)).is_some() {
                return Err(config_err("duplicate server alias"));
            }
        }
        if servers.is_empty() {
            return Err(config_err("no servers configured"));
        }
        let default = match self.default {
            Some(d) if servers.contains_key(&d) => Some(d),
            Some(_) => return Err(config_err("the default server alias is not configured")),
            None if servers.contains_key("default") => Some("default".to_owned()),
            None if servers.len() == 1 => servers.keys().next().cloned(),
            None => None,
        };
        Ok(TransitProvider {
            servers,
            default,
            cache: Arc::default(),
        })
    }
}

impl TransitProvider {
    /// Starts building a provider.
    pub fn builder() -> TransitProviderBuilder {
        TransitProviderBuilder::default()
    }

    /// One Vault server configured from `VAULT_*` environment variables (see [`EnvConfig`]).
    pub fn from_env() -> Result<Self> {
        Self::builder()
            .server("default", EnvConfig::vault().load()?)
            .build()
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment. The lookup is kept for variables read later (see [`EnvConfig::load_with`]).
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::builder()
            .server("default", EnvConfig::vault().load_with(lookup)?)
            .build()
    }

    /// One OpenBao server configured from `BAO_*` (falling back to `VAULT_*`) variables.
    pub fn from_env_openbao() -> Result<Self> {
        Self::builder()
            .server("default", EnvConfig::openbao().load()?)
            .build()
    }

    /// Like [`from_env_openbao`](Self::from_env_openbao), reading variables from `lookup` instead
    /// of the process environment (see [`EnvConfig::load_with`]).
    pub fn from_env_openbao_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::builder()
            .server("default", EnvConfig::openbao().load_with(lookup)?)
            .build()
    }

    /// Resolves a URI to a key context. Errors carry the key's resource: the URI without its
    /// query string when it does not parse, the key as written in it after that.
    fn resolve(&self, uri: impl IntoKeyUri, check: KeyTypeCheck) -> Result<KeyCtx> {
        let uri = uri.into_key_uri()?;
        let r = TransitKeyRef::parse(&uri).map_err(|e| e.with_resource(uri.without_query()))?;
        // No error below names a resource yet.
        let written = KeyCtx::resource(uri.scheme(), &r.alias, &r.mount, &r.name, None);
        self.resolve_inner(uri.scheme(), r, check)
            .map_err(|e| e.with_resource(&*written))
    }

    fn resolve_inner(&self, scheme: &str, r: TransitKeyRef, check: KeyTypeCheck) -> Result<KeyCtx> {
        let alias = if r.alias.is_empty() {
            self.default.as_deref().ok_or_else(|| {
                Error::new(
                    ErrorKind::Configuration,
                    BACKEND,
                    Operation::Open,
                    "URI has no server alias and no default server is configured",
                )
            })?
        } else {
            r.alias.as_str()
        };
        let server = self.servers.get(alias).ok_or_else(|| {
            Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "unknown server alias",
            )
        })?;
        let cfg = &server.cfg;
        let listed = cfg
            .allowed_mounts
            .as_ref()
            .map(|mounts| mounts.contains(&r.mount));
        if listed == Some(false) {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "mount is not allowed for this server",
            ));
        }
        // Vault Enterprise resolves leading path segments as (child) namespaces, so a
        // multi-segment mount like `team-b/transit` reaches namespace `team-b` without passing
        // the `allowed_namespaces` check. Such mounts need an explicit opt-in.
        if r.is_multi_segment_mount() && listed != Some(true) {
            return Err(Error::new(
                ErrorKind::Configuration,
                BACKEND,
                Operation::Open,
                "multi-segment mount paths must be listed in ServerConfig::allowed_mounts \
                 (leading path segments can select a Vault Enterprise namespace, bypassing \
                 allowed_namespaces); select namespaces with ?namespace= instead",
            ));
        }
        let namespace = match r.namespace {
            None => cfg.namespace.clone(),
            Some(ns)
                if cfg.namespace.as_deref() == Some(ns.as_str())
                    || cfg.allowed_namespaces.contains(&ns) =>
            {
                Some(ns)
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Configuration,
                    BACKEND,
                    Operation::Open,
                    "URI namespace is neither the server namespace nor in allowed_namespaces",
                ));
            }
        };
        let resource = KeyCtx::resource(
            scheme,
            &server.alias,
            &r.mount,
            &r.name,
            namespace.as_deref(),
        );
        Ok(KeyCtx {
            cache_key: KeyCtx::cache_key_of(&server.alias, namespace.as_deref(), &r.mount, &r.name),
            resource,
            server: server.clone(),
            mount: r.mount,
            name: r.name,
            namespace,
            check,
            cache: self.cache.clone(),
        })
    }

    /// Opens an AEAD key. No I/O; the key type is checked before the first operation.
    pub fn aead_key(&self, uri: impl IntoKeyUri) -> Result<TransitAeadKey> {
        Ok(TransitAeadKey {
            k: self.resolve(uri, KeyTypeCheck::Describe)?,
            weak_kek_warned: Arc::default(),
        })
    }

    /// Opens an ECDSA or RSA key for `alg`.
    pub fn digest_signing_key(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
    ) -> Result<TransitDigestKey> {
        let uri = uri.into_key_uri()?;
        if alg.is_message_signing() {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                Operation::Open,
                "Ed25519 signs messages; use ed25519_key",
            )
            .with_resource(uri.without_query()));
        }
        if let Some(h) = alg.hash() {
            transit_hash(h, Operation::Open).map_err(|e| e.with_resource(uri.without_query()))?;
        }
        Ok(TransitDigestKey {
            k: self.resolve(uri, KeyTypeCheck::Describe)?,
            alg,
        })
    }

    /// Opens an Ed25519 key.
    pub fn ed25519_key(&self, uri: impl IntoKeyUri) -> Result<TransitEd25519Key> {
        Ok(TransitEd25519Key {
            k: self.resolve(uri, KeyTypeCheck::Describe)?,
        })
    }

    /// Opens an HMAC key for `alg`.
    pub fn mac_key(&self, uri: impl IntoKeyUri, alg: MacAlgorithm) -> Result<TransitMacKey> {
        let uri = uri.into_key_uri()?;
        mac_path(alg, Operation::Open).map_err(|e| e.with_resource(uri.without_query()))?;
        Ok(TransitMacKey {
            k: self.resolve(uri, KeyTypeCheck::Describe)?,
            alg,
        })
    }
}

/// [`SignatureAlgorithm::require_shape`], naming the key (`uri` without its query string) on
/// failure, as every error after the URI is parsed does.
fn require_shape(uri: &KeyUri, alg: SignatureAlgorithm, shape: SigningShape) -> Result<()> {
    alg.require_shape(shape, BACKEND)
        .map_err(|e| e.with_resource(uri.without_query()))
}

impl Provider for TransitProvider {
    fn schemes(&self) -> &[&'static str] {
        SCHEMES
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    fn aead(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<AeadKey> {
        let k = self.aead_key(uri)?.with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(AeadKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k.clone()))
            .with_wrapped_data_keys(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    /// An AEAD key as a data-key source (`datakey/plaintext`, with the AAD rules of
    /// [`TransitAeadKey`]'s `DataKeys`), with describe.
    fn data_keys(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<DataKeysKey> {
        let k = self.aead_key(uri)?.with_key_type_check(opts.key_type_check);
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok(DataKeysKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(sem))
    }

    /// An AEAD key as a KEK, wrapping with empty AAD (transit has no separate wrap operation);
    /// server-side rewrap stays available. Warns about `aes128-gcm96` KEKs (see
    /// [`TransitAeadKey`]).
    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        let k = Arc::new(self.aead_key(uri)?.with_key_type_check(opts.key_type_check));
        Ok(
            KeyWrapKey::new(BACKEND, Arc::new(crate::handles::TransitKek((*k).clone())))
                .with_rewrap(k.clone())
                .with_describe(k.clone())
                .with_preflight(k.clone())
                .with_resource(k.k.resource.clone())
                .with_semantics(k.k.server.semantics.key_wrap.clone())
                .with_concrete(k),
        )
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        require_shape(uri, alg, SigningShape::Digest)?;
        let k = self.digest_signing_key(uri, alg)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok({
            let k = k.with_key_type_check(opts.key_type_check);
            DigestSignerKey::full(BACKEND, k.clone()).with_preflight(Arc::new(k))
        }
        .with_resource(r)
        .with_semantics(sem))
    }

    fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestVerifierKey> {
        require_shape(uri, alg, SigningShape::Digest)?;
        let k = self.digest_signing_key(uri, alg)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok({
            let k = k.with_key_type_check(opts.key_type_check);
            DigestVerifierKey::full(BACKEND, k.clone()).with_preflight(Arc::new(k))
        }
        .with_resource(r)
        .with_semantics(sem))
    }

    fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<MessageSignerKey> {
        require_shape(uri, alg, SigningShape::Message)?;
        let k = self.ed25519_key(uri)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok({
            let k = k.with_key_type_check(opts.key_type_check);
            MessageSignerKey::full(BACKEND, k.clone()).with_preflight(Arc::new(k))
        }
        .with_resource(r)
        .with_semantics(sem))
    }

    fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<MessageVerifierKey> {
        require_shape(uri, alg, SigningShape::Message)?;
        let k = self.ed25519_key(uri)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok({
            let k = k.with_key_type_check(opts.key_type_check);
            MessageVerifierKey::full(BACKEND, k.clone()).with_preflight(Arc::new(k))
        }
        .with_resource(r)
        .with_semantics(sem))
    }

    fn mac(&self, uri: &KeyUri, alg: MacAlgorithm, opts: &OpenOptions) -> Result<MacKey> {
        let k = self.mac_key(uri, alg)?;
        let r = k.k.resource.clone();
        let sem = k.semantics().clone();
        Ok({
            let k = k.with_key_type_check(opts.key_type_check);
            MacKey::full(BACKEND, k.clone()).with_preflight(Arc::new(k))
        }
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

    /// Describes any key type. `opts` has no effect: describing reads the key's metadata and
    /// never runs the key-type check, and transit defines no open-option extensions.
    /// The handle declares no [`KeySemantics`](anykms_core::KeySemantics): the key's family
    /// (which decides them) is unknown until the metadata is read.
    fn describe(&self, uri: &KeyUri, _opts: &OpenOptions) -> Result<DescribeKey> {
        let k = self.aead_key(uri)?;
        let r = k.k.resource.clone();
        Ok(DescribeKey::new(BACKEND, Arc::new(k)).with_resource(r))
    }
}
