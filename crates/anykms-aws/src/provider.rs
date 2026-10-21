//! The AWS KMS provider.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use anykms_core::{
    AeadKey, DataKeysKey, DescribeKey, DigestSignerKey, DigestVerifierKey, Error, ErrorKind,
    IntoKeyUri, KeyTypeCheck, KeyUri, KeyWrapKey, MacAlgorithm, MacKey, MessageSignerKey,
    MessageVerifierKey, OpenOptions, Operation, Provider, PublicKeysKey, Result,
    SignatureAlgorithm, SigningShape,
};

use crate::BACKEND;
use crate::client::{Http, Kms};
use crate::config::AwsProviderBuilder;
use crate::context::GrantTokens;
use crate::credentials::{CredentialSource, DefaultChain};
use crate::handles::{
    AwsAeadKey, AwsDigestKey, AwsEd25519Key, AwsKeyWrapKey, AwsMacKey, DescribeCache, KeyCtx,
    PublicKeyCache,
};
use crate::semantics;
use crate::uri::{AwsKeyRef, SCHEMES};

/// Opens `aws-kms://arn:...` keys. Cheap to clone (shared state).
#[derive(Clone)]
pub struct AwsProvider {
    inner: Arc<Inner>,
}

struct Inner {
    kms: Arc<Kms>,
    allowed_accounts: Option<BTreeSet<String>>,
    allowed_regions: Option<BTreeSet<String>>,
    /// Configured endpoints, validated at build: per region and global. Derived endpoints are
    /// computed on each open (a `format!`), so nothing grows with the regions of opened URIs.
    endpoints: BTreeMap<String, Arc<reqwest::Url>>,
    endpoint_url: Option<Arc<reqwest::Url>>,
    fips: bool,
    dual_stack: bool,
    #[cfg_attr(not(feature = "__test-fixtures"), allow(dead_code))]
    allow_loopback_http: bool,
    cache: Arc<DescribeCache>,
    public_keys: Arc<PublicKeyCache>,
}

impl std::fmt::Debug for AwsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = &self.inner;
        f.debug_struct("AwsProvider")
            .field("credentials", &i.kms.creds.source.kind())
            .field("allowed_accounts", &i.allowed_accounts)
            .field("allowed_regions", &i.allowed_regions)
            .field(
                "endpoints",
                &i.endpoints
                    .iter()
                    .map(|(r, u)| (r, crate::config::redacted_url(u.as_str())))
                    .collect::<BTreeMap<_, _>>(),
            )
            .field(
                "endpoint_url",
                &i.endpoint_url
                    .as_ref()
                    .map(|u| crate::config::redacted_url(u.as_str())),
            )
            .field("fips", &i.fips)
            .field("dual_stack", &i.dual_stack)
            .finish()
    }
}

impl AwsProviderBuilder {
    /// Validates the configuration and builds the KMS HTTP client: the TLS roots (system or
    /// [`ca_pem`](Self::ca_pem)) and the rustls crypto provider are resolved here, so a broken
    /// TLS configuration is `Configuration` now. No network I/O: credentials are resolved on
    /// the first operation.
    pub fn build(mut self) -> Result<AwsProvider> {
        self.validate()?;
        let parse = |u: &str| {
            crate::endpoint::validate_url(u, self.allow_loopback_http, "the KMS endpoint")
                .map(Arc::new)
        };
        let endpoints = self
            .endpoints
            .iter()
            .map(|(r, u)| Ok((r.clone(), parse(u)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let endpoint_url = self.endpoint_url.as_deref().map(parse).transpose()?;
        let http = Arc::new(Http::new(self.http.clone())?);
        let source: Arc<dyn CredentialSource> = match self.credentials.take() {
            Some(s) => s,
            None => Arc::new(match self.vars.take() {
                Some(v) => DefaultChain::from_vars(v),
                None => DefaultChain::new(),
            }),
        };
        #[cfg(feature = "tracing")]
        tracing::info!(
            backend = BACKEND,
            source = source.kind(),
            "AWS credential source configured"
        );
        Ok(AwsProvider {
            inner: Arc::new(Inner {
                kms: Arc::new({
                    let mut kms = Kms::new(http, source);
                    kms.requests = self.request_counter.take();
                    kms
                }),
                allowed_accounts: self.allowed_accounts,
                allowed_regions: self.allowed_regions,
                endpoints,
                endpoint_url,
                fips: self.fips,
                dual_stack: self.dual_stack,
                allow_loopback_http: self.allow_loopback_http,
                cache: Arc::default(),
                public_keys: Arc::default(),
            }),
        })
    }
}

fn open_err(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Open, m)
}

/// P1-6: an error raised after the URI is parsed names the key (`uri.without_query()`), unless
/// it already does.
fn named<T>(uri: &KeyUri, r: Result<T>) -> Result<T> {
    r.map_err(|e| {
        if e.resource().is_some() {
            e
        } else {
            e.with_resource(uri.without_query())
        }
    })
}

impl AwsProvider {
    /// Starts building a provider.
    pub fn builder() -> AwsProviderBuilder {
        AwsProviderBuilder::new()
    }

    /// A provider configured from the environment (see [`AwsProviderBuilder::from_env`]). Needs
    /// no variable and does no network I/O (it reads `AWS_CA_BUNDLE` when set, and the trust
    /// store).
    pub fn from_env() -> Result<Self> {
        AwsProviderBuilder::from_env()?.build()
    }

    /// Like [`from_env`](Self::from_env), reading variables from `lookup` instead of the process
    /// environment (see [`AwsProviderBuilder::from_env_with`]).
    pub fn from_env_with(
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Result<Self> {
        AwsProviderBuilder::from_env_with(lookup)?.build()
    }

    /// The endpoint for a key: per-region override, global override, derived.
    fn endpoint_for(&self, r: &AwsKeyRef) -> Result<Arc<reqwest::Url>> {
        let i = &self.inner;
        if let Some(u) = i.endpoints.get(&r.region).or(i.endpoint_url.as_ref()) {
            return Ok(u.clone());
        }
        let raw = crate::endpoint::derive(&r.partition, &r.region, i.fips, i.dual_stack)?;
        crate::endpoint::validate_url(&raw, false, "the KMS endpoint")
            .map(Arc::new)
            .map_err(|e| e.with_operation(Operation::Open))
    }

    fn resolve(&self, uri: impl IntoKeyUri, opts: Option<&OpenOptions>) -> Result<KeyCtx> {
        let uri = uri.into_key_uri()?;
        let r = AwsKeyRef::parse(&uri).map_err(|e| e.with_resource(uri.without_query()))?;
        let resource = KeyCtx::resource_of(&r);
        self.resolve_inner(r, opts, resource.clone())
            .map_err(|e| e.with_resource(&*resource))
    }

    fn resolve_inner(
        &self,
        r: AwsKeyRef,
        opts: Option<&OpenOptions>,
        resource: Arc<str>,
    ) -> Result<KeyCtx> {
        let i = &self.inner;
        if i.allowed_accounts
            .as_ref()
            .is_some_and(|a| !a.contains(&r.account))
        {
            return Err(open_err("the key's account is not in the allowed accounts"));
        }
        if i.allowed_regions
            .as_ref()
            .is_some_and(|a| !a.contains(&r.region))
        {
            return Err(open_err("the key's region is not in the allowed regions"));
        }
        let endpoint = self.endpoint_for(&r)?;
        let resolved = (!r.is_alias()).then(|| r.arn.clone());
        Ok(KeyCtx {
            kms: i.kms.clone(),
            endpoint,
            check: opts.map_or(KeyTypeCheck::Describe, |o| o.key_type_check),
            cache: i.cache.clone(),
            public_keys: i.public_keys.clone(),
            resource,
            grant_tokens: opts.and_then(|o| o.extension::<GrantTokens>()).cloned(),
            resolved: Arc::new(Mutex::new(resolved)),
            key: Arc::new(r),
        })
    }

    /// Opens a symmetric key. No I/O; the key type is checked before the first operation.
    pub fn aead_key(&self, uri: impl IntoKeyUri) -> Result<AwsAeadKey> {
        Ok(AwsAeadKey {
            k: self.resolve(uri, None)?,
        })
    }

    /// Opens a symmetric or RSA encryption key as an envelope KEK.
    pub fn key_wrap_key(&self, uri: impl IntoKeyUri) -> Result<AwsKeyWrapKey> {
        Ok(AwsKeyWrapKey {
            k: self.resolve(uri, None)?,
        })
    }

    /// Opens an ECDSA or RSA signing key for `alg`.
    pub fn digest_signing_key(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
    ) -> Result<AwsDigestKey> {
        self.digest_key(uri, alg, None)
    }

    fn digest_key(
        &self,
        uri: impl IntoKeyUri,
        alg: SignatureAlgorithm,
        opts: Option<&OpenOptions>,
    ) -> Result<AwsDigestKey> {
        // Parsed first, so the algorithm checks name the key (P1-6).
        let k = self.resolve(uri, opts)?;
        if alg.is_message_signing() {
            return Err(Error::new(
                ErrorKind::KeyMismatch,
                BACKEND,
                Operation::Open,
                "Ed25519 signs messages; use ed25519_key",
            )
            .with_resource(&*k.resource));
        }
        if crate::keyinfo::aws_signing_alg(alg).is_none() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                Operation::Open,
                "signature algorithm",
            )
            .with_resource(&*k.resource));
        }
        Ok(AwsDigestKey { k, alg })
    }

    /// Opens an Ed25519 key.
    pub fn ed25519_key(&self, uri: impl IntoKeyUri) -> Result<AwsEd25519Key> {
        Ok(AwsEd25519Key {
            k: self.resolve(uri, None)?,
        })
    }

    /// Opens an HMAC key for `alg`.
    pub fn mac_key(&self, uri: impl IntoKeyUri, alg: MacAlgorithm) -> Result<AwsMacKey> {
        self.mac_key_with(uri, alg, None)
    }

    fn mac_key_with(
        &self,
        uri: impl IntoKeyUri,
        alg: MacAlgorithm,
        opts: Option<&OpenOptions>,
    ) -> Result<AwsMacKey> {
        // Parsed first, so the algorithm check names the key (P1-6).
        let k = self.resolve(uri, opts)?;
        if crate::keyinfo::aws_mac_alg(alg).is_none() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                BACKEND,
                Operation::Open,
                "MAC algorithm",
            )
            .with_resource(&*k.resource));
        }
        Ok(AwsMacKey { k, alg })
    }

    #[doc(hidden)]
    /// The KMS client, for the hidden admin calls of the test fixtures (`__test-fixtures`
    /// feature; never enable it in production builds).
    #[cfg(feature = "__test-fixtures")]
    pub fn __admin(&self) -> crate::admin::Admin {
        crate::admin::Admin {
            kms: self.inner.kms.clone(),
            allow_loopback_http: self.inner.allow_loopback_http,
        }
    }

    #[doc(hidden)]
    /// The endpoint a key URI resolves to (tests).
    pub fn __endpoint(&self, uri: &str) -> Result<String> {
        let r = AwsKeyRef::parse(&uri.into_key_uri()?)?;
        Ok(self.endpoint_for(&r)?.to_string())
    }
}

impl Provider for AwsProvider {
    fn schemes(&self) -> &[&'static str] {
        SCHEMES
    }

    fn name(&self) -> &'static str {
        BACKEND
    }

    fn aead(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<AeadKey> {
        let k = AwsAeadKey {
            k: self.resolve(uri, Some(opts))?,
        };
        let r = k.k.resource.clone();
        Ok(AeadKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k.clone()))
            .with_wrapped_data_keys(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::AEAD.clone()))
    }

    /// A symmetric key as a data-key source (`GenerateDataKey`, AAD bound), with describe.
    fn data_keys(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<DataKeysKey> {
        let k = AwsAeadKey {
            k: self.resolve(uri, Some(opts))?,
        };
        let r = k.k.resource.clone();
        Ok(DataKeysKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::DATA_KEYS.clone()))
    }

    /// A symmetric key (wrapping with `Encrypt`, no context) or an RSA encryption key (local
    /// RSA-OAEP-SHA-256 wrap, `Decrypt` unwrap) as a KEK; see [`AwsKeyWrapKey`]. The public-key
    /// part serves RSA KEKs (to wrap offline); a symmetric KEK refuses it (`KeyMismatch`).
    fn key_wrap(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<KeyWrapKey> {
        let k = AwsKeyWrapKey {
            k: self.resolve(uri, Some(opts))?,
        };
        let r = k.k.resource.clone();
        Ok(KeyWrapKey::full(BACKEND, k.clone())
            .with_public_keys(Arc::new(k.clone()))
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::KEY_WRAP.clone()))
    }

    fn digest_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestSignerKey> {
        named(uri, alg.require_shape(SigningShape::Digest, BACKEND))?;
        let k = self.digest_key(uri, alg, Some(opts))?;
        let r = k.k.resource.clone();
        Ok(DigestSignerKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::DIGEST.clone()))
    }

    fn digest_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<DigestVerifierKey> {
        named(uri, alg.require_shape(SigningShape::Digest, BACKEND))?;
        let k = self.digest_key(uri, alg, Some(opts))?;
        let r = k.k.resource.clone();
        Ok(DigestVerifierKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::DIGEST.clone()))
    }

    fn message_signer(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<MessageSignerKey> {
        named(uri, alg.require_shape(SigningShape::Message, BACKEND))?;
        let k = AwsEd25519Key {
            k: self.resolve(uri, Some(opts))?,
        };
        let r = k.k.resource.clone();
        Ok(MessageSignerKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::ED25519.clone()))
    }

    fn message_verifier(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<MessageVerifierKey> {
        named(uri, alg.require_shape(SigningShape::Message, BACKEND))?;
        let k = AwsEd25519Key {
            k: self.resolve(uri, Some(opts))?,
        };
        let r = k.k.resource.clone();
        Ok(MessageVerifierKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::ED25519.clone()))
    }

    fn mac(&self, uri: &KeyUri, alg: MacAlgorithm, opts: &OpenOptions) -> Result<MacKey> {
        let k = self.mac_key_with(uri, alg, Some(opts))?;
        let r = k.k.resource.clone();
        Ok(MacKey::full(BACKEND, k.clone())
            .with_preflight(Arc::new(k))
            .with_resource(r)
            .with_semantics(semantics::MAC.clone()))
    }

    fn public_keys(
        &self,
        uri: &KeyUri,
        alg: SignatureAlgorithm,
        opts: &OpenOptions,
    ) -> Result<PublicKeysKey> {
        if alg.is_message_signing() {
            let k = AwsEd25519Key {
                k: self.resolve(uri, Some(opts))?,
            };
            let r = k.k.resource.clone();
            Ok(PublicKeysKey::full(BACKEND, k.clone())
                .with_preflight(Arc::new(k))
                .with_resource(r)
                .with_semantics(semantics::PUBLIC_KEYS.clone()))
        } else {
            let k = self.digest_key(uri, alg, Some(opts))?;
            let r = k.k.resource.clone();
            Ok(PublicKeysKey::full(BACKEND, k.clone())
                .with_preflight(Arc::new(k))
                .with_resource(r)
                .with_semantics(semantics::PUBLIC_KEYS.clone()))
        }
    }

    /// Describes any key (`DescribeKey`; never runs the key-type check).
    fn describe(&self, uri: &KeyUri, opts: &OpenOptions) -> Result<DescribeKey> {
        let k = AwsAeadKey {
            k: self.resolve(uri, Some(opts))?,
        };
        let r = k.k.resource.clone();
        Ok(DescribeKey::full(BACKEND, k)
            .with_resource(r)
            .with_semantics(semantics::DESCRIBE.clone()))
    }
}
