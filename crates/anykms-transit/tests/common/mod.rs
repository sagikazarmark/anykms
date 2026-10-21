//! Conformance fixture for Vault and OpenBao dev servers (see compose.yaml / scripts/dev-up.sh).
//!
//! The root token is used only here, for key management; the provider under test uses a
//! least-privilege token created by the fixture.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anykms_conformance::{
    AeadKeyHandles, Counting, DigestKeyHandles, Feature, Fixture, FixtureCaps, KeyUse,
    MacKeyHandles, MessageKeyHandles, TestKey, TestKeyKind, TypedHandles,
};
use anykms_core::{
    AeadKey, BoxFuture, Ciphertext, Error, ErrorKind, KeyUri, KeyVersion, MacAlgorithm, Operation,
    Provider, Result, SignatureAlgorithm,
};
use anykms_transit::{Flavor, ServerConfig, StaticToken, TokenSource, TransitProvider};
use base64::Engine as _;
use serde_json::{Value, json};

pub const POLICY: &str = r#"
path "transit/encrypt/*"          { capabilities = ["update"] }
path "transit/decrypt/*"          { capabilities = ["update"] }
path "transit/rewrap/*"           { capabilities = ["update"] }
path "transit/datakey/plaintext/*" { capabilities = ["update"] }
path "transit/datakey/wrapped/*"  { capabilities = ["update"] }
path "transit/datakey/wrapped/*"   { capabilities = ["update"] }
path "transit/sign/*"             { capabilities = ["update"] }
path "transit/verify/*"           { capabilities = ["update"] }
path "transit/hmac/*"             { capabilities = ["update"] }
path "transit/keys/*"             { capabilities = ["read"] }
"#;

pub struct Admin {
    pub addr: String,
    pub root: String,
    pub http: reqwest::Client,
}

fn fx_err(m: String) -> Error {
    Error::new(ErrorKind::Backend, "fixture", Operation::Configure, m)
}

impl Admin {
    pub async fn req(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut r = self
            .http
            .request(method, format!("{}/v1/{path}", self.addr))
            .header("X-Vault-Token", &self.root);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r
            .send()
            .await
            .map_err(|e| fx_err(format!("admin request {path}: {e}")))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(fx_err(format!("admin request {path}: {status}: {text}")));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

/// The typed API: `TransitProvider`'s typed constructors (`aead_key`, `digest_signing_key`, ...),
/// bridged into the dyn layer, rather than its `Provider` implementation.
pub struct TransitTyped(pub Arc<TransitProvider>);

impl TypedHandles for TransitTyped {
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        let k = Arc::new(self.0.aead_key(uri)?);
        let s = k.semantics().clone();
        Ok(AeadKeyHandles::bridge(k.clone())
            .with_rewrap(k.clone())
            .with_data_keys(k.clone())
            .with_wrapped_data_keys(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }

    fn digest_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<DigestKeyHandles> {
        let k = Arc::new(self.0.digest_signing_key(uri, alg)?);
        let s = k.semantics().clone();
        Ok(DigestKeyHandles::bridge(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }

    fn message_key(&self, uri: &KeyUri) -> Result<MessageKeyHandles> {
        let k = Arc::new(self.0.ed25519_key(uri)?);
        let s = k.semantics().clone();
        Ok(MessageKeyHandles::bridge(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }

    fn mac_key(&self, uri: &KeyUri, alg: MacAlgorithm) -> Result<MacKeyHandles> {
        let k = Arc::new(self.0.mac_key(uri, alg)?);
        let s = k.semantics().clone();
        Ok(MacKeyHandles::bridge(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }
}

/// Counts requests: the client asks its token source once per HTTP request (and once more for
/// the single retry after a 403).
#[derive(Debug)]
struct CountingToken {
    inner: StaticToken,
    count: Arc<AtomicU64>,
}

impl TokenSource for CountingToken {
    fn token(&self) -> BoxFuture<'_, Result<Option<anykms_transit::Token>>> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.token()
    }
}

pub struct TransitFixture {
    pub name: &'static str,
    pub flavor: Flavor,
    pub admin: Admin,
    pub version: String,
    pub data_token: String,
    pub provider: Arc<TransitProvider>,
    counter: AtomicU64,
    run_id: String,
    /// The (invalid) token of the unauthorized provider; unique, so leaks are detectable.
    denied_token: String,
}

fn parse_version(v: &str) -> (u64, u64) {
    let mut it = v
        .split(['.', '-', '+'])
        .map(|x| x.parse::<u64>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

impl TransitFixture {
    pub async fn connect(name: &'static str, flavor: Flavor) -> std::result::Result<Self, String> {
        let (addr_var, default_addr) = match flavor {
            Flavor::OpenBao => ("ANYKMS_OPENBAO_ADDR", "http://127.0.0.1:8300"),
            _ => ("ANYKMS_VAULT_ADDR", "http://127.0.0.1:8200"),
        };
        let addr = std::env::var(addr_var).unwrap_or_else(|_| default_addr.to_owned());
        let root = std::env::var("ANYKMS_ROOT_TOKEN").unwrap_or_else(|_| "root".to_owned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;
        let admin = Admin {
            addr: addr.clone(),
            root,
            http,
        };
        let health = admin
            .req(reqwest::Method::GET, "sys/health", None)
            .await
            .map_err(|e| {
                format!("{name} server at {addr} unreachable (run scripts/dev-up.sh): {e}")
            })?;
        let version = health["version"].as_str().unwrap_or_default().to_owned();
        // Idempotent setup (also done by the compose init containers).
        let _ = admin
            .req(
                reqwest::Method::POST,
                "sys/mounts/transit",
                Some(json!({"type": "transit"})),
            )
            .await;
        admin
            .req(
                reqwest::Method::POST,
                "transit/config/keys",
                Some(json!({"disable_upsert": true})),
            )
            .await
            .map_err(|e| e.to_string())?;
        // Rate-limit response headers, so throttled errors carry Retry-After.
        admin
            .req(
                reqwest::Method::POST,
                "sys/quotas/config",
                Some(json!({"enable_rate_limit_response_headers": true})),
            )
            .await
            .map_err(|e| e.to_string())?;
        admin
            .req(
                reqwest::Method::PUT,
                "sys/policies/acl/anykms-conformance",
                Some(json!({"policy": POLICY})),
            )
            .await
            .map_err(|e| e.to_string())?;
        let tok = admin
            .req(
                reqwest::Method::POST,
                "auth/token/create",
                Some(json!({"policies": ["anykms-conformance"], "ttl": "2h", "no_default_policy": true})),
            )
            .await
            .map_err(|e| e.to_string())?;
        let data_token = tok["auth"]["client_token"]
            .as_str()
            .ok_or("no client token")?
            .to_owned();
        let provider = TransitProvider::builder()
            .server(
                "default",
                ServerConfig::new(addr.clone(), flavor)
                    .token(data_token.clone())
                    .allow_loopback_http(),
            )
            .build()
            .map_err(|e| e.to_string())?;
        let run_id = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let denied_token = format!("anykms-denied-token-{run_id}");
        Ok(Self {
            name,
            flavor,
            admin,
            version,
            data_token,
            provider: Arc::new(provider),
            counter: AtomicU64::new(0),
            run_id,
            denied_token,
        })
    }

    pub fn uri(name: &str) -> KeyUri {
        format!("hashivault:///transit/keys/{name}")
            .parse()
            .expect("valid URI")
    }

    pub async fn create(&self, key_type: &str) -> Result<String> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let name = format!("conf-{}-{n}", self.run_id);
        let body = if key_type == "hmac" {
            json!({"type": key_type, "key_size": 32})
        } else {
            json!({"type": key_type})
        };
        self.admin
            .req(
                reqwest::Method::POST,
                &format!("transit/keys/{name}"),
                Some(body),
            )
            .await?;
        Ok(name)
    }

    pub fn openbao_at_least(&self, major: u64, minor: u64) -> bool {
        self.flavor == Flavor::OpenBao && parse_version(&self.version) >= (major, minor)
    }
}

fn key_type(kind: TestKeyKind) -> Result<&'static str> {
    Ok(match kind {
        TestKeyKind::Aead => "aes256-gcm96",
        TestKeyKind::Hmac(_) => "hmac",
        TestKeyKind::Signing(alg) => match alg {
            SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-p256",
            SignatureAlgorithm::EcdsaP384Sha384 => "ecdsa-p384",
            SignatureAlgorithm::EcdsaP521Sha512 => "ecdsa-p521",
            SignatureAlgorithm::Ed25519 => "ed25519",
            _ => "rsa-2048",
        },
        // Transit's RSA keys sign; they have no wrap operation.
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "fixture",
                Operation::Configure,
                format!("transit has no {kind:?} keys"),
            ));
        }
    })
}

impl Fixture for TransitFixture {
    fn backend_info_type(&self) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<anykms_transit::TransitKeyInfo>())
    }

    fn name(&self) -> &str {
        self.name
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::{
            Aead, DataKeys, Describe, DisableVersion, EmptyMessage, EmptyPlaintext, Extension,
            KeyWrap, KeyWrapRewrap, Mac, MacInputLimit, MessageInputLimit, MinDecryptionVersion,
            NativeCiphertext, RequestCount, Rewrap, Rotate, RotateKeyWrap, RotateMac,
            RotateSigning, ServerErrorMessages, Throttle, UnauthorizedProvider, WrappedDataKeys,
        };
        let mut caps = FixtureCaps::new()
            .not_applicable(Feature::KeyWrapPublicKeys, "no RSA key-wrapping keys")
            .supports(Feature::BackendInfo)
            .supports_all(&[
                Aead,
                Rewrap,
                DataKeys,
                WrappedDataKeys,
                Extension,
                Mac,
                Describe,
                Rotate,
                RotateMac,
                RotateSigning,
                MinDecryptionVersion,
                Throttle,
                NativeCiphertext,
                UnauthorizedProvider,
                RequestCount,
                EmptyPlaintext,
                EmptyMessage,
                ServerErrorMessages,
            ])
            .not_applicable(
                Feature::UsedPrimary,
                "decrypt does not report whether the primary version was used",
            )
            .not_applicable(
                KeyWrap,
                "transit AES keys wrap as AEAD keys (KeyWrapKey::from_aead); RSA keys only sign",
            )
            .not_applicable_all(
                &[KeyWrapRewrap, RotateKeyWrap],
                "no native key-wrapping keys",
            )
            .not_applicable(
                DisableVersion,
                "transit versions are retired with min_decryption_version, not one by one",
            )
            .not_applicable(
                MacInputLimit,
                "transit limits only the request size, which a MAC input never reaches here",
            )
            .not_applicable(
                MessageInputLimit,
                "transit limits only the request size, which a message never reaches here",
            )
            // Transit's key read lists no versions for HMAC keys (`keys` is null).
            .not_applicable(
                Feature::RewrapWithAad,
                "transit rewrap ignores associated_data",
            )
            .with_throttle_retry_after(true)
            // Preflight refuses a soft-deleted key (read where `Disable` applies: OpenBao 2.4+).
            .supports(Feature::PreflightState);
        caps = match self.flavor {
            Flavor::OpenBao if self.openbao_at_least(2, 4) => caps.supports(Feature::Disable),
            _ => caps.not_applicable(
                Feature::Disable,
                "Vault transit keys have no disabled or soft-deleted state",
            ),
        };
        caps = match self.flavor {
            // Vault rejects JSON strings above its limit (2 MB of base64 fails).
            Flavor::Vault => caps.with_oversize_plaintext(3 * 1024 * 1024),
            // OpenBao's default max_request_size is 32 MiB.
            _ => caps.with_oversize_plaintext(33 * 1024 * 1024),
        };
        for &alg in SignatureAlgorithm::ALL {
            caps = caps.supports(Feature::Signing(alg));
        }
        caps
    }

    /// Every key is fresh: dev-server keys are cheap.
    async fn create_key(&self, kind: TestKeyKind, _: KeyUse) -> Result<TestKey> {
        let name = self.create(key_type(kind)?).await?;
        Ok(TestKey::new(Self::uri(&name), name, kind))
    }

    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        self.admin
            .req(
                reqwest::Method::POST,
                &format!("transit/keys/{}/rotate", key.name),
                None,
            )
            .await?;
        Ok(key.clone())
    }

    async fn disable(&self, key: &TestKey) -> Result<()> {
        self.admin
            .req(
                reqwest::Method::DELETE,
                &format!("transit/keys/{}/soft-delete", key.name),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn set_min_decryption_version(&self, key: &TestKey, version: &KeyVersion) -> Result<()> {
        let version = version
            .as_u64()
            .ok_or_else(|| fx_err(format!("non-numeric transit key version {version}")))?;
        self.admin
            .req(
                reqwest::Method::POST,
                &format!("transit/keys/{}/config", key.name),
                Some(json!({"min_decryption_version": version})),
            )
            .await
            .map(|_| ())
    }

    async fn throttle(&self, key: &TestKey) -> Result<()> {
        self.admin
            .req(
                reqwest::Method::POST,
                &format!("sys/quotas/rate-limit/q-{}", key.name),
                Some(json!({"rate": 1, "interval": "60s", "path": format!("transit/encrypt/{}", key.name)})),
            )
            .await
            .map(|_| ())
    }

    async fn unthrottle(&self, key: &TestKey) -> Result<()> {
        self.admin
            .req(
                reqwest::Method::DELETE,
                &format!("sys/quotas/rate-limit/q-{}", key.name),
                None,
            )
            .await
            .map(|_| ())
    }

    async fn encrypt_natively(
        &self,
        key: &TestKey,
        plaintext: &[u8],
    ) -> Result<Option<Ciphertext>> {
        let pt = base64::engine::general_purpose::STANDARD.encode(plaintext);
        let r = self
            .admin
            .req(
                reqwest::Method::POST,
                &format!("transit/encrypt/{}", key.name),
                Some(json!({"plaintext": pt})),
            )
            .await?;
        Ok(r["data"]["ciphertext"]
            .as_str()
            .map(|s| Ciphertext::from_bytes(s.as_bytes().to_vec())))
    }

    /// A call through `AeadKey::call_extension`, as a backend extension trait makes it.
    async fn extension_call(&self, key: &AeadKey) -> Result<()> {
        let k = key
            .downcast_arc::<anykms_transit::TransitAeadKey>()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "fixture",
                    Operation::Encrypt,
                    "not a transit AEAD key",
                )
            })?;
        key.call_extension(Operation::Encrypt, "transit.conformance_encrypt", || {
            let k = k.clone();
            Box::pin(async move { anykms_core::Aead::encrypt(&*k, b"extension", b"").await })
        })
        .await
        .map(drop)
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        Self::uri(&format!("missing-{}", self.run_id))
    }

    fn provider(&self) -> Arc<dyn Provider> {
        self.provider.clone()
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(TransitTyped(self.provider.clone()))
    }

    fn counting(&self) -> Option<Counting> {
        let count = Arc::new(AtomicU64::new(0));
        let source = CountingToken {
            inner: StaticToken::new(self.data_token.clone()),
            count: count.clone(),
        };
        let p = Arc::new(
            TransitProvider::builder()
                .server(
                    "default",
                    ServerConfig::new(self.admin.addr.clone(), self.flavor)
                        .token_source(Arc::new(source))
                        .allow_loopback_http(),
                )
                .build()
                .ok()?,
        );
        Some(Counting::new(
            p.clone(),
            Arc::new(TransitTyped(p)),
            Arc::new(move || count.load(Ordering::SeqCst)),
        ))
    }

    fn secret_markers(&self) -> Vec<String> {
        vec![
            self.data_token.clone(),
            self.admin.root.clone(),
            self.denied_token.clone(),
        ]
    }

    fn unauthorized_provider(&self) -> Option<Arc<dyn Provider>> {
        let p = TransitProvider::builder()
            .server(
                "default",
                ServerConfig::new(self.admin.addr.clone(), self.flavor)
                    .token(self.denied_token.clone())
                    .allow_loopback_http(),
            )
            .build()
            .ok()?;
        Some(Arc::new(p))
    }
}
