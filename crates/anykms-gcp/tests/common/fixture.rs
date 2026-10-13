//! The conformance fixture: the same code drives the in-process fake server (every PR) and a
//! real Cloud KMS key ring (the env-gated nightly job). Keys are created, rotated and disabled
//! through the Cloud KMS admin REST API (`cryptoKeys.create`, `cryptoKeyVersions.create`,
//! `updatePrimaryVersion`, `cryptoKeyVersions.patch`), outside the public anykms API.
//!
//! Cloud KMS binds the HMAC algorithm to the key: [`TestKeyKind::Hmac`] creates an
//! `HMAC_SHA256`, `HMAC_SHA384` or `HMAC_SHA512` key for the algorithm asked. Signing, MAC and
//! RSA key-wrapping keys are opened with a version, so their missing-key URI
//! ([`Fixture::missing_key_uri`]) names version 1 of a key that does not exist.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anykms_conformance::{
    AeadKeyHandles, Counting, DigestKeyHandles, Feature, Fixture, FixtureCaps, KeyUse,
    KeyWrapKeyHandles, TestKey, TestKeyKind, TypedHandles,
};
use anykms_core::{
    BoxFuture, Ciphertext, Error, ErrorKind, KeyUri, KeyVersion, MacAlgorithm, Operation, Provider,
    Result, SignatureAlgorithm,
};
use anykms_gcp::{
    CredentialSource, Credentials, GcpKeyRef, GcpProvider, GcpProviderBuilder, Token,
};
use base64::Engine as _;
use serde_json::{Value, json};

use super::fake::{self, FakeKms};

fn fixture_err(msg: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Unsupported, "fixture", Operation::Configure, msg)
}

/// The Cloud KMS algorithm the fixture creates for a test key kind.
pub fn gcp_algorithm(kind: TestKeyKind) -> Option<&'static str> {
    use SignatureAlgorithm as S;
    Some(match kind {
        TestKeyKind::Aead => "GOOGLE_SYMMETRIC_ENCRYPTION",
        TestKeyKind::Hmac(MacAlgorithm::HmacSha256) => "HMAC_SHA256",
        TestKeyKind::Hmac(MacAlgorithm::HmacSha384) => "HMAC_SHA384",
        TestKeyKind::Hmac(MacAlgorithm::HmacSha512) => "HMAC_SHA512",
        TestKeyKind::KeyWrap => "RSA_DECRYPT_OAEP_2048_SHA256",
        TestKeyKind::Signing(S::EcdsaP256Sha256) => "EC_SIGN_P256_SHA256",
        TestKeyKind::Signing(S::EcdsaP384Sha384) => "EC_SIGN_P384_SHA384",
        TestKeyKind::Signing(S::RsaPssSha256) => "RSA_SIGN_PSS_2048_SHA256",
        TestKeyKind::Signing(S::RsaPssSha512) => "RSA_SIGN_PSS_4096_SHA512",
        TestKeyKind::Signing(S::RsaPkcs1v15Sha256) => "RSA_SIGN_PKCS1_2048_SHA256",
        TestKeyKind::Signing(S::RsaPkcs1v15Sha512) => "RSA_SIGN_PKCS1_4096_SHA512",
        TestKeyKind::Signing(S::Ed25519) => "EC_SIGN_ED25519",
        _ => return None,
    })
}

fn purpose(alg: &str) -> &'static str {
    match alg {
        "GOOGLE_SYMMETRIC_ENCRYPTION" => "ENCRYPT_DECRYPT",
        a if a.starts_with("HMAC_") => "MAC",
        a if a.starts_with("RSA_DECRYPT_") => "ASYMMETRIC_DECRYPT",
        _ => "ASYMMETRIC_SIGN",
    }
}

/// The Cloud KMS admin REST API, with a bearer token.
#[derive(Clone)]
pub struct Admin {
    http: reqwest::Client,
    base: String,
    token: String,
    /// How long to wait for a new version to leave `PENDING_GENERATION`.
    pending_timeout: Duration,
}

impl Admin {
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: anykms_http::client::ClientOptions::new()
                .request_timeout(Duration::from_secs(60))
                .build(
                    "fixture",
                    anykms_http::tls::TlsOptions::new()
                        .build("fixture")
                        .expect("TLS"),
                )
                .expect("client"),
            base: base.into().trim_end_matches('/').to_owned(),
            token: token.into(),
            pending_timeout: Duration::from_secs(180),
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut req = self
            .http
            .request(method, format!("{}/v1/{path}", self.base))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| fixture_err(format!("admin request failed: {e}")))?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(fixture_err(format!(
                "admin request {path} failed: {status} {}",
                v.pointer("/error/status")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            )));
        }
        Ok(v)
    }

    /// Creates `<ring>/cryptoKeys/<id>` and waits for its first version.
    pub async fn create_key(&self, ring: &str, id: &str, algorithm: &str) -> Result<String> {
        let body = json!({
            "purpose": purpose(algorithm),
            "versionTemplate": {"algorithm": algorithm, "protectionLevel": "SOFTWARE"},
            "destroyScheduledDuration": "86400s",
        });
        let k = self
            .call(
                reqwest::Method::POST,
                &format!("{ring}/cryptoKeys?cryptoKeyId={id}"),
                Some(body),
            )
            .await?;
        let name = k["name"]
            .as_str()
            .ok_or_else(|| fixture_err("no key name"))?
            .to_owned();
        self.wait_enabled(&name, 1).await?;
        Ok(name)
    }

    /// Adds a version and waits until it is enabled; returns its number.
    pub async fn add_version(&self, key: &str) -> Result<u64> {
        let v = self
            .call(
                reqwest::Method::POST,
                &format!("{key}/cryptoKeyVersions"),
                Some(json!({})),
            )
            .await?;
        let n = v["name"]
            .as_str()
            .and_then(|n| n.rsplit('/').next())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| fixture_err("no version name"))?;
        self.wait_enabled(key, n).await?;
        Ok(n)
    }

    async fn wait_enabled(&self, key: &str, n: u64) -> Result<()> {
        let started = Instant::now();
        loop {
            let v = self
                .call(
                    reqwest::Method::GET,
                    &format!("{key}/cryptoKeyVersions/{n}"),
                    None,
                )
                .await?;
            if v["state"] == "ENABLED" {
                return Ok(());
            }
            if started.elapsed() > self.pending_timeout {
                return Err(fixture_err("key version did not become ENABLED"));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    pub async fn set_primary(&self, key: &str, n: u64) -> Result<()> {
        self.call(
            reqwest::Method::POST,
            &format!("{key}:updatePrimaryVersion"),
            Some(json!({"cryptoKeyVersionId": n.to_string()})),
        )
        .await
        .map(drop)
    }

    pub async fn set_state(&self, key: &str, n: u64, state: &str) -> Result<()> {
        self.call(
            reqwest::Method::PATCH,
            &format!("{key}/cryptoKeyVersions/{n}?updateMask=state"),
            Some(json!({"state": state})),
        )
        .await
        .map(drop)
    }

    /// Encrypts without anykms and without AAD (the way another Cloud KMS client would).
    pub async fn encrypt(&self, key: &str, pt: &[u8]) -> Result<Ciphertext> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let r = self
            .call(
                reqwest::Method::POST,
                &format!("{key}:encrypt"),
                Some(json!({"plaintext": b64.encode(pt)})),
            )
            .await?;
        let ct = r["ciphertext"]
            .as_str()
            .and_then(|c| b64.decode(c).ok())
            .ok_or_else(|| fixture_err("no ciphertext"))?;
        Ok(Ciphertext::from_bytes(ct))
    }
}

/// The typed API: the GCP handles bridged with exactly their parts.
struct Typed(GcpProvider);

anykms_conformance::typed_handles! {
    impl for Typed => |t| &t.0;
    preflight;
    message_key => ed25519_key;
    mac_key => mac_key;
    {
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        let k = Arc::new(self.0.aead_key(uri)?);
        let s = k.semantics().clone();
        Ok(AeadKeyHandles::bridge(k.clone()).with_semantics(s).with_preflight(k))
    }

    fn key_wrap(&self, uri: &KeyUri) -> Result<KeyWrapKeyHandles> {
        match GcpKeyRef::parse(uri)?.version() {
            Some(_) => {
                let k = Arc::new(self.0.key_wrap_key(uri)?);
                let s = k.semantics().clone();
                Ok(KeyWrapKeyHandles::bridge(k.clone())
                    .with_public_keys(k.clone())
                    .with_semantics(s)
                    .with_preflight(k))
            }
            None => self.aead(uri).map(KeyWrapKeyHandles::from_aead),
        }
    }

    fn digest_key(&self, uri: &KeyUri, alg: SignatureAlgorithm) -> Result<DigestKeyHandles> {
        alg.require_shape(anykms_core::SigningShape::Digest, "gcp")?;
        let k = Arc::new(self.0.digest_signing_key(uri, alg)?);
        let s = k.semantics().clone();
        Ok(DigestKeyHandles::bridge(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }
    }
}

/// A static token whose uses are counted: one per request (two after a 401). Each token is
/// handed out already expired, so the provider's token cache asks for a new one every request.
#[derive(Debug)]
struct CountingToken {
    token: String,
    count: Arc<AtomicU64>,
}

impl CredentialSource for CountingToken {
    fn token(&self) -> BoxFuture<'_, Result<Option<Token>>> {
        self.count.fetch_add(1, Ordering::SeqCst);
        let t = Token::new(self.token.clone(), Some(std::time::UNIX_EPOCH));
        Box::pin(async move { Ok(Some(t)) })
    }
}

/// Where the fixture runs.
pub enum Mode {
    /// The in-process fake server.
    Fake(FakeKms),
    /// A real key ring.
    Live {
        /// A token with no Cloud KMS roles, for `UnauthorizedProvider`.
        unauthorized_token: Option<String>,
    },
}

pub struct GcpFixture {
    mode: Mode,
    admin: Admin,
    ring: String,
    run: String,
    counter: AtomicU64,
    /// Builds data-plane providers (the counted one swaps the credentials).
    builder: GcpProviderBuilder,
    /// A token for the counted provider.
    counting_token: String,
    provider: GcpProvider,
    shared: tokio::sync::Mutex<HashMap<String, TestKey>>,
    /// The provider keeps its default public-key cache ([`fake_cached`](Self::fake_cached)).
    cached: bool,
}

impl GcpFixture {
    /// The fixture over a fresh fake server.
    pub async fn fake() -> Self {
        Self::fake_with(super::builder).await
    }

    /// The fixture over a fresh fake server, with the provider's default public-key cache (as
    /// production runs it) instead of none. A disabled version's public key then stays cached
    /// for up to `public_key_ttl`, so the disabled-version cases are not applicable here; they
    /// run in the uncached `tests/conformance.rs`.
    pub async fn fake_cached() -> Self {
        Self {
            cached: true,
            ..Self::fake_with(super::cached_builder).await
        }
    }

    async fn fake_with(builder: fn(&FakeKms) -> GcpProviderBuilder) -> Self {
        let fake = FakeKms::start().await;
        let builder = builder(&fake);
        let admin = Admin::new(fake.uri(), fake::TOKEN);
        Self::new(
            Mode::Fake(fake),
            admin,
            FakeKms::RING.to_owned(),
            builder,
            fake::TOKEN.to_owned(),
        )
    }

    pub fn new(
        mode: Mode,
        admin: Admin,
        ring: String,
        builder: GcpProviderBuilder,
        counting_token: String,
    ) -> Self {
        let provider = builder.clone().build().expect("provider");
        let run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        Self {
            mode,
            admin,
            ring,
            run,
            counter: AtomicU64::new(0),
            builder,
            counting_token,
            provider,
            shared: tokio::sync::Mutex::default(),
            cached: false,
        }
    }

    fn next_id(&self) -> String {
        format!(
            "t-{}-{}",
            self.run,
            self.counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn create(&self, kind: TestKeyKind) -> Result<TestKey> {
        let alg = gcp_algorithm(kind).ok_or_else(|| fixture_err("no such key kind"))?;
        let id = self.next_id();
        let name = self.admin.create_key(&self.ring, &id, alg).await?;
        Ok(if kind == TestKeyKind::Aead {
            TestKey::new(format!("gcp-kms://{name}").parse()?, name, kind)
        } else {
            TestKey::new(
                format!("gcp-kms://{name}/cryptoKeyVersions/1").parse()?,
                name,
                kind,
            )
            .with_version(KeyVersion::from_u64(1))
        })
    }

    fn is_fake(&self) -> bool {
        matches!(self.mode, Mode::Fake(_))
    }
}

/// A key that does not exist: versioned for the kinds opened with a version (all but AEAD).
fn missing_uri(ring: &str, kind: TestKeyKind) -> KeyUri {
    let key = format!("gcp-kms://{ring}/cryptoKeys/does-not-exist");
    match kind {
        TestKeyKind::Aead => key,
        _ => format!("{key}/cryptoKeyVersions/1"),
    }
    .parse()
    .expect("valid URI")
}

fn shared_id(kind: TestKeyKind) -> String {
    format!("{kind:?}")
}

impl Fixture for GcpFixture {
    fn backend_info_type(&self) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<anykms_gcp::GcpKeyInfo>())
    }

    fn name(&self) -> &str {
        match self.mode {
            Mode::Fake(_) => "gcp (fake server)",
            Mode::Live { .. } => "gcp (live)",
        }
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::*;
        let max = 64 * 1024;
        let mut caps = FixtureCaps::new()
            .supports(Feature::BackendInfo)
            .supports(Feature::KeyWrapPublicKeys)
            .supports_all(&[
                Aead,
                Mac,
                Describe,
                KeyWrap,
                Rotate,
                RotateKeyWrap,
                RotateMac,
                RotateSigning,
                DisableVersion,
                DescribeVersionState,
                NativeCiphertext,
                RequestCount,
                EmptyPlaintext,
            ])
            .supports(Feature::UsedPrimary)
            .with_oversize_plaintext(max + 1)
            .supports(Feature::MacInputLimit)
            .supports(Feature::MessageInputLimit)
            .not_applicable_all(
                &[Rewrap, DataKeys, WrappedDataKeys, RewrapWithAad],
                "Cloud KMS has no native rewrap and no data keys (recipes: rewrap_local, \
                 ClientRewrap, EmulatedDataKeys)",
            )
            .not_applicable(
                KeyWrapRewrap,
                "Cloud KMS cannot rewrap RSA-wrapped keys server-side",
            )
            .not_applicable(Extension, "the GCP backend has no extension calls")
            .not_applicable(
                EmptyMessage,
                "Cloud KMS refuses an empty Ed25519 message and empty macVerify data (macSign \
                 accepts it; §24.4 probe T1)",
            )
            .not_applicable_all(
                &[Disable, MinDecryptionVersion],
                "Cloud KMS keeps state per version (no key-level disable) and has no minimum \
                 decryption version",
            )
            .not_applicable(
                PreflightState,
                "known limitation: the HMAC preflight reads the key type, not the state of the \
                 pinned version (KeyInfo::state is None on Cloud KMS; a disabled primary AEAD \
                 version is refused from the version list since R-49)",
            );
        if self.cached {
            caps = caps.not_applicable(
                DisableVersion,
                "the cached variant: a disabled version's public key stays cached for up to \
                 public_key_ttl (tests/conformance.rs runs these cases without the cache)",
            );
        }
        caps = match &self.mode {
            Mode::Fake(_) => caps
                .supports_all(&[Throttle, UnauthorizedProvider, ServerErrorMessages])
                .with_throttle_retry_after(true),
            Mode::Live { unauthorized_token } => {
                let caps = caps
                    .supports(ServerErrorMessages)
                    .lacks(Throttle, "Cloud KMS quotas cannot be tripped on demand")
                    // Disabling a version takes up to a minute to reach the data plane, plus
                    // the provider's public-key cache (disabled for the fixture).
                    .with_settle_time(Duration::from_secs(150));
                if unauthorized_token.is_some() {
                    caps.supports(UnauthorizedProvider)
                } else {
                    caps.lacks(
                        UnauthorizedProvider,
                        "set ANYKMS_GCP_UNAUTHORIZED_TOKEN (a token of an identity without roles)",
                    )
                }
            }
        };
        for &alg in SignatureAlgorithm::ALL {
            caps = match gcp_algorithm(TestKeyKind::Signing(alg)) {
                Some(_) => caps.supports(Signing(alg)),
                None => caps.not_applicable(
                    Signing(alg),
                    "Cloud KMS has no key for this algorithm (no P-521, no SHA-384 RSA)",
                ),
            };
        }
        caps
    }

    async fn create_key(&self, kind: TestKeyKind, key_use: KeyUse) -> Result<TestKey> {
        if key_use == KeyUse::Fresh {
            return self.create(kind).await;
        }
        let mut shared = self.shared.lock().await;
        if let Some(k) = shared.get(&shared_id(kind)) {
            return Ok(k.clone());
        }
        let k = self.create(kind).await?;
        shared.insert(shared_id(kind), k.clone());
        Ok(k)
    }

    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        if key.kind == TestKeyKind::Aead {
            let n = self.admin.add_version(&key.name).await?;
            self.admin.set_primary(&key.name, n).await?;
            return Ok(key.clone());
        }
        let n = self.admin.add_version(&key.name).await?;
        Ok(TestKey::new(
            format!("gcp-kms://{}/cryptoKeyVersions/{n}", key.name).parse()?,
            key.name.clone(),
            key.kind,
        )
        .with_version(KeyVersion::from_u64(n)))
    }

    async fn disable_version(&self, key: &TestKey, version: &KeyVersion) -> Result<()> {
        let n = version
            .as_u64()
            .ok_or_else(|| fixture_err("non-numeric version"))?;
        self.admin.set_state(&key.name, n, "DISABLED").await
    }

    async fn throttle(&self, key: &TestKey) -> Result<()> {
        match &self.mode {
            Mode::Fake(f) => {
                f.throttle(&key.name, true);
                Ok(())
            }
            Mode::Live { .. } => Err(fixture_err("cannot throttle live keys")),
        }
    }

    async fn unthrottle(&self, key: &TestKey) -> Result<()> {
        if let Mode::Fake(f) = &self.mode {
            f.throttle(&key.name, false);
        }
        Ok(())
    }

    async fn encrypt_natively(
        &self,
        key: &TestKey,
        plaintext: &[u8],
    ) -> Result<Option<Ciphertext>> {
        self.admin.encrypt(&key.name, plaintext).await.map(Some)
    }

    fn missing_key_uri(&self, kind: TestKeyKind) -> KeyUri {
        missing_uri(&self.ring, kind)
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(self.provider.clone())
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(Typed(self.provider.clone()))
    }

    fn counting(&self) -> Option<Counting> {
        let count = Arc::new(AtomicU64::new(0));
        let source = CountingToken {
            token: self.counting_token.clone(),
            count: count.clone(),
        };
        let p = self
            .builder
            .clone()
            .credentials(Credentials::custom(Arc::new(source)))
            .build()
            .ok()?;
        Some(Counting::new(
            Arc::new(p.clone()),
            Arc::new(Typed(p)),
            Arc::new(move || count.load(Ordering::SeqCst)),
        ))
    }

    fn secret_markers(&self) -> Vec<String> {
        let mut v = vec![self.counting_token.clone()];
        if let Mode::Live {
            unauthorized_token: Some(t),
        } = &self.mode
        {
            v.push(t.clone());
        }
        v
    }

    fn unauthorized_provider(&self) -> Option<Arc<dyn Provider>> {
        let token = match &self.mode {
            Mode::Fake(_) => fake::DENIED_TOKEN.to_owned(),
            Mode::Live { unauthorized_token } => unauthorized_token.clone()?,
        };
        let p = self
            .builder
            .clone()
            .credentials(Credentials::static_token(token))
            .build()
            .ok()?;
        Some(Arc::new(p))
    }
}
