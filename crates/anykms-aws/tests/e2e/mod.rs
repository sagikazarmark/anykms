//! The AWS conformance fixture, against an emulator (Floci, LocalStack) or real AWS.
//!
//! Emulator (`tests/conformance_emulator.rs`): `ANYKMS_AWS_EMULATOR_ENDPOINT` (default
//! `http://127.0.0.1:4566`, `docker compose --profile aws up -d --wait floci`),
//! `ANYKMS_AWS_EMULATOR` names it (`floci`, default, or `localstack`). Keys are created per case.
//!
//! Live (`tests/conformance_live.rs`): `ANYKMS_AWS_LIVE=1` plus credentials of the default chain
//! (CI: GitHub OIDC web identity), `ANYKMS_AWS_REGION` (else `AWS_REGION`) and optionally a pool
//! of long-lived keys for shared use (`ANYKMS_AWS_KEY_AEAD`, `_HMAC` (HMAC-SHA-256), `_HMAC_384`,
//! `_HMAC_512`, `_P256`, `_P384`, `_P521`, `_RSA_SIGN`, `_ED25519`, `_RSA_WRAP`: key ARNs, created
//! by `scripts/aws-test-setup.sh`). An AWS HMAC key serves one algorithm, so the fixture keeps one
//! per algorithm (`TestKeyKind::Hmac(alg)`).
//! Fresh keys are created tagged `anykms-conformance=fresh` and scheduled for deletion (7 days)
//! when the fixture is dropped; `scripts/aws-test-setup.sh cleanup` catches any left behind.
//! `ANYKMS_AWS_DENIED_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` (/ `_SESSION_TOKEN`): credentials with
//! no key permissions, for the unauthorized-provider cases.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anykms_aws::credentials::StaticCredentials;
use anykms_aws::{
    AwsProvider, AwsProviderBuilder, Credentials, EncryptionContext, EncryptionContextAead,
};
use anykms_conformance::{
    AeadKeyHandles, Counting, Feature, Fixture, FixtureCaps, FreshKeys, KeySpecTable, KeyUse,
    KeyWrapKeyHandles, TestKey, TestKeyKind, TypedHandles,
};
use anykms_core::{
    AeadKey, Ciphertext, Error, ErrorKind, KeyUri, MacAlgorithm, Operation, Provider, Result,
    SignatureAlgorithm,
};
use serde_json::{Value, json};

fn fx_err(m: impl Into<String>) -> Error {
    Error::new(
        ErrorKind::Backend,
        "fixture",
        Operation::Configure,
        m.into(),
    )
}

/// `(KeySpec, KeyUsage)` for a test key kind.
pub fn key_spec(kind: TestKeyKind) -> Result<(&'static str, &'static str)> {
    use SignatureAlgorithm as S;
    static TABLE: std::sync::LazyLock<KeySpecTable<(&str, &str)>> =
        std::sync::LazyLock::new(|| {
            let mac = "GENERATE_VERIFY_MAC";
            let sign = "SIGN_VERIFY";
            KeySpecTable::new("AWS")
                .with(TestKeyKind::Aead, ("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT"))
                .with(
                    TestKeyKind::Hmac(MacAlgorithm::HmacSha256),
                    ("HMAC_256", mac),
                )
                .with(
                    TestKeyKind::Hmac(MacAlgorithm::HmacSha384),
                    ("HMAC_384", mac),
                )
                .with(
                    TestKeyKind::Hmac(MacAlgorithm::HmacSha512),
                    ("HMAC_512", mac),
                )
                .with(TestKeyKind::KeyWrap, ("RSA_2048", "ENCRYPT_DECRYPT"))
                .with(
                    TestKeyKind::Signing(S::EcdsaP256Sha256),
                    ("ECC_NIST_P256", sign),
                )
                .with(
                    TestKeyKind::Signing(S::EcdsaP384Sha384),
                    ("ECC_NIST_P384", sign),
                )
                .with(
                    TestKeyKind::Signing(S::EcdsaP521Sha512),
                    ("ECC_NIST_P521", sign),
                )
                .with(
                    TestKeyKind::Signing(S::Ed25519),
                    ("ECC_NIST_EDWARDS25519", sign),
                )
                .with_any_signing(("RSA_2048", sign))
        });
    TABLE.get(kind).copied().map_err(fx_err)
}

/// The pool variable of a key kind (live runs).
fn pool_var(kind: TestKeyKind) -> &'static str {
    use SignatureAlgorithm as S;
    match kind {
        TestKeyKind::Aead => "ANYKMS_AWS_KEY_AEAD",
        TestKeyKind::Hmac(MacAlgorithm::HmacSha384) => "ANYKMS_AWS_KEY_HMAC_384",
        TestKeyKind::Hmac(MacAlgorithm::HmacSha512) => "ANYKMS_AWS_KEY_HMAC_512",
        TestKeyKind::Hmac(_) => "ANYKMS_AWS_KEY_HMAC",
        TestKeyKind::KeyWrap => "ANYKMS_AWS_KEY_RSA_WRAP",
        TestKeyKind::Signing(S::EcdsaP256Sha256) => "ANYKMS_AWS_KEY_P256",
        TestKeyKind::Signing(S::EcdsaP384Sha384) => "ANYKMS_AWS_KEY_P384",
        TestKeyKind::Signing(S::EcdsaP521Sha512) => "ANYKMS_AWS_KEY_P521",
        TestKeyKind::Signing(S::Ed25519) => "ANYKMS_AWS_KEY_ED25519",
        _ => "ANYKMS_AWS_KEY_RSA_SIGN",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Emulator,
    Live,
}

pub struct AwsFixture {
    name: String,
    mode: Mode,
    /// Builds a data-plane provider (credentials, endpoint, allowlists).
    make: Arc<dyn Fn() -> AwsProviderBuilder + Send + Sync>,
    provider: AwsProvider,
    endpoint: String,
    region: String,
    account: String,
    shared: tokio::sync::Mutex<HashMap<String, TestKey>>,
    fresh: FreshKeys<String>,
    denied: Option<AwsProvider>,
    markers: Vec<String>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

impl AwsFixture {
    /// The emulator fixture, or why it is unavailable.
    pub async fn emulator() -> std::result::Result<Self, String> {
        let endpoint =
            env("ANYKMS_AWS_EMULATOR_ENDPOINT").unwrap_or_else(|| "http://127.0.0.1:4566".into());
        let name = env("ANYKMS_AWS_EMULATOR").unwrap_or_else(|| "floci".into());
        let ep = endpoint.clone();
        let make: Arc<dyn Fn() -> AwsProviderBuilder + Send + Sync> = Arc::new(move || {
            AwsProvider::builder()
                .credentials(StaticCredentials::new(Credentials::new(
                    "test", "test", None,
                )))
                .endpoint_url(ep.clone())
                .allow_loopback_http()
        });
        let f = Self::new(
            name,
            Mode::Emulator,
            make,
            endpoint,
            "us-east-1".into(),
            "000000000000".into(),
            None,
        )?;
        f.admin("ListKeys", json!({"Limit": 1}))
            .await
            .map_err(|e| format!("AWS KMS emulator at {} unavailable: {e}", f.endpoint))?;
        Ok(f)
    }

    /// The live fixture, or why it is not enabled.
    pub async fn live() -> std::result::Result<Self, String> {
        if env("ANYKMS_AWS_LIVE").as_deref() != Some("1") {
            return Err(
                "ANYKMS_AWS_LIVE=1 not set (live AWS runs need credentials; see tests/e2e/mod.rs)"
                    .into(),
            );
        }
        let region = env("ANYKMS_AWS_REGION")
            .or_else(|| env("AWS_REGION"))
            .ok_or("ANYKMS_AWS_REGION or AWS_REGION must be set")?;
        let account = env("ANYKMS_AWS_ACCOUNT")
            .or_else(|| {
                env("ANYKMS_AWS_KEY_AEAD").and_then(|a| a.split(':').nth(4).map(str::to_owned))
            })
            .ok_or("ANYKMS_AWS_ACCOUNT (or ANYKMS_AWS_KEY_AEAD) must be set")?;
        let endpoint = env("AWS_ENDPOINT_URL_KMS")
            .unwrap_or_else(|| format!("https://kms.{region}.amazonaws.com/"));
        let acct = account.clone();
        let make: Arc<dyn Fn() -> AwsProviderBuilder + Send + Sync> = Arc::new(move || {
            AwsProviderBuilder::from_env()
                .expect("AWS environment")
                .allowed_accounts([acct.clone()])
        });
        let denied = match (
            env("ANYKMS_AWS_DENIED_ACCESS_KEY_ID"),
            env("ANYKMS_AWS_DENIED_SECRET_ACCESS_KEY"),
        ) {
            (Some(id), Some(secret)) => Some(
                AwsProvider::builder()
                    .credentials(StaticCredentials::new(Credentials::new(
                        id,
                        secret,
                        env("ANYKMS_AWS_DENIED_SESSION_TOKEN"),
                    )))
                    .build()
                    .map_err(|e| e.to_string())?,
            ),
            _ => None,
        };
        let f = Self::new(
            "aws".into(),
            Mode::Live,
            make,
            endpoint,
            region,
            account,
            denied,
        )?;
        f.admin("ListKeys", json!({"Limit": 1}))
            .await
            .map_err(|e| format!("AWS KMS unavailable: {e}"))?;
        Ok(f)
    }

    fn new(
        name: String,
        mode: Mode,
        make: Arc<dyn Fn() -> AwsProviderBuilder + Send + Sync>,
        endpoint: String,
        region: String,
        account: String,
        denied: Option<AwsProvider>,
    ) -> std::result::Result<Self, String> {
        let provider = make().build().map_err(|e| e.to_string())?;
        let markers = ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
            .iter()
            .filter_map(|k| env(k))
            .collect();
        Ok(Self {
            name,
            mode,
            make,
            provider,
            endpoint,
            region,
            account,
            shared: tokio::sync::Mutex::default(),
            fresh: FreshKeys::new(),
            denied,
            markers,
        })
    }

    pub fn provider_handle(&self) -> &AwsProvider {
        &self.provider
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn uri_of(arn: &str) -> KeyUri {
        format!("aws-kms://{arn}").parse().expect("valid URI")
    }

    /// A signed management call.
    pub async fn admin(&self, target: &'static str, body: Value) -> Result<Value> {
        self.provider
            .__admin()
            .call(&self.endpoint, &self.region, target, &body)
            .await
    }

    /// Creates a key and returns its ARN.
    pub async fn create(&self, kind: TestKeyKind, tag: &str) -> Result<String> {
        let (spec, usage) = key_spec(kind)?;
        let r = self
            .admin(
                "CreateKey",
                json!({
                    "KeySpec": spec,
                    "KeyUsage": usage,
                    "Description": "anykms conformance",
                    "Tags": [{"TagKey": "anykms-conformance", "TagValue": tag}],
                }),
            )
            .await?;
        r["KeyMetadata"]["Arn"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| fx_err("CreateKey returned no ARN"))
    }

    fn data_plane(&self, f: impl FnOnce(AwsProviderBuilder) -> AwsProviderBuilder) -> AwsProvider {
        f((self.make)()).build().expect("provider")
    }
}

impl Drop for AwsFixture {
    /// Live runs schedule their fresh keys for deletion (the shortest window, 7 days).
    fn drop(&mut self) {
        if self.mode != Mode::Live {
            return;
        }
        let keys = self.fresh.take();
        if keys.is_empty() {
            return;
        }
        let admin = self.provider.__admin();
        let (endpoint, region) = (self.endpoint.clone(), self.region.clone());
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async {
                for arn in keys {
                    let _ = admin
                        .call(
                            &endpoint,
                            &region,
                            "ScheduleKeyDeletion",
                            &json!({"KeyId": arn, "PendingWindowInDays": 7}),
                        )
                        .await;
                }
            });
        })
        .join();
    }
}

/// The typed API: the concrete handles bridged into the dyn layer.
struct AwsTyped(AwsProvider);

anykms_conformance::typed_handles! {
    impl for AwsTyped => |t| &t.0;
    preflight;
    digest_key => digest_signing_key;
    message_key => ed25519_key;
    mac_key => mac_key;
    {
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

    fn key_wrap(&self, uri: &KeyUri) -> Result<KeyWrapKeyHandles> {
        let k = Arc::new(self.0.key_wrap_key(uri)?);
        let s = k.semantics().clone();
        Ok(KeyWrapKeyHandles::bridge(k.clone())
            .with_public_keys(k.clone())
            .with_rewrap(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }
    }
}

impl Fixture for AwsFixture {
    fn backend_info_type(&self) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<anykms_aws::AwsKeyInfo>())
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::*;
        let mut caps = FixtureCaps::new()
            .supports(Feature::BackendInfo)
            .supports(Feature::KeyWrapPublicKeys)
            .supports_all(&[
                Aead,
                Rewrap,
                DataKeys,
                WrappedDataKeys,
                Mac,
                Describe,
                KeyWrap,
                KeyWrapRewrap,
                Extension,
                Rotate,
                Disable,
                PreflightState,
                NativeCiphertext,
                RewrapWithAad,
                RequestCount,
            ])
            .not_applicable(
                RotateKeyWrap,
                "AWS RSA keys cannot be rotated (a new key and an alias instead)",
            )
            .not_applicable(
                RotateMac,
                "AWS HMAC keys cannot be rotated (a new key and an alias instead)",
            )
            .not_applicable(
                RotateSigning,
                "AWS asymmetric keys cannot be rotated (a new key and an alias instead)",
            )
            .not_applicable(
                DisableVersion,
                "AWS keys have no individually disabled versions",
            )
            .not_applicable(
                MinDecryptionVersion,
                "AWS has no minimum decryption version",
            )
            .not_applicable(
                Throttle,
                "AWS request quotas cannot be lowered for one key by a test",
            )
            .not_applicable(
                EmptyPlaintext,
                "AWS Encrypt rejects empty plaintexts (1 to 4096 bytes)",
            )
            .not_applicable(
                EmptyMessage,
                "AWS GenerateMac and Sign reject empty messages",
            )
            .not_applicable(
                Feature::UsedPrimary,
                "decrypt does not report whether the primary version was used",
            )
            .with_oversize_plaintext(4097)
            .supports(Feature::MacInputLimit)
            .supports(Feature::MessageInputLimit);
        for &alg in SignatureAlgorithm::ALL {
            caps = caps.supports(Signing(alg));
        }
        match self.mode {
            // n/a, not a skip: CI runs the emulator suite with ANYKMS_FAIL_ON_SKIP=1, and the
            // live suite checks these cases against real IAM.
            Mode::Emulator => caps.with_emulated_errors(&self.name).not_applicable(
                UnauthorizedProvider,
                "the emulator does not enforce IAM (the live suite checks it)",
            ),
            Mode::Live => {
                caps = caps
                    .supports(ServerErrorMessages)
                    .with_settle_time(Duration::from_secs(30));
                if self.denied.is_some() {
                    caps.supports(UnauthorizedProvider)
                } else {
                    caps.lacks(
                        UnauthorizedProvider,
                        "ANYKMS_AWS_DENIED_ACCESS_KEY_ID not set",
                    )
                }
            }
        }
    }

    async fn create_key(&self, kind: TestKeyKind, key_use: KeyUse) -> Result<TestKey> {
        let label = format!("{kind:?}");
        if key_use == KeyUse::Shared {
            let mut shared = self.shared.lock().await;
            if let Some(k) = shared.get(&label) {
                return Ok(k.clone());
            }
            let arn = match (self.mode, env(pool_var(kind))) {
                (Mode::Live, Some(arn)) => arn,
                _ => {
                    let arn = self.create(kind, "shared").await?;
                    if self.mode == Mode::Live {
                        self.fresh.push(arn.clone());
                    }
                    arn
                }
            };
            let k = TestKey::new(Self::uri_of(&arn), arn, kind);
            shared.insert(label, k.clone());
            return Ok(k);
        }
        let arn = self.create(kind, "fresh").await?;
        if self.mode == Mode::Live {
            self.fresh.push(arn.clone());
        }
        Ok(TestKey::new(Self::uri_of(&arn), arn, kind))
    }

    /// Symmetric keys rotate on demand (the ARN stays, new ciphertexts use new material). AWS
    /// asymmetric and HMAC keys cannot rotate (`RotateKeyWrap`, `RotateSigning`, `RotateMac` are
    /// not applicable).
    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        match key.kind {
            TestKeyKind::Aead => {
                self.admin("RotateKeyOnDemand", json!({"KeyId": key.name}))
                    .await?;
                Ok(key.clone())
            }
            k => Err(fx_err(format!("AWS cannot rotate {k:?} keys"))),
        }
    }

    async fn disable(&self, key: &TestKey) -> Result<()> {
        self.admin("DisableKey", json!({"KeyId": key.name}))
            .await
            .map(drop)
    }

    async fn encrypt_natively(
        &self,
        key: &TestKey,
        plaintext: &[u8],
    ) -> Result<Option<Ciphertext>> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let r = self
            .admin(
                "Encrypt",
                json!({"KeyId": key.name, "Plaintext": b64.encode(plaintext)}),
            )
            .await?;
        let blob = r["CiphertextBlob"]
            .as_str()
            .ok_or_else(|| fx_err("no CiphertextBlob"))?;
        Ok(Some(Ciphertext::from_bytes(
            b64.decode(blob).map_err(|_| fx_err("bad blob"))?,
        )))
    }

    /// `encrypt_with_context` on the opaque handle, which runs through `call_extension`.
    async fn extension_call(&self, key: &AeadKey) -> Result<()> {
        let ctx = EncryptionContext::new().with("purpose", "conformance");
        key.encrypt_with_context(b"extension", &ctx).await.map(drop)
    }

    fn malformed_version(&self) -> Option<anykms_core::KeyVersion> {
        Some(anykms_core::KeyVersion::new("abc"))
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("rng");
        let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
        Self::uri_of(&format!(
            "arn:aws:kms:{}:{}:key/{}-{}-{}-{}-{}",
            self.region,
            self.account,
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        ))
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(self.provider.clone())
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(AwsTyped(self.provider.clone()))
    }

    fn counting(&self) -> Option<Counting> {
        let n = Arc::new(AtomicU64::new(0));
        let p = self.data_plane(|b| b.__count_requests(n.clone()));
        Some(Counting::new(
            Arc::new(p.clone()),
            Arc::new(AwsTyped(p)),
            Arc::new(move || n.load(Ordering::SeqCst)),
        ))
    }

    fn secret_markers(&self) -> Vec<String> {
        self.markers.clone()
    }

    fn unauthorized_provider(&self) -> Option<Arc<dyn Provider>> {
        self.denied
            .clone()
            .map(|p| Arc::new(p) as Arc<dyn Provider>)
    }
}
