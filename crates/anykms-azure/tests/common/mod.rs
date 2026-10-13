//! Shared by the Lowkey Vault, live and conformance targets: reaching Lowkey Vault (its
//! certificate), an admin client for key management outside the public API (create, rotate,
//! enable/disable, delete), and the conformance fixture.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anykms_azure::{AzureCredential, AzureProvider, AzureProviderBuilder, StaticToken, TestHost};
use anykms_conformance::{
    AeadKeyHandles, Counting, Feature, Fixture, FixtureCaps, KeyUse, KeyWrapKeyHandles, TestKey,
    TestKeyKind, TypedHandles,
};
use anykms_core::{
    DataKeysKey, Error, ErrorKind, KeyUri, MacAlgorithm, Operation, Provider, Result,
    SignatureAlgorithm,
};
use serde_json::{Value, json};

/// Lowkey Vault's HTTPS address (`host:port`); `ANYKMS_LOWKEY_HOST` overrides.
pub fn lowkey_host() -> String {
    std::env::var("ANYKMS_LOWKEY_HOST").unwrap_or_else(|_| "localhost:8443".to_owned())
}

/// The token scope Lowkey Vault gets (it accepts any token).
pub const LOWKEY_SCOPE: &str = "https://vault.azure.net/.default";
/// The static token used against Lowkey Vault (also a secret marker for hygiene checks).
pub const LOWKEY_TOKEN: &str = "lowkey-HYGIENE-TOKEN-0123456789";

/// Whether the dedicated CI jobs require the fixture (an unreachable server fails instead of
/// skipping).
pub fn require_fixture() -> bool {
    std::env::var("ANYKMS_REQUIRE_FIXTURE").is_ok_and(|v| v == "1")
}

// ---------------------------------------------------------------------------------------------
// Trust on first use of Lowkey Vault's self-signed certificate (loopback, tests only).

#[derive(Debug)]
struct Capture {
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert: Mutex<Option<Vec<u8>>>,
}

impl rustls::client::danger::ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.cert.lock().unwrap() = Some(end_entity.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The certificate `host_port` presents, as PEM (no verification: the result is then trusted
/// as the CA of a test host). Fails when nothing listens there.
pub fn fetch_server_cert_pem(host_port: &str) -> std::result::Result<String, String> {
    use base64::Engine as _;
    use std::net::ToSocketAddrs as _;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let capture = Arc::new(Capture {
        provider: provider.clone(),
        cert: Mutex::new(None),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port)
        .to_owned();
    let name = rustls::pki_types::ServerName::try_from(host).map_err(|e| e.to_string())?;
    // Every address in turn: `localhost` may resolve to `::1` first while the container
    // publishes the port on 127.0.0.1 only (GitHub's runners).
    let mut last = format!("{host_port}: no address");
    let mut sock = None;
    for addr in host_port
        .to_socket_addrs()
        .map_err(|e| format!("{host_port}: {e}"))?
    {
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last = format!("{host_port}: {e}"),
        }
    }
    let mut sock = sock.ok_or(last)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .map_err(|e| format!("{host_port}: TLS handshake: {e}"))?;
    }
    let der = capture
        .cert
        .lock()
        .unwrap()
        .take()
        .ok_or("no certificate presented")?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem)
}

/// A provider for Lowkey Vault at `host` (a static token, its certificate trusted).
pub fn lowkey_provider(host: &str, ca_pem: &str) -> AzureProvider {
    lowkey_builder(host, ca_pem)
        .build()
        .expect("Lowkey Vault provider")
}

/// The builder of [`lowkey_provider`]. Lowkey Vault refuses versionless operations, so writes
/// name the current version from the key cache; without caching they follow a rotation at once,
/// as the rotation cases expect.
pub fn lowkey_builder(host: &str, ca_pem: &str) -> AzureProviderBuilder {
    AzureProvider::builder()
        .credential(StaticToken::new(LOWKEY_TOKEN))
        .test_host(TestHost::https(host, LOWKEY_SCOPE))
        .ca_pem(ca_pem.as_bytes().to_vec())
        .key_cache_ttl(Duration::ZERO)
}

// ---------------------------------------------------------------------------------------------
// Admin client (key management outside the public anykms API).

/// What kind of key to create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spec {
    Ec(&'static str),
    Rsa(u32),
    /// RSA for wrapping (`wrapKey`, `unwrapKey`).
    RsaWrap(u32),
    /// Managed HSM AES-256 (`encrypt`, `decrypt`, `wrapKey`, `unwrapKey`).
    Aes256,
    /// Managed HSM HMAC (`sign`, `verify`) for one algorithm (`HS256/384/512`): the algorithm is
    /// bound to the key, by its size. To verify with T13: the key creation parameters.
    Hmac(MacAlgorithm),
}

impl Spec {
    pub fn for_kind(kind: TestKeyKind) -> Option<Self> {
        use SignatureAlgorithm::*;
        Some(match kind {
            TestKeyKind::KeyWrap => Self::RsaWrap(2048),
            TestKeyKind::Aead => Self::Aes256,
            TestKeyKind::Hmac(alg) => Self::Hmac(alg),
            TestKeyKind::Signing(EcdsaP256Sha256) => Self::Ec("P-256"),
            TestKeyKind::Signing(EcdsaP384Sha384) => Self::Ec("P-384"),
            TestKeyKind::Signing(EcdsaP521Sha512) => Self::Ec("P-521"),
            TestKeyKind::Signing(
                RsaPssSha256 | RsaPssSha384 | RsaPssSha512 | RsaPkcs1v15Sha256 | RsaPkcs1v15Sha384
                | RsaPkcs1v15Sha512,
            ) => Self::Rsa(2048),
            _ => return None,
        })
    }

    /// The `create` body. `emulator`: Lowkey Vault wraps only with keys that also list
    /// `encrypt`/`decrypt`.
    pub fn body(&self, mhsm: bool, emulator: bool) -> Value {
        let hsm = |kty: &str| {
            if mhsm {
                format!("{kty}-HSM")
            } else {
                kty.to_owned()
            }
        };
        match self {
            Self::Ec(crv) => json!({"kty": hsm("EC"), "crv": crv, "key_ops": ["sign", "verify"]}),
            Self::Rsa(bits) => {
                json!({"kty": hsm("RSA"), "key_size": bits, "key_ops": ["sign", "verify"]})
            }
            Self::RsaWrap(bits) => {
                let ops = if emulator {
                    json!(["wrapKey", "unwrapKey", "encrypt", "decrypt"])
                } else {
                    json!(["wrapKey", "unwrapKey"])
                };
                json!({"kty": hsm("RSA"), "key_size": bits, "key_ops": ops})
            }
            Self::Aes256 => json!({
                "kty": "oct-HSM", "key_size": 256,
                "key_ops": ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
            }),
            Self::Hmac(alg) => {
                let bits = match alg {
                    MacAlgorithm::HmacSha384 => 384,
                    MacAlgorithm::HmacSha512 => 512,
                    _ => 256,
                };
                json!({"kty": "oct-HSM", "key_size": bits, "key_ops": ["sign", "verify"]})
            }
        }
    }
}

/// Key management over the data plane (`create`, `rotate`, `PATCH`, `DELETE`).
pub struct Admin {
    http: reqwest::Client,
    /// `https://host[:port]`.
    pub base: String,
    cred: Arc<dyn AzureCredential>,
    scope: String,
    mhsm: bool,
    emulator: bool,
}

const API: &str = "api-version=2025-07-01";

fn fail(m: String) -> Error {
    Error::new(ErrorKind::Backend, "fixture", Operation::Configure, m)
}

impl Admin {
    pub fn new(
        base: String,
        ca_pem: Option<&str>,
        cred: Arc<dyn AzureCredential>,
        scope: String,
        mhsm: bool,
        emulator: bool,
    ) -> Self {
        // Test-side TLS uses ring, whatever provider the library uses.
        let tls = anykms_http::tls::TlsOptions::new()
            .ca_pem(ca_pem.map(str::as_bytes))
            .crypto_provider(
                Some(Arc::new(rustls::crypto::ring::default_provider())),
                "fixture",
            )
            .build("fixture")
            .expect("admin TLS");
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(60))
            .build()
            .expect("admin client");
        Self {
            http,
            base,
            cred,
            scope,
            mhsm,
            emulator,
        }
    }

    /// One admin request. A 429 (Key Vault limits key creation per vault, which parallel cases
    /// reach) is retried after `Retry-After`, or with backoff, up to 8 times.
    async fn req(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
        let url = format!("{}/{path}?{API}", self.base);
        let mut attempt = 0u32;
        loop {
            let token = self.cred.token(&self.scope).await?;
            let mut r = self
                .http
                .request(method.clone(), &url)
                .bearer_auth(token.secret());
            r = match &body {
                Some(b) => r.json(b),
                // Azure refuses a POST without a length (411); Lowkey Vault does not care.
                None if method == reqwest::Method::POST => {
                    r.header(reqwest::header::CONTENT_LENGTH, "0")
                }
                None => r,
            };
            let resp = r
                .send()
                .await
                .map_err(|e| fail(format!("{method} {path}: {e}")))?;
            let status = resp.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < 8 {
                let wait = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1 << attempt.min(4))
                    .clamp(1, 30);
                attempt += 1;
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
            let v: Value = resp.json().await.unwrap_or(Value::Null);
            if !status.is_success() {
                return Err(fail(format!("{method} {path}: {status} {v}")));
            }
            return Ok(v);
        }
    }

    fn version_of(kid: &Value) -> Result<String> {
        kid.as_str()
            .and_then(|k| k.rsplit('/').next())
            .map(str::to_owned)
            .ok_or_else(|| fail("no kid in response".into()))
    }

    /// Creates `name`; returns its version.
    pub async fn create(&self, name: &str, spec: Spec) -> Result<String> {
        let v = self
            .req(
                reqwest::Method::POST,
                &format!("keys/{name}/create"),
                Some(spec.body(self.mhsm, self.emulator)),
            )
            .await?;
        Self::version_of(&v["key"]["kid"])
    }

    /// Rotates `name`; returns the new version.
    pub async fn rotate(&self, name: &str) -> Result<String> {
        let v = self
            .req(reqwest::Method::POST, &format!("keys/{name}/rotate"), None)
            .await?;
        Self::version_of(&v["key"]["kid"])
    }

    /// Every version of `name`.
    pub async fn versions(&self, name: &str) -> Result<Vec<String>> {
        let v = self
            .req(reqwest::Method::GET, &format!("keys/{name}/versions"), None)
            .await?;
        v["value"]
            .as_array()
            .ok_or_else(|| fail("no version list".into()))?
            .iter()
            .map(|i| Self::version_of(&i["kid"]))
            .collect()
    }

    /// Enables or disables one version.
    pub async fn set_enabled(&self, name: &str, version: &str, enabled: bool) -> Result<()> {
        self.req(
            reqwest::Method::PATCH,
            &format!("keys/{name}/{version}"),
            Some(json!({"attributes": {"enabled": enabled}})),
        )
        .await
        .map(drop)
    }

    /// Deletes `name` (soft delete; best effort, for live cleanup).
    pub async fn delete(&self, name: &str) -> Result<()> {
        self.req(reqwest::Method::DELETE, &format!("keys/{name}"), None)
            .await
            .map(drop)
    }
}

// ---------------------------------------------------------------------------------------------
// The conformance fixture.

/// Where the fixture runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Lowkey Vault: a standard vault with emulated error messages.
    Lowkey,
    /// A real standard (or Premium) vault.
    LiveVault,
    /// A real Managed HSM.
    LiveMhsm,
}

/// The Azure fixture: keys created through the admin client under a run prefix.
pub struct AzureFixture {
    target: Target,
    host: String,
    /// Builds the fixture's providers (the counting one too).
    builder: AzureProviderBuilder,
    provider: AzureProvider,
    /// A provider whose identity has no role on the vault (live, optional).
    unauthorized: Option<AzureProvider>,
    admin: Admin,
    prefix: String,
    counter: AtomicU64,
    shared: tokio::sync::Mutex<HashMap<TestKeyKind, TestKey>>,
    created: Mutex<Vec<String>>,
    markers: Vec<String>,
}

/// A run prefix for key names: `anykms-<unix seconds>-<pid>-<n>` (unique per fixture, also
/// when several run in one process).
pub fn run_prefix() -> String {
    anykms_conformance::RunId::new().prefix().to_string()
}

impl AzureFixture {
    pub fn new(
        target: Target,
        host: String,
        builder: AzureProviderBuilder,
        admin: Admin,
        markers: Vec<String>,
    ) -> std::result::Result<Self, String> {
        let provider = builder.clone().build().map_err(|e| e.to_string())?;
        Ok(Self {
            target,
            host,
            builder,
            provider,
            unauthorized: None,
            admin,
            prefix: run_prefix(),
            counter: AtomicU64::new(0),
            shared: tokio::sync::Mutex::default(),
            created: Mutex::default(),
            markers,
        })
    }

    /// Lowkey Vault at [`lowkey_host`], or why it is unavailable.
    pub async fn lowkey() -> std::result::Result<Self, String> {
        let host = lowkey_host();
        let ca = fetch_server_cert_pem(&host)
            .map_err(|e| format!("Lowkey Vault not reachable ({e}); run `docker compose --profile azure up -d lowkey-vault`"))?;
        let builder = lowkey_builder(&host, &ca);
        let admin = Admin::new(
            format!("https://{host}"),
            Some(&ca),
            Arc::new(StaticToken::new(LOWKEY_TOKEN)),
            LOWKEY_SCOPE.to_owned(),
            false,
            true,
        );
        Self::new(
            Target::Lowkey,
            host,
            builder,
            admin,
            vec![LOWKEY_TOKEN.to_owned()],
        )
    }

    /// A live vault (`ANYKMS_AZURE_LIVE=1`, `ANYKMS_AZURE_VAULT_URL`) or Managed HSM
    /// (`ANYKMS_AZURE_MHSM_URL`), with the credential the environment selects, or why not.
    pub async fn live(mhsm: bool) -> std::result::Result<Self, String> {
        if std::env::var("ANYKMS_AZURE_LIVE").ok().as_deref() != Some("1") {
            return Err("ANYKMS_AZURE_LIVE=1 not set".into());
        }
        let var = if mhsm {
            "ANYKMS_AZURE_MHSM_URL"
        } else {
            "ANYKMS_AZURE_VAULT_URL"
        };
        let url = std::env::var(var).map_err(|_| format!("{var} not set"))?;
        let host = url
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let cred = anykms_azure::credential_from_env().map_err(|e| e.to_string())?;
        let builder = AzureProvider::builder()
            .credential_arc(cred.clone())
            .allowed_vaults([host.clone()]);
        // Optional: a token of an identity without a role on the vault (UnauthorizedProvider).
        let unauthorized_token = std::env::var("ANYKMS_AZURE_UNAUTHORIZED_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let suffix = host.split_once('.').map(|(_, s)| s).unwrap_or_default();
        let admin = Admin::new(
            format!("https://{host}"),
            None,
            cred,
            format!("https://{suffix}/.default"),
            mhsm,
            false,
        );
        let mut fx = Self::new(
            if mhsm {
                Target::LiveMhsm
            } else {
                Target::LiveVault
            },
            host,
            builder.clone(),
            admin,
            unauthorized_token.iter().cloned().collect(),
        )?;
        if let Some(t) = unauthorized_token {
            fx.unauthorized = Some(
                builder
                    .credential(StaticToken::new(t))
                    .build()
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(fx)
    }

    pub fn provider_ref(&self) -> &AzureProvider {
        &self.provider
    }

    pub fn admin(&self) -> &Admin {
        &self.admin
    }

    pub fn uri(&self, name: &str) -> KeyUri {
        format!("azure-kv://{}/keys/{name}", self.host)
            .parse()
            .expect("valid URI")
    }

    /// Creates a fresh key of `spec`.
    pub async fn create(&self, spec: Spec) -> Result<(String, KeyUri)> {
        let name = format!(
            "{}-{}",
            self.prefix,
            self.counter.fetch_add(1, Ordering::Relaxed)
        );
        self.admin.create(&name, spec).await?;
        self.created.lock().unwrap().push(name.clone());
        Ok((name.clone(), self.uri(&name)))
    }

    /// Soft-deletes every key this fixture created (live runs; a janitor purges them).
    pub async fn cleanup(&self) {
        let names = std::mem::take(&mut *self.created.lock().unwrap());
        for n in names {
            let _ = self.admin.delete(&n).await;
        }
    }

    fn mhsm(&self) -> bool {
        self.target == Target::LiveMhsm
    }
}

fn fixture_err(m: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported, "fixture", Operation::Configure, m)
}

impl Fixture for AzureFixture {
    fn backend_info_type(&self) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<anykms_azure::AzureKeyInfo>())
    }

    fn name(&self) -> &str {
        match self.target {
            Target::Lowkey => "azure-lowkey",
            Target::LiveVault => "azure-vault",
            Target::LiveMhsm => "azure-mhsm",
        }
    }

    async fn probe(&self) -> FixtureCaps {
        use Feature::*;
        let mut caps = FixtureCaps::new()
            .supports(Feature::BackendInfo)
            .not_applicable(
                Feature::KeyWrapPublicKeys,
                "Azure wrapped keys are framed with the key version (docs/azure-ciphertext.md): \
                 an offline wrap must be framed with anykms_azure::framing (tests/lowkey.rs)",
            )
            .supports_all(&[
                KeyWrap,
                DataKeys,
                Describe,
                Rotate,
                RotateKeyWrap,
                RotateSigning,
                DisableVersion,
            ])
            .not_applicable(
                Disable,
                "Key Vault has no key-level enabled flag: disabling a key means disabling its \
                 versions, which on a one-version key is DisableVersion (verify of its \
                 signatures is KeyVersionUnusable, not KeyStateInvalid; §24.4 probe T3)",
            )
            .not_applicable(
                Feature::UsedPrimary,
                "decrypt does not report whether the primary version was used",
            )
            .supports(RequestCount)
            .not_applicable(KeyWrapRewrap, "Azure has no server-side rewrap")
            .not_applicable(Extension, "anykms-azure defines no extension calls")
            .not_applicable_all(
                &[MinDecryptionVersion, Throttle, NativeCiphertext],
                "not available on Azure Key Vault",
            )
            .not_applicable_all(
                &[MessageInputLimit, EmptyMessage],
                "Azure has no message-signing keys",
            );
        caps = match self.target {
            Target::Lowkey => caps
                .with_emulated_errors("Lowkey Vault")
                .not_applicable(UnauthorizedProvider, "Lowkey Vault accepts any token")
                .not_applicable_all(
                    &[PreflightState, DescribeVersionState],
                    "Lowkey Vault answers a disabled key's read with 404, so describe and \
                     preflight fail with NotFound (Azure reads it: §24.4 probe T3)",
                ),
            // Key states are classified on the inner code (§24.4 probe T3, 2026-10-12).
            _ => {
                let caps =
                    caps.supports_all(&[ServerErrorMessages, PreflightState, DescribeVersionState]);
                if self.unauthorized.is_some() {
                    caps.supports(UnauthorizedProvider)
                } else {
                    caps.not_applicable(
                        UnauthorizedProvider,
                        "set ANYKMS_AZURE_UNAUTHORIZED_TOKEN (a token of an identity without a \
                         role on the vault)",
                    )
                }
            }
        };
        caps = if self.mhsm() {
            caps.supports_all(&[Aead])
                .not_applicable_all(
                    &[Rewrap, WrappedDataKeys],
                    "Azure has no server-side rewrap or wrapped-only data keys",
                )
                .not_applicable(
                    OversizePlaintext,
                    "the GCM plaintext limit is not documented (to verify with T13)",
                )
                .not_applicable(RewrapWithAad, "no rewrap")
                .not_applicable(EmptyPlaintext, "to verify with T13")
        } else {
            caps.not_applicable_all(
                &[
                    Aead,
                    Rewrap,
                    WrappedDataKeys,
                    OversizePlaintext,
                    EmptyPlaintext,
                ],
                "Azure standard vaults have no AEAD keys",
            )
        };
        caps = if self.mhsm() && cfg!(feature = "mhsm-hmac") {
            // The handle declares its 64 KiB input limit (the service's limit is to verify with
            // T13; the case MACs exactly that much).
            caps.supports_all(&[Mac, RotateMac, MacInputLimit])
        } else {
            caps.not_applicable_all(
                &[Mac, RotateMac, MacInputLimit],
                "HMAC keys exist on Managed HSM only, behind the mhsm-hmac feature",
            )
        };
        for &alg in SignatureAlgorithm::ALL {
            caps = if alg.is_message_signing() {
                caps.not_applicable(Signing(alg), "Azure has no Ed25519 keys")
            } else {
                caps.supports(Signing(alg))
            };
        }
        caps
    }

    async fn create_key(&self, kind: TestKeyKind, key_use: KeyUse) -> Result<TestKey> {
        let spec = Spec::for_kind(kind).ok_or_else(|| fixture_err("no such key kind"))?;
        if key_use == KeyUse::Shared {
            let mut shared = self.shared.lock().await;
            if let Some(k) = shared.get(&kind) {
                return Ok(k.clone());
            }
            let (name, uri) = self.create(spec).await?;
            let k = TestKey::new(uri, name, kind);
            shared.insert(kind, k.clone());
            return Ok(k);
        }
        let (name, uri) = self.create(spec).await?;
        Ok(TestKey::new(uri, name, kind))
    }

    async fn rotate(&self, key: &TestKey) -> Result<TestKey> {
        self.admin.rotate(&key.name).await?;
        Ok(key.clone())
    }

    async fn disable(&self, key: &TestKey) -> Result<()> {
        for v in self.admin.versions(&key.name).await? {
            self.admin.set_enabled(&key.name, &v, false).await?;
        }
        Ok(())
    }

    async fn disable_version(
        &self,
        key: &TestKey,
        version: &anykms_core::KeyVersion,
    ) -> Result<()> {
        self.admin
            .set_enabled(&key.name, version.as_str(), false)
            .await
    }

    fn missing_key_uri(&self, _: TestKeyKind) -> KeyUri {
        self.uri(&format!("{}-missing", self.prefix))
    }

    fn provider(&self) -> Arc<dyn Provider> {
        Arc::new(self.provider.clone())
    }

    fn typed(&self) -> Arc<dyn TypedHandles> {
        Arc::new(Typed(self.provider.clone()))
    }

    fn counting(&self) -> Option<Counting> {
        let n = Arc::new(AtomicU64::new(0));
        let p = self
            .builder
            .clone()
            .__count_requests(n.clone())
            .build()
            .ok()?;
        Some(Counting::new(
            Arc::new(p.clone()),
            Arc::new(Typed(p)),
            Arc::new(move || n.load(Ordering::SeqCst)),
        ))
    }

    fn secret_markers(&self) -> Vec<String> {
        self.markers.clone()
    }

    fn unauthorized_provider(&self) -> Option<Arc<dyn Provider>> {
        self.unauthorized
            .clone()
            .map(|p| Arc::new(p) as Arc<dyn Provider>)
    }
}

/// The typed path: `AzureProvider`'s typed handles bridged with exactly their parts.
pub struct Typed(pub AzureProvider);

anykms_conformance::typed_handles! {
    impl for Typed => |t| &t.0;
    preflight;
    digest_key => digest_signing_key;
    {
    fn aead(&self, uri: &KeyUri) -> Result<AeadKeyHandles> {
        let k = Arc::new(self.0.aead_key(uri)?);
        let s = k.semantics().clone();
        Ok(AeadKeyHandles::bridge(k.clone())
            .with_data_keys(anykms_recipes::EmulatedDataKeys::new(k.clone()))
            .with_semantics(s)
            .with_preflight(k))
    }

    fn key_wrap(&self, uri: &KeyUri) -> Result<KeyWrapKeyHandles> {
        let k = Arc::new(self.0.key_wrap_key(uri)?);
        let s = k.semantics().clone();
        Ok(KeyWrapKeyHandles::bridge(k.clone())
            .with_public_keys(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }

    fn data_keys(&self, uri: &KeyUri) -> Result<DataKeysKey> {
        // A vault's data keys: `KeyWrapDataKeys` (non-empty AAD refused), as the provider's.
        let kw = self.0.key_wrap_key(uri)?;
        let s = kw
            .semantics()
            .clone()
            .with_ciphertext_reveals_version(false)
            .with_data_keys(Some(anykms_core::DataKeySource::emulated(
                anykms_core::DataKeyAad::Refused,
            )));
        Ok(DataKeysKey::new(
            "typed",
            Arc::new(anykms_recipes::KeyWrapDataKeys::new(kw.clone())),
        )
        .with_describe(Arc::new(kw))
        .with_semantics(s))
    }


    #[cfg(feature = "mhsm-hmac")]
    fn mac_key(
        &self,
        uri: &KeyUri,
        alg: MacAlgorithm,
    ) -> Result<anykms_conformance::MacKeyHandles> {
        let k = Arc::new(self.0.mac_key(uri, alg)?);
        let s = k.semantics().clone();
        Ok(anykms_conformance::MacKeyHandles::bridge(k.clone())
            .with_semantics(s)
            .with_preflight(k))
    }
    }
}

#[cfg(not(feature = "mhsm-hmac"))]
#[allow(unused)]
fn _unused(_: MacAlgorithm) {}
