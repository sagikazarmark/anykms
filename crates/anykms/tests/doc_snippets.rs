//! The Rust snippets of the README, the crate READMEs and the user docs (`docs/*.md` but the plan
//! and the spec), compiled.
//!
//! Each ```` ```rust ```` block of those documents is copied here verbatim, between
//! `// snippet: <document>` and `// end snippet`, inside a function (or module) that supplies
//! what the surrounding prose assumes: a `registry`, an `envelope`, the `rows` of a table.
//! [`snippets_match_the_documents`] fails when a block has no identical copy here, so a snippet
//! edited in a document has to be edited here too, where it must compile. Blocks fenced as
//! ```` ```rust,ignore ```` are not checked. The snippets that need no server also run.
//!
//! `aws-config` and `azure_identity` are not dependencies of this workspace: the modules of the
//! same name below stand in for the few items the bridge snippets call, with the real
//! `aws-credential-types` and `azure_core` types those return, so the anykms side of each bridge
//! is checked.
//!
//! Not part of the published package (`exclude` in Cargo.toml): it reads files outside the crate.

#![allow(unused, clippy::all, clippy::pedantic)]

use std::collections::BTreeMap;
use std::path::Path;

// README.md

/// "Run without Vault": runs on in-memory keys.
#[rustfmt::skip]
mod quick_start {
    // snippet: README.md
    use anykms::local::{LocalKeyset, LocalProvider};
    use anykms::prelude::*;
    use anykms::recipes::EnvelopeAead;
    use anykms::Registry;

    #[tokio::main]
    async fn main() -> anykms::Result<()> {
        // In-memory keys that vanish with the process: development and tests only.
        let keyset = LocalKeyset::builder().aead("app-kek").build();
        let registry = Registry::builder()
            .provider(LocalProvider::new(keyset).allow_ephemeral_local_keys()) // explicit opt-in
            .build()?;

        let kek = registry.key_wrap("local://default/app-kek")?; // the envelope's key-wrapping key
        let envelope = EnvelopeAead::new("app-kek", kek)?;
        let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
        assert_eq!(&*envelope.decrypt(&ct, b"users/42/ssn").await?, b"123-45-6789");
        Ok(())
    }
    // end snippet

    pub(super) fn run() -> anykms::Result<()> {
        main()
    }
}

#[test]
fn quick_start_runs() {
    quick_start::run().unwrap();
}

#[rustfmt::skip]
async fn with_vault() -> anyhow::Result<()> {
    // snippet: README.md
    use anykms::prelude::*;
    use anykms::recipes::EnvelopeAead;

    // VAULT_ADDR, VAULT_TOKEN / VAULT_TOKEN_FILE / ~/.vault-token, VAULT_NAMESPACE, VAULT_CACERT or
    // VAULT_CAPATH, ... (or the BAO_* equivalents). A missing token source is an error. In
    // Kubernetes, ANYKMS_TRANSIT_AUTH=kubernetes and ANYKMS_TRANSIT_AUTH_ROLE=<role> log in and
    // renew the token.
    let registry = anykms::with_default_providers()?
        .layer(anykms::retry_layer()) // every handle retries transient failures
        .build()?;
    // A key-wrapping key: transit AEAD keys wrap data keys by encrypting them with empty AAD.
    let kek = registry.key_wrap("hashivault:///transit-envelope/keys/app-kek")?;

    // Field encryption: the KMS wraps a per-message data key; the payload never leaves the process.
    let envelope = EnvelopeAead::new("app-kek", kek)?;
    let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
    let pt = envelope.decrypt(&ct, b"users/42/ssn").await?;

    // After rotating the KEK: move the data key to the new version, payload untouched.
    let ct = envelope.rewrap(&ct).await?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn skipped_providers() -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use anykms::SkipCause;

    let defaults = anykms::with_default_providers()?;
    for s in defaults.skipped() {
        // A backend whose feature is off, or that the environment opts out of, was never wanted.
        if !matches!(s.cause(), SkipCause::FeatureDisabled | SkipCause::OptedOut) {
            eprintln!("{} not registered: {}", s.backend(), s.reason());
        }
    }
    let registry = defaults.layer(anykms::retry_layer()).build()?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn interactive_policy() -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use anykms::RetryPolicy;

    let registry = anykms::with_default_providers()?
        .layer(anykms::retry_layer().with_policy(RetryPolicy::interactive())) // 3 attempts, 2 s deadline
        .build()?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn env_config() -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use anykms::transit::anykms_http::ReqwestTransport;
    use anykms::transit::{EnvConfig, TransitProvider};

    let server = EnvConfig::vault()
        .no_home_token() // never fall back to ~/.vault-token
        // .no_token()   // behind a Vault/Bao Agent API proxy (or ANYKMS_TRANSIT_NO_TOKEN=1)
        .load()?
        .allowed_namespaces(["team-a"]) // key URIs may select it with ?namespace=team-a
        // TLS, timeouts and proxying live on the transport (replaces VAULT_CACERT & co. here).
        .http_transport(
            ReqwestTransport::builder()
                .request_timeout(std::time::Duration::from_secs(5))
                .build()?,
        );
    let registry = anykms::Registry::builder()
        .provider(TransitProvider::builder().server("default", server).build()?)
        .layer(anykms::retry_layer())
        .build()?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn typed_handles() -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use anykms::transit::TransitProvider;
    use anykms::{MacAlgorithm, SignatureAlgorithm};

    let transit = TransitProvider::from_env()?;
    let uri = "hashivault:///transit/keys/app-kek"; // or a parsed `KeyUri`
    let kek = transit.aead_key(uri)?;                                                // Aead + Rewrap + DataKeys + Describe
    let jwt = transit.digest_signing_key(uri, SignatureAlgorithm::EcdsaP256Sha256)?; // DigestSigner + DigestVerifier + PublicKeys + Describe
    let ed = transit.ed25519_key(uri)?;                                              // MessageSigner + MessageVerifier + PublicKeys + Describe
    let tok = transit.mac_key(uri, MacAlgorithm::HmacSha256)?;                       // Mac + Describe
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn preflight(registry: anykms::Registry) -> anyhow::Result<()> {
    // snippet: docs/guide.md
    let kek = registry.aead("hashivault:///transit/keys/app-kek")?;
    kek.preflight().await?; // KeyMismatch, KeyStateInvalid, NotFound, ... at startup
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn downcast(kek: anykms::AeadKey) -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use anykms::Preflight;
    use anykms::transit::{TransitAeadKey, TransitKeyInfo};

    if let Some(transit_kek) = kek.downcast_ref::<TransitAeadKey>() {
        let info = transit_kek.preflight().await?; // transit's own key-type and state check
        let native: Option<&TransitKeyInfo> = info.backend_info(); // transit's metadata
    }
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn with_a_cloud_kms() -> anyhow::Result<()> {
    // snippet: README.md
    use anykms::prelude::*;
    use anykms::recipes::EnvelopeAead;
    use anykms::SignatureAlgorithm;

    // Every cloud provider whose feature is on is registered; credentials are resolved from the
    // environment on the first operation (AWS credential chain, Application Default Credentials,
    // Entra ID workload or managed identity).
    let registry = anykms::with_default_providers()?.layer(anykms::retry_layer()).build()?;

    let kek = registry.key_wrap("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek")?;
    let envelope = EnvelopeAead::new("app-kek", kek)?;

    // GCP signing keys name their version; Azure keys are addressed by vault host.
    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let signer = registry.digest_signer(
        "gcp-kms://projects/my-project/locations/global/keyRings/r/cryptoKeys/jwt/cryptoKeyVersions/1",
        alg,
    )?;
    let azure_kek = registry.key_wrap("azure-kv://my-vault.vault.azure.net/keys/app-kek")?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
fn from_synchronous_code() -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use anykms::prelude::*;

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let registry = anykms::with_default_providers()?.build()?;
    let kek = registry.key_wrap("hashivault:///transit-envelope/keys/app-kek")?;

    let data_key = [7u8; 32];
    let wrapped = rt.block_on(kek.wrap_key(&data_key))?;
    assert_eq!(&*rt.block_on(kek.unwrap_key(&wrapped))?, &data_key);
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn ciphertexts_as_text(
    envelope: anykms::recipes::EnvelopeAead<anykms::KeyWrapKey>,
) -> anyhow::Result<()> {
    use anykms::prelude::*;

    // snippet: docs/guide.md
    use anykms::Ciphertext;

    let ct = envelope.encrypt(b"123-45-6789", b"users/42/ssn").await?;
    let column: String = ct.to_base64();
    let ct = Ciphertext::from_base64(&column)?;

    // Zeroizing<String>; a plaintext that is not UTF-8 is `InvalidArgument`.
    let ssn = envelope.decrypt_utf8(&ct, b"users/42/ssn").await?;

    // Which KEK version decrypted it, e.g. to find data due for a rewrap. (`used_primary()` stays
    // `None` unless the backend reports it; transit and local do not.)
    let d = envelope.decrypt_with_info(&ct, b"users/42/ssn").await?;
    let version = d.key_version();
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn jwts(registry: anykms::Registry) -> anyhow::Result<()> {
    // snippet: docs/guide.md
    use std::time::Duration;

    use anykms::recipes::jose::{JwtOptions, JwtSigner};
    use anykms::SignatureAlgorithm;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Claims { sub: String, iss: String, aud: String }

    let alg = SignatureAlgorithm::EcdsaP256Sha256;
    let uri = "hashivault:///transit/keys/release";

    // Issuer: the kid is `release.<version>`, cached, so each token costs one KMS sign.
    let signer = JwtSigner::new(registry.digest_signer(uri, alg)?, "release");
    let claims = Claims { sub: "42".into(), iss: "https://issuer.example".into(), aud: "api".into() };
    let jwt = signer.sign(&claims, &JwtOptions::new().with_ttl(Duration::from_secs(300))).await?;

    // Publish at /.well-known/jwks.json: the public key of every enabled version.
    let jwks = signer.jwks().await?;

    // Relying party, with jsonwebtoken (`rust_crypto` or `aws_lc_rs` feature): the key by kid, the
    // algorithm pinned, exp (required by default), iss and aud checked.
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
    let jwks: JwkSet = serde_json::from_value(jwks)?;
    // (`ok_or_else(|| anyhow!(..))` works with anyhow; with `Box<dyn Error>`, `ok_or("..")` does too.)
    let kid = decode_header(&jwt)?.kid.ok_or_else(|| anyhow::anyhow!("token has no kid"))?;
    let key = DecodingKey::from_jwk(jwks.find(&kid).ok_or_else(|| anyhow::anyhow!("unknown kid"))?)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://issuer.example"]);
    validation.set_audience(&["api"]);
    let claims: Claims = decode(&jwt, &key, &validation)?.claims;
    // end snippet
    Ok(())
}

fn process(_: &[u8]) {}
fn report_stale_row(_: &str, _: &anykms::Error) {}
fn report_bad_row(_: &str, _: &anykms::Error) {}

#[rustfmt::skip]
async fn errors(kek: anykms::AeadKey, rows: Vec<(&str, anykms::Ciphertext)>) -> anykms::Result<()> {
    use anykms::prelude::*;

    // snippet: docs/errors.md
    use anykms::ErrorKind;

    for (id, ct) in rows {
        match kek.decrypt(&ct, id.as_bytes()).await {
            Ok(pt) => process(&pt),
            Err(e) if e.kind() == ErrorKind::KeyVersionUnusable => report_stale_row(id, &e),
            Err(e) if e.is_caller_error() => report_bad_row(id, &e), // tampered, wrong AAD, ...
            Err(e) => return Err(e), // config errors: alert; retryable ones were already retried
        }
    }
    // end snippet
    Ok(())
}

#[rustfmt::skip]
fn errors_as_http(e: &anykms::Error, input_from_request: bool, verifying_token: bool) {
    // snippet: docs/errors.md
    use anykms::ErrorClass;

    let (status, retry_after) = match e.class() {
        ErrorClass::Caller if !input_from_request => (500, None), // stored data: integrity, alert
        ErrorClass::Caller if verifying_token => (401, None),
        ErrorClass::Caller => (400, None),
        ErrorClass::Hinted(d) => (503, Some(d)),
        ErrorClass::Retryable(d) => (503, d),
        _ => (500, None), // Config, and classes added later
    };
    // end snippet
}

/// "Testing your application": runs on in-memory keys.
#[rustfmt::skip]
fn local_faults() -> anykms::Result<()> {
    // snippet: docs/testing.md
    use anykms::local::{Fault, LocalKeyset, LocalProvider};
    use anykms::{ErrorKind, Operation};

    let ks = LocalKeyset::builder().aead("kek").hmac("tokens").build();
    let registry = anykms::Registry::builder()
        .provider(LocalProvider::new(ks.clone()).allow_ephemeral_local_keys()) // explicit opt-in
        .build()?;
    ks.rotate("kek")?;                                        // exercise rotation
    ks.inject(Fault::throttled(2));                           // exercise retries
    ks.inject_for_key("tokens", Fault::permission_denied(1)); // exercise error mapping
    ks.inject_on(Operation::Decrypt, Fault::of_kind(ErrorKind::DecryptFailed, 1)); // one operation
    // end snippet
    Ok(())
}

#[test]
fn local_faults_run() {
    local_faults().unwrap();
}

/// A hand-written fake: runs.
#[rustfmt::skip]
async fn fake_kek() -> anykms::Result<()> {
    // snippet: docs/testing.md
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use anykms::prelude::*;
    use anykms::{
        AeadKey, Ciphertext, Error, ErrorKind, Result, RetryLayer, RetryPolicy, Zeroizing, instant_sleep,
    };

    /// Throttled twice, then "encrypts" by prefixing the AAD. Never use outside tests.
    struct FakeKek {
        calls: AtomicU32,
    }

    impl Aead for FakeKek {
        async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
            if self.calls.fetch_add(1, Ordering::Relaxed) < 2 {
                return Err(Error::app(ErrorKind::Throttled, "fake throttling"));
            }
            Ok(Ciphertext::from_bytes([aad, plaintext].concat()))
        }

        async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            match ct.as_bytes().strip_prefix(aad) {
                Some(pt) => Ok(Zeroizing::new(pt.to_vec())),
                None => Err(Error::app(ErrorKind::DecryptFailed, "fake: wrong AAD")),
            }
        }
    }

    // Code under test takes an `AeadKey` (or `impl Aead`), so the fake slots in.
    let retry = RetryLayer::new(instant_sleep()).with_policy(RetryPolicy::immediate());
    let kek = AeadKey::new("fake", Arc::new(FakeKek { calls: AtomicU32::new(0) })).layer(&retry);
    let ct = kek.encrypt(b"123-45-6789", b"users/42/ssn").await?; // two retries, then success
    assert_eq!(&*kek.decrypt(&ct, b"users/42/ssn").await?, b"123-45-6789");
    // end snippet
    Ok(())
}

#[tokio::test]
async fn fake_kek_runs() {
    fake_kek().await.unwrap();
}

#[rustfmt::skip]
async fn generic_code(registry: anykms::Registry) -> anykms::Result<()> {
    // snippet: docs/guide.md
    use std::sync::Arc;

    use anykms::prelude::*;
    use anykms::{AeadKey, Ciphertext, DynAead, Result};

    async fn seal<A: Aead + ?Sized>(key: &A, field: &str, value: &str) -> Result<Ciphertext> {
        key.encrypt(value.as_bytes(), field.as_bytes()).await
    }

    #[derive(Clone)]
    struct AppState {
        kek: AeadKey, // Send + Sync + 'static; share it across tasks by cloning, no Arc needed
    }

    let state = AppState { kek: registry.aead("hashivault:///transit/keys/app-kek")? };
    seal(&state.kek, "users/42/ssn", "123-45-6789").await?;

    let dynamic: Arc<dyn DynAead> = Arc::new(state.kek.clone()); // any handle, typed or opaque
    seal(&*dynamic, "users/42/ssn", "123-45-6789").await?;
    // end snippet
    Ok(())
}

// The crate READMEs

#[rustfmt::skip]
async fn aws_readme() -> anyhow::Result<()> {
    // snippet: crates/anykms-aws/README.md
    use anykms_core::prelude::*;

    let aws = anykms_aws::AwsProvider::from_env()?; // no I/O; credentials on first use
    let kek = aws.aead_key("aws-kms://arn:aws:kms:eu-west-1:111122223333:alias/app-kek")?;
    let ct = kek.encrypt(b"secret", b"users/42").await?; // AAD → encryption context
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn azure_readme() -> anyhow::Result<()> {
    // snippet: crates/anykms-azure/README.md
    use anykms_core::prelude::*;

    let azure = anykms_azure::AzureProvider::from_env()?; // no I/O; credentials on first use
    let kek = azure.key_wrap_key("azure-kv://contoso-prod.vault.azure.net/keys/app-kek")?;
    let wrapped = kek.wrap_key(&[7u8; 32]).await?; // RSA-OAEP-256, framed with the key version
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn gcp_readme() -> anyhow::Result<()> {
    // snippet: crates/anykms-gcp/README.md
    use anykms_core::prelude::*;

    let gcp = anykms_gcp::GcpProvider::from_env()?; // no I/O; credentials on first use
    let kek = gcp.aead_key("gcp-kms://projects/my-project/locations/global/keyRings/app/cryptoKeys/kek")?;
    let ct = kek.encrypt(b"secret", b"users/42").await?;
    // end snippet
    Ok(())
}

// The operator guides

#[rustfmt::skip]
async fn aws_compact_tag(mac: anykms::MacKey, token_id: &[u8]) -> anyhow::Result<()> {
    use anykms::Tag;
    use anykms::prelude::*;

    // snippet: docs/operations-aws.md
    let tag = mac.mac(token_id).await?;
    let stored = tag.as_bytes().to_vec(); // no algorithm, no ARN
    // Later: the handle's algorithm, no version.
    let tag = Tag::from_parts(mac.mac_algorithm(), None, stored);
    mac.verify_mac(token_id, &tag).await?;
    // end snippet
    Ok(())
}

/// Stands in for `aws-config` (see the module docs).
mod aws_config {
    use aws_credential_types::provider::SharedCredentialsProvider;

    pub struct BehaviorVersion;

    impl BehaviorVersion {
        pub fn latest() -> Self {
            Self
        }
    }

    pub struct SdkConfig;

    impl SdkConfig {
        pub fn credentials_provider(&self) -> Option<SharedCredentialsProvider> {
            unimplemented!("compile-only stand-in")
        }
    }

    pub async fn load_defaults(_: BehaviorVersion) -> SdkConfig {
        SdkConfig
    }
}

#[rustfmt::skip]
async fn aws_sdk_credentials() -> anyhow::Result<()> {
    use anykms::aws::AwsProvider;

    // snippet: docs/operations-aws.md
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let provider = AwsProvider::builder()
        .credentials(anykms_aws::credentials::SdkCredentials::new(
            sdk.credentials_provider().expect("credentials"),
        ))
        .build()?;
    // end snippet
    Ok(())
}

/// Stands in for `azure_identity` (see the module docs).
mod azure_identity {
    use std::sync::Arc;

    use azure_core::credentials::TokenCredential;

    pub struct AzureCliCredential;

    impl AzureCliCredential {
        /// The real one returns `Arc<AzureCliCredential>`, which coerces to this.
        pub fn new(_: Option<()>) -> azure_core::Result<Arc<dyn TokenCredential>> {
            unimplemented!("compile-only stand-in")
        }
    }
}

#[rustfmt::skip]
async fn azure_identity_credentials() -> anyhow::Result<()> {
    use anykms::azure::AzureProviderBuilder;

    // snippet: docs/operations-azure.md
    let cli = azure_identity::AzureCliCredential::new(None)?;
    let provider = AzureProviderBuilder::default()
        .credential(anykms_azure::AzureIdentity::new(cli))
        .build()?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn gcp_google_cloud_auth() -> anyhow::Result<()> {
    use anykms::gcp::{Credentials, GcpProvider};

    // snippet: docs/operations-gcp.md
    let creds = google_cloud_auth::credentials::Builder::default().build_access_token_credentials()?;
    let provider = GcpProvider::builder()
        .credentials(Credentials::google_cloud_auth(creds))
        .build()?;
    // end snippet
    Ok(())
}

#[rustfmt::skip]
async fn retry_layers(
    kek_uri: String,
    mac_uri: String,
    transit: anykms::transit::TransitProvider,
) -> anyhow::Result<()> {
    use anykms::MacAlgorithm;

    // snippet: docs/operations.md
    let registry = anykms::with_default_providers()?
        .layer(anykms::retry_layer())                          // one budget for every handle and backend
        .build()?;
    // Or per handle of a registry without a retry layer, with one shared layer:
    let retry = anykms::retry_layer();
    let kek = registry.aead(&kek_uri)?.layer(&retry);
    let mac = registry.mac(&mac_uri, MacAlgorithm::HmacSha256)?.layer(&retry);
    // Typed handles take the same layer as a decorator:
    let typed = retry.wrap(transit.aead_key(&kek_uri)?);
    // end snippet
    Ok(())
}

fn record_attempt(_: &anykms::OpEvent<'_>) {}
fn record_call(_: &anykms::OpEvent<'_>) {}

#[rustfmt::skip]
async fn observe_layers() -> anyhow::Result<()> {
    use anykms::ObserveLayer;

    // snippet: docs/operations.md
    let registry = anykms::with_default_providers()?
        .layer(ObserveLayer::new(record_attempt))   // every backend request
        .layer(anykms::retry_layer())
        .layer(ObserveLayer::new(record_call))      // every call, retries included
        .build()?;
    // end snippet
    Ok(())
}

// The check

/// The `rust` blocks of the documents, by document (relative to the workspace root).
fn document_snippets(root: &Path) -> Vec<(String, usize, String)> {
    let mut docs = vec!["README.md".to_owned()];
    for dir in ["crates", "docs"] {
        let mut names: Vec<String> = std::fs::read_dir(root.join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter_map(|p| {
                let rel = p.strip_prefix(root).unwrap().to_str()?.to_owned();
                match dir {
                    "crates" => Some(format!("{rel}/README.md")).filter(|r| root.join(r).is_file()),
                    // The plan and the spec hold design sketches, not user-facing snippets.
                    _ => {
                        let name = p.file_name()?.to_str()?;
                        (name.ends_with(".md") && !matches!(name, "PLAN.md" | "spec.md"))
                            .then_some(rel)
                    }
                }
            })
            .collect();
        names.sort();
        docs.extend(names);
    }
    let mut out = Vec::new();
    for doc in docs {
        let text = std::fs::read_to_string(root.join(&doc)).unwrap();
        let mut lines = text.lines().enumerate();
        while let Some((n, line)) = lines.next() {
            let Some(info) = line.trim_start().strip_prefix("```") else {
                continue;
            };
            let body: Vec<&str> = lines
                .by_ref()
                .take_while(|(_, l)| !l.trim_start().starts_with("```"))
                .map(|(_, l)| l)
                .collect();
            let attrs: Vec<&str> = info.split(',').map(str::trim).collect();
            if attrs[0] == "rust" && !attrs.contains(&"ignore") {
                out.push((doc.clone(), n + 1, dedent(&body)));
            }
        }
    }
    out
}

/// The copies in this file, by document.
fn copied_snippets() -> Vec<(String, String)> {
    let source = include_str!("doc_snippets.rs");
    let mut out = Vec::new();
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let Some(doc) = line.trim().strip_prefix("// snippet: ") else {
            continue;
        };
        let body: Vec<&str> = lines
            .by_ref()
            .take_while(|l| l.trim() != "// end snippet")
            .collect();
        out.push((doc.to_owned(), dedent(&body)));
    }
    out
}

/// The lines without their common indentation, joined.
fn dedent(lines: &[&str]) -> String {
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let lines: Vec<&str> = lines
        .iter()
        .map(|l| l.get(indent..).unwrap_or("").trim_end())
        .collect();
    lines.join("\n")
}

#[test]
fn snippets_match_the_documents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let documents = document_snippets(&root);
    let copies = copied_snippets();
    let mut errors = Vec::new();
    for (doc, line, text) in &documents {
        if !copies.iter().any(|(d, t)| d == doc && t == text) {
            errors.push(format!(
                "{doc}:{line}: no identical copy in crates/anykms/tests/doc_snippets.rs:\n{text}"
            ));
        }
    }
    for (doc, text) in &copies {
        if !documents.iter().any(|(d, _, t)| d == doc && t == text) {
            errors.push(format!(
                "a copy of a snippet that {doc} no longer has:\n{text}"
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n\n"));
}
