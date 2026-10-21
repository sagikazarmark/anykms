//! Captures every log line at TRACE (reqwest and hyper included, through the log bridge) while
//! running operations whose requests and responses carry marker secrets, and asserts the
//! markers never appear in logs or errors (`Display`, `Debug`, and every error in the
//! `source()` chain).
//!
//! Covered: encrypt, decrypt, sign, verify, MAC and its verification, RSA key wrapping, every
//! credential type (static, metadata server, authorized_user, external_account with STS and
//! impersonation, impersonated SA, self-signed service-account JWT), the 401 refresh, server
//! errors echoing input, undecodable and oversized responses, transport errors, token endpoint
//! errors and (feature `google-cloud-auth`) tokens from Google's auth library, failing ones
//! included. Every handle error must name its key. Every `anykms.gcp*` span must carry
//! exactly the shared field schema (`anykms_http::span`, asserted through `anykms-testkit`), and
//! `Debug` of every config, builder and credential type redacts proxy userinfo, secrets and
//! tokens (P1-1). Run with `--features tracing`.

#![cfg(feature = "tracing")]

mod common;

use std::fmt::Write as _;
use std::sync::Arc;

use anykms_core::prelude::*;
use anykms_core::{
    BoxFuture, Ciphertext, Digest, KeyVersion, MacAlgorithm, SignatureAlgorithm, Tag,
};
use anykms_gcp::{AuthEndpoints, CredentialSource, Credentials, Endpoint, GcpProvider, Token};
use anykms_testkit::SpanRecorder;
use base64::Engine as _;
use common::fake::{self, FakeKms};
use common::{uri, vuri};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The shared schema (through testkit), plus what the GCP spans record: every request span
/// names a `gcp-kms://` resource, the encrypt span names the version that answered, an error
/// span carries `code` and `request_id`, and a token span its outcome.
fn check_span_schema(spans: &SpanRecorder) {
    anykms_testkit::assert_request_schema(spans, "gcp");
    anykms_testkit::assert_token_schema(spans, "gcp");
    let requests = spans.named("anykms.gcp");
    for s in &requests {
        assert!(
            s.value("resource")
                .is_some_and(|r| r.starts_with("gcp-kms://projects/")),
            "{s:?}"
        );
    }
    assert!(
        requests.iter().any(|s| s.value("op") == Some("encrypt")
            && s.value("outcome") == Some("ok")
            && s.value("key_version").is_some()),
        "no encrypt span recorded key_version"
    );
    assert!(
        requests
            .iter()
            .any(|s| s.value("code").is_some() && s.value("request_id") == Some("fake-req-1")),
        "no error span recorded code and request_id"
    );
    let tokens = spans.named("anykms.gcp.token");
    assert!(
        tokens.iter().any(|s| s.value("outcome") == Some("ok")
            && s.value("expires_in_s").is_some()
            && s.value("latency_ms").is_some()),
        "no token span recorded its outcome"
    );
    assert!(
        tokens
            .iter()
            .any(|s| s.value("credential") == Some("custom") && s.value("outcome") == Some("ok")),
        "a custom source runs in a token span (P1-7)"
    );
}

const PROXY_SECRET: &str = "HYGIENEPROXYSECRET0123";

/// A custom source handing out [`TOKEN`] for an hour.
#[derive(Debug)]
struct Custom;

impl CredentialSource for Custom {
    fn token(&self) -> BoxFuture<'_, anykms_core::Result<Option<Token>>> {
        let t = Token::new(
            TOKEN,
            std::time::SystemTime::now().checked_add(std::time::Duration::from_secs(3600)),
        );
        Box::pin(async move { Ok(Some(t)) })
    }
}

/// P1-1: `Debug` of every public config, builder and credential type holding a proxy with
/// userinfo, a custom endpoint with userinfo, a token or a secret prints none of them.
#[test]
fn debug_output_redacts_secrets() {
    // Proxies live on the transport: its builder redacts the URL's userinfo and query.
    let proxy = anykms_gcp::anykms_http::ReqwestTransport::builder().proxy(Some(format!(
        "http://user:{PROXY_SECRET}@proxy.example:3128/p?token={PROXY_SECRET}"
    )));
    let transport = || proxy.clone().require_roots(false).build().unwrap();
    let secrets = [PROXY_SECRET, TOKEN, CLIENT_SECRET, fake::REFRESH_TOKEN];
    anykms_testkit::assert_debug_redacts(&proxy, &secrets);
    anykms_testkit::assert_debug_redacts(&transport(), &secrets);
    let endpoint = Endpoint::custom(format!("https://u:{PROXY_SECRET}@kms.example/?t={TOKEN}"));
    anykms_testkit::assert_debug_redacts(&endpoint, &secrets);
    let creds = [
        Credentials::static_token(TOKEN),
        Credentials::from_json(
            json!({"type": "authorized_user", "client_id": "c", "client_secret": CLIENT_SECRET,
                "refresh_token": fake::REFRESH_TOKEN})
            .to_string(),
        ),
        Credentials::impersonated(
            Credentials::static_token(TOKEN),
            "a@p.iam.gserviceaccount.com",
        ),
        Credentials::custom(Arc::new(Custom)),
    ];
    for c in creds {
        anykms_testkit::assert_debug_redacts(&c, &secrets);
        let b = GcpProvider::builder()
            .credentials(c)
            .http_transport(transport())
            .endpoint(endpoint.clone());
        anykms_testkit::assert_debug_redacts(&b, &secrets);
    }
    // A google-cloud-auth credential holding a client secret and a refresh token (building one
    // spawns the library's refresh task, so it needs a runtime).
    #[cfg(feature = "google-cloud-auth")]
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let lib = google_cloud_auth::credentials::user_account::Builder::new(json!({
                "type": "authorized_user", "client_id": "c", "client_secret": CLIENT_SECRET,
                "refresh_token": fake::REFRESH_TOKEN}))
            .build_access_token_credentials()
            .unwrap();
            anykms_testkit::assert_debug_redacts(&Credentials::google_cloud_auth(lib), &secrets);
        });
    anykms_testkit::assert_debug_redacts(&Token::new(TOKEN, None), &secrets);
    let p = GcpProvider::builder()
        .credentials(Credentials::static_token(TOKEN))
        .http_transport(transport())
        .build()
        .unwrap();
    anykms_testkit::assert_debug_redacts(&p, &secrets);
}

const PT: &str = "HYGIENEPLAINTEXT0123456789";
const AAD: &str = "HYGIENEAAD0123456789";
const MSG: &str = "HYGIENEMESSAGE0123456789";
const MAC_DATA: &str = "HYGIENEMACDATA0123456789";
const TOKEN: &str = "ya29.HYGIENETOKEN0123456789";
const CLIENT_SECRET: &str = "HYGIENECLIENTSECRET0123";
const DEK: &[u8; 32] = b"HYGIENEDATAKEY0123456789abcdefgh";

fn b64(s: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// `Display`, `Debug` and the whole `source()` chain of an error.
fn render(e: &anykms_core::Error) -> String {
    let r = e.resource().unwrap_or_else(|| panic!("no resource on {e}"));
    assert!(
        r.starts_with("gcp-kms://projects/") && !r.contains('?'),
        "{r}"
    );
    let mut out = format!("{e}\n{e:?}\n{e:#?}\n");
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        writeln!(out, "{s}\n{s:?}").unwrap();
        src = s.source();
    }
    out
}

fn with_creds(fake: &FakeKms, creds: Credentials) -> GcpProvider {
    common::builder(fake)
        .credentials(creds)
        .auth_endpoints(AuthEndpoints::custom(&fake.uri()).unwrap())
        .build()
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn trace_output_and_errors_never_contain_secrets() {
    let capture = anykms_testkit::capture();

    let fake = FakeKms::start().await;
    fake.accept_token(TOKEN);
    let mut text = String::new();
    let p = common::builder(&fake)
        .credentials(Credentials::static_token(TOKEN))
        .build()
        .unwrap();

    // AEAD.
    let aead = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let k = p.aead_key(uri(&aead)).unwrap();
    let ct = k.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap();
    assert_eq!(
        &*k.decrypt(&ct, AAD.as_bytes()).await.unwrap(),
        PT.as_bytes()
    );
    let e = k.decrypt(&ct, b"wrong").await.unwrap_err();
    text.push_str(&render(&e));
    writeln!(text, "{p:?}\n{k:?}").unwrap();

    // Signing, verification, MAC, RSA key wrapping.
    let ec = fake.create_key("EC_SIGN_P256_SHA256");
    let s = p
        .digest_signing_key(vuri(&ec, 1), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    let d = Digest::sha256(MSG.as_bytes());
    let sig = s.sign_digest(&d).await.unwrap();
    s.verify_digest(&d, &sig).await.unwrap();
    let e = s
        .verify_digest(&Digest::sha256(b"x"), &sig)
        .await
        .unwrap_err();
    text.push_str(&render(&e));
    let ed = fake.create_key("EC_SIGN_ED25519");
    let m = p.ed25519_key(vuri(&ed, 1)).unwrap();
    let sig = m.sign_message(MSG.as_bytes()).await.unwrap();
    m.verify_message(MSG.as_bytes(), &sig).await.unwrap();
    let hm = fake.create_key("HMAC_SHA256");
    let mk = p.mac_key(vuri(&hm, 1), MacAlgorithm::HmacSha256).unwrap();
    let tag = mk.mac(MAC_DATA.as_bytes()).await.unwrap();
    mk.verify_mac(MAC_DATA.as_bytes(), &tag).await.unwrap();
    let bad = Tag::from_parts(
        MacAlgorithm::HmacSha256,
        Some(KeyVersion::from_u64(1)),
        [0; 32],
    );
    text.push_str(&render(
        &mk.verify_mac(MAC_DATA.as_bytes(), &bad).await.unwrap_err(),
    ));
    let rsa = fake.create_key("RSA_DECRYPT_OAEP_2048_SHA256");
    let kek = p.key_wrap_key(vuri(&rsa, 1)).unwrap();
    let w = kek.wrap_key(DEK).await.unwrap();
    assert_eq!(&*kek.unwrap_key(&w).await.unwrap(), DEK);

    // Every credential type through the fake's token endpoints.
    let subject_dir = std::env::temp_dir().join(format!("anykms-gcp-hyg-{}", std::process::id()));
    std::fs::create_dir_all(&subject_dir).unwrap();
    let subject = subject_dir.join("subject");
    std::fs::write(&subject, fake::SUBJECT_TOKEN).unwrap();
    let origin = fake.uri();
    let creds = [
        Credentials::metadata_server(),
        Credentials::from_json(
            json!({"type": "authorized_user", "client_id": "c", "client_secret": CLIENT_SECRET,
                "refresh_token": fake::REFRESH_TOKEN})
            .to_string(),
        ),
        Credentials::from_json(
            json!({"type": "external_account", "audience": "aud",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_url": format!("{origin}/v1/token"),
                "service_account_impersonation_url": format!(
                    "{origin}/v1/projects/-/serviceAccounts/a@p.iam.gserviceaccount.com:generateAccessToken"),
                "credential_source": {"file": subject}})
            .to_string(),
        ),
        Credentials::from_json(
            json!({"type": "impersonated_service_account",
                "service_account_impersonation_url": format!(
                    "{origin}/v1/projects/-/serviceAccounts/a@p.iam.gserviceaccount.com:generateAccessToken"),
                "source_credentials": {"type": "authorized_user", "client_id": "c",
                    "client_secret": CLIENT_SECRET, "refresh_token": fake::REFRESH_TOKEN}})
            .to_string(),
        ),
        Credentials::from_json(service_account_json()),
        Credentials::custom(Arc::new(Custom)),
    ];
    for c in creds {
        writeln!(text, "{c:?}").unwrap();
        let p = with_creds(&fake, c);
        let k = p.aead_key(uri(&aead)).unwrap();
        let ct = k.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap();
        k.decrypt(&ct, AAD.as_bytes()).await.unwrap();
        writeln!(text, "{p:?}").unwrap();
    }
    // The 401 refresh: the fake forgets the metadata token.
    let p = with_creds(&fake, Credentials::metadata_server());
    let k = p.aead_key(uri(&aead)).unwrap();
    k.encrypt(PT.as_bytes(), b"").await.unwrap();
    for n in 1..=20 {
        fake.revoke_token(&format!("ya29.issued-{n}"));
    }
    k.encrypt(PT.as_bytes(), b"").await.unwrap();
    // Token endpoint errors (a refresh token the fake rejects).
    let e = with_creds(
        &fake,
        Credentials::from_json(
            json!({"type": "authorized_user", "client_id": "c", "client_secret": CLIENT_SECRET,
                "refresh_token": "1//HYGIENEBADREFRESH"})
            .to_string(),
        ),
    )
    .aead_key(uri(&aead))
    .unwrap()
    .encrypt(PT.as_bytes(), b"")
    .await
    .unwrap_err();
    text.push_str(&render(&e));

    // Server errors echoing input, undecodable and oversized bodies, a transport error.
    let server = MockServer::start().await;
    let key = "projects/fake-project/locations/global/keyRings/r/cryptoKeys/m";
    Mock::given(method("POST"))
        .and(path(format!("/v1/{key}:encrypt")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": {
            "code": 500, "status": "INTERNAL", "message": format!("odd {PT} {}", b64(PT))}})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{key}:decrypt")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"plaintext": format!("!{PT}!"), "plaintextCrc32c": "1"})),
        )
        .mount(&server)
        .await;
    let mp = GcpProvider::builder()
        .credentials(Credentials::static_token(TOKEN))
        .endpoint(Endpoint::custom(server.uri()))
        .allow_loopback_http()
        .build()
        .unwrap();
    let mk = mp
        .aead_key(uri(key))
        .unwrap()
        .with_key_type_check(anykms_core::KeyTypeCheck::TrustCaller);
    text.push_str(&render(
        &mk.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap_err(),
    ));
    text.push_str(&render(
        &mk.decrypt(&Ciphertext::from_bytes(b"c".to_vec()), AAD.as_bytes())
            .await
            .unwrap_err(),
    ));
    let closed = GcpProvider::builder()
        .credentials(Credentials::static_token(TOKEN))
        .endpoint(Endpoint::custom("http://127.0.0.1:9"))
        .allow_loopback_http()
        .build()
        .unwrap();
    text.push_str(&render(
        &closed
            .aead_key(uri(key))
            .unwrap()
            .encrypt(PT.as_bytes(), AAD.as_bytes())
            .await
            .unwrap_err(),
    ));

    check_span_schema(capture.spans());
    let logs = capture.text();
    assert!(logs.contains("anykms.gcp"), "no spans captured");
    assert!(logs.contains("anykms.gcp.token"), "no token spans captured");
    assert!(
        logs.contains("hyper") || logs.contains("reqwest"),
        "no HTTP-stack logs captured"
    );
    let all = format!("{logs}\n{text}");
    for marker in [
        PT.to_owned(),
        b64(PT),
        AAD.to_owned(),
        b64(AAD),
        MSG.to_owned(),
        MAC_DATA.to_owned(),
        b64(MAC_DATA),
        TOKEN.to_owned(),
        CLIENT_SECRET.to_owned(),
        fake::REFRESH_TOKEN.to_owned(),
        "HYGIENEBADREFRESH".to_owned(),
        fake::SUBJECT_TOKEN.to_owned(),
        "ya29.issued".to_owned(),
        "ya29.impersonated".to_owned(),
        "PRIVATE KEY".to_owned(),
        // `{"alg":"RS256",` base64url: a self-signed JWT.
        "eyJhbGciOiJSUzI1NiIs".to_owned(),
        b64(DEK),
        String::from_utf8_lossy(DEK).into_owned(),
    ] {
        assert!(!all.contains(&marker), "marker {marker:?} leaked");
    }
}

fn service_account_json() -> String {
    use aws_lc_rs::encoding::AsDer as _;
    let kp = aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'_> = kp.as_der().unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64(der.as_ref())
    );
    json!({"type": "service_account", "private_key_id": "kid", "private_key": pem,
        "client_email": "app@fake-project.iam.gserviceaccount.com"})
    .to_string()
}

/// The `google-cloud-auth` bridge at TRACE: the library's token (a marker) authorizes real
/// requests and a failing library's error is rendered with its source chain; neither the logs nor
/// the errors contain the marker, and each fetch runs inside a token span of the shared schema.
#[cfg(feature = "google-cloud-auth")]
#[tokio::test(flavor = "current_thread")]
async fn google_cloud_auth_tokens_never_appear_in_trace_output_or_errors() {
    use google_cloud_auth::credentials::{
        AccessToken, AccessTokenCredentials, AccessTokenCredentialsProvider, CacheableResource,
        CredentialsProvider,
    };
    use google_cloud_auth::errors::CredentialsError;

    const LIB_TOKEN: &str = "ya29.HYGIENELIBRARYTOKEN0123456789";

    /// Hands out `LIB_TOKEN`, or fails (transient) when `fail`.
    #[derive(Debug)]
    struct Lib {
        fail: bool,
    }
    impl CredentialsProvider for Lib {
        async fn headers(
            &self,
            _: http::Extensions,
        ) -> Result<CacheableResource<http::HeaderMap>, CredentialsError> {
            Err(CredentialsError::from_msg(false, "unused"))
        }
        async fn universe_domain(&self) -> Option<String> {
            None
        }
    }
    impl AccessTokenCredentialsProvider for Lib {
        async fn access_token(&self) -> Result<AccessToken, CredentialsError> {
            if self.fail {
                return Err(CredentialsError::from_msg(
                    true,
                    "metadata server unreachable",
                ));
            }
            Ok(AccessToken {
                token: LIB_TOKEN.into(),
            })
        }
    }
    let creds = |fail| Credentials::google_cloud_auth(AccessTokenCredentials::from(Lib { fail }));

    let capture = anykms_testkit::capture();
    let fake = FakeKms::start().await;
    fake.accept_token(LIB_TOKEN);
    let aead = fake.create_key("GOOGLE_SYMMETRIC_ENCRYPTION");
    let p = common::builder(&fake)
        .credentials(creds(false))
        .build()
        .unwrap();
    let k = p.aead_key(uri(&aead)).unwrap();
    let ct = k.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap();
    k.decrypt(&ct, AAD.as_bytes()).await.unwrap();
    let failing = common::builder(&fake)
        .credentials(creds(true))
        .build()
        .unwrap();
    let e = failing
        .aead_key(uri(&aead))
        .unwrap()
        .encrypt(PT.as_bytes(), AAD.as_bytes())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable, "{e}");

    let mut all = capture.text();
    anykms_testkit::assert_request_schema(capture.spans(), "gcp");
    anykms_testkit::assert_token_schema(capture.spans(), "gcp");
    let tokens = capture.spans().named("anykms.gcp.token");
    assert!(
        tokens
            .iter()
            .any(|s| s.value("credential") == Some("google_cloud_auth")
                && s.value("outcome") == Some("ok")),
        "{tokens:?}"
    );
    assert!(
        tokens.iter().any(|s| s.value("outcome") == Some("error")),
        "{tokens:?}"
    );
    all.push_str(&render(&e));
    writeln!(all, "{p:?}\n{k:?}\n{failing:?}").unwrap();
    for m in [LIB_TOKEN, PT, AAD] {
        assert!(!all.contains(m), "marker {m} leaked:\n{all}");
    }
}
