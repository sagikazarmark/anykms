//! Captures every log line at TRACE (including reqwest and hyper) while running operations whose
//! requests and responses carry marker secrets, and asserts the markers never appear in logs or
//! errors (`Display`, `Debug`, the `source()` chain).
//!
//! Covered: access tokens (static, client secret, workload identity, managed identity with a
//! marker client id in the IMDS query string; with feature `azure-identity`, an Azure SDK
//! credential, failing ones included), the client secret and the federated token,
//! wrapped and unwrapped keys, AES-GCM plaintext and AAD, data keys, server error messages that
//! echo input, the 401 refresh, transport errors, oversize and undecodable responses. Every key
//! error names its key. The span schema (D3) and the `Debug` output of every public
//! configuration and credential type (P1-1) are checked too. Run with `--features tracing`.
//!
//! Captures are the thread's subscriber (`anykms_testkit::capture`); this binary installs no
//! global subscriber.

#![cfg(feature = "tracing")]

use std::fmt::Write as _;

use anykms_azure::{
    AzureCredential, AzureProvider, ClientSecret, ManagedIdentity, StaticToken, TestHost,
    WorkloadIdentity, framing,
};
use anykms_core::prelude::*;
use anykms_core::{Ciphertext, DataKeySpec, Digest, KeyVersion, OpenOptions, Provider, Signature};
use base64::Engine as _;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SCOPE: &str = "https://vault.azure.net/.default";
const V1: &str = "0123456789abcdef0123456789abcdef";
const TOKEN: &str = "HYGIENE-STATIC-TOKEN-0123456789";
const SECRET: &str = "HYGIENE-CLIENT-SECRET-0123456789";
const SECRET_TOKEN: &str = "HYGIENE-SECRET-ACCESS-TOKEN-0123";
const FEDERATED: &str = "HYGIENE-FEDERATED-JWT-0123456789";
const WI_TOKEN: &str = "HYGIENE-WI-ACCESS-TOKEN-01234567";
const MI_CLIENT: &str = "HYGIENE-MI-CLIENT-ID-0123456789";
const MI_TOKEN: &str = "HYGIENE-MI-ACCESS-TOKEN-01234567";
const DEK: &[u8; 32] = b"HYGIENEDATAKEY0123456789abcdefgh";
const PT: &str = "HYGIENEPLAINTEXT0123456789";
const AAD: &str = "HYGIENEAAD0123456789";
const ECHO: &str = "HYGIENE-ECHOED-INPUT-0123456789";

fn b64u(b: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn render(e: &anykms_core::Error, key_error: bool) -> String {
    if key_error {
        let r = e.resource().unwrap_or_else(|| panic!("no resource on {e}"));
        assert!(r.starts_with("azure-kv://") && !r.contains('?'), "{r}");
    }
    let mut out = format!("{e}\n{e:?}\n");
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        writeln!(out, "{s}\n{s:?}").unwrap();
        src = s.source();
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn trace_output_and_errors_never_contain_secrets() {
    let capture = anykms_testkit::capture();

    let server = MockServer::start().await;
    let host = server.address().to_string();
    let kid = |n: &str| format!("https://{host}/keys/{n}/{V1}");
    let rsa_der = anykms_recipes::pem_to_der(include_str!("data/rsa_2048.spki.pem")).unwrap();
    let n = b64u(&rsa_der[rsa_der.len() - 5 - 256..rsa_der.len() - 5]);
    for name in ["kek", "kek2"] {
        Mock::given(method("GET"))
            .and(path(format!("/keys/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": {"kid": kid(name), "kty": "RSA", "n": n, "e": "AQAB", "key_ops": ["wrapKey", "unwrapKey"]},
                "attributes": {"enabled": true}
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/keys/kek/wrapkey"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": kid("kek"), "value": b64u([7u8; 256])})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/kek/{V1}/unwrapkey")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kid": kid("kek"), "value": b64u(DEK)})),
        )
        .mount(&server)
        .await;
    // An error that echoes the request.
    Mock::given(method("POST"))
        .and(path("/keys/kek2/wrapkey"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {"code": "BadParameter", "message": format!("bad value {ECHO} {}", b64u(DEK))}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/kek2/{V1}/unwrapkey")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("{{\"value\":\"{ECHO}")))
        .mount(&server)
        .await;
    // MHSM AES key.
    Mock::given(method("GET"))
        .and(path("/keys/aes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": {"kid": kid("aes"), "kty": "oct-HSM", "key_ops": ["encrypt", "decrypt"]},
            "attributes": {"enabled": true}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/aes/encrypt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kid": kid("aes"), "value": b64u(b"CT"), "iv": b64u([1u8; 12]), "tag": b64u([2u8; 16])
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/keys/aes/{V1}/decrypt")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"kid": kid("aes"), "value": b64u(PT)})),
        )
        .mount(&server)
        .await;
    // A key that always answers 401.
    Mock::given(method("GET"))
        .and(path("/keys/denied"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {"code": "Unauthorized", "message": format!("token {TOKEN} rejected")}
        })))
        .mount(&server)
        .await;
    // Entra, IMDS.
    Mock::given(method("POST"))
        .and(path("/t/oauth2/v2.0/token"))
        .and(wiremock::matchers::body_string_contains("client_secret"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": SECRET_TOKEN, "expires_in": 3600})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/t/oauth2/v2.0/token"))
        .and(wiremock::matchers::body_string_contains("client_assertion="))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client", "error_description": format!("bad assertion {FEDERATED}"), "error_codes": [700_016]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/metadata/identity/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": MI_TOKEN, "expires_on": "4000000000"})),
        )
        .mount(&server)
        .await;

    let mut errors = String::new();
    let th = || TestHost::loopback_http(&host, SCOPE);
    let uri = |n: &str| format!("azure-kv://{host}/keys/{n}");

    // Static token: wrap, unwrap, data keys, error echo, undecodable response.
    let p = AzureProvider::builder()
        .credential(StaticToken::new(TOKEN))
        .test_host(th())
        .build()
        .unwrap();
    let kek = p.key_wrap_key(uri("kek").as_str()).unwrap();
    let w = kek.wrap_key(DEK).await.unwrap();
    let back = kek.unwrap_key(&w).await.unwrap();
    assert_eq!(&*back, DEK);
    let dk = p
        .data_keys(&uri("kek").parse().unwrap(), &OpenOptions::new())
        .unwrap();
    let key = dk
        .generate_data_key(DataKeySpec::Aes256, b"")
        .await
        .unwrap();
    let dbg = format!("{key:?}");
    assert!(!dbg.contains(&b64u(key.plaintext())));
    let kek2 = p.key_wrap_key(uri("kek2").as_str()).unwrap();
    errors.push_str(&render(&kek2.wrap_key(DEK).await.unwrap_err(), true));
    let w2 = Ciphertext::from_bytes(
        framing::encode(framing::FrameAlg::RsaOaep256, V1, &[1; 256]).unwrap(),
    );
    errors.push_str(&render(&kek2.unwrap_key(&w2).await.unwrap_err(), true));
    errors.push_str(&render(
        &p.key_wrap_key(uri("denied").as_str())
            .unwrap()
            .describe()
            .await
            .unwrap_err(),
        true,
    ));
    // Transport error with a reqwest source.
    let dead = AzureProvider::builder()
        .credential(StaticToken::new(TOKEN))
        .test_host(TestHost::loopback_http("127.0.0.1:9", SCOPE))
        .build()
        .unwrap();
    errors.push_str(&render(
        &dead
            .key_wrap_key("azure-kv://127.0.0.1:9/keys/k")
            .unwrap()
            .wrap_key(DEK)
            .await
            .unwrap_err(),
        true,
    ));
    // Verify with a signature the server never sees malformed.
    let sk = p
        .digest_signing_key(
            uri("kek").as_str(),
            anykms_core::SignatureAlgorithm::RsaPssSha256,
        )
        .unwrap();
    let sig = Signature::from_parts(
        anykms_core::SignatureAlgorithm::RsaPssSha256,
        Some(KeyVersion::new(ECHO)),
        vec![0; 256],
    );
    errors.push_str(&render(
        &sk.verify_digest(&Digest::sha256(PT.as_bytes()), &sig)
            .await
            .unwrap_err(),
        true,
    ));

    // MHSM AES-GCM: plaintext and AAD.
    let mp = AzureProvider::builder()
        .credential(StaticToken::new(TOKEN))
        .test_host(th().managed_hsm())
        .build()
        .unwrap();
    let aes = mp.aead_key(uri("aes").as_str()).unwrap();
    let ct = aes.encrypt(PT.as_bytes(), AAD.as_bytes()).await.unwrap();
    assert_eq!(
        &*aes.decrypt(&ct, AAD.as_bytes()).await.unwrap(),
        PT.as_bytes()
    );
    write!(errors, "{ct:?}").unwrap();

    // Client secret, workload identity, managed identity.
    let cs = ClientSecret::new("t", "c", SECRET)
        .unwrap()
        .authority_host(&server.uri())
        .unwrap();
    write!(errors, "{cs:?}").unwrap();
    let t = cs.token(SCOPE).await.unwrap();
    write!(errors, "{t:?}").unwrap();
    let dir = std::env::temp_dir().join(format!("anykms-azure-hygiene-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("token");
    std::fs::write(&file, FEDERATED).unwrap();
    let wi = WorkloadIdentity::new("t", "c", &file)
        .unwrap()
        .authority_host(&server.uri())
        .unwrap();
    errors.push_str(&render(&wi.token(SCOPE).await.unwrap_err(), false));
    write!(errors, "{wi:?}").unwrap();
    let mi = ManagedIdentity::client_id(MI_CLIENT)
        .unwrap()
        .imds_endpoint(&format!("{}/metadata/identity/oauth2/token", server.uri()))
        .unwrap();
    let t = mi.token(SCOPE).await.unwrap();
    assert_eq!(t.secret(), MI_TOKEN);
    let mi_dead = ManagedIdentity::client_id(MI_CLIENT)
        .unwrap()
        .imds_endpoint("http://127.0.0.1:9/metadata/identity/oauth2/token")
        .unwrap();
    errors.push_str(&render(&mi_dead.token(SCOPE).await.unwrap_err(), false));
    // A provider using the client secret end to end.
    let sp = AzureProvider::builder()
        .credential(cs)
        .test_host(th())
        .build()
        .unwrap();
    write!(errors, "{sp:?}").unwrap();
    sp.key_wrap_key(uri("kek").as_str())
        .unwrap()
        .wrap_key(DEK)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let logs = capture.text();
    assert!(
        logs.contains("anykms.azure"),
        "spans are recorded: {}",
        &logs[..logs.len().min(2000)]
    );
    let dek_b64 = b64u(DEK);
    let pt_b64 = b64u(PT);
    let aad_b64 = b64u(AAD);
    let markers: [&str; 14] = [
        TOKEN,
        SECRET,
        SECRET_TOKEN,
        FEDERATED,
        WI_TOKEN,
        MI_CLIENT,
        MI_TOKEN,
        PT,
        AAD,
        ECHO,
        &dek_b64,
        &pt_b64,
        &aad_b64,
        "HYGIENEDATAKEY",
    ];
    for m in markers {
        assert!(!logs.contains(m), "marker {m} in logs");
        assert!(!errors.contains(m), "marker {m} in errors:\n{errors}");
    }
}

// ---------------------------------------------------------------------------------------------
// The span schema (D3, through anykms-testkit): every request and token span declares exactly
// the shared fields, and no other `anykms.azure.*` span exists; the request id is filtered and
// the innermost error code recorded.

#[tokio::test(flavor = "current_thread")]
async fn spans_follow_the_shared_schema() {
    let capture = anykms_testkit::capture();

    let server = MockServer::start().await;
    let host = server.address().to_string();
    let kid = |n: &str| format!("https://{host}/keys/{n}/{V1}");
    let rsa_der = anykms_recipes::pem_to_der(include_str!("data/rsa_2048.spki.pem")).unwrap();
    let n = b64u(&rsa_der[rsa_der.len() - 5 - 256..rsa_der.len() - 5]);
    for name in ["ok", "denied"] {
        Mock::given(method("GET"))
            .and(path(format!("/keys/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": {"kid": kid(name), "kty": "RSA", "n": n, "e": "AQAB", "key_ops": ["sign"]},
                "attributes": {"enabled": true}
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/keys/ok/sign"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-ms-request-id", "rid-ok-1")
                .set_body_json(json!({"kid": kid("ok"), "value": b64u([1u8; 256])})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys/denied/sign"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ms-request-id", format!("rid-{}", "x".repeat(200)))
                .set_body_json(json!({"error": {
                    "code": "Forbidden", "message": "denied",
                    "innererror": {"code": "ForbiddenByRbac"}
                }})),
        )
        .mount(&server)
        .await;
    let p = AzureProvider::builder()
        .credential(StaticToken::new(TOKEN))
        .test_host(TestHost::loopback_http(&host, SCOPE))
        .build()
        .unwrap();
    let alg = anykms_core::SignatureAlgorithm::RsaPssSha256;
    let d = Digest::sha256(b"m");
    p.digest_signing_key(format!("azure-kv://{host}/keys/ok"), alg)
        .unwrap()
        .sign_digest(&d)
        .await
        .unwrap();
    let e = p
        .digest_signing_key(format!("azure-kv://{host}/keys/denied"), alg)
        .unwrap()
        .sign_digest(&d)
        .await
        .unwrap_err();
    assert_eq!(e.detail().unwrap().code(), Some("ForbiddenByRbac"));
    assert_eq!(
        e.detail().unwrap().request_id(),
        None,
        "overlong id dropped"
    );

    anykms_testkit::assert_request_schema(capture.spans(), "azure");
    anykms_testkit::assert_token_schema(capture.spans(), "azure");
    let values: Vec<(String, String)> = capture
        .spans()
        .named("anykms.azure")
        .into_iter()
        .flat_map(|s| s.values.into_iter())
        .collect();
    let has = |field: &str, value: &str| values.iter().any(|(f, v)| f == field && v == value);
    assert!(has("request_id", "rid-ok-1"), "{values:?}");
    assert!(
        !values.iter().any(|(_, v)| v.contains("xxxxxxxx")),
        "unfiltered request id: {values:?}"
    );
    assert!(has("code", "ForbiddenByRbac"), "{values:?}");
    assert!(
        has("resource", &format!("azure-kv://{host}/keys/ok")),
        "{values:?}"
    );
    // A versionless write records the version the response names.
    assert!(has("key_version", V1), "{values:?}");
    assert!(
        has("outcome", "ok") && has("outcome", "error"),
        "{values:?}"
    );
}

/// P1-1: no public configuration, builder or credential type prints a proxy's userinfo, a
/// secret or a token.
#[test]
fn debug_output_redacts_proxies_secrets_and_tokens() {
    use anykms_azure::{AccessToken, AzureOptions, AzureProviderBuilder, Proxy};
    const USER: &str = "PROXYUSER";
    const PASS: &str = "PROXYPASS";
    const QUERY: &str = "URLQUERYSECRET";
    const HEADER: &str = "HYGIENE-IDENTITY-HEADER-0123456";
    let proxy = || {
        Proxy::Url(format!(
            "http://{USER}:{PASS}@proxy.example:3128/?t={QUERY}"
        ))
    };
    let secrets = [USER, PASS, QUERY, TOKEN, SECRET, FEDERATED, HEADER];
    let check = |v: &dyn std::fmt::Debug| anykms_testkit::assert_debug_redacts(v, &secrets);

    check(&proxy());
    let builder = || {
        AzureProviderBuilder::default()
            .credential(StaticToken::new(TOKEN))
            .proxy(proxy())
            .test_host(TestHost::loopback_http("127.0.0.1:8480", SCOPE))
    };
    check(&builder());
    check(&builder().build().unwrap());
    check(&StaticToken::new(TOKEN));
    // An Azure SDK credential that holds a secret: AzureIdentity shows only its Debug, which
    // the SDK redacts.
    #[cfg(feature = "azure-identity")]
    {
        #[derive(Debug)]
        struct SdkCred(azure_core::credentials::Secret);
        #[async_trait::async_trait]
        impl azure_core::credentials::TokenCredential for SdkCred {
            async fn get_token(
                &self,
                _: &[&str],
                _: Option<azure_core::credentials::TokenRequestOptions<'_>>,
            ) -> azure_core::Result<azure_core::credentials::AccessToken> {
                Ok(azure_core::credentials::AccessToken::new(
                    self.0.clone(),
                    azure_core::time::OffsetDateTime::now_utc(),
                ))
            }
        }
        let sdk = anykms_azure::AzureIdentity::new(std::sync::Arc::new(SdkCred(SECRET.into())));
        check(&sdk);
        check(&AzureProviderBuilder::default().credential(sdk));
    }
    check(&AccessToken::new(TOKEN.to_owned(), None));
    check(&ClientSecret::new("t", "c", SECRET).unwrap());
    let dir = std::env::temp_dir().join(format!("anykms-azure-debug-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("token"), FEDERATED).unwrap();
    check(&WorkloadIdentity::new("t", "c", dir.join("token")).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    check(
        &ManagedIdentity::system()
            .app_service("http://127.0.0.1:8081/msi/token", HEADER)
            .unwrap(),
    );
    check(&TestHost::loopback_http("127.0.0.1:8480", SCOPE));
    check(&AzureOptions::new().local_verify());
}

/// The `azure-identity` bridge at TRACE: an Azure SDK credential's token (a marker) authorizes
/// real requests and a failing SDK credential's error is rendered with its source chain; neither
/// the logs nor the errors contain the marker, and each fetch runs inside a token span of the
/// shared schema.
#[cfg(feature = "azure-identity")]
#[tokio::test(flavor = "current_thread")]
async fn azure_identity_tokens_never_appear_in_trace_output_or_errors() {
    use anykms_azure::{AzureIdentity, AzureProviderBuilder};
    use anykms_core::SignatureAlgorithm;
    use azure_core::credentials::{AccessToken as SdkToken, TokenRequestOptions};
    use azure_core::time::{Duration as SdkDuration, OffsetDateTime};

    const SDK_TOKEN: &str = "HYGIENE-SDK-ACCESS-TOKEN-0123456";

    /// Hands out `SDK_TOKEN`, or fails (a connection error) when `fail`.
    #[derive(Debug)]
    struct Sdk {
        fail: bool,
    }
    #[async_trait::async_trait]
    impl azure_core::credentials::TokenCredential for Sdk {
        async fn get_token(
            &self,
            _: &[&str],
            _: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<SdkToken> {
            if self.fail {
                return Err(azure_core::Error::with_message(
                    azure_core::error::ErrorKind::Connection,
                    "login.microsoftonline.com unreachable",
                ));
            }
            Ok(SdkToken::new(
                SDK_TOKEN,
                OffsetDateTime::now_utc() + SdkDuration::hours(1),
            ))
        }
    }

    let capture = anykms_testkit::capture();
    let vault = MockServer::start().await;
    let host = vault.address().to_string();
    Mock::given(method("GET"))
        .and(path("/keys/k"))
        .and(wiremock::matchers::header(
            "authorization",
            format!("Bearer {SDK_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": {"kid": format!("https://{host}/keys/k/{V1}"), "kty": "EC", "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
            "attributes": {"enabled": true}
        })))
        .expect(2)
        .mount(&vault)
        .await;
    let provider = |fail| {
        AzureProviderBuilder::default()
            .credential(AzureIdentity::new(std::sync::Arc::new(Sdk { fail })))
            .test_host(TestHost::loopback_http(&host, SCOPE))
            .build()
            .unwrap()
    };
    let key = format!("azure-kv://{host}/keys/k");
    let ok = provider(false);
    let k = ok
        .digest_signing_key(key.as_str(), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap();
    for _ in 0..2 {
        k.public_key().await.unwrap();
    }
    let failing = provider(true);
    let e = failing
        .digest_signing_key(key.as_str(), SignatureAlgorithm::EcdsaP256Sha256)
        .unwrap()
        .public_key()
        .await
        .unwrap_err();
    assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable, "{e}");

    let mut all = capture.text();
    anykms_testkit::assert_token_schema(capture.spans(), "azure");
    all.push_str(&render(&e, false));
    writeln!(all, "{ok:?}\n{k:?}\n{failing:?}").unwrap();
    assert!(!all.contains(SDK_TOKEN), "the SDK token leaked:\n{all}");
}
