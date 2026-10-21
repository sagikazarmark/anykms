//! Credential sources against mock endpoints: workload identity and client secret (Entra ID
//! token endpoint), managed identity (IMDS and App Service), static
//! tokens, and the environment-driven selection (in child processes, since the environment is
//! process-wide).

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anykms_azure::{
    AzureCredential, AzureProvider, ClientSecret, EnvCredentialKind, ManagedIdentity, StaticToken,
    TestHost, WorkloadIdentity,
};
use anykms_core::prelude::*;
use anykms_core::{ErrorKind, SignatureAlgorithm};
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SCOPE: &str = "https://vault.azure.net/.default";

fn temp_file(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anykms-azure-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn token_ok(token: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({"token_type": "Bearer", "expires_in": 3599, "access_token": token}))
}

#[tokio::test]
async fn workload_identity_reads_the_token_file_at_each_exchange() {
    let server = MockServer::start().await;
    let file = temp_file("federated-token", "assertion-one\n");
    Mock::given(method("POST"))
        .and(path("/my-tenant/oauth2/v2.0/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("client_id=my-client"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .and(body_string_contains("scope=https%3A%2F%2Fvault.azure.net%2F.default"))
        .and(body_string_contains("client_assertion=assertion-one"))
        .respond_with(token_ok("at-1"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/my-tenant/oauth2/v2.0/token"))
        .and(body_string_contains("client_assertion=assertion-two"))
        .respond_with(token_ok("at-2"))
        .expect(1)
        .mount(&server)
        .await;
    let cred = WorkloadIdentity::new("my-tenant", "my-client", &file)
        .unwrap()
        .authority_host(&server.uri())
        .unwrap();
    assert_eq!(cred.kind(), "workload_identity");
    assert_eq!(cred.tenant_id(), Some("my-tenant"));
    let t = cred.token(SCOPE).await.unwrap();
    assert_eq!(t.secret(), "at-1");
    assert!(t.expires_at().unwrap() > SystemTime::now() + Duration::from_mins(50));
    std::fs::write(&file, "assertion-two").unwrap();
    assert_eq!(cred.token(SCOPE).await.unwrap().secret(), "at-2");
    // A missing file is retryable, its contents never shown.
    std::fs::remove_file(&file).unwrap();
    let e = cred.token(SCOPE).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(!format!("{e:?}").contains("assertion"));
    // P1-2: any other failure is a deployment error (`Configuration`), naming the file.
    let dir = file.parent().unwrap().join("federated-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let empty = temp_file("federated-empty", " \n");
    let big = temp_file("federated-big", &"a".repeat(64 * 1024 + 1));
    for p in [dir, empty, big] {
        let cred = WorkloadIdentity::new("my-tenant", "my-client", &p)
            .unwrap()
            .authority_host(&server.uri())
            .unwrap();
        let e = cred.token(SCOPE).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{}: {e}", p.display());
        assert!(e.to_string().contains(&*p.to_string_lossy()), "{e}");
    }
    // Construction does no I/O and validates its inputs.
    assert!(WorkloadIdentity::new("bad/tenant", "c", "/nonexistent").is_err());
    assert!(WorkloadIdentity::new("t", "c", "/nonexistent").is_ok());
    assert!(
        WorkloadIdentity::new("t", "c", "/x")
            .unwrap()
            .authority_host("http://login.example.com")
            .is_err()
    );
}

#[tokio::test]
async fn token_endpoint_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/t/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided for app 1234-SECRET-ID.",
            "error_codes": [7_000_215]
        })))
        .mount(&server)
        .await;
    let cred = ClientSecret::new("t", "c", "SECRET-VALUE-123")
        .unwrap()
        .authority_host(&server.uri())
        .unwrap();
    let dbg = format!("{cred:?}");
    assert!(!dbg.contains("SECRET-VALUE-123"), "{dbg}");
    let e = cred.token(SCOPE).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated);
    assert_eq!(
        e.detail().unwrap().code(),
        Some("invalid_client/AADSTS7000215")
    );
    let rendered = format!("{e} {e:?}");
    assert!(!rendered.contains("SECRET"), "{rendered}");
    // The secret was sent in the form body.
    let reqs = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("client_secret=SECRET-VALUE-123"), "{body}");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "4"))
        .mount(&server)
        .await;
    let cred = ClientSecret::new("t", "c", "s")
        .unwrap()
        .authority_host(&server.uri())
        .unwrap();
    let e = cred.token(SCOPE).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);
    assert_eq!(e.retry_after(), Some(Duration::from_secs(4)));
    assert!(ClientSecret::new("t", "c", "").is_err());
}

#[tokio::test]
async fn managed_identity_imds_and_app_service() {
    let server = MockServer::start().await;
    let on = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    Mock::given(method("GET"))
        .and(path("/metadata/identity/oauth2/token"))
        .and(header("metadata", "true"))
        .and(query_param("api-version", "2018-02-01"))
        .and(query_param("resource", "https://vault.azure.net"))
        .and(query_param("client_id", "uami-client"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mi-token", "expires_on": on.to_string(), "expires_in": "3599",
            "resource": "https://vault.azure.net", "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let imds = format!("{}/metadata/identity/oauth2/token", server.uri());
    let cred = ManagedIdentity::client_id("uami-client")
        .unwrap()
        .imds_endpoint(&imds)
        .unwrap();
    let t = cred.token(SCOPE).await.unwrap();
    assert_eq!(t.secret(), "mi-token");
    assert_eq!(
        t.expires_at(),
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(on))
    );
    assert!(!format!("{cred:?}").contains("token"));

    // IMDS errors.
    for (status, kind) in [
        (400, ErrorKind::Unauthenticated),
        (404, ErrorKind::Unavailable),
        (410, ErrorKind::Unavailable),
        (429, ErrorKind::Unavailable),
        (500, ErrorKind::Unavailable),
    ] {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": "invalid_request", "error_description": "Identity not found"
            })))
            .mount(&s)
            .await;
        let e = ManagedIdentity::system()
            .imds_endpoint(&format!("{}/metadata/identity/oauth2/token", s.uri()))
            .unwrap()
            .token(SCOPE)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{status}");
    }
    // Nothing listening: Unavailable, fast.
    let started = std::time::Instant::now();
    let e = ManagedIdentity::system()
        .imds_endpoint("http://127.0.0.1:9/metadata/identity/oauth2/token")
        .unwrap()
        .token(SCOPE)
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);
    assert!(started.elapsed() < Duration::from_secs(5));
    // Only IMDS or loopback.
    assert!(
        ManagedIdentity::system()
            .imds_endpoint("http://10.0.0.1/token")
            .is_err()
    );

    // App Service.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/msi/token"))
        .and(header("x-identity-header", "IDENTITY-HEADER-SECRET"))
        .and(query_param("api-version", "2019-08-01"))
        .and(query_param("resource", "https://managedhsm.azure.net"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "as-token", "expires_on": on, "resource": "https://managedhsm.azure.net"
        })))
        .mount(&server)
        .await;
    let cred = ManagedIdentity::system()
        .app_service(
            &format!("{}/msi/token", server.uri()),
            "IDENTITY-HEADER-SECRET",
        )
        .unwrap();
    assert!(!format!("{cred:?}").contains("IDENTITY-HEADER-SECRET"));
    let t = cred
        .token("https://managedhsm.azure.net/.default")
        .await
        .unwrap();
    assert_eq!(t.secret(), "as-token");
}

#[tokio::test]
async fn provider_uses_the_credential_and_caches_its_token() {
    let entra = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/t/oauth2/v2.0/token"))
        .respond_with(token_ok("vault-token"))
        .expect(1)
        .mount(&entra)
        .await;
    let vault = MockServer::start().await;
    let host = vault.address().to_string();
    Mock::given(method("GET"))
        .and(path("/keys/k"))
        .and(header("authorization", "Bearer vault-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": {"kid": format!("https://{host}/keys/k/0123456789abcdef0123456789abcdef"), "kty": "EC", "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
            "attributes": {"enabled": true}
        })))
        .expect(3)
        .mount(&vault)
        .await;
    let p = AzureProvider::builder()
        .credential(
            ClientSecret::new("t", "c", "s")
                .unwrap()
                .authority_host(&entra.uri())
                .unwrap(),
        )
        .test_host(TestHost::loopback_http(&host, SCOPE))
        .build()
        .unwrap();
    let k = p
        .digest_signing_key(
            format!("azure-kv://{host}/keys/k").as_str(),
            SignatureAlgorithm::EcdsaP256Sha256,
        )
        .unwrap();
    for _ in 0..3 {
        k.public_key().await.unwrap();
    }
}

#[tokio::test]
async fn static_tokens() {
    let t = StaticToken::new("abc");
    assert_eq!(t.token(SCOPE).await.unwrap().secret(), "abc");
    assert_eq!(t.token(SCOPE).await.unwrap().expires_at(), None);
    assert!(!format!("{t:?}").contains("abc"));
    let at = SystemTime::now() + Duration::from_secs(60);
    let t = StaticToken::with_expiry("x", at);
    assert_eq!(t.token(SCOPE).await.unwrap().expires_at(), Some(at));
}

// ---------------------------------------------------------------------------------------------
// from_env, in child processes (the environment cannot be changed safely in-process).

const CHILD: &str = "ANYKMS_AZURE_ENV_CHILD";

/// Runs in a child process: reports what the environment selects.
#[test]
fn env_child() {
    if std::env::var(CHILD).is_err() {
        return;
    }
    let kind = match anykms_azure::env_credential_kind() {
        Ok(Some(k)) => k.as_str().to_owned(),
        Ok(None) => "unset".to_owned(),
        Err(e) => format!("error:{}", e.kind().as_str()),
    };
    let provider = match AzureProvider::from_env() {
        Ok(p) => {
            let other = p.key_wrap_key("azure-kv://other.vault.azure.net/keys/k");
            let mut r = format!(
                "ok:other={}",
                if other.is_ok() { "allowed" } else { "refused" }
            );
            // Without a credential, the first operation fails (before any I/O).
            if kind == "unset" {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let e = rt
                    .block_on(other.unwrap().describe())
                    .expect_err("no credential");
                assert!(e.to_string().contains("AZURE_CLIENT_SECRET"), "{e}");
                write!(r, ",use=error:{}", e.kind().as_str()).unwrap();
            }
            r
        }
        Err(e) => format!("error:{}", e.kind().as_str()),
    };
    println!(
        "RESULT kind={kind} provider={provider} configured={}",
        matches!(anykms_azure::env_credential_kind(), Ok(Some(_)) | Err(_))
    );
    let _ = EnvCredentialKind::Workload;
}

fn run_child(vars: &[(&str, &str)]) -> String {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "env_child", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD, "1");
    for (k, v) in vars {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r))
        .unwrap_or_else(|| panic!("no result: {stdout}"))
        .to_owned()
}

#[test]
fn from_env_selects_deterministically() {
    let token_file = temp_file("env-token", "t").display().to_string();
    let wi = [
        ("AZURE_FEDERATED_TOKEN_FILE", token_file.as_str()),
        ("AZURE_TENANT_ID", "t"),
        ("AZURE_CLIENT_ID", "c"),
    ];
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        // No credential: the provider builds, and its first use is Configuration.
        (
            vec![],
            "kind=unset provider=ok:other=allowed,use=error:configuration configured=false",
        ),
        (
            wi.to_vec(),
            "kind=workload provider=ok:other=allowed configured=true",
        ),
        // Workload identity wins over a client secret.
        (
            [&wi[..], &[("AZURE_CLIENT_SECRET", "s")]].concat(),
            "kind=workload provider=ok:other=allowed configured=true",
        ),
        (
            vec![
                ("AZURE_CLIENT_SECRET", "s"),
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_CLIENT_ID", "c"),
                (
                    "ANYKMS_AZURE_ALLOWED_VAULTS",
                    "prod.vault.azure.net, abc.vault.azure.net",
                ),
            ],
            "kind=secret provider=ok:other=refused configured=true",
        ),
        // A selected credential with missing settings is an error, not a skip.
        (
            vec![("AZURE_CLIENT_SECRET", "s")],
            "kind=secret provider=error:configuration configured=true",
        ),
        (
            vec![
                ("IDENTITY_ENDPOINT", "http://127.0.0.1:41000/msi/token"),
                ("IDENTITY_HEADER", "h"),
            ],
            "kind=managed provider=ok:other=allowed configured=true",
        ),
        (
            vec![("ANYKMS_AZURE_MANAGED_IDENTITY", "1")],
            "kind=managed provider=ok:other=allowed configured=true",
        ),
        // Plain IMDS is never chosen without the opt-in.
        (
            vec![("AZURE_CLIENT_ID", "c")],
            "kind=unset provider=ok:other=allowed,use=error:configuration configured=false",
        ),
        (
            [&wi[..], &[("ANYKMS_AZURE_CREDENTIAL", "managed")]].concat(),
            "kind=managed provider=ok:other=allowed configured=true",
        ),
        (
            vec![("ANYKMS_AZURE_CREDENTIAL", "none")],
            "kind=none provider=error:configuration configured=true",
        ),
        (
            vec![("ANYKMS_AZURE_CREDENTIAL", "bogus")],
            "kind=error:configuration provider=error:configuration configured=true",
        ),
        (
            vec![
                ("AZURE_AUTHORITY_HOST", "http://login.example.com"),
                ("AZURE_CLIENT_SECRET", "s"),
                ("AZURE_TENANT_ID", "t"),
                ("AZURE_CLIENT_ID", "c"),
            ],
            "kind=secret provider=error:configuration configured=true",
        ),
    ];
    for (vars, want) in cases {
        assert_eq!(run_child(&vars), want, "{vars:?}");
    }
    // The Azure CLI is not built in: selecting it names the azure-identity feature.
    let cli = run_child(&[("ANYKMS_AZURE_CREDENTIAL", "cli")]);
    assert_eq!(
        cli,
        "kind=error:configuration provider=error:configuration configured=true"
    );
    let e = anykms_azure::env_credential_kind_with(|k| {
        (k == "ANYKMS_AZURE_CREDENTIAL").then(|| "cli".to_owned())
    })
    .unwrap_err();
    assert!(e.to_string().contains("azure-identity"), "{e}");
    let _ = Arc::new(());
}

/// `AzureIdentity`: an Azure SDK credential's token signs the vault request for the vault scope,
/// is cached until its reported expiry, and its errors keep their kind.
#[cfg(feature = "azure-identity")]
mod sdk {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anykms_azure::AzureIdentity;
    use azure_core::credentials::{AccessToken as SdkToken, TokenRequestOptions};
    use azure_core::error::{Error as SdkError, ErrorKind as SdkKind};
    use azure_core::time::{Duration as SdkDuration, OffsetDateTime};

    use super::*;

    /// What a [`Fake`] answers.
    type Make = fn() -> azure_core::Result<SdkToken>;

    /// Answers with `make()`, recording the scopes asked for.
    #[derive(Debug)]
    struct Fake {
        scopes: Mutex<Vec<String>>,
        calls: AtomicUsize,
        make: Make,
    }

    #[async_trait::async_trait]
    impl azure_core::credentials::TokenCredential for Fake {
        async fn get_token(
            &self,
            scopes: &[&str],
            _: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<SdkToken> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.scopes
                .lock()
                .unwrap()
                .extend(scopes.iter().map(std::string::ToString::to_string));
            (self.make)()
        }
    }

    fn fake(make: Make) -> Arc<Fake> {
        Arc::new(Fake {
            scopes: Mutex::default(),
            calls: AtomicUsize::new(0),
            make,
        })
    }

    #[tokio::test]
    async fn sdk_tokens_sign_and_are_cached_until_expiry() {
        let sdk = fake(|| {
            Ok(SdkToken::new(
                "sdk-token",
                OffsetDateTime::now_utc() + SdkDuration::hours(1),
            ))
        });
        let vault = MockServer::start().await;
        let host = vault.address().to_string();
        Mock::given(method("GET"))
            .and(path("/keys/k"))
            .and(header("authorization", "Bearer sdk-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key": {"kid": format!("https://{host}/keys/k/0123456789abcdef0123456789abcdef"), "kty": "EC", "crv": "P-256",
                        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
                "attributes": {"enabled": true}
            })))
            .expect(3)
            .mount(&vault)
            .await;
        let p = AzureProvider::builder()
            .credential(AzureIdentity::new(sdk.clone()))
            .test_host(TestHost::loopback_http(&host, SCOPE))
            .build()
            .unwrap();
        let k = p
            .digest_signing_key(
                format!("azure-kv://{host}/keys/k").as_str(),
                SignatureAlgorithm::EcdsaP256Sha256,
            )
            .unwrap();
        for _ in 0..3 {
            k.public_key().await.unwrap();
        }
        assert_eq!(sdk.calls.load(Ordering::SeqCst), 1);
        assert_eq!(*sdk.scopes.lock().unwrap(), [SCOPE]);
        let t = AzureIdentity::new(sdk.clone()).token(SCOPE).await.unwrap();
        let left = t
            .expires_at()
            .unwrap()
            .duration_since(SystemTime::now())
            .unwrap();
        assert!(left > Duration::from_secs(3500), "{left:?}");
    }

    #[tokio::test]
    async fn sdk_errors_keep_their_kind() {
        let cases: [(Make, ErrorKind); 3] = [
            (
                || Err(SdkError::with_message(SdkKind::Connection, "unreachable")),
                ErrorKind::Unavailable,
            ),
            (
                || Err(SdkError::with_message(SdkKind::Io, "reset")),
                ErrorKind::Unavailable,
            ),
            (
                || Err(SdkError::with_message(SdkKind::Credential, "AADSTS7000215")),
                ErrorKind::Unauthenticated,
            ),
        ];
        for (make, kind) in cases {
            let e = AzureIdentity::new(fake(make))
                .token(SCOPE)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), kind, "{e}");
            assert!(std::error::Error::source(&e).is_some(), "{e}");
        }
    }
}
