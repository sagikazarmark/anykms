//! Credential flows against mocked token endpoints (wiremock): the exact requests each source
//! sends, caching and single-flight, failure kinds, refused planted URLs, unsupported types and
//! the ADC chain. Tests that need environment variables run in a child process (the workspace
//! forbids `unsafe`, so `std::env::set_var` is unavailable).

use std::sync::Arc;
use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck};
use anykms_gcp::{AuthEndpoints, Credentials, Endpoint, GcpProvider};
use base64::Engine as _;
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const KEY: &str = "projects/my-project/locations/global/keyRings/r/cryptoKeys/k";

fn crc(data: &[u8]) -> String {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
    }
    (!c).to_string()
}

/// A KMS encrypt answer for any token in `tokens`.
async fn kms(server: &MockServer, token: &str) {
    let b64 = base64::engine::general_purpose::STANDARD;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}:encrypt")))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": format!("{KEY}/cryptoKeyVersions/1"),
            "ciphertext": b64.encode(b"ct"),
            "ciphertextCrc32c": crc(b"ct"),
            "verifiedPlaintextCrc32c": true,
        })))
        .mount(server)
        .await;
}

fn provider(server: &MockServer, creds: Credentials) -> GcpProvider {
    GcpProvider::builder()
        .credentials(creds)
        .endpoint(Endpoint::custom(server.uri()))
        .auth_endpoints(AuthEndpoints::custom(&server.uri()).unwrap())
        .allow_loopback_http()
        .build()
        .unwrap()
}

async fn encrypt(p: &GcpProvider) -> anykms_core::Result<()> {
    p.aead_key(format!("gcp-kms://{KEY}"))
        .unwrap()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"x", b"")
        .await
        .map(drop)
}

fn token_response(t: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": t, "expires_in": 3599, "token_type": "Bearer"
    }))
}

const METADATA_TOKEN: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

#[tokio::test]
async fn metadata_server_tokens_are_cached_and_single_flight() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(METADATA_TOKEN))
        .and(header("Metadata-Flavor", "Google"))
        .respond_with(
            token_response("ya29.md")
                .insert_header("Metadata-Flavor", "Google")
                .set_delay(Duration::from_millis(100)),
        )
        .expect(1)
        .mount(&server)
        .await;
    kms(&server, "ya29.md").await;
    let p = Arc::new(provider(&server, Credentials::metadata_server()));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let p = p.clone();
        tasks.push(tokio::spawn(async move { encrypt(&p).await }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    encrypt(&p).await.unwrap();
}

#[tokio::test]
async fn metadata_server_failures() {
    // 5xx: Unavailable, shared for 5 s (R-30): the next operation gets the same error without a
    // fetch.
    let server = MockServer::start().await;
    Mock::given(path(METADATA_TOKEN))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let p = provider(&server, Credentials::metadata_server());
    for _ in 0..2 {
        let e = encrypt(&p).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
        assert!(e.resource().is_some());
    }
    // A response without Metadata-Flavor: Google is not the metadata server.
    let server = MockServer::start().await;
    Mock::given(path(METADATA_TOKEN))
        .respond_with(token_response("ya29.x"))
        .mount(&server)
        .await;
    let e = encrypt(&provider(&server, Credentials::metadata_server()))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable);
    // No service account attached.
    let server = MockServer::start().await;
    Mock::given(path(METADATA_TOKEN))
        .respond_with(ResponseTemplate::new(404).insert_header("Metadata-Flavor", "Google"))
        .mount(&server)
        .await;
    let e = encrypt(&provider(&server, Credentials::metadata_server()))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    // Nothing listening.
    let p = GcpProvider::builder()
        .credentials(Credentials::metadata_server())
        .endpoint(Endpoint::custom("http://127.0.0.1:9"))
        .auth_endpoints(AuthEndpoints::custom("http://127.0.0.1:9").unwrap())
        .allow_loopback_http()
        .build()
        .unwrap();
    assert_eq!(
        encrypt(&p).await.unwrap_err().kind(),
        ErrorKind::Unavailable
    );
}

#[tokio::test]
async fn authorized_user_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("client_id=cid.apps"))
        .and(body_string_contains("client_secret=s%2Bcret"))
        .and(body_string_contains("refresh_token=1%2F%2Frt"))
        .respond_with(token_response("ya29.user"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}:encrypt")))
        .and(header("x-goog-user-project", "quota-proj"))
        .and(header("authorization", "Bearer ya29.user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": format!("{KEY}/cryptoKeyVersions/1"),
            "ciphertext": "Y3Q=", "ciphertextCrc32c": crc(b"ct"), "verifiedPlaintextCrc32c": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let f = json!({"type": "authorized_user", "client_id": "cid.apps", "client_secret": "s+cret",
        "refresh_token": "1//rt", "quota_project_id": "quota-proj"});
    encrypt(&provider(&server, Credentials::from_json(f.to_string())))
        .await
        .unwrap();

    // invalid_grant: Unauthenticated, with only the error code kept.
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked SECRETECHO"}),
        ))
        .mount(&server)
        .await;
    let e = encrypt(&provider(&server, Credentials::from_json(f.to_string())))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unauthenticated, "{e}");
    assert_eq!(e.detail().unwrap().code(), Some("invalid_grant"));
    assert!(!format!("{e} {e:?}").contains("SECRETECHO"));
}

#[tokio::test]
async fn external_account_sts_and_impersonation_requests() {
    let server = MockServer::start().await;
    let dir = std::env::temp_dir().join(format!("anykms-gcp-auth-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let subject = dir.join("oidc-token");
    std::fs::write(&subject, "eyJ.subject.token\n").unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_string_contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
        ))
        .and(body_string_contains(
            "audience=%2F%2Fiam.googleapis.com%2Fpool",
        ))
        .and(body_string_contains(
            "scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform",
        ))
        .and(body_string_contains(
            "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
        ))
        .and(body_string_contains("subject_token=eyJ.subject.token&"))
        .and(body_string_contains(
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "ya29.federated", "expires_in": 3600,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/ci@p.iam.gserviceaccount.com:generateAccessToken",
        ))
        .and(header("authorization", "Bearer ya29.federated"))
        .and(wiremock::matchers::body_json(json!({
            "scope": ["https://www.googleapis.com/auth/cloud-platform"],
            "lifetime": "1200s",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "ya29.sa", "expireTime": "2099-01-01T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;
    kms(&server, "ya29.sa").await;
    let f = json!({
        "type": "external_account",
        "audience": "//iam.googleapis.com/pool",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": format!("{}/v1/token", server.uri()),
        "service_account_impersonation_url": format!(
            "{}/v1/projects/-/serviceAccounts/ci@p.iam.gserviceaccount.com:generateAccessToken",
            server.uri()
        ),
        "service_account_impersonation": {"token_lifetime_seconds": 1200},
        "credential_source": {"file": subject},
    });
    let wif = dir.join("wif.json");
    std::fs::write(&wif, f.to_string()).unwrap();
    let p = provider(&server, Credentials::external_account_file(&wif));
    encrypt(&p).await.unwrap();
    encrypt(&p).await.unwrap();

    // Workforce pools pass the user project to STS (without impersonation).
    let server = MockServer::start().await;
    Mock::given(path("/v1/token"))
        .and(body_string_contains(
            "options=%7B%22userProject%22%3A%22wf-proj%22%7D",
        ))
        .respond_with(token_response("ya29.wf"))
        .expect(1)
        .mount(&server)
        .await;
    kms(&server, "ya29.wf").await;
    let f = json!({
        "type": "external_account", "audience": "//iam.googleapis.com/locations/global/workforcePools/p/providers/x",
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "token_url": format!("{}/v1/token", server.uri()),
        "workforce_pool_user_project": "wf-proj",
        "credential_source": {"file": subject},
    });
    encrypt(&provider(&server, Credentials::from_json(f.to_string())))
        .await
        .unwrap();
}

#[tokio::test]
async fn planted_urls_never_receive_credentials() {
    let attacker = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(token_response("ya29.evil"))
        .expect(0)
        .mount(&attacker)
        .await;
    let server = MockServer::start().await;
    let subject = std::env::temp_dir().join(format!("anykms-gcp-planted-{}", std::process::id()));
    std::fs::write(&subject, "eyJ.subject").unwrap();
    for f in [
        json!({"type": "external_account", "audience": "a",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": format!("{}/v1/token", attacker.uri()),
            "credential_source": {"file": subject}}),
        json!({"type": "external_account", "audience": "a",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": format!("{}/v1/token", server.uri()),
            "service_account_impersonation_url": format!("{}/x:generateAccessToken", attacker.uri()),
            "credential_source": {"file": subject}}),
        json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
            "refresh_token": "r", "token_uri": format!("{}/token", attacker.uri())}),
        json!({"type": "impersonated_service_account",
            "service_account_impersonation_url": "https://evil.example/v1/x:generateAccessToken",
            "source_credentials": {"type": "authorized_user", "client_id": "c",
                "client_secret": "s", "refresh_token": "r"}}),
        json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
            "refresh_token": "r", "token_uri": "http://oauth2.googleapis.com/token"}),
        // The exfiltration example: the VM's own token as the "subject token", posted to a
        // storage upload URL (a path and query other than the fixed STS endpoint).
        json!({"type": "external_account", "audience": "a",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://firebasestorage.googleapis.com/v0/b/attacker-bucket/o?name=leak",
            "credential_source": {
                "url": format!("{}/computeMetadata/v1/instance/service-accounts/default/token", server.uri()),
                "headers": {"Metadata-Flavor": "Google"},
                "format": {"type": "json", "subject_token_field_name": "access_token"}}}),
        json!({"type": "external_account", "audience": "a",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": format!("{}/upload/storage/v1/b/bucket/o?uploadType=media&name=leak", server.uri()),
            "credential_source": {"file": subject}}),
        json!({"type": "external_account", "audience": "a",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": format!("{}/v1/token?name=leak", server.uri()),
            "credential_source": {"file": subject}}),
        json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
            "refresh_token": "r", "token_uri": format!("{}/v1/token", server.uri())}),
    ] {
        let e = encrypt(&provider(&server, Credentials::from_json(f.to_string())))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{f}: {e}");
    }
}

#[tokio::test]
async fn unsupported_credential_types_are_named() {
    let server = MockServer::start().await;
    let cases = [
        (
            json!({"type": "external_account", "audience": "a", "subject_token_type": "t",
                "credential_source": {"environment_id": "aws1", "region_url": "x"}}),
            "AWS",
        ),
        (
            json!({"type": "external_account", "audience": "a", "subject_token_type": "t",
                "credential_source": {"executable": {"command": "x"}}}),
            "executable",
        ),
        (
            json!({"type": "external_account_authorized_user"}),
            "external_account_authorized_user",
        ),
        (
            json!({"type": "gdch_service_account"}),
            "gdch_service_account",
        ),
        (
            json!({"type": "authorized_user", "universe_domain": "example.com"}),
            "universe",
        ),
        (json!({"type": "nope"}), "unknown"),
        (json!({}), "type"),
    ];
    for (f, needle) in cases {
        let e = encrypt(&provider(&server, Credentials::from_json(f.to_string())))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{f}");
        assert!(e.to_string().contains(needle), "{f}: {e}");
        // Types google-cloud-auth supports name the feature that brings it.
        if [
            "AWS",
            "executable",
            "external_account_authorized_user",
            "gdch_service_account",
        ]
        .contains(&needle)
        {
            assert!(e.to_string().contains("`google-cloud-auth`"), "{f}: {e}");
        }
    }
    // A type mismatch for a typed constructor, and file errors naming the path only.
    let dir = std::env::temp_dir().join(format!("anykms-gcp-types-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let au = dir.join("au.json");
    std::fs::write(
        &au,
        json!({"type": "authorized_user", "client_id": "c", "client_secret": "SECRETVALUE", "refresh_token": "r"})
            .to_string(),
    )
    .unwrap();
    let e = encrypt(&provider(&server, Credentials::service_account_file(&au)))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert!(e.to_string().contains("au.json"), "{e}");
    assert!(!format!("{e:?}").contains("SECRETVALUE"));
    let big = dir.join("big.json");
    std::fs::write(&big, vec![b' '; 70 * 1024]).unwrap();
    let e = encrypt(&provider(&server, Credentials::from_file(&big)))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("64 KiB"), "{e}");
    let e = encrypt(&provider(
        &server,
        Credentials::from_file(dir.join("missing.json")),
    ))
    .await
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert!(e.to_string().contains("missing.json"), "{e}");
}

/// A self-signed JWT: RS256, `kid`, the cloud-platform scope, one hour, a valid signature; used
/// as the bearer token directly (no token endpoint).
#[tokio::test]
async fn service_account_self_signed_jwt() {
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::signature::KeyPair as _;
    let kp = aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'_> = kp.as_der().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = b64.encode(der.as_ref());
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
    let public = kp.public_key().as_ref().to_vec();
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let seen = Arc::new(std::sync::Mutex::new(None::<String>));
    let s2 = seen.clone();
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}:encrypt")))
        .respond_with(move |r: &Request| {
            let t = r.headers["authorization"].to_str().unwrap().to_owned();
            *s2.lock().unwrap() = Some(t);
            ResponseTemplate::new(200).set_body_json(json!({
                "name": format!("{KEY}/cryptoKeyVersions/1"), "ciphertext": "Y3Q=",
                "ciphertextCrc32c": crc(b"ct"), "verifiedPlaintextCrc32c": true,
            }))
        })
        .mount(&server)
        .await;
    let f = json!({"type": "service_account", "private_key_id": "kid-1", "private_key": pem,
        "client_email": "app@p.iam.gserviceaccount.com", "project_id": "p"});
    encrypt(&provider(&server, Credentials::from_json(f.to_string())))
        .await
        .unwrap();
    let auth = seen.lock().unwrap().clone().unwrap();
    let jwt = auth.strip_prefix("Bearer ").unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h: serde_json::Value = serde_json::from_slice(&url.decode(parts[0]).unwrap()).unwrap();
    let c: serde_json::Value = serde_json::from_slice(&url.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(h["alg"], "RS256");
    assert_eq!(h["kid"], "kid-1");
    assert_eq!(c["iss"], "app@p.iam.gserviceaccount.com");
    assert_eq!(c["sub"], c["iss"]);
    assert_eq!(c["scope"], "https://www.googleapis.com/auth/cloud-platform");
    assert_eq!(
        c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(),
        3600
    );
    let sig = url.decode(parts[2]).unwrap();
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
        &public,
    )
    .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
    .expect("valid RS256 signature");
    // A bad key is a Configuration error that does not echo it.
    let f = json!({"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nSECRETPEM\n-----END PRIVATE KEY-----\n",
        "client_email": "a@b"});
    let e = encrypt(&provider(&server, Credentials::from_json(f.to_string())))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
    assert!(!format!("{e:?}").contains("SECRETPEM"));
}

#[tokio::test]
async fn impersonated_service_account_file() {
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(token_response("ya29.source"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/target@p.iam.gserviceaccount.com:generateAccessToken",
        ))
        .and(header("authorization", "Bearer ya29.source"))
        .and(wiremock::matchers::body_json(json!({
            "scope": ["https://www.googleapis.com/auth/cloud-platform"],
            "lifetime": "3600s",
            "delegates": ["projects/-/serviceAccounts/d@p.iam.gserviceaccount.com"],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "ya29.target", "expireTime": "2099-01-01T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;
    kms(&server, "ya29.target").await;
    let f = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": format!(
            "{}/v1/projects/-/serviceAccounts/target@p.iam.gserviceaccount.com:generateAccessToken",
            server.uri()),
        "source_credentials": {"type": "authorized_user", "client_id": "c",
            "client_secret": "s", "refresh_token": "r"},
        "delegates": ["d@p.iam.gserviceaccount.com"],
    });
    encrypt(&provider(&server, Credentials::from_json(f.to_string())))
        .await
        .unwrap();
    // A 403 from IAM credentials (no token creator role).
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(token_response("ya29.source"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": {"code": 403,
            "status": "PERMISSION_DENIED", "message": "iam.serviceAccounts.getAccessToken denied"}})))
        .mount(&server)
        .await;
    let e = encrypt(&provider(
        &server,
        Credentials::impersonated(
            Credentials::from_json(
                json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
                    "refresh_token": "r"})
                .to_string(),
            ),
            "target@p.iam.gserviceaccount.com",
        ),
    ))
    .await
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert_eq!(e.detail().unwrap().code(), Some("PERMISSION_DENIED"));
    // Not an email.
    let e = GcpProvider::builder()
        .credentials(Credentials::impersonated(Credentials::none(), "../evil"))
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration);
}

/// Runs `test` in a child process with `env` set (and every ADC variable cleared otherwise).
fn in_child(test: &str, env: &[(&str, String)]) {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = std::process::Command::new(exe);
    cmd.args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env("ANYKMS_GCP_CHILD", "1");
    for v in [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_CONFIG",
        "GCE_METADATA_HOST",
        "ANYKMS_GCP_ENDPOINT",
        "ANYKMS_GCP_QUOTA_PROJECT",
        "GOOGLE_CLOUD_QUOTA_PROJECT",
        "ANYKMS_GCP_ALLOWED_PROJECTS",
        "ANYKMS_GCP_ALLOWED_LOCATIONS",
    ] {
        cmd.env_remove(v);
    }
    cmd.env("HOME", std::env::temp_dir().join("anykms-gcp-no-home"));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("1 passed"),
        "child {test} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn child() -> bool {
    std::env::var("ANYKMS_GCP_CHILD").is_ok()
}

#[tokio::test]
async fn adc_chain() {
    if child() {
        return;
    }
    // The parent's server (wiremock serves from its own threads while the child runs) answers
    // the token endpoints, the metadata server and Cloud KMS.
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(token_response("ya29.file"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(header("Metadata-Flavor", "Google"))
        .respond_with(ResponseTemplate::new(200).insert_header("Metadata-Flavor", "Google"))
        .mount(&server)
        .await;
    Mock::given(path(METADATA_TOKEN))
        .and(header("Metadata-Flavor", "Google"))
        .respond_with(token_response("ya29.md").insert_header("Metadata-Flavor", "Google"))
        .mount(&server)
        .await;
    kms(&server, "ya29.file").await;
    kms(&server, "ya29.md").await;
    let dir = std::env::temp_dir().join(format!("anykms-gcp-adc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let au = json!({"type": "authorized_user", "client_id": "c", "client_secret": "s",
        "refresh_token": "r"});
    let f = dir.join("creds.json");
    std::fs::write(&f, au.to_string()).unwrap();
    std::fs::write(
        dir.join("application_default_credentials.json"),
        au.to_string(),
    )
    .unwrap();
    let host = server.uri().trim_start_matches("http://").to_owned();
    let srv = ("ADC_TEST_SERVER", server.uri());
    // 1. GOOGLE_APPLICATION_CREDENTIALS (wins over the gcloud file).
    in_child(
        "adc_child",
        &[
            srv.clone(),
            ("GOOGLE_APPLICATION_CREDENTIALS", f.display().to_string()),
            ("CLOUDSDK_CONFIG", "/nonexistent".into()),
            ("ADC_TEST_EXPECT", "file".into()),
        ],
    );
    // 2. The gcloud file under CLOUDSDK_CONFIG.
    in_child(
        "adc_child",
        &[
            srv.clone(),
            ("CLOUDSDK_CONFIG", dir.display().to_string()),
            ("ADC_TEST_EXPECT", "file".into()),
        ],
    );
    // 3. The metadata server, at GCE_METADATA_HOST.
    in_child(
        "adc_child",
        &[
            srv.clone(),
            ("GCE_METADATA_HOST", host),
            ("ADC_TEST_EXPECT", "metadata".into()),
        ],
    );
    // Nothing found: Configuration.
    in_child(
        "adc_child",
        &[
            srv.clone(),
            ("GCE_METADATA_HOST", "127.0.0.1:9".into()),
            ("ADC_TEST_EXPECT", "none".into()),
        ],
    );
    // A broken GOOGLE_APPLICATION_CREDENTIALS fails (no fallback to the next step).
    in_child(
        "adc_child",
        &[
            srv,
            (
                "GOOGLE_APPLICATION_CREDENTIALS",
                dir.join("nope.json").display().to_string(),
            ),
            ("CLOUDSDK_CONFIG", dir.display().to_string()),
            ("ADC_TEST_EXPECT", "none".into()),
        ],
    );
}

/// `from_env_with`: ADC's lazily read variables come from the lookup, never from the process
/// environment (which may hold a developer's `GOOGLE_APPLICATION_CREDENTIALS`). In-process: no
/// child is needed.
#[tokio::test]
async fn adc_reads_variables_through_the_lookup() {
    if child() {
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(header("Metadata-Flavor", "Google"))
        .respond_with(ResponseTemplate::new(200).insert_header("Metadata-Flavor", "Google"))
        .mount(&server)
        .await;
    Mock::given(path(METADATA_TOKEN))
        .and(header("Metadata-Flavor", "Google"))
        .respond_with(token_response("ya29.lookup").insert_header("Metadata-Flavor", "Google"))
        .mount(&server)
        .await;
    kms(&server, "ya29.lookup").await;
    let uri = server.uri();
    let build = |metadata_host: String| {
        let uri = uri.clone();
        anykms_gcp::GcpProviderBuilder::from_env_with(move |v| match v {
            "GCE_METADATA_HOST" => Some(metadata_host.clone()),
            "HOME" | "APPDATA" => Some("/nonexistent/anykms-gcp-lookup".to_owned()),
            _ => None,
        })
        .unwrap()
        .endpoint(Endpoint::custom(uri.as_str()))
        .allow_loopback_http()
        .build()
        .unwrap()
    };
    // The metadata server named by the lookup answers.
    let host = server.uri().trim_start_matches("http://").to_owned();
    encrypt(&build(host)).await.unwrap();
    // Nothing reachable through the lookup: Configuration, with no fallback to the process.
    let e = encrypt(&build("127.0.0.1:9".to_owned())).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
}

#[tokio::test]
async fn adc_child() {
    if !child() {
        return;
    }
    let uri = std::env::var("ADC_TEST_SERVER").unwrap();
    let expect = std::env::var("ADC_TEST_EXPECT").unwrap();
    let mut b = GcpProvider::builder()
        .endpoint(Endpoint::custom(uri.as_str()))
        .allow_loopback_http();
    if expect == "file" {
        // Token endpoints on the test server; the metadata server is not involved.
        b = b.auth_endpoints(AuthEndpoints::custom(&uri).unwrap());
    }
    let p = b.build().unwrap();
    match expect.as_str() {
        "none" => {
            let e = encrypt(&p).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        }
        _ => encrypt(&p).await.unwrap(),
    }
}

#[test]
fn from_env() {
    if child() {
        return;
    }
    in_child(
        "from_env_child",
        &[
            ("ANYKMS_GCP_ENDPOINT", "regional".into()),
            ("ANYKMS_GCP_ALLOWED_PROJECTS", "a-project, b-project".into()),
            ("ANYKMS_GCP_ALLOWED_LOCATIONS", "europe-west1".into()),
            ("GOOGLE_CLOUD_QUOTA_PROJECT", "q-project".into()),
        ],
    );
    in_child(
        "from_env_bad_child",
        &[("ANYKMS_GCP_ALLOWED_PROJECTS", "Bad_Project".into())],
    );
}

#[test]
fn from_env_child() {
    if !child() {
        return;
    }
    let p = GcpProvider::from_env().unwrap();
    assert!(
        p.aead_key("gcp-kms://projects/a-project/locations/europe-west1/keyRings/r/cryptoKeys/k")
            .is_ok()
    );
    for bad in [
        "gcp-kms://projects/c-project/locations/europe-west1/keyRings/r/cryptoKeys/k",
        "gcp-kms://projects/a-project/locations/us-east1/keyRings/r/cryptoKeys/k",
    ] {
        assert_eq!(
            p.aead_key(bad).unwrap_err().kind(),
            ErrorKind::Configuration,
            "{bad}"
        );
    }
}

#[test]
fn from_env_bad_child() {
    if !child() {
        return;
    }
    assert_eq!(
        GcpProvider::from_env().unwrap_err().kind(),
        ErrorKind::Configuration
    );
}

/// `Credentials::google_cloud_auth`: the library's token signs each request (it caches tokens
/// itself, so it is asked every time), and its errors keep their kind with no KMS request.
#[cfg(feature = "google-cloud-auth")]
mod gca {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use google_cloud_auth::credentials::{
        AccessToken, AccessTokenCredentials, AccessTokenCredentialsProvider, CacheableResource,
        CredentialsProvider,
    };
    use google_cloud_auth::errors::CredentialsError;
    use http::{Extensions, HeaderMap};

    use super::*;

    /// What a [`Fake`] answers.
    type Make = fn() -> Result<String, CredentialsError>;

    /// Answers with `make()`, counting calls.
    #[derive(Debug)]
    struct Fake {
        calls: Arc<AtomicUsize>,
        make: Make,
    }

    impl CredentialsProvider for Fake {
        async fn headers(
            &self,
            _: Extensions,
        ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
            Err(CredentialsError::from_msg(false, "unused"))
        }

        async fn universe_domain(&self) -> Option<String> {
            None
        }
    }

    impl AccessTokenCredentialsProvider for Fake {
        async fn access_token(&self) -> Result<AccessToken, CredentialsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.make)().map(|token| AccessToken { token })
        }
    }

    fn fake(make: Make) -> (Credentials, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = AccessTokenCredentials::from(Fake {
            calls: calls.clone(),
            make,
        });
        (Credentials::google_cloud_auth(c), calls)
    }

    #[tokio::test]
    async fn library_tokens_sign_every_request() {
        let server = MockServer::start().await;
        kms(&server, "ya29.from-library").await;
        let (creds, calls) = fake(|| Ok("ya29.from-library".into()));
        let p = provider(&server, creds);
        encrypt(&p).await.unwrap();
        encrypt(&p).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn library_errors_keep_their_kind() {
        let cases: [(Make, ErrorKind); 2] = [
            (
                || Err(CredentialsError::from_msg(true, "metadata server down")),
                ErrorKind::Unavailable,
            ),
            (
                || Err(CredentialsError::from_msg(false, "invalid_grant")),
                ErrorKind::Unauthenticated,
            ),
        ];
        for (make, kind) in cases {
            let server = MockServer::start().await;
            let (creds, _) = fake(make);
            let e = encrypt(&provider(&server, creds)).await.unwrap_err();
            assert_eq!(e.kind(), kind, "{e}");
            assert!(std::error::Error::source(&e).is_some(), "{e}");
            assert!(server.received_requests().await.unwrap().is_empty());
        }
    }
}
