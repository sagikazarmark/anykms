//! Built-in login (`Login`) against a mock server: login, reuse, renewal, re-login, refusal and
//! the 403 retry.

use std::path::PathBuf;
use std::time::Duration;

use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyUri};
use anykms_transit::{Flavor, Login, ServerConfig, TransitProvider};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.LOGINTESTJWT.c2ln";

fn uri() -> KeyUri {
    "hashivault:///transit/keys/k".parse().unwrap()
}

/// A JWT file in a fresh directory, unique per test.
fn jwt_file(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anykms-login-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("token");
    std::fs::write(&p, format!("{JWT}\n")).unwrap();
    p
}

fn provider(server: &MockServer, login: Login) -> TransitProvider {
    TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(server.uri(), Flavor::Vault)
                .allow_loopback_http()
                .login(login),
        )
        .build()
        .unwrap()
}

fn auth(token: &str, lease: u64, renewable: bool) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "auth": {"client_token": token, "lease_duration": lease, "renewable": renewable},
        "warnings": ["TTL of \"768h\" exceeded the effective max_ttl"]
    }))
}

/// `GET keys/k` and `POST encrypt/k`, accepted only with `token`.
async fn transit_accepting(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data": {"type": "aes256-gcm96", "latest_version": 1, "keys": {"1": 1}}}),
        ))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/encrypt/k"))
        .and(header("X-Vault-Token", token))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"ciphertext": "vault:v1:AAAA"}})),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn logs_in_once_and_reuses_the_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .and(header("X-Vault-Namespace", "team-a"))
        .and(body_json(json!({"role": "app", "jwt": JWT})))
        .respond_with(auth("s.login-1", 3600, true))
        .expect(1)
        .mount(&server)
        .await;
    transit_accepting(&server, "s.login-1").await;
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new(server.uri(), Flavor::Vault)
                .allow_loopback_http()
                .namespace("team-a")
                .login(Login::kubernetes("app").jwt_file(jwt_file("reuse"))),
        )
        .build()
        .unwrap();
    let k = p.aead_key(uri()).unwrap();
    // Concurrent first requests share one login.
    let calls: Vec<_> = (0..8).map(|_| k.encrypt(b"x", b"")).collect();
    for r in futures_join(calls).await {
        r.unwrap();
    }
    k.encrypt(b"x", b"").await.unwrap();
}

#[tokio::test]
async fn renews_a_renewable_token_before_it_expires() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(auth("s.login-1", 1, true))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .and(header("X-Vault-Token", "s.login-1"))
        .respond_with(auth("s.login-1", 1, true))
        .expect(1)
        .mount(&server)
        .await;
    transit_accepting(&server, "s.login-1").await;
    let k = provider(&server, Login::jwt("ci", jwt_file("renew")))
        .aead_key(uri())
        .unwrap();
    k.encrypt(b"x", b"").await.unwrap();
    // Two thirds of the 1 s lease have passed.
    tokio::time::sleep(Duration::from_millis(750)).await;
    k.encrypt(b"x", b"").await.unwrap();
}

#[tokio::test]
async fn logs_in_again_when_not_renewable_or_renewal_is_capped() {
    for (renewable, renewed_lease) in [(false, 0), (true, 0)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/jwt/login"))
            .respond_with(auth("s.login-1", 1, renewable))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/auth/jwt/login"))
            .respond_with(auth("s.login-2", 3600, true))
            .expect(1)
            .mount(&server)
            .await;
        // A renewal that comes back with almost no lease left (max TTL reached).
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(auth("s.login-1", renewed_lease, true))
            .expect(u64::from(renewable))
            .mount(&server)
            .await;
        transit_accepting(&server, "s.login-1").await;
        transit_accepting(&server, "s.login-2").await;
        let k = provider(&server, Login::jwt("ci", jwt_file("relogin")))
            .aead_key(uri())
            .unwrap();
        k.encrypt(b"x", b"").await.unwrap();
        tokio::time::sleep(Duration::from_millis(750)).await;
        k.encrypt(b"x", b"").await.unwrap();
    }
}

#[tokio::test]
async fn failed_login_keeps_an_unexpired_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(auth("s.login-1", 2, false))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    transit_accepting(&server, "s.login-1").await;
    let k = provider(&server, Login::jwt("ci", jwt_file("keep")))
        .aead_key(uri())
        .unwrap();
    k.encrypt(b"x", b"").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1400)).await;
    // Refresh is due and the login fails, but the token is valid for another ~0.6 s.
    k.encrypt(b"x", b"").await.unwrap();
}

#[tokio::test]
async fn a_rejected_token_triggers_one_fresh_login() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .respond_with(auth("s.revoked", 3600, true))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .respond_with(auth("s.fresh", 3600, true))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .and(header("X-Vault-Token", "s.revoked"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
        )
        .mount(&server)
        .await;
    transit_accepting(&server, "s.fresh").await;
    let k = provider(&server, Login::kubernetes("app").jwt_file(jwt_file("403")))
        .aead_key(uri())
        .unwrap();
    k.encrypt(b"x", b"").await.unwrap();
}

#[tokio::test]
async fn refused_login_is_permission_denied_without_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errors": [format!("invalid role name \"app\" for {JWT}")]})),
        )
        .mount(&server)
        .await;
    let k = provider(
        &server,
        Login::kubernetes("app").jwt_file(jwt_file("refused")),
    )
    .aead_key(uri())
    .unwrap();
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert!(
        e.to_string()
            .contains("login to auth/kubernetes was refused"),
        "{e}"
    );
    let text = format!("{e} {e:?}");
    assert!(!text.contains("LOGINTESTJWT"), "{text}");
}

#[tokio::test]
async fn missing_jwt_file_is_unavailable() {
    let server = MockServer::start().await;
    let k = provider(&server, Login::jwt("ci", "/nonexistent/anykms/jwt"))
        .aead_key(uri())
        .unwrap();
    let e = k.encrypt(b"x", b"").await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
    assert!(e.to_string().contains("/nonexistent/anykms/jwt"), "{e}");
}

#[test]
fn invalid_login_is_a_configuration_error() {
    for login in [
        Login::kubernetes(""),
        Login::kubernetes("app").mount("a/../b"),
    ] {
        let e = TransitProvider::builder()
            .server(
                "default",
                ServerConfig::new("https://vault.example:8200", Flavor::Vault).login(login),
            )
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
    }
}

/// Awaits all futures concurrently on the current task.
async fn futures_join<F: std::future::Future>(fs: Vec<F>) -> Vec<F::Output> {
    let handles: Vec<_> = fs.into_iter().map(Box::pin).collect();
    let mut out: Vec<Option<F::Output>> = (0..handles.len()).map(|_| None).collect();
    let mut handles: Vec<_> = handles.into_iter().map(Some).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, h) in handles.iter_mut().enumerate() {
            if let Some(f) = h {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => {
                        out[i] = Some(v);
                        *h = None;
                    }
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().map(Option::unwrap).collect()
}

#[tokio::test]
async fn policy_denials_do_not_mint_a_token_per_request() {
    let server = MockServer::start().await;
    // The first login, then at most one more: the first 403 may be a revoked token, the rest
    // within the interval are policy denials and reuse the token.
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .respond_with(auth("s.app", 3600, true))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
        )
        .mount(&server)
        .await;
    let k = provider(
        &server,
        Login::kubernetes("app").jwt_file(jwt_file("denials")),
    )
    .aead_key(uri())
    .unwrap();
    for _ in 0..5 {
        let e = k.encrypt(b"x", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    }
}

#[tokio::test]
async fn a_failed_refresh_backs_off_instead_of_retrying_per_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(auth("s.login-1", 2, false))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Refresh logins fail; within the backoff only one is attempted.
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    transit_accepting(&server, "s.login-1").await;
    let k = provider(&server, Login::jwt("ci", jwt_file("backoff")))
        .aead_key(uri())
        .unwrap();
    k.encrypt(b"x", b"").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1400)).await;
    for _ in 0..5 {
        k.encrypt(b"x", b"").await.unwrap();
    }
}

#[tokio::test]
async fn a_huge_lease_is_clamped() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(auth("s.forever", u64::MAX, true))
        .expect(1)
        .mount(&server)
        .await;
    transit_accepting(&server, "s.forever").await;
    let k = provider(&server, Login::jwt("ci", jwt_file("huge")))
        .aead_key(uri())
        .unwrap();
    k.encrypt(b"x", b"").await.unwrap();
    k.encrypt(b"x", b"").await.unwrap();
}

#[tokio::test]
async fn a_cancelled_forced_login_is_retried_by_the_next_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(auth("s.revoked", 3600, true))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(auth("s.fresh", 3600, true).set_delay(Duration::from_millis(300)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/keys/k"))
        .and(header("X-Vault-Token", "s.revoked"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"errors": ["permission denied", "invalid token"]})),
        )
        .mount(&server)
        .await;
    transit_accepting(&server, "s.fresh").await;
    let k = provider(&server, Login::jwt("ci", jwt_file("cancel")))
        .aead_key(uri())
        .unwrap();
    // The caller gives up during the 403-triggered login.
    let r = tokio::time::timeout(Duration::from_millis(150), k.encrypt(b"x", b"")).await;
    assert!(r.is_err(), "the login should still be in flight");
    // The next request must not be stuck with the revoked token for the 30 s limit.
    k.encrypt(b"x", b"").await.unwrap();
}

#[tokio::test]
async fn a_failed_login_without_a_token_is_shared_by_waiting_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/jwt/login"))
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(100)))
        .expect(1)
        .mount(&server)
        .await;
    let k = provider(&server, Login::jwt("ci", jwt_file("nolease")))
        .aead_key(uri())
        .unwrap();
    let results = futures_join((0..6).map(|_| k.encrypt(b"x", b"")).collect()).await;
    for r in results {
        assert_eq!(r.unwrap_err().kind(), ErrorKind::Unavailable);
    }
    // Within the backoff, a new request also gets the recorded failure without a login.
    assert_eq!(
        k.encrypt(b"x", b"").await.unwrap_err().kind(),
        ErrorKind::Unavailable
    );
}
