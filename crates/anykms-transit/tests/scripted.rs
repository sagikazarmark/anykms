//! The transit backend over an injected [`ScriptedTransport`]: no network, no reqwest. Proves
//! the transport seam carries the response limit, that bodies are zeroizing, that an oversized
//! body from a transport that ignores the limit is still rejected, that transport failures map
//! to the documented kinds, and that the built-in login goes through the same transport.

use std::path::PathBuf;

use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyTypeCheck, KeyUri};
use anykms_testkit::{Scripted, ScriptedTransport};
use anykms_transit::anykms_http::transport::ConnectFailure;
use anykms_transit::anykms_http::{HttpTransport, SendError};
use anykms_transit::{Flavor, Login, ServerConfig, TransitProvider};
use serde_json::json;

fn uri() -> KeyUri {
    "hashivault:///transit/keys/k".parse().unwrap()
}

const KEY_INFO: &str =
    r#"{"data": {"type": "aes256-gcm96", "latest_version": 1, "keys": {"1": 1}}}"#;

fn provider(
    t: &ScriptedTransport,
    cfg: impl FnOnce(ServerConfig) -> ServerConfig,
) -> TransitProvider {
    TransitProvider::builder()
        .server(
            "default",
            cfg(
                ServerConfig::new("https://vault.example:8200", Flavor::Vault)
                    .token("s.token")
                    .http_transport(t.clone()),
            ),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn requests_carry_the_configured_limit_and_bodies_are_zeroizing() {
    let t = ScriptedTransport::new();
    t.reply(200, KEY_INFO)
        .reply(200, r#"{"data": {"ciphertext": "vault:v1:AAAA"}}"#);
    let limit = 2 * 1024 * 1024;
    let p = provider(&t, |c| c.max_response_bytes(limit));
    let ct = p
        .aead_key(uri())
        .unwrap()
        .encrypt(b"secret plaintext", b"")
        .await
        .unwrap();
    assert_eq!(ct.as_bytes(), b"vault:v1:AAAA");

    let seen = t.seen();
    assert_eq!(seen.len(), 2);
    for r in &seen {
        assert_eq!(r.limit, limit, "{r:?}");
        assert!(
            r.uri.starts_with("https://vault.example:8200/v1/transit/"),
            "{r:?}"
        );
        assert_eq!(r.headers.get("X-Vault-Token").unwrap(), "s.token");
        assert!(r.headers.get("X-Vault-Token").unwrap().is_sensitive());
        assert_eq!(r.timeout, None);
    }
    assert_eq!(
        seen[1].method,
        anykms_transit::anykms_http::http::Method::POST
    );
    // The request body reaches the transport in a zeroizing buffer, with the plaintext encoded.
    let body: serde_json::Value = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(body["plaintext"], json!("c2VjcmV0IHBsYWludGV4dA=="));
    assert!(t.exhausted());
}

/// The response type the transport returns is a zeroizing buffer: this is what every transport
/// hands back, and what `ScriptedTransport` builds. Checked at the type level here.
#[test]
fn transport_responses_are_zeroizing() {
    fn body(_: &anykms_transit::anykms_http::transport::Response) -> &zeroize::Zeroizing<Vec<u8>> {
        unreachable!()
    }
    let _ = body;
    // And the trait object the backends hold is `Send + Sync`.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<std::sync::Arc<dyn HttpTransport>>();
}

#[tokio::test]
async fn an_oversized_body_from_a_misbehaving_transport_is_still_rejected() {
    let t = ScriptedTransport::new();
    let limit = 64 * 1024;
    t.reply(200, KEY_INFO)
        .push(Scripted::Oversized(200, vec![b'x'; limit + 1]));
    let p = provider(&t, |c| c.max_response_bytes(limit));
    let e = p
        .aead_key(uri())
        .unwrap()
        .encrypt(b"x", b"")
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("response exceeds the maximum size"),
        "{e}"
    );
    assert_eq!(e.detail().and_then(|d| d.http_status), Some(200));
}

#[tokio::test]
async fn transport_failures_map_to_the_documented_kinds() {
    let cases = [
        (
            SendError::Timeout("t".into()),
            ErrorKind::Timeout,
            "request timed out",
            true,
        ),
        (
            SendError::Dns("d".into()),
            ErrorKind::Unavailable,
            "DNS lookup failed",
            true,
        ),
        (
            SendError::connect(ConnectFailure::Refused, "r"),
            ErrorKind::Unavailable,
            "connection refused",
            true,
        ),
        (
            SendError::TlsRejected {
                reason: "TLS certificate rejected: unknown issuer",
                source: "x".into(),
            },
            ErrorKind::Configuration,
            "unknown issuer",
            false,
        ),
        (
            SendError::Tls("h".into()),
            ErrorKind::Unavailable,
            "TLS handshake failed",
            true,
        ),
        (
            SendError::Body("b".into()),
            ErrorKind::Unavailable,
            "response was interrupted",
            true,
        ),
        (
            SendError::NoRuntime,
            ErrorKind::Configuration,
            "Tokio runtime",
            false,
        ),
    ];
    for (err, kind, msg, retryable) in cases {
        let t = ScriptedTransport::new();
        t.reply(200, KEY_INFO).push(Scripted::Fail(err));
        let p = provider(&t, |c| c);
        let e = p
            .aead_key(uri())
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{e}");
        assert!(e.to_string().contains(msg), "{e}");
        assert_eq!(e.is_retryable(), retryable, "{e}");
        assert_eq!(e.operation(), anykms_core::Operation::Encrypt, "{e}");
        if !matches!(e.kind(), ErrorKind::Configuration) || msg != "Tokio runtime" {
            assert!(std::error::Error::source(&e).is_some(), "{e}");
        }
    }
}

#[tokio::test]
async fn login_goes_through_the_injected_transport() {
    let dir = std::env::temp_dir().join(format!("anykms-scripted-login-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt: PathBuf = dir.join("jwt");
    std::fs::write(&jwt, "eyJhbGciOiJFUzI1NiJ9.LOGINTESTJWT.c2ln\n").unwrap();

    let t = ScriptedTransport::new();
    t.reply(
        200,
        r#"{"auth": {"client_token": "s.login-1", "lease_duration": 3600, "renewable": true}}"#,
    )
    .reply(200, KEY_INFO)
    .reply(200, r#"{"data": {"ciphertext": "vault:v1:AAAA"}}"#);
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new("https://vault.example:8200", Flavor::Vault)
                .namespace("team-a")
                .login(Login::jwt("ci", &jwt))
                .http_transport(t.clone()),
        )
        .build()
        .unwrap();
    p.aead_key(uri()).unwrap().encrypt(b"x", b"").await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].uri, "https://vault.example:8200/v1/auth/jwt/login");
    assert_eq!(seen[0].headers.get("X-Vault-Namespace").unwrap(), "team-a");
    // The login endpoint has its own, fixed cap, not the server's `max_response_bytes`.
    assert_eq!(seen[0].limit, 64 * 1024);
    let login: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
    assert_eq!(login["role"], json!("ci"));
    assert_eq!(seen[1].headers.get("X-Vault-Token").unwrap(), "s.login-1");
    assert_eq!(seen[2].headers.get("X-Vault-Token").unwrap(), "s.login-1");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Without the `reqwest` feature and without an injected transport, building fails with
/// `Configuration` naming both remedies. With the feature a default transport is built.
#[test]
fn default_transport_needs_the_reqwest_feature() {
    let r = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new("http://127.0.0.1:1", Flavor::Vault)
                .token("t")
                .allow_loopback_http(),
        )
        .build();
    #[cfg(all(
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    {
        // A plain-HTTP loopback server needs no system roots: the default transport builds.
        r.unwrap();
    }
    #[cfg(all(
        feature = "reqwest",
        not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))
    ))]
    {
        // The built-in transport exists but has no TLS crypto provider to build with.
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(e.to_string().contains("no rustls crypto provider"), "{e}");
    }
    #[cfg(not(feature = "reqwest"))]
    {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(e.to_string().contains("`reqwest`"), "{e}");
        assert!(e.to_string().contains(".http_transport(..)"), "{e}");
    }
}

/// What `ReqwestTransport` reports by default: twice its 2 s connect plus 10 s request timeout.
const FOLLOWER_WAIT: std::time::Duration = std::time::Duration::from_secs(24);

/// A transport whose first login does not answer until `release` is notified, answering by path
/// otherwise: logins hand out `tokens` in order, `keys/k` reads the key, `encrypt/k` encrypts.
/// It records each request's path and token, and bounds followers like `ReqwestTransport`.
#[derive(Debug, Default)]
struct StallFirstLogin {
    tokens: std::sync::Mutex<std::collections::VecDeque<&'static str>>,
    seen: std::sync::Mutex<Vec<(String, String)>>,
    stalled: std::sync::atomic::AtomicBool,
    release: tokio::sync::Notify,
}

impl StallFirstLogin {
    fn new(tokens: &[&'static str]) -> std::sync::Arc<Self> {
        let t = Self::default();
        t.tokens.lock().unwrap().extend(tokens);
        std::sync::Arc::new(t)
    }

    /// `(path, token)` of every request so far (`-` for none).
    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

impl HttpTransport for StallFirstLogin {
    fn send(
        &self,
        req: anykms_transit::anykms_http::transport::Request,
        _limit: usize,
    ) -> anykms_core::BoxFuture<
        '_,
        Result<anykms_transit::anykms_http::transport::Response, SendError>,
    > {
        let path = req.uri().path().to_owned();
        let token = req
            .headers()
            .get("X-Vault-Token")
            .map_or("-".to_owned(), |v| v.to_str().unwrap().to_owned());
        self.seen.lock().unwrap().push((path.clone(), token));
        let login = path.ends_with("/login");
        let stall = login && !self.stalled.swap(true, std::sync::atomic::Ordering::SeqCst);
        // Decided at send time, so a stalled login keeps the token it was sent for.
        let body = if login {
            let t = self
                .tokens
                .lock()
                .unwrap()
                .pop_front()
                .expect("a login token");
            format!(r#"{{"auth": {{"client_token": "{t}", "lease_duration": 3600}}}}"#)
        } else if path.ends_with("/keys/k") {
            KEY_INFO.to_owned()
        } else {
            r#"{"data": {"ciphertext": "vault:v1:AAAA"}}"#.to_owned()
        };
        Box::pin(async move {
            if stall {
                self.release.notified().await;
            }
            let mut r = anykms_transit::anykms_http::http::Response::new(zeroize::Zeroizing::new(
                body.into_bytes(),
            ));
            r.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            Ok(r)
        })
    }

    fn follower_wait(&self) -> Option<(std::time::Duration, anykms_core::SleepFn)> {
        Some((
            FOLLOWER_WAIT,
            std::sync::Arc::new(|d| Box::pin(tokio::time::sleep(d))),
        ))
    }
}

fn login_provider(t: &std::sync::Arc<StallFirstLogin>, test: &str) -> (TransitProvider, PathBuf) {
    let dir = std::env::temp_dir().join(format!("anykms-scripted-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwt = dir.join("jwt");
    std::fs::write(&jwt, "eyJhbGciOiJFUzI1NiJ9.LOGINTESTJWT.c2ln\n").unwrap();
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new("https://vault.example:8200", Flavor::Vault)
                .login(Login::jwt("ci", &jwt))
                .http_transport(t.clone()),
        )
        .build()
        .unwrap();
    (p, dir)
}

/// Polls `f` once.
async fn poll_once<F: std::future::Future + Unpin>(f: &mut F) -> std::task::Poll<F::Output> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(std::pin::Pin::new(&mut *f).poll(cx))).await
}

/// A request whose login is in flight but that its caller stopped polling (a future kept in an
/// idle `select!` branch) holds the login lock. Later requests wait for it at most the
/// transport's follower bound, then log in themselves.
#[tokio::test(start_paused = true)]
async fn a_stalled_login_does_not_block_other_requests() {
    let t = StallFirstLogin::new(&["s.stalled", "s.fresh"]);
    let (p, dir) = login_provider(&t, "stalled-login");
    let key = p.aead_key(uri()).unwrap();
    let mut stalled = Box::pin(key.encrypt(b"x", b""));
    assert!(poll_once(&mut stalled).await.is_pending());
    assert_eq!(t.seen().len(), 1, "the first request is logging in");

    let started = tokio::time::Instant::now();
    let ct = tokio::time::timeout(std::time::Duration::from_secs(600), key.encrypt(b"y", b""))
        .await
        .expect("a request is blocked behind a login nobody polls")
        .unwrap();
    assert_eq!(ct.as_bytes(), b"vault:v1:AAAA");
    assert!(
        started.elapsed() >= FOLLOWER_WAIT,
        "{:?}",
        started.elapsed()
    );
    let seen = t.seen();
    assert_eq!(seen[1].0, "/v1/auth/jwt/login", "{seen:?}");
    assert!(seen[2..].iter().all(|(_, t)| t == "s.fresh"), "{seen:?}");
    drop(stalled);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The stalled login of the test above, resumed after a newer login stored its token: its own
/// request goes ahead with the token it got, but it does not replace the newer one.
#[tokio::test(start_paused = true)]
async fn a_stalled_login_that_resumes_keeps_the_newer_token() {
    let t = StallFirstLogin::new(&["s.stalled", "s.fresh"]);
    let (p, dir) = login_provider(&t, "stalled-resume");
    let key = p.aead_key(uri()).unwrap();
    let mut stalled = Box::pin(key.encrypt(b"x", b""));
    assert!(poll_once(&mut stalled).await.is_pending());
    tokio::time::timeout(std::time::Duration::from_secs(600), key.encrypt(b"y", b""))
        .await
        .expect("a request is blocked behind a login nobody polls")
        .unwrap();

    t.release.notify_one();
    stalled.await.unwrap();
    let before = t.seen().len();
    key.encrypt(b"z", b"").await.unwrap();
    let seen = t.seen();
    assert_eq!(seen.len(), before + 1, "no further login: {seen:?}");
    assert_eq!(
        seen.last().unwrap(),
        &("/v1/transit/encrypt/k".to_owned(), "s.fresh".to_owned()),
        "{seen:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A transport whose first `keys/k` read does not answer until `release` is notified, and
/// describes the key as it was then (`rsa-2048`); later reads describe it as recreated
/// (`aes256-gcm96`), but the second fails with a 400 if `fail_second_read`. `encrypt/k`
/// encrypts, but the first time answers that the key is missing if `fail_first_encrypt`. It
/// records each request's path, and bounds followers like `ReqwestTransport`.
#[derive(Debug, Default)]
struct StallFirstKeyRead {
    seen: std::sync::Mutex<Vec<String>>,
    reads: std::sync::atomic::AtomicUsize,
    fail_second_read: bool,
    fail_first_encrypt: bool,
    encrypts: std::sync::atomic::AtomicUsize,
    release: tokio::sync::Notify,
}

impl HttpTransport for StallFirstKeyRead {
    fn send(
        &self,
        req: anykms_transit::anykms_http::transport::Request,
        _limit: usize,
    ) -> anykms_core::BoxFuture<
        '_,
        Result<anykms_transit::anykms_http::transport::Response, SendError>,
    > {
        let path = req.uri().path().to_owned();
        self.seen.lock().unwrap().push(path.clone());
        let read = path
            .ends_with("/keys/k")
            .then(|| self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let (status, body) = match read {
            Some(0) => (
                200,
                r#"{"data": {"type": "rsa-2048", "latest_version": 1, "keys": {"1": 1}}}"#,
            ),
            Some(1) if self.fail_second_read => (400, r#"{"errors": ["try again"]}"#),
            Some(_) => (200, KEY_INFO),
            None if self.fail_first_encrypt
                && self
                    .encrypts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0 =>
            {
                (400, r#"{"errors": ["encryption key not found"]}"#)
            }
            None => (200, r#"{"data": {"ciphertext": "vault:v1:AAAA"}}"#),
        };
        Box::pin(async move {
            if read == Some(0) {
                self.release.notified().await;
            }
            let mut r = anykms_transit::anykms_http::http::Response::new(zeroize::Zeroizing::new(
                body.as_bytes().to_vec(),
            ));
            *r.status_mut() = status.try_into().unwrap();
            r.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            Ok(r)
        })
    }

    fn follower_wait(&self) -> Option<(std::time::Duration, anykms_core::SleepFn)> {
        Some((
            FOLLOWER_WAIT,
            std::sync::Arc::new(|d| Box::pin(tokio::time::sleep(d))),
        ))
    }
}

/// An AEAD handle over `t`, and an encryption whose key-type read is stalled (its caller
/// stopped polling it).
async fn stalled_type_read(
    t: &std::sync::Arc<StallFirstKeyRead>,
) -> (
    anykms_transit::TransitAeadKey,
    std::pin::Pin<
        Box<impl std::future::Future<Output = anykms_core::Result<anykms_core::Ciphertext>>>,
    >,
) {
    let p = TransitProvider::builder()
        .server(
            "default",
            ServerConfig::new("https://vault.example:8200", Flavor::Vault)
                .token("s.token")
                .http_transport(t.clone()),
        )
        .build()
        .unwrap();
    let key = p.aead_key(uri()).unwrap();
    let mut stalled = {
        let key = key.clone();
        Box::pin(async move { key.encrypt(b"x", b"").await })
    };
    assert!(poll_once(&mut stalled).await.is_pending());
    (key, stalled)
}

/// A key-type read that stalls is taken over by a request that waited out the follower bound,
/// which reads the key's newer type and caches it. When the stalled read resumes, its own
/// request is answered from what it read, but the older type it read does not replace the
/// newer one in the cache.
#[tokio::test(start_paused = true)]
async fn a_stalled_type_read_that_resumes_does_not_overwrite_the_newer_type() {
    let t = std::sync::Arc::new(StallFirstKeyRead::default());
    let (key, stalled) = stalled_type_read(&t).await;
    let ct = tokio::time::timeout(std::time::Duration::from_secs(600), key.encrypt(b"y", b""))
        .await
        .expect("a request is blocked behind a key read nobody polls")
        .unwrap();
    assert_eq!(ct.as_bytes(), b"vault:v1:AAAA");

    // The stalled read resumes: its request is checked against the type it read.
    t.release.notify_one();
    let e = stalled.await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");

    // The cache still holds the newer type: no metadata read, no refusal.
    let before = t.seen.lock().unwrap().len();
    key.encrypt(b"z", b"")
        .await
        .expect("the stalled read's older type replaced the cached one");
    let seen = t.seen.lock().unwrap().clone();
    assert_eq!(seen[before..], ["/v1/transit/encrypt/k"], "{seen:?}");
}

/// As above, but the replacement read fails, so nothing newer is cached: the superseded read
/// still stores nothing, and the next request reads the key again.
#[tokio::test(start_paused = true)]
async fn a_superseded_type_read_stores_nothing_when_its_replacement_failed() {
    let t = std::sync::Arc::new(StallFirstKeyRead {
        fail_second_read: true,
        ..Default::default()
    });
    let (key, stalled) = stalled_type_read(&t).await;
    tokio::time::timeout(std::time::Duration::from_secs(600), key.encrypt(b"y", b""))
        .await
        .expect("a request is blocked behind a key read nobody polls")
        .unwrap_err();

    t.release.notify_one();
    let e = stalled.await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");

    let before = t.seen.lock().unwrap().len();
    key.encrypt(b"z", b"")
        .await
        .expect("the superseded read's older type was cached");
    let seen = t.seen.lock().unwrap().clone();
    assert_eq!(
        seen[before..],
        ["/v1/transit/keys/k", "/v1/transit/encrypt/k"],
        "{seen:?}"
    );
}

/// A key-type read that started before the cached type was dropped (another request found the
/// key missing) does not store its type when it resumes: the next request reads the key again.
#[tokio::test(start_paused = true)]
async fn a_type_read_from_before_the_type_was_dropped_stores_nothing() {
    let t = std::sync::Arc::new(StallFirstKeyRead {
        fail_first_encrypt: true,
        ..Default::default()
    });
    let (key, stalled) = stalled_type_read(&t).await;
    let e = key
        .clone()
        .with_key_type_check(KeyTypeCheck::TrustCaller)
        .encrypt(b"y", b"")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");

    t.release.notify_one();
    let e = stalled.await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::KeyMismatch, "{e}");

    let before = t.seen.lock().unwrap().len();
    key.encrypt(b"z", b"")
        .await
        .expect("the read from before the type was dropped was cached");
    let seen = t.seen.lock().unwrap().clone();
    assert_eq!(
        seen[before..],
        ["/v1/transit/keys/k", "/v1/transit/encrypt/k"],
        "{seen:?}"
    );
}
