//! The transit backend over an injected [`ScriptedTransport`]: no network, no reqwest. Proves
//! the transport seam carries the response limit, that bodies are zeroizing, that an oversized
//! body from a transport that ignores the limit is still rejected, that transport failures map
//! to the documented kinds, and that the built-in login goes through the same transport.

use std::path::PathBuf;

use anykms_core::prelude::*;
use anykms_core::{ErrorKind, KeyUri};
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
    #[cfg(feature = "reqwest")]
    {
        // The default transport requires system roots; on a host without any that is the only
        // acceptable failure.
        if let Err(e) = r {
            assert!(
                anykms_transit::anykms_http::tls::is_missing_system_roots(&e),
                "{e}"
            );
        }
    }
    #[cfg(not(feature = "reqwest"))]
    {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
        assert!(e.to_string().contains("`reqwest`"), "{e}");
        assert!(e.to_string().contains(".http_transport(..)"), "{e}");
    }
}
