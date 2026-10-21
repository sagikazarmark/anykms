//! Transport failures against local TLS servers: certificate problems are `Configuration` (not
//! retryable) with a short reason, DNS and connection failures stay `Unavailable`.
//!
//! The certificates and keys in `tests/data` are throwaway test fixtures:
//! `ca.pem` signs `server.pem` (`DNS:anykms.test`) and `loopback.pem` (`IP:127.0.0.1`), both for
//! server and client auth; `other-ca.pem` is unrelated.

#![cfg(feature = "reqwest")]

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use anykms_core::prelude::*;
use anykms_core::{Error, ErrorKind, KeyUri};
use anykms_transit::anykms_http::{ReqwestTransport, ReqwestTransportBuilder, rustls};
use anykms_transit::{Flavor, ServerConfig, TransitProvider};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

const CA: &[u8] = include_bytes!("data/ca.pem");
const OTHER_CA: &[u8] = include_bytes!("data/other-ca.pem");
const SERVER_CERT: &[u8] = include_bytes!("data/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("data/server-key.pem");
const LOOPBACK_CERT: &[u8] = include_bytes!("data/loopback.pem");
const LOOPBACK_KEY: &[u8] = include_bytes!("data/loopback-key.pem");

/// The built-in transport, configured by `f` (TLS settings live on the transport, not on
/// `ServerConfig`).
fn transport(
    f: impl FnOnce(ReqwestTransportBuilder) -> ReqwestTransportBuilder,
) -> ReqwestTransport {
    f(ReqwestTransport::builder()).build().unwrap()
}

fn crypto() -> Arc<CryptoProvider> {
    #[cfg(feature = "rustls-aws-lc-rs")]
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(not(feature = "rustls-aws-lc-rs"))]
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS server that drives handshakes and then hangs up.
fn tls_server(cert: &[u8], key: &[u8], require_client_cert: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let builder = rustls::ServerConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = if require_client_cert {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(CA).unwrap())
            .unwrap();
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto())
                .build()
                .unwrap();
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let config = Arc::new(
        builder
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(cert).unwrap()],
                PrivateKeyDer::from_pem_slice(key).unwrap(),
            )
            .unwrap(),
    );
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(mut tcp) = tcp else { break };
            let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut tcp).is_err() {
                    break;
                }
            }
            // Flush a pending alert, if any.
            let _ = conn.complete_io(&mut tcp);
        }
    });
    addr
}

fn uri() -> KeyUri {
    "hashivault:///transit/keys/k".parse().unwrap()
}

async fn encrypt(cfg: ServerConfig) -> Error {
    let p = TransitProvider::builder()
        .server("default", cfg.token("s.test"))
        .build()
        .unwrap();
    p.aead_key(uri())
        .unwrap()
        .encrypt(b"pt", b"")
        .await
        .unwrap_err()
}

fn assert_err(e: &Error, kind: ErrorKind, msg: &str) {
    assert_eq!(e.kind(), kind, "{e}");
    assert!(e.to_string().contains(msg), "{e}");
    assert!(!e.to_string().contains("s.test"), "{e}");
}

#[tokio::test]
async fn unknown_issuer_is_configuration() {
    let addr = tls_server(SERVER_CERT, SERVER_KEY, false);
    let e = encrypt(
        ServerConfig::new(format!("https://{addr}"), Flavor::Vault)
            .http_transport(transport(|b| b.ca_pem(OTHER_CA))),
    )
    .await;
    assert_err(
        &e,
        ErrorKind::Configuration,
        "TLS certificate rejected: unknown issuer",
    );
    assert!(!e.is_retryable());
}

#[tokio::test]
async fn name_mismatch_is_configuration() {
    let addr = tls_server(SERVER_CERT, SERVER_KEY, false);
    // Trusted CA, but the certificate names anykms.test, not 127.0.0.1.
    let e = encrypt(
        ServerConfig::new(format!("https://{addr}"), Flavor::Vault)
            .http_transport(transport(|b| b.ca_pem(CA))),
    )
    .await;
    assert_err(
        &e,
        ErrorKind::Configuration,
        "TLS certificate rejected: name mismatch",
    );
}

#[tokio::test]
async fn client_certificate_rejection_is_configuration() {
    let addr = tls_server(LOOPBACK_CERT, LOOPBACK_KEY, true);
    let cfg = |t: ReqwestTransport| {
        ServerConfig::new(format!("https://{addr}"), Flavor::Vault).http_transport(t)
    };
    // Without a client certificate the server sends an alert (in TLS 1.3 after the client's
    // side of the handshake, so it arrives with the response).
    let e = encrypt(cfg(transport(|b| b.ca_pem(CA)))).await;
    assert_err(
        &e,
        ErrorKind::Configuration,
        "TLS handshake rejected by the server (client certificate?)",
    );
    // Control: with a trusted client certificate the handshake succeeds; the server then hangs
    // up without answering, which is a transient failure.
    let e = encrypt(cfg(transport(|b| {
        b.ca_pem(CA).client_identity(SERVER_CERT, SERVER_KEY)
    })))
    .await;
    assert_eq!(e.kind(), ErrorKind::Unavailable, "{e}");
}

#[tokio::test]
async fn explicit_crypto_provider_is_used() {
    // A provider without cipher suites cannot build a TLS configuration: proof it is the one
    // used, not the feature-selected default.
    let empty = CryptoProvider {
        cipher_suites: vec![],
        ..(*crypto()).clone()
    };
    let e = ReqwestTransport::builder()
        .ca_pem(CA)
        .crypto_provider(Arc::new(empty))
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");

    let addr = tls_server(SERVER_CERT, SERVER_KEY, false);
    let e = encrypt(
        ServerConfig::new(format!("https://{addr}"), Flavor::Vault)
            .http_transport(transport(|b| b.ca_pem(OTHER_CA).crypto_provider(crypto()))),
    )
    .await;
    assert_err(&e, ErrorKind::Configuration, "unknown issuer");
}

#[tokio::test]
async fn client_identity_loads_into_rustls() {
    ReqwestTransport::builder()
        .ca_pem(CA)
        .client_identity(SERVER_CERT, SERVER_KEY)
        .build()
        .unwrap();
    // A key that does not match the certificate is refused.
    let e = ReqwestTransport::builder()
        .ca_pem(CA)
        .client_identity(SERVER_CERT, include_bytes!("data/sec1-key.pem"))
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
}

#[test]
fn ca_pem_without_certificates_is_named() {
    let e = ReqwestTransport::builder().ca_pem(b"").build().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");
    assert!(e.to_string().contains("contains no certificates"), "{e}");
}

#[tokio::test]
async fn dns_failure_is_unavailable() {
    // `.invalid` never resolves (RFC 6761).
    let e = encrypt(
        ServerConfig::new("https://anykms-test.invalid:8200", Flavor::Vault)
            .http_transport(transport(|b| b.ca_pem(CA))),
    )
    .await;
    assert_err(&e, ErrorKind::Unavailable, "DNS lookup failed");
    assert!(e.is_retryable());
}

#[tokio::test]
async fn connection_refused_is_unavailable() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    // The listener is dropped: nothing accepts on the port.
    let e =
        encrypt(ServerConfig::new(format!("http://{addr}"), Flavor::Vault).allow_loopback_http())
            .await;
    assert_err(&e, ErrorKind::Unavailable, "connection refused");
}
