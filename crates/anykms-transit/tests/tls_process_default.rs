//! A process-wide rustls provider installed by the application wins over the provider the
//! `rustls-*` features select. Its own test binary: the default is process-global.

#![cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]

use std::sync::Arc;

use anykms_core::ErrorKind;
use anykms_transit::rustls;
use anykms_transit::{Flavor, ServerConfig, TransitProvider};

fn feature_provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "rustls-aws-lc-rs")]
    return rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(feature = "rustls-aws-lc-rs"))]
    rustls::crypto::ring::default_provider()
}

fn build(cfg: ServerConfig) -> anykms_core::Result<TransitProvider> {
    TransitProvider::builder().server("default", cfg).build()
}

#[test]
fn installed_default_wins_over_features() {
    let https = || ServerConfig::new("https://127.0.0.1:1", Flavor::Vault).ca_pem(CA);

    // Before anything is installed, the feature's provider works.
    build(https()).unwrap();

    // A provider without cipher suites cannot build a TLS config: if it is the one chosen,
    // building fails, which proves the installed default was used instead of the feature's.
    let crippled = rustls::crypto::CryptoProvider {
        cipher_suites: vec![],
        ..feature_provider()
    };
    crippled.install_default().unwrap();
    let e = build(https()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Configuration, "{e}");

    // A per-server provider still wins over the installed default.
    build(https().crypto_provider(Arc::new(feature_provider()))).unwrap();
}

const CA: &[u8] = include_bytes!("data/ca.pem");
