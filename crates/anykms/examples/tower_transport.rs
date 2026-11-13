//! Put the built-in HTTP client at the bottom of a tower stack: a concurrency limit here, but
//! any layer (rate limiting, instrumentation) goes the same way. The stack becomes the transit
//! provider's transport through `TowerTransport`.
//!
//!     # against Vault (scripts/dev-up.sh; create the key first):
//!     VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ANYKMS_KEK_URI=hashivault:///transit/keys/app-kek \
//!       cargo run -p anykms --features transit,tower --example tower_transport
//!
//! Without `VAULT_ADDR` (or `BAO_ADDR`) it prints a note and exits: the example is about the
//! transport, which local keys never use.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anykms::prelude::*;
use anykms::transit::anykms_http::{ReqwestTransport, TowerTransport};
use anykms::transit::{EnvConfig, EnvTls, TransitProvider};
use tower::ServiceBuilder;

#[tokio::main]
async fn main() -> anykms::Result<()> {
    let set = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
    if !set("VAULT_ADDR") && !set("BAO_ADDR") {
        eprintln!("note: set VAULT_ADDR or BAO_ADDR; this example runs against transit only");
        return Ok(());
    }
    let env = if set("BAO_ADDR") {
        EnvConfig::openbao()
    } else {
        EnvConfig::vault()
    };

    // The hardened client (TLS, no redirects, timeouts) as a tower service, with the caller's
    // layers on top. It is built from the TLS variables (`VAULT_CACERT`, `VAULT_CAPATH`,
    // `VAULT_CLIENT_CERT`/`VAULT_CLIENT_KEY`) `EnvConfig` reads: the transport passed to
    // `http_transport` below replaces the one `load` built from them, so building it from
    // anything else would silently drop a pinned CA or client certificate. Every request the
    // backend sends passes through the stack; the counters around the limit show it holding.
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let service = ServiceBuilder::new()
        .map_result({
            let in_flight = in_flight.clone();
            move |r| {
                in_flight.fetch_sub(1, Ordering::SeqCst);
                r
            }
        })
        .concurrency_limit(4)
        .map_request({
            let (in_flight, peak) = (in_flight.clone(), peak.clone());
            move |req| {
                let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                req
            }
        })
        .service(
            env.tls()?
                .map_or_else(ReqwestTransport::builder, EnvTls::into_transport_builder)
                .build()?
                .into_service(),
        );
    // `TowerTransport` cannot see the client's timeouts through the stack, so it does not bound how
    // long a backend's single-flight followers wait for another caller's credential or metadata
    // request; the built-in transport does (twice its connect plus request timeout: 24 s with the
    // defaults). Without a bound, a caller that stops polling its request mid-flight leaves later
    // callers waiting for as long as that future lives. Set one above the request timeout.
    let transport = TowerTransport::new(service)
        .with_follower_wait(Duration::from_secs(24), anykms::tokio_sleep());
    let server = env.load()?.http_transport(transport);

    let registry = anykms::Registry::builder()
        .provider(
            TransitProvider::builder()
                .server("default", server)
                .build()?,
        )
        .layer(anykms::retry_layer())
        .build()?;
    let uri = std::env::var("ANYKMS_KEK_URI")
        .unwrap_or_else(|_| "hashivault:///transit/keys/app-kek".to_owned());
    let aead = registry.aead(&uri)?;

    // Sixteen concurrent round trips; the stack lets at most four requests reach the server at
    // once.
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..16u8 {
        let aead = aead.clone();
        tasks.spawn(async move {
            let aad = [i];
            let ct = aead.encrypt(b"123-45-6789", &aad).await?;
            let pt = aead.decrypt(&ct, &aad).await?;
            assert_eq!(&*pt, b"123-45-6789");
            anykms::Result::Ok(())
        });
    }
    while let Some(r) = tasks.join_next().await {
        r.expect("task panicked")?;
    }
    let peak = peak.load(Ordering::SeqCst);
    println!("32 requests through the stack, at most {peak} in flight");
    assert!(peak <= 4, "the concurrency limit let {peak} through");
    Ok(())
}
