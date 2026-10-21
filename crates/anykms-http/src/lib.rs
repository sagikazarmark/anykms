//! HTTP plumbing shared by the anykms backends.
//!
//! **When to use this crate.** Never from an application, except to build a transport: depend on
//! the [`anykms`] facade (or a backend crate), which pulls this crate in where it is needed.
//! **The rest of this API is for anykms backends (`anykms-transit`, the cloud backends) only.**
//! It is published only because the backends that use it are. It is versioned in lockstep with
//! the other anykms crates and follows the same semver rules, which CI checks: a breaking change
//! comes only in a `0.(x+1)` release, never a patch, but it can come in any such release,
//! whenever a backend needs it.
//!
//! Every in-house anykms REST client follows the same rules (the backend checklist in
//! `docs/cloud/shared.md` §5); this crate holds the code that implements them once:
//!
//! - [`transport`]: the seam between the backends and the network. [`HttpTransport`] moves one
//!   bounded, zeroizing request/response pair; [`SendError`] is the fixed set of failure classes
//!   the backends map to `anykms_core::Error`; [`RequestTimeout`] is the per-request timeout a
//!   probe sets; [`BodyBuffer`] is the bounded zeroizing body every transport reads into.
//!   Backends take any transport through their builders (`.http_transport(..)`).
//! - [`reqwest`](mod@reqwest) (feature `reqwest`, default): the built-in transport
//!   ([`ReqwestTransport`]), reqwest over a preconfigured rustls configuration, never following
//!   redirects. It owns TLS trust and client certificates, the crypto provider, timeouts, proxying
//!   and the HTTP version ([`ReqwestTransportBuilder`]); the backends know none of these.
//! - [`tower`](mod@tower) (feature `tower`): [`TowerTransport`], any tower `Service` as a
//!   transport: a tower stack around the built-in client
//!   (`ReqwestTransport::into_service`), or a `fetch`-based service where reqwest cannot run
//!   (Cloudflare Workers). It sets `content-length`, reads bodies through [`BodyBuffer`], has no
//!   timeout of its own and cannot control redirects: the inner service must not follow them.
//! - [`tls`] (feature `rustls`): the rustls crypto provider precedence ([`select_provider`]:
//!   configured → process default → aws-lc-rs → ring) and the client TLS configuration
//!   ([`TlsOptions`]); the provider is never installed process-wide. [`is_missing_system_roots`]
//!   tells an empty system trust store from the other TLS configuration errors.
//! - [`pem`]: private keys from PEM into zeroizing buffers ([`private_key_from_pem`]).
//! - [`client`]: sending a request through a transport and reading its response ([`send`],
//!   which re-checks the body limit); `Retry-After` parsing ([`retry_after`]); the least response
//!   limit a backend accepts ([`MIN_RESPONSE_BYTES`]). No retries: those belong to
//!   `anykms_core::Retry`.
//! - [`zbuf`]: zeroizing buffers that grow without leaving unwiped copies, a JSON writer into
//!   them ([`json_body`]), bounded secret-file reads, and the classification of token-file
//!   failures ([`token_file_error_kind`]).
//! - [`credentials`]: a single-flight cache for expiring credentials ([`CredentialCache`]):
//!   every waiting caller gets the one fetch's result (a failure too, then remembered for 5 s),
//!   refresh ahead of expiry without blocking the holders of a valid credential,
//!   [`invalidate`] for the refresh-once-on-401 rule.
//! - [`cache`]: metadata-cache expiry with jitter ([`jittered_ttl`]) and one fetch per key at a
//!   time for concurrent misses ([`SingleFlight`]).
//! - [`redact`](mod@redact): server messages for errors and logs, pinned messages verbatim and
//!   anything else as its length and a keyed fingerprint ([`redact()`](redact::redact)); request
//!   ids ([`request_id`](redact::request_id)); URLs in `Debug` output ([`url_origin`]).
//! - [`span`]: the span schema of every backend: [`request_span!`] and [`token_span!`], with
//!   [`start_request`](span::start_request) and [`finish_token`](span::finish_token).
//!
//! # Cargo features
//!
//! | Feature | Default | Effect |
//! |---|---|---|
//! | `reqwest` | yes | [`ReqwestTransport`], the built-in transport; without it every backend needs `.http_transport(..)` |
//! | `rustls` | (by `reqwest`) | the [`tls`] module |
//! | `rustls-aws-lc-rs` | yes | aws-lc-rs as the fallback TLS crypto provider (wins over ring); `ReqwestTransport`-only |
//! | `rustls-ring` | | ring as the fallback provider (opt-in, with `default-features = false`); `ReqwestTransport`-only |
//! | `tracing` | | a debug event naming the provider chosen; the [`span`] schema (no-ops without it) |
//! | `http2` | | [`ReqwestTransportBuilder::http2`] may negotiate HTTP/2; `ReqwestTransport`-only |
//! | `tower` | | [`TowerTransport`], any tower `Service` as a transport; `ReqwestTransport::into_service` with `reqwest` |
//! | `js` | | `wasm32-unknown-unknown` on a JS host: the clocks (`anykms_core::time`) and RNG read the host; pair it with `tower` over a `fetch` service |
//!
//! aws-lc-rs builds C and assembly (aws-lc-sys), so the default build needs a C compiler.
//!
//! Backends forward their own `reqwest`, `rustls-*`, `tracing`, `http2`, `tower` and `js`
//! features to these.
//!
//! # `Send`
//!
//! [`HttpTransport`] is `Send + Sync` and its future is `Send` on every target, wasm32 included.
//! The backends' futures are `Send` (`anykms_core::BoxFuture`), so they can live in shared state
//! and run inside `Send`-requiring frameworks (tower, axum, workers-rs handlers); making the
//! transport conditionally `Send` would make the backends conditionally `Send` too, which those
//! frameworks reject. JS futures (`fetch`) are not `Send`, but a JS host without the `atomics`
//! target feature is single-threaded: a transport over a JS API wraps them (a `SendWrapper`) on
//! its side of the seam, as `tower-worker-fetch` does; anykms itself has no such wrapper.
//!
//! [`select_provider`]: tls::select_provider
//! [`TlsOptions`]: tls::TlsOptions
//! [`is_missing_system_roots`]: tls::is_missing_system_roots
//! [`private_key_from_pem`]: pem::private_key_from_pem
//! [`send`]: client::send
//! [`retry_after`]: client::retry_after
//! [`MIN_RESPONSE_BYTES`]: client::MIN_RESPONSE_BYTES
//! [`json_body`]: zbuf::json_body
//! [`token_file_error_kind`]: zbuf::token_file_error_kind
//! [`CredentialCache`]: credentials::CredentialCache
//! [`invalidate`]: credentials::CredentialCache::invalidate
//! [`jittered_ttl`]: cache::jittered_ttl
//! [`SingleFlight`]: cache::SingleFlight
//! [`url_origin`]: redact::url_origin
//! [`anykms`]: https://docs.rs/anykms

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub mod cache;
pub mod client;
pub mod credentials;
pub mod pem;
pub mod redact;
#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
pub mod reqwest;
pub mod span;
#[cfg(feature = "rustls")]
#[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
pub mod tls;
#[cfg(feature = "tower")]
#[cfg_attr(docsrs, doc(cfg(feature = "tower")))]
pub mod tower;
pub mod transport;
pub mod zbuf;

pub use transport::{BodyBuffer, HttpTransport, RequestTimeout, SendError, default_transport};

#[cfg(feature = "reqwest")]
pub use self::reqwest::{ReqwestTransport, ReqwestTransportBuilder};
#[cfg(feature = "tower")]
pub use self::tower::TowerTransport;

/// The `http` types in [`HttpTransport`]'s signature.
pub use http;
/// The rustls version used for TLS (`ReqwestTransportBuilder::crypto_provider` takes its
/// `CryptoProvider`).
#[cfg(feature = "rustls")]
pub use rustls;
/// The URL parser the backends build request URLs with.
pub use url;

/// What the span macros expand through. Not part of the API.
#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "tracing")]
    pub use tracing;
}
