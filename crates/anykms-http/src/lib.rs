//! HTTP plumbing shared by the anykms backends.
//!
//! **When to use this crate.** Never from an application: depend on the [`anykms`] facade (or a
//! backend crate), which pulls this crate in where it is needed. **This API is for anykms
//! backends (`anykms-transit`, the cloud backends) only.** It is published only because the
//! backends that use it are. It is versioned in lockstep with the other anykms crates and follows
//! the same semver rules, which CI checks: a breaking change comes only in a `0.(x+1)` release,
//! never a patch, but it can come in any such release, whenever a backend needs it.
//!
//! Every in-house anykms REST client follows the same rules (the backend checklist in
//! `docs/cloud/shared.md` §5); this crate holds the code that implements them once:
//!
//! - [`tls`]: the rustls crypto provider precedence ([`select_provider`]: configured → process
//!   default → aws-lc-rs → ring) and the client TLS configuration ([`TlsOptions`]); the provider
//!   is never installed process-wide. [`is_missing_system_roots`] tells an empty system trust
//!   store from the other TLS configuration errors.
//! - [`client`]: a reqwest client that never follows redirects, with connect and per-attempt
//!   timeouts ([`ClientOptions`]); sending a request and reading its response into a bounded
//!   zeroizing buffer ([`send`], [`read_body`]); transport-error classification with fixed
//!   messages and no URL ([`transport_error`]); `Retry-After` parsing ([`retry_after`]); the
//!   least response limit a backend accepts ([`MIN_RESPONSE_BYTES`]). No retries: those belong
//!   to `anykms_core::Retry`.
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
//! | `rustls-aws-lc-rs` | yes | aws-lc-rs as the fallback TLS crypto provider (wins over ring) |
//! | `rustls-ring` | | ring as the fallback provider (opt-in, with `default-features = false`) |
//! | `tracing` | | a debug event naming the provider chosen; the [`span`] schema (no-ops without it) |
//! | `http2` | | [`ClientOptions::http2`] may negotiate HTTP/2 |
//!
//! aws-lc-rs builds C and assembly (aws-lc-sys), so the default build needs a C compiler.
//!
//! Backends forward their own `rustls-*`, `tracing` and `http2` features to these.
//!
//! [`select_provider`]: tls::select_provider
//! [`TlsOptions`]: tls::TlsOptions
//! [`is_missing_system_roots`]: tls::is_missing_system_roots
//! [`ClientOptions`]: client::ClientOptions
//! [`ClientOptions::http2`]: client::ClientOptions::http2
//! [`send`]: client::send
//! [`transport_error`]: client::transport_error
//! [`read_body`]: client::read_body
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
pub mod redact;
pub mod span;
pub mod tls;
pub mod zbuf;

/// The reqwest version the clients are built with.
pub use reqwest;
/// The rustls version used for TLS.
pub use rustls;

/// What the span macros expand through. Not part of the API.
#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "tracing")]
    pub use tracing;
}
