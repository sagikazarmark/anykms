//! The transport seam: [`HttpTransport`], its error ([`SendError`]), the per-call request timeout
//! ([`RequestTimeout`]) and the bounded zeroizing body buffer every transport reads into
//! ([`BodyBuffer`]).
//!
//! A transport only moves bytes: one request in, one whole response out, with the body capped at
//! the limit the caller passes. It is deliberately **not** streaming: KMS payloads are small and
//! bounded, and they must be zeroized. Everything above it — authentication, retries, error
//! classification into `anykms_core::Error` — lives in the backends and in [`client`](crate::client).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anykms_core::BoxFuture;
use http::StatusCode;
use zeroize::Zeroizing;

/// A request with its body in a zeroizing buffer. A transport that must copy the body (reqwest
/// does) cannot wipe its copy; the guarantee is best effort and transport-dependent.
pub type Request = http::Request<Zeroizing<Vec<u8>>>;

/// A whole response, its body in a zeroizing buffer of at most the limit passed to
/// [`HttpTransport::send`].
pub type Response = http::Response<Zeroizing<Vec<u8>>>;

/// The underlying error of a [`SendError`].
pub type Source = Box<dyn std::error::Error + Send + Sync>;

/// Moves bytes for the anykms HTTP backends.
///
/// `limit` is the most bytes the response body may hold; it depends on the call site (data-plane
/// calls use the provider's `max_response_bytes`, token endpoints a fixed cap), not on the
/// transport, which is why it is an argument and not configuration. An implementation **must
/// stop reading once the limit is exceeded** and fail with [`SendError::TooLarge`]; what was read
/// so far must be wiped. [`client::send`](crate::client::send) checks the length again on the
/// way out, so a transport that ignores the limit still cannot push an oversized body into a
/// backend. [`BodyBuffer`] does the bookkeeping.
///
/// Implementations must never follow redirects (a redirect is returned as its 3xx response).
///
/// A request may carry a [`RequestTimeout`] in its extensions; a transport that can honour a
/// per-request timeout should.
///
/// The future is `Send`. A transport whose futures are not (a browser `fetch`, say) wraps them
/// on its own side of this boundary.
pub trait HttpTransport: Send + Sync + 'static {
    /// Sends `req` and reads the whole response (any status) into a body of at most `limit`
    /// bytes.
    fn send(&self, req: Request, limit: usize) -> BoxFuture<'_, Result<Response, SendError>>;

    /// Whether a request can be sent from the calling context. A backend asks before it starts
    /// an operation, ahead of its credential fetch, so that a context the transport cannot work
    /// from fails with one clear error instead of a credential-chain failure.
    /// [`ReqwestTransport`](crate::reqwest::ReqwestTransport) answers [`SendError::NoRuntime`]
    /// outside a Tokio runtime. The default is `Ok`.
    fn ready(&self) -> Result<(), SendError> {
        Ok(())
    }
}

impl<T: HttpTransport + ?Sized> HttpTransport for Arc<T> {
    fn send(&self, req: Request, limit: usize) -> BoxFuture<'_, Result<Response, SendError>> {
        (**self).send(req, limit)
    }

    fn ready(&self) -> Result<(), SendError> {
        (**self).ready()
    }
}

/// A per-request timeout, from sending to the end of the response body, in a request's
/// extensions (`req.extensions_mut().insert(RequestTimeout(d))`). Overrides the transport's own
/// request timeout for that request. Probes of metadata servers set it to fail fast. A transport
/// may ignore it; [`ReqwestTransport`](crate::reqwest::ReqwestTransport) honours it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTimeout(pub Duration);

/// How a connection attempt failed ([`SendError::Connect`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectFailure {
    /// The peer refused the connection.
    Refused,
    /// The connection was reset or aborted.
    Reset,
    /// Anything else (unreachable network, a connect timeout, ...).
    Other,
}

/// Why [`HttpTransport::send`] failed. No response was delivered.
///
/// The variants are the classes the backends map to `anykms_core::Error` (see
/// [`into_error`](Self::into_error)); a retrying decorator can rely on them: `NoRuntime`,
/// `InvalidRequest` and `TlsRejected` are `Configuration` and never worth a retry; `Timeout` is
/// `Timeout`; every other variant is `Unavailable` (transient, or at least unknown). Sources must not carry the request URL (it
/// may hold a query string with a secret).
#[non_exhaustive]
pub enum SendError {
    /// The transport needs an async runtime the caller is not inside (reqwest needs Tokio).
    /// Nothing was sent. A `Configuration` error naming the fix.
    NoRuntime,
    /// The request could not be built or is not sendable by this transport. `Configuration`.
    InvalidRequest(Source),
    /// The request timed out (the transport's request timeout or a [`RequestTimeout`]).
    Timeout(Source),
    /// The host name did not resolve. `Unavailable` (resolvers have transient outages too).
    Dns(Source),
    /// The TLS handshake was rejected: an untrusted or mismatched certificate, a missing client
    /// certificate, no common protocol. `Configuration`: retrying cannot fix it. `reason` is
    /// one of a fixed set of messages.
    TlsRejected {
        /// A fixed message such as `TLS certificate rejected: unknown issuer`.
        reason: &'static str,
        /// The underlying error.
        source: Source,
    },
    /// The TLS handshake failed for another reason (an interrupted handshake, say).
    /// `Unavailable`.
    Tls(Source),
    /// No connection. `Unavailable`.
    Connect {
        /// How it failed.
        failure: ConnectFailure,
        /// The underlying error.
        source: Source,
    },
    /// The response body was interrupted or could not be decoded. `Unavailable`.
    Body(Source),
    /// The response body exceeds the limit; what was read so far has been wiped.
    TooLarge {
        /// The response's status code.
        status: StatusCode,
    },
    /// Anything else. `Unavailable`.
    Other(Source),
}

impl fmt::Debug for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuntime => f.write_str("NoRuntime"),
            Self::InvalidRequest(s) => f.debug_tuple("InvalidRequest").field(s).finish(),
            Self::Timeout(s) => f.debug_tuple("Timeout").field(s).finish(),
            Self::Dns(s) => f.debug_tuple("Dns").field(s).finish(),
            Self::TlsRejected { reason, source } => f
                .debug_struct("TlsRejected")
                .field("reason", reason)
                .field("source", source)
                .finish(),
            Self::Tls(s) => f.debug_tuple("Tls").field(s).finish(),
            Self::Connect { failure, source } => f
                .debug_struct("Connect")
                .field("failure", failure)
                .field("source", source)
                .finish(),
            Self::Body(s) => f.debug_tuple("Body").field(s).finish(),
            Self::TooLarge { status } => {
                f.debug_struct("TooLarge").field("status", status).finish()
            }
            Self::Other(s) => f.debug_tuple("Other").field(s).finish(),
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoRuntime | Self::TooLarge { .. } => None,
            Self::InvalidRequest(s)
            | Self::Timeout(s)
            | Self::Dns(s)
            | Self::Tls(s)
            | Self::Body(s)
            | Self::Other(s)
            | Self::TlsRejected { source: s, .. }
            | Self::Connect { source: s, .. } => Some(&**s),
        }
    }
}

impl SendError {
    /// A [`Connect`](Self::Connect) error.
    pub fn connect(failure: ConnectFailure, source: impl Into<Source>) -> Self {
        Self::Connect {
            failure,
            source: source.into(),
        }
    }

    /// The fixed message [`into_error`](Self::into_error) uses.
    pub fn message(&self) -> &'static str {
        match self {
            Self::NoRuntime => NO_RUNTIME_MESSAGE,
            Self::InvalidRequest(_) => "the request could not be built",
            Self::Timeout(_) => "request timed out",
            Self::Dns(_) => "DNS lookup failed",
            Self::TlsRejected { reason, .. } => reason,
            Self::Tls(_) => "TLS handshake failed",
            Self::Connect { failure, .. } => match failure {
                ConnectFailure::Refused => "connection refused",
                ConnectFailure::Reset => "connection reset",
                ConnectFailure::Other => "cannot connect to the server",
            },
            Self::Body(_) => "response was interrupted",
            Self::TooLarge { .. } => "response exceeds the maximum size",
            Self::Other(_) => "request failed",
        }
    }

    /// The `anykms_core::ErrorKind` of this failure.
    pub fn kind(&self) -> anykms_core::ErrorKind {
        use anykms_core::ErrorKind as K;
        match self {
            Self::NoRuntime | Self::InvalidRequest(_) | Self::TlsRejected { .. } => {
                K::Configuration
            }
            Self::Timeout(_) => K::Timeout,
            Self::Dns(_)
            | Self::Tls(_)
            | Self::Connect { .. }
            | Self::Body(_)
            | Self::Other(_)
            | Self::TooLarge { .. } => K::Unavailable,
        }
    }

    /// Classifies this failure as an anykms error: the kind of [`kind`](Self::kind), the fixed
    /// message of [`message`](Self::message), the source attached. [`TooLarge`](Self::TooLarge)
    /// becomes `Unavailable` with the status as detail; a backend that reports it differently
    /// matches on it first.
    pub fn into_error(
        self,
        backend: &'static str,
        op: anykms_core::Operation,
    ) -> anykms_core::Error {
        use anykms_core::{BackendDetail, Error};
        let (kind, msg) = (self.kind(), self.message());
        let e = Error::new(kind, backend, op, msg);
        match self {
            Self::NoRuntime => e,
            Self::TooLarge { status } => {
                e.with_detail(BackendDetail::new().with_http_status(status.as_u16()))
            }
            Self::InvalidRequest(s)
            | Self::Timeout(s)
            | Self::Dns(s)
            | Self::Tls(s)
            | Self::Body(s)
            | Self::Other(s)
            | Self::TlsRejected { source: s, .. }
            | Self::Connect { source: s, .. } => e.with_source(s),
        }
    }
}

const NO_RUNTIME_MESSAGE: &str = "anykms HTTP backends must run inside a Tokio runtime; from synchronous code, run the call \
     on one (tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(..))";

/// The most a response's `Content-Length` may pre-allocate; larger bodies grow as they arrive.
pub const INITIAL_RESPONSE_CAPACITY: usize = 64 * 1024;

/// The bounded, zeroizing response body every transport reads into.
///
/// `Content-Length` is a hint from the server, trusted only up to [`INITIAL_RESPONSE_CAPACITY`]
/// (and the limit) for the first allocation; the buffer then grows through
/// [`zbuf::extend`](crate::zbuf::extend), never leaving unwiped copies and never beyond the
/// limit. On overflow what was read so far is wiped.
#[derive(Debug)]
pub struct BodyBuffer {
    body: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BodyBuffer {
    /// An empty buffer for a body of at most `limit` bytes, pre-allocated per `content_length`.
    pub fn new(content_length: Option<u64>, limit: usize) -> Self {
        let cap = content_length
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(1024)
            .min(INITIAL_RESPONSE_CAPACITY)
            .min(limit);
        Self {
            body: Zeroizing::new(Vec::with_capacity(cap)),
            limit,
        }
    }

    /// Appends `chunk`. On overflow the buffer is wiped and emptied and
    /// [`SendError::TooLarge`] (with `status`) is returned; the transport should stop reading.
    pub fn push(&mut self, chunk: &[u8], status: StatusCode) -> Result<(), SendError> {
        if crate::zbuf::extend(&mut self.body, chunk, self.limit) {
            Ok(())
        } else {
            self.body = Zeroizing::new(Vec::new());
            Err(SendError::TooLarge { status })
        }
    }

    /// The body read so far.
    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}

/// The transport a backend uses when none was injected: a default
/// [`ReqwestTransport`](crate::reqwest::ReqwestTransport) with the `reqwest` feature; without it,
/// `Configuration` naming the two remedies (the feature, or the builder's `.http_transport(..)`).
/// `backend` names the backend in that error. `require_roots` is `false` when the backend talks
/// only to plain-HTTP loopback endpoints (an agent sidecar, an emulator), which need no trust
/// store. Decided at compile time; there is no runtime registry.
pub fn default_transport(
    backend: &'static str,
    require_roots: bool,
) -> anykms_core::Result<Arc<dyn HttpTransport>> {
    #[cfg(feature = "reqwest")]
    {
        // The transport's configuration errors are the backend's to report.
        let t = crate::reqwest::ReqwestTransport::builder()
            .require_roots(require_roots)
            .build()
            .map_err(|e| e.with_backend(backend))?;
        Ok(Arc::new(t))
    }
    #[cfg(not(feature = "reqwest"))]
    {
        let _ = require_roots;
        Err(anykms_core::Error::new(
            anykms_core::ErrorKind::Configuration,
            backend,
            anykms_core::Operation::Configure,
            "no HTTP transport: enable the `reqwest` feature or call `.http_transport(..)` on \
             the builder",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_buffer_caps_at_the_limit_and_wipes_on_overflow() {
        let mut b = BodyBuffer::new(Some(u64::MAX), 5);
        assert!(b.body.capacity() <= 5);
        b.push(b"hel", StatusCode::OK).unwrap();
        b.push(b"lo", StatusCode::OK).unwrap();
        assert_eq!(&b.finish()[..], b"hello");

        let mut b = BodyBuffer::new(None, 4);
        b.push(b"hell", StatusCode::OK).unwrap();
        match b.push(b"o", StatusCode::BAD_GATEWAY) {
            Err(SendError::TooLarge { status }) => assert_eq!(status, StatusCode::BAD_GATEWAY),
            other => panic!("{other:?}"),
        }
        assert!(b.finish().is_empty());
    }

    #[test]
    fn kinds_and_messages_are_fixed() {
        use anykms_core::{ErrorKind, Operation};
        let src = || Source::from("x");
        let cases = [
            (SendError::NoRuntime, ErrorKind::Configuration),
            (SendError::InvalidRequest(src()), ErrorKind::Configuration),
            (SendError::Timeout(src()), ErrorKind::Timeout),
            (SendError::Dns(src()), ErrorKind::Unavailable),
            (
                SendError::TlsRejected {
                    reason: "TLS certificate rejected: expired",
                    source: src(),
                },
                ErrorKind::Configuration,
            ),
            (SendError::Tls(src()), ErrorKind::Unavailable),
            (
                SendError::connect(ConnectFailure::Refused, "r"),
                ErrorKind::Unavailable,
            ),
            (SendError::Body(src()), ErrorKind::Unavailable),
            (
                SendError::TooLarge {
                    status: StatusCode::OK,
                },
                ErrorKind::Unavailable,
            ),
            (SendError::Other(src()), ErrorKind::Unavailable),
        ];
        for (e, kind) in cases {
            let msg = e.message();
            let err = e.into_error("t", Operation::Encrypt);
            assert_eq!(err.kind(), kind, "{msg}");
            assert_eq!(err.message(), msg);
        }
        assert_eq!(
            SendError::connect(ConnectFailure::Reset, "r").message(),
            "connection reset"
        );
        assert!(
            SendError::NoRuntime
                .message()
                .contains("new_current_thread().enable_all()")
        );
    }
}

#[cfg(all(test, not(feature = "reqwest")))]
mod no_reqwest_tests {
    /// Without the `reqwest` feature there is no default transport: a `Configuration` error
    /// naming both remedies.
    #[test]
    fn default_transport_names_both_remedies() {
        let Err(e) = super::default_transport("t", true) else {
            panic!("a transport without the reqwest feature");
        };
        assert_eq!(e.kind(), anykms_core::ErrorKind::Configuration);
        assert_eq!(e.backend(), "t");
        assert!(e.message().contains("`reqwest`"), "{e}");
        assert!(e.message().contains(".http_transport(..)"), "{e}");
    }
}
