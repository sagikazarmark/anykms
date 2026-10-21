//! The reqwest client, transport errors, bounded response bodies and `Retry-After`.

use std::fmt;
use std::time::{Duration, SystemTime};

use anykms_core::{Error, ErrorKind, Operation, Result};
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use zeroize::Zeroizing;

/// The most a response's `Content-Length` may pre-allocate; larger bodies grow as they arrive.
pub const INITIAL_RESPONSE_CAPACITY: usize = 64 * 1024;

/// The smallest `max_response_bytes` a backend accepts (64 KiB): smaller limits break describe
/// and token responses with confusing `Backend` errors.
pub const MIN_RESPONSE_BYTES: usize = 64 * 1024;

/// Options for [`build`](Self::build): a reqwest client that **never follows redirects**, with a
/// connect timeout and a per-attempt (whole request) timeout. The overall deadline across
/// attempts belongs to `anykms_core::Retry`, which is also the only retry layer.
///
/// Defaults (transit's): connect 2 s, request 10 s, idle pooled connections kept 50 s, TCP
/// keepalive 30 s, HTTP/1.1 only, no proxy (environment proxy variables are ignored), user agent
/// `anykms/<version>`.
///
/// `Debug` prints only the proxy URL's origin ([`url_origin`](crate::redact::url_origin)): its
/// userinfo may carry credentials.
#[derive(Clone)]
pub struct ClientOptions {
    connect_timeout: Duration,
    request_timeout: Duration,
    pool_idle_timeout: Duration,
    tcp_keepalive: Duration,
    http2: bool,
    proxy: Option<String>,
    user_agent: String,
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOptions")
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("pool_idle_timeout", &self.pool_idle_timeout)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .field("http2", &self.http2)
            .field(
                "proxy",
                &self.proxy.as_deref().map(crate::redact::url_origin),
            )
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientOptions {
    /// The defaults.
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(50),
            tcp_keepalive: Duration::from_secs(30),
            http2: false,
            proxy: None,
            user_agent: concat!("anykms/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// Timeout for establishing a connection (TCP and TLS).
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Timeout for one request, from sending to the end of the response body.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// How long idle pooled connections are kept.
    pub fn pool_idle_timeout(mut self, d: Duration) -> Self {
        self.pool_idle_timeout = d;
        self
    }

    /// TCP keepalive interval.
    pub fn tcp_keepalive(mut self, d: Duration) -> Self {
        self.tcp_keepalive = d;
        self
    }

    /// Allows HTTP/2 (`false`: HTTP/1.1 only). Without the `http2` feature reqwest speaks HTTP/1.1
    /// regardless; pair it with [`TlsOptions::http2`](crate::tls::TlsOptions::http2) for ALPN.
    pub fn http2(mut self, http2: bool) -> Self {
        self.http2 = http2;
        self
    }

    /// Sends every request through this proxy URL; `None` (the default) connects directly and
    /// ignores proxy environment variables.
    pub fn proxy(mut self, url: Option<String>) -> Self {
        self.proxy = url;
        self
    }

    /// The `User-Agent` header.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Builds the client with `tls` (from [`TlsOptions::build`](crate::tls::TlsOptions::build)),
    /// preconfigured so that no process-global rustls provider is installed or required.
    /// Errors are `Configuration` with fixed messages.
    pub fn build(
        &self,
        backend: &'static str,
        tls: rustls::ClientConfig,
    ) -> Result<reqwest::Client> {
        let err = |m| Error::new(ErrorKind::Configuration, backend, Operation::Configure, m);
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
            .tcp_keepalive(self.tcp_keepalive)
            .user_agent(self.user_agent.as_str())
            .use_preconfigured_tls(tls);
        b = match &self.proxy {
            None => b.no_proxy(),
            Some(u) => {
                b.proxy(reqwest::Proxy::all(u.as_str()).map_err(|_| err("invalid proxy URL"))?)
            }
        };
        if !self.http2 {
            b = b.http1_only();
        }
        b.build().map_err(|_| err("cannot build the HTTP client"))
    }
}

/// Classifies a connection failure by walking the error's source chain (reqwest → hyper-util →
/// `io::Error` → `rustls::Error`). Certificate and handshake-policy failures are
/// `Configuration`: retrying cannot fix a CA, hostname or client-certificate mismatch. DNS
/// failures stay `Unavailable` (resolvers have transient outages too) with a message that names
/// them, so a mistyped host is easy to spot. Messages are fixed strings.
pub fn connect_failure(e: &(dyn std::error::Error + 'static)) -> Option<(ErrorKind, &'static str)> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(tls) = err.downcast_ref::<rustls::Error>() {
            return Some(tls_failure(tls));
        }
        // hyper-util's (private) connect error for resolver failures.
        if err.to_string() == "dns error" {
            return Some((ErrorKind::Unavailable, "DNS lookup failed"));
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    return Some((ErrorKind::Unavailable, "connection refused"));
                }
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                    return Some((ErrorKind::Unavailable, "connection reset"));
                }
                _ => {}
            }
            // `io::Error::source` skips the wrapped error itself; descend into it instead.
            if let Some(inner) = io.get_ref() {
                cur = Some(inner);
                continue;
            }
        }
        cur = err.source();
    }
    None
}

fn tls_failure(e: &rustls::Error) -> (ErrorKind, &'static str) {
    use rustls::{AlertDescription as A, CertificateError as C, Error as E};
    let config = |m| (ErrorKind::Configuration, m);
    match e {
        E::InvalidCertificate(c) => config(match c {
            C::UnknownIssuer => "TLS certificate rejected: unknown issuer",
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                "TLS certificate rejected: name mismatch"
            }
            C::Expired | C::ExpiredContext { .. } => "TLS certificate rejected: expired",
            C::NotValidYet | C::NotValidYetContext { .. } => {
                "TLS certificate rejected: not yet valid"
            }
            C::Revoked => "TLS certificate rejected: revoked",
            C::BadSignature => "TLS certificate rejected: bad signature",
            C::BadEncoding => "TLS certificate rejected: bad encoding",
            _ => "TLS certificate rejected",
        }),
        E::NoCertificatesPresented => config("TLS certificate rejected: none presented"),
        E::AlertReceived(
            A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::CertificateRequired
            | A::AccessDenied,
        ) => config("TLS handshake rejected by the server (client certificate?)"),
        E::PeerIncompatible(_) => config("TLS handshake failed: no common protocol or cipher"),
        _ => (ErrorKind::Unavailable, "TLS handshake failed"),
    }
}

/// Classifies a reqwest failure (no response) as an anykms error: fixed messages, the URL
/// stripped from the source (it may carry a query string).
pub fn transport_error(backend: &'static str, op: Operation, e: reqwest::Error) -> Error {
    let (kind, msg) = if e.is_builder() {
        (ErrorKind::Configuration, "the request could not be built")
    } else if e.is_timeout() {
        (ErrorKind::Timeout, "request timed out")
    } else if let Some(c) = connect_failure(&e) {
        c
    } else if e.is_connect() {
        (ErrorKind::Unavailable, "cannot connect to the server")
    } else if e.is_body() || e.is_decode() {
        (ErrorKind::Unavailable, "response was interrupted")
    } else {
        (ErrorKind::Unavailable, "request failed")
    };
    Error::new(kind, backend, op, msg).with_source(e.without_url())
}

/// Why [`read_body`] failed.
#[derive(Debug)]
pub enum BodyError {
    /// The body exceeds the limit; what was read so far has been wiped.
    TooLarge,
    /// Reading failed (classify it with [`transport_error`]).
    Transport(reqwest::Error),
}

/// Reads a response body into a zeroizing buffer of at most `limit` bytes. `Content-Length` is a
/// hint from the server, trusted only up to [`INITIAL_RESPONSE_CAPACITY`] for the first
/// allocation; the buffer then grows through [`zbuf::extend`](crate::zbuf::extend), never leaving
/// unwiped copies and never beyond `limit`.
pub async fn read_body(
    mut resp: reqwest::Response,
    limit: usize,
) -> std::result::Result<Zeroizing<Vec<u8>>, BodyError> {
    let mut body = Zeroizing::new(Vec::with_capacity(
        resp.content_length()
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(1024)
            .min(INITIAL_RESPONSE_CAPACITY)
            .min(limit),
    ));
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if !crate::zbuf::extend(&mut body, &chunk, limit) {
                    return Err(BodyError::TooLarge);
                }
            }
            Ok(None) => return Ok(body),
            Err(e) => return Err(BodyError::Transport(e)),
        }
    }
}

/// A response read by [`send`]: its status, headers and body (at most the limit, zeroizing).
///
/// `Debug` prints the status and the body length only.
pub struct Response {
    /// The status code.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The body, wiped on drop.
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Why [`send`] failed.
#[derive(Debug)]
pub enum SendError {
    /// The caller is not inside a Tokio runtime, where reqwest would panic (classify it with
    /// [`no_runtime_error`]). Nothing was sent.
    NoRuntime,
    /// No response, or reading its body failed (classify it with [`transport_error`]). The URL
    /// has been stripped from the error.
    Transport(reqwest::Error),
    /// The response body exceeds the limit; what was read so far has been wiped.
    TooLarge {
        /// The response's status code.
        status: StatusCode,
    },
}

/// The `Configuration` error for a call made outside a Tokio runtime ([`require_runtime`],
/// [`SendError::NoRuntime`]); its message names the fix.
pub fn no_runtime_error(backend: &'static str, op: Operation) -> Error {
    Error::new(
        ErrorKind::Configuration,
        backend,
        op,
        "anykms HTTP backends must run inside a Tokio runtime; from synchronous code, run the \
         call on one (tokio::runtime::Builder::new_current_thread().enable_all().build()?\
         .block_on(..))",
    )
}

/// `Ok` inside a Tokio runtime; otherwise [`no_runtime_error`]. reqwest, its timers and the
/// tokio-based credential sources panic outside one, so a backend checks this first, before its
/// credential fetch. A runtime built without `enable_all()` (no I/O or time driver) passes the
/// check and still panics in reqwest.
pub fn require_runtime(backend: &'static str, op: Operation) -> Result<()> {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => Ok(()),
        Err(_) => Err(no_runtime_error(backend, op)),
    }
}

/// Sends `req` and reads the whole response (any status) into a [`Response`] whose body is at
/// most `limit` bytes (see [`read_body`]). Records `http_status` into the current span (the
/// request span, [`request_span!`](crate::request_span)) for every response, success included;
/// a second attempt (the refresh-once retry) overwrites it.
///
/// Outside a Tokio runtime it sends nothing and fails with [`SendError::NoRuntime`] instead of
/// panicking.
///
/// reqwest copies a request body into its own buffer, which cannot be zeroized.
pub async fn send(
    req: reqwest::RequestBuilder,
    limit: usize,
) -> std::result::Result<Response, SendError> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(SendError::NoRuntime);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| SendError::Transport(e.without_url()))?;
    let status = resp.status();
    #[cfg(feature = "tracing")]
    tracing::Span::current().record("http_status", status.as_u16());
    let headers = resp.headers().clone();
    let body = read_body(resp, limit).await.map_err(|e| match e {
        BodyError::TooLarge => SendError::TooLarge { status },
        BodyError::Transport(e) => SendError::Transport(e.without_url()),
    })?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// The `Retry-After` header as a delay: delay-seconds or an HTTP-date (RFC 9110 §10.2.3), a date
/// in the past being a zero delay. `None` when absent or malformed.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let v = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    retry_after_value(v, SystemTime::now())
}

/// A `Retry-After` value relative to `now` (see [`retry_after`]).
pub fn retry_after_value(v: &str, now: SystemTime) -> Option<Duration> {
    let v = v.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = httpdate::parse_http_date(v).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Polls `fut` to completion on this thread, with no Tokio runtime.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn block_on<F: Future>(fut: F) -> F::Output {
        struct Unpark(std::thread::Thread);
        impl std::task::Wake for Unpark {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = std::sync::Arc::new(Unpark(std::thread::current())).into();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            std::thread::park();
        }
    }

    /// R-35: outside a Tokio runtime `require_runtime` is `Configuration` naming the fix; inside
    /// one it passes.
    #[test]
    fn require_runtime_names_the_fix() {
        let e = require_runtime("test", Operation::Encrypt).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert_eq!(e.operation(), Operation::Encrypt);
        assert!(
            e.message()
                .starts_with("anykms HTTP backends must run inside a Tokio runtime; ")
                && e.message().contains("new_current_thread().enable_all()"),
            "{e}"
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async { require_runtime("test", Operation::Encrypt) })
            .unwrap();
    }

    /// R-35: outside a Tokio runtime `send` sends nothing and fails instead of panicking.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn outside_a_runtime_send_fails_instead_of_panicking() {
        let tls = crate::tls::TlsOptions::new()
            .require_roots(false)
            .build("t")
            .unwrap();
        let client = ClientOptions::new().build("t", tls).unwrap();
        let r = block_on(send(client.get("http://127.0.0.1:1/"), MIN_RESPONSE_BYTES));
        assert!(matches!(r, Err(SendError::NoRuntime)), "{r:?}");
    }

    #[test]
    fn retry_after_seconds_and_http_date() {
        // 2015-10-21 07:28:00 UTC.
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1_445_412_480);
        assert_eq!(retry_after_value(" 7 ", now), Some(Duration::from_secs(7)));
        assert_eq!(retry_after_value("0", now), Some(Duration::ZERO));
        assert_eq!(
            retry_after_value("Wed, 21 Oct 2015 07:28:30 GMT", now),
            Some(Duration::from_secs(30))
        );
        // A date in the past means "now".
        assert_eq!(
            retry_after_value("Wed, 21 Oct 2015 07:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(retry_after_value("soon", now), None);
        assert_eq!(retry_after_value("-1", now), None);

        let mut h = HeaderMap::new();
        assert_eq!(retry_after(&h), None);
        h.insert(reqwest::header::RETRY_AFTER, "3".parse().unwrap());
        assert_eq!(retry_after(&h), Some(Duration::from_secs(3)));
    }

    #[derive(Debug)]
    struct Wrap(&'static str, Box<dyn std::error::Error + Send + Sync>);
    impl std::fmt::Display for Wrap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Wrap {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.1)
        }
    }

    #[test]
    fn connect_failures_are_classified_from_the_source_chain() {
        use std::io;
        let tls = |e: rustls::Error| {
            Wrap(
                "client error (Connect)",
                Box::new(io::Error::new(io::ErrorKind::InvalidData, e)),
            )
        };
        let cert = |c| tls(rustls::Error::InvalidCertificate(c));
        let cases: Vec<(Wrap, ErrorKind, &str)> = vec![
            (
                cert(rustls::CertificateError::UnknownIssuer),
                ErrorKind::Configuration,
                "TLS certificate rejected: unknown issuer",
            ),
            (
                cert(rustls::CertificateError::NotValidForName),
                ErrorKind::Configuration,
                "TLS certificate rejected: name mismatch",
            ),
            (
                cert(rustls::CertificateError::Expired),
                ErrorKind::Configuration,
                "TLS certificate rejected: expired",
            ),
            (
                tls(rustls::Error::AlertReceived(
                    rustls::AlertDescription::CertificateRequired,
                )),
                ErrorKind::Configuration,
                "TLS handshake rejected by the server (client certificate?)",
            ),
            (
                tls(rustls::Error::DecryptError),
                ErrorKind::Unavailable,
                "TLS handshake failed",
            ),
            (
                Wrap(
                    "client error (Connect)",
                    Box::new(Wrap(
                        "dns error",
                        Box::new(io::Error::other("failed to lookup address information")),
                    )),
                ),
                ErrorKind::Unavailable,
                "DNS lookup failed",
            ),
            (
                Wrap(
                    "client error (Connect)",
                    Box::new(Wrap(
                        "tcp connect error",
                        Box::new(io::Error::from(io::ErrorKind::ConnectionRefused)),
                    )),
                ),
                ErrorKind::Unavailable,
                "connection refused",
            ),
        ];
        for (err, kind, msg) in cases {
            assert_eq!(connect_failure(&err), Some((kind, msg)), "{err:?}");
        }
        let other = Wrap("x", Box::new(io::Error::other("y")));
        assert_eq!(connect_failure(&other), None);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn builds_clients() {
        let tls = || {
            crate::tls::TlsOptions::new()
                .require_roots(false)
                .build("t")
                .unwrap()
        };
        ClientOptions::new().build("t", tls()).unwrap();
        ClientOptions::new()
            .proxy(Some("http://127.0.0.1:3128".into()))
            .user_agent("x")
            .build("t", tls())
            .unwrap();
        let e = ClientOptions::new()
            .proxy(Some("::not a url".into()))
            .build("t", tls())
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
    }

    #[test]
    fn client_options_debug_prints_the_proxy_origin_only() {
        let o = ClientOptions::new().proxy(Some("http://alice:SECRET@proxy.example:3128/x".into()));
        let d = format!("{o:?}");
        assert!(d.contains("http://proxy.example:3128"), "{d}");
        assert!(!d.contains("SECRET") && !d.contains("alice"), "{d}");
    }

    /// Serves one canned HTTP/1.1 response per connection on a loopback port, `n` times.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn serve(response: Vec<u8>, n: usize) -> String {
        use std::io::{Read as _, Write as _};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..n {
                let (mut s, _) = l.accept().unwrap();
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => req.extend_from_slice(&b[..k]),
                    }
                }
                let _ = s.write_all(&response);
            }
        });
        format!("http://{addr}/p?token=SECRET")
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[tokio::test]
    async fn send_reads_any_status_within_the_limit() {
        let tls = crate::tls::TlsOptions::new()
            .require_roots(false)
            .build("t")
            .unwrap();
        let client = ClientOptions::new().build("t", tls).unwrap();
        let url = serve(
            b"HTTP/1.1 503 Service Unavailable\r\nx-request-id: r1\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello"
                .to_vec(),
            2,
        );
        let r = send(client.get(&url), 5).await.unwrap();
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers.get("x-request-id").unwrap(), "r1");
        assert_eq!(&r.body[..], b"hello");
        assert!(!format!("{r:?}").contains("hello"));
        match send(client.get(&url), 4).await {
            Err(SendError::TooLarge { status }) => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("{other:?}"),
        }
        // Nothing listens there.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/p?token=SECRET", l.local_addr().unwrap())
        };
        match send(client.get(&closed), 4).await {
            Err(SendError::Transport(e)) => {
                assert!(e.url().is_none());
                assert!(!format!("{e:?}").contains("SECRET"));
            }
            other => panic!("{other:?}"),
        }
    }
}
