//! [`ReqwestTransport`]: the built-in [`HttpTransport`] (feature `reqwest`), reqwest over rustls.
//!
//! This is the one place anykms knows about reqwest, hyper and rustls. The transport owns every
//! connection-level setting — TLS trust and client certificates, the crypto provider, timeouts,
//! proxying, HTTP version, the user agent — through [`ReqwestTransportBuilder`]. Backends
//! configure only what is transport-independent (endpoint, credentials, response limit).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anykms_core::{BoxFuture, Error, ErrorKind, Operation, Result};
use rustls::crypto::CryptoProvider;
use zeroize::Zeroizing;

use crate::tls::TlsOptions;
use crate::transport::{
    BodyBuffer, ConnectFailure, HttpTransport, Request, RequestTimeout, Response, SendError, Source,
};

/// The backend name in this transport's `Configuration` errors.
const BACKEND: &str = "http";

/// Hosts never sent through a configured proxy: the cloud metadata servers (AWS IMDS and ECS on
/// IPv4 and IPv6, the GCP metadata server by address and name, Azure IMDS: all link-local or
/// unique-local) and loopback.
const NO_PROXY: &str =
    "169.254.0.0/16,fe80::/10,fd00:ec2::/64,metadata.google.internal,127.0.0.0/8,::1,localhost";

fn config_err(m: &'static str) -> Error {
    Error::new(ErrorKind::Configuration, BACKEND, Operation::Configure, m)
}

/// Builds a [`ReqwestTransport`].
///
/// Defaults: system roots (required), no client certificate, the crypto provider of
/// [`select_provider`](crate::tls::select_provider), connect 2 s, request 10 s, idle pooled
/// connections kept 50 s, TCP keepalive 30 s, HTTP/1.1 only, no proxy (environment proxy
/// variables are ignored), user agent `anykms/<version>`. Redirects are never followed.
///
/// `Debug` prints only the proxy URL's origin ([`url_origin`](crate::redact::url_origin)): its
/// userinfo may carry credentials. Key material is never printed.
#[derive(Clone)]
pub struct ReqwestTransportBuilder {
    ca_pem: Option<Vec<u8>>,
    client_identity: Option<(Vec<u8>, Zeroizing<Vec<u8>>)>,
    crypto_provider: Option<Arc<CryptoProvider>>,
    require_roots: bool,
    connect_timeout: Duration,
    request_timeout: Duration,
    pool_idle_timeout: Duration,
    tcp_keepalive: Duration,
    http2: bool,
    proxy: Option<String>,
    user_agent: String,
}

impl fmt::Debug for ReqwestTransportBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestTransportBuilder")
            .field("ca_pem", &self.ca_pem.is_some())
            .field("client_identity", &self.client_identity.is_some())
            .field("crypto_provider", &self.crypto_provider.is_some())
            .field("require_roots", &self.require_roots)
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

impl Default for ReqwestTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestTransportBuilder {
    /// The defaults.
    pub fn new() -> Self {
        Self {
            ca_pem: None,
            client_identity: None,
            crypto_provider: None,
            require_roots: true,
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(50),
            tcp_keepalive: Duration::from_secs(30),
            http2: false,
            proxy: None,
            user_agent: concat!("anykms/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// Trusts only the certificates in `pem` instead of the system roots.
    pub fn ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_pem = Some(pem.into());
        self
    }

    /// Presents a client certificate chain and its private key (PEM; PKCS#8, PKCS#1 or SEC1,
    /// unencrypted). The key is kept in a zeroizing buffer and decoded into zeroizing buffers;
    /// rustls wipes the DER after loading it. Pass an owned `Vec` (not a slice) so no unwiped copy
    /// is made here. The parsed signing key then lives inside the crypto provider: aws-lc clears
    /// it when freed, ring does not.
    pub fn client_identity(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_identity = Some((cert_pem.into(), Zeroizing::new(key_pem.into())));
        self
    }

    /// The rustls crypto provider (first in [`select_provider`](crate::tls::select_provider)'s
    /// order).
    pub fn crypto_provider(mut self, provider: Arc<CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Whether having no trusted root is an error (default `true`). A transport used only for
    /// plain-HTTP loopback servers needs none.
    pub fn require_roots(mut self, require: bool) -> Self {
        self.require_roots = require;
        self
    }

    /// Timeout for establishing a connection (TCP and TLS).
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Timeout for one request, from sending to the end of the response body. A request's
    /// [`RequestTimeout`] overrides it. The overall deadline across attempts belongs to
    /// `anykms_core::Retry`.
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

    /// Offers HTTP/2 (`h2` in ALPN, then `http/1.1`); default HTTP/1.1 only. Without the
    /// `http2` feature reqwest speaks HTTP/1.1 regardless of ALPN.
    pub fn http2(mut self, http2: bool) -> Self {
        self.http2 = http2;
        self
    }

    /// Sends requests through this proxy URL, except to link-local and loopback hosts (the cloud
    /// metadata servers are always reached directly). `None` (the default) connects directly and
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

    /// Builds the transport. Errors are `Configuration` with fixed messages; an empty system
    /// trust store (and no `ca_pem`) is the one
    /// [`is_missing_system_roots`](crate::tls::is_missing_system_roots) recognizes.
    pub fn build(&self) -> Result<ReqwestTransport> {
        if self.http2 && !cfg!(feature = "http2") {
            return Err(config_err("http2 needs the anykms-http `http2` feature"));
        }
        let tls = TlsOptions::new()
            .ca_pem(self.ca_pem.as_deref())
            .client_identity(self.client_identity.as_ref().map(|(c, k)| (&c[..], &k[..])))
            .crypto_provider(
                self.crypto_provider.clone(),
                "ReqwestTransportBuilder::crypto_provider",
            )
            .require_roots(self.require_roots)
            .http2(self.http2)
            .build(BACKEND)?;
        let mut b = ::reqwest::Client::builder()
            .redirect(::reqwest::redirect::Policy::none())
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .pool_idle_timeout(self.pool_idle_timeout)
            .tcp_keepalive(self.tcp_keepalive)
            .user_agent(self.user_agent.as_str())
            .use_preconfigured_tls(tls);
        b = match &self.proxy {
            None => b.no_proxy(),
            Some(u) => b.proxy(
                ::reqwest::Proxy::all(u.as_str())
                    .map_err(|_| config_err("invalid proxy URL"))?
                    .no_proxy(::reqwest::NoProxy::from_string(NO_PROXY)),
            ),
        };
        if !self.http2 {
            b = b.http1_only();
        }
        let client = b
            .build()
            .map_err(|_| config_err("cannot build the HTTP client"))?;
        Ok(ReqwestTransport { client })
    }
}

/// The built-in transport: a reqwest client over a preconfigured rustls configuration (no
/// process-global provider is installed or required) that never follows redirects.
///
/// It must run inside a Tokio runtime; outside one [`send`](HttpTransport::send) sends nothing
/// and fails with [`SendError::NoRuntime`] instead of panicking. A runtime built without
/// `enable_all()` (no I/O or time driver) passes the check and still panics in reqwest.
///
/// reqwest copies a request body into its own buffer, which cannot be zeroized.
#[derive(Clone)]
pub struct ReqwestTransport {
    client: ::reqwest::Client,
}

impl fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestTransport").finish_non_exhaustive()
    }
}

impl ReqwestTransport {
    /// A builder with the defaults.
    pub fn builder() -> ReqwestTransportBuilder {
        ReqwestTransportBuilder::new()
    }

    /// The defaults ([`ReqwestTransportBuilder::new`]).
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    async fn send_inner(&self, req: Request, limit: usize) -> Result<Response, SendError> {
        let timeout = req.extensions().get::<RequestTimeout>().copied();
        let (parts, body) = req.into_parts();
        // The copy reqwest needs; it cannot be wiped.
        let req = http::Request::from_parts(parts, body.to_vec());
        let mut req = ::reqwest::Request::try_from(req).map_err(classify)?;
        if let Some(RequestTimeout(d)) = timeout {
            *req.timeout_mut() = Some(d);
        }
        let mut resp = self.client.execute(req).await.map_err(classify)?;
        let status = resp.status();
        let mut out = http::Response::new(Zeroizing::new(Vec::new()));
        *out.status_mut() = status;
        *out.version_mut() = resp.version();
        *out.headers_mut() = std::mem::take(resp.headers_mut());
        let mut buf = BodyBuffer::new(resp.content_length(), limit);
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => buf.push(&chunk, status)?,
                Ok(None) => break,
                Err(e) => return Err(classify(e)),
            }
        }
        *out.body_mut() = buf.finish();
        Ok(out)
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, req: Request, limit: usize) -> BoxFuture<'_, Result<Response, SendError>> {
        // Checked before the future exists, so nothing is built outside a runtime.
        if let Err(e) = self.ready() {
            return Box::pin(async move { Err(e) });
        }
        Box::pin(self.send_inner(req, limit))
    }

    /// `Err(NoRuntime)` outside a Tokio runtime, where reqwest would panic.
    fn ready(&self) -> Result<(), SendError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(SendError::NoRuntime);
        }
        Ok(())
    }
}

/// Classifies a reqwest failure, the URL stripped from it (it may carry a query string).
fn classify(e: ::reqwest::Error) -> SendError {
    if e.is_builder() {
        return SendError::InvalidRequest(strip(e));
    }
    if e.is_timeout() {
        return SendError::Timeout(strip(e));
    }
    if let Some(c) = connect_failure(&e) {
        return c(strip(e));
    }
    if e.is_connect() {
        return SendError::connect(ConnectFailure::Other, strip(e));
    }
    if e.is_body() || e.is_decode() {
        return SendError::Body(strip(e));
    }
    SendError::Other(strip(e))
}

fn strip(e: ::reqwest::Error) -> Source {
    Box::new(e.without_url())
}

type Classified = fn(Source) -> SendError;

/// Classifies a connection failure by walking the error's source chain (reqwest → hyper-util →
/// `io::Error` → `rustls::Error`). Certificate and handshake-policy failures are
/// [`SendError::TlsRejected`]: retrying cannot fix a CA, hostname or client-certificate mismatch.
/// DNS failures are named, so a mistyped host is easy to spot.
fn connect_failure(e: &(dyn std::error::Error + 'static)) -> Option<Classified> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(tls) = err.downcast_ref::<rustls::Error>() {
            return Some(tls_failure(tls));
        }
        // hyper-util's (private) connect error for resolver failures.
        if err.to_string() == "dns error" {
            return Some(SendError::Dns);
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    return Some(|s| SendError::connect(ConnectFailure::Refused, s));
                }
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                    return Some(|s| SendError::connect(ConnectFailure::Reset, s));
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

fn tls_failure(e: &rustls::Error) -> Classified {
    use rustls::{AlertDescription as A, CertificateError as C, Error as E};
    macro_rules! rejected {
        ($m:expr) => {
            |source| SendError::TlsRejected { reason: $m, source }
        };
    }
    match e {
        E::InvalidCertificate(c) => match c {
            C::UnknownIssuer => rejected!("TLS certificate rejected: unknown issuer"),
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                rejected!("TLS certificate rejected: name mismatch")
            }
            C::Expired | C::ExpiredContext { .. } => rejected!("TLS certificate rejected: expired"),
            C::NotValidYet | C::NotValidYetContext { .. } => {
                rejected!("TLS certificate rejected: not yet valid")
            }
            C::Revoked => rejected!("TLS certificate rejected: revoked"),
            C::BadSignature => rejected!("TLS certificate rejected: bad signature"),
            C::BadEncoding => rejected!("TLS certificate rejected: bad encoding"),
            _ => rejected!("TLS certificate rejected"),
        },
        E::NoCertificatesPresented => rejected!("TLS certificate rejected: none presented"),
        E::AlertReceived(
            A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::CertificateRequired
            | A::AccessDenied,
        ) => rejected!("TLS handshake rejected by the server (client certificate?)"),
        E::PeerIncompatible(_) => rejected!("TLS handshake failed: no common protocol or cipher"),
        _ => SendError::Tls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    /// Polls `fut` to completion on this thread, with no Tokio runtime.
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

    fn plain() -> ReqwestTransport {
        ReqwestTransport::builder()
            .require_roots(false)
            .build()
            .unwrap()
    }

    fn get(url: &str) -> Request {
        http::Request::get(url)
            .body(Zeroizing::new(Vec::new()))
            .unwrap()
    }

    /// R-35: outside a Tokio runtime `send` sends nothing and fails instead of panicking.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn outside_a_runtime_send_fails_instead_of_panicking() {
        let t = plain();
        let r = block_on(t.send(get("http://127.0.0.1:1/"), 1024));
        assert!(matches!(r, Err(SendError::NoRuntime)), "{r:?}");
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
        use anykms_core::ErrorKind;
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
            let dbg = format!("{err:?}");
            let c = connect_failure(&err).unwrap_or_else(|| panic!("{dbg}"));
            let e = c(Box::new(err));
            assert_eq!((e.kind(), e.message()), (kind, msg), "{dbg}");
        }
        let other = Wrap("x", Box::new(io::Error::other("y")));
        assert!(connect_failure(&other).is_none());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn builds_transports() {
        plain();
        ReqwestTransport::builder()
            .require_roots(false)
            .proxy(Some("http://127.0.0.1:3128".into()))
            .user_agent("x")
            .build()
            .unwrap();
        let e = ReqwestTransport::builder()
            .require_roots(false)
            .proxy(Some("::not a url".into()))
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        let e = ReqwestTransport::builder()
            .ca_pem(b"no certs".to_vec())
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(!crate::tls::is_missing_system_roots(&e));
    }

    /// Offering `h2` without the `http2` feature would advertise what reqwest cannot speak.
    #[cfg(all(
        not(feature = "http2"),
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn http2_needs_the_feature() {
        let e = ReqwestTransport::builder()
            .require_roots(false)
            .http2(true)
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(e.message().contains("`http2`"), "{e}");
    }

    #[test]
    fn builder_debug_prints_the_proxy_origin_only() {
        let o = ReqwestTransport::builder()
            .proxy(Some("http://alice:SECRET@proxy.example:3128/x".into()))
            .client_identity(b"cert".to_vec(), b"KEYMATERIAL".to_vec());
        let d = format!("{o:?}");
        assert!(d.contains("http://proxy.example:3128"), "{d}");
        assert!(!d.contains("SECRET") && !d.contains("alice"), "{d}");
        assert!(!d.contains("KEYMATERIAL"), "{d}");
    }

    /// Serves one canned HTTP/1.1 response per connection on a loopback port, `n` times.
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
        let t = plain();
        let url = serve(
            b"HTTP/1.1 503 Service Unavailable\r\nx-request-id: r1\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello"
                .to_vec(),
            2,
        );
        let r = t.send(get(&url), 5).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers().get("x-request-id").unwrap(), "r1");
        assert_eq!(&r.body()[..], b"hello");
        match t.send(get(&url), 4).await {
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
        match t.send(get(&closed), 4).await {
            Err(e @ SendError::Connect { .. }) => {
                assert!(!format!("{e:?}").contains("SECRET"));
            }
            other => panic!("{other:?}"),
        }
    }

    /// A `RequestTimeout` shorter than the server's delay times the request out; the transport's
    /// own 10 s timeout would not.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[tokio::test]
    async fn request_timeout_extension_is_honoured() {
        use std::io::Read as _;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b);
            std::thread::sleep(Duration::from_secs(2));
        });
        let t = plain();
        let mut req = get(&format!("http://{addr}/"));
        req.extensions_mut()
            .insert(RequestTimeout(Duration::from_millis(100)));
        let start = std::time::Instant::now();
        match t.send(req, 1024).await {
            Err(SendError::Timeout(_)) => {}
            other => panic!("{other:?}"),
        }
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
