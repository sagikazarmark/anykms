//! [`ReqwestTransport`] as a tower service (feature `tower`), for the bottom of a stack that a
//! [`TowerTransport`](crate::tower::TowerTransport) wraps.

use std::fmt;
use std::task::{Context, Poll};

use anykms_core::BoxFuture;
use http_body_util::BodyExt as _;

use super::{ReqwestTransport, classify};
use crate::tower::RequestBody;
use crate::transport::{HttpTransport as _, RequestTimeout, SendError};

/// The response body of [`ReqwestService`]: reqwest's, its errors classified as [`SendError`].
pub type ReqwestBody =
    http_body_util::combinators::MapErr<::reqwest::Body, fn(::reqwest::Error) -> SendError>;

/// [`ReqwestTransport`] as a tower service ([`ReqwestTransport::into_service`]), over
/// `http::Request<`[`RequestBody`]`>`.
///
/// Its errors are [`SendError`]s, already classified, which
/// [`TowerTransport`](crate::tower::TowerTransport) passes through, so a stack built on it
/// reports failures exactly as the transport alone does. A request's [`RequestTimeout`] is
/// honoured. Like the transport, it fails with [`SendError::NoRuntime`] outside a Tokio runtime
/// instead of panicking, from `call` (a stack has no `ready` of its own to ask first).
#[derive(Clone)]
pub struct ReqwestService {
    transport: ReqwestTransport,
}

impl fmt::Debug for ReqwestService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestService").finish_non_exhaustive()
    }
}

impl ReqwestTransport {
    /// This client as a tower service, for the bottom of a tower stack that a
    /// [`TowerTransport`](crate::tower::TowerTransport) then wraps: the hardened client (TLS,
    /// no redirects, timeouts, proxy rules) with the caller's layers on top.
    pub fn into_service(self) -> ReqwestService {
        ReqwestService { transport: self }
    }
}

impl tower_service::Service<http::Request<RequestBody>> for ReqwestService {
    type Response = http::Response<ReqwestBody>;
    type Error = SendError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<RequestBody>) -> Self::Future {
        if let Err(e) = self.transport.ready() {
            return Box::pin(async move { Err(e) });
        }
        let transport = self.transport.clone();
        let timeout = req.extensions().get::<RequestTimeout>().copied();
        let req = req.map(::reqwest::Body::wrap);
        Box::pin(async move {
            let resp: http::Response<::reqwest::Body> =
                transport.execute(req, timeout).await?.into();
            Ok(resp.map(|b| b.map_err(classify as fn(::reqwest::Error) -> SendError)))
        })
    }
}

#[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
mod tests {
    use std::time::Duration;

    use http::StatusCode;
    use zeroize::Zeroizing;

    use super::super::test_support::{closed_port, get, plain, serve, slow_server};
    use super::*;
    use crate::tower::TowerTransport;

    /// The built-in client at the bottom of a tower stack: the body and `content-length` reach
    /// the wire, the response is read within the limit, and the failures keep the transport's
    /// classes (a connection refused is `Connect`, not `Other`).
    #[tokio::test]
    async fn a_stack_over_the_client_behaves_like_the_transport() {
        let svc = ::tower::ServiceBuilder::new()
            .concurrency_limit(4)
            .service(plain().into_service());
        let t = TowerTransport::new(svc);
        let (url, rx) = serve(
            b"HTTP/1.1 503 Service Unavailable\r\nx-request-id: r1\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello"
                .to_vec(),
            2,
        );
        let req = http::Request::post(&url)
            .body(Zeroizing::new(b"{\"k\":1}".to_vec()))
            .unwrap();
        let r = t.send(req, 5).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers().get("x-request-id").unwrap(), "r1");
        assert_eq!(&r.body()[..], b"hello");
        let seen = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(
            seen.to_ascii_lowercase().contains("content-length: 7\r\n"),
            "{seen}"
        );
        assert!(seen.ends_with("{\"k\":1}"), "{seen}");

        match t.send(get(&url), 4).await {
            Err(SendError::TooLarge { status }) => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            }
            other => panic!("{other:?}"),
        }
        let seen = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(
            !seen.to_ascii_lowercase().contains("content-length"),
            "{seen}"
        );

        match t.send(get(&closed_port()), 4).await {
            Err(e @ SendError::Connect { .. }) => {
                assert!(!format!("{e:?}").contains("SECRET"));
            }
            other => panic!("{other:?}"),
        }
    }

    /// A `RequestTimeout` reaches the client through the stack.
    #[tokio::test]
    async fn request_timeout_extension_is_honoured_through_the_stack() {
        let t = TowerTransport::new(plain().into_service());
        let mut req = get(&slow_server(Duration::from_secs(2)));
        req.extensions_mut()
            .insert(RequestTimeout(Duration::from_millis(100)));
        let start = std::time::Instant::now();
        match t.send(req, 1024).await {
            Err(SendError::Timeout(_)) => {}
            other => panic!("{other:?}"),
        }
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// Outside a Tokio runtime the service fails from `call`, as the transport does from `send`.
    #[test]
    fn outside_a_runtime_call_fails_instead_of_panicking() {
        use tower_service::Service as _;
        let mut svc = plain().into_service();
        let req = http::Request::get("http://127.0.0.1:1/")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        let r = super::super::test_support::block_on(svc.call(req));
        assert!(matches!(r, Err(SendError::NoRuntime)), "{r:?}");
    }
}
