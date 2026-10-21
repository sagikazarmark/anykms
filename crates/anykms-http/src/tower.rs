//! [`TowerTransport`]: any tower [`Service`] as an [`HttpTransport`] (feature `tower`).
//!
//! Two uses. A service that already has a tower stack (concurrency limits, rate limits, its own
//! instrumentation) puts the built-in client at the bottom of it:
//!
//! ```rust,ignore
//! let svc = ServiceBuilder::new()
//!     .concurrency_limit(4)
//!     .service(ReqwestTransport::new()?.into_service());
//! let transport = TowerTransport::new(svc);
//! ```
//!
//! And a host without reqwest's TLS stack, such as Cloudflare Workers, brings a `fetch`-based
//! service (`tower-worker-fetch`'s `FetchService`): anykms ships no Workers transport of its
//! own and depends on no Workers crate.
//!
//! The adapter only moves bytes. It clones the service for each request, sets `content-length`,
//! and reads the response body frame by frame into a [`BodyBuffer`], so nothing past the limit
//! is buffered and what was read is wiped on overflow. It has **no timeout of its own**
//! (`tower::timeout` needs a Tokio runtime and panics inside a Worker): a native stack adds its
//! own layer, a Worker a `map_request` layer that inserts a `fetch` timeout. It **cannot control
//! redirects**: the inner service must be configured not to follow them; a 3xx that reaches the
//! adapter is returned as is, and the backends treat it as an error.

use std::fmt;
use std::future::poll_fn;
use std::pin::pin;

use anykms_core::BoxFuture;
use bytes::Bytes;
use http::Method;
use http::header::{CONTENT_LENGTH, HeaderValue};
use http_body_util::Full;
use tower_service::Service;

use crate::transport::{BodyBuffer, HttpTransport, Request, Response, SendError, Source};

/// The request body a service behind [`TowerTransport`] receives: the whole body, cloneable (a
/// retry layer can replay it), and an [`http_body::Body`] (most tower HTTP services, and
/// `tower-worker-fetch`, require one; `Bytes` alone is not).
pub type RequestBody = Full<Bytes>;

/// A tower [`Service`] as an [`HttpTransport`].
///
/// `S` takes `http::Request<`[`RequestBody`]`>` and returns `http::Response<B>` for any
/// [`http_body::Body`] whose data is `Bytes`; its error is anything boxable. A service that
/// returns a boxed [`SendError`] (a `map_err` layer can produce one, and
/// [`ReqwestService`](crate::reqwest::ReqwestService) does) has it passed through unchanged, so
/// the backends classify it; any other error is [`SendError::Other`] (a body read failure
/// [`SendError::Body`]). The request's extensions, including its
/// [`RequestTimeout`](crate::transport::RequestTimeout), reach the service unchanged: a service
/// that can honour them may.
///
/// The service, its future and the response body must be `Send` (see the trait's note): a
/// `fetch`-based service wraps its JS futures on its own side, as `tower-worker-fetch` does.
///
/// The request body is copied into a `Bytes` for the service and cannot be wiped afterwards (the
/// same best-effort note as the built-in transport).
#[derive(Clone)]
pub struct TowerTransport<S> {
    service: S,
}

impl<S> fmt::Debug for TowerTransport<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TowerTransport").finish_non_exhaustive()
    }
}

impl<S> TowerTransport<S> {
    /// Wraps `service`.
    pub fn new(service: S) -> Self {
        Self { service }
    }

    /// The service.
    pub fn get_ref(&self) -> &S {
        &self.service
    }

    /// Unwraps the service.
    pub fn into_inner(self) -> S {
        self.service
    }
}

impl<S, B> HttpTransport for TowerTransport<S>
where
    S: Service<http::Request<RequestBody>, Response = http::Response<B>>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
    S::Error: Into<Source>,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Source>,
{
    fn send(&self, req: Request, limit: usize) -> BoxFuture<'_, Result<Response, SendError>> {
        let service = self.service.clone();
        Box::pin(send(service, req, limit))
    }
}

/// Builds the request, drives the service once (ready, then call) and reads the response.
async fn send<S, B>(mut service: S, req: Request, limit: usize) -> Result<Response, SendError>
where
    S: Service<http::Request<RequestBody>, Response = http::Response<B>>,
    S::Error: Into<Source>,
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<Source>,
{
    let (mut parts, body) = req.into_parts();
    // The copy the service needs; it cannot be wiped.
    let body = Bytes::copy_from_slice(&body);
    // The adapter owns `content-length`: a stale value is replaced, or removed.
    match body_len_header(&parts.method, body.len()) {
        Some(v) => parts.headers.insert(CONTENT_LENGTH, v),
        None => parts.headers.remove(CONTENT_LENGTH),
    };
    let req = http::Request::from_parts(parts, Full::new(body));

    poll_fn(|cx| service.poll_ready(cx))
        .await
        .map_err(|e| classify(e, SendError::Other))?;
    let resp = service
        .call(req)
        .await
        .map_err(|e| classify(e, SendError::Other))?;

    let (parts, body) = resp.into_parts();
    let status = parts.status;
    // The header, not `size_hint()`: a `fetch` body reports no size.
    let content_length = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    if content_length.is_some_and(|n| n > u64::try_from(limit).unwrap_or(u64::MAX)) {
        return Err(SendError::TooLarge { status });
    }
    let mut buf = BodyBuffer::new(content_length, limit);
    let mut body = pin!(body);
    while let Some(frame) = poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        let frame = frame.map_err(|e| classify(e, SendError::Body))?;
        // Trailers carry nothing a backend reads.
        if let Ok(data) = frame.into_data() {
            buf.push(&data, status)?;
        }
    }
    Ok(http::Response::from_parts(parts, buf.finish()))
}

/// The `content-length` to set: always for a body with content, and for the methods that carry
/// one even when it is empty (so an endpoint that rejects a POST without a length gets `0`),
/// never for an empty GET-like request (RFC 9110 §8.6 advises against it). A `fetch`-based
/// service streams every body without a length otherwise, and some endpoints reject chunked
/// requests.
fn body_len_header(method: &Method, len: usize) -> Option<HeaderValue> {
    let get_like = matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::CONNECT
    );
    (len > 0 || !get_like).then(|| HeaderValue::from(len))
}

/// A boxed [`SendError`] passes through; anything else is `other`.
fn classify(e: impl Into<Source>, other: fn(Source) -> SendError) -> SendError {
    match e.into().downcast::<SendError>() {
        Ok(e) => *e,
        Err(e) => other(e),
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use http::StatusCode;
    use http_body::Frame;
    use zeroize::Zeroizing;

    use super::*;
    use crate::transport::RequestTimeout;

    /// A body of `n` frames of `chunk`, counting the frames handed out.
    struct Chunks {
        chunk: Bytes,
        left: usize,
        polled: Arc<Mutex<usize>>,
    }

    impl http_body::Body for Chunks {
        type Data = Bytes;
        type Error = Source;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Source>>> {
            if self.left == 0 {
                return Poll::Ready(None);
            }
            self.left -= 1;
            *self.polled.lock().unwrap() += 1;
            Poll::Ready(Some(Ok(Frame::data(self.chunk.clone()))))
        }
    }

    /// What a scripted service replies with.
    struct Reply {
        status: StatusCode,
        chunk: Vec<u8>,
        n: usize,
        headers: Vec<(&'static str, &'static str)>,
        fail: Option<Source>,
    }

    fn whole(status: StatusCode, body: &[u8]) -> Reply {
        Reply {
            status,
            chunk: body.to_vec(),
            n: usize::from(!body.is_empty()),
            headers: vec![],
            fail: None,
        }
    }

    fn chunks(status: StatusCode, chunk: &[u8], n: usize) -> Reply {
        Reply {
            status,
            chunk: chunk.to_vec(),
            n,
            headers: vec![],
            fail: None,
        }
    }

    fn fail(e: Source) -> Reply {
        Reply {
            status: StatusCode::OK,
            chunk: vec![],
            n: 0,
            headers: vec![],
            fail: Some(e),
        }
    }

    impl Reply {
        fn header(mut self, k: &'static str, v: &'static str) -> Self {
            self.headers.push((k, v));
            self
        }
    }

    #[derive(Clone)]
    struct Scripted {
        reply: Arc<Mutex<Option<Reply>>>,
        seen: Arc<Mutex<Vec<http::Request<RequestBody>>>>,
        /// Frames handed out so far.
        polled: Arc<Mutex<usize>>,
    }

    impl Scripted {
        fn new(reply: Reply) -> Self {
            Self {
                reply: Arc::new(Mutex::new(Some(reply))),
                seen: Arc::new(Mutex::new(Vec::new())),
                polled: Arc::new(Mutex::new(0)),
            }
        }

        fn seen(&self) -> Vec<http::Request<RequestBody>> {
            std::mem::take(&mut *self.seen.lock().unwrap())
        }

        fn polled(&self) -> usize {
            *self.polled.lock().unwrap()
        }
    }

    impl Service<http::Request<RequestBody>> for Scripted {
        type Response = http::Response<Chunks>;
        type Error = Source;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<RequestBody>) -> Self::Future {
            self.seen.lock().unwrap().push(req);
            let reply = self.reply.lock().unwrap().take().expect("one call");
            if let Some(e) = reply.fail {
                return std::future::ready(Err(e));
            }
            let mut r = http::Response::new(Chunks {
                chunk: Bytes::from(reply.chunk),
                left: reply.n,
                polled: self.polled.clone(),
            });
            *r.status_mut() = reply.status;
            for (k, v) in reply.headers {
                r.headers_mut().insert(k, HeaderValue::from_static(v));
            }
            std::future::ready(Ok(r))
        }
    }

    fn post(body: &[u8]) -> Request {
        http::Request::post("https://kms.example/op")
            .body(Zeroizing::new(body.to_vec()))
            .unwrap()
    }

    #[tokio::test]
    async fn reads_any_status_within_the_limit_and_sets_content_length() {
        let svc = Scripted::new(whole(StatusCode::SERVICE_UNAVAILABLE, b"hello"));
        let t = TowerTransport::new(svc.clone());
        let mut req = post(b"{\"k\":1}");
        req.extensions_mut()
            .insert(RequestTimeout(std::time::Duration::from_secs(1)));
        let r = t.send(req, 5).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(&r.body()[..], b"hello");

        let seen = svc.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].headers().get(CONTENT_LENGTH).unwrap(), "7");
        // Extensions reach the service.
        assert_eq!(
            seen[0].extensions().get::<RequestTimeout>(),
            Some(&RequestTimeout(std::time::Duration::from_secs(1)))
        );
    }

    #[tokio::test]
    async fn content_length_follows_the_method_for_empty_bodies() {
        for (method, expect) in [
            (Method::GET, None),
            (Method::HEAD, None),
            (Method::POST, Some("0")),
            (Method::PUT, Some("0")),
            (Method::DELETE, Some("0")),
        ] {
            let svc = Scripted::new(whole(StatusCode::OK, b""));
            let t = TowerTransport::new(svc.clone());
            let req = http::Request::builder()
                .method(method.clone())
                .uri("https://kms.example/")
                // A stale value is replaced.
                .header(CONTENT_LENGTH, "99")
                .body(Zeroizing::new(Vec::new()))
                .unwrap();
            t.send(req, 16).await.unwrap();
            let seen = svc.seen();
            let got = seen[0]
                .headers()
                .get(CONTENT_LENGTH)
                .map(|v| v.to_str().unwrap().to_owned());
            // A stale value is replaced (or, on a GET, removed).
            assert_eq!(got.as_deref(), expect, "{method}");
        }
    }

    /// The limit stops the read: no more frames are pulled once it is exceeded, and a
    /// `content-length` beyond it fails before any frame is read.
    #[tokio::test]
    async fn oversized_bodies_stop_at_the_limit() {
        let svc = Scripted::new(chunks(StatusCode::OK, b"xxxx", 100));
        let t = TowerTransport::new(svc.clone());
        match t.send(post(b""), 10).await {
            Err(SendError::TooLarge { status }) => assert_eq!(status, StatusCode::OK),
            other => panic!("{other:?}"),
        }
        // 4 + 4 fit, the third frame overflows; nothing after it was pulled.
        assert_eq!(svc.polled(), 3);

        let svc = Scripted::new(
            chunks(StatusCode::BAD_GATEWAY, b"xxxx", 100).header("content-length", "400"),
        );
        let t = TowerTransport::new(svc.clone());
        match t.send(post(b""), 10).await {
            Err(SendError::TooLarge { status }) => assert_eq!(status, StatusCode::BAD_GATEWAY),
            other => panic!("{other:?}"),
        }
        assert_eq!(svc.polled(), 0);

        // Exactly the limit is fine.
        let svc = Scripted::new(chunks(StatusCode::OK, b"xxxxx", 2).header("content-length", "10"));
        let r = TowerTransport::new(svc).send(post(b""), 10).await.unwrap();
        assert_eq!(r.body().len(), 10);
    }

    /// A redirect is not followed: the 3xx comes back as is, `location` intact, for the backend
    /// to reject.
    #[tokio::test]
    async fn redirects_are_returned_unchanged() {
        let svc = Scripted::new(
            whole(StatusCode::FOUND, b"").header("location", "https://evil.example/"),
        );
        let r = TowerTransport::new(svc).send(post(b"x"), 16).await.unwrap();
        assert!(r.status().is_redirection());
        assert_eq!(
            r.headers().get("location").unwrap(),
            "https://evil.example/"
        );
        // What `client::send` hands a backend, which treats any non-2xx as a failure.
        let resp = crate::client::send(
            &TowerTransport::new(Scripted::new(whole(StatusCode::FOUND, b""))),
            Ok(post(b"x")),
            16,
        )
        .await
        .unwrap();
        assert_eq!(resp.status, StatusCode::FOUND);
    }

    /// A boxed `SendError` from the service keeps its class; anything else is `Other`.
    #[tokio::test]
    async fn service_errors_are_classified() {
        let svc = Scripted::new(fail(Box::new(SendError::Timeout("slow".into()))));
        match TowerTransport::new(svc).send(post(b""), 16).await {
            Err(SendError::Timeout(_)) => {}
            other => panic!("{other:?}"),
        }
        let svc = Scripted::new(fail("boom".into()));
        match TowerTransport::new(svc).send(post(b""), 16).await {
            Err(e @ SendError::Other(_)) => {
                assert_eq!(e.kind(), anykms_core::ErrorKind::Unavailable);
                assert_eq!(std::error::Error::source(&e).unwrap().to_string(), "boom");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A `map_err` layer is how a stack classifies its own failures (`tower::timeout` here).
    #[tokio::test(start_paused = true)]
    async fn a_tower_stack_classifies_through_map_err() {
        use ::tower::ServiceBuilder;

        let slow = ::tower::service_fn(|_req: http::Request<RequestBody>| async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            Ok::<http::Response<Full<Bytes>>, Source>(http::Response::new(Full::new(Bytes::new())))
        });
        let svc = ServiceBuilder::new()
            .map_err(|e: Source| -> Source {
                if e.is::<::tower::timeout::error::Elapsed>() {
                    Box::new(SendError::Timeout(e))
                } else {
                    e
                }
            })
            .concurrency_limit(1)
            .timeout(std::time::Duration::from_millis(50))
            .service(slow);
        let t = TowerTransport::new(svc);
        match t.send(post(b""), 16).await {
            Err(SendError::Timeout(_)) => {}
            other => panic!("{other:?}"),
        }
        // The clone per call released the one permit.
        match t.send(post(b""), 16).await {
            Err(SendError::Timeout(_)) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn is_send_and_sync() {
        fn assert<T: Send + Sync>() {}
        assert::<TowerTransport<Scripted>>();
    }
}
