//! Sending a request through an [`HttpTransport`] and reading its response; `Retry-After`.

use std::time::{Duration, SystemTime};

use http::header::HeaderMap;
use http::{Method, StatusCode};
use url::Url;
use zeroize::Zeroizing;

use crate::transport::{HttpTransport, Request, SendError};

pub use crate::transport::INITIAL_RESPONSE_CAPACITY;

/// The smallest `max_response_bytes` a backend accepts (64 KiB): smaller limits break describe
/// and token responses with confusing `Backend` errors.
pub const MIN_RESPONSE_BYTES: usize = 64 * 1024;

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

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// A request builder for `method` on `url`: the start of every backend request. Finish it with
/// [`body`](http::request::Builder::body) and pass the result to [`send`].
pub fn request(method: Method, url: &Url) -> http::request::Builder {
    http::Request::builder().method(method).uri(url.as_str())
}

/// An empty request body.
pub fn empty() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::new())
}

/// Sends `req` through `transport` and reads the whole response (any status) into a [`Response`]
/// whose body is at most `limit` bytes. A request that could not be built (the `Err` of
/// [`Builder::body`](http::request::Builder::body)) is [`SendError::InvalidRequest`]. The body
/// length is checked again here, so a transport that ignores `limit` still cannot deliver an
/// oversized body ([`SendError::TooLarge`]).
///
/// Records `http_status` into the current span (the request span,
/// [`request_span!`](crate::request_span)) for every response, success included; a second
/// attempt (the refresh-once retry) overwrites it.
pub async fn send(
    transport: &(impl HttpTransport + ?Sized),
    req: http::Result<Request>,
    limit: usize,
) -> Result<Response, SendError> {
    let req = req.map_err(|e| SendError::InvalidRequest(Box::new(e)))?;
    let resp = transport.send(req, limit).await?;
    let status = resp.status();
    #[cfg(feature = "tracing")]
    tracing::Span::current().record("http_status", status.as_u16());
    if resp.body().len() > limit {
        // Defence in depth against a transport that ignored the limit; the body is wiped here.
        return Err(SendError::TooLarge { status });
    }
    let (parts, body) = resp.into_parts();
    Ok(Response {
        status,
        headers: parts.headers,
        body,
    })
}

/// The `Retry-After` header as a delay: delay-seconds or an HTTP-date (RFC 9110 §10.2.3), a date
/// in the past being a zero delay. `None` when absent or malformed.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let v = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    retry_after_value(v, anykms_core::time::system_now())
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
    use anykms_core::BoxFuture;

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
        h.insert(http::header::RETRY_AFTER, "3".parse().unwrap());
        assert_eq!(retry_after(&h), Some(Duration::from_secs(3)));
    }

    /// A transport that returns a fixed body whatever the limit.
    struct Ignores(Vec<u8>);
    impl HttpTransport for Ignores {
        fn send(
            &self,
            _req: Request,
            _limit: usize,
        ) -> BoxFuture<'_, Result<crate::transport::Response, SendError>> {
            let body = self.0.clone();
            Box::pin(async move {
                let mut r = http::Response::new(Zeroizing::new(body));
                *r.status_mut() = StatusCode::IM_A_TEAPOT;
                Ok(r)
            })
        }
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected_even_when_the_transport_ignores_the_limit() {
        let t = Ignores(b"hello".to_vec());
        let url: Url = "http://127.0.0.1:1/".parse().unwrap();
        let r = send(&t, request(Method::GET, &url).body(empty()), 5)
            .await
            .unwrap();
        assert_eq!(r.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(&r.body[..], b"hello");
        match send(&t, request(Method::GET, &url).body(empty()), 4).await {
            Err(SendError::TooLarge { status }) => assert_eq!(status, StatusCode::IM_A_TEAPOT),
            other => panic!("{other:?}"),
        }
        // Also through an Arc<dyn HttpTransport>.
        let t: std::sync::Arc<dyn HttpTransport> = std::sync::Arc::new(t);
        assert!(
            send(&t, request(Method::GET, &url).body(empty()), 4)
                .await
                .is_err()
        );
        // An unbuildable request.
        let bad = http::Request::builder().uri("not a uri").body(empty());
        match send(&t, bad, 4).await {
            Err(SendError::InvalidRequest(_)) => {}
            other => panic!("{other:?}"),
        }
    }
}
