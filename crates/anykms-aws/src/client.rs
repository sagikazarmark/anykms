//! The AWS JSON 1.1 client: signed `POST /` requests with `X-Amz-Target: TrentService.<Op>`.
//!
//! No retries (those belong to `anykms_core::Retry`) except one: when AWS rejects the
//! credentials as expired or unknown, they are refetched and the request is sent once more if
//! the new credentials differ. A clock-skew rejection records the server's clock offset (used to
//! sign every later request) and is reported as retryable `Unavailable`.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

use anykms_core::{Error, ErrorKind, Operation, Result};
use anykms_http::credentials::{Credential, CredentialCache, Expiring};
use anykms_http::http::header::{AUTHORIZATION, CONTENT_TYPE, DATE, HeaderMap, HeaderValue};
use anykms_http::http::{Method, StatusCode};
use anykms_http::transport::Request;
use anykms_http::url::Url;
use anykms_http::{HttpTransport, RequestTimeout, SendError};
use zeroize::Zeroizing;

use crate::BACKEND;
use crate::credentials::{CredentialSource, Credentials, SourceContext};
use crate::errors::{Failure, classify, parse_error, request_id};

/// The HTTP side shared by the KMS client and the credential sources: one injected transport
/// (TLS, proxy, timeouts and the HTTP version are its business), the response limit, and
/// whether loopback `http://` endpoints are allowed (emulators, tests).
pub(crate) struct Http {
    transport: Arc<dyn HttpTransport>,
    pub(crate) max_response_bytes: usize,
    pub(crate) loopback_allowed: bool,
}

impl Http {
    pub(crate) fn new(
        transport: Arc<dyn HttpTransport>,
        max_response_bytes: usize,
        loopback_http: bool,
    ) -> Self {
        Self {
            transport,
            max_response_bytes,
            loopback_allowed: loopback_http,
        }
    }

    /// Sends `req` and reads the whole response (at most `limit` bytes). `send` records
    /// `http_status` into the request span. A body over the limit is an unusable response;
    /// every other failure is classified by [`SendError::into_error`].
    pub(crate) async fn send(
        &self,
        req: anykms_http::http::Result<Request>,
        limit: usize,
        op: Operation,
    ) -> Result<anykms_http::client::Response> {
        anykms_http::client::send(&*self.transport, req, limit)
            .await
            .map_err(|e| match e {
                SendError::TooLarge { status } => crate::errors::unusable_response(
                    op,
                    Some(status.as_u16()),
                    "response exceeds the maximum size",
                ),
                e => e.into_error(BACKEND, op),
            })
    }

    /// [`HttpTransport::ready`], as this backend's error.
    pub(crate) fn ready(&self, op: Operation) -> Result<()> {
        self.transport
            .ready()
            .map_err(|e| e.into_error(BACKEND, op))
    }

    /// A request to a link-local credential endpoint (IMDS, the container endpoint): it fails
    /// fast ([`LOCAL_TIMEOUT`](crate::credentials::LOCAL_TIMEOUT) × 2, as a per-request
    /// [`RequestTimeout`]) so an absent endpoint does not stall the credential chain.
    pub(crate) fn local(method: Method, url: &Url) -> anykms_http::http::request::Builder {
        anykms_http::client::request(method, url)
            .extension(RequestTimeout(crate::credentials::LOCAL_TIMEOUT * 2))
    }
}

/// Cached credentials from one source.
pub(crate) struct CredsCache {
    pub(crate) source: Arc<dyn CredentialSource>,
    cache: CredentialCache<Credentials>,
}

impl CredsCache {
    pub(crate) fn new(source: Arc<dyn CredentialSource>) -> Self {
        Self {
            source,
            cache: CredentialCache::new(),
        }
    }

    pub(crate) async fn get(&self, cx: &SourceContext) -> Result<Credential<Credentials>> {
        self.cache
            .get(|| async {
                let fetch = async {
                    let c = self.source.credentials(cx).await?;
                    c.validate()?;
                    Ok::<_, Error>(c)
                };
                // The token span shared by the HTTP backends.
                let credential = self.source.kind();
                let span = anykms_http::token_span!(
                    "anykms.aws.token",
                    backend = BACKEND,
                    credential = credential,
                );
                let started = anykms_core::time::Instant::now();
                let r = anykms_http::span::instrument(fetch, &span).await;
                let expires_in = r.as_ref().ok().and_then(|c| {
                    c.expires_at()
                        .and_then(|t| t.duration_since(anykms_core::time::system_now()).ok())
                });
                anykms_http::span::finish_token(&span, started, expires_in, &r);
                // P1-8: a refresh is routine; a failure needs an operator. A token file that
                // failed is named in the error's message.
                #[cfg(feature = "tracing")]
                match &r {
                    Ok(_) => tracing::debug!(
                        parent: &span,
                        backend = BACKEND,
                        credential,
                        "AWS credentials obtained"
                    ),
                    Err(e) => tracing::warn!(
                        parent: &span,
                        backend = BACKEND,
                        credential,
                        error_kind = e.kind().as_str(),
                        error = %e,
                        "AWS credentials could not be obtained"
                    ),
                }
                let c = r?;
                Ok(match c.expires_at() {
                    Some(t) => Expiring::valid_until(c, t),
                    None => Expiring::never_expires(c),
                })
            })
            .await
    }

    pub(crate) fn invalidate(&self, c: &Credential<Credentials>) {
        self.cache.invalidate(c);
    }
}

/// The KMS client of one provider: credentials, HTTP clients, the clock offset.
pub(crate) struct Kms {
    pub(crate) http: Arc<Http>,
    pub(crate) creds: CredsCache,
    /// Server clock minus local clock, in milliseconds, recorded from skew rejections.
    skew_ms: AtomicI64,
    /// Counts KMS requests (test fixtures).
    pub(crate) requests: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// One KMS request.
pub(crate) struct Call<'a> {
    pub(crate) endpoint: &'a Url,
    pub(crate) region: &'a str,
    /// The operation name (`Encrypt`, `Sign`, ...).
    pub(crate) target: &'static str,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) op: Operation,
    /// The key URI (`aws-kms://arn:...`, never a query), for the span's `resource`.
    pub(crate) resource: Option<&'a str>,
    /// The key version the request uses (the resolved key ARN of signing, MAC and public-key
    /// requests), for the span's `key_version`.
    pub(crate) key_version: Option<&'a str>,
}

impl Kms {
    pub(crate) fn new(http: Arc<Http>, source: Arc<dyn CredentialSource>) -> Self {
        Self {
            http,
            creds: CredsCache::new(source),
            skew_ms: AtomicI64::new(0),
            requests: None,
        }
    }

    pub(crate) fn source_context(&self) -> SourceContext {
        SourceContext {
            http: self.http.clone(),
        }
    }

    /// The signing time: the local clock corrected by the recorded skew.
    fn now(&self) -> SystemTime {
        let skew = self.skew_ms.load(Ordering::Relaxed);
        let now = anykms_core::time::system_now();
        let d = Duration::from_millis(skew.unsigned_abs());
        if skew >= 0 {
            now.checked_add(d).unwrap_or(now)
        } else {
            now.checked_sub(d).unwrap_or(now)
        }
    }

    /// Records the server's clock from a `Date` header.
    fn record_skew(&self, headers: &HeaderMap) {
        let Some(server) = headers
            .get(DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok())
        else {
            return;
        };
        let now = anykms_core::time::system_now();
        let ms = match server.duration_since(now) {
            Ok(ahead) => i64::try_from(ahead.as_millis()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
        };
        self.skew_ms.store(ms, Ordering::Relaxed);
        #[cfg(feature = "tracing")]
        tracing::warn!(
            backend = BACKEND,
            clock_offset_ms = ms,
            "AWS rejected the request time; recorded the server clock offset"
        );
    }

    /// Shifts the signing clock by `ms` (the A0 probe's clock-skew case).
    #[cfg(feature = "__test-fixtures")]
    pub(crate) fn set_clock_offset(&self, ms: i64) {
        self.skew_ms.store(ms, Ordering::Relaxed);
    }

    /// One signed request with the current credentials, returning the raw response (the A0
    /// probe records error bodies and headers).
    #[cfg(feature = "__test-fixtures")]
    pub(crate) async fn raw(
        &self,
        call: &Call<'_>,
    ) -> Result<(StatusCode, HeaderMap, Zeroizing<Vec<u8>>)> {
        let cred = self.creds.get(&self.source_context()).await?;
        self.send(call, cred.value()).await
    }

    async fn send(
        &self,
        call: &Call<'_>,
        creds: &Credentials,
    ) -> Result<(StatusCode, HeaderMap, Zeroizing<Vec<u8>>)> {
        if let Some(n) = &self.requests {
            n.fetch_add(1, Ordering::SeqCst);
        }
        let host = host_header(call.endpoint);
        let target = format!("TrentService.{}", call.target);
        let time = self.now();
        let date = crate::sigv4::amz_date(time);
        let mut headers: Vec<(&str, &str)> = vec![
            ("content-type", "application/x-amz-json-1.1"),
            ("host", &host),
            ("x-amz-date", &date),
            ("x-amz-target", &target),
        ];
        if let Some(t) = creds.session_token() {
            headers.push(("x-amz-security-token", t));
        }
        let path = call.endpoint.path();
        let signed = crate::sigv4::sign(
            creds.access_key_id(),
            creds.secret_access_key(),
            &crate::sigv4::Request {
                method: "POST",
                path,
                query: &[],
                headers: &headers,
                payload: &call.body,
            },
            &crate::sigv4::Scope {
                region: call.region,
                service: "kms",
                time,
            },
        );
        let bad_header = || {
            Error::new(
                ErrorKind::Configuration,
                BACKEND,
                call.op,
                "AWS credentials contain characters not allowed in HTTP headers",
            )
        };
        let mut auth = HeaderValue::from_str(&signed.authorization).map_err(|_| bad_header())?;
        auth.set_sensitive(true);
        let mut req = anykms_http::client::request(Method::POST, call.endpoint)
            .header(CONTENT_TYPE, "application/x-amz-json-1.1")
            .header("x-amz-date", &signed.amz_date)
            .header("x-amz-target", &target)
            .header(AUTHORIZATION, auth);
        if let Some(t) = creds.session_token() {
            let mut v = HeaderValue::from_str(t).map_err(|_| bad_header())?;
            v.set_sensitive(true);
            req = req.header("x-amz-security-token", v);
        }
        // The body stays in a zeroizing buffer up to the transport (which may copy it; see the
        // crate docs on zeroization limits). `send` records `http_status` into the request span.
        let resp = self
            .http
            .send(
                req.body(call.body.clone()),
                self.http.max_response_bytes,
                call.op,
            )
            .await?;
        Ok((resp.status, resp.headers, resp.body))
    }

    /// Performs a call; returns the success body. Every non-success response is classified.
    pub(crate) async fn call(&self, call: Call<'_>) -> Result<Zeroizing<Vec<u8>>> {
        // The span schema shared by the HTTP backends (docs/cloud/shared.md §5).
        let span = anykms_http::request_span!(
            "anykms.aws",
            backend = BACKEND,
            op = call.op.as_str(),
            resource = call.resource,
            key_version = call.key_version,
        );
        let guard = anykms_http::span::start_request(&span);
        let r = anykms_http::span::instrument(self.call_inner(&call), &span).await;
        let (r, request_id) = match r {
            Ok((body, id)) => (Ok(body), id),
            Err(e) => (Err(e), None),
        };
        guard.finish(request_id.as_deref(), &r);
        r
    }

    /// The success body and its request id, or the classified failure.
    async fn call_inner(&self, call: &Call<'_>) -> Result<(Zeroizing<Vec<u8>>, Option<String>)> {
        // First: a transport that cannot send from this context (reqwest outside a Tokio
        // runtime) fails here, before the credential chain runs.
        self.http.ready(call.op)?;
        let cx = self.source_context();
        let cred = self
            .creds
            .get(&cx)
            .await
            .map_err(|e| e.with_operation(call.op))?;
        anykms_http::span::record_attempt(1);
        let (mut status, mut headers, mut body) = self.send(call, cred.value()).await?;
        if !status.is_success() {
            let (code, _) = parse_error(&headers, &body);
            if code
                .as_deref()
                .is_some_and(|c| crate::errors::REFRESH_CODES.contains(&c))
            {
                self.creds.invalidate(&cred);
                // If the source cannot produce credentials now, report the original rejection.
                if let Ok(fresh) = self.creds.get(&cx).await
                    && fresh.generation() != cred.generation()
                    && !fresh.value().same_as(cred.value())
                {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        backend = BACKEND,
                        reason = "credentials refreshed after rejection",
                        "retrying once"
                    );
                    anykms_http::span::record_attempt(2);
                    (status, headers, body) = self.send(call, fresh.value()).await?;
                }
            }
        }
        if status.is_success() {
            return Ok((body, request_id(&headers)));
        }
        let (code, message) = parse_error(&headers, &body);
        drop(body);
        if crate::errors::is_skew(code.as_deref(), message.as_deref()) {
            self.record_skew(&headers);
        }
        Err(classify(Failure {
            status: status.as_u16(),
            code: code.as_deref(),
            message: message.as_deref(),
            request_id: request_id(&headers),
            retry_after: anykms_http::client::retry_after(&headers),
            op: call.op,
        }))
    }
}

/// The `Host` header the transport sends for `url` (port only when not the scheme's default).
pub(crate) fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a provider feature (and no process default in this test binary), building fails
    /// and says how to fix it (P1-12: the data-plane client is built by `build()`).
    #[cfg(all(
        feature = "reqwest",
        not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))
    ))]
    #[test]
    fn no_crypto_provider_fails_at_build() {
        let e = crate::AwsProvider::builder()
            .credentials(crate::credentials::StaticCredentials::new(
                Credentials::new("a", "s", None),
            ))
            .build()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Configuration);
        assert!(e.to_string().contains("rustls-aws-lc-rs"), "{e}");
    }

    #[test]
    fn host_headers() {
        let u: Url = "https://kms.eu-west-1.amazonaws.com/".parse().unwrap();
        assert_eq!(host_header(&u), "kms.eu-west-1.amazonaws.com");
        let u: Url = "http://127.0.0.1:4566/".parse().unwrap();
        assert_eq!(host_header(&u), "127.0.0.1:4566");
        let u: Url = "https://kms.eu-west-1.amazonaws.com:443/".parse().unwrap();
        assert_eq!(host_header(&u), "kms.eu-west-1.amazonaws.com");
        let u: Url = "http://[::1]:8080/".parse().unwrap();
        assert_eq!(host_header(&u), "[::1]:8080");
    }
}
