//! The span schema every HTTP backend shares (`docs/cloud/shared.md` §5, PLAN D3).
//!
//! - One **request span** per operation call, named `anykms.<backend>`, built by
//!   [`request_span!`](crate::request_span) with exactly the fields of [`REQUEST_FIELDS`].
//! - One **token span** per credential fetch, named `anykms.<backend>.token`, built by
//!   [`token_span!`](crate::token_span) with exactly the fields of [`TOKEN_FIELDS`].
//!
//! The macros declare every field (unset ones as `Empty`), so a subscriber sees the same schema
//! from every backend. [`start_request`]'s guard (which also records a call dropped before it
//! finished) and [`finish_token`] record the outcome fields; [`send`](crate::client::send)
//! records `http_status` into the current span.
//!
//! Without the `tracing` feature the macros build a [`Span`] that is a unit no-op type, and
//! every helper here does nothing, so callers need no `cfg` of their own.

use std::time::Duration;

use anykms_core::time::Instant;

use anykms_core::Result;

/// The fields of a request span, exactly: `backend, op, resource, key_version, attempt,
/// http_status, code, request_id, latency_ms, error_kind, outcome`.
///
/// `attempt` counts the sends within one operation call: 1, or 2 when the backend rejected the
/// credential and the request was resent once with a refreshed one. It is not the retry layer's
/// attempt: anykms-core's `anykms retry` event carries an `attempt` of its own, the number of
/// the operation call that failed, and each retried call is a new request span.
///
/// `outcome` is `ok`, `error`, or `cancelled` for a call dropped before it finished (a timeout
/// around it, an aborted task): `latency_ms` is then the time until the drop, and `error_kind`
/// stays empty.
pub const REQUEST_FIELDS: &[&str] = &[
    "backend",
    "op",
    "resource",
    "key_version",
    "attempt",
    "http_status",
    "code",
    "request_id",
    "latency_ms",
    "error_kind",
    "outcome",
];

/// The fields of a token span, exactly: `backend, credential, outcome, error_kind, latency_ms,
/// expires_in_s`. `credential` is the credential source's stable snake_case label
/// (`web_identity`, `service_account`, `workload_identity`, `token_file`, ...).
pub const TOKEN_FIELDS: &[&str] = &[
    "backend",
    "credential",
    "outcome",
    "error_kind",
    "latency_ms",
    "expires_in_s",
];

/// The span the macros build: [`tracing::Span`] with the `tracing` feature.
#[cfg(feature = "tracing")]
pub type Span = tracing::Span;

/// The span the macros build: a unit no-op type without the `tracing` feature.
#[cfg(not(feature = "tracing"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Span;

/// A request span (see the [module docs](self)): `request_span!("anykms.aws", backend = ..,
/// op = .., resource = .., key_version = ..)`.
///
/// The name is a literal. `backend` and `op` are `&str`; `resource` and `key_version` are
/// `&str` or `Option<&str>` (`None` leaves the field empty). Every other field of
/// [`REQUEST_FIELDS`] is declared `Empty`: `attempt` through [`record_attempt`],
/// `http_status` through [`send`](crate::client::send), the rest through [`finish_request`].
/// The span is at `DEBUG` level.
#[cfg(feature = "tracing")]
#[macro_export]
macro_rules! request_span {
    ($name:literal, backend = $backend:expr, op = $op:expr, resource = $resource:expr,
     key_version = $key_version:expr $(,)?) => {
        $crate::__private::tracing::debug_span!(
            $name,
            backend = $backend,
            op = $op,
            resource = $resource,
            key_version = $key_version,
            attempt = $crate::__private::tracing::field::Empty,
            http_status = $crate::__private::tracing::field::Empty,
            code = $crate::__private::tracing::field::Empty,
            request_id = $crate::__private::tracing::field::Empty,
            latency_ms = $crate::__private::tracing::field::Empty,
            error_kind = $crate::__private::tracing::field::Empty,
            outcome = $crate::__private::tracing::field::Empty,
        )
    };
}

/// A request span (see the [module docs](self)): `request_span!("anykms.aws", backend = ..,
/// op = .., resource = .., key_version = ..)`.
///
/// Without the `tracing` feature: evaluates its arguments and returns the no-op [`Span`].
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! request_span {
    ($name:literal, backend = $backend:expr, op = $op:expr, resource = $resource:expr,
     key_version = $key_version:expr $(,)?) => {{
        let _ = (&$backend, &$op, &$resource, &$key_version);
        $crate::span::Span
    }};
}

/// A token span (see the [module docs](self)): `token_span!("anykms.aws.token", backend = ..,
/// credential = ..)`.
///
/// The name is a literal; `backend` and `credential` are `&str`. Every other field of
/// [`TOKEN_FIELDS`] is declared `Empty` and recorded by [`finish_token`]. The span is at
/// `DEBUG` level.
#[cfg(feature = "tracing")]
#[macro_export]
macro_rules! token_span {
    ($name:literal, backend = $backend:expr, credential = $credential:expr $(,)?) => {
        $crate::__private::tracing::debug_span!(
            $name,
            backend = $backend,
            credential = $credential,
            outcome = $crate::__private::tracing::field::Empty,
            error_kind = $crate::__private::tracing::field::Empty,
            latency_ms = $crate::__private::tracing::field::Empty,
            expires_in_s = $crate::__private::tracing::field::Empty,
        )
    };
}

/// A token span (see the [module docs](self)): `token_span!("anykms.aws.token", backend = ..,
/// credential = ..)`.
///
/// Without the `tracing` feature: evaluates its arguments and returns the no-op [`Span`].
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! token_span {
    ($name:literal, backend = $backend:expr, credential = $credential:expr $(,)?) => {{
        let _ = (&$backend, &$credential);
        $crate::span::Span
    }};
}

/// Runs `fut` inside `span` (`tracing::Instrument`); without the `tracing` feature, `fut`
/// itself.
pub fn instrument<F: Future>(fut: F, span: &Span) -> impl Future<Output = F::Output> {
    #[cfg(feature = "tracing")]
    {
        tracing::Instrument::instrument(fut, span.clone())
    }
    #[cfg(not(feature = "tracing"))]
    {
        let _ = span;
        fut
    }
}

/// Records `attempt` (the credential-refresh attempt, see [`REQUEST_FIELDS`]) into the current
/// span.
pub fn record_attempt(attempt: u32) {
    #[cfg(feature = "tracing")]
    tracing::Span::current().record("attempt", attempt);
    #[cfg(not(feature = "tracing"))]
    let _ = attempt;
}

/// Starts timing a request span. The returned guard records the end with
/// [`RequestGuard::finish`], or `outcome=cancelled` when it is dropped unfinished, i.e. when the
/// caller drops the operation's future (see [`REQUEST_FIELDS`]). Hold it across the call:
///
/// ```ignore
/// let guard = anykms_http::span::start_request(&span);
/// let r = anykms_http::span::instrument(self.call_inner(&call), &span).await;
/// guard.finish(None, &r);
/// ```
pub fn start_request(span: &Span) -> RequestGuard {
    RequestGuard {
        span: span.clone(),
        started: Instant::now(),
        finished: false,
    }
}

/// A request span's end, pending; see [`start_request`].
#[must_use = "dropping the guard records the request as cancelled"]
#[derive(Debug)]
pub struct RequestGuard {
    span: Span,
    started: Instant,
    finished: bool,
}

impl RequestGuard {
    /// Records the end of the request, as [`finish_request`] does from the guard's start.
    pub fn finish<T>(mut self, request_id: Option<&str>, r: &Result<T>) {
        self.finished = true;
        finish_request(&self.span, self.started, request_id, r);
    }
}

/// Records `outcome=cancelled` and `latency_ms` unless [`finish`](RequestGuard::finish) ran.
impl Drop for RequestGuard {
    fn drop(&mut self) {
        #[cfg(feature = "tracing")]
        if !self.finished {
            self.span
                .record("latency_ms", millis(self.started.elapsed()));
            self.span.record("outcome", "cancelled");
        }
        #[cfg(not(feature = "tracing"))]
        let _ = self.finished;
    }
}

/// Records the end of a request span: `latency_ms` since `started`, `outcome` (`ok` or
/// `error`), and on failure `error_kind` plus `code` and `request_id` from the error's backend
/// detail. On success `request_id` comes from the argument (filtered through
/// [`redact::request_id`](crate::redact::request_id)).
pub fn finish_request<T>(span: &Span, started: Instant, request_id: Option<&str>, r: &Result<T>) {
    #[cfg(feature = "tracing")]
    {
        span.record("latency_ms", millis(started.elapsed()));
        match r {
            Ok(_) => {
                span.record("outcome", "ok");
                if let Some(id) = request_id.and_then(crate::redact::request_id) {
                    span.record("request_id", id);
                }
            }
            Err(e) => {
                span.record("outcome", "error");
                span.record("error_kind", e.kind().as_str());
                if let Some(d) = e.detail() {
                    if let Some(c) = d.code() {
                        span.record("code", c);
                    }
                    if let Some(id) = d.request_id() {
                        span.record("request_id", id);
                    }
                }
            }
        }
    }
    #[cfg(not(feature = "tracing"))]
    let _ = (span, started, request_id, r);
}

/// Records the end of a token span: `latency_ms` since `started`, `outcome` (`ok` or `error`),
/// `expires_in_s` on success when known, `error_kind` on failure. The events of a refresh
/// (`debug!` on success, `warn!` on failure) are the caller's: they name the credential source.
pub fn finish_token<T>(span: &Span, started: Instant, expires_in: Option<Duration>, r: &Result<T>) {
    #[cfg(feature = "tracing")]
    {
        span.record("latency_ms", millis(started.elapsed()));
        match r {
            Ok(_) => {
                span.record("outcome", "ok");
                if let Some(d) = expires_in {
                    span.record("expires_in_s", d.as_secs());
                }
            }
            Err(e) => {
                span.record("outcome", "error");
                span.record("error_kind", e.kind().as_str());
            }
        }
    }
    #[cfg(not(feature = "tracing"))]
    let _ = (span, started, expires_in, r);
}

#[cfg(feature = "tracing")]
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macros_build_spans_without_a_subscriber() {
        let started = Instant::now();
        let s = crate::request_span!(
            "anykms.test",
            backend = "test",
            op = "encrypt",
            resource = "test://k",
            key_version = None::<&str>,
        );
        let r: Result<()> = Ok(());
        finish_request(&s, started, Some("id-1"), &r);
        let t = crate::token_span!("anykms.test.token", backend = "test", credential = "static");
        finish_token(&t, started, Some(Duration::from_secs(60)), &r);
    }

    #[cfg(feature = "tracing")]
    #[test]
    fn macros_declare_the_schema() {
        let names = |s: &Span| -> Option<Vec<&'static str>> {
            Some(s.metadata()?.fields().iter().map(|f| f.name()).collect())
        };
        let s = crate::request_span!(
            "anykms.test",
            backend = "test",
            op = "encrypt",
            resource = Some("test://k"),
            key_version = "1",
        );
        if let Some(f) = names(&s) {
            assert_eq!(f, REQUEST_FIELDS);
        }
        let t = crate::token_span!("anykms.test.token", backend = "test", credential = "static");
        if let Some(f) = names(&t) {
            assert_eq!(f, TOKEN_FIELDS);
        }
    }
}
