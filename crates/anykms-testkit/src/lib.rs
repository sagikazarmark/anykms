//! Test helpers shared by the anykms HTTP backends' hygiene tests. **Never published.**
//!
//! - [`capture`] / [`capture_trace`]: every trace line at `TRACE` (every target, `log` records
//!   of reqwest included, span closes with their recorded fields) into a [`Buf`], plus a
//!   [`SpanRecorder`] of every span's declared fields and recorded values.
//! - [`assert_request_schema`] and [`assert_token_schema`]: a backend's spans follow the shared
//!   schema of `anykms_http::span` exactly.
//! - [`assert_debug_redacts`]: a value's `Debug` output names none of the given secrets.
//! - [`ScriptedTransport`]: an in-process `HttpTransport` that answers from a script and records
//!   every request, so a backend and its credential sources run without a network.
//!
//! The capturing subscriber is the **thread's** default while the [`Capture`] guard lives, so
//! async tests that capture run on a current-thread runtime
//! (`#[tokio::test(flavor = "current_thread")]`, the default).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

pub use anykms_http::span::{REQUEST_FIELDS, TOKEN_FIELDS};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A shared, growable byte buffer: an [`io::Write`] sink and a `tracing_subscriber` writer.
#[derive(Clone, Default)]
pub struct Buf(Arc<Mutex<Vec<u8>>>);

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buf")
            .field("len", &lock(&self.0).len())
            .finish()
    }
}

impl Buf {
    /// Everything written so far, lossily decoded as UTF-8.
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&lock(&self.0)).into_owned()
    }
}

impl io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        lock(&self.0).extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// One span seen by a [`SpanRecorder`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedSpan {
    /// The span name, such as `anykms.aws`.
    pub name: String,
    /// The declared field names, in declaration order.
    pub fields: Vec<String>,
    /// The recorded values, by field name: strings as they are, anything else in its `Debug`
    /// form. A field recorded twice keeps the last value.
    pub values: BTreeMap<String, String>,
}

impl RecordedSpan {
    /// The recorded value of `field`.
    pub fn value(&self, field: &str) -> Option<&str> {
        self.values.get(field).map(String::as_str)
    }
}

#[derive(Default)]
struct Recorded {
    spans: Vec<RecordedSpan>,
    /// Span id → index into `spans` (ids are reused after a span closes; the latest wins).
    open: HashMap<u64, usize>,
}

/// A `tracing_subscriber` layer that records every span: its name, declared fields and the
/// values recorded at creation and later.
#[derive(Clone, Default)]
pub struct SpanRecorder(Arc<Mutex<Recorded>>);

impl fmt::Debug for SpanRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanRecorder")
            .field("spans", &lock(&self.0).spans.len())
            .finish()
    }
}

impl SpanRecorder {
    /// Every span recorded so far, in creation order.
    pub fn spans(&self) -> Vec<RecordedSpan> {
        lock(&self.0).spans.clone()
    }

    /// The recorded spans named `name`.
    pub fn named(&self, name: &str) -> Vec<RecordedSpan> {
        lock(&self.0)
            .spans
            .iter()
            .filter(|s| s.name == name)
            .cloned()
            .collect()
    }
}

struct Values<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for Values<'_> {
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        self.0.insert(f.name().to_owned(), v.to_owned());
    }

    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn fmt::Debug) {
        self.0.insert(f.name().to_owned(), format!("{v:?}"));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanRecorder {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let m = attrs.metadata();
        let mut span = RecordedSpan {
            name: m.name().to_owned(),
            fields: m.fields().iter().map(|f| f.name().to_owned()).collect(),
            values: BTreeMap::new(),
        };
        attrs.record(&mut Values(&mut span.values));
        let mut r = lock(&self.0);
        let i = r.spans.len();
        r.spans.push(span);
        r.open.insert(id.into_u64(), i);
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut r = lock(&self.0);
        if let Some(&i) = r.open.get(&id.into_u64()) {
            values.record(&mut Values(&mut r.spans[i].values));
        }
    }

    fn on_close(&self, id: tracing::span::Id, _: tracing_subscriber::layer::Context<'_, S>) {
        lock(&self.0).open.remove(&id.into_u64());
    }
}

/// A running capture (see [`capture`]); the capturing subscriber is the thread's default until
/// it is dropped.
pub struct Capture {
    buf: Buf,
    spans: SpanRecorder,
    _guard: tracing::subscriber::DefaultGuard,
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture")
            .field("buf", &self.buf)
            .field("spans", &self.spans)
            .finish_non_exhaustive()
    }
}

impl Capture {
    /// Every line formatted so far: events of every target at `TRACE`, and span closes with
    /// their recorded fields.
    pub fn text(&self) -> String {
        self.buf.contents()
    }

    /// The spans recorded so far.
    pub fn spans(&self) -> &SpanRecorder {
        &self.spans
    }
}

/// Starts capturing every trace line at `TRACE` on this thread (every target; `log` records,
/// such as reqwest's, through a process-wide `log` bridge installed on first use; span closes
/// with their recorded fields), and every span into a [`SpanRecorder`].
///
/// The bridge is a global `log` logger: a test binary that calls `capture` cannot also install
/// a global subscriber with `try_init()` (whichever comes second fails to set the logger).
pub fn capture() -> Capture {
    use tracing_subscriber::layer::SubscriberExt as _;
    static LOG_BRIDGE: std::sync::Once = std::sync::Once::new();
    LOG_BRIDGE.call_once(|| {
        // Another logger already installed (by the test binary) keeps working as it was.
        let _ = tracing_log::LogTracer::init();
    });
    let buf = Buf::default();
    let spans = SpanRecorder::default();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(buf.clone())
                .with_ansi(false)
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE),
        )
        .with(spans.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    Capture {
        buf,
        spans,
        _guard: guard,
    }
}

/// Runs `f` under [`capture`] and returns the captured text.
pub fn capture_trace(f: impl FnOnce()) -> String {
    let c = capture();
    f();
    c.text()
}

/// The span names of `backend`'s schema: `anykms.<backend>` and `anykms.<backend>.token`.
fn names(backend: &str) -> (String, String) {
    let request = format!("anykms.{backend}");
    let token = format!("{request}.token");
    (request, token)
}

/// Panics on any span of `backend` (named `anykms.<backend>` or `anykms.<backend>.*`) that is
/// neither its request nor its token span.
fn assert_known_spans(rec: &SpanRecorder, backend: &str) {
    let (request, token) = names(backend);
    let prefix = format!("{request}.");
    for s in rec.spans() {
        assert!(
            !(s.name.starts_with(&prefix) && s.name != token),
            "span {} is not in the schema: {s:?}",
            s.name
        );
    }
}

fn sorted(v: &[impl AsRef<str>]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|s| s.as_ref().to_owned()).collect();
    v.sort();
    v
}

/// Asserts that `backend` recorded at least one request span, that every span named
/// `anykms.<backend>` declares exactly [`REQUEST_FIELDS`] and records `backend = <backend>`, and
/// that no other `anykms.<backend>.*` span exists except the token span.
pub fn assert_request_schema(rec: &SpanRecorder, backend: &str) {
    let (request, _) = names(backend);
    assert_known_spans(rec, backend);
    let spans = rec.named(&request);
    assert!(!spans.is_empty(), "no {request} span was recorded");
    for s in spans {
        assert_eq!(sorted(&s.fields), sorted(REQUEST_FIELDS), "{s:?}");
        assert_eq!(s.value("backend"), Some(backend), "{s:?}");
    }
}

/// Asserts that `backend` recorded at least one token span, that every span named
/// `anykms.<backend>.token` declares exactly [`TOKEN_FIELDS`] and records
/// `backend = <backend>`, and that no other `anykms.<backend>.*` span exists.
pub fn assert_token_schema(rec: &SpanRecorder, backend: &str) {
    let (_, token) = names(backend);
    assert_known_spans(rec, backend);
    let spans = rec.named(&token);
    assert!(!spans.is_empty(), "no {token} span was recorded");
    for s in spans {
        assert_eq!(sorted(&s.fields), sorted(TOKEN_FIELDS), "{s:?}");
        assert_eq!(s.value("backend"), Some(backend), "{s:?}");
    }
}

/// Asserts that neither the `Debug` nor the alternate (`{:#?}`) output of `value` contains any
/// of `secrets` (P1-1: configs, builders and credentials holding proxy userinfo, secrets or
/// tokens).
pub fn assert_debug_redacts(value: &dyn fmt::Debug, secrets: &[&str]) {
    let outputs = [format!("{value:?}"), format!("{value:#?}")];
    for s in secrets {
        assert!(!s.is_empty(), "an empty secret matches everything");
        for out in &outputs {
            assert!(
                !out.contains(s),
                "Debug output contains the secret {s:?}:\n{out}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use anykms_core::{BackendDetail, Error, ErrorKind, Operation, Result};
    use anykms_http::span::{finish_request, finish_token, record_attempt, start_request};

    use super::*;

    fn field_names(s: &tracing::Span) -> Vec<&'static str> {
        s.metadata()
            .unwrap()
            .fields()
            .iter()
            .map(|f| f.name())
            .collect()
    }

    fn request_span() -> tracing::Span {
        anykms_http::request_span!(
            "anykms.test",
            backend = "test",
            op = "encrypt",
            resource = "test://key",
            key_version = None::<&str>,
        )
    }

    #[test]
    fn macros_match_the_schema_constants() {
        let c = capture();
        let s = request_span();
        assert_eq!(field_names(&s), REQUEST_FIELDS);
        let t = anykms_http::token_span!("anykms.test.token", backend = "test", credential = "x");
        assert_eq!(field_names(&t), TOKEN_FIELDS);

        s.in_scope(|| record_attempt(1));
        let err: Result<()> =
            Err(
                Error::new(ErrorKind::Unavailable, "test", Operation::Encrypt, "down").with_detail(
                    BackendDetail::new()
                        .with_code("Down")
                        .with_request_id("req-1"),
                ),
            );
        finish_request(&s, Instant::now(), None, &err);
        finish_token(&t, Instant::now(), Some(Duration::from_secs(90)), &Ok(()));
        drop((s, t));

        assert_request_schema(c.spans(), "test");
        assert_token_schema(c.spans(), "test");
        let r = &c.spans().named("anykms.test")[0];
        assert_eq!(r.value("op"), Some("encrypt"));
        assert_eq!(r.value("resource"), Some("test://key"));
        assert_eq!(r.value("key_version"), None);
        assert_eq!(r.value("attempt"), Some("1"));
        assert_eq!(r.value("outcome"), Some("error"));
        assert_eq!(r.value("error_kind"), Some("unavailable"));
        assert_eq!(r.value("code"), Some("Down"));
        assert_eq!(r.value("request_id"), Some("req-1"));
        assert!(r.value("latency_ms").is_some());
        let t = &c.spans().named("anykms.test.token")[0];
        assert_eq!(t.value("credential"), Some("x"));
        assert_eq!(t.value("outcome"), Some("ok"));
        assert_eq!(t.value("expires_in_s"), Some("90"));
        assert!(c.text().contains("anykms.test"), "{}", c.text());
    }

    #[test]
    fn a_successful_request_records_the_filtered_request_id() {
        let c = capture();
        let s = request_span();
        finish_request(&s, Instant::now(), Some("ok-id"), &Ok(()));
        let s2 = request_span();
        finish_request(&s2, Instant::now(), Some("bad id\n"), &Ok(()));
        drop((s, s2));
        let spans = c.spans().named("anykms.test");
        assert_eq!(spans[0].value("outcome"), Some("ok"));
        assert_eq!(spans[0].value("request_id"), Some("ok-id"));
        assert_eq!(spans[1].value("request_id"), None);
    }

    /// The guard records the outcome once: `cancelled` when dropped unfinished, otherwise what
    /// `finish` was given.
    #[test]
    fn the_request_guard_records_a_cancelled_request() {
        let c = capture();
        let s = request_span();
        drop(start_request(&s));
        let s2 = request_span();
        start_request(&s2).finish(Some("ok-id"), &Ok(()));
        drop((s, s2));
        let spans = c.spans().named("anykms.test");
        assert_eq!(spans[0].value("outcome"), Some("cancelled"));
        assert_eq!(spans[0].value("error_kind"), None);
        assert!(spans[0].value("latency_ms").is_some());
        assert_eq!(spans[1].value("outcome"), Some("ok"));
        assert_eq!(spans[1].value("request_id"), Some("ok-id"));
    }

    #[test]
    fn capture_trace_sees_events_and_span_fields() {
        let text = capture_trace(|| {
            let s = request_span();
            s.in_scope(|| tracing::trace!(target: "some::dependency", "deep detail"));
        });
        assert!(text.contains("deep detail"), "{text}");
        assert!(text.contains(r#"resource="test://key""#), "{text}");
    }

    #[test]
    #[should_panic(expected = "anykms.test")]
    fn a_span_off_the_schema_fails() {
        let c = capture();
        drop(tracing::debug_span!(
            "anykms.test",
            backend = "test",
            op = "x"
        ));
        assert_request_schema(c.spans(), "test");
    }

    #[test]
    #[should_panic(expected = "not in the schema")]
    fn an_unknown_backend_span_fails() {
        let c = capture();
        drop(request_span());
        drop(tracing::debug_span!("anykms.test.extra", backend = "test"));
        assert_request_schema(c.spans(), "test");
    }

    #[test]
    #[should_panic(expected = "no anykms.test.token span")]
    fn a_missing_token_span_fails() {
        let c = capture();
        drop(request_span());
        assert_token_schema(c.spans(), "test");
    }

    #[derive(Debug)]
    #[allow(dead_code)] // read through Debug only
    struct Leaky {
        token: &'static str,
    }

    #[test]
    fn debug_redaction() {
        assert_debug_redacts(&Leaky { token: "public" }, &["SECRET"]);
        let r = std::panic::catch_unwind(|| {
            assert_debug_redacts(&Leaky { token: "SECRET" }, &["SECRET"]);
        });
        assert!(r.is_err());
    }
}

/// One request a [`ScriptedTransport`] received.
#[derive(Clone, Debug)]
pub struct SeenRequest {
    /// The method.
    pub method: anykms_http::http::Method,
    /// The full URI.
    pub uri: String,
    /// The headers.
    pub headers: anykms_http::http::HeaderMap,
    /// The body.
    pub body: Vec<u8>,
    /// The `limit` the backend passed.
    pub limit: usize,
    /// The [`RequestTimeout`](anykms_http::RequestTimeout) the request carried, if any.
    pub timeout: Option<std::time::Duration>,
}

/// What a [`ScriptedTransport`] answers next.
pub enum Scripted {
    /// A response with this status and body (JSON-ish bytes), `content-type: application/json`.
    Reply(u16, Vec<u8>),
    /// A response with this status, headers and body.
    ReplyWith(u16, Vec<(&'static str, String)>, Vec<u8>),
    /// A transport failure.
    Fail(anykms_http::SendError),
    /// A reply whose body ignores the limit (a misbehaving transport), to prove the caller-side
    /// check.
    Oversized(u16, Vec<u8>),
}

impl fmt::Debug for Scripted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reply(s, b) => f.debug_tuple("Reply").field(s).field(&b.len()).finish(),
            Self::ReplyWith(s, h, b) => f
                .debug_tuple("ReplyWith")
                .field(s)
                .field(h)
                .field(&b.len())
                .finish(),
            Self::Fail(e) => f.debug_tuple("Fail").field(e).finish(),
            Self::Oversized(s, b) => f.debug_tuple("Oversized").field(s).field(&b.len()).finish(),
        }
    }
}

/// An in-process [`HttpTransport`](anykms_http::HttpTransport) that answers from a script and
/// records every request, for exercising a backend without a network or reqwest. It honours
/// `limit` like a real transport (a body over it is `TooLarge`) unless the script says
/// [`Scripted::Oversized`]. Runs out of script: `SendError::Other`.
#[derive(Clone, Debug, Default)]
pub struct ScriptedTransport {
    inner: Arc<Mutex<ScriptState>>,
}

#[derive(Debug, Default)]
struct ScriptState {
    script: std::collections::VecDeque<Scripted>,
    seen: Vec<SeenRequest>,
}

impl ScriptedTransport {
    /// An empty script.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a scripted answer.
    pub fn push(&self, s: Scripted) -> &Self {
        lock(&self.inner).script.push_back(s);
        self
    }

    /// Appends a JSON reply.
    pub fn reply(&self, status: u16, body: impl Into<Vec<u8>>) -> &Self {
        self.push(Scripted::Reply(status, body.into()))
    }

    /// Every request so far.
    pub fn seen(&self) -> Vec<SeenRequest> {
        lock(&self.inner).seen.clone()
    }

    /// The number of requests so far.
    pub fn count(&self) -> usize {
        lock(&self.inner).seen.len()
    }

    /// Whether the whole script was consumed.
    pub fn exhausted(&self) -> bool {
        lock(&self.inner).script.is_empty()
    }
}

impl anykms_http::HttpTransport for ScriptedTransport {
    fn send(
        &self,
        req: anykms_http::transport::Request,
        limit: usize,
    ) -> anykms_core::BoxFuture<'_, Result<anykms_http::transport::Response, anykms_http::SendError>>
    {
        use anykms_http::SendError;
        use anykms_http::http::{Response, StatusCode};
        let next = {
            let mut st = lock(&self.inner);
            st.seen.push(SeenRequest {
                method: req.method().clone(),
                uri: req.uri().to_string(),
                headers: req.headers().clone(),
                body: req.body().to_vec(),
                limit,
                timeout: req
                    .extensions()
                    .get::<anykms_http::RequestTimeout>()
                    .map(|t| t.0),
            });
            st.script.pop_front()
        };
        let build = |status: u16, headers: Vec<(&'static str, String)>, body: Vec<u8>| {
            let mut r = Response::new(zeroize::Zeroizing::new(body));
            *r.status_mut() = StatusCode::from_u16(status).unwrap();
            r.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            for (k, v) in headers {
                r.headers_mut().insert(k, v.parse().unwrap());
            }
            r
        };
        Box::pin(async move {
            match next {
                None => Err(SendError::Other(
                    "scripted transport: script exhausted".into(),
                )),
                Some(Scripted::Fail(e)) => Err(e),
                Some(Scripted::Reply(s, b) | Scripted::ReplyWith(s, _, b)) if b.len() > limit => {
                    Err(SendError::TooLarge {
                        status: StatusCode::from_u16(s).unwrap(),
                    })
                }
                Some(Scripted::Reply(s, b) | Scripted::Oversized(s, b)) => Ok(build(s, vec![], b)),
                Some(Scripted::ReplyWith(s, h, b)) => Ok(build(s, h, b)),
            }
        })
    }
}
