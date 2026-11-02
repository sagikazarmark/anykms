//! A metrics hook: [`ObserveLayer`] reports every operation of a handle with its outcome and
//! latency to a callback, without a metrics dependency.
//!
//! ```
//! use std::sync::Arc;
//! use anykms_core::{ObserveLayer, OpEvent, Registry};
//!
//! let observe = ObserveLayer::new(|e: &OpEvent<'_>| {
//!     // e.g. a histogram labelled with the part, operation and outcome
//!     println!("{} {} {} {:?}", e.part(), e.operation(), e.outcome(), e.latency());
//! });
//! let registry = Registry::builder().layer(observe).build().unwrap();
//! # let _ = registry;
//! ```
//!
//! Where the layer sits relative to a [`RetryLayer`](crate::RetryLayer) decides what it sees:
//! added **before** the retry layer it observes every attempt (one event per backend request, the
//! view for backend latency and throttling), added **after** it observes each call as the caller
//! sees it, retries and backoff included. Calls through the typed handle
//! behind an opaque handle (`downcast_ref`) bypass every layer, this one included, unless they
//! run through the handle's `call_extension` (reported with [`OpEvent::extension_name`]).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::around::{Around, Call, CallCx, CallOutput};
use crate::dynamic::{BoxFuture, Layer, LayerCx, Part, PartKind};
use crate::error::{ErrorKind, Operation, Result};
use crate::retry::{ClockFn, std_clock};

/// One finished or [cancelled](Self::is_cancelled) operation, reported by an [`ObserveLayer`].
/// Holds no input or output data.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct OpEvent<'a> {
    backend: Option<&'static str>,
    resource: Option<&'a str>,
    part: PartKind,
    op: Operation,
    extension: Option<&'static str>,
    error: Option<&'a crate::Error>,
    cancelled: bool,
    latency: Duration,
}

impl<'a> OpEvent<'a> {
    /// The backend of the handle (see [`LayerCx`]).
    pub fn backend(&self) -> Option<&'static str> {
        self.backend
    }

    /// The key the handle opens ([`LayerCx::resource`]), e.g. for a
    /// per-key metric label; `None` when the handle names none.
    pub fn resource(&self) -> Option<&'a str> {
        self.resource
    }

    /// The handle part that ran the operation.
    pub fn part(&self) -> PartKind {
        self.part
    }

    /// The operation.
    pub fn operation(&self) -> Operation {
        self.op
    }

    /// For a backend-specific operation (part [`PartKind::Extension`]), the backend's name of
    /// it ([`Call::name`](crate::Call::name), e.g.
    /// `"aws.encrypt_with_context"`); `None` for the portable operations.
    pub fn extension_name(&self) -> Option<&'static str> {
        self.extension
    }

    /// Whether the operation succeeded: `false` for a failed or a [cancelled](Self::is_cancelled)
    /// one.
    pub fn is_ok(&self) -> bool {
        self.error.is_none() && !self.cancelled
    }

    /// Whether the caller dropped the operation before it finished (a timeout around it, an
    /// aborted task). A cancelled operation has no [`error`](Self::error); its
    /// [`latency`](Self::latency) is the time until the drop.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// The outcome as a metric label: `"ok"`, `"cancelled"`, or the error kind
    /// ([`ErrorKind::as_str`]).
    pub fn outcome(&self) -> &'static str {
        match self.error {
            Some(e) => e.kind().as_str(),
            None if self.cancelled => "cancelled",
            None => "ok",
        }
    }

    /// The error kind, for a failed operation.
    pub fn error_kind(&self) -> Option<ErrorKind> {
        self.error.map(crate::Error::kind)
    }

    /// The error, for a failed operation (its backend, resource, retry hints, ...).
    pub fn error(&self) -> Option<&'a crate::Error> {
        self.error
    }

    /// How long the operation took, by the layer's clock.
    pub fn latency(&self) -> Duration {
        self.latency
    }
}

type Observer = Arc<dyn Fn(&OpEvent<'_>) + Send + Sync>;

/// A [`Layer`] that reports every operation of every part to a callback as an [`OpEvent`]: the
/// hook for metrics (counts, error rates, latency histograms) and audit logs. See the
/// [module docs](self) for where to put it relative to a retry layer.
///
/// Cheap to clone: clones share the callback.
#[derive(Clone)]
pub struct ObserveLayer {
    observer: Observer,
    clock: ClockFn,
}

impl fmt::Debug for ObserveLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObserveLayer").finish_non_exhaustive()
    }
}

impl ObserveLayer {
    /// Reports to `observer`, measuring latency with [`std_clock`]. The callback runs inline
    /// after each operation, or for a cancelled one where its future is dropped: keep it cheap
    /// and non-blocking.
    pub fn new(observer: impl Fn(&OpEvent<'_>) + Send + Sync + 'static) -> Self {
        Self {
            observer: Arc::new(observer),
            clock: std_clock(),
        }
    }

    /// Measures latency with `clock` instead of [`std_clock`] (which panics on
    /// `wasm32-unknown-unknown`; pass a clock that works there).
    pub fn with_clock(mut self, clock: ClockFn) -> Self {
        self.clock = clock;
        self
    }

    /// Reports one event.
    fn report(&self, event: &OpEvent<'_>) {
        (self.observer)(event);
    }
}

impl Layer for ObserveLayer {
    /// Every part's operations, as [`Call`]s, each reported once.
    fn part(&self, cx: &LayerCx<'_>, part: Part<'_>) {
        part.wrap_around(cx, Arc::new(self.clone()));
    }
}

/// Reports each call once, with its part, operation and, for backend-specific calls
/// ([`PartKind::Extension`]), its name.
impl Around for ObserveLayer {
    fn around<'a>(&'a self, cx: &'a CallCx, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>> {
        Box::pin(async move {
            let pending = Pending::start(
                self,
                cx.backend(),
                cx.resource(),
                call.part(),
                call.operation(),
                (call.part() == PartKind::Extension).then(|| call.name()),
            );
            let r = call.run().await;
            pending.finish(&r);
            r
        })
    }
}

/// One call in flight: reports it once, when it finishes, or as cancelled when it is dropped
/// before that (the caller dropped the future). A call unwound by a panic is not reported, so
/// that a panicking callback cannot abort the process.
struct Pending<'a> {
    layer: &'a ObserveLayer,
    backend: Option<&'static str>,
    resource: Option<&'a str>,
    part: PartKind,
    op: Operation,
    extension: Option<&'static str>,
    start: Duration,
    reported: bool,
}

impl<'a> Pending<'a> {
    fn start(
        layer: &'a ObserveLayer,
        backend: Option<&'static str>,
        resource: Option<&'a str>,
        part: PartKind,
        op: Operation,
        extension: Option<&'static str>,
    ) -> Self {
        Self {
            layer,
            backend,
            resource,
            part,
            op,
            extension,
            start: (layer.clock)(),
            reported: false,
        }
    }

    fn finish<R>(mut self, r: &Result<R>) {
        self.report(r.as_ref().err(), false);
    }

    fn report(&mut self, error: Option<&crate::Error>, cancelled: bool) {
        self.reported = true;
        self.layer.report(&OpEvent {
            backend: self.backend,
            resource: self.resource,
            part: self.part,
            op: self.op,
            extension: self.extension,
            error,
            cancelled,
            latency: (self.layer.clock)().saturating_sub(self.start),
        });
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.reported && !std::thread::panicking() {
            self.report(None, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        Aead, AeadKey, Ciphertext, Error, KeyWrap, RetryLayer, RetryPolicy, instant_sleep,
    };

    /// Fails `fail` times with `Unavailable`, then echoes.
    struct Flaky {
        fail: Mutex<u32>,
    }
    impl Aead for Flaky {
        async fn encrypt(&self, pt: &[u8], _: &[u8]) -> Result<Ciphertext> {
            let mut f = self.fail.lock().unwrap();
            if *f > 0 {
                *f -= 1;
                return Err(Error::app(ErrorKind::Unavailable, "down"));
            }
            Ok(Ciphertext::from_bytes(pt.to_vec()))
        }
        async fn decrypt(&self, ct: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.as_bytes().to_vec()))
        }
    }

    type Log = Arc<Mutex<Vec<(PartKind, Operation, Option<ErrorKind>)>>>;

    fn recording() -> (ObserveLayer, Log) {
        let log: Log = Arc::default();
        let l = log.clone();
        let layer = ObserveLayer::new(move |e: &OpEvent<'_>| {
            l.lock()
                .unwrap()
                .push((e.part(), e.operation(), e.error_kind()));
        });
        (layer, log)
    }

    #[tokio::test]
    async fn reports_each_operation_and_outcome() {
        let (observe, log) = recording();
        let k = AeadKey::new(
            "t",
            Arc::new(Flaky {
                fail: Mutex::new(1),
            }),
        )
        .layer(&observe);
        assert!(k.encrypt(b"x", b"").await.is_err());
        k.encrypt(b"x", b"").await.unwrap();
        k.decrypt(&Ciphertext::from_bytes(b"x".to_vec()), b"")
            .await
            .unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                (
                    PartKind::Aead,
                    Operation::Encrypt,
                    Some(ErrorKind::Unavailable)
                ),
                (PartKind::Aead, Operation::Encrypt, None),
                (PartKind::Aead, Operation::Decrypt, None),
            ]
        );
    }

    /// Key wrapping is observed as `WrapKey`/`UnwrapKey`, and the AEAD adapter relabels its
    /// errors the same way.
    #[tokio::test]
    async fn key_wrap_operations_are_named() {
        let (observe, log) = recording();
        let k = crate::KeyWrapKey::from_aead(AeadKey::new(
            "t",
            Arc::new(Flaky {
                fail: Mutex::new(1),
            }),
        ))
        .layer(&observe);
        let e = k.wrap_key(b"dek").await.unwrap_err();
        assert_eq!(e.operation(), Operation::WrapKey);
        let wrapped = k.wrap_key(b"dek").await.unwrap();
        k.unwrap_key(&wrapped).await.unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                (
                    PartKind::KeyWrap,
                    Operation::WrapKey,
                    Some(ErrorKind::Unavailable)
                ),
                (PartKind::KeyWrap, Operation::WrapKey, None),
                (PartKind::KeyWrap, Operation::UnwrapKey, None),
            ]
        );
    }

    /// Events name the handle's backend and key, including for layers applied before the
    /// resource was set, and for registry-wide layers.
    #[tokio::test]
    async fn events_carry_the_backend_and_resource() {
        type Seen = Vec<(Option<&'static str>, Option<String>)>;
        let seen: Arc<Mutex<Seen>> = Arc::default();
        let s = seen.clone();
        let observe = ObserveLayer::new(move |e: &OpEvent<'_>| {
            s.lock()
                .unwrap()
                .push((e.backend(), e.resource().map(str::to_owned)));
        });
        let flaky = || {
            Arc::new(Flaky {
                fail: Mutex::new(0),
            })
        };
        let k = AeadKey::new("t", flaky()).layer(&observe);
        k.encrypt(b"x", b"").await.unwrap();
        let k = k.with_resource("t://k1");
        assert_eq!(k.resource(), Some("t://k1"));
        k.encrypt(b"x", b"").await.unwrap();
        crate::KeyWrapKey::from_aead(k)
            .wrap_key(b"dek")
            .await
            .unwrap();

        struct P;
        impl crate::Provider for P {
            fn schemes(&self) -> &[&'static str] {
                &["p"]
            }
            fn aead(&self, _: &crate::KeyUri, _: &crate::OpenOptions) -> Result<AeadKey> {
                Ok(AeadKey::new(
                    "p",
                    Arc::new(Flaky {
                        fail: Mutex::new(0),
                    }),
                ))
            }
        }
        let r = crate::Registry::builder()
            .provider(P)
            .layer(observe)
            .build()
            .unwrap();
        r.aead("p://srv/k2?opt=1")
            .unwrap()
            .encrypt(b"x", b"")
            .await
            .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (Some("t"), None),
                (Some("t"), Some("t://k1".to_owned())),
                (Some("t"), Some("t://k1".to_owned())),
                (Some("p"), Some("p://srv/k2".to_owned())),
            ]
        );
    }

    /// Never finishes an operation.
    struct Hang;
    impl Aead for Hang {
        async fn encrypt(&self, _: &[u8], _: &[u8]) -> Result<Ciphertext> {
            std::future::pending().await
        }
        async fn decrypt(&self, _: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            std::future::pending().await
        }
    }

    /// A call dropped before it finishes is reported once, as cancelled and not ok, through a
    /// layer and through `wrap`.
    #[tokio::test]
    async fn reports_a_cancelled_call() {
        type Seen = Vec<(Operation, bool, bool, Option<ErrorKind>, &'static str)>;
        let seen: Arc<Mutex<Seen>> = Arc::default();
        let s = seen.clone();
        let observe = ObserveLayer::new(move |e: &OpEvent<'_>| {
            s.lock().unwrap().push((
                e.operation(),
                e.is_ok(),
                e.is_cancelled(),
                e.error_kind(),
                e.outcome(),
            ));
        });
        let timeout = Duration::from_millis(10);
        let k = AeadKey::new("t", Arc::new(Hang)).layer(&observe);
        for _ in 0..3 {
            assert!(
                tokio::time::timeout(timeout, k.encrypt(b"x", b""))
                    .await
                    .is_err()
            );
        }
        let ct = Ciphertext::from_bytes(b"x".to_vec());
        assert!(
            tokio::time::timeout(timeout, k.decrypt(&ct, b""))
                .await
                .is_err()
        );
        let cancelled = |op| (op, false, true, None, "cancelled");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                cancelled(Operation::Encrypt),
                cancelled(Operation::Encrypt),
                cancelled(Operation::Encrypt),
                cancelled(Operation::Decrypt),
            ]
        );

        // A finished call is not reported again when its future is dropped.
        seen.lock().unwrap().clear();
        let k = AeadKey::new(
            "t",
            Arc::new(Flaky {
                fail: Mutex::new(1),
            }),
        )
        .layer(&observe);
        assert!(k.encrypt(b"x", b"").await.is_err());
        k.encrypt(b"x", b"").await.unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (
                    Operation::Encrypt,
                    false,
                    false,
                    Some(ErrorKind::Unavailable),
                    "unavailable"
                ),
                (Operation::Encrypt, true, false, None, "ok"),
            ]
        );
    }

    /// Before the retry layer it sees every attempt; after it, each call once.
    #[tokio::test]
    async fn position_relative_to_retries() {
        let retry = RetryLayer::new(instant_sleep()).with_policy(RetryPolicy::immediate());
        let (inner, attempts) = recording();
        let (outer, calls) = recording();
        let k = AeadKey::new(
            "t",
            Arc::new(Flaky {
                fail: Mutex::new(2),
            }),
        )
        .layer(&inner)
        .layer(&retry)
        .layer(&outer);
        k.encrypt(b"x", b"").await.unwrap();
        assert_eq!(attempts.lock().unwrap().len(), 3);
        assert_eq!(
            *calls.lock().unwrap(),
            [(PartKind::Aead, Operation::Encrypt, None)]
        );
    }
}
