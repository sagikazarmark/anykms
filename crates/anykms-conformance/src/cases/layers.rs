//! Layers apply to backend extension calls like to every other part.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anykms_core::{
    Around, BoxFuture, Call, CallCx, CallOutput, Error, ErrorKind, Layer, LayerCx, ObserveLayer,
    OpEvent, Part, PartKind, Result, RetryLayer, RetryPolicy, instant_sleep,
};

use crate::ctx::{CaseResult, Check, Ctx, ensure};
use crate::fixture::{Fixture, TestKeyKind};

type Events = Arc<Mutex<Vec<(PartKind, Option<&'static str>, bool)>>>;

/// An observe layer recording every event.
fn observing() -> (ObserveLayer, Events) {
    let events = Events::default();
    let ev = events.clone();
    let layer = ObserveLayer::new(move |e: &OpEvent<'_>| {
        ev.lock()
            .expect("events")
            .push((e.part(), e.extension_name(), e.is_ok()))
    });
    (layer, events)
}

/// A layer whose extension slot fails the first `fail` attempts with a retryable error and
/// counts every attempt.
#[derive(Clone)]
struct FailFirst {
    fail: Arc<AtomicU32>,
    attempts: Arc<AtomicU32>,
}

impl Layer for FailFirst {
    /// Intercepts the extension slot only.
    fn part(&self, cx: &LayerCx<'_>, part: Part<'_>) {
        if part.kind() == PartKind::Extension {
            part.wrap_around(cx, Arc::new(self.clone()));
        }
    }
}

impl Around for FailFirst {
    fn around<'a>(&'a self, _: &'a CallCx, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            // Fails while `fail` is positive, decrementing it (`try_update` is newer than the
            // MSRV, and newer releases deprecate `fetch_update`).
            let mut n = self.fail.load(Ordering::SeqCst);
            let failed = loop {
                if n == 0 {
                    break false;
                }
                match self
                    .fail
                    .compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break true,
                    Err(now) => n = now,
                }
            };
            if failed {
                return Err(Error::new(
                    ErrorKind::Unavailable,
                    "conformance",
                    call.operation(),
                    "injected transient failure",
                ));
            }
            call.run().await
        })
    }
}

/// One extension call on a layered `AeadKey` is one `Extension` event of every layer, with the
/// call's name, and a transient failure below a `RetryLayer` is retried.
pub(crate) async fn extension_calls_are_layered<F: Fixture>(c: Ctx<F>) -> CaseResult {
    let key = c.key(TestKeyKind::Aead).await?;
    let k = c.aead(&key.uri).ctx("open")?;
    ensure!(
        !k.is_retrying(),
        "the fixture's handles already retry; the case adds its own retry layer"
    );

    let (observe, events) = observing();
    c.fx.extension_call(&k.clone().layer(&observe))
        .await
        .ctx("fixture extension_call")?;
    let seen = events.lock().expect("events").clone();
    let ext: Vec<_> = seen
        .iter()
        .filter(|(p, _, _)| *p == PartKind::Extension)
        .collect();
    ensure!(
        ext.len() == 1,
        "one extension call produced {} extension events: {seen:?}",
        ext.len()
    );
    let (_, name, ok) = ext[0];
    ensure!(
        name.is_some_and(|n| !n.is_empty()) && *ok,
        "extension event {:?} has no name or failed",
        ext[0]
    );

    let fail = FailFirst {
        fail: Arc::new(AtomicU32::new(1)),
        attempts: Arc::new(AtomicU32::new(0)),
    };
    let (below, attempts) = observing();
    let retry = RetryLayer::new(instant_sleep()).with_policy(RetryPolicy::immediate());
    let layered = k.layer(&below).layer(&fail).layer(&retry);
    c.fx.extension_call(&layered)
        .await
        .ctx("fixture extension_call after an injected transient failure")?;
    ensure!(
        fail.attempts.load(Ordering::SeqCst) == 2,
        "the extension call was attempted {} time(s), expected a retry after the failure",
        fail.attempts.load(Ordering::SeqCst)
    );
    let below: Vec<_> = attempts
        .lock()
        .expect("events")
        .iter()
        .filter(|(p, _, _)| *p == PartKind::Extension)
        .cloned()
        .collect();
    ensure!(
        below.len() == 1 && below[0].2,
        "the backend saw extension events {below:?}, expected one successful call"
    );
    Ok(())
}
