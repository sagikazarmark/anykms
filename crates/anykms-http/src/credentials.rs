//! A single-flight cache for one expiring credential (an access token, a set of temporary keys).
//!
//! The backends' credential sources (AWS SigV4 keys, GCP and Entra ID access tokens) fetch; this
//! cache decides when:
//!
//! - **Lazy and single-flight.** Nothing is fetched before the first [`get`], and one fetch runs
//!   at a time ([`SingleFlight`]). Callers that find no usable credential while it runs wait for
//!   it and all get its result: the credential, **or the error**. If the fetching caller is
//!   cancelled, one of the waiting callers fetches instead. If it is alive but not being
//!   polled (stalled), they wait for as long as it lives, unless
//!   [`max_wait`](CredentialCache::max_wait) or [`bound_by`](CredentialCache::bound_by) sets a
//!   stall bound: then, once its fetch has been woken (its response arrived, or its timeout
//!   passed) and left unpolled for that long, the first waiting caller to notice fetches in
//!   its place, and the others wait for that fetch (one fetch, not one per waiter). A fetch
//!   that is being polled is waited for however long it takes. If the stalled caller resumes,
//!   its fetch's credential, older and possibly revoked, is not cached over the newer one: it
//!   gets the newer one too. The built-in backends bound every cache by their transport's
//!   [`follower_wait`](crate::HttpTransport::follower_wait): twice the connect plus request
//!   timeout with the built-in transport.
//! - **Refresh ahead, without waiting.** A credential is refreshed `refresh_ahead` before it
//!   expires (at half its lifetime for short-lived ones), while it is still usable. The first
//!   caller to find it due fetches; every other caller keeps getting the current credential
//!   meanwhile. If that early refresh fails, the current credential keeps being returned and the
//!   next early refresh waits `refresh_backoff`.
//! - **Failures are cached briefly.** With no usable credential, a failed fetch is returned to
//!   every caller for `refresh_backoff` (5 s by default, as transit's `Login` does) before a
//!   [`get`] fetches again: a failing source sees one fetch per backoff, not one per request.
//! - **Refresh once on 401.** A client whose request was rejected calls [`invalidate`] with the
//!   credential it sent; the next [`get`] fetches a new one (at most once per
//!   `forced_refresh_interval`), and the client retries **once** only if the
//!   [`generation`](Credential::generation) changed. That retry is not multiplied by `Retry`.
//!   The generation counts fetches, not distinct values: a fetch that returns the same
//!   credential again (static credentials, a source with its own cache) still gets a new
//!   generation, so the retry then resends the rejected credential. That costs one request and
//!   stays bounded; a client that wants to skip it also compares the values.
//!
//! Expiry and backoffs follow tokio's clock (`tokio::time::Instant`): the system clock, except in
//! tests that pause time (tokio's `test-util`). On a JS host they follow `anykms_core::time`.
//!
//! [`get`]: CredentialCache::get
//! [`invalidate`]: CredentialCache::invalidate
//! [`SingleFlight`]: crate::cache::SingleFlight

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use anykms_core::time::{Instant, system_now};
use anykms_core::{Error, Result};

use crate::cache::{Flight, FlightId, SingleFlight, Waited};

/// Now, on tokio's clock, which paused test time moves; on `wasm32-unknown-unknown` (where
/// tokio's clock, like `std`'s, panics) the `anykms_core::time` clock: the JS host's with the
/// `js` feature, `std`'s (panicking as before) without. The predicate is the target alone, unlike
/// `anykms_core::time`'s: the feature decides what `Instant::now` reads, not whether tokio's
/// clock is usable.
fn now() -> Instant {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        tokio::time::Instant::now().into_std()
    }
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        Instant::now()
    }
}

/// A freshly fetched credential and when it expires (`None`: never).
#[derive(Clone)]
pub struct Expiring<T> {
    value: T,
    expires_at: Option<Instant>,
}

impl<T> fmt::Debug for Expiring<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Expiring")
            .field("value", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl<T> Expiring<T> {
    /// A credential expiring at `expires_at` (`None`: never).
    pub fn new(value: T, expires_at: Option<Instant>) -> Self {
        Self { value, expires_at }
    }

    /// A credential that never expires.
    pub fn never_expires(value: T) -> Self {
        Self::new(value, None)
    }

    /// A credential valid for `lifetime` from now (e.g. an OAuth `expires_in`).
    pub fn valid_for(value: T, lifetime: Duration) -> Self {
        let now = now();
        Self::new(value, Some(now.checked_add(lifetime).unwrap_or(now)))
    }

    /// A credential valid until the wall-clock time `at` (e.g. an AWS `Expiration`); a time in
    /// the past means already expired.
    pub fn valid_until(value: T, at: SystemTime) -> Self {
        let left = at.duration_since(system_now()).unwrap_or(Duration::ZERO);
        Self::valid_for(value, left)
    }

    /// The credential.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// When it expires.
    pub fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }
}

/// A credential handed out by [`CredentialCache::get`], with the generation that tells a
/// refreshed credential from the one a server rejected.
#[derive(Clone)]
pub struct Credential<T> {
    value: T,
    generation: u64,
}

impl<T> fmt::Debug for Credential<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("value", &"<redacted>")
            .field("generation", &self.generation)
            .finish()
    }
}

impl<T> Credential<T> {
    /// The credential.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns the credential.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Increases with every successful fetch (starting at 1), whether or not the fetch returned
    /// a different value (see the [module docs](self)).
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

struct Entry<T> {
    value: T,
    generation: u64,
    obtained: Instant,
    expires_at: Option<Instant>,
}

impl<T: Clone> Entry<T> {
    fn expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }

    fn refresh_due(&self, now: Instant, ahead: Duration) -> bool {
        let Some(exp) = self.expires_at else {
            return false;
        };
        let lifetime = exp.saturating_duration_since(self.obtained);
        let margin = ahead.min(lifetime / 2);
        exp.checked_sub(margin).is_none_or(|t| now >= t)
    }

    fn credential(&self) -> Credential<T> {
        Credential {
            value: self.value.clone(),
            generation: self.generation,
        }
    }
}

struct State<T> {
    current: Option<Entry<T>>,
    last_generation: u64,
    /// The last fetch failed: no early refresh before this, and without a usable credential,
    /// `last_error` until then.
    retry_at: Option<Instant>,
    /// The failure shared until `retry_at` (only kept when there was no usable credential).
    last_error: Option<Error>,
    last_forced: Option<Instant>,
    /// The flight whose outcome was recorded last: an older flight's outcome is not recorded.
    settled: Option<FlightId>,
}

/// The cache. See the [module docs](self).
pub struct CredentialCache<T> {
    state: Mutex<State<T>>,
    /// The one fetch at a time; its result is what [`get`](Self::get) returns to its waiters.
    flight: SingleFlight<(), Result<Credential<T>>>,
    /// The generation a server rejected ([`invalidate`](Self::invalidate)); 0 for none.
    rejected: AtomicU64,
    refresh_ahead: Duration,
    refresh_backoff: Duration,
    forced_interval: Duration,
}

impl<T> fmt::Debug for CredentialCache<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialCache")
            .field("refresh_ahead", &self.refresh_ahead)
            .field("refresh_backoff", &self.refresh_backoff)
            .field("forced_refresh_interval", &self.forced_interval)
            .finish_non_exhaustive()
    }
}

impl<T: Clone + Send> Default for CredentialCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Send> CredentialCache<T> {
    /// An empty cache: refresh 5 minutes ahead of expiry (at half the lifetime for credentials
    /// shorter than 10 minutes), backoff after a failed fetch 5 s, at most one forced refresh
    /// per 30 s.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                current: None,
                last_generation: 0,
                retry_at: None,
                last_error: None,
                last_forced: None,
                settled: None,
            }),
            flight: SingleFlight::new(),
            rejected: AtomicU64::new(0),
            refresh_ahead: Duration::from_mins(5),
            refresh_backoff: Duration::from_secs(5),
            forced_interval: Duration::from_secs(30),
        }
    }

    /// How long before expiry to refresh (capped at half the credential's lifetime).
    pub fn refresh_ahead(mut self, d: Duration) -> Self {
        self.refresh_ahead = d;
        self
    }

    /// How long a failed fetch is remembered: a still-valid credential is used without an early
    /// refresh, and with no usable credential the failure is returned without a fetch.
    pub fn refresh_backoff(mut self, d: Duration) -> Self {
        self.refresh_backoff = d;
        self
    }

    /// Bounds how long a caller waits for another caller's **stalled** fetch: once that fetch
    /// has been woken and left unpolled for `max` (measured with `sleep`, e.g.
    /// `tokio::time::sleep`), it fetches in that caller's place (the other waiters then wait for
    /// its fetch; see the [module docs](self) and [`SingleFlight::with_max_wait`]). A fetch that
    /// is being polled is never replaced, however long it takes. Without a bound, a fetching
    /// caller that is alive but not being polled (see [`SingleFlight`]) strands every caller
    /// that needs a credential.
    pub fn max_wait(mut self, max: Duration, sleep: anykms_core::SleepFn) -> Self {
        let flight = std::mem::take(&mut self.flight);
        self.flight = flight.with_max_wait(max, sleep);
        self
    }

    /// Takes the stall bound from `transport` ([`HttpTransport::follower_wait`](crate::HttpTransport::follower_wait))
    /// unless one is set already (see [`SingleFlight::bound_by`]). The built-in backends call it
    /// with the transport the credential is fetched with.
    pub fn bound_by(&self, transport: &dyn crate::HttpTransport) {
        self.flight.bound_by(transport);
    }

    /// The stall bound, if any.
    pub fn wait_bound(&self) -> Option<Duration> {
        self.flight.max_wait()
    }

    /// The least time between two refreshes forced by [`invalidate`](Self::invalidate), so a
    /// server that rejects every credential does not turn each request into a fetch.
    pub fn forced_refresh_interval(mut self, d: Duration) -> Self {
        self.forced_interval = d;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cached credential, or a new one from `fetch` when there is none, it expired, it is
    /// due for an early refresh, or it was [invalidated](Self::invalidate). `fetch` runs at most
    /// once at a time across all callers (a stalled fetch that was replaced aside: see
    /// the [module docs](self)), and only in a caller that found no fetch running;
    /// the others wait for that fetch's result, unless they can return a still-valid
    /// credential. A failed fetch returns a still-valid credential if there is one, else the
    /// error, which later callers get too until the backoff ends.
    pub async fn get<F, Fut>(&self, fetch: F) -> Result<Credential<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Expiring<T>>>,
    {
        // The flight this caller gave up waiting for (alive, not being polled).
        let mut stalled: Option<FlightId> = None;
        loop {
            let stalled_now = stalled.take();
            let flight = {
                let mut st = self.lock();
                let now = now();
                let rejected = st
                    .current
                    .as_ref()
                    .is_some_and(|e| e.generation == self.rejected.load(Ordering::Acquire));
                let forced = rejected
                    && st
                        .last_forced
                        .is_none_or(|t| now.saturating_duration_since(t) >= self.forced_interval);
                let backing_off = st.retry_at.is_some_and(|t| now < t);
                if !forced && let Some(e) = st.current.as_ref().filter(|e| !e.expired(now)) {
                    if rejected {
                        // Rejected, and the forced refresh was used up recently: wait for the
                        // fetch that may be replacing it, else return it (the caller then
                        // reports the rejection).
                        // A stalled fetch was waited for already: do not wait again.
                        match self.flight.follow(&()) {
                            Some(f) if Some(f.id()) != stalled_now => Flight::Follower(f),
                            _ => return Ok(e.credential()),
                        }
                    } else if backing_off || !e.refresh_due(now, self.refresh_ahead) {
                        return Ok(e.credential());
                    } else {
                        // Due for an early refresh: this caller refreshes unless another
                        // already does; either way nobody waits for it but the refreshing
                        // caller.
                        match self.flight.try_lead(&()) {
                            Some(leader) => Flight::Leader(leader),
                            None => return Ok(e.credential()),
                        }
                    }
                } else {
                    let usable = st.current.as_ref().is_some_and(|e| !e.expired(now));
                    if !usable
                        && backing_off
                        && let Some(e) = st.last_error.as_ref()
                    {
                        return Err(e.clone());
                    }
                    // The fetching caller is alive but not being polled: the first waiter to
                    // give up replaces its flight, and the others follow the replacement.
                    let flight = match stalled_now {
                        Some(id) => self.flight.take_over(&(), id),
                        None => self.flight.join(&()),
                    };
                    if forced && matches!(flight, Flight::Leader(_)) {
                        st.last_forced = Some(now);
                    }
                    flight
                }
            };
            match flight {
                Flight::Leader(leader) => {
                    let result = self.settle(leader.id(), leader.track(fetch()).await);
                    leader.finish(result.clone());
                    return result;
                }
                Flight::Follower(f) => {
                    let id = f.id();
                    match f.wait_bounded().await {
                        Waited::Done(result) => return result,
                        // The fetching caller was cancelled, or its flight was replaced: decide
                        // again (and maybe fetch).
                        Waited::Cancelled => {}
                        // The fetching caller is alive but not being polled: decide again, and
                        // replace its flight if a fetch is still needed.
                        Waited::TimedOut => stalled = Some(id),
                    }
                }
            }
        }
    }

    /// Records the outcome of flight `flight`'s fetch; returns what its caller and waiters get.
    /// A fetch started before the last recorded one (a stalled flight that was replaced, then
    /// resumed) records nothing: its credential, older and possibly revoked, never replaces a
    /// newer one, nor does its failure undo a newer success.
    fn settle(&self, flight: FlightId, result: Result<Expiring<T>>) -> Result<Credential<T>> {
        let now = now();
        let mut st = self.lock();
        if st.settled.is_some_and(|last| flight < last) {
            return Self::superseded(&st, now, result);
        }
        st.settled = Some(flight);
        match result {
            Ok(new) => {
                st.last_generation += 1;
                let entry = Entry {
                    value: new.value,
                    generation: st.last_generation,
                    obtained: now,
                    expires_at: new.expires_at,
                };
                let cred = entry.credential();
                st.current = Some(entry);
                st.retry_at = None;
                st.last_error = None;
                Ok(cred)
            }
            Err(e) => {
                st.retry_at = now.checked_add(self.refresh_backoff);
                if let Some(c) = st.current.as_ref().filter(|c| !c.expired(now)) {
                    // Still valid: keep using it rather than fail the request. A rejected one
                    // is returned too: its generation is unchanged, so the caller reports the
                    // rejection instead of retrying.
                    Ok(c.credential())
                } else {
                    st.last_error = Some(e.clone());
                    Err(e)
                }
            }
        }
    }

    /// What the caller of a superseded fetch gets: the newer credential while it is usable, else
    /// the newer failure; only when neither is left (the newer credential expired, or the cache
    /// was cleared) its own result, not recorded (under the current generation, so a rejection
    /// of it forces no refresh of its own).
    fn superseded(
        st: &State<T>,
        now: Instant,
        result: Result<Expiring<T>>,
    ) -> Result<Credential<T>> {
        if let Some(c) = st.current.as_ref().filter(|c| !c.expired(now)) {
            return Ok(c.credential());
        }
        if let Some(e) = st.last_error.as_ref() {
            return Err(e.clone());
        }
        result.map(|new| Credential {
            value: new.value,
            generation: st.last_generation,
        })
    }

    /// Reports that a server rejected `rejected` (e.g. HTTP 401): unless a newer credential is
    /// already cached, the next [`get`](Self::get) fetches a new one. Synchronous and cheap.
    pub fn invalidate(&self, rejected: &Credential<T>) {
        self.rejected
            .fetch_max(rejected.generation, Ordering::AcqRel);
    }

    /// Drops the cached credential and any remembered failure: the next [`get`](Self::get)
    /// fetches.
    #[allow(
        clippy::unused_async,
        reason = "public API: making it synchronous would be a breaking change"
    )]
    pub async fn clear(&self) {
        let mut st = self.lock();
        st.current = None;
        st.retry_at = None;
        st.last_error = None;
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Ready, ready};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use anykms_core::{Error, ErrorKind, Operation};
    use tokio::time::{advance, sleep};

    use super::*;

    fn down() -> Error {
        Error::new(ErrorKind::Unavailable, "t", Operation::Configure, "down")
    }

    #[derive(Default)]
    struct Source {
        fetches: AtomicUsize,
    }

    impl Source {
        // Ready futures: `CredentialCache::get` awaits the fetch future as soon as it creates it.
        fn ok(&self, lifetime: Option<Duration>) -> Ready<Result<Expiring<String>>> {
            let n = self.fetches.fetch_add(1, Ordering::SeqCst) + 1;
            let v = format!("token-{n}");
            ready(Ok(match lifetime {
                Some(l) => Expiring::valid_for(v, l),
                None => Expiring::never_expires(v),
            }))
        }

        fn fail(&self) -> Ready<Result<Expiring<String>>> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            ready(Err(down()))
        }

        fn count(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    /// How a fetch in [`callers`] ends: success with a lifetime (`None`: never expires) or failure.
    #[derive(Clone, Copy)]
    enum Fetch {
        Ok(Option<Duration>),
        Fail,
    }

    type Shared = (Arc<CredentialCache<String>>, Arc<Source>);

    fn shared(cache: CredentialCache<String>) -> Shared {
        (Arc::new(cache), Arc::new(Source::default()))
    }

    /// `n` concurrent callers whose fetch takes `delay` and then succeeds (`Fetch::Ok(lifetime)`) or fails
    /// (`Fetch::Fail`); each returns its result and how long it waited.
    async fn callers(
        (cache, src): &Shared,
        n: usize,
        delay: Duration,
        ok: Fetch,
    ) -> Vec<(Result<Credential<String>>, Duration)> {
        let tasks: Vec<_> = (0..n)
            .map(|_| {
                let (cache, src) = (cache.clone(), src.clone());
                tokio::spawn(async move {
                    let started = tokio::time::Instant::now();
                    let r = cache
                        .get(|| async {
                            sleep(delay).await;
                            match ok {
                                Fetch::Ok(lifetime) => src.ok(lifetime).await,
                                Fetch::Fail => src.fail().await,
                            }
                        })
                        .await;
                    (r, started.elapsed())
                })
            })
            .collect();
        let mut out = Vec::new();
        for t in tasks {
            out.push(t.await.unwrap());
        }
        out
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_cached_and_single_flight() {
        let s = shared(CredentialCache::new());
        for (r, _) in callers(&s, 16, Duration::from_millis(20), Fetch::Ok(None)).await {
            let c = r.unwrap();
            assert_eq!(c.value(), "token-1");
            assert_eq!(c.generation(), 1);
        }
        let (cache, src) = &s;
        assert_eq!(src.count(), 1);
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!(c.value(), "token-1");
        assert_eq!(src.count(), 1);
    }

    /// R-30: 8 callers on a source that fails after 1 s all get that one fetch's error after
    /// 1 s (not 1, 2 … 8 s); the failure is then returned without a fetch until the backoff
    /// ends.
    #[tokio::test(start_paused = true)]
    async fn failures_are_shared_and_cached_briefly() {
        let s = shared(CredentialCache::new());
        let started = tokio::time::Instant::now();
        for (r, waited) in callers(&s, 8, Duration::from_secs(1), Fetch::Fail).await {
            assert_eq!(r.unwrap_err().kind(), ErrorKind::Unavailable);
            assert!(waited <= Duration::from_millis(1010), "{waited:?}");
        }
        assert!(started.elapsed() <= Duration::from_millis(1010));
        let (cache, src) = &s;
        assert_eq!(src.count(), 1);
        // Within the 5 s backoff: the same error, no fetch.
        advance(Duration::from_millis(4900)).await;
        let e = cache.get(|| src.ok(None)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        assert_eq!(src.count(), 1);
        // After it: fetched again.
        advance(Duration::from_millis(200)).await;
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!(c.value(), "token-2");
        // A cleared cache forgets a failure too.
        let cache = CredentialCache::<String>::new();
        assert!(cache.get(|| src.fail()).await.is_err());
        cache.clear().await;
        assert!(cache.get(|| src.ok(None)).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_credentials_are_refetched() {
        let cache = CredentialCache::<String>::new();
        let src = Source::default();
        let c = cache.get(|| src.ok(Some(Duration::ZERO))).await.unwrap();
        assert_eq!(c.value(), "token-1");
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!(c.value(), "token-2");
        // Expired and the fetch fails: the error, not the expired credential.
        let cache = CredentialCache::<String>::new();
        cache.get(|| src.ok(Some(Duration::ZERO))).await.unwrap();
        assert!(cache.get(|| src.fail()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn refreshes_ahead_and_keeps_a_valid_credential_when_that_fails() {
        // Lifetime 200 ms: the margin is capped at half of it (100 ms).
        let cache = CredentialCache::<String>::new().refresh_backoff(Duration::from_secs(60));
        let src = Source::default();
        let lifetime = Some(Duration::from_millis(200));
        cache.get(|| src.ok(lifetime)).await.unwrap();
        assert_eq!(
            cache.get(|| src.ok(lifetime)).await.unwrap().value(),
            "token-1"
        );
        assert_eq!(src.count(), 1);
        sleep(Duration::from_millis(120)).await;
        // Due: the refresh fails, the still-valid credential is returned.
        let c = cache.get(|| src.fail()).await.unwrap();
        assert_eq!(c.value(), "token-1");
        assert_eq!(src.count(), 2);
        // Backing off: no fetch.
        let c = cache.get(|| src.fail()).await.unwrap();
        assert_eq!(c.value(), "token-1");
        assert_eq!(src.count(), 2);
        // Expired: fetched again regardless of the backoff.
        sleep(Duration::from_millis(100)).await;
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!(c.value(), "token-3");
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_ahead_success_replaces_the_credential() {
        let cache = CredentialCache::<String>::new();
        let src = Source::default();
        cache
            .get(|| src.ok(Some(Duration::from_millis(100))))
            .await
            .unwrap();
        sleep(Duration::from_millis(60)).await;
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!((c.value().as_str(), c.generation()), ("token-2", 2));
    }

    /// Starts a refresh in a task that holds it for `hold`, and returns once its fetch is
    /// running.
    async fn start_refresh(
        (cache, src): &Shared,
        hold: Duration,
    ) -> tokio::task::JoinHandle<Result<Credential<String>>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (cache, src) = (cache.clone(), src.clone());
        let task = tokio::spawn(async move {
            cache
                .get(move || async move {
                    tx.send(()).unwrap();
                    sleep(hold).await;
                    src.ok(Some(Duration::from_secs(3600))).await
                })
                .await
        });
        rx.await.unwrap();
        task
    }

    /// R-30: while one caller refreshes ahead of expiry, the others keep getting the valid
    /// credential at once, without fetching.
    #[tokio::test(start_paused = true)]
    async fn refresh_ahead_does_not_block_holders_of_a_valid_credential() {
        let s = shared(CredentialCache::new());
        let (cache, src) = &s;
        cache
            .get(|| src.ok(Some(Duration::from_secs(3600))))
            .await
            .unwrap();
        // 5 minutes before expiry: due.
        advance(Duration::from_mins(56)).await;
        let refresh = start_refresh(&s, Duration::from_secs(10)).await;
        let started = tokio::time::Instant::now();
        for _ in 0..8 {
            let c = cache.get(|| src.fail()).await.unwrap();
            assert_eq!(c.value(), "token-1");
        }
        assert_eq!(src.count(), 1);
        // No time passed: nobody waited for the 10 s refresh.
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(refresh.await.unwrap().unwrap().value(), "token-2");
        assert_eq!(cache.get(|| src.ok(None)).await.unwrap().value(), "token-2");
        assert_eq!(src.count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn invalidate_forces_one_refresh() {
        let cache = CredentialCache::<String>::new();
        let src = Source::default();
        let first = cache.get(|| src.ok(None)).await.unwrap();
        cache.invalidate(&first);
        let second = cache.get(|| src.ok(None)).await.unwrap();
        assert_ne!(second.generation(), first.generation());
        // A stale report about the first credential does not refetch.
        cache.invalidate(&first);
        assert_eq!(
            cache.get(|| src.ok(None)).await.unwrap().generation(),
            second.generation()
        );
        // The second is rejected within the interval: no fetch, same generation (the caller
        // reports the rejection instead of retrying).
        cache.invalidate(&second);
        assert_eq!(
            cache.get(|| src.ok(None)).await.unwrap().generation(),
            second.generation()
        );
        assert_eq!(src.count(), 2);
    }

    /// Concurrent callers after a 401 share one forced refresh.
    #[tokio::test(start_paused = true)]
    async fn a_forced_refresh_is_shared() {
        let s = shared(CredentialCache::new());
        let (cache, src) = &s;
        let first = cache.get(|| src.ok(None)).await.unwrap();
        cache.invalidate(&first);
        for (r, _) in callers(&s, 8, Duration::from_millis(50), Fetch::Ok(None)).await {
            assert_eq!(r.unwrap().generation(), 2);
        }
        assert_eq!(src.count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_forced_refresh_returns_the_rejected_credential() {
        let cache = CredentialCache::<String>::new();
        let src = Source::default();
        let first = cache.get(|| src.ok(None)).await.unwrap();
        cache.invalidate(&first);
        let again = cache.get(|| src.fail()).await.unwrap();
        assert_eq!(again.generation(), first.generation());
        assert_eq!(src.count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn forced_refreshes_are_rate_limited_but_allowed_after_the_interval() {
        let cache =
            CredentialCache::<String>::new().forced_refresh_interval(Duration::from_millis(30));
        let src = Source::default();
        let a = cache.get(|| src.ok(None)).await.unwrap();
        cache.invalidate(&a);
        let b = cache.get(|| src.ok(None)).await.unwrap();
        cache.invalidate(&b);
        sleep(Duration::from_millis(40)).await;
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!(c.generation(), 3);
    }

    /// R-30: cancelling the caller that fetches neither strands the waiting callers nor makes
    /// them wait out its fetch: one of them fetches, and all get that result.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_fetch_hands_over() {
        let s = shared(CredentialCache::new());
        let (cache, src) = &s;
        let leader = start_refresh(&s, Duration::from_secs(60)).await;
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let (cache, src) = (cache.clone(), src.clone());
                tokio::spawn(async move { cache.get(|| src.ok(None)).await })
            })
            .collect();
        sleep(Duration::from_millis(20)).await;
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());
        let started = tokio::time::Instant::now();
        for w in waiters {
            assert_eq!(w.await.unwrap().unwrap().value(), "token-1");
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(src.count(), 1);

        // A cancelled early refresh: the next caller to find the credential due refreshes.
        let s = shared(CredentialCache::new());
        let (cache, src) = &s;
        cache
            .get(|| src.ok(Some(Duration::from_secs(3600))))
            .await
            .unwrap();
        advance(Duration::from_mins(56)).await;
        let refresh = start_refresh(&s, Duration::from_secs(60)).await;
        refresh.abort();
        assert!(refresh.await.unwrap_err().is_cancelled());
        let c = cache.get(|| src.ok(None)).await.unwrap();
        assert_eq!((c.value().as_str(), c.generation()), ("token-2", 2));
    }

    #[tokio::test]
    async fn clear_drops_the_credential() {
        let cache = CredentialCache::<String>::new();
        let src = Source::default();
        cache.get(|| src.ok(None)).await.unwrap();
        cache.clear().await;
        assert_eq!(cache.get(|| src.ok(None)).await.unwrap().generation(), 2);
    }

    #[test]
    fn debug_redacts() {
        let e = Expiring::never_expires("secret".to_owned());
        assert!(!format!("{e:?}").contains("secret"));
        let c = Credential {
            value: "secret".to_owned(),
            generation: 1,
        };
        assert!(!format!("{c:?}").contains("secret"));
        assert!(
            Expiring::valid_until(1, SystemTime::UNIX_EPOCH)
                .expires_at()
                .unwrap()
                <= Instant::now()
        );
    }
}

/// Regression test for the security review (L29, credential path).
#[cfg(test)]
mod review_tests {
    use std::task::Poll;

    use super::*;

    /// A credential fetch whose caller is alive but never polled again must not hang every other
    /// caller that needs a credential: after the bound, a waiter fetches for itself.
    #[tokio::test(start_paused = true)]
    async fn review_l29_a_waiter_does_not_wait_forever_on_an_unpolled_fetch() {
        let cache: CredentialCache<String> = review_cache();
        let mut leader = Box::pin(cache.get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(Expiring::never_expires("slow".to_owned()))
        }));
        std::future::poll_fn(|cx| {
            assert!(leader.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let r = tokio::time::timeout(
            Duration::from_secs(120),
            cache.get(|| async { Ok(Expiring::never_expires("own".to_owned())) }),
        )
        .await
        .expect("the waiter hung on the unpolled fetch")
        .unwrap();
        assert_eq!(r.value(), "own");
        drop(leader);
    }

    /// L29, by default: a credential cache bound by the built-in transport (what every backend
    /// does) does not hang on an unpolled fetch.
    // `reqwest` alone enables no crypto provider: building the transport needs one.
    #[cfg(all(
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(start_paused = true)]
    async fn review_l29_the_builtin_transport_bounds_waiters() {
        let transport = crate::ReqwestTransport::builder()
            .require_roots(false)
            .build()
            .unwrap();
        let cache: CredentialCache<String> = CredentialCache::new();
        assert_eq!(cache.wait_bound(), None);
        cache.bound_by(&transport);
        assert_eq!(cache.wait_bound(), Some(Duration::from_secs(24)));
        let mut leader = Box::pin(cache.get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(Expiring::never_expires("slow".to_owned()))
        }));
        std::future::poll_fn(|cx| {
            assert!(leader.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let r = tokio::time::timeout(
            Duration::from_secs(120),
            cache.get(|| async { Ok(Expiring::never_expires("own".to_owned())) }),
        )
        .await
        .expect("the waiter hung on the unpolled fetch")
        .unwrap();
        assert_eq!(r.value(), "own");
        drop(leader);
    }

    /// A fetch whose caller stalled (alive, not polled) and that resumes after a waiting caller
    /// has taken over and cached a newer credential: its older, possibly revoked, credential
    /// must not replace the newer one, and its own caller gets the newer one too.
    #[tokio::test(start_paused = true)]
    async fn review_a_resumed_stalled_fetch_does_not_replace_a_newer_credential() {
        let cache: CredentialCache<String> = review_cache();
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let mut stalled = Box::pin(cache.get(|| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            gate.await.unwrap();
            Ok(Expiring::never_expires("old".to_owned()))
        }));
        std::future::poll_fn(|cx| {
            assert!(stalled.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let newer = tokio::time::timeout(
            Duration::from_secs(120),
            cache.get(|| async { Ok(Expiring::never_expires("new".to_owned())) }),
        )
        .await
        .expect("the waiter hung on the stalled fetch")
        .unwrap();
        assert_eq!((newer.value().as_str(), newer.generation()), ("new", 1));
        // The stalled caller resumes; its fetch returns the older credential.
        release.send(()).unwrap();
        let resumed = stalled.await.unwrap();
        assert_eq!(
            (resumed.value().as_str(), resumed.generation()),
            ("new", 1),
            "the superseded fetch was committed"
        );
        let now = cache
            .get(|| async { Ok(Expiring::never_expires("unexpected".to_owned())) })
            .await
            .unwrap();
        assert_eq!((now.value().as_str(), now.generation()), ("new", 1));
    }

    /// Callers waiting on a stalled fetch, joined at different times, give up together and share
    /// one replacement fetch: no burst of one fetch per waiter, and the late joiners do not wait
    /// out a bound of their own.
    #[tokio::test(start_paused = true)]
    async fn review_waiters_on_a_stalled_fetch_share_one_replacement() {
        let cache = std::sync::Arc::new(review_cache());
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Woken at 1 s, never polled again.
        let mut stalled = Box::pin(cache.get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            std::future::pending::<Result<Expiring<String>>>().await
        }));
        std::future::poll_fn(|cx| {
            assert!(stalled.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let started = tokio::time::Instant::now();
        let waiters: Vec<_> = (0..8u64)
            .map(|i| {
                let (cache, fetches) = (cache.clone(), fetches.clone());
                tokio::spawn(async move {
                    // Join at 0, 2 … 14 s.
                    tokio::time::sleep(Duration::from_secs(2 * i)).await;
                    cache
                        .get(|| async {
                            let n = fetches.fetch_add(1, Ordering::SeqCst) + 1;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            Ok(Expiring::never_expires(format!("own-{n}")))
                        })
                        .await
                })
            })
            .collect();
        let mut got = Vec::new();
        for w in waiters {
            let c = w.await.unwrap().unwrap();
            got.push((c.value().clone(), c.generation()));
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "{got:?}");
        assert!(got.iter().all(|g| *g == ("own-1".to_owned(), 1)), "{got:?}");
        // The waiter that joined at 2 s found the fetch woken already and still unpolled one
        // bound (30 s) later; then the replacement fetch (1 s).
        assert_eq!(started.elapsed(), Duration::from_secs(33));
        drop(stalled);
    }

    /// A fetch whose caller keeps polling it is never replaced, however long it takes: here ten
    /// 10 s steps (each woken and polled at once), over three times the 30 s bound. Every caller,
    /// whenever it came, gets that fetch's credential.
    #[tokio::test(start_paused = true)]
    async fn review_a_slow_fetch_that_is_polled_is_never_replaced() {
        let cache = std::sync::Arc::new(review_cache());
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = tokio::time::Instant::now();
        let callers: Vec<_> = (0..8u64)
            .map(|i| {
                let (cache, fetches) = (cache.clone(), fetches.clone());
                tokio::spawn(async move {
                    // The fetching caller at 0 s, waiters at 12, 24 … 84 s.
                    tokio::time::sleep(Duration::from_secs(12 * i)).await;
                    cache
                        .get(|| async {
                            let n = fetches.fetch_add(1, Ordering::SeqCst) + 1;
                            for _ in 0..10 {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            }
                            Ok(Expiring::never_expires(format!("slow-{n}")))
                        })
                        .await
                })
            })
            .collect();
        for c in callers {
            let c = c.await.unwrap().unwrap();
            assert_eq!((c.value().as_str(), c.generation()), ("slow-1", 1));
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::from_secs(100));
    }

    fn review_cache() -> CredentialCache<String> {
        CredentialCache::new().max_wait(
            Duration::from_secs(30),
            std::sync::Arc::new(|d| Box::pin(tokio::time::sleep(d))),
        )
    }
}
