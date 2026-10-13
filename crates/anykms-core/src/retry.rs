//! The [`Retry`] decorator: bounded retries with exponential backoff and equal jitter.
//!
//! - Backoff: the n-th retry waits between half and all of `min(base * 2^(n-1), cap)` ("equal
//!   jitter"). Unlike full jitter (anywhere from zero), this guarantees a minimum total wait, so
//!   the defaults reliably span a leader step-down: on Vault 1.20/2.1 and OpenBao 2.4 a step-down
//!   left the whole cluster unavailable for up to about 6 s (measured with
//!   `scripts/probe-failover.sh`). The 5 retries of the default policy wait 4.65 to 9.3 s in
//!   total. A hard failover (the active node dies) took 8 to 22 s, beyond the defaults; tune raft
//!   timing on the server or raise `max_attempts` where that matters.
//!
//! - Only errors with [`Error::is_retryable`] are retried, plus, opt-in
//!   ([`RetryPolicy::retry_on_hint`]), one retry of an error carrying a backend's
//!   [`retry_hint`](Error::retry_hint) (e.g. transit replica lag), waiting at least the hint.
//!   Hints are capped like `Retry-After`: one above the cap or past the deadline is not honored
//!   and the error is returned unchanged.
//! - A server's `Retry-After` is a *floor* over the normal backoff: the retry waits for the longer
//!   of the jittered exponential delay and `Retry-After` plus a random extra of up to `base` (so
//!   clients throttled together do not retry in lockstep). `Retry-After: 0` therefore never
//!   shortens the schedule. If it is above the cap or the wait would pass the remaining deadline,
//!   a [`Throttled`](crate::ErrorKind::Throttled) error carrying the `Retry-After` value (and the
//!   original error as its source) is returned at once instead of sleeping. Values above one day
//!   are treated as one day.
//! - Attempts, an overall deadline and a retry budget (a token bucket: at most `budget_ratio` of
//!   requests may be retries) protect the backend from retry storms. Each [`RetryLayer`] has its
//!   own budget, shared by everything it wraps; to cap retries per *backend* across layers,
//!   share one [`RetryBudget`] with [`RetryLayer::with_budget`]. Backends do not retry
//!   internally (see [`Provider`](crate::Provider)), and a handle takes at most one retrying
//!   layer, so attempts do not multiply.
//! - Runtime-agnostic: the caller supplies the sleep function and, optionally, the clock that
//!   measures the deadline (the `anykms` facade provides tokio ones, so tests with paused tokio
//!   time run the whole schedule instantly).
//!
//! # Handles and layers
//!
//! A [`RetryLayer`] holds the configuration (policy, sleep, clock, budget) and is the one entry
//! point, applied in one of two ways:
//!
//! - **Registries and opaque handles:** as a [`Layer`], preferably on the registry
//!   (`Registry::builder().layer(retry)`, [`RegistryBuilder::layer`](crate::RegistryBuilder::layer))
//!   so every handle it opens retries with one budget, or on one handle (`key.layer(&retry)`). It
//!   wraps each part of the handle separately, so the result is the same handle type with the
//!   same optional parts. A handle takes at most one retrying layer: applying another to a handle
//!   that already retries (e.g. one opened from a retrying registry) returns it unchanged, so
//!   attempts never multiply; `key.replace_retry(&retry)` swaps the policy of one handle
//!   instead.
//! - **Typed handles** (e.g. `TransitAeadKey`): [`RetryLayer::wrap`] returns the [`Retry<T>`]
//!   decorator, which implements every capability trait `T` has. Do not wrap opaque handles this
//!   way: `Retry<AeadKey>` would claim `Rewrap` and `DataKeys` whether or not the key has them,
//!   and would retry on top of any layer the handle already has. Wrapping a `Retry` again nests
//!   the retries; nothing prevents that at the type level, so wrap each typed handle once.
//!
//! # Testing
//!
//! [`RetryPolicy::immediate`] retries without delays; [`instant_sleep`] skips the sleeps of any
//! policy. With a recorded sleep function, inject a matching clock ([`RetryLayer::with_clock`]) so
//! the deadline follows the simulated time instead of the wall clock.
//!
//! # Deadline scope
//!
//! The overall deadline bounds the *retry schedule*, not an attempt in flight: it is checked
//! before each sleep, and a retry is skipped when the backoff would end past the deadline. Being
//! runtime-agnostic, `Retry` has no timer with which to cancel a running attempt, so a slow
//! attempt can overrun the deadline by up to its own duration. Bound each attempt with the HTTP
//! client's per-request timeout (transit has one), or wrap the call in your runtime's timeout
//! (e.g. `tokio::time::timeout`) for a hard limit.
//!
//! # Tracing
//!
//! With the `tracing` feature, each retry is an `info` event `anykms retry` with `attempt` (the
//! number of the call that failed: 1 for the first), `error_kind`, `backend`, `op`,
//! `retry_after_ms`, `retry_hint_ms` and `delay_ms`. This `attempt` counts operation calls; the
//! `attempt` field of the HTTP backends' request spans is different: it counts the sends within
//! one call (2 after a credential refresh), and each retried call is a new request span.
//!
//! Data-plane operations are safe to retry when transit upsert is disabled (see the transit docs).

use std::fmt;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::around::{Around, Call, CallCx, CallOutput};
use crate::dynamic::*;
use crate::error::{Error, ErrorKind, Result};
use crate::traits::*;
use crate::types::*;

/// Sleeps for the given duration (e.g. `tokio::time::sleep`).
pub type SleepFn = Arc<dyn Fn(Duration) -> BoxFuture<'static, ()> + Send + Sync>;

/// A [`SleepFn`] that returns at once, for tests: retries happen back to back.
pub fn instant_sleep() -> SleepFn {
    Arc::new(|_| Box::pin(async {}))
}

/// A monotonic clock: the time elapsed since an arbitrary, fixed origin. [`Retry`] only
/// subtracts two readings, to enforce [`RetryPolicy::deadline`].
///
/// Inject one that matches the [`SleepFn`] (e.g. tokio's clock with `tokio::time::sleep`, so
/// paused test time drives both), or one that never calls `std::time::Instant::now`, which
/// panics on `wasm32-unknown-unknown`.
pub type ClockFn = Arc<dyn Fn() -> Duration + Send + Sync>;

/// The default [`ClockFn`]: `std::time::Instant`, measured from the first reading in the process.
pub fn std_clock() -> ClockFn {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    Arc::new(|| ORIGIN.get_or_init(Instant::now).elapsed())
}

/// Retry-After values and retry hints above this are treated as this (and then exceed any sane
/// cap).
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Retry limits.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct RetryPolicy {
    /// Initial backoff (default 300 ms).
    pub base: Duration,
    /// Maximum backoff (default 5 s).
    pub cap: Duration,
    /// Maximum attempts including the first (default 6).
    pub max_attempts: u32,
    /// Overall deadline across attempts (default 15 s). Checked before each backoff sleep; it does
    /// not interrupt an attempt in flight (see the [module docs](self#deadline-scope)).
    pub deadline: Duration,
    /// Fraction of requests that may be retries (default 0.1). Configures the budget a
    /// [`RetryLayer`] creates for itself; ignored when a shared budget is set with [`RetryLayer::with_budget`].
    pub budget_ratio: f64,
    /// Token-bucket capacity for retries (default 10). Like `budget_ratio`, ignored with a
    /// shared budget.
    pub budget_cap: f64,
    /// Allow one retry of an error whose kind is not retryable but which carries a
    /// [`retry_hint`](Error::retry_hint) (default off). The retry waits like one after a
    /// `Retry-After` of the hint: at least the hint, never less than the normal backoff. A hint
    /// above `cap` (or one whose wait would pass the deadline) is not honored: the error is
    /// returned unchanged, as it is when a second hinted error follows the hinted retry.
    ///
    /// Backends hint where the permanent and the transient condition look the same (transit
    /// "not found" on a lagging replica), so when enabled a genuine failure of that kind (a key
    /// that really does not exist) costs one extra delay.
    ///
    /// The hinted retry is an ordinary attempt: it counts towards `max_attempts` (so with
    /// `max_attempts == 1` there is none), spends a budget token and must fit in the deadline.
    pub retry_on_hint: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(300),
            cap: Duration::from_secs(5),
            max_attempts: 6,
            deadline: Duration::from_secs(15),
            budget_ratio: 0.1,
            budget_cap: 10.0,
            retry_on_hint: false,
        }
    }
}

impl RetryPolicy {
    /// Sets the maximum number of attempts.
    pub fn with_max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n.max(1);
        self
    }

    /// Sets base and cap backoff.
    pub fn with_backoff(mut self, base: Duration, cap: Duration) -> Self {
        self.base = base;
        self.cap = cap.max(base);
        self
    }

    /// Sets the overall deadline.
    pub fn with_deadline(mut self, d: Duration) -> Self {
        self.deadline = d;
        self
    }

    /// Sets the retry budget.
    pub fn with_budget(mut self, ratio: f64, cap: f64) -> Self {
        self.budget_ratio = ratio.max(0.0);
        self.budget_cap = cap.max(0.0);
        self
    }

    /// Enables the retry of hinted errors ([`retry_on_hint`](Self::retry_on_hint)).
    pub fn with_retry_on_hint(mut self, enabled: bool) -> Self {
        self.retry_on_hint = enabled;
        self
    }

    /// A policy for request paths (an HTTP handler waiting on the KMS): 3 attempts, backoff from
    /// 50 ms up to 500 ms, a 2 s deadline, and the default budget. A backend that fails fast then
    /// costs a request about 2 s instead of the default policy's 15 s.
    ///
    /// The deadline bounds the retry schedule, not an attempt in flight (see
    /// [Deadline scope](self#deadline-scope)). The worst case is the deadline plus one attempt
    /// that started before it, which lasts up to the provider's `request_timeout` (10 s by default
    /// on the HTTP backends), plus any wait for credentials: a server that accepts the connection
    /// and never answers takes about 10 s, not 2 s. To bound a request, lower the provider's
    /// `request_timeout` or wrap the call in your runtime's timeout (e.g. `tokio::time::timeout`).
    ///
    /// The deadline must leave room for any wait the policy is meant to cover: with
    /// [`with_retry_on_hint`](Self::with_retry_on_hint) around a `CachedVerifier`, the hinted
    /// retry waits out the verifier's refresh interval (500 ms by default) plus backoff, which
    /// fits; raise the deadline if you lengthen that interval.
    pub fn interactive() -> Self {
        Self {
            base: Duration::from_millis(50),
            cap: Duration::from_millis(500),
            max_attempts: 3,
            deadline: Duration::from_secs(2),
            ..Self::default()
        }
    }

    /// A policy for tests: the default number of attempts with no delays at all (zero backoff)
    /// and a budget that never runs out in a test, so failure injection runs in microseconds
    /// whatever the sleep function. The sleep function is still called (with zero), so a
    /// recording sleep sees every retry. A non-zero `Retry-After` or retry hint exceeds the zero
    /// cap, so such errors are returned at once, as with any policy whose cap they exceed.
    ///
    /// Not for production: retrying without backoff hammers a struggling backend.
    pub fn immediate() -> Self {
        Self {
            base: Duration::ZERO,
            cap: Duration::ZERO,
            budget_ratio: 1.0,
            budget_cap: 1_000_000.0,
            ..Self::default()
        }
    }

    /// Sanitizes values that would disable the budget or overflow (fields are public).
    fn sanitized(mut self) -> Self {
        if !self.budget_ratio.is_finite() || self.budget_ratio < 0.0 {
            self.budget_ratio = 0.0;
        }
        if !self.budget_cap.is_finite() || self.budget_cap < 0.0 {
            self.budget_cap = 0.0;
        }
        self.max_attempts = self.max_attempts.max(1);
        self.cap = self.cap.max(self.base);
        self
    }
}

/// A retry budget: a token bucket in which every request deposits `ratio` tokens (up to `cap`)
/// and every retry spends one, so at most about `ratio` of requests are retries.
///
/// Cheap to clone; clones share the bucket. Give every handle that talks to one backend the same
/// budget (with [`RetryLayer::with_budget`]) to bound retries per backend rather than per handle.
#[derive(Clone)]
pub struct RetryBudget {
    inner: Arc<BudgetInner>,
}

struct BudgetInner {
    tokens: Mutex<f64>,
    ratio: f64,
    cap: f64,
}

impl RetryBudget {
    /// A full budget. Negative or non-finite values are treated as zero (no retries).
    pub fn new(ratio: f64, cap: f64) -> Self {
        let sane = |v: f64| if v.is_finite() && v > 0.0 { v } else { 0.0 };
        let cap = sane(cap);
        Self {
            inner: Arc::new(BudgetInner {
                tokens: Mutex::new(cap),
                ratio: sane(ratio),
                cap,
            }),
        }
    }

    /// The budget described by a policy's `budget_ratio` and `budget_cap`.
    pub fn from_policy(policy: &RetryPolicy) -> Self {
        Self::new(policy.budget_ratio, policy.budget_cap)
    }

    fn tokens(&self) -> std::sync::MutexGuard<'_, f64> {
        self.inner.tokens.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn deposit(&self) {
        let mut t = self.tokens();
        *t = (*t + self.inner.ratio).min(self.inner.cap);
    }

    fn withdraw(&self) -> bool {
        let mut t = self.tokens();
        if *t < 1.0 {
            return false;
        }
        *t -= 1.0;
        true
    }
}

impl Default for RetryBudget {
    /// The default policy's budget: ratio 0.1, capacity 10.
    fn default() -> Self {
        Self::from_policy(&RetryPolicy::default())
    }
}

impl fmt::Debug for RetryBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryBudget")
            .field("ratio", &self.inner.ratio)
            .field("cap", &self.inner.cap)
            .field("tokens", &*self.tokens())
            .finish()
    }
}

/// The retry configuration: policy, sleep function, clock and budget. Cheap to clone; clones
/// share the budget.
///
/// As a [`Layer`] it retries every part of an opaque handle (for every handle a registry
/// opens with [`RegistryBuilder::layer`](crate::RegistryBuilder::layer), or for one handle with
/// `key.layer(&retry)`), keeping the handle's type and optional parts; all parts, and all
/// handles given the same layer, share one budget. A handle that already retries is left
/// unchanged ([`Layer::retries`]). [`wrap`](Self::wrap) decorates a typed handle instead. See
/// the [module docs](self#handles-and-layers).
#[derive(Clone)]
pub struct RetryLayer {
    policy: RetryPolicy,
    sleep: SleepFn,
    clock: ClockFn,
    budget: RetryBudget,
    shared_budget: bool,
}

impl fmt::Debug for RetryLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryLayer")
            .field("policy", &self.policy)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl RetryLayer {
    /// The default policy, sleeping with `sleep` and measuring the deadline with [`std_clock`].
    pub fn new(sleep: SleepFn) -> Self {
        let policy = RetryPolicy::default();
        Self {
            budget: RetryBudget::from_policy(&policy),
            policy,
            sleep,
            clock: std_clock(),
            shared_budget: false,
        }
    }

    /// Uses `policy` (sanitized). Unless a budget was set with
    /// [`with_budget`](Self::with_budget), the budget is replaced by a fresh one from the
    /// policy's `budget_ratio` and `budget_cap`.
    pub fn with_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy.sanitized();
        if !self.shared_budget {
            self.budget = RetryBudget::from_policy(&self.policy);
        }
        self
    }

    /// Uses `budget` (typically shared with other layers or handles of the same backend); the
    /// policy's `budget_ratio` and `budget_cap` are then ignored.
    pub fn with_budget(mut self, budget: RetryBudget) -> Self {
        self.budget = budget;
        self.shared_budget = true;
        self
    }

    /// Measures the deadline with `clock` instead of [`std_clock`].
    pub fn with_clock(mut self, clock: ClockFn) -> Self {
        self.clock = clock;
        self
    }

    /// The policy.
    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }

    /// The retry budget.
    pub fn budget(&self) -> &RetryBudget {
        &self.budget
    }

    /// Retries the typed handle `inner` with this configuration, sharing this layer's budget.
    ///
    /// For opaque handles ([`AeadKey`], ...) apply the layer instead (`key.layer(&retry)`), which
    /// keeps the handle type and never nests retries.
    pub fn wrap<T>(&self, inner: T) -> Retry<T> {
        Retry {
            inner,
            cfg: self.clone(),
        }
    }
}

impl crate::Layer for RetryLayer {
    fn retries(&self) -> bool {
        true
    }

    /// Every part's operations, as [`Call`]s, retried by this layer's policy and budget.
    fn part(&self, cx: &crate::LayerCx<'_>, part: Part<'_>) {
        part.wrap_around(cx, Arc::new(self.clone()));
    }
}

/// Retries each call with the layer's policy and budget: one [`Call::run`] per attempt.
impl Around for RetryLayer {
    fn around<'a>(&'a self, _: &'a CallCx, call: Call<'a>) -> BoxFuture<'a, Result<CallOutput>> {
        Box::pin(async move { self.wrap(()).run(|| call.run()).await })
    }
}

/// Wraps a typed handle and retries its operations; created with [`RetryLayer::wrap`].
/// Implements the same traits as the inner handle. Clones, and every `Retry` from the same
/// [`RetryLayer`], share the retry budget.
///
/// For opaque handles ([`AeadKey`], ...) apply the [`RetryLayer`] as a layer instead:
/// `Retry<AeadKey>` implements `Rewrap` and `DataKeys` even when the key lacks them (see the
/// [module docs](self#handles-and-layers)).
///
/// The policy's deadline bounds the retry schedule only; an attempt in flight is not cancelled
/// (see the [module docs](self#deadline-scope)).
#[non_exhaustive]
#[derive(Clone)]
pub struct Retry<T> {
    inner: T,
    cfg: RetryLayer,
}

impl<T: fmt::Debug> fmt::Debug for Retry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retry")
            .field("inner", &self.inner)
            .field("policy", &self.cfg.policy)
            .field("budget", &self.cfg.budget)
            .finish()
    }
}

impl<T> Retry<T> {
    /// The retry budget.
    pub fn budget(&self) -> &RetryBudget {
        &self.cfg.budget
    }

    /// The policy.
    pub fn policy(&self) -> &RetryPolicy {
        &self.cfg.policy
    }

    /// The wrapped handle.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Retries a backend-specific operation of the wrapped handle with this decorator's policy
    /// and budget: `f` starts one attempt and is called again for each retry. The typed
    /// counterpart of the opaque handles' `call_extension` (e.g.
    /// [`AeadKey::call_extension`]), for a backend's extension trait on `Retry<TheirKey>`:
    ///
    /// ```
    /// # use anykms_core::*;
    /// struct NativeKey;
    /// impl NativeKey {
    ///     async fn encrypt_with_context(&self, pt: &[u8], ctx: &str) -> Result<Ciphertext> {
    ///         Ok(Ciphertext::from_bytes([pt, ctx.as_bytes()].concat()))
    ///     }
    /// }
    /// # async fn demo() -> Result<()> {
    /// let key = RetryLayer::new(instant_sleep()).wrap(NativeKey);
    /// let ct = key.call(|| key.inner().encrypt_with_context(b"pt", "ctx")).await?;
    /// # Ok(()) }
    /// ```
    pub async fn call<R, Fut>(&self, f: impl FnMut() -> Fut) -> Result<R>
    where
        Fut: Future<Output = Result<R>>,
    {
        self.run(f).await
    }

    fn random_fraction(&self, salt: u32) -> f64 {
        random_fraction(salt, (self.cfg.clock)())
    }

    fn jitter(&self, attempt: u32) -> Duration {
        let exp = self.cfg.policy.base.saturating_mul(
            1u32.checked_shl(attempt.saturating_sub(1))
                .unwrap_or(u32::MAX),
        );
        let ceiling = exp.min(self.cfg.policy.cap);
        (ceiling / 2).saturating_add(fraction_of(ceiling / 2, self.random_fraction(attempt)))
    }

    /// The wait for a server's `Retry-After`: the normal jittered backoff, raised to at least the
    /// `Retry-After` plus a random extra of up to `base` (to spread out clients throttled at the
    /// same moment). Never shorter than either.
    fn after_retry_after(&self, retry_after: Duration, attempt: u32) -> Duration {
        let spread = fraction_of(
            self.cfg.policy.base,
            self.random_fraction(attempt ^ 0x5bd1_e995),
        );
        retry_after
            .min(MAX_RETRY_AFTER)
            .saturating_add(spread)
            .max(self.jitter(attempt))
    }

    async fn run<R, Fut>(&self, mut f: impl FnMut() -> Fut) -> Result<R>
    where
        Fut: Future<Output = Result<R>>,
    {
        let p = &self.cfg.policy;
        let start = (self.cfg.clock)();
        self.cfg.budget.deposit();
        let mut attempt = 1;
        let mut hint_used = false;
        loop {
            let e: Error = match f().await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let hint = match e.retry_hint() {
                Some(h) if p.retry_on_hint && !hint_used && !e.is_retryable() => Some(h),
                _ => None,
            };
            if !(e.is_retryable() || hint.is_some()) || attempt >= p.max_attempts {
                return Err(e);
            }
            let delay = if let Some(h) = hint {
                if h.min(MAX_RETRY_AFTER) > p.cap {
                    return Err(e);
                }
                hint_used = true;
                self.after_retry_after(h, attempt)
            } else if let Some(ra) = e.retry_after() {
                if ra.min(MAX_RETRY_AFTER) > p.cap {
                    return Err(throttled_by_retry_after(e, ra));
                }
                self.after_retry_after(ra, attempt)
            } else {
                self.jitter(attempt)
            };
            let elapsed = (self.cfg.clock)().saturating_sub(start);
            match elapsed.checked_add(delay) {
                Some(end) if end <= p.deadline => {}
                _ => {
                    return Err(match e.retry_after() {
                        Some(ra) if hint.is_none() => throttled_by_retry_after(e, ra),
                        _ => e,
                    });
                }
            }
            if !self.cfg.budget.withdraw() {
                return Err(e);
            }
            #[cfg(feature = "tracing")]
            tracing::info!(
                attempt,
                error_kind = e.kind().as_str(),
                backend = e.backend(),
                op = e.operation().as_str(),
                retry_after_ms = e.retry_after().map(|d| d.as_millis() as u64),
                retry_hint_ms = hint.map(|d| d.as_millis() as u64),
                delay_ms = delay.as_millis() as u64,
                "anykms retry"
            );
            (self.cfg.sleep)(delay).await;
            attempt += 1;
        }
    }
}

/// `d * f` for `f` in `[0, 1)`, never more than `d` and never panicking.
fn fraction_of(d: Duration, f: f64) -> Duration {
    Duration::try_from_secs_f64(d.as_secs_f64() * f)
        .unwrap_or(d)
        .min(d)
}

/// A uniformly distributed value in `[0, 1)` from `RandomState`'s keys, `salt`, a process-wide
/// call counter and `now`.
///
/// `RandomState` alone is not enough everywhere: on targets without OS randomness
/// (`wasm32-unknown-unknown`) its keys are fixed, so every client would compute the same jitter
/// sequence and retry in lockstep. The counter separates calls within a process and `now` (the
/// layer's clock, which differs between clients by when they started and failed) separates
/// processes.
fn random_fraction(salt: u32, now: Duration) -> f64 {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    let mut h = std::hash::RandomState::new().build_hasher();
    h.write_u32(salt);
    h.write_u64(CALLS.fetch_add(1, Ordering::Relaxed));
    h.write_u128(now.as_nanos());
    (h.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// The error returned when a server's `Retry-After` cannot be honored within the policy: a
/// `Throttled` error that keeps the `Retry-After` value, backend, operation, resource and detail,
/// with the original error as its source. An error that is already `Throttled` is returned
/// unchanged.
fn throttled_by_retry_after(e: Error, retry_after: Duration) -> Error {
    if e.kind() == ErrorKind::Throttled {
        return e;
    }
    let mut t = Error::new(
        ErrorKind::Throttled,
        e.backend(),
        e.operation(),
        "server Retry-After exceeds the retry cap or deadline",
    )
    .with_retry_after(retry_after);
    if let Some(d) = e.detail() {
        t = t.with_detail(d.clone());
    }
    if let Some(r) = e.resource() {
        t = t.with_resource(r);
    }
    t.with_source(e)
}

impl<T: Aead> Aead for Retry<T> {
    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
        self.run(|| self.inner.encrypt(plaintext, aad)).await
    }

    async fn decrypt(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.run(|| self.inner.decrypt(ct, aad)).await
    }

    fn ciphertext_version(&self, ct: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.inner.ciphertext_version(ct)
    }

    async fn decrypt_with_info(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Decrypted> {
        self.run(|| self.inner.decrypt_with_info(ct, aad)).await
    }
}

impl<T: Rewrap> Rewrap for Retry<T> {
    async fn rewrap(&self, ct: &Ciphertext, aad: &[u8]) -> Result<Ciphertext> {
        self.run(|| self.inner.rewrap(ct, aad)).await
    }
}

impl<T: DataKeys> DataKeys for Retry<T> {
    async fn generate_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<DataKey> {
        self.run(|| self.inner.generate_data_key(spec, aad)).await
    }
}

/// Each attempt runs the call again ([`Call::run`] through the inner slot).
impl<T: ExtensionCalls> ExtensionCalls for Retry<T> {
    async fn run_extension(&self, call: Call<'_>) -> Result<CallOutput> {
        self.run(|| self.inner.run_extension(call)).await
    }
}

impl<T: WrappedDataKeys> WrappedDataKeys for Retry<T> {
    async fn generate_wrapped_data_key(&self, spec: DataKeySpec, aad: &[u8]) -> Result<Ciphertext> {
        self.run(|| self.inner.generate_wrapped_data_key(spec, aad))
            .await
    }
}

impl<T: DigestSigner> DigestSigner for Retry<T> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.inner.signature_algorithm()
    }

    async fn sign_digest(&self, digest: &Digest) -> Result<Signature> {
        self.run(|| self.inner.sign_digest(digest)).await
    }
}

impl<T: MessageSigner> MessageSigner for Retry<T> {
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.inner.signature_algorithm()
    }

    async fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        self.run(|| self.inner.sign_message(msg)).await
    }
}

/// Forwards: retrying changes no behavior that [`KeySemantics`](crate::KeySemantics) describes.
impl<T: crate::Semantics> crate::Semantics for Retry<T> {
    fn semantics(&self) -> Option<&crate::KeySemantics> {
        self.inner.semantics()
    }
}

impl<T: PinnedVerifier> PinnedVerifier for Retry<T> {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.inner.pinned_algorithm()
    }
}

impl<T: DigestVerifier> DigestVerifier for Retry<T> {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        self.run(|| self.inner.verify_digest(digest, sig)).await
    }
}

impl<T: MessageVerifier> MessageVerifier for Retry<T> {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.run(|| self.inner.verify_message(msg, sig)).await
    }
}

impl<T: Mac> Mac for Retry<T> {
    fn mac_algorithm(&self) -> MacAlgorithm {
        self.inner.mac_algorithm()
    }

    async fn mac(&self, data: &[u8]) -> Result<Tag> {
        self.run(|| self.inner.mac(data)).await
    }

    async fn verify_mac(&self, data: &[u8], tag: &Tag) -> Result<()> {
        self.run(|| self.inner.verify_mac(data, tag)).await
    }
}

impl<T: PublicKeys> PublicKeys for Retry<T> {
    async fn public_key(&self) -> Result<PublicKey> {
        self.run(|| self.inner.public_key()).await
    }

    async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
        self.run(|| self.inner.public_key_version(version)).await
    }
}

impl<T: Describe> Describe for Retry<T> {
    async fn describe(&self) -> Result<KeyInfo> {
        self.run(|| self.inner.describe()).await
    }
}

impl<T: Preflight> Preflight for Retry<T> {
    async fn preflight(&self) -> Result<KeyInfo> {
        self.run(|| self.inner.preflight()).await
    }
}

impl<T: KeyWrap> KeyWrap for Retry<T> {
    async fn wrap_key(&self, key: &[u8]) -> Result<Ciphertext> {
        self.run(|| self.inner.wrap_key(key)).await
    }

    async fn unwrap_key(&self, wrapped: &Ciphertext) -> Result<Zeroizing<Vec<u8>>> {
        self.run(|| self.inner.unwrap_key(wrapped)).await
    }

    fn wrapped_key_version(&self, wrapped: &Ciphertext) -> Result<Option<KeyVersion>> {
        self.inner.wrapped_key_version(wrapped)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::{BackendDetail, Operation};

    /// Jitter does not repeat between calls with the same salt and clock reading (a fixed
    /// `RandomState`, as on wasm, would make it repeat), and spans `[0, 1)`.
    #[test]
    fn jitter_varies_between_calls_and_clocks() {
        let now = Duration::from_millis(1234);
        let a: Vec<f64> = (0..64).map(|_| random_fraction(1, now)).collect();
        assert!(a.iter().all(|f| (0.0..1.0).contains(f)));
        let distinct = a
            .iter()
            .map(|f| f.to_bits())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(distinct.len() > 60, "{}", distinct.len());
        assert_ne!(
            random_fraction(1, Duration::from_millis(1)),
            random_fraction(1, Duration::from_millis(2))
        );
    }

    #[test]
    fn interactive_policy_bounds_a_request() {
        let p = RetryPolicy::interactive();
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.deadline, Duration::from_secs(2));
        assert!(p.cap <= Duration::from_millis(500) && p.base <= p.cap);
        // It survives sanitizing unchanged.
        assert_eq!(p.clone().sanitized(), p);
    }

    struct Flaky {
        calls: AtomicU32,
        fail: u32,
        err: fn() -> Error,
    }

    impl Aead for Flaky {
        async fn encrypt(&self, _: &[u8], _: &[u8]) -> Result<Ciphertext> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail {
                Err((self.err)())
            } else {
                Ok(Ciphertext::from_bytes(vec![1]))
            }
        }
        async fn decrypt(&self, _: &Ciphertext, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(vec![]))
        }
    }

    fn retry<T>(inner: T, sleep: SleepFn) -> Retry<T> {
        RetryLayer::new(sleep).wrap(inner)
    }

    fn retry_with<T>(inner: T, sleep: SleepFn, policy: RetryPolicy) -> Retry<T> {
        RetryLayer::new(sleep).with_policy(policy).wrap(inner)
    }

    fn recorded() -> (SleepFn, Arc<Mutex<Vec<Duration>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let f: SleepFn = Arc::new(move |d| {
            l.lock().unwrap().push(d);
            Box::pin(async {})
        });
        (f, log)
    }

    fn throttled() -> Error {
        Error::new(ErrorKind::Throttled, "t", Operation::Encrypt, "x")
    }

    fn flaky(fail: u32, err: fn() -> Error) -> Flaky {
        Flaky {
            calls: AtomicU32::new(0),
            fail,
            err,
        }
    }

    #[tokio::test]
    async fn retries_retryable_up_to_max_attempts() {
        let (s, log) = recorded();
        let r = retry(flaky(2, throttled), s);
        assert!(r.encrypt(b"", b"").await.is_ok());
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 3);
        assert_eq!(log.lock().unwrap().len(), 2);
        let (s, _) = recorded();
        let r = retry(flaky(10, throttled), s);
        assert_eq!(
            r.encrypt(b"", b"").await.unwrap_err().kind(),
            ErrorKind::Throttled
        );
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn does_not_retry_permanent_errors() {
        let (s, log) = recorded();
        let r = retry(
            flaky(1, || {
                Error::new(ErrorKind::DecryptFailed, "t", Operation::Decrypt, "x")
            }),
            s,
        );
        assert!(r.encrypt(b"", b"").await.is_err());
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retry_after_is_a_clamped_minimum() {
        let (s, log) = recorded();
        let r = retry(flaky(1, || throttled().with_retry_after(Duration::ZERO)), s);
        r.encrypt(b"", b"").await.unwrap();
        let d = log.lock().unwrap()[0];
        assert!(
            (Duration::from_millis(150)..=Duration::from_millis(300)).contains(&d),
            "Retry-After: 0 keeps the normal first backoff: {d:?}"
        );
        let (s, log) = recorded();
        let r = retry(
            flaky(1, || throttled().with_retry_after(Duration::from_secs(30))),
            s,
        );
        assert_eq!(
            r.encrypt(b"", b"").await.unwrap_err().kind(),
            ErrorKind::Throttled
        );
        assert!(
            log.lock().unwrap().is_empty(),
            "Retry-After above the cap fails fast"
        );
    }

    #[tokio::test]
    async fn unhonorable_retry_after_becomes_throttled() {
        fn unavailable_after(secs: u64) -> Error {
            Error::new(ErrorKind::Unavailable, "t", Operation::Decrypt, "x")
                .with_retry_after(Duration::from_secs(secs))
                .with_detail(BackendDetail::new().with_http_status(503))
        }
        fn check(e: Error, secs: u64) {
            assert_eq!(e.kind(), ErrorKind::Throttled);
            assert_eq!(e.retry_after(), Some(Duration::from_secs(secs)));
            assert_eq!(e.operation(), Operation::Decrypt);
            assert_eq!(e.backend(), "t");
            assert_eq!(e.detail().and_then(|d| d.http_status), Some(503));
            let src = std::error::Error::source(&e)
                .and_then(|s| s.downcast_ref::<Error>())
                .expect("original error kept as source");
            assert_eq!(src.kind(), ErrorKind::Unavailable);
        }

        // Above the cap (5 s).
        let (s, log) = recorded();
        let r = retry(flaky(1, || unavailable_after(30)), s);
        check(r.encrypt(b"", b"").await.unwrap_err(), 30);
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
        assert!(log.lock().unwrap().is_empty());

        // Within the cap but past the deadline.
        let (s, log) = recorded();
        let r = retry_with(
            flaky(1, || unavailable_after(3)),
            s,
            RetryPolicy::default().with_deadline(Duration::from_secs(1)),
        );
        check(r.encrypt(b"", b"").await.unwrap_err(), 3);
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
        assert!(log.lock().unwrap().is_empty());

        // Within cap and deadline: retried after the Retry-After delay plus jitter below base.
        let (s, log) = recorded();
        let r = retry(flaky(1, || unavailable_after(2)), s);
        assert!(r.encrypt(b"", b"").await.is_ok());
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert!(
            (Duration::from_secs(2)..Duration::from_millis(2300)).contains(&log[0]),
            "{:?}",
            log[0]
        );
    }

    #[test]
    fn retry_after_is_never_shortened_and_is_spread() {
        let (s, _) = recorded();
        let r = retry((), s);
        let ra = Duration::from_secs(2);
        let waits: Vec<_> = (0..64).map(|_| r.after_retry_after(ra, 1)).collect();
        assert!(
            waits
                .iter()
                .all(|w| (ra..ra + Duration::from_millis(300)).contains(w))
        );
        assert!(
            waits.iter().any(|w| *w != waits[0]),
            "clients told the same Retry-After do not retry in lockstep"
        );
    }

    /// A small `Retry-After` never shortens the normal schedule: `Retry-After: 0` on every attempt
    /// waits at least the equal-jitter floor of each step.
    #[tokio::test]
    async fn small_retry_after_keeps_the_jitter_floor() {
        for ra in [Duration::ZERO, Duration::from_millis(10)] {
            let (s, _) = recorded();
            let r = retry((), s);
            for a in 1..10u32 {
                let floor = (Duration::from_millis(300) * 2u32.saturating_pow(a - 1))
                    .min(Duration::from_secs(5))
                    / 2;
                for _ in 0..16 {
                    let d = r.after_retry_after(ra, a);
                    assert!(d >= floor, "attempt {a}, Retry-After {ra:?}: {d:?}");
                }
            }
        }
        // End to end, the default schedule keeps its length under `Retry-After: 0`.
        let (s, log) = recorded();
        let r = retry(
            flaky(u32::MAX, || throttled().with_retry_after(Duration::ZERO)),
            s,
        );
        let _ = r.encrypt(b"", b"").await;
        let total: Duration = log.lock().unwrap().iter().sum();
        assert!(total >= Duration::from_millis(4650), "{total:?}");
    }

    #[tokio::test]
    async fn huge_retry_after_does_not_panic() {
        fn huge() -> Error {
            throttled().with_retry_after(Duration::from_secs(u64::MAX))
        }
        let (s, log) = recorded();
        let r = retry(flaky(1, huge), s);
        let e = r.encrypt(b"", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Throttled);
        assert!(log.lock().unwrap().is_empty());
        // Even with an unbounded cap and deadline, the delay is clamped instead of overflowing.
        let (s, log) = recorded();
        let r = retry_with(
            flaky(1, huge),
            s,
            RetryPolicy::default()
                .with_backoff(Duration::from_millis(300), Duration::MAX)
                .with_deadline(Duration::MAX),
        );
        assert!(r.encrypt(b"", b"").await.is_ok());
        let d = log.lock().unwrap()[0];
        assert!(d >= MAX_RETRY_AFTER && d < MAX_RETRY_AFTER + Duration::from_secs(1));
        let r = retry((), instant_sleep());
        let _ = r.after_retry_after(Duration::MAX, u32::MAX);
    }

    #[tokio::test]
    async fn backoff_past_the_deadline_returns_the_error() {
        let (s, log) = recorded();
        let r = retry_with(
            flaky(u32::MAX, || {
                Error::new(ErrorKind::Unavailable, "t", Operation::Encrypt, "x")
            }),
            s,
            // The first backoff (150 to 300 ms) already ends past the deadline.
            RetryPolicy::default().with_deadline(Duration::from_millis(100)),
        );
        let e = r.encrypt(b"", b"").await.unwrap_err();
        assert_eq!(
            e.kind(),
            ErrorKind::Unavailable,
            "without Retry-After the original error is returned"
        );
        assert!(e.retry_after().is_none());
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn shared_budget_spans_handles() {
        let budget = RetryBudget::new(0.0, 3.0);
        let layer = || RetryLayer::new(instant_sleep()).with_budget(budget.clone());
        let a = layer().wrap(flaky(u32::MAX, throttled));
        let b = layer().wrap(flaky(u32::MAX, throttled));
        let _ = a.encrypt(b"", b"").await;
        let _ = b.encrypt(b"", b"").await;
        // 2 first attempts + 3 retries in total, not 3 per handle.
        let calls = a.inner().calls.load(Ordering::SeqCst) + b.inner().calls.load(Ordering::SeqCst);
        assert_eq!(calls, 5);
        assert!(format!("{budget:?}").contains("RetryBudget"));
    }

    #[tokio::test]
    async fn budget_limits_retry_storms() {
        let (s, _) = recorded();
        let r = retry_with(
            flaky(u32::MAX, throttled),
            s,
            RetryPolicy::default().with_budget(0.0, 2.0),
        );
        for _ in 0..3 {
            let _ = r.encrypt(b"", b"").await;
        }
        // 3 first attempts + only 2 retries allowed by the budget.
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 5);
    }

    fn hinted() -> Error {
        Error::new(ErrorKind::NotFound, "t", Operation::Encrypt, "x")
            .with_retry_hint(Duration::from_millis(500))
    }

    #[tokio::test]
    async fn hinted_retry_is_opt_in_and_single() {
        let (s, _) = recorded();
        let r = retry(flaky(1, hinted), s.clone());
        assert_eq!(
            r.encrypt(b"", b"").await.unwrap_err().kind(),
            ErrorKind::NotFound
        );
        let r = retry_with(
            flaky(1, hinted),
            s.clone(),
            RetryPolicy::default().with_retry_on_hint(true),
        );
        assert!(r.encrypt(b"", b"").await.is_ok());
        let r = retry_with(
            flaky(2, hinted),
            s,
            RetryPolicy::default().with_retry_on_hint(true),
        );
        assert!(r.encrypt(b"", b"").await.is_err());
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 2);
    }

    /// Any backend's hint works the same way (here a key version still being generated): one
    /// retry after at least the hint, counted as an attempt.
    #[tokio::test]
    async fn hinted_retry_waits_at_least_the_hint_and_counts_towards_max_attempts() {
        fn pending() -> Error {
            Error::new(
                ErrorKind::KeyStateInvalid,
                "gcp",
                Operation::Sign,
                "pending",
            )
            .with_detail(BackendDetail::new().with_code("FAILED_PRECONDITION"))
            .with_retry_hint(Duration::from_secs(2))
        }
        let (s, log) = recorded();
        let r = retry_with(
            flaky(1, pending),
            s.clone(),
            RetryPolicy::default().with_retry_on_hint(true),
        );
        assert!(r.encrypt(b"", b"").await.is_ok());
        {
            let log = log.lock().unwrap();
            assert_eq!(log.len(), 1);
            assert!(log[0] >= Duration::from_secs(2), "{:?}", log[0]);
        }
        // The hinted retry used the second of two attempts: no third try after it fails again
        // with a retryable error.
        static CALLS: AtomicU32 = AtomicU32::new(0);
        fn pending_then_throttled() -> Error {
            if CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                pending()
            } else {
                throttled()
            }
        }
        let r = retry_with(
            flaky(u32::MAX, pending_then_throttled),
            s.clone(),
            RetryPolicy::default()
                .with_retry_on_hint(true)
                .with_max_attempts(2),
        );
        let e = r.encrypt(b"", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Throttled);
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 2);
        // With a single attempt there is no hinted retry and no sleep.
        log.lock().unwrap().clear();
        let r = retry_with(
            flaky(1, pending),
            s,
            RetryPolicy::default()
                .with_retry_on_hint(true)
                .with_max_attempts(1),
        );
        let e = r.encrypt(b"", b"").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyStateInvalid);
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
        assert!(log.lock().unwrap().is_empty(), "no hinted retry, no sleep");
    }

    /// Like `Retry-After`, a hint above the cap (or past the deadline) is not waited for; unlike
    /// it, the error keeps its kind (it was never retryable).
    #[tokio::test]
    async fn hints_above_the_cap_or_deadline_are_not_honored() {
        fn long() -> Error {
            Error::new(ErrorKind::NotFound, "t", Operation::Encrypt, "x")
                .with_retry_hint(Duration::from_secs(6))
        }
        fn huge() -> Error {
            Error::new(ErrorKind::NotFound, "t", Operation::Encrypt, "x")
                .with_retry_hint(Duration::MAX)
        }
        let (s, log) = recorded();
        let on = RetryPolicy::default().with_retry_on_hint(true);
        for err in [long as fn() -> Error, huge] {
            let r = retry_with(flaky(1, err), s.clone(), on.clone());
            let e = r.encrypt(b"", b"").await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::NotFound);
            assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
        }
        let r = retry_with(
            flaky(1, hinted),
            s.clone(),
            on.with_deadline(Duration::from_millis(400)),
        );
        assert_eq!(
            r.encrypt(b"", b"").await.unwrap_err().kind(),
            ErrorKind::NotFound
        );
        // `immediate()` has a zero cap, so a non-zero hint is not honored either...
        let r = retry_with(
            flaky(1, hinted),
            s.clone(),
            RetryPolicy::immediate().with_retry_on_hint(true),
        );
        assert!(r.encrypt(b"", b"").await.is_err());
        assert!(log.lock().unwrap().is_empty());
        // ... but a zero one is.
        fn zero() -> Error {
            Error::new(ErrorKind::NotFound, "t", Operation::Encrypt, "x")
                .with_retry_hint(Duration::ZERO)
        }
        let r = retry_with(
            flaky(1, zero),
            s,
            RetryPolicy::immediate().with_retry_on_hint(true),
        );
        assert!(r.encrypt(b"", b"").await.is_ok());
        assert_eq!(*log.lock().unwrap(), [Duration::ZERO]);
    }

    /// Errors of a retryable kind follow the normal schedule; their hint adds no extra attempt.
    #[tokio::test]
    async fn hints_on_retryable_errors_are_ignored() {
        fn hinted_throttle() -> Error {
            throttled().with_retry_hint(Duration::from_secs(60))
        }
        let (s, log) = recorded();
        let r = retry_with(
            flaky(u32::MAX, hinted_throttle),
            s,
            RetryPolicy::default().with_retry_on_hint(true),
        );
        assert_eq!(
            r.encrypt(b"", b"").await.unwrap_err().kind(),
            ErrorKind::Throttled
        );
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 6);
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|d| *d <= Duration::from_secs(5))
        );
    }

    #[test]
    fn jitter_is_bounded() {
        let (s, _) = recorded();
        let r = retry((), s);
        for a in 1..20 {
            assert!(r.jitter(a) <= Duration::from_secs(5));
        }
    }

    #[test]
    fn equal_jitter_keeps_half_of_each_step() {
        let (s, _) = recorded();
        let r = retry((), s);
        for a in 1..20u32 {
            let ceiling = (Duration::from_millis(300) * 2u32.saturating_pow(a - 1))
                .min(Duration::from_secs(5));
            for _ in 0..16 {
                let d = r.jitter(a);
                assert!(ceiling / 2 <= d && d <= ceiling, "attempt {a}: {d:?}");
            }
        }
    }

    /// A clock driven by the recorded sleeps: simulated time, so deadline tests need no waiting.
    fn simulated() -> (SleepFn, ClockFn, Arc<Mutex<Duration>>) {
        let now = Arc::new(Mutex::new(Duration::ZERO));
        let n = now.clone();
        let sleep: SleepFn = Arc::new(move |d| {
            *n.lock().unwrap() += d;
            Box::pin(async {})
        });
        let n = now.clone();
        let clock: ClockFn = Arc::new(move || *n.lock().unwrap());
        (sleep, clock, now)
    }

    #[tokio::test]
    async fn injected_clock_drives_the_deadline() {
        // With `instant_sleep` and the real clock, no time passes and all 6 attempts run even
        // with a 2 s deadline. With a simulated clock the sleeps count against the deadline.
        let (sleep, clock, now) = simulated();
        let r = RetryLayer::new(sleep)
            .with_policy(
                RetryPolicy::default()
                    .with_backoff(Duration::from_secs(1), Duration::from_secs(1))
                    .with_deadline(Duration::from_millis(2500)),
            )
            .with_clock(clock)
            .wrap(flaky(u32::MAX, throttled));
        assert!(r.encrypt(b"", b"").await.is_err());
        let calls = r.inner().calls.load(Ordering::SeqCst);
        // Each backoff is 0.5..=1 s: at least 2 and at most 4 retries fit in 2.5 s.
        assert!((3..=5).contains(&calls), "{calls} attempts");
        assert!(*now.lock().unwrap() <= Duration::from_millis(2500));

        // A clock that jumps past the deadline stops retries at once.
        let jump: ClockFn = {
            let first = Arc::new(Mutex::new(true));
            Arc::new(move || {
                let mut f = first.lock().unwrap();
                if std::mem::replace(&mut *f, false) {
                    Duration::ZERO
                } else {
                    Duration::from_secs(60)
                }
            })
        };
        let r = RetryLayer::new(instant_sleep())
            .with_clock(jump)
            .wrap(flaky(u32::MAX, throttled));
        assert!(r.encrypt(b"", b"").await.is_err());
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn immediate_policy_retries_without_delay() {
        let (s, log) = recorded();
        let r = retry_with(flaky(5, throttled), s, RetryPolicy::immediate());
        assert!(r.encrypt(b"", b"").await.is_ok());
        {
            let log = log.lock().unwrap();
            assert_eq!(log.len(), 5);
            assert!(log.iter().all(|d| d.is_zero()));
        }
        // The budget does not get in the way of a test hammering one handle.
        let r = retry_with(
            flaky(u32::MAX, throttled),
            instant_sleep(),
            RetryPolicy::immediate(),
        );
        for _ in 0..100 {
            let _ = r.encrypt(b"", b"").await;
        }
        assert_eq!(r.inner().calls.load(Ordering::SeqCst), 600);
    }

    #[tokio::test]
    async fn layer_shares_one_budget_and_keeps_explicit_budgets() {
        let budget = RetryBudget::new(0.0, 3.0);
        // `with_policy` after `with_budget` keeps the explicit budget.
        let layer = RetryLayer::new(instant_sleep())
            .with_budget(budget.clone())
            .with_policy(RetryPolicy::immediate());
        let a = layer.wrap(flaky(u32::MAX, throttled));
        let b = layer.wrap(flaky(u32::MAX, throttled));
        let _ = a.encrypt(b"", b"").await;
        let _ = b.encrypt(b"", b"").await;
        let calls = a.inner().calls.load(Ordering::SeqCst) + b.inner().calls.load(Ordering::SeqCst);
        assert_eq!(calls, 5);
        assert_eq!(layer.policy().base, Duration::ZERO);
        assert!(format!("{layer:?}").contains("RetryLayer"));
    }

    /// The default schedule spans the measured step-down outages (up to about 6 s, see the module
    /// docs) without approaching the deadline.
    #[tokio::test]
    async fn default_schedule_spans_a_step_down() {
        for _ in 0..32 {
            let (s, log) = recorded();
            let r = retry(flaky(u32::MAX, throttled), s);
            let _ = r.encrypt(b"", b"").await;
            let log = log.lock().unwrap();
            assert_eq!(log.len(), 5);
            let total: Duration = log.iter().sum();
            assert!(
                (Duration::from_millis(4650)..=Duration::from_millis(9300)).contains(&total),
                "{total:?}"
            );
        }
    }
}
