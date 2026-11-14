//! Local verification with public keys fetched from the backend and cached per version.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};
use std::time::Duration;

use anykms_core::time::Instant;
use anykms_core::{
    Digest, DigestVerifier, Error, ErrorKind, KeyVersion, MessageVerifier, Operation, PublicKey,
    PublicKeys, Result, RetryLayer, Signature, SignatureAlgorithm,
};

use crate::LocalVerifier;

const BACKEND: &str = "cached-verifier";
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(5);
const DEFAULT_MAX_ENTRIES: usize = 1024;
/// Equal to transit's replica-lag retry hint. Ceiling rejections carry this interval as their
/// retry hint, so a hinted retry re-reads the latest version.
const DEFAULT_LATEST_REFRESH: Duration = Duration::from_millis(500);

type Lookup = Result<Arc<LocalVerifier>>;

/// Cache key: `None` is the key's current public key (unversioned signatures).
type Key = Option<KeyVersion>;

/// A cached public key and when it was fetched.
struct Cached {
    at: Instant,
    verifier: Arc<LocalVerifier>,
}

/// One in-progress backend request that concurrent callers wait on.
struct Flight<T>(Mutex<FlightState<T>>);

struct FlightState<T> {
    done: Option<T>,
    /// The leading caller was dropped before finishing; waiters retry.
    abandoned: bool,
    wakers: Vec<Waker>,
}

impl<T> Default for Flight<T> {
    fn default() -> Self {
        Self(Mutex::new(FlightState {
            done: None,
            abandoned: false,
            wakers: Vec::new(),
        }))
    }
}

impl<T: Clone> Flight<T> {
    fn lock(&self) -> MutexGuard<'_, FlightState<T>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn finish(&self, done: Option<T>) {
        let wakers = {
            let mut st = self.lock();
            match done {
                Some(r) => st.done = Some(r),
                None => st.abandoned = true,
            }
            std::mem::take(&mut st.wakers)
        };
        wakers.into_iter().for_each(Waker::wake);
    }

    /// The result, or `None` if the leader was dropped.
    async fn wait(&self) -> Option<T> {
        std::future::poll_fn(|cx| {
            let mut st = self.lock();
            if let Some(r) = &st.done {
                return Poll::Ready(Some(r.clone()));
            }
            if st.abandoned {
                return Poll::Ready(None);
            }
            if !st.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                st.wakers.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}

/// What the source's current public key says about its versions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Latest {
    /// Not read successfully yet.
    #[default]
    Unknown,
    /// The source's versions are numeric; this is the newest.
    Numeric(u64),
    /// The current public key has no numeric version: no ceiling applies.
    NonNumeric,
}

#[derive(Default)]
struct State {
    /// Public keys (at most `max_entries`).
    entries: HashMap<Key, Cached>,
    /// Lookups in progress, kept apart from `entries` (and bounded only by concurrency) so that
    /// lookups of forged versions in flight never evict cached public keys (L15).
    in_flight: HashMap<Key, Arc<Flight<Lookup>>>,
    /// Failed lookups that will fail again (with when they failed and for how long they are
    /// remembered), kept apart (and bounded separately) so forged versions cannot evict real
    /// public keys.
    negative: HashMap<Key, (Instant, Duration, Error)>,
    latest: Latest,
    latest_checked: Option<Instant>,
    /// The error of the last latest-version read, until one succeeds.
    latest_err: Option<Error>,
    /// The latest-version read in progress, shared by concurrent callers.
    refreshing: Option<Arc<Flight<()>>>,
    /// When a cached public key was last re-fetched after a signature failed under it.
    rechecked: Option<Instant>,
    /// That re-fetch in progress, shared by concurrent callers.
    rechecking: Option<Arc<Flight<()>>>,
    /// Bumped whenever cached public keys are dropped, so a caller can tell that a retry may see
    /// a different key.
    generation: u64,
}

/// Verifies signatures of **one** algorithm locally using the public key of the signature's
/// [`KeyVersion`] (or the current public key for unversioned signatures).
///
/// **Emulates:** the backend's verify operation. **Enforced by:** this process (see
/// [`LocalVerifier`]).
///
/// The algorithm is fixed at construction, as for [`LocalVerifier`]: a signature naming any other
/// algorithm fails with `InvalidArgument` before any lookup, and a public key of another type
/// fails with `KeyMismatch`.
///
/// Cache expiry and the refresh interval read a monotonic clock directly (`anykms_core::time`:
/// `std::time::Instant`, or `performance.now()` on `wasm32-unknown-unknown` with the `js` feature).
///
/// # Rotation
///
/// A signature naming a version above the latest version the verifier knows is rejected without
/// a lookup when the latest version was already read within the refresh interval (default
/// 500 ms; see [Untrusted key versions](#untrusted-key-versions)). Right after a rotation, the
/// new version's first signatures can therefore fail with `InvalidArgument` for up to one
/// refresh interval. This happens on a single node too, not only with lagging replicas: any read
/// in that interval is enough (the first verification after startup, another signature naming a
/// version above the latest, a recheck after a signature failed under a cached key). The error
/// carries the refresh interval as its [`retry_hint`](Error::retry_hint), so give the verifier a
/// retry layer with `RetryPolicy::with_retry_on_hint(true)`
/// ([`with_retry`](CachedVerifier::with_retry)), whatever the replica topology:
///
/// ```
/// use anykms_core::{PublicKeys, RetryLayer, RetryPolicy, SignatureAlgorithm, SleepFn};
/// use anykms_recipes::CachedVerifier;
///
/// // With the `anykms` facade, `anykms::retry_layer()` instead of `RetryLayer::new(sleep)`.
/// fn verifier<P: PublicKeys>(src: P, sleep: SleepFn) -> CachedVerifier<P> {
///     let retry = RetryLayer::new(sleep)
///         .with_policy(RetryPolicy::default().with_retry_on_hint(true));
///     CachedVerifier::new(src, SignatureAlgorithm::EcdsaP256Sha256).with_retry(&retry)
/// }
/// ```
///
/// With such a layer the verifier waits out the interval itself (with the layer's sleep
/// function), then re-reads the latest version and verifies once more. The wait is not one of
/// the layer's retries: it spends no attempt and no budget token, so a flood of forged versions
/// cannot drain a budget the layer shares with other operations (or with the rotation case
/// itself). What bounds its cost is the latest-version read: at most one per refresh interval,
/// coalesced across callers, however many requests wait. A request naming a version above the
/// latest is held for up to one refresh interval. The verifier does not re-read the latest
/// version without waiting: that would let every forged version cost a backend request again.
/// A retry layer on the source (e.g. on the registry it was opened from) never sees this
/// rejection, which the verifier makes itself; when the source already retries, give the
/// verifier's layer `with_max_attempts(2)` so attempts on transient errors do not multiply.
///
/// # Revocation
///
/// The public key of a version never changes, but a version can be *revoked* on the backend
/// (transit: raising `min_decryption_version`, which also stops verification; disabling a key or
/// version; deleting the key). Cached entries expire after a TTL (default 5 minutes), so a
/// revocation takes effect locally within the TTL, plus whatever the source caches itself. Call
/// [`CachedVerifier::invalidate`] to drop this verifier's cache, and the source's through
/// [`PublicKeys::invalidate_public_keys`], at once.
///
/// This relies on the source refusing the public key of a disabled key or version, as the
/// [`PublicKeys` contract](anykms_core::PublicKeys#contract) requires: `KeyStateInvalid` for a
/// disabled key, `KeyVersionUnusable` for a disabled version. Every built-in backend refuses it
/// on a lookup that reaches the backend (AWS checks the key state with `DescribeKey`, because
/// `GetPublicKey` serves disabled keys); AWS, Azure and transit read the state on every lookup.
/// **GCP** answers from its provider's public-key cache (`public_key_ttl`, default 60 s, +10 %
/// jitter) without a state check, so through a GCP source the bound is this verifier's TTL plus
/// `public_key_ttl`; [`invalidate`](CachedVerifier::invalidate) drops both caches, so the next
/// verification re-reads the version's state. A third-party [`PublicKeys`] source must honor the
/// contract too, or a disabled key's signatures keep verifying here after the backend stopped
/// accepting them; one that caches must implement
/// [`invalidate_public_keys`](PublicKeys::invalidate_public_keys), as GCP's handles do.
///
/// # Errors
///
/// - A signature naming a version the key does not have, or another key's version, fails with
///   `VerificationFailed`, like a signature that does not verify: the source's
///   `UnknownKeyVersion` becomes `VerificationFailed`, kept as the error's
///   [`source`](std::error::Error::source) (and its retry hint, if any).
/// - The verifier's own rejections stay `InvalidArgument`: a version above the version ceiling
///   (with the refresh interval as its retry hint) and a non-numeric version of a key with
///   numeric versions (see [Untrusted key versions](#untrusted-key-versions)).
/// - Other source errors pass through unchanged (`KeyStateInvalid`, `KeyVersionUnusable`,
///   `NotFound`, transient errors).
///
/// # Deleted and recreated keys
///
/// A key deleted and created again under the same name restarts its versions at 1, with new key
/// material, so a cached "version 1" would be the old key's. Whenever the verifier sees the key's
/// latest version **decrease**, or a version's public key differ from the cached one, it drops
/// every cached public key and failed lookup. A signature that does not verify under a cached
/// public key triggers two checks: a read of the key's latest version and a re-fetch of the
/// signature's version, each at most once per refresh interval (shared by all callers and
/// versions). If either dropped the cache, the signature is verified once more with freshly
/// fetched keys. A new key's signature therefore verifies on arrival unless a check already ran
/// within the refresh interval; it then fails, and verifies when presented again after the
/// interval. The old key's signatures stop verifying as soon as a check sees the new key, and
/// within the TTL otherwise.
///
/// # Untrusted key versions
///
/// The version a signature names often comes from the signed data itself (a JWT `kid`), so an
/// attacker picks it. To keep forged versions from turning each verification into a backend
/// request, the verifier:
///
/// - reads the key's latest version (from [`PublicKeys::public_key`], at most once per refresh
///   interval, default 500 ms, coalesced across concurrent callers) and, when it is numeric,
///   rejects without any lookup versions above it (`InvalidArgument` with the refresh interval as
///   its [`retry_hint`](Error::retry_hint), so `RetryPolicy::retry_on_hint` retries once, after
///   the latest version may be re-read, following a rotation; see [Rotation](#rotation)) and
///   non-numeric versions (`InvalidArgument`);
/// - while that read fails (an outage, or before the first read succeeded), rejects versions it
///   cannot vouch for with the read's error instead of fetching them, so an outage does not turn
///   each unique `kid` into a backend request; versions at or below the last known latest
///   version keep working from the cache;
/// - caches failed lookups that will fail again (`UnknownKeyVersion`, `KeyVersionUnusable`,
///   `NotFound`, `InvalidArgument`, `KeyStateInvalid`, `KeyMismatch`, `Unsupported`, and its own
///   refusal of a source that answers with another version than asked for) in a separate,
///   smaller map (an eighth of the entry limit), so they never evict cached public keys: for the
///   negative TTL (default
///   5 seconds), or, when the backend attached a [`retry_hint`](Error::retry_hint) (transit does
///   for a version above the latest it knows, as possible replication lag), for the shorter of
///   the negative TTL and the hint, so the hinted retry asks again; transient errors are not
///   cached;
/// - coalesces concurrent lookups of one version into a single backend request (runtime-agnostic);
/// - bounds the cache (default 1024 public keys, evicting expired, then the oldest entries when
///   a lookup has a public key to add); lookups in flight are kept apart and never evict them.
///
/// Opt out of the version checks with
/// [`allow_versions_above_latest`](CachedVerifier::allow_versions_above_latest) for sources whose
/// `public_key` is not the newest version (e.g. a handle pinned to an old version).
///
/// ## Residual behaviour
///
/// With a numeric source and the version checks on, only real versions (at most the key's
/// latest version) reach the backend, each at most once per negative TTL; forged versions cost
/// no request. For sources without numeric versions, or with the checks off, each unique forged
/// version costs one backend request per negative TTL (per retry hint, 500 ms on transit, when
/// the backend attaches one, as transit does for versions above its latest), and they compete only for the negative map: under a flood its entries turn over
/// quickly (so a repeated forged version may be fetched again sooner), while cached public keys
/// stay. Eviction scans the full map, which only happens when it is full; with the version checks
/// on the public-key map holds at most one entry per real version. Signatures that fail to verify
/// under a cached key cost at most one latest-version read and one public-key re-fetch per refresh
/// interval.
///
/// # Unversioned signatures
///
/// A signature without a key version (backends that expose none, such as AWS KMS, or a JWS whose
/// `kid` names no version) is verified against [`PublicKeys::public_key`], cached like a version.
///
/// # Cloning
///
/// Cheap, and clones **share** the source and the cache (public keys, failed lookups, the latest
/// version and the in-flight lookups), so cloning into request handlers or tasks keeps one cache
/// per key. Configure before cloning and before use: every builder method (except
/// [`with_retry`](Self::with_retry)) gives the verifier its own, empty cache, so verifiers with
/// different settings never share entries and no public key cached under the old settings is used
/// under the new ones.
pub struct CachedVerifier<P> {
    source: Arc<P>,
    alg: SignatureAlgorithm,
    ttl: Duration,
    negative_ttl: Duration,
    max_entries: usize,
    latest_refresh: Duration,
    version_ceiling: bool,
    require_low_s: bool,
    retry: Option<RetryLayer>,
    state: Arc<Mutex<State>>,
}

impl<P> Clone for CachedVerifier<P> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            alg: self.alg,
            ttl: self.ttl,
            negative_ttl: self.negative_ttl,
            max_entries: self.max_entries,
            latest_refresh: self.latest_refresh,
            version_ceiling: self.version_ceiling,
            require_low_s: self.require_low_s,
            retry: self.retry.clone(),
            state: self.state.clone(),
        }
    }
}

impl<P> std::fmt::Debug for CachedVerifier<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.state.lock().map_or(0, |s| s.entries.len());
        f.debug_struct("CachedVerifier")
            .field("algorithm", &self.alg)
            .field("ttl", &self.ttl)
            .field("negative_ttl", &self.negative_ttl)
            .field("max_entries", &self.max_entries)
            .field("version_ceiling", &self.version_ceiling)
            .field("require_low_s", &self.require_low_s)
            .field("retry", &self.retry.as_ref().map(RetryLayer::policy))
            .field("cached_versions", &n)
            .finish()
    }
}

/// Evicts expired, then the oldest entries of `map` until one more fits under `max`. Linear, but
/// only runs when the map is full. `at` is an entry's insertion time.
fn make_room<V>(
    map: &mut HashMap<Key, V>,
    max: usize,
    expired: impl Fn(&V) -> bool,
    at: impl Fn(&V) -> Instant,
) {
    if map.len() < max {
        return;
    }
    map.retain(|_, v| !expired(v));
    while map.len() >= max {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, v)| at(v))
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        map.remove(&oldest);
    }
}

/// Completes the lookup when dropped: publishes the result (`complete`) or, if the leading future
/// was dropped first, releases the waiters so one of them takes over.
struct Lead<'a, P> {
    cv: &'a CachedVerifier<P>,
    key: &'a Key,
    flight: Arc<Flight<Lookup>>,
    result: Option<Lookup>,
}

impl<P> Drop for Lead<'_, P> {
    fn drop(&mut self) {
        let result = self.result.take();
        {
            let mut st = self.cv.lock();
            let ours = matches!(
                st.in_flight.get(self.key),
                Some(f) if Arc::ptr_eq(f, &self.flight)
            );
            if ours {
                st.in_flight.remove(self.key);
                match &result {
                    Some(Ok(verifier)) => {
                        // Only now, with a public key to cache, is room made: an expired entry
                        // for this version, then other expired, then the oldest public keys.
                        st.entries.remove(self.key);
                        let ttl = self.cv.ttl;
                        make_room(
                            &mut st.entries,
                            self.cv.max_entries,
                            |c| c.at.elapsed() >= ttl,
                            |c| c.at,
                        );
                        let cached = Cached {
                            at: Instant::now(),
                            verifier: verifier.clone(),
                        };
                        st.entries.insert(self.key.clone(), cached);
                    }
                    Some(Err(e)) => {
                        if let Some(ttl) = self.cv.negative_ttl_for(e) {
                            let max = self.cv.max_negative();
                            make_room(
                                &mut st.negative,
                                max,
                                |(t, ttl, _)| t.elapsed() >= *ttl,
                                |(t, _, _)| *t,
                            );
                            st.negative
                                .insert(self.key.clone(), (Instant::now(), ttl, e.clone()));
                        }
                    }
                    // Abandoned lookup: nothing to remember.
                    None => {}
                }
            }
        }
        self.flight.finish(result);
    }
}

/// Publishes a latest-version read when dropped (or, if the reader was dropped first, lets a
/// waiter read again).
struct RefreshLead<'a, P> {
    cv: &'a CachedVerifier<P>,
    flight: Arc<Flight<()>>,
    result: Option<Result<PublicKey>>,
}

impl<P> Drop for RefreshLead<'_, P> {
    fn drop(&mut self) {
        let result = self.result.take();
        {
            let mut st = self.cv.lock();
            if st
                .refreshing
                .as_ref()
                .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
            {
                st.refreshing = None;
                match &result {
                    Some(Ok(pk)) => observe_latest(&mut st, pk),
                    Some(Err(e)) => st.latest_err = Some(e.clone()),
                    None => st.latest_checked = None,
                }
            }
        }
        self.flight.finish(result.map(|_| ()));
    }
}

/// Publishes a re-fetch of a cached public key when dropped (or, if the re-fetcher was dropped
/// first, lets a waiter re-fetch).
struct RecheckLead<'a, P> {
    cv: &'a CachedVerifier<P>,
    key: &'a Key,
    /// The cached public key the signature failed under, and the generation it belonged to.
    cached: Arc<LocalVerifier>,
    generation: u64,
    flight: Arc<Flight<()>>,
    result: Option<Result<PublicKey>>,
}

impl<P> Drop for RecheckLead<'_, P> {
    fn drop(&mut self) {
        let result = self.result.take();
        {
            let mut st = self.cv.lock();
            if st
                .rechecking
                .as_ref()
                .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
            {
                st.rechecking = None;
                match &result {
                    Some(Ok(pk)) => {
                        // Only while the entry re-fetched is still cached: a concurrent
                        // `invalidate` or refresh already made this answer moot.
                        let current = st.generation == self.generation
                            && st
                                .entries
                                .get(self.key)
                                .is_some_and(|c| Arc::ptr_eq(&c.verifier, &self.cached));
                        if current && differs(st.entries.get(self.key), pk) {
                            forget(&mut st);
                        }
                    }
                    // Keep the cached key: the version may be unreachable only for now.
                    Some(Err(_)) => {}
                    None => st.rechecked = None,
                }
            }
        }
        self.flight.finish(result.map(|_| ()));
    }
}

/// Drops every cached public key and failed lookup: the key was deleted and recreated.
fn forget(st: &mut State) {
    st.entries.clear();
    // A lookup in flight now hands its result to its waiters only, never to the cache.
    st.in_flight.clear();
    st.negative.clear();
    st.generation += 1;
}

/// Whether `cached` holds a public key other than `pk`.
fn differs(cached: Option<&Cached>, pk: &PublicKey) -> bool {
    cached.is_some_and(|c| c.verifier.public_key().spki_der() != pk.spki_der())
}

/// Records a successful read of the key's current public key. A latest version lower than the
/// one seen before, or a cached public key for the same version that differs, means the key was
/// deleted and recreated: every cached public key and failed lookup is dropped. A cached current
/// key (unversioned signatures) that differs was rotated away and is dropped alone.
fn observe_latest(st: &mut State, pk: &PublicKey) {
    let latest = match pk.key_version().and_then(KeyVersion::as_u64) {
        Some(l) => Latest::Numeric(l),
        None => Latest::NonNumeric,
    };
    let decreased =
        matches!((st.latest, latest), (Latest::Numeric(old), Latest::Numeric(new)) if new < old);
    let replaced = pk
        .key_version()
        .is_some_and(|v| differs(st.entries.get(&Some(v.clone())), pk));
    if decreased || replaced {
        forget(st);
    } else if differs(st.entries.get(&None), pk) {
        st.entries.remove(&None);
        st.generation += 1;
    }
    st.latest = latest;
    st.latest_err = None;
}

impl<P> CachedVerifier<P> {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Gives this verifier its own, empty cache: called by every builder method, so verifiers
    /// with different settings never share entries, and public keys cached under the old
    /// settings (e.g. lenient verifiers before `require_low_s`) are never used under the new
    /// ones, also when this verifier was used before it was reconfigured.
    fn detach(mut self) -> Self {
        self.state = Arc::new(Mutex::new(State::default()));
        self
    }

    fn max_negative(&self) -> usize {
        (self.max_entries / 8).max(1)
    }

    /// How long a failed lookup is remembered: `None` for transient failures (not at all),
    /// for at most the retry hint of hinted failures (so the hinted retry asks again), the
    /// negative TTL otherwise. Lasting failures are the ones the same lookup fails with again:
    /// the source's caller errors (a disabled version, `KeyVersionUnusable`, included) and the
    /// verifier's own refusal of a source that answers with another version than asked for.
    fn negative_ttl_for(&self, e: &Error) -> Option<Duration> {
        let lasting = matches!(
            e.kind(),
            ErrorKind::UnknownKeyVersion
                | ErrorKind::KeyVersionUnusable
                | ErrorKind::NotFound
                | ErrorKind::InvalidArgument
                | ErrorKind::KeyStateInvalid
                | ErrorKind::KeyMismatch
                | ErrorKind::Unsupported
        ) || is_other_version(e);
        if !lasting {
            return None;
        }
        Some(
            e.retry_hint()
                .map_or(self.negative_ttl, |h| self.negative_ttl.min(h)),
        )
    }
}

/// Whether the version passes the ceiling given what is known about the latest version:
/// `Some(Ok)` passes, `Some(Err)` is rejected, `None` needs a (re-)read.
fn judge(st: &State, n: Option<u64>) -> Option<Result<()>> {
    match (st.latest, n) {
        (Latest::NonNumeric, _) => Some(Ok(())),
        (Latest::Numeric(l), Some(n)) if n <= l => Some(Ok(())),
        (Latest::Numeric(_), None) => Some(Err(Error::new(
            ErrorKind::InvalidArgument,
            BACKEND,
            Operation::Verify,
            "signature names a non-numeric version of a key with numeric versions",
        ))),
        _ => None,
    }
}

impl<P: PublicKeys> CachedVerifier<P> {
    /// Verifies `alg` signatures with public keys from `source`, caching each for 5 minutes.
    pub fn new(source: P, alg: SignatureAlgorithm) -> Self {
        Self {
            source: Arc::new(source),
            alg,
            ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            max_entries: DEFAULT_MAX_ENTRIES,
            latest_refresh: DEFAULT_LATEST_REFRESH,
            version_ceiling: true,
            require_low_s: false,
            retry: None,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// How long a public key is cached (default 5 minutes; bounds how long a revoked version
    /// keeps verifying locally).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self.detach()
    }

    /// How long a failed lookup (e.g. an unknown version) is remembered (default 5 seconds).
    pub fn with_negative_ttl(mut self, ttl: Duration) -> Self {
        self.negative_ttl = ttl;
        self.detach()
    }

    /// The maximum number of cached public keys (default 1024, at least 1). Failed lookups are
    /// kept separately, up to an eighth of this (at least 1).
    pub fn with_max_entries(mut self, n: usize) -> Self {
        self.max_entries = n.max(1);
        self.detach()
    }

    /// How often the key's latest version may be re-read when a signature names a newer version
    /// or fails to verify under a cached key, and a cached public key re-fetched when a signature
    /// fails to verify under it (default 500 ms). After a rotation, signatures with the new
    /// version are rejected for at most this long, with this interval as their
    /// [`retry_hint`](Error::retry_hint) (so keep it at or below the retry policy's `cap` for the
    /// hinted retry to happen; see [Rotation](CachedVerifier#rotation)).
    pub fn with_latest_refresh_interval(mut self, interval: Duration) -> Self {
        self.latest_refresh = interval;
        self.detach()
    }

    /// Fetches any version a signature names, even above the key's latest version or
    /// non-numeric. Needed when the source's [`PublicKeys::public_key`] is not the newest
    /// version.
    pub fn allow_versions_above_latest(mut self) -> Self {
        self.version_ceiling = false;
        self.detach()
    }

    /// Rejects high-S ECDSA signatures ([`LocalVerifier::require_low_s`]; read its caveats).
    pub fn require_low_s(mut self) -> Self {
        self.require_low_s = true;
        self.detach()
    }

    /// Retries each verification with `retry` (its policy, budget and deadline), as a retry
    /// layer on a handle does. With `RetryPolicy::with_retry_on_hint(true)` this is what makes
    /// the verifier tolerate a rotation (see [Rotation](CachedVerifier#rotation)): the verifier
    /// then waits out its own rejection of a version above the latest with the layer's sleep
    /// function (if the policy allows at least 2 attempts and its `cap` is at least the refresh
    /// interval), spending no attempt and no budget token. Transient errors of the source
    /// (throttling, failover) are retried by the layer as usual; when the source already
    /// retries, give this layer `with_max_attempts(2)`.
    ///
    /// Does not detach the cache: clones with and without a retry layer share their entries.
    pub fn with_retry(mut self, retry: &RetryLayer) -> Self {
        self.retry = Some(retry.clone());
        self
    }

    /// The only signature algorithm this verifier accepts.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    /// Drops every cached public key and failed lookup (e.g. after revoking a key version), and
    /// the source's own cache through [`PublicKeys::invalidate_public_keys`], so the next
    /// verification reads the version's state from the backend.
    pub fn invalidate(&self) {
        self.source.invalidate_public_keys();
        let mut st = self.lock();
        st.entries.clear();
        st.in_flight.clear();
        st.negative.clear();
        st.latest = Latest::Unknown;
        st.latest_checked = None;
        st.latest_err = None;
        st.rechecked = None;
        st.generation += 1;
    }

    /// Re-reads the latest version unless one was read within the refresh interval; joins a
    /// read already in progress.
    async fn refresh_latest(&self) {
        loop {
            let (flight, leader) = {
                let mut st = self.lock();
                if let Some(f) = &st.refreshing {
                    (f.clone(), false)
                } else if st
                    .latest_checked
                    .is_none_or(|t| t.elapsed() >= self.latest_refresh)
                {
                    st.latest_checked = Some(Instant::now());
                    let f = Arc::new(Flight::default());
                    st.refreshing = Some(f.clone());
                    (f, true)
                } else {
                    return;
                }
            };
            if leader {
                let mut lead = RefreshLead {
                    cv: self,
                    flight,
                    result: None,
                };
                lead.result = Some(self.source.public_key().await);
                return;
            }
            if flight.wait().await.is_some() {
                return;
            }
        }
    }

    /// After a signature failed under the cached public key `cached` for `key`: re-reads the
    /// latest version and re-fetches the version (each rate limited) and reports whether that
    /// dropped cached keys, i.e. whether verifying again may give another answer.
    async fn recheck(&self, key: &Key, cached: &Arc<LocalVerifier>) -> bool {
        let generation = self.lock().generation;
        self.refresh_latest().await;
        self.refetch(key, cached, generation).await;
        self.lock().generation != generation
    }

    /// Re-fetches a cached version's public key unless a re-fetch (of any version) ran within the
    /// refresh interval; joins one already in progress. The latest version's public key alone
    /// cannot tell a recreated key once it was rotated past the versions cached.
    async fn refetch(&self, key: &Key, cached: &Arc<LocalVerifier>, generation: u64) {
        let Some(v) = key else {
            // The current key is re-read by `refresh_latest`.
            return;
        };
        loop {
            let (flight, leader) = {
                let mut st = self.lock();
                if st.generation != generation {
                    return;
                }
                if let Some(f) = &st.rechecking {
                    (f.clone(), false)
                } else if st
                    .rechecked
                    .is_none_or(|t| t.elapsed() >= self.latest_refresh)
                {
                    st.rechecked = Some(Instant::now());
                    let f = Arc::new(Flight::default());
                    st.rechecking = Some(f.clone());
                    (f, true)
                } else {
                    return;
                }
            };
            if leader {
                let mut lead = RecheckLead {
                    cv: self,
                    key,
                    cached: cached.clone(),
                    generation,
                    flight,
                    result: None,
                };
                lead.result = Some(self.source.public_key_version(v).await);
                return;
            }
            if flight.wait().await.is_some() {
                return;
            }
        }
    }

    /// Admits a version only if it is at most the key's latest (numeric) version; see the type
    /// docs.
    async fn check_ceiling(&self, v: &KeyVersion) -> Result<()> {
        if !self.version_ceiling {
            return Ok(());
        }
        let n = v.as_u64();
        if let Some(r) = judge(&self.lock(), n) {
            return r;
        }
        self.refresh_latest().await;
        let st = self.lock();
        if let Some(r) = judge(&st, n) {
            return r;
        }
        if let Some(e) = &st.latest_err {
            // The latest version cannot be read: refuse rather than fetch an unvouched version.
            return Err(e.clone());
        }
        match st.latest {
            Latest::Numeric(_) => Err(above_latest().with_retry_hint(self.latest_refresh)),
            // Only after a concurrent `invalidate`.
            _ => Err(Error::new(
                ErrorKind::Unavailable,
                BACKEND,
                Operation::Verify,
                "the key's latest version is not known yet",
            )),
        }
    }

    async fn fetch(&self, key: &Key) -> Lookup {
        let pk = match key {
            Some(v) => {
                let pk = self.source.public_key_version(v).await?;
                // A source that answers with another version (or none) would get this key cached
                // under `v` and let signatures naming `v` verify under it. The same lookup gets
                // the same answer again (e.g. a source that canonicalizes the version, as Azure
                // case-folds hex), so the refusal is remembered like an unknown version (L14).
                if pk.key_version() != Some(v) {
                    return Err(other_version());
                }
                pk
            }
            None => self.source.public_key().await?,
        };
        let mut verifier = LocalVerifier::new(pk, self.alg)?;
        if self.require_low_s {
            verifier = verifier.require_low_s();
        }
        Ok(Arc::new(verifier))
    }

    /// The verifier for the signature's version, and whether it came from the cache (rather than
    /// a lookup this call made or waited for).
    async fn verifier(&self, sig: &Signature) -> Result<(Arc<LocalVerifier>, bool)> {
        if sig.algorithm() != self.alg {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                BACKEND,
                Operation::Verify,
                "signature algorithm does not match the verifier's algorithm",
            ));
        }
        let key: Key = sig.key_version().cloned();
        if let Some(v) = &key {
            self.check_ceiling(v).await?;
        }
        loop {
            let (flight, leader) = {
                let mut st = self.lock();
                if let Some((at, ttl, e)) = st.negative.get(&key) {
                    if at.elapsed() < *ttl {
                        return Err(e.clone());
                    }
                    st.negative.remove(&key);
                }
                if let Some(c) = st.entries.get(&key)
                    && c.at.elapsed() < self.ttl
                {
                    return Ok((c.verifier.clone(), true));
                }
                if let Some(f) = st.in_flight.get(&key) {
                    (f.clone(), false)
                } else {
                    // Room in `entries` is made when the lookup has a public key to cache.
                    let f = Arc::new(Flight::default());
                    st.in_flight.insert(key.clone(), f.clone());
                    (f, true)
                }
            };
            if leader {
                let mut lead = Lead {
                    cv: self,
                    key: &key,
                    flight,
                    result: None,
                };
                let r = self.fetch(&key).await;
                lead.result = Some(r.clone());
                return r.map(|v| (v, false));
            }
            if let Some(r) = flight.wait().await {
                return r.map(|v| (v, false));
            }
        }
    }
}

/// A3: a signature naming a version the key does not have (the source's `UnknownKeyVersion`)
/// is a signature that does not verify. The original error is kept as the source, and its retry
/// hint (a version that may not have replicated yet) stays readable for `RetryLayer`.
fn unknown_version_fails(e: Error) -> Error {
    if e.kind() != ErrorKind::UnknownKeyVersion {
        return e;
    }
    let mut f = Error::new(
        ErrorKind::VerificationFailed,
        BACKEND,
        Operation::Verify,
        "signature names a key version the key does not have",
    );
    if let Some(r) = e.resource() {
        f = f.with_resource(r.to_owned());
    }
    if let Some(h) = e.retry_hint() {
        f = f.with_retry_hint(h);
    }
    f.with_source(e)
}

/// The verifier's rejection of a version above the key's latest version (see
/// [Rotation](CachedVerifier#rotation)).
fn above_latest() -> Error {
    Error::new(
        ErrorKind::InvalidArgument,
        BACKEND,
        Operation::Verify,
        "signature names a key version above the key's latest version",
    )
}

/// Whether `e` is [`above_latest`] with its retry hint: the only hinted `InvalidArgument` the
/// verifier itself makes.
fn is_ceiling_rejection(e: &Error) -> bool {
    e.kind() == ErrorKind::InvalidArgument && e.backend() == BACKEND && e.retry_hint().is_some()
}

/// The verifier's refusal of a source that answered with another version than asked for.
fn other_version() -> Error {
    Error::new(
        ErrorKind::Backend,
        BACKEND,
        Operation::Verify,
        "public key source returned a different key version than requested",
    )
}

/// Whether `e` is [`other_version`]: the only `Backend` error the verifier itself makes.
fn is_other_version(e: &Error) -> bool {
    e.kind() == ErrorKind::Backend && e.backend() == BACKEND
}

/// Whether a failure under a cached public key is worth a [`CachedVerifier::recheck`].
fn mismatch(r: &Result<()>) -> bool {
    r.as_ref()
        .is_err_and(|e| e.kind() == ErrorKind::VerificationFailed)
}

impl<P> crate::PinnedVerifier for CachedVerifier<P> {
    fn pinned_algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl<P: PublicKeys> CachedVerifier<P> {
    async fn verify_digest_once(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        let (v, cached) = self.verifier(sig).await.map_err(unknown_version_fails)?;
        let r = v.verify_digest(digest, sig).await;
        if cached && mismatch(&r) && self.recheck(&sig.key_version().cloned(), &v).await {
            return self
                .verifier(sig)
                .await
                .map_err(unknown_version_fails)?
                .0
                .verify_digest(digest, sig)
                .await;
        }
        r
    }

    async fn verify_message_once(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let (v, cached) = self.verifier(sig).await.map_err(unknown_version_fails)?;
        let r = v.verify_message(msg, sig).await;
        if cached && mismatch(&r) && self.recheck(&sig.key_version().cloned(), &v).await {
            return self
                .verifier(sig)
                .await
                .map_err(unknown_version_fails)?
                .0
                .verify_message(msg, sig)
                .await;
        }
        r
    }
}

impl<P> CachedVerifier<P> {
    /// How long to wait out `e` before trying once more, if it is the verifier's rejection of a
    /// version above the latest and `retry`'s policy would honor its hint (L16). The verifier
    /// waits itself instead of handing the hinted error to the layer, so the wait spends no
    /// attempt and no budget token: what bounds its cost is the latest-version read it leads to,
    /// at most one per refresh interval and coalesced across callers, so a flood of forged
    /// versions neither reaches the backend nor drains a budget shared with other operations.
    fn ceiling_wait(retry: &RetryLayer, e: &Error) -> Option<Duration> {
        let p = retry.policy();
        if !p.retry_on_hint || p.max_attempts < 2 || !is_ceiling_rejection(e) {
            return None;
        }
        e.retry_hint().filter(|h| *h <= p.cap)
    }
}

/// After the wait: a second rejection has nothing left for a retry layer to act on.
fn waited(r: Result<()>) -> Result<()> {
    r.map_err(|e| {
        if is_ceiling_rejection(&e) {
            above_latest()
        } else {
            e
        }
    })
}

impl<P: PublicKeys> CachedVerifier<P> {
    async fn verify_digest_waiting(
        &self,
        retry: &RetryLayer,
        digest: &Digest,
        sig: &Signature,
    ) -> Result<()> {
        let r = self.verify_digest_once(digest, sig).await;
        match r.as_ref().err().and_then(|e| Self::ceiling_wait(retry, e)) {
            Some(wait) => {
                retry.sleep(wait).await;
                waited(self.verify_digest_once(digest, sig).await)
            }
            None => r,
        }
    }

    async fn verify_message_waiting(
        &self,
        retry: &RetryLayer,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<()> {
        let r = self.verify_message_once(msg, sig).await;
        match r.as_ref().err().and_then(|e| Self::ceiling_wait(retry, e)) {
            Some(wait) => {
                retry.sleep(wait).await;
                waited(self.verify_message_once(msg, sig).await)
            }
            None => r,
        }
    }
}

impl<P: PublicKeys> DigestVerifier for CachedVerifier<P> {
    async fn verify_digest(&self, digest: &Digest, sig: &Signature) -> Result<()> {
        match &self.retry {
            Some(retry) => {
                retry
                    .call(|| self.verify_digest_waiting(retry, digest, sig))
                    .await
            }
            None => self.verify_digest_once(digest, sig).await,
        }
    }
}

impl<P: PublicKeys> MessageVerifier for CachedVerifier<P> {
    async fn verify_message(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        match &self.retry {
            Some(retry) => {
                retry
                    .call(|| self.verify_message_waiting(retry, msg, sig))
                    .await
            }
            None => self.verify_message_once(msg, sig).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use anykms_core::{AsymmetricKeyType, PublicKey, SignatureAlgorithm};
    use p256::pkcs8::EncodePublicKey as _;
    use signature::hazmat::PrehashSigner as _;

    use super::*;

    const ALG: SignatureAlgorithm = SignatureAlgorithm::EcdsaP256Sha256;

    /// A P-256 key with versions `1..=latest` that counts backend calls. Like transit,
    /// `public_key_version` rejects non-numeric versions with `InvalidArgument` and versions above
    /// the latest with `UnknownKeyVersion` carrying transit's retry hint. It yields `delay` times before
    /// answering (to let concurrent callers pile up) and fails with `fail` if set (with
    /// `fail_hint` as the retry hint); `public_key` fails with `latest_fail` if set. Each
    /// waits while its `hang` flag is set.
    /// Bumping `epoch` models deleting and recreating the key: other key material per version.
    struct Source {
        latest: Arc<AtomicU64>,
        epoch: AtomicU64,
        delay: usize,
        fail: Option<ErrorKind>,
        fail_hint: Option<Duration>,
        latest_fail: Mutex<Option<ErrorKind>>,
        hang: AtomicBool,
        latest_hang: AtomicBool,
        version_calls: AtomicUsize,
        latest_calls: AtomicUsize,
    }

    impl Source {
        fn new(latest: u64) -> Self {
            Self {
                latest: Arc::new(AtomicU64::new(latest)),
                epoch: AtomicU64::new(0),
                delay: 0,
                fail: None,
                fail_hint: None,
                latest_fail: Mutex::new(None),
                hang: AtomicBool::new(false),
                latest_hang: AtomicBool::new(false),
                version_calls: AtomicUsize::new(0),
                latest_calls: AtomicUsize::new(0),
            }
        }

        fn signing_key(epoch: u64, v: u64) -> p256::ecdsa::SigningKey {
            p256::ecdsa::SigningKey::from_slice(&[u8::try_from(epoch * 100 + v).unwrap(); 32])
                .unwrap()
        }

        fn pk(&self, v: u64) -> PublicKey {
            let der = Self::signing_key(self.epoch.load(Ordering::SeqCst), v)
                .verifying_key()
                .to_public_key_der()
                .unwrap();
            PublicKey::new(
                AsymmetricKeyType::EcP256,
                der.as_bytes().to_vec(),
                Some(KeyVersion::from_u64(v)),
            )
        }

        fn versions(&self) -> usize {
            self.version_calls.load(Ordering::SeqCst)
        }

        fn latests(&self) -> usize {
            self.latest_calls.load(Ordering::SeqCst)
        }

        fn fail_latest(&self, kind: Option<ErrorKind>) {
            *self.latest_fail.lock().unwrap() = kind;
        }
    }

    /// Yields once to the executor (runtime-agnostic).
    async fn yield_now() {
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }

    impl PublicKeys for Source {
        async fn public_key(&self) -> Result<PublicKey> {
            self.latest_calls.fetch_add(1, Ordering::SeqCst);
            while self.latest_hang.load(Ordering::SeqCst) {
                yield_now().await;
            }
            if let Some(kind) = *self.latest_fail.lock().unwrap() {
                return Err(Error::new(kind, "test", Operation::PublicKey, "stub"));
            }
            Ok(self.pk(self.latest.load(Ordering::SeqCst)))
        }

        async fn public_key_version(&self, version: &KeyVersion) -> Result<PublicKey> {
            self.version_calls.fetch_add(1, Ordering::SeqCst);
            for _ in 0..self.delay {
                yield_now().await;
            }
            while self.hang.load(Ordering::SeqCst) {
                yield_now().await;
            }
            if let Some(kind) = self.fail {
                let e = Error::new(kind, "test", Operation::PublicKey, "stub");
                return Err(match self.fail_hint {
                    Some(h) => e.with_retry_hint(h),
                    None => e,
                });
            }
            let latest = self.latest.load(Ordering::SeqCst);
            match version.as_u64() {
                Some(v) if (1..=latest).contains(&v) => Ok(self.pk(v)),
                Some(v) => {
                    let e = Error::new(
                        ErrorKind::UnknownKeyVersion,
                        "test",
                        Operation::PublicKey,
                        "no such version",
                    );
                    Err(if v > latest {
                        e.with_retry_hint(LAG_HINT)
                    } else {
                        e
                    })
                }
                None => Err(Error::new(
                    ErrorKind::InvalidArgument,
                    "test",
                    Operation::PublicKey,
                    "versions are numeric",
                )),
            }
        }
    }

    fn signed(v: u64, digest: &Digest) -> Signature {
        signed_in(0, v, digest)
    }

    /// Signed by version `v` of the key as it was in `epoch`.
    fn signed_in(epoch: u64, v: u64, digest: &Digest) -> Signature {
        let s: p256::ecdsa::Signature = Source::signing_key(epoch, v)
            .sign_prehash(digest.as_bytes())
            .unwrap();
        Signature::from_parts(
            ALG,
            Some(KeyVersion::from_u64(v)),
            s.to_der().as_bytes().to_vec(),
        )
    }

    fn with_version(sig: &Signature, v: &str) -> Signature {
        Signature::from_parts(
            sig.algorithm(),
            Some(KeyVersion::new(v)),
            sig.as_bytes().to_vec(),
        )
    }

    fn len<P>(cv: &CachedVerifier<P>) -> usize {
        cv.lock().entries.len()
    }

    #[tokio::test]
    async fn concurrent_lookups_of_one_version_are_coalesced() {
        let cv = CachedVerifier::new(
            Source {
                delay: 5,
                ..Source::new(2)
            },
            ALG,
        );
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let all = futures_join_all((0..16).map(|_| cv.verify_digest(&d, &sig))).await;
        assert!(all.iter().all(std::result::Result::is_ok));
        assert_eq!(cv.source.versions(), 1);
        // Cached afterwards.
        cv.verify_digest(&d, &sig).await.unwrap();
        assert_eq!(cv.source.versions(), 1);
    }

    #[tokio::test]
    async fn concurrent_failures_are_shared_but_transient_ones_not_cached() {
        let cv = CachedVerifier::new(
            Source {
                delay: 5,
                fail: Some(ErrorKind::Unavailable),
                ..Source::new(2)
            },
            ALG,
        );
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let all = futures_join_all((0..8).map(|_| cv.verify_digest(&d, &sig))).await;
        assert!(
            all.iter()
                .all(|r| r.as_ref().unwrap_err().kind() == ErrorKind::Unavailable)
        );
        assert_eq!(cv.source.versions(), 1);
        // Not remembered: the next call asks again.
        cv.verify_digest(&d, &sig).await.unwrap_err();
        assert_eq!(cv.source.versions(), 2);
    }

    #[tokio::test]
    async fn unknown_versions_are_negatively_cached() {
        let cv = CachedVerifier::new(Source::new(2), ALG).allow_versions_above_latest();
        let d = Digest::sha256(b"m");
        let forged = with_version(&signed(1, &d), "abc");
        for _ in 0..5 {
            let e = cv.verify_digest(&d, &forged).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        }
        assert_eq!(cv.source.versions(), 1);
        // Expired negative entries are fetched again.
        let cv = CachedVerifier::new(Source::new(2), ALG)
            .allow_versions_above_latest()
            .with_negative_ttl(Duration::ZERO);
        cv.verify_digest(&d, &forged).await.unwrap_err();
        cv.verify_digest(&d, &forged).await.unwrap_err();
        assert_eq!(cv.source.versions(), 2);
    }

    #[tokio::test]
    async fn versions_above_latest_are_rejected_without_fetching() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        let base = signed(1, &d);
        for v in 3..50 {
            let e = cv
                .verify_digest(&d, &with_version(&base, &v.to_string()))
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument);
            assert!(hinted(&e));
        }
        assert_eq!(cv.source.versions(), 0);
        // The latest version is read once per refresh interval (500 ms), not per request.
        assert_eq!(cv.source.latests(), 1);
        // Known versions still verify.
        cv.verify_digest(&d, &base).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        // With a zero interval the latest version is re-read each time (picks up rotations).
        let cv =
            CachedVerifier::new(Source::new(2), ALG).with_latest_refresh_interval(Duration::ZERO);
        cv.verify_digest(&d, &with_version(&base, "3"))
            .await
            .unwrap_err();
        cv.verify_digest(&d, &with_version(&base, "3"))
            .await
            .unwrap_err();
        assert_eq!(cv.source.latests(), 2);
    }

    #[tokio::test]
    async fn cache_is_bounded() {
        let cv = CachedVerifier::new(Source::new(10), ALG).with_max_entries(3);
        let d = Digest::sha256(b"m");
        for v in 1..=10 {
            cv.verify_digest(&d, &signed(v, &d)).await.unwrap();
            assert!(len(&cv) <= 3, "{} entries", len(&cv));
        }
        // The most recent versions are still cached.
        let before = cv.source.versions();
        cv.verify_digest(&d, &signed(10, &d)).await.unwrap();
        assert_eq!(cv.source.versions(), before);
    }

    /// Transit's replica-lag hint.
    const LAG_HINT: Duration = Duration::from_millis(500);

    fn hinted(e: &Error) -> bool {
        e.retry_hint().is_some()
    }

    #[tokio::test]
    async fn ceiling_rejections_carry_a_hint_and_a_hinted_retry_recovers() {
        let source = Source::new(1);
        let latest = source.latest.clone();
        let cv = CachedVerifier::new(source, ALG);
        let d = Digest::sha256(b"m");
        let e = cv.verify_digest(&d, &signed(2, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert_eq!(e.retry_hint(), Some(DEFAULT_LATEST_REFRESH));
        // The replica catches up while the retry waits; the retry re-reads the latest version.
        let sleep: anykms_core::SleepFn = Arc::new(move |dur| {
            latest.store(2, Ordering::SeqCst);
            Box::pin(tokio::time::sleep(dur))
        });
        let policy = anykms_core::RetryPolicy::default().with_retry_on_hint(true);
        let retrying = cv.with_retry(&anykms_core::RetryLayer::new(sleep).with_policy(policy));
        retrying.verify_digest(&d, &signed(2, &d)).await.unwrap();
        assert_eq!(retrying.source.latests(), 2);
    }

    #[tokio::test]
    async fn hinted_lookup_failures_are_cached_briefly() {
        let lagging = |hint| Source {
            fail: Some(ErrorKind::UnknownKeyVersion),
            fail_hint: Some(hint),
            ..Source::new(2)
        };
        let d = Digest::sha256(b"m");
        // Remembered for the hint (500 ms, shorter than the negative TTL)...
        let cv = CachedVerifier::new(lagging(LAG_HINT), ALG);
        for _ in 0..3 {
            let e = cv.verify_digest(&d, &signed(1, &d)).await.unwrap_err();
            assert!(hinted(&e));
        }
        assert_eq!(cv.source.versions(), 1);
        let (_, ttl, _) = cv.lock().negative[&Some(KeyVersion::from_u64(1))].clone();
        assert_eq!(ttl, LAG_HINT);
        // ... so the hinted retry, which waits at least that long, asks again.
        let cv = CachedVerifier::new(lagging(Duration::ZERO), ALG);
        for _ in 0..3 {
            cv.verify_digest(&d, &signed(1, &d)).await.unwrap_err();
        }
        assert_eq!(cv.source.versions(), 3);
    }

    /// Transit hints a retry for a version above its latest (replica lag). Without the version
    /// ceiling such forged versions reach the backend, but each only once per refresh interval.
    #[tokio::test]
    async fn forged_versions_above_latest_are_negatively_cached_without_the_ceiling() {
        let cv = CachedVerifier::new(Source::new(2), ALG).allow_versions_above_latest();
        let d = Digest::sha256(b"m");
        let forged = with_version(&signed(1, &d), "999999");
        for _ in 0..20 {
            let e = cv.verify_digest(&d, &forged).await.unwrap_err();
            // A3: the source's UnknownKeyVersion is a failed verification, the original kept
            // as the source, the hint kept for the retry layer; the class stays Caller.
            assert_eq!(e.kind(), ErrorKind::VerificationFailed);
            assert!(hinted(&e));
            assert_eq!(e.class(), anykms_core::ErrorClass::Caller);
            let src = std::error::Error::source(&e)
                .and_then(|s| s.downcast_ref::<Error>())
                .expect("the source's error");
            assert_eq!(src.kind(), ErrorKind::UnknownKeyVersion);
        }
        assert_eq!(cv.source.versions(), 1);
        // Real versions are unaffected.
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
    }

    #[tokio::test]
    async fn signatures_of_another_algorithm_are_rejected_before_any_lookup() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        let s = signed(1, &d);
        for alg in SignatureAlgorithm::ALL.iter().filter(|a| **a != ALG) {
            let relabeled =
                Signature::from_parts(*alg, s.key_version().cloned(), s.as_bytes().to_vec());
            let e = cv.verify_digest(&d, &relabeled).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{alg}");
        }
        assert_eq!((cv.source.versions(), cv.source.latests()), (0, 0));
        // A verifier for another algorithm refuses this key once it sees it.
        let cv = CachedVerifier::new(Source::new(2), SignatureAlgorithm::EcdsaP384Sha384);
        let relabeled = Signature::from_parts(
            SignatureAlgorithm::EcdsaP384Sha384,
            s.key_version().cloned(),
            s.as_bytes().to_vec(),
        );
        let e = cv
            .verify_digest(&Digest::sha384(b"m"), &relabeled)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::KeyMismatch);
    }

    /// A key deleted and recreated restarts at version 1 with new key material: the first
    /// signature of the new key drops the stale cache (the latest version went down) and verifies.
    #[tokio::test]
    async fn a_recreated_key_with_lower_versions_invalidates_the_cache() {
        let cv =
            CachedVerifier::new(Source::new(3), ALG).with_latest_refresh_interval(Duration::ZERO);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(3, &d)).await.unwrap();
        cv.source.epoch.store(1, Ordering::SeqCst);
        cv.source.latest.store(1, Ordering::SeqCst);
        cv.verify_digest(&d, &signed_in(1, 1, &d)).await.unwrap();
        // The old key's version 1 no longer verifies, and its version 3 is gone.
        let e = cv.verify_digest(&d, &signed(1, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed);
        let e = cv.verify_digest(&d, &signed(3, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    }

    /// Recreated and rotated back up to the same latest version: the latest version's public key
    /// changed, which also drops the cache.
    #[tokio::test]
    async fn a_recreated_key_with_the_same_latest_version_invalidates_the_cache() {
        let cv =
            CachedVerifier::new(Source::new(2), ALG).with_latest_refresh_interval(Duration::ZERO);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        cv.source.epoch.store(1, Ordering::SeqCst);
        let before = cv.source.versions();
        cv.verify_digest(&d, &signed_in(1, 2, &d)).await.unwrap();
        cv.verify_digest(&d, &signed_in(1, 1, &d)).await.unwrap();
        assert_eq!(cv.source.versions(), before + 2);
        // Without a refresh (within the interval) a bad signature costs no extra read.
        let cv = CachedVerifier::new(Source::new(2), ALG);
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        for _ in 0..5 {
            cv.verify_digest(&d, &signed(2, &Digest::sha256(b"x")))
                .await
                .unwrap_err();
        }
        assert_eq!(cv.source.latests(), 1);
    }

    /// Recreated and rotated past the cached versions: neither the latest version nor its public
    /// key gives it away, but the re-fetch of the failing signature's version does.
    #[tokio::test]
    async fn a_recreated_key_rotated_past_the_cached_versions_invalidates_the_cache() {
        let cv =
            CachedVerifier::new(Source::new(1), ALG).with_latest_refresh_interval(Duration::ZERO);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.source.epoch.store(1, Ordering::SeqCst);
        cv.source.latest.store(2, Ordering::SeqCst);
        cv.verify_digest(&d, &signed_in(1, 1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed_in(1, 2, &d)).await.unwrap();
        let e = cv.verify_digest(&d, &signed(1, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed);
    }

    /// Bad signatures under a cached key re-fetch it at most once per refresh interval, however
    /// many arrive and whichever cached versions they name.
    #[tokio::test]
    async fn bad_signatures_refetch_at_most_once_per_refresh_interval() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        let other = Digest::sha256(b"x");
        let bad: Vec<_> = (0..16).map(|i| signed(1 + i % 2, &other)).collect();
        let forged = futures_join_all(bad.iter().map(|s| cv.verify_digest(&d, s))).await;
        for e in forged {
            assert_eq!(e.unwrap_err().kind(), ErrorKind::VerificationFailed);
        }
        for v in 1..=2 {
            for _ in 0..10 {
                cv.verify_digest(&d, &signed(v, &other)).await.unwrap_err();
            }
        }
        assert_eq!((cv.source.versions(), cv.source.latests()), (3, 1));
        // The cached keys survive the checks.
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        assert_eq!(cv.source.versions(), 3);
        // Once the interval has passed, one more.
        let cv = CachedVerifier::new(Source::new(2), ALG)
            .with_latest_refresh_interval(Duration::from_millis(50));
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(1, &other)).await.unwrap_err();
        cv.verify_digest(&d, &signed(1, &other)).await.unwrap_err();
        assert_eq!(cv.source.versions(), 2);
        tokio::time::sleep(Duration::from_millis(60)).await;
        cv.verify_digest(&d, &signed(1, &other)).await.unwrap_err();
        assert_eq!(cv.source.versions(), 3);
    }

    #[tokio::test]
    async fn invalidate_during_a_lookup_does_not_cache_its_result() {
        let source = Source::new(2);
        source.hang.store(true, Ordering::SeqCst);
        let cv = CachedVerifier::new(source, ALG);
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let mut lookup = Box::pin(cv.verify_digest(&d, &sig));
        assert!(lookup.as_mut().poll(&mut cx).is_pending());
        cv.invalidate();
        cv.source.hang.store(false, Ordering::SeqCst);
        lookup.await.unwrap();
        assert_eq!(len(&cv), 0);
        cv.verify_digest(&d, &sig).await.unwrap();
        assert_eq!(cv.source.versions(), 2);
    }

    #[tokio::test]
    async fn a_dropped_latest_reader_hands_over_to_waiters() {
        let source = Source::new(2);
        source.latest_hang.store(true, Ordering::SeqCst);
        let cv = CachedVerifier::new(source, ALG);
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let mut leader = Box::pin(cv.verify_digest(&d, &sig));
        let mut waiter = Box::pin(cv.verify_digest(&d, &sig));
        assert!(leader.as_mut().poll(&mut cx).is_pending());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        drop(leader);
        cv.source.latest_hang.store(false, Ordering::SeqCst);
        waiter.await.unwrap();
        assert_eq!(cv.source.latests(), 2);
    }

    #[tokio::test]
    async fn a_dropped_refetcher_hands_over_to_waiters() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.source.hang.store(true, Ordering::SeqCst);
        let bad = signed(1, &Digest::sha256(b"x"));
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let mut leader = Box::pin(cv.verify_digest(&d, &bad));
        let mut waiter = Box::pin(cv.verify_digest(&d, &bad));
        assert!(leader.as_mut().poll(&mut cx).is_pending());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        drop(leader);
        cv.source.hang.store(false, Ordering::SeqCst);
        let e = waiter.await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed);
        assert_eq!(cv.source.versions(), 3);
    }

    #[tokio::test]
    async fn unknown_latest_refuses_versions_instead_of_fetching_them() {
        let source = Source::new(5);
        source.fail_latest(Some(ErrorKind::Unavailable));
        let cv = CachedVerifier::new(source, ALG);
        let d = Digest::sha256(b"m");
        let base = signed(1, &d);
        for v in 1..50 {
            let e = cv
                .verify_digest(&d, &with_version(&base, &v.to_string()))
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Unavailable);
            assert!(e.is_retryable());
        }
        assert_eq!(cv.source.versions(), 0);
        // One read per refresh interval, not one per request.
        assert_eq!(cv.source.latests(), 1);

        // Once the latest version is known, versions up to it keep working while reads fail;
        // versions above it fail with the read's error.
        let cv =
            CachedVerifier::new(Source::new(2), ALG).with_latest_refresh_interval(Duration::ZERO);
        cv.verify_digest(&d, &base).await.unwrap();
        cv.source.fail_latest(Some(ErrorKind::Unavailable));
        cv.verify_digest(&d, &base).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        let e = cv.verify_digest(&d, &signed(3, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unavailable);
        assert_eq!(cv.source.versions(), 2);
        cv.source.fail_latest(None);
        let e = cv.verify_digest(&d, &signed(3, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    }

    #[tokio::test]
    async fn concurrent_latest_reads_are_coalesced() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let all = futures_join_all((0..16).map(|_| cv.verify_digest(&d, &sig))).await;
        assert!(all.iter().all(std::result::Result::is_ok));
        assert_eq!(cv.source.latests(), 1);
    }

    #[tokio::test]
    async fn non_numeric_versions_of_numeric_keys_never_reach_the_cache() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        let base = signed(1, &d);
        for v in ["abc", "01", "", "1.0", "-1", "99999999999999999999999"] {
            let e = cv
                .verify_digest(&d, &with_version(&base, v))
                .await
                .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument, "{v:?}");
        }
        assert_eq!(cv.source.versions(), 0);
        assert_eq!(len(&cv), 0);
        assert!(cv.lock().negative.is_empty());
    }

    #[tokio::test]
    async fn failed_lookups_do_not_evict_public_keys() {
        let cv = CachedVerifier::new(Source::new(2), ALG)
            .allow_versions_above_latest()
            .with_max_entries(16);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        let base = signed(1, &d);
        for i in 0..100 {
            cv.verify_digest(&d, &with_version(&base, &format!("forged-{i}")))
                .await
                .unwrap_err();
        }
        assert!(cv.lock().negative.len() <= 2);
        let before = cv.source.versions();
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        assert_eq!(cv.source.versions(), before);
    }

    #[tokio::test]
    async fn unversioned_signatures_use_the_current_key() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        let s2 = signed(2, &d);
        let unversioned = Signature::from_parts(ALG, None, s2.as_bytes().to_vec());
        cv.verify_digest(&d, &unversioned).await.unwrap();
        cv.verify_digest(&d, &unversioned).await.unwrap();
        assert_eq!(cv.source.latests(), 1);
        let s1 = signed(1, &d);
        let old = Signature::from_parts(ALG, None, s1.as_bytes().to_vec());
        let e = cv.verify_digest(&d, &old).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed);
    }

    #[tokio::test]
    async fn a_dropped_leader_hands_over_to_waiters() {
        let source = Source::new(2);
        source.hang.store(true, Ordering::SeqCst);
        let cv = CachedVerifier::new(source, ALG);
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let mut leader = Box::pin(cv.verify_digest(&d, &sig));
        let mut waiter = Box::pin(cv.verify_digest(&d, &sig));
        assert!(leader.as_mut().poll(&mut cx).is_pending());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        drop(leader);
        cv.source.hang.store(false, Ordering::SeqCst);
        waiter.await.unwrap();
        assert_eq!(cv.source.versions(), 2);
        assert_eq!(len(&cv), 1);
    }

    /// A source that answers every version request with version 2's public key.
    struct WrongVersion(Source);

    impl PublicKeys for WrongVersion {
        async fn public_key(&self) -> Result<PublicKey> {
            self.0.public_key().await
        }

        async fn public_key_version(&self, _: &KeyVersion) -> Result<PublicKey> {
            self.0.version_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.0.pk(2))
        }
    }

    #[tokio::test]
    async fn a_source_answering_another_version_is_refused_and_negatively_cached() {
        let cv = CachedVerifier::new(WrongVersion(Source::new(2)), ALG);
        let d = Digest::sha256(b"m");
        // Signed by version 2 but naming version 1: without the check, version 2's key would be
        // cached as version 1's and this would verify.
        let sig = with_version(&signed(2, &d), "1");
        let e = cv.verify_digest(&d, &sig).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Backend);
        assert_eq!(len(&cv), 0);
        // L14: the source answers the same way next time (e.g. a version it canonicalizes, such
        // as Azure's case-folded hex), so the refusal is remembered like an unknown version:
        // replaying the signature costs no further lookup.
        for _ in 0..5 {
            let e = cv.verify_digest(&d, &sig).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Backend);
        }
        assert_eq!(cv.source.0.versions(), 1);
    }

    #[tokio::test]
    async fn clones_share_the_cache_until_reconfigured() {
        let cv = CachedVerifier::new(Source::new(2), ALG);
        let d = Digest::sha256(b"m");
        let sig = signed(1, &d);
        let clone = cv.clone();
        clone.verify_digest(&d, &sig).await.unwrap();
        cv.verify_digest(&d, &sig).await.unwrap();
        assert_eq!(cv.source.versions(), 1);
        assert_eq!(len(&cv), 1);
        // A builder method on a clone detaches it: other settings, own cache.
        let other = cv.clone().with_ttl(Duration::from_secs(1));
        assert_eq!(len(&other), 0);
        other.verify_digest(&d, &sig).await.unwrap();
        assert_eq!(cv.source.versions(), 2);
    }

    #[tokio::test]
    async fn message_verification_of_digest_algorithms_names_the_helper() {
        let cv = CachedVerifier::new(Source::new(1), ALG);
        let d = Digest::sha256(b"m");
        let e = cv.verify_message(b"m", &signed(1, &d)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidArgument);
        assert!(e.message().contains("verify_message_hashed"), "{e}");
    }

    /// Polls all futures to completion concurrently on the current task.
    async fn futures_join_all<F: Future>(futs: impl Iterator<Item = F>) -> Vec<F::Output> {
        let mut futs: Vec<_> = futs.map(Box::pin).collect();
        let mut out: Vec<Option<F::Output>> = futs.iter().map(|_| None).collect();
        std::future::poll_fn(|cx| {
            for (f, o) in futs.iter_mut().zip(out.iter_mut()) {
                if o.is_none()
                    && let Poll::Ready(v) = f.as_mut().poll(cx)
                {
                    *o = Some(v);
                }
            }
            if out.iter().all(Option::is_some) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        out.into_iter().map(Option::unwrap).collect()
    }

    /// L15: lookups in flight (forged versions under `allow_versions_above_latest`, or any
    /// version of a non-numeric source) never evict cached public keys, however many there are.
    #[tokio::test]
    async fn in_flight_lookups_do_not_evict_public_keys() {
        let cv = CachedVerifier::new(Source::new(2), ALG)
            .allow_versions_above_latest()
            .with_max_entries(4);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        assert_eq!(cv.source.versions(), 2);
        cv.source.hang.store(true, Ordering::SeqCst);
        let base = signed(1, &d);
        // Twice the entry limit, all in flight at once.
        let forged: Vec<_> = (0..8)
            .map(|i| with_version(&base, &format!("forged-{i}")))
            .collect();
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let mut futs: Vec<_> = forged
            .iter()
            .map(|s| Box::pin(cv.verify_digest(&d, s)))
            .collect();
        for f in &mut futs {
            assert!(f.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(len(&cv), 2, "both public keys still cached");
        cv.source.hang.store(false, Ordering::SeqCst);
        for f in futs {
            f.await.unwrap_err();
        }
        let before = cv.source.versions();
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        cv.verify_digest(&d, &signed(2, &d)).await.unwrap();
        assert_eq!(cv.source.versions(), before, "no re-fetch of a real key");
        // The limit still holds for public keys.
        let cv = CachedVerifier::new(Source::new(10), ALG).with_max_entries(3);
        for v in 1..=10 {
            cv.verify_digest(&d, &signed(v, &d)).await.unwrap();
            assert!(len(&cv) <= 3, "{} entries", len(&cv));
        }
    }

    /// L14(b): a disabled version (`KeyVersionUnusable`) fails again on every lookup, so it is
    /// remembered like an unknown one.
    #[tokio::test]
    async fn unusable_versions_are_negatively_cached() {
        let source = Source {
            fail: Some(ErrorKind::KeyVersionUnusable),
            ..Source::new(2)
        };
        let cv = CachedVerifier::new(source, ALG);
        let d = Digest::sha256(b"m");
        for _ in 0..5 {
            let e = cv.verify_digest(&d, &signed(1, &d)).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::KeyVersionUnusable);
        }
        assert_eq!(cv.source.versions(), 1, "one lookup per negative TTL");
    }

    /// L16: rejections of versions above the latest are waited out by the verifier itself (one
    /// coalesced latest-version read per refresh interval), not by a hinted retry of the layer,
    /// so a flood of forged versions does not drain the layer's retry budget: other retries
    /// sharing the layer, and the rotation case the hint exists for, keep working.
    #[tokio::test]
    async fn forged_versions_do_not_drain_a_shared_retry_budget() {
        use anykms_core::{RetryLayer, RetryPolicy};
        let interval = Duration::from_millis(20);
        let sleep: anykms_core::SleepFn = Arc::new(|d| Box::pin(tokio::time::sleep(d)));
        let policy = RetryPolicy::default()
            .with_retry_on_hint(true)
            .with_backoff(Duration::from_millis(1), Duration::from_millis(50))
            .with_max_attempts(3);
        let retry = RetryLayer::new(sleep).with_policy(policy);
        let source = Source::new(2);
        let latest = source.latest.clone();
        let cv = CachedVerifier::new(source, ALG)
            .with_latest_refresh_interval(interval)
            .with_retry(&retry);
        let d = Digest::sha256(b"m");
        cv.verify_digest(&d, &signed(1, &d)).await.unwrap();
        let fetched = cv.source.versions();
        let forged = with_version(&signed(1, &d), "999999");
        for _ in 0..30 {
            let e = cv.verify_digest(&d, &forged).await.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidArgument);
            // Already waited out: nothing left for a layer to retry.
            assert!(!hinted(&e), "{e}");
        }
        assert_eq!(
            cv.source.versions(),
            fetched,
            "forged versions are never fetched"
        );
        // An unrelated transient error on the same layer is still retried.
        let calls = AtomicUsize::new(0);
        let r: Result<()> = retry
            .call(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(Error::new(
                        ErrorKind::Unavailable,
                        "t",
                        Operation::Verify,
                        "x",
                    ))
                }
            })
            .await;
        r.unwrap_err();
        assert!(calls.load(Ordering::SeqCst) > 1, "transient error retried");
        // And a version signed right after a rotation verifies once the latest is re-read.
        latest.store(3, Ordering::SeqCst);
        cv.verify_digest(&d, &signed(3, &d)).await.unwrap();
        // Without a retry layer the rejection still carries the hint, for the caller to act on.
        let bare = CachedVerifier::new(Source::new(2), ALG);
        let e = bare.verify_digest(&d, &forged).await.unwrap_err();
        assert_eq!(e.retry_hint(), Some(DEFAULT_LATEST_REFRESH));
    }

    /// A builder method called on a verifier that already cached public keys drops them, so the
    /// new setting applies to every later verification, not only to versions fetched later.
    #[tokio::test]
    async fn builder_methods_on_a_used_verifier_reset_its_cache() {
        let cv = CachedVerifier::new(Source::new(1), ALG);
        let d = Digest::sha256(b"m");
        let low: p256::ecdsa::Signature = Source::signing_key(0, 1)
            .sign_prehash(d.as_bytes())
            .unwrap();
        let low = low.normalize_s();
        let high = p256::ecdsa::Signature::from_scalars(low.r(), -low.s()).unwrap();
        let sig = |s: p256::ecdsa::Signature| {
            Signature::from_parts(
                ALG,
                Some(KeyVersion::from_u64(1)),
                s.to_der().as_bytes().to_vec(),
            )
        };
        cv.verify_digest(&d, &sig(high)).await.unwrap();
        let strict = cv.require_low_s();
        assert_eq!(len(&strict), 0);
        let e = strict.verify_digest(&d, &sig(high)).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::VerificationFailed);
        strict.verify_digest(&d, &sig(low)).await.unwrap();
    }
}
