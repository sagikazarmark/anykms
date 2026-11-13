//! Helpers for the backends' caches (key descriptions, key bundles, public keys, credentials):
//! expiry with jitter ([`jittered_ttl`]) and one fetch per key at a time ([`SingleFlight`]).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use anykms_core::SleepFn;
use tokio::sync::watch;

use crate::transport::HttpTransport;

/// `ttl` ±10 %, drawn uniformly per call, so entries cached together (at start-up, after a
/// rotation) do not all expire, and refetch, at once. If the OS RNG fails, `ttl` itself.
/// Saturates at `Duration::MAX` instead of panicking for a huge `ttl` ("cache forever"); adding
/// the result to an `Instant` can still overflow, so callers use `Instant::checked_add`.
pub fn jittered_ttl(ttl: Duration) -> Duration {
    let mut b = [0u8; 2];
    match getrandom::fill(&mut b) {
        Ok(()) => {
            let factor = 0.9 + 0.2 * f64::from(u16::from_le_bytes(b)) / 65536.0;
            // What `Duration::mul_f64` computes, without its overflow panic.
            Duration::try_from_secs_f64(ttl.as_secs_f64() * factor).unwrap_or(Duration::MAX)
        }
        Err(_) => ttl,
    }
}

/// One fetch per key at a time, its result shared with every caller that asked meanwhile.
///
/// The first caller for a key leads the flight: it runs its own fetch, in its own task (nothing
/// is spawned), and publishes the result, success **or** failure, to every caller that joined
/// while it ran. Nothing is kept once the flight lands: the leader stores what should outlive it
/// (a metadata or credential cache) as it [finishes](Leader::finish_and_commit) (see below on
/// superseded leaders), and a caller arriving later starts a new flight. If the leader is
/// cancelled (its future dropped) before it finishes, its followers wake up and one of them
/// leads a new flight with its own fetch, so a cancelled caller never strands the others.
///
/// A leader that is alive but **not being polled** is another matter: nothing is spawned, so its
/// fetch progresses only while its caller polls it. A caller that leads a flight inside one item
/// of a `buffer_unordered` stream and then awaits, from the loop body, an operation that follows
/// the same flight, or that keeps a leading future pinned in an idle `select!` branch, strands
/// its followers: the leader's own HTTP timeout cannot fire while it is not polled. Such a leader
/// still has its fetch **woken** (by the response arriving, or by that timeout's timer), but
/// nothing polls it. A leader runs its fetch through [`Leader::track`] (as
/// [`run_and_commit`](Self::run_and_commit) does) so that its followers can see this. With
/// [`with_max_wait`](Self::with_max_wait), or the transport's bound through
/// [`bound_by`](Self::bound_by) (what the built-in backends do), a follower looks at the leader
/// each time the bound passes, and the first to find its fetch woken at the previous look (or
/// when it started waiting) and not polled since [takes the flight over](Self::take_over): it
/// leads a replacement flight with its own fetch, and the stalled flight's other followers move
/// to it (one replacement fetch, not one per follower). A stalled leader is so replaced between
/// one and two bounds after its fetch was woken. The bound is how long a woken fetch may go
/// unpolled, not how long a fetch may take: a leader that is being polled is never replaced,
/// however long its fetch takes, and neither is one whose fetch is never woken (I/O without a
/// timeout that never completes, or a fetch not run through [`Leader::track`]): its followers
/// wait for it as for a polled one.
///
/// The stalled leader is superseded: if it resumes, it still gets its own fetch's result, but
/// publishes nothing and does not end the replacement flight. A fetch that stored its result
/// itself would still store it once superseded, over the replacement's newer one: a cache stores
/// in the `commit` step of [`run_and_commit`](Self::run_and_commit) (or
/// [`Leader::finish_and_commit`]) instead, which runs only for a flight that was not taken over,
/// atomically with ending it. (The credential cache orders its outcomes by [`Leader::id`]
/// instead: later flights have greater ids.) Without a bound, followers wait for as long as the
/// leader lives.
///
/// [`run`](Self::run) is the whole pattern; [`join`](Self::join), [`try_lead`](Self::try_lead),
/// [`follow`](Self::follow), [`take_over`](Self::take_over) and [`Leader::track`] are its parts,
/// for a cache that decides under its own lock whether to wait (the credential cache refreshes
/// ahead of expiry without making the holders of a valid credential wait).
pub struct SingleFlight<K, V> {
    flights: Mutex<Flights<K, V>>,
    /// Set once, by [`with_max_wait`](Self::with_max_wait) or [`bound_by`](Self::bound_by).
    max_wait: OnceLock<(Duration, SleepFn)>,
}

/// What a [`Follower::wait_bounded`] ended with.
#[derive(Debug)]
pub enum Waited<V> {
    /// The leader's result.
    Done(V),
    /// The leader was cancelled before it finished, or another follower took the flight over:
    /// [`join`](SingleFlight::join) again.
    Cancelled,
    /// The leader stalled: its fetch was woken and then not polled for a whole
    /// [`with_max_wait`](SingleFlight::with_max_wait) bound (see [`SingleFlight`]).
    /// [`take_over`](SingleFlight::take_over) the flight (its [`id`](Follower::id)).
    TimedOut,
}

/// Identifies one flight of a [`SingleFlight`]; a flight started later has a greater id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlightId(u64);

/// What a flight's followers see.
enum Slot<V> {
    Pending,
    Done(V),
    /// Another follower took the flight over: follow the replacement.
    Moved,
}

struct Running<V> {
    id: u64,
    /// Shared with the leader: [`SingleFlight::take_over`] tells the followers of a stalled
    /// flight to move. Dropped from here when the flight lands or is taken over, so once the
    /// leader is gone too the channel closes (a cancelled leader).
    tx: Arc<watch::Sender<Slot<V>>>,
    /// The leader's fetch, as [`Leader::track`] reports it to the followers.
    progress: Arc<Progress>,
}

/// How a leader's [tracked](Leader::track) fetch is getting on: bit 0 is set when the fetch is
/// woken and cleared when it is polled; the other bits count the polls. A follower that reads
/// the same woken state twice, one bound apart, has seen the fetch go unpolled for that long.
#[derive(Debug, Default)]
struct Progress(AtomicU64);

impl Progress {
    const WOKEN: u64 = 1;

    fn load(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// The fetch is about to be polled: one more poll, not woken since. (A wake between the two
    /// steps is lost, harmlessly: the poll that follows sees what it woke for.)
    fn polled(&self) {
        self.0.fetch_add(Self::WOKEN + 1, Ordering::AcqRel);
        self.0.fetch_and(!Self::WOKEN, Ordering::AcqRel);
    }

    fn woken(&self) {
        self.0.fetch_or(Self::WOKEN, Ordering::AcqRel);
    }

    /// Whether the fetch was woken at `then` and has not been polled since (`now`).
    fn stalled(then: u64, now: u64) -> bool {
        then & Self::WOKEN != 0 && now == then
    }
}

/// The waker a tracked fetch is polled with: records the wake, then wakes the leader's task.
struct ProgressWaker {
    progress: Arc<Progress>,
    /// The leader task's waker, as of its last poll.
    task: Mutex<Waker>,
}

impl Wake for ProgressWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.progress.woken();
        self.task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .wake_by_ref();
    }
}

struct Flights<K, V> {
    running: HashMap<K, Running<V>>,
    next_id: u64,
}

impl<K, V> fmt::Debug for SingleFlight<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleFlight").finish_non_exhaustive()
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Default for SingleFlight<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Clone, V: Clone> SingleFlight<K, V> {
    /// No flights.
    pub fn new() -> Self {
        Self {
            flights: Mutex::new(Flights {
                running: HashMap::new(),
                next_id: 0,
            }),
            max_wait: OnceLock::new(),
        }
    }

    /// Bounds how long a follower waits for a **stalled** leader (see the type's docs): once
    /// the leader's fetch has been woken and left unpolled for `max` (measured with `sleep`,
    /// e.g. `tokio::time::sleep`), [`run`](Self::run) takes the flight over with the
    /// follower's own fetch, between one and two `max` after the wake. A leader that is being
    /// polled is never replaced, however long its fetch takes, so `max` need not cover the
    /// fetch: it is how long a stall goes unnoticed, and must stay well above the time a busy
    /// executor may take to poll a woken task.
    pub fn with_max_wait(mut self, max: Duration, sleep: SleepFn) -> Self {
        self.max_wait = OnceLock::from((max, sleep));
        self
    }

    /// Takes the stall bound ([`with_max_wait`](Self::with_max_wait)) from `transport`
    /// ([`HttpTransport::follower_wait`]) unless one is set already: the first bound wins. A
    /// transport without a timer (`None`) leaves it unbounded.
    pub fn bound_by(&self, transport: &dyn HttpTransport) {
        if self.max_wait.get().is_none()
            && let Some(w) = transport.follower_wait()
        {
            let _ = self.max_wait.set(w);
        }
    }

    /// The follower bound, if any ([`with_max_wait`](Self::with_max_wait),
    /// [`bound_by`](Self::bound_by)).
    pub fn max_wait(&self) -> Option<Duration> {
        self.max_wait.get().map(|(d, _)| *d)
    }

    fn follower(&self, running: &Running<V>) -> Follower<V> {
        Follower {
            id: running.id,
            rx: running.tx.subscribe(),
            max_wait: self.max_wait.get().cloned(),
            progress: running.progress.clone(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Flights<K, V>> {
        self.flights.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lead(&self, flights: &mut Flights<K, V>, key: &K) -> Leader<'_, K, V> {
        let tx = Arc::new(watch::channel(Slot::Pending).0);
        let id = flights.next_id;
        flights.next_id = flights.next_id.wrapping_add(1);
        let progress = Arc::<Progress>::default();
        flights.running.insert(
            key.clone(),
            Running {
                id,
                tx: tx.clone(),
                progress: progress.clone(),
            },
        );
        Leader {
            group: self,
            key: key.clone(),
            id,
            tx,
            progress,
        }
    }

    /// The result of `fetch`, or of the flight already running for `key`. When that flight's
    /// leader is cancelled, `fetch` runs instead (once). When that leader stalls (see the type's
    /// docs), the first follower to notice runs `fetch` in a replacement flight that the others
    /// follow. A caller that leads runs `fetch` [tracked](Leader::track).
    pub async fn run<F, Fut>(&self, key: &K, fetch: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        self.run_and_commit(key, fetch, |_| {}).await
    }

    /// [`run`](Self::run), where the caller that runs `fetch` also runs `commit` on its result
    /// (to store it in a cache) as it [finishes](Leader::finish_and_commit) the flight: only if
    /// its flight was not [taken over](Self::take_over) meanwhile, and under the group's lock, so
    /// no replacement flight lands between the check and the store, and a caller that joins
    /// after the flight landed finds what `commit` stored. A superseded leader's caller still
    /// gets its own result, uncommitted. Nothing is committed when the fetch is cancelled, nor
    /// by a caller that followed another's flight (that flight's leader commits).
    ///
    /// `commit` runs with the group's lock held: it must be quick, not block, and not call into
    /// this group.
    pub async fn run_and_commit<F, Fut, C>(&self, key: &K, fetch: F, commit: C) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
        C: FnOnce(&V),
    {
        let mut stalled = None;
        loop {
            let flight = match stalled.take() {
                Some(id) => self.take_over(key, id),
                None => self.join(key),
            };
            match flight {
                Flight::Leader(leader) => {
                    let v = leader.track(fetch()).await;
                    leader.finish_and_commit(v.clone(), commit);
                    return v;
                }
                Flight::Follower(f) => {
                    let id = f.id();
                    match f.wait_bounded().await {
                        Waited::Done(v) => return v,
                        Waited::Cancelled => {}
                        // The leader is alive but stalled: replace its flight.
                        Waited::TimedOut => stalled = Some(id),
                    }
                }
            }
        }
    }

    /// Follows the flight running for `key`, or leads a new one.
    pub fn join(&self, key: &K) -> Flight<'_, K, V> {
        let mut flights = self.lock();
        if let Some(running) = flights.running.get(key) {
            return Flight::Follower(self.follower(running));
        }
        Flight::Leader(self.lead(&mut flights, key))
    }

    /// For a follower whose wait for flight `stalled` [timed out](Waited::TimedOut) (its leader
    /// stalled): if that flight is still the one running for `key`, leads a replacement and
    /// moves the stalled flight's other followers to it (their wait ends with
    /// [`Waited::Cancelled`], and they join the replacement). Otherwise, as
    /// [`join`](Self::join): another follower took over first, or the flight landed.
    pub fn take_over(&self, key: &K, stalled: FlightId) -> Flight<'_, K, V> {
        let mut flights = self.lock();
        match flights.running.get(key) {
            Some(running) if running.id == stalled.0 => {
                if let Some(old) = flights.running.remove(key) {
                    old.tx.send_replace(Slot::Moved);
                }
                Flight::Leader(self.lead(&mut flights, key))
            }
            Some(running) => Flight::Follower(self.follower(running)),
            None => Flight::Leader(self.lead(&mut flights, key)),
        }
    }

    /// Follows the flight running for `key`, or `None` if there is none.
    pub fn follow(&self, key: &K) -> Option<Follower<V>> {
        let flights = self.lock();
        let running = flights.running.get(key)?;
        Some(self.follower(running))
    }

    /// Leads a new flight for `key`, or `None` while one is running.
    pub fn try_lead(&self, key: &K) -> Option<Leader<'_, K, V>> {
        let mut flights = self.lock();
        if flights.running.contains_key(key) {
            return None;
        }
        Some(self.lead(&mut flights, key))
    }
}

/// A caller's place in a [`SingleFlight`].
#[derive(Debug)]
pub enum Flight<'a, K: Eq + Hash, V> {
    /// No flight was running: this caller fetches ([tracked](Leader::track)), then
    /// [finishes](Leader::finish).
    Leader(Leader<'a, K, V>),
    /// A flight is running: [wait](Follower::wait) for its result.
    Follower(Follower<V>),
}

/// The caller that fetches for a flight. Dropping it unfinished (a cancelled fetch) wakes the
/// followers, which then lead again.
pub struct Leader<'a, K: Eq + Hash, V> {
    group: &'a SingleFlight<K, V>,
    key: K,
    id: u64,
    tx: Arc<watch::Sender<Slot<V>>>,
    progress: Arc<Progress>,
}

impl<K: Eq + Hash, V> fmt::Debug for Leader<'_, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leader").finish_non_exhaustive()
    }
}

impl<K: Eq + Hash, V> Leader<'_, K, V> {
    /// This flight's id: greater than that of every flight started before it, a flight that
    /// [took it over](SingleFlight::take_over) included.
    pub fn id(&self) -> FlightId {
        FlightId(self.id)
    }

    /// `fetch`, reporting to the flight's followers when it is woken and when it is polled, so
    /// that they can tell a stalled leader from a slow one (see [`SingleFlight`]). Run the
    /// flight's fetch through it: followers never take over a leader whose fetch is not
    /// tracked.
    pub fn track<F: Future>(&self, fetch: F) -> impl Future<Output = F::Output> + use<F, K, V> {
        let progress = self.progress.clone();
        async move {
            let mut fetch = std::pin::pin!(fetch);
            // Made at the first poll, then reused: only the task waker it forwards to changes.
            let mut proxy: Option<(Arc<ProgressWaker>, Waker)> = None;
            std::future::poll_fn(|cx| {
                progress.polled();
                let (p, waker) = proxy.get_or_insert_with(|| {
                    let p = Arc::new(ProgressWaker {
                        progress: progress.clone(),
                        task: Mutex::new(cx.waker().clone()),
                    });
                    (p.clone(), Waker::from(p))
                });
                {
                    let mut task = p.task.lock().unwrap_or_else(PoisonError::into_inner);
                    if !task.will_wake(cx.waker()) {
                        task.clone_from(cx.waker());
                    }
                }
                fetch.as_mut().poll(&mut Context::from_waker(waker))
            })
            .await
        }
    }

    /// Ends the flight if it is still the one running for its key; `false` if it was taken
    /// over.
    fn land(&self, flights: &mut Flights<K, V>) -> bool {
        let current = flights
            .running
            .get(&self.key)
            .is_some_and(|r| r.id == self.id);
        if current {
            flights.running.remove(&self.key);
        }
        current
    }

    /// Ends the flight and hands `value` to its followers. A caller asking from now on starts a
    /// new flight. A flight that was [taken over](SingleFlight::take_over) has no followers
    /// left: nothing is handed out, and the replacement flight goes on.
    pub fn finish(self, value: V) {
        self.finish_and_commit(value, |_| {});
    }

    /// [`finish`](Self::finish), running `commit` on `value` first (to store it in a cache) if
    /// the flight was not [taken over](SingleFlight::take_over): under the group's lock, so no
    /// replacement flight lands between the check and the store, and before the followers get
    /// `value`. Returns whether `commit` ran; a superseded flight commits nothing.
    ///
    /// `commit` runs with the group's lock held: it must be quick, not block, and not call into
    /// the group.
    pub fn finish_and_commit(self, value: V, commit: impl FnOnce(&V)) -> bool {
        let mut flights = self
            .group
            .flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.land(&mut flights) {
            return false;
        }
        // Should `commit` panic, the flight has landed: its followers see a cancelled leader.
        commit(&value);
        self.tx.send_replace(Slot::Done(value));
        true
    }
}

impl<K: Eq + Hash, V> Drop for Leader<'_, K, V> {
    fn drop(&mut self) {
        let mut flights = self
            .group
            .flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.land(&mut flights);
    }
}

/// A caller waiting for another caller's fetch.
pub struct Follower<V> {
    id: u64,
    rx: watch::Receiver<Slot<V>>,
    max_wait: Option<(Duration, SleepFn)>,
    /// The followed leader's fetch ([`Leader::track`]).
    progress: Arc<Progress>,
}

impl<V> fmt::Debug for Follower<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Follower").finish_non_exhaustive()
    }
}

impl<V: Clone> Follower<V> {
    /// The followed flight's id, for [`SingleFlight::take_over`].
    pub fn id(&self) -> FlightId {
        FlightId(self.id)
    }

    /// The leader's result, or `None` if the leader was cancelled before it finished or the
    /// flight was [taken over](SingleFlight::take_over) (then [`join`](SingleFlight::join)
    /// again).
    pub async fn wait(mut self) -> Option<V> {
        let r = self
            .rx
            .wait_for(|s| !matches!(s, Slot::Pending))
            .await
            .ok()?;
        match &*r {
            Slot::Done(v) => Some(v.clone()),
            Slot::Pending | Slot::Moved => None,
        }
    }

    /// [`wait`](Self::wait), ending with [`Waited::TimedOut`] once the leader is seen stalled:
    /// each time the group's [`with_max_wait`](SingleFlight::with_max_wait) bound passes, the
    /// follower looks at the leader's [tracked](Leader::track) fetch, and gives up if it was
    /// woken at the previous look (or when the wait began) and has not been polled since. A
    /// leader that is being polled, or whose fetch is never woken, is waited for until it
    /// finishes or is cancelled; so is every leader without a bound.
    pub async fn wait_bounded(mut self) -> Waited<V> {
        let Some((max, sleep)) = self.max_wait.take() else {
            return self.wait().await.map_or(Waited::Cancelled, Waited::Done);
        };
        let progress = self.progress.clone();
        let mut seen = progress.load();
        let mut wait = std::pin::pin!(self.wait());
        let mut timer = sleep(max);
        std::future::poll_fn(|cx| {
            if let Poll::Ready(v) = wait.as_mut().poll(cx) {
                return Poll::Ready(v.map_or(Waited::Cancelled, Waited::Done));
            }
            // At most two looks per poll: with a `sleep` that is ready at once, the follower
            // yields between looks instead of spinning here.
            for _ in 0..2 {
                if timer.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                let now = progress.load();
                if Progress::stalled(seen, now) {
                    return Poll::Ready(Waited::TimedOut);
                }
                seen = now;
                timer = sleep(max);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn jitter_stays_within_ten_percent() {
        let ttl = Duration::from_secs(600);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let t = jittered_ttl(ttl);
            assert!(
                t >= Duration::from_secs(540) && t <= Duration::from_mins(11),
                "{t:?}"
            );
            seen.insert(t);
        }
        assert!(seen.len() > 1, "no jitter");
        assert_eq!(jittered_ttl(Duration::ZERO), Duration::ZERO);
    }

    type Group = SingleFlight<&'static str, Result<usize, String>>;

    /// 20 callers of one key: one fetch, its result (success or failure) for all; another key
    /// flies on its own; nothing is kept after landing.
    #[tokio::test(start_paused = true)]
    async fn one_fetch_per_key_and_the_result_is_shared() {
        for ok in [true, false] {
            let group = Arc::new(Group::new());
            let fetches = Arc::new(AtomicUsize::new(0));
            let started = tokio::time::Instant::now();
            let mut tasks = Vec::new();
            for i in 0..21 {
                let (group, fetches) = (group.clone(), fetches.clone());
                let key = if i == 20 { "other" } else { "k" };
                tasks.push(tokio::spawn(async move {
                    group
                        .run(&key, || async {
                            let n = fetches.fetch_add(1, Ordering::SeqCst) + 1;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            if ok { Ok(n) } else { Err(format!("down {n}")) }
                        })
                        .await
                }));
            }
            let mut results = Vec::new();
            for t in tasks {
                results.push(t.await.unwrap());
            }
            let took = started.elapsed();
            assert!(took >= Duration::from_secs(1) && took < Duration::from_millis(1100));
            assert_eq!(fetches.load(Ordering::SeqCst), 2);
            let first = results[0].clone();
            assert!(results[..20].iter().all(|r| *r == first), "{results:?}");
            assert_ne!(results[20], first);
            assert_eq!(first.is_ok(), ok);
            // Landed: the next caller fetches again.
            assert!(group.lock().running.is_empty());
            assert_eq!(group.run(&"k", || async { Ok(0) }).await, Ok(0));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_leader_hands_over_to_a_follower() {
        let group = Arc::new(Group::new());
        let leader = {
            let group = group.clone();
            tokio::spawn(async move {
                group
                    .run(&"k", || async {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        Ok(1)
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        let followers: Vec<_> = (0..3)
            .map(|i| {
                let group = group.clone();
                tokio::spawn(async move {
                    group
                        .run(&"k", || async move {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            Ok(10 + i)
                        })
                        .await
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(10)).await;
        leader.abort();
        let started = tokio::time::Instant::now();
        let mut results = Vec::new();
        for f in followers {
            results.push(f.await.unwrap().unwrap());
        }
        // One follower led the new flight (1 s); the others got its result, without waiting out
        // the cancelled leader's fetch (60 s).
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(results.iter().all(|r| *r == results[0]), "{results:?}");
        assert!(group.lock().running.is_empty());
    }

    #[test]
    fn try_lead_refuses_while_a_flight_runs() {
        let group = Group::new();
        let leader = group.try_lead(&"k").unwrap();
        assert!(group.try_lead(&"k").is_none());
        assert!(matches!(group.join(&"k"), Flight::Follower(_)));
        assert!(group.follow(&"k").is_some());
        assert!(group.follow(&"other").is_none());
        assert!(group.try_lead(&"other").is_some());
        drop(leader);
        assert!(group.try_lead(&"k").is_some());
    }
}

/// Regression tests for the security review (L28, L29).
#[cfg(test)]
mod review_tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;

    use tokio::time::{Instant, sleep};

    use super::*;

    /// L28: "cache forever" (`Duration::MAX`) must not panic.
    #[test]
    fn review_l28_jitter_saturates_for_huge_ttls() {
        for _ in 0..200 {
            let t = jittered_ttl(Duration::MAX);
            assert!(t >= Duration::MAX.mul_f64(0.9), "{t:?}");
        }
    }

    type Group = SingleFlight<&'static str, Result<usize, String>>;

    /// Polls `f` once, expecting it to be pending: a leader that has started its fetch, and that
    /// its caller then stops polling.
    async fn poll_once<F: Future + Unpin>(f: &mut F) {
        std::future::poll_fn(|cx| {
            assert!(Pin::new(&mut *f).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    /// L29: a leader that is alive but never polled again (one `buffer_unordered` item awaited
    /// from the loop body, a pinned `select!` branch) must not hang its followers forever: once
    /// its fetch was woken (here at 1 s) and then left unpolled for the bound, a follower
    /// fetches for itself.
    #[tokio::test(start_paused = true)]
    async fn review_l29_a_follower_does_not_wait_forever_on_an_unpolled_leader() {
        let group: Arc<Group> = Arc::new(review_group());
        let mut leader = Box::pin(group.run(&"k", || async {
            sleep(Duration::from_secs(1)).await;
            Ok(1)
        }));
        poll_once(&mut leader).await;
        let started = Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(120),
            group.run(&"k", || async { Ok(2) }),
        )
        .await;
        assert_eq!(r, Ok(Ok(2)), "the follower hung on the unpolled leader");
        // Seen woken at the first look (30 s), still unpolled at the second.
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        drop(leader);
    }

    /// L29, by default: a group bound by the built-in transport (what every backend does with
    /// its caches) gets twice the transport's connect plus request timeout, and a follower of an
    /// unpolled leader completes after it.
    // `reqwest` alone enables no crypto provider: building the transport needs one.
    #[cfg(all(
        feature = "reqwest",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(start_paused = true)]
    async fn review_l29_the_builtin_transport_bounds_followers() {
        let transport = crate::ReqwestTransport::builder()
            .require_roots(false)
            .build()
            .unwrap();
        let group: Arc<Group> = Arc::new(SingleFlight::new());
        assert_eq!(group.max_wait(), None);
        group.bound_by(&transport);
        // 2 × (2 s connect + 10 s request).
        assert_eq!(group.max_wait(), Some(Duration::from_secs(24)));
        let mut leader = Box::pin(group.run(&"k", || async {
            sleep(Duration::from_secs(1)).await;
            Ok(1)
        }));
        poll_once(&mut leader).await;
        let r = tokio::time::timeout(
            Duration::from_secs(120),
            group.run(&"k", || async { Ok(2) }),
        )
        .await;
        assert_eq!(r, Ok(Ok(2)), "the follower hung on the unpolled leader");
        drop(leader);
    }

    /// A leader that is being polled is never taken over, however long its fetch takes: here
    /// ten 10 s steps (each woken and polled at once), over three times the 30 s bound. Every
    /// follower, whenever it joined, gets the one fetch's result.
    #[tokio::test(start_paused = true)]
    async fn review_a_polled_leader_is_never_taken_over() {
        let group: Arc<Group> = Arc::new(review_group());
        let fetches = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let callers: Vec<_> = (0..8u64)
            .map(|i| {
                let (group, fetches) = (group.clone(), fetches.clone());
                tokio::spawn(async move {
                    // The leader at 0 s, followers at 12, 24 … 84 s.
                    sleep(Duration::from_secs(12 * i)).await;
                    group
                        .run(&"k", || async {
                            let n = fetches.fetch_add(1, Ordering::SeqCst);
                            for _ in 0..10 {
                                sleep(Duration::from_secs(10)).await;
                            }
                            Ok(n)
                        })
                        .await
                })
            })
            .collect();
        let mut results = Vec::new();
        for c in callers {
            results.push(c.await.unwrap());
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "{results:?}");
        assert!(results.iter().all(|r| *r == Ok(0)), "{results:?}");
        assert_eq!(started.elapsed(), Duration::from_secs(100));
        assert!(group.lock().running.is_empty());
    }

    /// A leader whose fetch is never woken (I/O without a timeout that never completes) cannot
    /// be told from a polled one: its followers wait for it, until it is cancelled.
    #[tokio::test(start_paused = true)]
    async fn review_a_leader_never_woken_is_waited_for() {
        let group: Arc<Group> = Arc::new(review_group());
        let mut leader = Box::pin(group.run(&"k", std::future::pending));
        poll_once(&mut leader).await;
        let follower = {
            let group = group.clone();
            tokio::spawn(async move { group.run(&"k", || async { Ok(2) }).await })
        };
        sleep(Duration::from_secs(600)).await;
        assert!(
            !follower.is_finished(),
            "a leader never woken was taken over"
        );
        drop(leader);
        assert_eq!(follower.await.unwrap(), Ok(2));
    }

    /// Followers of a stalled (alive, unpolled) leader, joined at different times, give up
    /// together and share one replacement flight: no burst of one fetch per follower, and the
    /// late joiners do not wait out a bound of their own.
    #[tokio::test(start_paused = true)]
    async fn review_followers_of_a_stalled_leader_share_one_replacement() {
        let group: Arc<Group> = Arc::new(review_group());
        let fetches = Arc::new(AtomicUsize::new(0));
        // Woken at 1 s, never polled again.
        let mut stalled = Box::pin(group.run(&"k", || async {
            sleep(Duration::from_secs(1)).await;
            std::future::pending().await
        }));
        poll_once(&mut stalled).await;
        let started = Instant::now();
        let followers: Vec<_> = (0..8u64)
            .map(|i| {
                let (group, fetches) = (group.clone(), fetches.clone());
                tokio::spawn(async move {
                    // Join at 0, 2 … 14 s.
                    sleep(Duration::from_secs(2 * i)).await;
                    group
                        .run(&"k", || async {
                            let n = fetches.fetch_add(1, Ordering::SeqCst);
                            sleep(Duration::from_secs(1)).await;
                            Ok(10 + n)
                        })
                        .await
                })
            })
            .collect();
        let mut results = Vec::new();
        for f in followers {
            results.push(f.await.unwrap());
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "{results:?}");
        assert!(results.iter().all(|r| *r == Ok(10)), "{results:?}");
        // The follower that joined at 2 s found the fetch woken already and still unpolled one
        // bound (30 s) later; then the replacement fetch (1 s).
        assert_eq!(started.elapsed(), Duration::from_secs(33));
        // The replacement landed; the stalled leader, still alive, holds no flight.
        assert!(group.lock().running.is_empty());
        drop(stalled);
    }

    /// A stalled leader that resumes after a follower took its flight over gets its own result,
    /// but hands it to nobody and does not end the replacement flight: the replacement's
    /// followers get the replacement's result.
    #[tokio::test(start_paused = true)]
    async fn review_a_resumed_stalled_leader_does_not_end_its_replacement() {
        let group: Arc<Group> = Arc::new(review_group());
        let (release_old, gate_old) = tokio::sync::oneshot::channel::<()>();
        let mut stalled = Box::pin(group.run(&"k", || async move {
            sleep(Duration::from_secs(1)).await;
            gate_old.await.unwrap();
            Ok(1)
        }));
        poll_once(&mut stalled).await;
        let (release_new, gate_new) = tokio::sync::oneshot::channel::<()>();
        let replacing = {
            let group = group.clone();
            tokio::spawn(async move {
                group
                    .run(&"k", || async move {
                        gate_new.await.unwrap();
                        Ok(2)
                    })
                    .await
            })
        };
        // Woken at 1 s, seen woken at 30 s and still unpolled at 60 s: taken over.
        sleep(Duration::from_secs(61)).await;
        let late = {
            let group = group.clone();
            tokio::spawn(async move { group.run(&"k", || async { Ok(3) }).await })
        };
        sleep(Duration::from_millis(1)).await;
        // The stalled leader resumes and finishes.
        release_old.send(()).unwrap();
        assert_eq!(stalled.await, Ok(1));
        assert!(
            !group.lock().running.is_empty(),
            "the stalled leader ended the flight that replaced it"
        );
        release_new.send(()).unwrap();
        assert_eq!(replacing.await.unwrap(), Ok(2));
        assert_eq!(late.await.unwrap(), Ok(2));
        assert!(group.lock().running.is_empty());
    }

    /// `run_and_commit`: the stalled leader resumes after a follower took its flight over and
    /// gets its own result, but only the replacement's result is committed (even when the
    /// stalled leader finishes last); a follower commits nothing; a cancelled leader commits
    /// nothing.
    #[tokio::test(start_paused = true)]
    async fn review_only_a_current_leader_commits() {
        let group: Arc<Group> = Arc::new(review_group());
        let committed = Arc::new(Mutex::new(Vec::new()));
        let commit = |c: &Arc<Mutex<Vec<Result<usize, String>>>>| {
            let c = c.clone();
            move |v: &Result<usize, String>| c.lock().unwrap().push(v.clone())
        };

        let (release_old, gate_old) = tokio::sync::oneshot::channel::<()>();
        let mut stalled = Box::pin(group.run_and_commit(
            &"k",
            || async move {
                sleep(Duration::from_secs(1)).await;
                gate_old.await.unwrap();
                Ok(1)
            },
            commit(&committed),
        ));
        poll_once(&mut stalled).await;
        let (release_new, gate_new) = tokio::sync::oneshot::channel::<()>();
        let replacing = {
            let (group, commit) = (group.clone(), commit(&committed));
            tokio::spawn(async move {
                group
                    .run_and_commit(
                        &"k",
                        || async move {
                            gate_new.await.unwrap();
                            Ok(2)
                        },
                        commit,
                    )
                    .await
            })
        };
        // Woken at 1 s, seen woken at 30 s and still unpolled at 60 s: taken over.
        sleep(Duration::from_secs(61)).await;
        let follower = {
            let (group, commit) = (group.clone(), commit(&committed));
            tokio::spawn(
                async move { group.run_and_commit(&"k", || async { Ok(3) }, commit).await },
            )
        };
        sleep(Duration::from_millis(1)).await;
        // The replacement lands first; then the stalled leader resumes.
        release_new.send(()).unwrap();
        assert_eq!(replacing.await.unwrap(), Ok(2));
        assert_eq!(follower.await.unwrap(), Ok(2));
        release_old.send(()).unwrap();
        assert_eq!(stalled.await, Ok(1));
        assert_eq!(*committed.lock().unwrap(), [Ok(2)]);

        // A superseded leader that finishes before its replacement commits nothing either.
        let committed = Arc::new(Mutex::new(Vec::new()));
        let old = group.try_lead(&"k").unwrap();
        let Flight::Follower(f) = group.join(&"k") else {
            panic!("a flight is running")
        };
        let Flight::Leader(new) = group.take_over(&"k", f.id()) else {
            panic!("the stalled flight is replaced")
        };
        assert!(!old.finish_and_commit(Ok(1), commit(&committed)));
        assert!(new.finish_and_commit(Ok(2), commit(&committed)));
        assert_eq!(*committed.lock().unwrap(), [Ok(2)]);

        // A cancelled leader commits nothing; the follower that leads next does.
        let committed = Arc::new(Mutex::new(Vec::new()));
        let leader = {
            let (group, commit) = (group.clone(), commit(&committed));
            tokio::spawn(async move {
                group
                    .run_and_commit(&"k", std::future::pending, commit)
                    .await
            })
        };
        sleep(Duration::from_millis(1)).await;
        let follower = group.follow(&"k").unwrap();
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());
        assert_eq!(follower.wait().await, None);
        assert!(committed.lock().unwrap().is_empty());
        let next = group.run_and_commit(&"k", || async { Ok(4) }, commit(&committed));
        assert_eq!(next.await, Ok(4));
        assert_eq!(*committed.lock().unwrap(), [Ok(4)]);
        assert!(group.lock().running.is_empty());
    }

    /// A transport without a timer leaves the group unbounded, and the first bound wins.
    #[test]
    fn bound_by_keeps_the_first_bound() {
        struct NoTimer;
        impl crate::HttpTransport for NoTimer {
            fn send(
                &self,
                _: crate::transport::Request,
                _: usize,
            ) -> anykms_core::BoxFuture<'_, Result<crate::transport::Response, crate::SendError>>
            {
                unreachable!()
            }
        }
        let group: Group = SingleFlight::new();
        group.bound_by(&NoTimer);
        assert_eq!(group.max_wait(), None);
        let group: Group = review_group();
        group.bound_by(&NoTimer);
        assert_eq!(group.max_wait(), Some(Duration::from_secs(30)));
    }
}

#[cfg(test)]
fn review_group<K: Eq + Hash + Clone, V: Clone>() -> SingleFlight<K, V> {
    SingleFlight::new().with_max_wait(
        Duration::from_secs(30),
        std::sync::Arc::new(|d| Box::pin(tokio::time::sleep(d))),
    )
}
