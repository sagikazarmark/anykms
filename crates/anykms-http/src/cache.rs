//! Helpers for the backends' caches (key descriptions, key bundles, public keys, credentials):
//! expiry with jitter ([`jittered_ttl`]) and one fetch per key at a time ([`SingleFlight`]).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::watch;

/// `ttl` ±10 %, drawn uniformly per call, so entries cached together (at start-up, after a
/// rotation) do not all expire, and refetch, at once. If the OS RNG fails, `ttl` itself.
pub fn jittered_ttl(ttl: Duration) -> Duration {
    let mut b = [0u8; 2];
    match getrandom::fill(&mut b) {
        Ok(()) => ttl.mul_f64(0.9 + 0.2 * f64::from(u16::from_le_bytes(b)) / 65536.0),
        Err(_) => ttl,
    }
}

/// One fetch per key at a time, its result shared with every caller that asked meanwhile.
///
/// The first caller for a key leads the flight: it runs its own fetch, in its own task (nothing
/// is spawned), and publishes the result, success **or** failure, to every caller that joined
/// while it ran. Nothing is kept once the flight lands: the leader stores what should outlive it
/// (a metadata or credential cache) before it [finishes](Leader::finish), and a caller arriving
/// later starts a new flight. If the leader is cancelled (its future dropped) before it
/// finishes, its followers wake up and one of them leads a new flight with its own fetch, so a
/// cancelled caller never strands the others.
///
/// [`run`](Self::run) is the whole pattern; [`join`](Self::join), [`try_lead`](Self::try_lead)
/// and [`follow`](Self::follow) are its parts, for a cache that decides under its own lock
/// whether to wait (the credential cache refreshes ahead of expiry without making the holders
/// of a valid credential wait).
pub struct SingleFlight<K, V> {
    flights: Mutex<Flights<K, V>>,
}

struct Flights<K, V> {
    running: HashMap<K, (u64, watch::Receiver<Option<V>>)>,
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
        }
    }

    fn lock(&self) -> MutexGuard<'_, Flights<K, V>> {
        self.flights.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lead(&self, flights: &mut Flights<K, V>, key: &K) -> Leader<'_, K, V> {
        let (tx, rx) = watch::channel(None);
        let id = flights.next_id;
        flights.next_id = flights.next_id.wrapping_add(1);
        flights.running.insert(key.clone(), (id, rx));
        Leader {
            group: self,
            key: key.clone(),
            id,
            tx,
        }
    }

    /// The result of `fetch`, or of the flight already running for `key`. When that flight's
    /// leader is cancelled, `fetch` runs instead (once).
    pub async fn run<F, Fut>(&self, key: &K, fetch: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        loop {
            match self.join(key) {
                Flight::Leader(leader) => {
                    let v = fetch().await;
                    leader.finish(v.clone());
                    return v;
                }
                Flight::Follower(f) => {
                    if let Some(v) = f.wait().await {
                        return v;
                    }
                }
            }
        }
    }

    /// Follows the flight running for `key`, or leads a new one.
    pub fn join(&self, key: &K) -> Flight<'_, K, V> {
        let mut flights = self.lock();
        if let Some((_, rx)) = flights.running.get(key) {
            return Flight::Follower(Follower { rx: rx.clone() });
        }
        Flight::Leader(self.lead(&mut flights, key))
    }

    /// Follows the flight running for `key`, or `None` if there is none.
    pub fn follow(&self, key: &K) -> Option<Follower<V>> {
        let flights = self.lock();
        let (_, rx) = flights.running.get(key)?;
        Some(Follower { rx: rx.clone() })
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
    /// No flight was running: this caller fetches, then [finishes](Leader::finish).
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
    tx: watch::Sender<Option<V>>,
}

impl<K: Eq + Hash, V> fmt::Debug for Leader<'_, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leader").finish_non_exhaustive()
    }
}

impl<K: Eq + Hash, V> Leader<'_, K, V> {
    fn land(&self, flights: &mut Flights<K, V>) {
        if flights
            .running
            .get(&self.key)
            .is_some_and(|(id, _)| *id == self.id)
        {
            flights.running.remove(&self.key);
        }
    }

    /// Ends the flight and hands `value` to its followers. A caller asking from now on starts a
    /// new flight.
    pub fn finish(self, value: V) {
        let mut flights = self
            .group
            .flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.land(&mut flights);
        self.tx.send_replace(Some(value));
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
    rx: watch::Receiver<Option<V>>,
}

impl<V> fmt::Debug for Follower<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Follower").finish_non_exhaustive()
    }
}

impl<V: Clone> Follower<V> {
    /// The leader's result, or `None` if the leader was cancelled before it finished (then
    /// [`join`](SingleFlight::join) again).
    pub async fn wait(mut self) -> Option<V> {
        let r = self.rx.wait_for(Option::is_some).await.ok()?;
        r.clone()
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
                t >= Duration::from_secs(540) && t <= Duration::from_secs(660),
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
