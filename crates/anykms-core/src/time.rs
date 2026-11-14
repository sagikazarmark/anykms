//! Clock access for every anykms crate.
//!
//! [`Instant`] is a monotonic clock and [`unix_now`] the wall clock, with one implementation per
//! environment:
//!
//! - Everywhere except `wasm32-unknown-unknown` with the `js` feature, [`Instant`] **is**
//!   `std::time::Instant` and [`unix_now`] reads `std::time::SystemTime`.
//! - On `wasm32-unknown-unknown` with the `js` feature (browsers, Node.js, Cloudflare Workers)
//!   `std::time::{Instant, SystemTime}::now` panic, so [`Instant`] reads `performance.now()`
//!   (monotonic, sub-millisecond where the host allows) and [`unix_now`] reads `Date.now()`. The
//!   source is chosen once per thread: `performance.now()` when the host has it, otherwise
//!   `Date.now()`; a reading never comes from the other source. Only forward steps between
//!   successive readings advance [`Instant`], so a wall clock set back (the `Date.now()` source)
//!   or a failed reading leaves it where it was instead of moving it backwards or extending
//!   every TTL by the jump. Cloudflare Workers advance both clocks only across I/O; a `Duration`
//!   measured inside one synchronous section is therefore zero there, which is what the caches and
//!   `Retry` expect.
//!
//! Without the `js` feature, `wasm32-unknown-unknown` keeps the std clock and panics on first use,
//! as it always did: this module never assumes a JS host unless asked. WASI targets have a working
//! std clock and never need the feature.
//!
//! The JS `Instant` offers the subset of `std::time::Instant` the anykms crates use (`now`,
//! `elapsed`, `duration_since` and friends, `+`/`-` with `Duration`, comparisons). It is a
//! different type from `std::time::Instant`, so the application-facing APIs of this crate take a
//! `Duration` or a closure ([`crate::retry::ClockFn`]) rather than an instant. The backend-facing
//! APIs of `anykms-http` (`Expiring`, the span helpers) name [`Instant`] from this module, which
//! is `std::time::Instant` on every target but a JS host; code written against them does the same.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown", feature = "js")))]
mod imp {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub use std::time::Instant;

    /// Time since the Unix epoch; zero if the system clock is before it. Expiry checks use
    /// [`try_unix_now`](super::try_unix_now), which fails instead.
    #[must_use]
    pub fn unix_now() -> Duration {
        try_unix_now().unwrap_or_default()
    }

    /// Time since the Unix epoch, or `None` if the system clock is before it.
    #[must_use]
    pub fn try_unix_now() -> Option<Duration> {
        SystemTime::now().duration_since(UNIX_EPOCH).ok()
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown", feature = "js"))]
mod imp {
    use std::cell::OnceCell;
    use std::ops::{Add, AddAssign, Sub, SubAssign};
    use std::time::Duration;

    use wasm_bindgen::{JsCast, JsValue};

    use super::Monotonic;

    /// `(performance, performance.now)` when the host has them; looked up once per thread
    /// (wasm32-unknown-unknown has one).
    fn performance() -> Option<(JsValue, js_sys::Function)> {
        let global = js_sys::global();
        let perf = js_sys::Reflect::get(&global, &JsValue::from_str("performance")).ok()?;
        if perf.is_undefined() || perf.is_null() {
            return None;
        }
        let now = js_sys::Reflect::get(&perf, &JsValue::from_str("now")).ok()?;
        let now = now.dyn_into::<js_sys::Function>().ok()?;
        Some((perf, now))
    }

    /// One reading of the monotonic clock's source, chosen once per thread: `performance.now()`
    /// if the host has it, `Date.now()` otherwise. `None` when the reading fails; the caller then
    /// keeps the last value rather than switching sources (whose time bases differ).
    fn raw_reading() -> Option<f64> {
        thread_local! {
            static PERF: OnceCell<Option<(JsValue, js_sys::Function)>> = const { OnceCell::new() };
        }
        PERF.with(|cell| match cell.get_or_init(performance) {
            Some((perf, now)) => now.call0(perf).ok()?.as_f64(),
            None => Some(date_now_ms()),
        })
    }

    fn date_now_ms() -> f64 {
        js_sys::Date::now()
    }

    fn ms_to_duration(ms: f64) -> Duration {
        // Negative or NaN readings (a clock before the epoch, an exotic host) become zero
        // rather than a panic in `from_secs_f64`.
        if ms.is_finite() && ms > 0.0 {
            Duration::from_secs_f64(ms / 1000.0)
        } else {
            Duration::ZERO
        }
    }

    /// Time since the Unix epoch, from `Date.now()`; zero for a reading before the epoch or
    /// not a number. Expiry checks use [`try_unix_now`](super::try_unix_now), which fails
    /// instead.
    #[must_use]
    pub fn unix_now() -> Duration {
        ms_to_duration(date_now_ms())
    }

    /// Time since the Unix epoch, from `Date.now()`, or `None` for a reading before the epoch
    /// or not a number.
    #[must_use]
    pub fn try_unix_now() -> Option<Duration> {
        let ms = date_now_ms();
        (ms.is_finite() && ms >= 0.0).then(|| Duration::from_secs_f64(ms / 1000.0))
    }

    /// A measurement of a monotonically nondecreasing clock, from `performance.now()` (or
    /// `Date.now()` when the host has no `performance`). Opaque; useful only through comparison
    /// and subtraction, like `std::time::Instant`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Instant(Duration);

    impl Instant {
        /// The current instant.
        #[must_use]
        pub fn now() -> Self {
            thread_local! {
                static CLOCK: std::cell::RefCell<Monotonic> =
                    const { std::cell::RefCell::new(Monotonic::new()) };
            }
            let raw = raw_reading();
            Self(ms_to_duration(CLOCK.with(|c| c.borrow_mut().advance(raw))))
        }

        /// Time elapsed since `earlier`, or zero if `earlier` is later than `self` (saturating,
        /// as `std::time::Instant::duration_since` has been since Rust 1.60).
        #[must_use]
        pub fn duration_since(&self, earlier: Self) -> Duration {
            self.0.saturating_sub(earlier.0)
        }

        /// Same as [`duration_since`](Self::duration_since).
        #[must_use]
        pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
            self.duration_since(earlier)
        }

        /// Time elapsed since `earlier`, or `None` if `earlier` is later than `self`.
        #[must_use]
        pub fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
            self.0.checked_sub(earlier.0)
        }

        /// Time elapsed since this instant.
        #[must_use]
        pub fn elapsed(&self) -> Duration {
            Self::now().duration_since(*self)
        }

        /// `self + duration`, or `None` on overflow.
        #[must_use]
        pub fn checked_add(&self, duration: Duration) -> Option<Self> {
            self.0.checked_add(duration).map(Self)
        }

        /// `self - duration`, or `None` if the result would precede the clock's origin.
        #[must_use]
        pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
            self.0.checked_sub(duration).map(Self)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Self;

        /// # Panics
        ///
        /// On overflow, like `std::time::Instant`.
        fn add(self, rhs: Duration) -> Self {
            self.checked_add(rhs)
                .expect("overflow when adding duration to instant")
        }
    }

    impl AddAssign<Duration> for Instant {
        fn add_assign(&mut self, rhs: Duration) {
            *self = *self + rhs;
        }
    }

    impl Sub<Duration> for Instant {
        type Output = Self;

        /// # Panics
        ///
        /// If the result would precede the clock's origin, like `std::time::Instant`.
        fn sub(self, rhs: Duration) -> Self {
            self.checked_sub(rhs)
                .expect("overflow when subtracting duration from instant")
        }
    }

    impl SubAssign<Duration> for Instant {
        fn sub_assign(&mut self, rhs: Duration) {
            *self = *self - rhs;
        }
    }

    impl Sub<Instant> for Instant {
        type Output = Duration;

        fn sub(self, rhs: Instant) -> Duration {
            self.duration_since(rhs)
        }
    }
}

pub use imp::{Instant, try_unix_now, unix_now};

/// Turns readings of a clock that can jump backwards or fail (the JS clock sources) into a
/// monotonic clock, in milliseconds: only forward steps between successive readings advance it,
/// so a wall clock set back by X neither moves it backwards nor extends a TTL by X, and a failed
/// reading leaves it where it was.
#[cfg(any(
    test,
    all(target_arch = "wasm32", target_os = "unknown", feature = "js")
))]
#[derive(Debug)]
struct Monotonic {
    last_raw: Option<f64>,
    now_ms: f64,
}

#[cfg(any(
    test,
    all(target_arch = "wasm32", target_os = "unknown", feature = "js")
))]
impl Monotonic {
    const fn new() -> Self {
        Self {
            last_raw: None,
            now_ms: 0.0,
        }
    }

    /// The clock after a reading (`None`: the reading failed).
    fn advance(&mut self, raw: Option<f64>) -> f64 {
        if let Some(r) = raw.filter(|r| r.is_finite()) {
            match self.last_raw {
                // The first reading sets the origin, as the source's own value.
                None => self.now_ms = r.max(0.0),
                Some(last) if r > last => self.now_ms += r - last,
                Some(_) => {}
            }
            self.last_raw = Some(r);
        }
        self.now_ms
    }
}

/// The wall clock as a `SystemTime` ([`unix_now`] after the epoch), for code that compares
/// against or formats `SystemTime` values: a `SystemTime` is a plain value on every target, only
/// `SystemTime::now()` is not.
#[must_use]
pub fn system_now() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + unix_now()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    // The std clock. The JS clock is exercised by `anykms-wasm-tests` under Node (`just wasm`):
    // this crate's test binary cannot build for wasm32 (tokio dev-dependency).
    use super::{Instant, system_now, unix_now};

    #[test]
    fn instant_is_monotonic_and_arithmetic_is_std_like() {
        let a = Instant::now();
        let b = Instant::now();
        assert!(b >= a);
        assert_eq!(a.duration_since(b), Duration::ZERO, "saturating");
        assert!(b.duration_since(a) <= b.elapsed() + Duration::from_millis(1));
        let later = a + Duration::from_secs(5);
        assert!(later > b);
        assert_eq!(later - a, Duration::from_secs(5));
        assert_eq!(later.checked_sub(Duration::from_secs(5)), Some(a));
        assert_eq!(a.checked_duration_since(later), None);
    }

    #[test]
    fn unix_now_is_after_2020() {
        // 2020-01-01T00:00:01Z.
        assert!(unix_now() > Duration::from_secs(1_577_836_801));
        let d = system_now()
            .duration_since(std::time::SystemTime::now())
            .unwrap_or_else(|e| e.duration());
        assert!(d < Duration::from_secs(1), "{d:?}");
    }
}

#[cfg(test)]
mod review_l30_tests {
    use std::time::Duration;

    use super::{Monotonic, try_unix_now, unix_now};

    /// L30(a)/(b): the JS clock's accumulator. A reading from a different time base (the old
    /// per-call `Date.now()` fallback) or a wall clock set back never moves the clock backwards
    /// nor jumps it; a failed reading holds it.
    #[test]
    fn monotonic_accumulator_ignores_backward_jumps_and_failures() {
        let mut m = Monotonic::new();
        assert_eq!(m.advance(Some(100.0)), 100.0);
        assert_eq!(m.advance(Some(150.0)), 150.0);
        // Failed reading: holds.
        assert_eq!(m.advance(None), 150.0);
        assert_eq!(m.advance(Some(f64::NAN)), 150.0);
        // Wall clock set back by an hour: no backwards move, and later progress counts from
        // the new reading, so a TTL is not extended by the jump.
        assert_eq!(m.advance(Some(150.0 - 3_600_000.0)), 150.0);
        assert_eq!(m.advance(Some(150.0 - 3_600_000.0 + 50.0)), 200.0);
        // A negative first reading starts at zero.
        let mut m = Monotonic::new();
        assert_eq!(m.advance(Some(-5.0)), 0.0);
        assert_eq!(m.advance(Some(-1.0)), 4.0);
    }

    /// L30(c): `try_unix_now` reports a usable wall clock instead of zero.
    #[test]
    fn try_unix_now_matches_unix_now() {
        let t = try_unix_now().expect("system clock after 1970");
        assert!(t > Duration::from_secs(1_577_836_801));
        assert!(unix_now().abs_diff(t) < Duration::from_secs(1));
    }
}
