//! Per-client rate limiting of failed LDAP authentication attempts.
//!
//! Attempts are tracked per client key (see `client_key`): the IPv4 address,
//! or the /64 prefix for IPv6. Each key gets a fixed window of `window`
//! length that starts at its first counted attempt. When `max_failures`
//! failures accumulate inside that window, the key is blocked until
//! `block_duration` has passed and the window has ended, so no key ever gets
//! more than `max_failures` counted attempts per window. While blocked, any
//! LDAP authentication attempt from it is rejected without contacting the
//! LDAP server.
//!
//! To keep concurrent attempts from slipping past the limit, an attempt is
//! counted as a failure when it is admitted (atomically with the block
//! check). The caller refunds it only once it is known not to be a failure
//! (see `auth::free_callback`). A refund only removes that attempt's own
//! count, so a successful login doesn't clear failures from other attempts.
//!
//! The limiter is disabled when `max_failures` is 0 (the default).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use log::{error, warn};

/// Number of tracked keys above which expired entries are pruned.
const MIN_PRUNE_THRESHOLD: usize = 1024;

/// Hard cap on the number of tracked keys, to bound memory under a flood of
/// failed attempts from many distinct addresses. When the cap is reached and
/// no entry has expired, attempts from new keys share the `OVERFLOW_KEY`
/// bucket, so existing counts and blocks are kept and new keys are still
/// limited.
const MAX_TRACKED_KEYS: usize = 100_000;

/// Bucket shared by new keys while the limiter is at `MAX_TRACKED_KEYS`.
const OVERFLOW_KEY: &str = "overflow";

/// Bucket shared by clients whose address could not be determined.
pub const UNKNOWN_KEY: &str = "unknown";

/// Minimum time between full scans for expired entries while at capacity.
const MIN_CAPACITY_PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum time between "limiter is full" warnings.
const OVERFLOW_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Maps a client address, as reported by Valkey, to the key it is rate
/// limited under. IPv6 addresses are grouped by their /64 prefix, since a
/// single host can usually use every address in its /64. IPv4-mapped IPv6
/// addresses are treated as IPv4. Other addresses, such as a Unix socket
/// path, are used as is, and an empty address maps to `UNKNOWN_KEY`.
pub fn client_key(addr: &str) -> String {
    if addr.is_empty() {
        return UNKNOWN_KEY.to_string();
    }
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let prefix = u128::from(v6) & !((1u128 << 64) - 1);
                format!("{}/64", std::net::Ipv6Addr::from(prefix))
            }
        },
        Err(_) => addr.to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimitSettings {
    pub max_failures: u64,
    pub window: Duration,
    pub block_duration: Duration,
}

impl RateLimitSettings {
    pub fn is_enabled(&self) -> bool {
        self.max_failures > 0
    }
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        RateLimitSettings {
            max_failures: 0,
            window: Duration::from_secs(60),
            block_duration: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
struct Entry {
    failures: u64,
    window_start: Instant,
    blocked_until: Option<Instant>,
}

impl Entry {
    fn expires_at(&self, settings: &RateLimitSettings) -> Instant {
        // A block always outlasts the window (see record_failure)
        self.blocked_until
            .unwrap_or(self.window_start + settings.window)
    }

    fn is_expired(&self, now: Instant, settings: &RateLimitSettings) -> bool {
        now >= self.expires_at(settings)
    }
}

/// An attempt admitted by `AuthRateLimiter::begin_attempt`, counted as a
/// failure until refunded.
#[derive(Clone, Debug, PartialEq)]
pub struct Attempt {
    key: String,
    window_start: Instant,
}

/// What `begin_attempt` decided about an attempt.
#[derive(Debug, PartialEq)]
pub enum Admission {
    /// The limiter is disabled.
    NotLimited,
    /// The attempt was counted under `attempt.key`.
    Admitted(Attempt),
    /// The key is blocked for the given remaining time.
    Blocked(Duration),
}

#[derive(Debug)]
pub struct AuthRateLimiter {
    settings: RateLimitSettings,
    entries: HashMap<String, Entry>,
    prune_threshold: usize,
    // While at MAX_TRACKED_KEYS, the earliest time an entry expires, so new
    // keys don't trigger a full scan until something can be pruned. Cleared
    // whenever an entry is removed or its expiry moves earlier.
    next_capacity_prune: Option<Instant>,
    last_capacity_prune: Option<Instant>,
    last_overflow_warn: Option<Instant>,
}

impl AuthRateLimiter {
    pub fn new(settings: RateLimitSettings) -> Self {
        AuthRateLimiter {
            settings,
            entries: HashMap::new(),
            prune_threshold: MIN_PRUNE_THRESHOLD,
            next_capacity_prune: None,
            last_capacity_prune: None,
            last_overflow_warn: None,
        }
    }

    /// Replaces the settings and drops all tracked state.
    pub fn configure(&mut self, settings: RateLimitSettings) {
        *self = AuthRateLimiter::new(settings);
    }

    /// Returns the remaining block time if `key` is currently blocked,
    /// dropping its entry if it has expired.
    fn check(&mut self, key: &str, now: Instant) -> Option<Duration> {
        let entry = self.entries.get(key)?;
        if entry.is_expired(now, &self.settings) {
            self.remove(key);
            return None;
        }
        entry.blocked_until.map(|until| until - now)
    }

    /// Atomically rejects the client if its key is blocked, or else counts
    /// this attempt as a failure under that key.
    pub fn begin_attempt(&mut self, key: &str, now: Instant) -> Admission {
        if !self.settings.is_enabled() {
            return Admission::NotLimited;
        }
        if let Some(remaining) = self.check(key, now) {
            return Admission::Blocked(remaining);
        }
        let key = if self.has_capacity_for(key, now) {
            key
        } else {
            if self
                .last_overflow_warn
                .is_none_or(|t| now.duration_since(t) >= OVERFLOW_WARN_INTERVAL)
            {
                self.last_overflow_warn = Some(now);
                warn!(
                    "auth rate limiter is tracking {MAX_TRACKED_KEYS} clients, new clients share one bucket"
                );
            }
            if let Some(remaining) = self.check(OVERFLOW_KEY, now) {
                return Admission::Blocked(remaining);
            }
            OVERFLOW_KEY
        };
        let window_start = self.record_failure(key, now);
        Admission::Admitted(Attempt {
            key: key.to_string(),
            window_start,
        })
    }

    // Returns true if `key` is tracked or can be added without exceeding
    // MAX_TRACKED_KEYS, pruning expired entries if needed. Full scans happen
    // at most once per MIN_CAPACITY_PRUNE_INTERVAL and only once an entry
    // can have expired.
    fn has_capacity_for(&mut self, key: &str, now: Instant) -> bool {
        if self.entries.len() < MAX_TRACKED_KEYS || self.entries.contains_key(key) {
            return true;
        }
        if self.next_capacity_prune.is_some_and(|t| now < t)
            || self
                .last_capacity_prune
                .is_some_and(|t| now.duration_since(t) < MIN_CAPACITY_PRUNE_INTERVAL)
        {
            return false;
        }
        self.last_capacity_prune = Some(now);
        self.prune(now);
        self.entries.len() < MAX_TRACKED_KEYS
    }

    /// Undoes the count of an admitted attempt that turned out not to be a
    /// failure. Attempts admitted in an earlier window are not refunded.
    pub fn refund_attempt(&mut self, attempt: &Attempt) {
        let max_failures = self.settings.max_failures;
        let Some(entry) = self.entries.get_mut(&attempt.key) else {
            return;
        };
        if entry.window_start != attempt.window_start {
            return;
        }
        entry.failures = entry.failures.saturating_sub(1);
        if entry.failures == 0 {
            // Nothing left to count; the next failure starts a new window
            self.remove(&attempt.key);
        } else if entry.failures < max_failures && entry.blocked_until.is_some() {
            entry.blocked_until = None;
            self.next_capacity_prune = None;
        }
    }

    // Counts a failure for `key` and returns the start of its current window.
    fn record_failure(&mut self, key: &str, now: Instant) -> Instant {
        let settings = self.settings;
        let entry = self.entries.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            window_start: now,
            blocked_until: None,
        });

        if entry.is_expired(now, &settings) {
            *entry = Entry {
                failures: 0,
                window_start: now,
                blocked_until: None,
            };
        }

        entry.failures += 1;
        if entry.failures >= settings.max_failures {
            // Block for at least block_duration and at least until the end of
            // the window, so a short block can't be used to reset the count.
            let window_end = entry.window_start + settings.window;
            entry.blocked_until = Some((now + settings.block_duration).max(window_end));
        }
        let window_start = entry.window_start;

        self.maybe_prune(now);
        window_start
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
        self.next_capacity_prune = None;
    }

    fn is_blocked(&self, key: &str, now: Instant) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| e.blocked_until.is_some_and(|until| now < until))
    }

    /// Number of keys that are currently blocked.
    pub fn blocked_count(&self, now: Instant) -> usize {
        self.entries
            .values()
            .filter(|e| e.blocked_until.is_some_and(|until| now < until))
            .count()
    }

    // Drops expired entries once the map grows past the threshold, then
    // doubles the threshold relative to the surviving entries so pruning
    // stays amortized O(1) per insertion.
    fn maybe_prune(&mut self, now: Instant) {
        if self.entries.len() >= self.prune_threshold {
            self.prune(now);
        }
    }

    fn prune(&mut self, now: Instant) {
        let settings = self.settings;
        self.entries.retain(|_, e| !e.is_expired(now, &settings));
        self.prune_threshold = MIN_PRUNE_THRESHOLD.max(self.entries.len() * 2);
        self.next_capacity_prune = if self.entries.len() >= MAX_TRACKED_KEYS {
            self.entries.values().map(|e| e.expires_at(&settings)).min()
        } else {
            None
        };
    }
}

lazy_static! {
    static ref RATE_LIMITER: Mutex<AuthRateLimiter> =
        Mutex::new(AuthRateLimiter::new(RateLimitSettings::default()));
}

fn with_limiter<R>(f: impl FnOnce(&mut AuthRateLimiter) -> R) -> R {
    let mut guard = match RATE_LIMITER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("auth rate limiter mutex is poisoned, recovering");
            poisoned.into_inner()
        }
    };
    f(&mut guard)
}

pub fn configure(settings: RateLimitSettings) {
    with_limiter(|l| {
        if l.settings != settings {
            l.configure(settings);
        }
    });
}

pub fn is_enabled() -> bool {
    with_limiter(|l| l.settings.is_enabled())
}

/// Admits an authentication attempt from the client with the given key (see
/// `client_key`), or reports that it is blocked.
pub fn begin_attempt(key: &str) -> Admission {
    let (admission, blocked_now) = with_limiter(|l| {
        let now = Instant::now();
        let admission = l.begin_attempt(key, now);
        let blocked_now = match &admission {
            Admission::Admitted(attempt) => l.is_blocked(&attempt.key, now),
            _ => false,
        };
        (admission, blocked_now)
    });
    if blocked_now {
        if let Admission::Admitted(attempt) = &admission {
            warn!(
                "too many failed LDAP authentication attempts from {}, blocking it",
                attempt.key
            );
        }
    }
    admission
}

/// Refunds an attempt that turned out not to be a failure.
pub fn refund_attempt(attempt: &Attempt) {
    with_limiter(|l| l.refund_attempt(attempt));
}

/// Returns whether the limiter is enabled and how many keys are blocked.
/// With `nonblocking`, returns None instead of waiting if the limiter is
/// locked (used when building a crash report).
pub fn info_snapshot(nonblocking: bool) -> Option<(bool, usize)> {
    let snapshot = |l: &AuthRateLimiter| (l.settings.is_enabled(), l.blocked_count(Instant::now()));
    if nonblocking {
        match RATE_LIMITER.try_lock() {
            Ok(guard) => Some(snapshot(&guard)),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(snapshot(&p.into_inner())),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    } else {
        Some(with_limiter(|l| snapshot(l)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(max_failures: u64, window: u64, block: u64) -> RateLimitSettings {
        RateLimitSettings {
            max_failures,
            window: Duration::from_secs(window),
            block_duration: Duration::from_secs(block),
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn admit(l: &mut AuthRateLimiter, key: &str, now: Instant) -> Attempt {
        match l.begin_attempt(key, now) {
            Admission::Admitted(attempt) => attempt,
            other => panic!("expected {key} to be admitted, got {other:?}"),
        }
    }

    fn is_admitted(l: &mut AuthRateLimiter, key: &str, now: Instant) -> bool {
        matches!(l.begin_attempt(key, now), Admission::Admitted(_))
    }

    #[test]
    fn client_keys() {
        assert_eq!(client_key("10.1.2.3"), "10.1.2.3");
        assert_eq!(client_key("::ffff:10.1.2.3"), "10.1.2.3");
        assert_eq!(
            client_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            "2001:db8:1:2::/64"
        );
        assert_eq!(
            client_key("2001:db8:1:2::1"),
            client_key("2001:db8:1:2:ffff::9")
        );
        assert_ne!(client_key("2001:db8:1:2::1"), client_key("2001:db8:1:3::1"));
        assert_eq!(client_key("/tmp/valkey.sock"), "/tmp/valkey.sock");
        assert_eq!(client_key(""), UNKNOWN_KEY);
    }

    #[test]
    fn disabled_by_default() {
        let mut l = AuthRateLimiter::new(RateLimitSettings::default());
        let now = Instant::now();
        for _ in 0..100 {
            assert_eq!(l.begin_attempt("1.2.3.4", now), Admission::NotLimited);
        }
        assert!(l.entries.is_empty());
    }

    #[test]
    fn blocks_after_max_failures() {
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        for _ in 0..3 {
            admit(&mut l, "1.2.3.4", now);
        }
        assert_eq!(
            l.begin_attempt("1.2.3.4", now),
            Admission::Blocked(secs(300))
        );
        // Other keys are unaffected
        admit(&mut l, "5.6.7.8", now);
        assert_eq!(l.blocked_count(now), 1);
    }

    #[test]
    fn concurrent_attempts_cannot_exceed_limit() {
        // Attempts are counted on admission, so in-flight attempts whose
        // results haven't arrived yet still count towards the limit.
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        let admitted = (0..10).filter(|_| is_admitted(&mut l, "ip", now)).count();
        assert_eq!(admitted, 3);
    }

    #[test]
    fn block_expires() {
        let mut l = AuthRateLimiter::new(settings(1, 5, 10));
        let now = Instant::now();
        admit(&mut l, "ip", now);
        assert!(!is_admitted(&mut l, "ip", now + secs(9)));
        assert!(is_admitted(&mut l, "ip", now + secs(10)));
    }

    #[test]
    fn block_lasts_until_window_end() {
        // A block shorter than the window can't be used to reset the count
        let mut l = AuthRateLimiter::new(settings(2, 3600, 1));
        let now = Instant::now();
        admit(&mut l, "ip", now);
        admit(&mut l, "ip", now + secs(10));
        assert_eq!(
            l.begin_attempt("ip", now + secs(11)),
            Admission::Blocked(secs(3589))
        );
        assert!(!is_admitted(&mut l, "ip", now + secs(3599)));
        assert!(is_admitted(&mut l, "ip", now + secs(3600)));
    }

    #[test]
    fn failures_outside_window_reset() {
        let mut l = AuthRateLimiter::new(settings(2, 10, 300));
        let now = Instant::now();
        admit(&mut l, "ip", now);
        admit(&mut l, "ip", now + secs(10));
        admit(&mut l, "ip", now + secs(11));
        assert!(!is_admitted(&mut l, "ip", now + secs(11)));
    }

    #[test]
    fn refund_only_removes_own_attempt() {
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        admit(&mut l, "ip", now);
        admit(&mut l, "ip", now);
        // A successful login is refunded but keeps the other failures
        let success = admit(&mut l, "ip", now);
        l.refund_attempt(&success);
        admit(&mut l, "ip", now);
        assert!(!is_admitted(&mut l, "ip", now));
    }

    #[test]
    fn refund_lifts_block_caused_by_refunded_attempt() {
        let mut l = AuthRateLimiter::new(settings(2, 60, 300));
        let now = Instant::now();
        admit(&mut l, "ip", now);
        let attempt = admit(&mut l, "ip", now);
        assert_eq!(l.blocked_count(now), 1);
        l.refund_attempt(&attempt);
        assert_eq!(l.blocked_count(now), 0);
        admit(&mut l, "ip", now);
    }

    #[test]
    fn refund_from_previous_window_is_ignored() {
        let mut l = AuthRateLimiter::new(settings(2, 10, 300));
        let now = Instant::now();
        let old = admit(&mut l, "ip", now);
        admit(&mut l, "ip", now + secs(10));
        l.refund_attempt(&old);
        admit(&mut l, "ip", now + secs(10));
        assert!(!is_admitted(&mut l, "ip", now + secs(10)));
    }

    #[test]
    fn refund_to_zero_starts_new_window() {
        let mut l = AuthRateLimiter::new(settings(2, 10, 300));
        let now = Instant::now();
        let attempt = admit(&mut l, "ip", now);
        l.refund_attempt(&attempt);
        assert!(l.entries.is_empty());
        // Failures straddling the refunded attempt's window still count together
        admit(&mut l, "ip", now + secs(9));
        admit(&mut l, "ip", now + secs(11));
        assert!(!is_admitted(&mut l, "ip", now + secs(11)));
    }

    #[test]
    fn configure_clears_state() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 300));
        let now = Instant::now();
        admit(&mut l, "ip", now);
        l.configure(settings(5, 60, 300));
        admit(&mut l, "ip", now);
    }

    fn fill(l: &mut AuthRateLimiter, now: Instant) {
        for i in 0..MAX_TRACKED_KEYS {
            admit(l, &format!("ip{i}"), now);
        }
    }

    #[test]
    fn new_keys_share_overflow_bucket_at_capacity() {
        let mut l = AuthRateLimiter::new(settings(2, 60, 300));
        let now = Instant::now();
        fill(&mut l, now);
        // Tracked keys keep counting under their own key
        assert_eq!(admit(&mut l, "ip0", now).key, "ip0");
        // New keys are limited together in the overflow bucket
        assert_eq!(admit(&mut l, "new1", now).key, OVERFLOW_KEY);
        assert_eq!(admit(&mut l, "new2", now).key, OVERFLOW_KEY);
        assert!(matches!(
            l.begin_attempt("new3", now),
            Admission::Blocked(_)
        ));
        // At capacity, new keys don't rescan until the earliest entry expires
        assert_eq!(l.next_capacity_prune, Some(now + secs(60)));
        // Room frees up once entries expire
        assert_eq!(admit(&mut l, "new4", now + secs(60)).key, "new4");
        assert_eq!(l.next_capacity_prune, None);
    }

    #[test]
    fn capacity_cache_is_cleared_when_entries_are_removed() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 3600));
        let now = Instant::now();
        // Fill with blocked entries, so the cached expiry is an hour away
        let attempts: Vec<_> = (0..MAX_TRACKED_KEYS)
            .map(|i| admit(&mut l, &format!("ip{i}"), now))
            .collect();
        let overflow = admit(&mut l, "new", now);
        assert_eq!(overflow.key, OVERFLOW_KEY);
        assert_eq!(l.next_capacity_prune, Some(now + secs(3600)));
        // Lifting a block invalidates the cached expiry
        l.refund_attempt(&attempts[0]);
        assert_eq!(l.next_capacity_prune, None);
        // So once entries expire, new keys are tracked again
        l.refund_attempt(&overflow);
        assert_eq!(admit(&mut l, "late", now + secs(60)).key, "late");
    }

    #[test]
    fn capacity_scans_are_throttled() {
        let mut l = AuthRateLimiter::new(settings(5, 1, 1));
        let now = Instant::now();
        // Entries expire one by one, a microsecond apart
        for i in 0..MAX_TRACKED_KEYS {
            admit(
                &mut l,
                &format!("ip{i}"),
                now + Duration::from_micros(i as u64),
            );
        }
        // Only ip0 has expired at this point
        let later = now + secs(1);
        assert_eq!(admit(&mut l, "a", later).key, "a");
        // A second scan right away is skipped, so this one overflows
        assert_eq!(
            admit(&mut l, "b", later + Duration::from_micros(10)).key,
            OVERFLOW_KEY
        );
        assert_eq!(admit(&mut l, "c", later + secs(1)).key, "c");
    }

    #[test]
    fn prunes_expired_entries() {
        let mut l = AuthRateLimiter::new(settings(5, 1, 1));
        let now = Instant::now();
        for i in 0..MIN_PRUNE_THRESHOLD - 1 {
            admit(&mut l, &format!("ip{i}"), now);
        }
        assert_eq!(l.entries.len(), MIN_PRUNE_THRESHOLD - 1);
        admit(&mut l, "late", now + secs(2));
        assert_eq!(l.entries.len(), 1);
    }
}
