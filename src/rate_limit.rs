//! Per-client-IP rate limiting of failed LDAP authentication attempts.
//!
//! Each client IP gets a fixed window of `window` length that starts at its
//! first failure. When `max_failures` failures accumulate inside that window,
//! the IP is blocked for `block_duration`, during which any LDAP
//! authentication attempt from it is rejected without contacting the LDAP
//! server.
//!
//! To keep concurrent attempts from slipping past the limit, an attempt is
//! counted as a failure when it is admitted (atomically with the block
//! check). Once its outcome is known, an attempt that did not fail on
//! credentials (successful login, LDAP server unavailable, submission error)
//! is refunded. A refund only removes that attempt's own count, so a
//! successful login doesn't clear failures from other attempts.
//!
//! The limiter is disabled when `max_failures` is 0 (the default).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use log::{error, warn};

/// Number of tracked IPs above which expired entries are pruned.
const MIN_PRUNE_THRESHOLD: usize = 1024;

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
struct IpEntry {
    failures: u64,
    window_start: Instant,
    blocked_until: Option<Instant>,
}

impl IpEntry {
    fn is_expired(&self, now: Instant, settings: &RateLimitSettings) -> bool {
        match self.blocked_until {
            Some(until) => now >= until,
            None => now.duration_since(self.window_start) >= settings.window,
        }
    }
}

#[derive(Debug)]
pub struct AuthRateLimiter {
    settings: RateLimitSettings,
    entries: HashMap<String, IpEntry>,
    prune_threshold: usize,
}

impl AuthRateLimiter {
    pub fn new(settings: RateLimitSettings) -> Self {
        AuthRateLimiter {
            settings,
            entries: HashMap::new(),
            prune_threshold: MIN_PRUNE_THRESHOLD,
        }
    }

    /// Replaces the settings and drops all tracked state.
    pub fn configure(&mut self, settings: RateLimitSettings) {
        self.settings = settings;
        self.entries.clear();
        self.prune_threshold = MIN_PRUNE_THRESHOLD;
    }

    /// Returns the remaining block time if `ip` is currently blocked.
    fn check(&mut self, ip: &str, now: Instant) -> Option<Duration> {
        if !self.settings.is_enabled() {
            return None;
        }
        let entry = self.entries.get(ip)?;
        if entry.is_expired(now, &self.settings) {
            self.entries.remove(ip);
            return None;
        }
        entry.blocked_until.map(|until| until - now)
    }

    /// Atomically rejects `ip` if it is blocked, or else counts this attempt
    /// as a failure. Returns `Ok(None)` when the limiter is disabled,
    /// `Ok(Some(token))` for an admitted attempt (`token` is passed to
    /// `refund_attempt`), or `Err(remaining)` when the IP is blocked.
    pub fn begin_attempt(&mut self, ip: &str, now: Instant) -> Result<Option<Instant>, Duration> {
        if !self.settings.is_enabled() {
            return Ok(None);
        }
        if let Some(remaining) = self.check(ip, now) {
            return Err(remaining);
        }
        Ok(Some(self.record_failure(ip, now)))
    }

    /// Undoes the count of an admitted attempt that turned out not to be a
    /// credential failure. `token` is the value returned by `begin_attempt`;
    /// attempts admitted in an earlier window are not refunded.
    pub fn refund_attempt(&mut self, ip: &str, token: Instant) {
        let max_failures = self.settings.max_failures;
        if let Some(entry) = self.entries.get_mut(ip) {
            if entry.window_start != token {
                return;
            }
            entry.failures = entry.failures.saturating_sub(1);
            if entry.failures < max_failures {
                entry.blocked_until = None;
            }
        }
    }

    // Counts a failure for `ip` and returns the start of its current window.
    fn record_failure(&mut self, ip: &str, now: Instant) -> Instant {
        let settings = self.settings;
        let entry = self.entries.entry(ip.to_string()).or_insert(IpEntry {
            failures: 0,
            window_start: now,
            blocked_until: None,
        });

        if entry.is_expired(now, &settings) {
            *entry = IpEntry {
                failures: 0,
                window_start: now,
                blocked_until: None,
            };
        }

        entry.failures += 1;
        if entry.failures >= settings.max_failures {
            entry.blocked_until = Some(now + settings.block_duration);
        }
        let window_start = entry.window_start;

        self.maybe_prune(now);
        window_start
    }

    fn is_blocked(&self, ip: &str, now: Instant) -> bool {
        self.entries
            .get(ip)
            .is_some_and(|e| e.blocked_until.is_some_and(|until| now < until))
    }

    /// Number of IPs that are currently blocked.
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
        if self.entries.len() < self.prune_threshold {
            return;
        }
        let settings = self.settings;
        self.entries.retain(|_, e| !e.is_expired(now, &settings));
        self.prune_threshold = MIN_PRUNE_THRESHOLD.max(self.entries.len() * 2);
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

/// An admitted authentication attempt, counted as a failure until refunded.
#[derive(Clone, Debug)]
pub struct Attempt {
    ip: String,
    token: Instant,
}

/// Admits an authentication attempt from `ip`, or returns the remaining block
/// time if the IP is blocked. Returns `Ok(None)` when rate limiting is
/// disabled.
pub fn begin_attempt(ip: &str) -> Result<Option<Attempt>, Duration> {
    let (res, blocked_now) = with_limiter(|l| {
        let now = Instant::now();
        let res = l.begin_attempt(ip, now);
        let blocked_now = matches!(res, Ok(Some(_))) && l.is_blocked(ip, now);
        (res, blocked_now)
    });
    if blocked_now {
        warn!("too many failed LDAP authentication attempts from {ip}, blocking it");
    }
    res.map(|token| {
        token.map(|token| Attempt {
            ip: ip.to_string(),
            token,
        })
    })
}

/// Refunds an attempt that did not fail on credentials.
pub fn refund_attempt(attempt: &Attempt) {
    with_limiter(|l| l.refund_attempt(&attempt.ip, attempt.token));
}

pub fn blocked_count() -> usize {
    with_limiter(|l| l.blocked_count(Instant::now()))
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

    #[test]
    fn disabled_by_default() {
        let mut l = AuthRateLimiter::new(RateLimitSettings::default());
        let now = Instant::now();
        for _ in 0..100 {
            assert_eq!(l.begin_attempt("1.2.3.4", now), Ok(None));
        }
        assert!(l.entries.is_empty());
    }

    #[test]
    fn blocks_after_max_failures() {
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        for _ in 0..3 {
            assert!(matches!(l.begin_attempt("1.2.3.4", now), Ok(Some(_))));
        }
        assert_eq!(l.begin_attempt("1.2.3.4", now), Err(secs(300)));
        // Other IPs are unaffected
        assert!(matches!(l.begin_attempt("5.6.7.8", now), Ok(Some(_))));
        assert_eq!(l.blocked_count(now), 1);
    }

    #[test]
    fn concurrent_attempts_cannot_exceed_limit() {
        // Attempts are counted on admission, so in-flight attempts whose
        // results haven't arrived yet still count towards the limit.
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        let admitted = (0..10)
            .filter(|_| l.begin_attempt("ip", now).is_ok())
            .count();
        assert_eq!(admitted, 3);
    }

    #[test]
    fn block_expires() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 10));
        let now = Instant::now();
        assert!(l.begin_attempt("ip", now).is_ok());
        assert!(l.begin_attempt("ip", now + secs(9)).is_err());
        assert!(matches!(l.begin_attempt("ip", now + secs(10)), Ok(Some(_))));
    }

    #[test]
    fn failures_outside_window_reset() {
        let mut l = AuthRateLimiter::new(settings(2, 10, 300));
        let now = Instant::now();
        assert!(l.begin_attempt("ip", now).is_ok());
        assert!(l.begin_attempt("ip", now + secs(10)).is_ok());
        assert!(l.begin_attempt("ip", now + secs(11)).is_ok());
        assert!(l.begin_attempt("ip", now + secs(11)).is_err());
    }

    #[test]
    fn refund_only_removes_own_attempt() {
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        assert!(l.begin_attempt("ip", now).is_ok());
        assert!(l.begin_attempt("ip", now).is_ok());
        // A successful login is refunded but keeps the other failures
        let token = l.begin_attempt("ip", now).unwrap().unwrap();
        l.refund_attempt("ip", token);
        assert!(l.begin_attempt("ip", now).is_ok());
        assert!(l.begin_attempt("ip", now).is_err());
    }

    #[test]
    fn refund_lifts_block_caused_by_refunded_attempt() {
        let mut l = AuthRateLimiter::new(settings(2, 60, 300));
        let now = Instant::now();
        assert!(l.begin_attempt("ip", now).is_ok());
        let token = l.begin_attempt("ip", now).unwrap().unwrap();
        assert_eq!(l.blocked_count(now), 1);
        l.refund_attempt("ip", token);
        assert_eq!(l.blocked_count(now), 0);
        assert!(l.begin_attempt("ip", now).is_ok());
    }

    #[test]
    fn refund_from_previous_window_is_ignored() {
        let mut l = AuthRateLimiter::new(settings(2, 10, 300));
        let now = Instant::now();
        let token = l.begin_attempt("ip", now).unwrap().unwrap();
        assert!(l.begin_attempt("ip", now + secs(10)).is_ok());
        l.refund_attempt("ip", token);
        assert!(l.begin_attempt("ip", now + secs(10)).is_ok());
        assert!(l.begin_attempt("ip", now + secs(10)).is_err());
    }

    #[test]
    fn configure_clears_state() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 300));
        let now = Instant::now();
        assert!(l.begin_attempt("ip", now).is_ok());
        l.configure(settings(5, 60, 300));
        assert!(matches!(l.begin_attempt("ip", now), Ok(Some(_))));
    }

    #[test]
    fn prunes_expired_entries() {
        let mut l = AuthRateLimiter::new(settings(5, 1, 1));
        let now = Instant::now();
        for i in 0..MIN_PRUNE_THRESHOLD - 1 {
            let _ = l.begin_attempt(&format!("ip{i}"), now);
        }
        assert_eq!(l.entries.len(), MIN_PRUNE_THRESHOLD - 1);
        let _ = l.begin_attempt("late", now + secs(2));
        assert_eq!(l.entries.len(), 1);
    }
}
