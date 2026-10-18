//! Per-client-IP rate limiting of failed LDAP authentication attempts.
//!
//! Each client IP gets a fixed window of `window` length that starts at its
//! first failure. When `max_failures` failures accumulate inside that window,
//! the IP is blocked for `block_duration`, during which any LDAP
//! authentication attempt from it is rejected without contacting the LDAP
//! server. A successful authentication clears the IP's failure count.
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
    pub fn check(&mut self, ip: &str, now: Instant) -> Option<Duration> {
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

    /// Records a failed authentication. Returns true if this failure caused
    /// the IP to become blocked.
    pub fn record_failure(&mut self, ip: &str, now: Instant) -> bool {
        if !self.settings.is_enabled() {
            return false;
        }

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

        if entry.blocked_until.is_some() {
            return false;
        }

        entry.failures += 1;
        let blocked = entry.failures >= settings.max_failures;
        if blocked {
            entry.blocked_until = Some(now + settings.block_duration);
        }

        self.maybe_prune(now);
        blocked
    }

    /// Records a successful authentication, clearing the IP's failure count.
    pub fn record_success(&mut self, ip: &str) {
        self.entries.remove(ip);
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

pub fn check(ip: &str) -> Option<Duration> {
    with_limiter(|l| l.check(ip, Instant::now()))
}

pub fn record_failure(ip: &str) {
    let blocked = with_limiter(|l| l.record_failure(ip, Instant::now()));
    if blocked {
        warn!("too many failed LDAP authentication attempts from {ip}, blocking it");
    }
}

pub fn record_success(ip: &str) {
    with_limiter(|l| l.record_success(ip));
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

    #[test]
    fn disabled_by_default() {
        let mut l = AuthRateLimiter::new(RateLimitSettings::default());
        let now = Instant::now();
        for _ in 0..100 {
            assert!(!l.record_failure("1.2.3.4", now));
        }
        assert_eq!(l.check("1.2.3.4", now), None);
        assert!(l.entries.is_empty());
    }

    #[test]
    fn blocks_after_max_failures() {
        let mut l = AuthRateLimiter::new(settings(3, 60, 300));
        let now = Instant::now();
        assert!(!l.record_failure("1.2.3.4", now));
        assert!(!l.record_failure("1.2.3.4", now));
        assert_eq!(l.check("1.2.3.4", now), None);
        assert!(l.record_failure("1.2.3.4", now));
        assert_eq!(l.check("1.2.3.4", now), Some(Duration::from_secs(300)));
        // Other IPs are unaffected
        assert_eq!(l.check("5.6.7.8", now), None);
        assert_eq!(l.blocked_count(now), 1);
    }

    #[test]
    fn block_expires() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 10));
        let now = Instant::now();
        assert!(l.record_failure("ip", now));
        assert!(l.check("ip", now + Duration::from_secs(9)).is_some());
        assert_eq!(l.check("ip", now + Duration::from_secs(10)), None);
        assert_eq!(l.blocked_count(now + Duration::from_secs(10)), 0);
    }

    #[test]
    fn failures_outside_window_reset() {
        let mut l = AuthRateLimiter::new(settings(2, 10, 300));
        let now = Instant::now();
        assert!(!l.record_failure("ip", now));
        assert!(!l.record_failure("ip", now + Duration::from_secs(10)));
        assert!(l.record_failure("ip", now + Duration::from_secs(11)));
    }

    #[test]
    fn success_clears_failures() {
        let mut l = AuthRateLimiter::new(settings(2, 60, 300));
        let now = Instant::now();
        assert!(!l.record_failure("ip", now));
        l.record_success("ip");
        assert!(!l.record_failure("ip", now));
        assert!(l.record_failure("ip", now));
    }

    #[test]
    fn failures_while_blocked_do_not_extend_block() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 10));
        let now = Instant::now();
        assert!(l.record_failure("ip", now));
        assert!(!l.record_failure("ip", now + Duration::from_secs(5)));
        assert_eq!(
            l.check("ip", now + Duration::from_secs(5)),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn configure_clears_state() {
        let mut l = AuthRateLimiter::new(settings(1, 60, 300));
        let now = Instant::now();
        assert!(l.record_failure("ip", now));
        l.configure(settings(5, 60, 300));
        assert_eq!(l.check("ip", now), None);
    }

    #[test]
    fn prunes_expired_entries() {
        let mut l = AuthRateLimiter::new(settings(5, 1, 1));
        let now = Instant::now();
        for i in 0..MIN_PRUNE_THRESHOLD - 1 {
            l.record_failure(&format!("ip{i}"), now);
        }
        assert_eq!(l.entries.len(), MIN_PRUNE_THRESHOLD - 1);
        l.record_failure("late", now + Duration::from_secs(2));
        assert_eq!(l.entries.len(), 1);
    }
}
