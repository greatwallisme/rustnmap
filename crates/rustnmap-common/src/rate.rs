//! Rate limiting for scan operations.
//!
//! This module provides rate limiting functionality to control packet
//! transmission rates for bandwidth management and IDS evasion.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

/// Rate limiter for controlling scan rate.
///
/// Uses a sliding window algorithm to enforce minimum and maximum
/// packet rates. The window size is 1 second by default.
#[derive(Debug)]
pub struct RateLimiter {
    /// Minimum rate in packets per second (None = no limit).
    min_rate: Option<u64>,
    /// Maximum rate in packets per second (None = no limit).
    max_rate: Option<u64>,
    /// Packets sent in current window.
    window_count: AtomicU64,
    /// Window start time.
    window_start: StdMutex<Instant>,
    /// Window size for rate measurement.
    window_size: Duration,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// # Arguments
    ///
    /// * `min_rate` - Minimum packets per second (None for no minimum)
    /// * `max_rate` - Maximum packets per second (None for no maximum)
    #[must_use]
    pub fn new(min_rate: Option<u64>, max_rate: Option<u64>) -> Self {
        Self {
            min_rate,
            max_rate,
            window_count: AtomicU64::new(0),
            window_start: StdMutex::new(Instant::now()),
            window_size: Duration::from_secs(1),
        }
    }

    /// Records a packet being sent.
    pub fn record_sent(&self) {
        self.window_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the current rate in packets per second.
    ///
    /// # Panics
    ///
    /// This function may panic if the internal lock is poisoned.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Packet counts fit within f64 precision for rate calculation"
    )]
    pub fn current_rate(&self) -> f64 {
        let count = self.window_count.load(Ordering::Relaxed);
        let elapsed = self.window_start.lock().unwrap().elapsed();

        if elapsed.as_secs() == 0 {
            count as f64
        } else {
            count as f64 / elapsed.as_secs_f64()
        }
    }

    /// Checks if sending is allowed based on rate limits.
    ///
    /// Returns how long to wait before sending (None = can send immediately).
    ///
    /// # Panics
    ///
    /// This function may panic if the internal lock is poisoned.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Packet counts fit within f64 precision for rate calculation"
    )]
    pub fn check_rate(&self) -> Option<Duration> {
        let window_start = *self.window_start.lock().unwrap();
        let elapsed = window_start.elapsed();

        // Reset window if needed
        if elapsed > self.window_size {
            self.window_count.store(0, Ordering::Relaxed);
            *self.window_start.lock().unwrap() = Instant::now();
            return None;
        }

        let count = self.window_count.load(Ordering::Relaxed);

        // Check max rate
        if let Some(max_rate) = self.max_rate {
            let current_rate = count as f64 / elapsed.as_secs_f64();
            if current_rate >= max_rate as f64 {
                // Calculate wait time
                let wait_secs = count as f64 / max_rate as f64 - elapsed.as_secs_f64();
                return Some(Duration::from_secs_f64(wait_secs.max(0.001)));
            }
        }

        None
    }

    /// Returns true if we're below the minimum rate.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Rate values fit within f64 precision for comparison"
    )]
    pub fn below_min_rate(&self) -> bool {
        if let Some(min_rate) = self.min_rate {
            let current_rate = self.current_rate();
            current_rate < min_rate as f64 * 0.9 // 10% tolerance
        } else {
            false
        }
    }

    /// Returns the minimum rate.
    #[must_use]
    pub const fn min_rate(&self) -> Option<u64> {
        self.min_rate
    }

    /// Returns the maximum rate.
    #[must_use]
    pub const fn max_rate(&self) -> Option<u64> {
        self.max_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_no_limit() {
        let limiter = RateLimiter::new(None, None);

        // Should always allow sending
        assert!(limiter.check_rate().is_none());
        limiter.record_sent();
        assert!(limiter.check_rate().is_none());
    }

    #[test]
    fn test_rate_limiter_max_rate() {
        let limiter = RateLimiter::new(None, Some(10)); // Max 10 pps

        // Should be able to send initially
        assert!(limiter.check_rate().is_none());

        // Simulate sending at max rate
        for _ in 0..10 {
            limiter.record_sent();
        }

        // Next send should be rate limited
        assert!(limiter.check_rate().is_some());
    }

    #[test]
    fn test_rate_limiter_current_rate() {
        let limiter = RateLimiter::new(None, None);

        // Initially rate should be 0 or very high
        assert!(limiter.current_rate() >= 0.0);

        limiter.record_sent();
        limiter.record_sent();

        // Rate should be positive
        assert!(limiter.current_rate() > 0.0);
    }

    #[test]
    fn test_rate_limiter_min_rate() {
        let limiter = RateLimiter::new(Some(10), None);

        // Initially below min rate (0 packets sent)
        assert!(limiter.below_min_rate());

        // Send some packets - initially this will make us above min rate
        // because time elapsed is very small
        for _ in 0..10 {
            limiter.record_sent();
        }

        // After sending packets, current rate is high due to small time elapsed
        // So we are NOT below min rate
        assert!(!limiter.below_min_rate());
    }
}
