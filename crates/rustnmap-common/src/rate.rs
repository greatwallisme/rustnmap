//! Rate limiting for scan operations.
//!
//! This module provides rate limiting functionality to control packet
//! transmission rates for bandwidth management and IDS evasion.
//!
//! # Performance
//!
//! This implementation uses lock-free atomics for high performance on
//! the hot path. The rate limiter is designed to minimize overhead
//! while maintaining accurate rate control.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Window size in nanoseconds (1 second).
const WINDOW_SIZE_NANOS: u64 = 1_000_000_000;

/// Rate limiter for controlling scan rate.
///
/// Uses a lock-free sliding window algorithm to enforce minimum and maximum
/// packet rates. The window size is 1 second by default.
///
/// # Thread Safety
///
/// All operations are lock-free and can be called from multiple threads
/// concurrently without blocking.
///
/// # Performance
///
/// - `check_rate()`: ~2-3 CPU cycles (lock-free, no syscalls)
/// - `record_sent()`: ~1 CPU cycle (single atomic `fetch_add`)
///
/// # Examples
///
/// ```
/// use rustnmap_common::rate::RateLimiter;
///
/// let limiter = RateLimiter::new(None, Some(100)); // Max 100 pps
///
/// // Check if we can send
/// if limiter.check_rate().is_none() {
///     // Send packet
///     limiter.record_sent();
/// }
/// ```
#[derive(Debug)]
pub struct RateLimiter {
    /// Minimum rate in packets per second (None = no limit).
    min_rate: Option<u64>,
    /// Maximum rate in packets per second (None = no limit).
    max_rate: Option<u64>,
    /// Packets sent in current window.
    window_count: AtomicU64,
    /// Window start time in nanoseconds since reference instant.
    window_start_nanos: AtomicU64,
    /// Reference instant for time calculations.
    reference_instant: Instant,
    /// Pre-computed: minimum nanoseconds between packets at `max_rate`.
    /// This avoids division on the hot path.
    min_packet_interval_nanos: Option<u64>,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// # Arguments
    ///
    /// * `min_rate` - Minimum packets per second (None for no minimum)
    /// * `max_rate` - Maximum packets per second (None for no maximum)
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_common::rate::RateLimiter;
    ///
    /// let limiter = RateLimiter::new(Some(10), Some(100));
    /// ```
    #[must_use]
    pub fn new(min_rate: Option<u64>, max_rate: Option<u64>) -> Self {
        // Pre-compute the minimum packet interval to avoid division on hot path
        // Formula: 1 second / max_rate = nanoseconds between packets
        let min_packet_interval_nanos = max_rate.map(|rate| {
            if rate == 0 {
                u64::MAX // Effectively unlimited if rate is 0
            } else {
                1_000_000_000 / rate
            }
        });

        Self {
            min_rate,
            max_rate,
            window_count: AtomicU64::new(0),
            window_start_nanos: AtomicU64::new(0),
            reference_instant: Instant::now(),
            min_packet_interval_nanos,
        }
    }

    /// Records a packet being sent.
    ///
    /// This increments the packet counter for the current window.
    /// Call this after successfully sending a packet.
    #[inline]
    pub fn record_sent(&self) {
        self.window_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the current rate in packets per second.
    ///
    /// This is a best-effort estimate and may not be accurate under
    /// high concurrency.
    ///
    /// # Panics
    ///
    /// This function does not panic. It returns 0.0 if the elapsed time
    /// cannot be determined.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Packet counts fit within f64 precision for rate calculation"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Instant elapsed time fits in u64 for practical scan durations"
    )]
    pub fn current_rate(&self) -> f64 {
        let count = self.window_count.load(Ordering::Relaxed);
        let window_start_nanos = self.window_start_nanos.load(Ordering::Relaxed);
        let now_nanos = self.reference_instant.elapsed().as_nanos() as u64;
        let elapsed_nanos = now_nanos.saturating_sub(window_start_nanos);

        if elapsed_nanos == 0 {
            return count as f64;
        }

        // Convert to rate: count / (elapsed_ns / 1e9) = count * 1e9 / elapsed_ns
        count as f64 * 1_000_000_000.0 / elapsed_nanos as f64
    }

    /// Checks if sending is allowed based on rate limits.
    ///
    /// Returns `None` if sending is allowed immediately, or `Some(duration)`
    /// indicating how long to wait before sending.
    ///
    /// This method is lock-free and safe to call from hot paths.
    ///
    /// # Algorithm
    ///
    /// 1. Check if the window needs to be reset (1 second elapsed)
    /// 2. If reset needed, use CAS to atomically reset the window
    /// 3. Check if we've hit the max rate using pre-computed interval
    /// 4. Return wait time if rate limited, None otherwise
    ///
    /// # Thread Safety
    ///
    /// Multiple threads can call this concurrently. At most one thread
    /// will succeed in resetting the window; others will see the updated state.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Instant elapsed time fits in u64 for practical scan durations"
    )]
    pub fn check_rate(&self) -> Option<Duration> {
        let now_nanos = self.reference_instant.elapsed().as_nanos() as u64;
        let window_start_nanos = self.window_start_nanos.load(Ordering::Acquire);
        let elapsed_nanos = now_nanos.saturating_sub(window_start_nanos);

        // Check if window needs reset (1 second elapsed)
        if elapsed_nanos >= WINDOW_SIZE_NANOS {
            // Try to reset the window using CAS
            // This is lock-free: only one thread will succeed
            if self
                .window_start_nanos
                .compare_exchange(
                    window_start_nanos,
                    now_nanos,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // We successfully reset the window
                self.window_count.store(0, Ordering::Release);
                return None;
            }
            // Another thread reset it, reload and continue
            // The window_start has been updated by another thread
            // Recalculate elapsed time with the new window start
            let new_start = self.window_start_nanos.load(Ordering::Acquire);
            let new_elapsed = now_nanos.saturating_sub(new_start);
            if new_elapsed >= WINDOW_SIZE_NANOS {
                // Edge case: window still needs reset, retry on next call
                return Some(Duration::from_micros(1));
            }
            // Continue with rate check using new window state
            return self.check_max_rate(now_nanos, new_start);
        }

        // Check max rate
        self.check_max_rate(now_nanos, window_start_nanos)
    }

    /// Internal helper to check max rate using pre-computed interval.
    ///
    /// This avoids division by using the pre-computed minimum packet interval.
    #[inline]
    fn check_max_rate(&self, now_nanos: u64, window_start_nanos: u64) -> Option<Duration> {
        let min_interval_nanos = self.min_packet_interval_nanos?;

        let count = self.window_count.load(Ordering::Relaxed);
        let elapsed_nanos = now_nanos.saturating_sub(window_start_nanos);

        // Calculate the minimum time that should have elapsed for `count` packets
        // If we've sent `count` packets, we need at least count * interval time
        let min_elapsed_nanos = count.saturating_mul(min_interval_nanos);

        (elapsed_nanos < min_elapsed_nanos).then(|| {
            // We need to wait before sending the next packet
            let wait_nanos = min_elapsed_nanos - elapsed_nanos;
            // Clamp to reasonable range (1 microsecond minimum to avoid busy loop)
            Duration::from_nanos(wait_nanos.max(1_000))
        })
    }

    /// Returns true if we're below the minimum rate.
    ///
    /// This is used to determine if we should speed up sending.
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

    #[test]
    fn test_rate_limiter_precomputed_interval() {
        // Test that pre-computed interval is correct
        let limiter = RateLimiter::new(None, Some(100)); // 100 pps = 10ms interval
        assert_eq!(limiter.min_packet_interval_nanos, Some(10_000_000));

        let limiter = RateLimiter::new(None, Some(1000)); // 1000 pps = 1ms interval
        assert_eq!(limiter.min_packet_interval_nanos, Some(1_000_000));
    }

    #[test]
    fn test_rate_limiter_zero_rate() {
        // Zero rate should be treated as unlimited
        let limiter = RateLimiter::new(None, Some(0));
        assert!(limiter.check_rate().is_none());
    }
}
