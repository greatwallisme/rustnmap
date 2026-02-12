//! Timeout tracking for adaptive RTT-based scanning.
//!
//! This module implements RFC 2988 timeout tracking with smooth
//! round-trip time estimates for network scanning.

#![warn(missing_docs)]
#![allow(
    clippy::manual_abs_diff,
    clippy::must_use_candidate,
    reason = "Using explicit abs_diff for clarity; algorithms follow RFC 2988"
)]

use std::time::{Duration, Instant};

/// Initial RTT estimate in milliseconds before any measurements.
///
/// Based on typical LAN conditions for TCP connections.
const INITIAL_RTT_ESTIMATE_MILLIS: u64 = 100;

/// Minimum RTT floor in milliseconds to prevent overly aggressive timeouts.
///
/// Even on very fast networks, some minimum delay is needed.
const MIN_RTT_MILLIS: u64 = 10;

/// Maximum RTT ceiling in milliseconds to prevent excessive wait times.
const MAX_RTT_MILLIS: u64 = 10000;

/// RTT variance multiplier for timeout calculation (RFC 2988).
const RTTVAR_MULTIPLIER: u32 = 4;

/// Timeout tracker implementing RFC 2988 algorithm.
///
/// Provides adaptive timeout estimation based on measured round-trip times.
/// Follows standard TCP retransmission timeout algorithm.
#[derive(Debug, Clone)]
pub struct TimeoutTracker {
    /// Smoothed round-trip time (SRTT) in microseconds.
    srtt: u64,

    /// Round-trip time variance (RTTVAR) in microseconds.
    rttvar: u64,

    /// Current timeout value.
    timeout: Duration,

    /// Whether we have taken any real measurements yet.
    measured: bool,

    /// Last timeout update time.
    last_update: Option<Instant>,
}

impl Default for TimeoutTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeoutTracker {
    /// Creates a new timeout tracker with default values.
    ///
    /// # Returns
    ///
    /// A new `TimeoutTracker` with initial RTT estimates.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            srtt: INITIAL_RTT_ESTIMATE_MILLIS.saturating_mul(1000),
            rttvar: INITIAL_RTT_ESTIMATE_MILLIS.saturating_mul(500),
            timeout: Duration::from_millis(INITIAL_RTT_ESTIMATE_MILLIS.saturating_mul(2)),
            measured: false,
            last_update: None,
        }
    }

    /// Returns the current timeout value.
    ///
    /// # Returns
    ///
    /// Reference to the current timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> &Duration {
        &self.timeout
    }

    /// Updates the tracker based on a new RTT measurement.
    ///
    /// This implements RFC 2988 algorithm for computing
    /// retransmission timeout values.
    ///
    /// # Arguments
    ///
    /// * `rtt` - Measured round-trip time for this exchange
    pub fn update(&mut self, rtt: Duration) {
        // Convert to u64 safely, capping at reasonable maximum
        let rtt_micros = rtt.as_micros().try_into().unwrap_or(u64::MAX);

        // Subsequent measurement: update using RFC 2988 formulas
        if self.measured {
            // Use absolute difference for RTT variance calculation
            let rtt_diff = rtt_micros.abs_diff(self.srtt);

            // Update variance: (3 * RTTVAR + diff) / 4
            self.rttvar = (3 * self.rttvar).saturating_add(rtt_diff) / 4;

            // Update SRTT: (7 * SRTT + RTT) / 8
            self.srtt = (7 * self.srtt).saturating_add(rtt_micros) / 8;
        } else {
            // First measurement: initialize directly
            self.srtt = rtt_micros;
            self.rttvar = rtt_micros / 2;
            self.measured = true;
        }

        // Clamp values to reasonable bounds
        let min_srtt = MIN_RTT_MILLIS.saturating_mul(1000);
        let max_srtt = MAX_RTT_MILLIS.saturating_mul(1000);
        self.srtt = self.srtt.clamp(min_srtt, max_srtt);

        let min_rttvar = MIN_RTT_MILLIS.saturating_mul(500);
        let max_rttvar = MAX_RTT_MILLIS.saturating_mul(1000);
        self.rttvar = self.rttvar.clamp(min_rttvar, max_rttvar);

        // Calculate new timeout: SRTT + 4 * RTTVAR (RFC 2988)
        let rttvar_scaled = u64::from(RTTVAR_MULTIPLIER).saturating_mul(self.rttvar);
        let timeout_micros = self.srtt.saturating_add(rttvar_scaled);
        self.timeout = Duration::from_micros(timeout_micros);
        self.last_update = Some(Instant::now());
    }

    /// Forces a specific timeout value.
    ///
    /// Used when network conditions change abruptly (e.g., new target host).
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout value to set
    pub fn force_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        self.last_update = Some(Instant::now());
    }

    /// Returns the current smoothed RTT estimate.
    ///
    /// # Returns
    ///
    /// The smoothed round-trip time as a `Duration`.
    #[must_use]
    pub const fn srtt(&self) -> Duration {
        Duration::from_micros(self.srtt)
    }

    /// Returns the current RTT variance estimate.
    ///
    /// # Returns
    ///
    /// The round-trip time variance as a `Duration`.
    #[must_use]
    pub const fn rttvar(&self) -> Duration {
        Duration::from_micros(self.rttvar)
    }

    /// Gets timeout for a single retry attempt.
    ///
    /// Returns shorter timeout for subsequent retries to adapt quickly.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The retry attempt number (0-indexed)
    ///
    /// # Returns
    ///
    /// Scaled timeout duration for this retry attempt.
    #[must_use]
    pub fn retry_timeout(&self, attempt: u8) -> Duration {
        // Scale down timeout for retries
        let multiplier = match attempt {
            0 => 100u8,
            1 => 80u8,
            2 => 60u8,
            _ => 50u8,
        };

        // Perform calculation to get timeout in milliseconds
        // Use u128 for intermediate calculation to prevent overflow,
        // then safely convert to u64 (clamped at u64::MAX for safety)
        let timeout_millis = self
            .timeout
            .as_millis()
            .saturating_mul(u128::from(multiplier))
            .saturating_div(100);

        Duration::from_millis(timeout_millis.try_into().unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_tracker_default() {
        let tracker = TimeoutTracker::new();
        // Default timeout should be approximately 2x initial RTT
        assert!(tracker.timeout().as_millis() >= 190);
        assert!(tracker.timeout().as_millis() <= 210);
    }

    #[test]
    fn test_timeout_tracker_update() {
        let mut tracker = TimeoutTracker::new();
        let initial_timeout = *tracker.timeout();

        // Simulate first RTT measurement of 50ms
        tracker.update(Duration::from_millis(50));

        // SRTT should be updated to approximately 50ms
        // First measurement: srtt = RTT = 50000us, rttvar = RTT/2 = 25000us
        // Then clamped to MIN_RTT_MILLIS * 1000 = 10000us
        // So final srtt = max(50000, 10000) = 50000us = 50ms
        assert_eq!(tracker.srtt().as_millis(), 50);

        // Timeout should change
        assert!(tracker.timeout().as_millis() != initial_timeout.as_millis());
    }

    #[test]
    fn test_timeout_tracker_clamping() {
        let mut tracker = TimeoutTracker::new();

        // Simulate very fast RTT (1ms)
        tracker.update(Duration::from_millis(1));
        assert!(tracker.srtt().as_millis() >= u128::from(MIN_RTT_MILLIS));

        // Simulate very slow RTT (20 seconds)
        tracker.update(Duration::from_millis(20000));
        assert!(tracker.srtt().as_millis() <= u128::from(MAX_RTT_MILLIS));
    }

    #[test]
    fn test_retry_timeout_scales() {
        let tracker = TimeoutTracker::new();
        let base_timeout = *tracker.timeout();

        // First retry should be shorter
        let retry1 = tracker.retry_timeout(1);
        assert!(retry1 < base_timeout);

        // Third retry should be even shorter
        let retry3 = tracker.retry_timeout(3);
        assert!(retry3 < retry1);
    }

    #[test]
    fn test_force_timeout() {
        let mut tracker = TimeoutTracker::new();
        let custom_timeout = Duration::from_millis(5000);

        tracker.force_timeout(custom_timeout);
        assert_eq!(*tracker.timeout(), custom_timeout);
    }
}
