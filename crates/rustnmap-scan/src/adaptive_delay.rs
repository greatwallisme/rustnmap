//! Adaptive scan delay for network volatility handling.
//!
//! This module implements dynamic scan delay adjustment based on packet loss
//! and network conditions, following nmap's timing algorithm.
//!
//! # Architecture
//!
//! Based on `doc/architecture.md` Section 2.3.4:
//!
//! ```text
//! ScanDelayBoost (动态延迟)
//! ├─ On high drop rate:
//! │  ├─ timing_level < 4: delay = min(10000, max(1000, delay*10))
//! │  └─ timing_level >= 4: delay = min(1000, max(100, delay*2))
//! └─ Decay after good responses:
//!    └─ if good_responses > threshold: delay = max(default, delay/2)
//! ```
//!
//! # Behavior
//!
//! - **High Drop Rate**: Exponentially increase delay (10x for T0-T3, 2x for T4-T5)
//! - **Good Responses**: Halve delay (down to template default)
//! - **Adaptive**: Responds to changing network conditions
//!
//! # Examples
//!
//! ```rust
//! use rustnmap_scan::adaptive_delay::AdaptiveDelay;
//! use rustnmap_common::TimingTemplate;
//!
//! let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
//!
//! // High drop rate detected (30% packet loss)
//! delay.on_high_drop_rate(0.3);
//!
//! // Good responses received
//! delay.on_good_response();
//! ```
//!
//! # References
//!
//! - `doc/architecture.md` Section 2.3.4
//! - `reference/nmap/timing.cc` - Nmap's timing algorithm

#![warn(missing_docs)]

use rustnmap_common::TimingTemplate;
use std::time::Duration;

/// Number of consecutive good responses before reducing delay.
const GOOD_RESPONSE_THRESHOLD: u8 = 5;

/// Minimum scan delay in milliseconds (T4-T5 timing).
const MIN_DELAY_MS_T4_T5: u64 = 100;

/// Maximum scan delay in milliseconds for T0-T3 (aggressive backoff).
const MAX_DELAY_MS_T0_T3: u64 = 10000;

/// Maximum scan delay in milliseconds for T4-T5 (moderate backoff).
const MAX_DELAY_MS_T4_T5: u64 = 1000;

/// Minimum scan delay in milliseconds for T0-T3 (moderate backoff floor).
const MIN_DELAY_MS_T0_T3: u64 = 1000;

/// Adaptive scan delay manager.
///
/// Dynamically adjusts scan delay based on network conditions:
/// - Increases delay on high packet loss (exponential backoff)
/// - Decreases delay on good responses (exponential decay)
/// - Respects timing template bounds (T0-T5)
///
/// # Thread Safety
///
/// This type is `Send + Sync` and can be shared between threads using
/// `Arc<Mutex<AdaptiveDelay>>` for coordinated scanning.
#[derive(Debug, Clone)]
pub struct AdaptiveDelay {
    /// Current scan delay.
    current_delay: Duration,
    /// Default scan delay (from timing template).
    default_delay: Duration,
    /// Timing template level (0-5 for T0-T5).
    timing_level: u8,
    /// Consecutive good responses (for delay decay).
    good_responses: u8,
    /// Current drop rate estimate (0.0 to 1.0).
    drop_rate: f32,
}

impl AdaptiveDelay {
    /// Creates a new adaptive delay manager.
    ///
    /// # Arguments
    ///
    /// * `template` - Timing template (T0-T5) to base defaults on
    ///
    /// # Returns
    ///
    /// A new `AdaptiveDelay` initialized with template defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_scan::adaptive_delay::AdaptiveDelay;
    /// use rustnmap_common::TimingTemplate;
    ///
    /// let delay = AdaptiveDelay::new(TimingTemplate::Normal);
    /// assert_eq!(delay.timing_level(), 3);
    /// ```
    #[must_use]
    pub fn new(template: TimingTemplate) -> Self {
        let (default_delay, timing_level) = match template {
            TimingTemplate::Paranoid => (Duration::from_secs(300), 0), // 5 min
            TimingTemplate::Sneaky => (Duration::from_secs(15), 1),    // 15 sec
            TimingTemplate::Polite => (Duration::from_millis(400), 2), // 400 ms
            TimingTemplate::Normal => (Duration::from_millis(0), 3),   // 0 ms
            TimingTemplate::Aggressive => (Duration::from_millis(0), 4), // 0 ms
            TimingTemplate::Insane => (Duration::from_millis(0), 5),   // 0 ms
        };

        Self {
            current_delay: default_delay,
            default_delay,
            timing_level,
            good_responses: 0,
            drop_rate: 0.0,
        }
    }

    /// Returns the current scan delay.
    ///
    /// # Returns
    ///
    /// Current delay duration.
    #[must_use]
    pub const fn delay(&self) -> Duration {
        self.current_delay
    }

    /// Returns the timing level (0-5 for T0-T5).
    ///
    /// # Returns
    ///
    /// Timing level as a u8.
    #[must_use]
    pub const fn timing_level(&self) -> u8 {
        self.timing_level
    }

    /// Returns the current drop rate estimate.
    ///
    /// # Returns
    ///
    /// Drop rate as a float (0.0 to 1.0).
    #[must_use]
    pub const fn drop_rate(&self) -> f32 {
        self.drop_rate
    }

    /// Records a high drop rate event.
    ///
    /// Increases scan delay exponentially based on timing level:
    /// - **T0-T3** (level < 4): `delay = min(10000, max(1000, delay*10))`
    /// - **T4-T5** (level >= 4): `delay = min(1000, max(100, delay*2))`
    ///
    /// # Arguments
    ///
    /// * `drop_rate` - Estimated drop rate (0.0 to 1.0)
    pub fn on_high_drop_rate(&mut self, drop_rate: f32) {
        self.drop_rate = drop_rate;

        if self.timing_level < 4 {
            // T0-T3: aggressive backoff (10x multiplier)
            let delay_ms = self.current_delay.as_millis().saturating_mul(10);
            self.current_delay = Duration::from_millis(delay_ms.try_into().unwrap_or(u64::MAX));
            self.current_delay = self
                .current_delay
                .min(Duration::from_millis(MAX_DELAY_MS_T0_T3));
            self.current_delay = self
                .current_delay
                .max(Duration::from_millis(MIN_DELAY_MS_T0_T3));
        } else {
            // T4-T5: moderate backoff (2x multiplier)
            let delay_ms = self.current_delay.as_millis().saturating_mul(2);
            self.current_delay = Duration::from_millis(delay_ms.try_into().unwrap_or(u64::MAX));
            self.current_delay = self
                .current_delay
                .min(Duration::from_millis(MAX_DELAY_MS_T4_T5));
            self.current_delay = self
                .current_delay
                .max(Duration::from_millis(MIN_DELAY_MS_T4_T5));
        }

        // Reset good response counter on drop rate event
        self.good_responses = 0;
    }

    /// Records a good response (successful probe).
    ///
    /// After `GOOD_RESPONSE_THRESHOLD` consecutive good responses,
    /// the delay is halved (down to the default delay).
    pub fn on_good_response(&mut self) {
        self.good_responses = self.good_responses.saturating_add(1);
        self.drop_rate *= 0.9; // Decay drop rate estimate

        if self.good_responses >= GOOD_RESPONSE_THRESHOLD {
            // Halve delay (but not below default)
            let delay_ms = self.current_delay.as_millis() / 2;
            self.current_delay = Duration::from_millis(delay_ms.try_into().unwrap_or(u64::MAX));
            self.current_delay = self.current_delay.max(self.default_delay);

            // Reset counter after reducing delay
            self.good_responses = 0;
        }
    }

    /// Records a packet loss.
    ///
    /// This is a more severe event than high drop rate and triggers
    /// immediate delay increase.
    pub fn on_packet_loss(&mut self) {
        // Treat packet loss as 100% drop rate
        self.on_high_drop_rate(1.0);
    }

    /// Forces a specific delay value.
    ///
    /// Useful for manual control or when network conditions change abruptly.
    ///
    /// # Arguments
    ///
    /// * `delay` - The delay value to set
    pub fn set_delay(&mut self, delay: Duration) {
        self.current_delay = delay;
    }

    /// Resets to the default delay for the current timing template.
    pub fn reset(&mut self) {
        self.current_delay = self.default_delay;
        self.good_responses = 0;
        self.drop_rate = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_delay_new() {
        let delay = AdaptiveDelay::new(TimingTemplate::Normal);
        assert_eq!(delay.timing_level(), 3);
        assert_eq!(delay.delay(), Duration::from_millis(0));
    }

    #[test]
    fn test_adaptive_delay_paranoid() {
        let delay = AdaptiveDelay::new(TimingTemplate::Paranoid);
        assert_eq!(delay.timing_level(), 0);
        assert_eq!(delay.delay(), Duration::from_secs(300)); // 5 min
    }

    #[test]
    fn test_adaptive_delay_sneaky() {
        let delay = AdaptiveDelay::new(TimingTemplate::Sneaky);
        assert_eq!(delay.timing_level(), 1);
        assert_eq!(delay.delay(), Duration::from_secs(15)); // 15 sec
    }

    #[test]
    fn test_adaptive_delay_polite() {
        let delay = AdaptiveDelay::new(TimingTemplate::Polite);
        assert_eq!(delay.timing_level(), 2);
        assert_eq!(delay.delay(), Duration::from_millis(400)); // 400 ms
    }

    #[test]
    fn test_high_drop_rate_t0_t3() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        assert_eq!(delay.timing_level(), 3);

        // Simulate high drop rate
        delay.on_high_drop_rate(0.3);

        // Should increase delay (10x multiplier for T0-T3)
        // Starting from 0ms, max(0*10, 1000) = 1000ms
        assert_eq!(delay.delay(), Duration::from_millis(MIN_DELAY_MS_T0_T3));
    }

    #[test]
    fn test_high_drop_rate_t4_t5() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Aggressive);
        assert_eq!(delay.timing_level(), 4);

        // Simulate high drop rate
        delay.on_high_drop_rate(0.3);

        // Should increase delay (2x multiplier for T4-T5)
        // Starting from 0ms, max(0*2, 100) = 100ms
        assert_eq!(delay.delay(), Duration::from_millis(MIN_DELAY_MS_T4_T5));
    }

    #[test]
    fn test_high_drop_rate_clamp_t0_t3() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        delay.set_delay(Duration::from_millis(2000));

        // Multiple high drop rate events
        delay.on_high_drop_rate(0.3);
        // 2000 * 10 = 20000, clamped to 10000
        assert_eq!(delay.delay(), Duration::from_millis(MAX_DELAY_MS_T0_T3));

        delay.on_high_drop_rate(0.3);
        // Should stay at max
        assert_eq!(delay.delay(), Duration::from_millis(MAX_DELAY_MS_T0_T3));
    }

    #[test]
    fn test_high_drop_rate_clamp_t4_t5() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Aggressive);
        delay.set_delay(Duration::from_millis(600));

        // Multiple high drop rate events
        delay.on_high_drop_rate(0.3);
        // 600 * 2 = 1200, clamped to 1000
        assert_eq!(delay.delay(), Duration::from_millis(MAX_DELAY_MS_T4_T5));

        delay.on_high_drop_rate(0.3);
        // Should stay at max
        assert_eq!(delay.delay(), Duration::from_millis(MAX_DELAY_MS_T4_T5));
    }

    #[test]
    fn test_good_response_decay() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        delay.set_delay(Duration::from_millis(2000));

        // Accumulate good responses
        for _ in 0..GOOD_RESPONSE_THRESHOLD {
            delay.on_good_response();
        }

        // Delay should be halved: 2000 / 2 = 1000ms
        assert_eq!(delay.delay(), Duration::from_millis(1000));

        // More good responses
        for _ in 0..GOOD_RESPONSE_THRESHOLD {
            delay.on_good_response();
        }

        // Delay should be halved again: 1000 / 2 = 500ms
        assert_eq!(delay.delay(), Duration::from_millis(500));
    }

    #[test]
    fn test_good_response_clamp_to_default() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        // Default is 0ms. Start with 1ms to test decay.
        delay.set_delay(Duration::from_millis(1));

        for _ in 0..GOOD_RESPONSE_THRESHOLD {
            delay.on_good_response();
        }

        // 1ms / 2 = 0ms (integer division), max(0ms, 0ms) = 0ms
        assert_eq!(delay.delay(), Duration::from_millis(0));
    }

    #[test]
    fn test_packet_loss() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        delay.set_delay(Duration::from_millis(100));

        delay.on_packet_loss();

        // Packet loss triggers aggressive backoff
        assert_eq!(delay.delay(), Duration::from_millis(MIN_DELAY_MS_T0_T3));
    }

    #[test]
    fn test_reset() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        delay.set_delay(Duration::from_millis(5000));

        delay.reset();

        // Should return to default (0ms for T3 Normal)
        assert_eq!(delay.delay(), Duration::from_millis(0));
        assert!((delay.drop_rate() - 0.0).abs() < f32::EPSILON);
        assert_eq!(delay.good_responses, 0);
    }

    #[test]
    fn test_set_delay() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        let custom_delay = Duration::from_millis(2500);

        delay.set_delay(custom_delay);

        assert_eq!(delay.delay(), custom_delay);
    }

    #[test]
    fn test_drop_rate() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        assert!((delay.drop_rate() - 0.0).abs() < f32::EPSILON);

        delay.on_high_drop_rate(0.25);
        assert!((delay.drop_rate() - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn test_drop_rate_decay() {
        let mut delay = AdaptiveDelay::new(TimingTemplate::Normal);
        delay.on_high_drop_rate(1.0);
        assert!((delay.drop_rate() - 1.0).abs() < f32::EPSILON);

        // Good responses should decay drop rate estimate
        for _ in 0..10 {
            delay.on_good_response();
        }

        assert!(delay.drop_rate() < 1.0);
        assert!(delay.drop_rate() > 0.0);
    }
}
