//! Congestion control and adaptive timing for network scanning.
//!
//! This module implements congestion control mechanisms including RTT tracking,
//! packet loss detection, and adaptive rate limiting for efficient scanning.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustnmap_evasion::TimingTemplate;
use tracing::{debug, trace};

/// Statistics for congestion control decisions.
#[derive(Debug, Default)]
pub struct CongestionStats {
    /// Total packets sent.
    packets_sent: AtomicU64,
    /// Total packets acknowledged (responses received).
    packets_acked: AtomicU64,
    /// Total retransmissions.
    retransmissions: AtomicU64,
    /// Current estimated RTT in microseconds.
    rtt_micros: AtomicU64,
    /// RTT variance in microseconds.
    rttvar_micros: AtomicU64,
    /// Last congestion window update time.
    last_update: Mutex<Option<Instant>>,
}

impl CongestionStats {
    /// Creates new congestion statistics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_acked: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            rtt_micros: AtomicU64::new(100_000), // 100ms default
            rttvar_micros: AtomicU64::new(50_000), // 50ms default
            last_update: Mutex::new(None),
        }
    }

    /// Records a packet being sent.
    pub fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a packet acknowledgment (response received).
    pub fn record_acked(&self) {
        self.packets_acked.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a retransmission.
    pub fn record_retransmission(&self) {
        self.retransmissions.fetch_add(1, Ordering::Relaxed);
    }

    /// Updates RTT estimate using EWMA (Exponentially Weighted Moving Average).
    ///
    /// Uses the formula from RFC 2988:
    ///     - SRTT = (1 - alpha) * SRTT + alpha * RTT
    ///     - RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|
    ///
    /// where alpha = 1/8 and beta = 1/4
    ///
    /// # Panics
    ///
    /// This function may panic if the internal lock is poisoned.
    #[expect(clippy::cast_possible_truncation, reason = "RTT in micros fits in u64")]
    pub fn update_rtt(&self, rtt: Duration) {
        debug_assert!(!rtt.is_zero(), "RTT should never be zero");
        debug_assert!(rtt.as_secs() < 300, "RTT should be less than 5 minutes");

        let rtt_micros = rtt.as_micros() as u64;

        loop {
            let old_srtt = self.rtt_micros.load(Ordering::Relaxed);
            let old_rttvar = self.rttvar_micros.load(Ordering::Relaxed);

            // RFC 2988 calculations
            // SRTT = (7/8) * old_SRTT + (1/8) * RTT
            let new_srtt = (7 * old_srtt + rtt_micros) / 8;

            // RTTVAR = (3/4) * old_RTTVAR + (1/4) * |SRTT - RTT|
            let diff = new_srtt.abs_diff(rtt_micros);
            let new_rttvar = (3 * old_rttvar + diff) / 4;

            // Clamp values to reasonable bounds
            let clamped_srtt = new_srtt.clamp(1_000, 10_000_000); // 1ms to 10s
            let clamped_rttvar = new_rttvar.clamp(500, 5_000_000); // 0.5ms to 5s

            if self
                .rtt_micros
                .compare_exchange(old_srtt, clamped_srtt, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.rttvar_micros.store(clamped_rttvar, Ordering::Relaxed);
                *self.last_update.lock().unwrap() = Some(Instant::now());
                trace!(srtt = clamped_srtt, rttvar = clamped_rttvar, "RTT updated");
                break;
            }
        }
    }

    /// Returns the current packet loss rate (0.0 to 1.0).
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Packet counts fit within f64 precision for rate calculation"
    )]
    pub fn packet_loss_rate(&self) -> f64 {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let acked = self.packets_acked.load(Ordering::Relaxed);

        if sent == 0 {
            0.0
        } else {
            let lost = sent.saturating_sub(acked);
            lost as f64 / sent as f64
        }
    }

    /// Returns the current RTT estimate.
    #[must_use]
    pub fn rtt(&self) -> Duration {
        Duration::from_micros(self.rtt_micros.load(Ordering::Relaxed))
    }

    /// Returns the current RTT variance.
    #[must_use]
    pub fn rttvar(&self) -> Duration {
        Duration::from_micros(self.rttvar_micros.load(Ordering::Relaxed))
    }

    /// Returns the recommended timeout based on current RTT.
    ///
    /// Uses RFC 2988 formula: RTO = SRTT + 4 * RTTVAR
    #[must_use]
    pub fn recommended_timeout(&self) -> Duration {
        let srtt = self.rtt_micros.load(Ordering::Relaxed);
        let rttvar = self.rttvar_micros.load(Ordering::Relaxed);
        let timeout_micros = srtt.saturating_add(4 * rttvar);
        Duration::from_micros(timeout_micros.min(30_000_000)) // Cap at 30s
    }
}

/// Congestion controller for adaptive scanning.
#[derive(Debug)]
pub struct CongestionController {
    /// Congestion statistics.
    stats: Arc<CongestionStats>,
    /// Current congestion window (number of parallel probes).
    cwnd: AtomicUsize,
    /// Minimum congestion window.
    min_cwnd: usize,
    /// Maximum congestion window.
    max_cwnd: usize,
    /// Slow start threshold.
    ssthresh: AtomicUsize,
    /// Timing template for base rates.
    timing_template: TimingTemplate,
    /// Last time congestion was detected.
    last_congestion: Mutex<Option<Instant>>,
}

impl CongestionController {
    /// Creates a new congestion controller with default settings.
    ///
    /// # Arguments
    ///
    /// * `timing_template` - Base timing template for rate control
    /// * `max_parallel` - Maximum number of parallel probes (must be > 0)
    #[must_use]
    pub fn new(timing_template: TimingTemplate, max_parallel: usize) -> Self {
        debug_assert!(max_parallel > 0, "max_parallel must be greater than 0");

        let initial_cwnd = (max_parallel / 4).max(1); // Start conservatively

        Self {
            stats: Arc::new(CongestionStats::new()),
            cwnd: AtomicUsize::new(initial_cwnd),
            min_cwnd: 1,
            max_cwnd: max_parallel,
            ssthresh: AtomicUsize::new(max_parallel / 2),
            timing_template,
            last_congestion: Mutex::new(None),
        }
    }

    /// Returns a reference to the congestion statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<CongestionStats> {
        &self.stats
    }

    /// Returns the current congestion window size.
    #[must_use]
    pub fn cwnd(&self) -> usize {
        self.cwnd.load(Ordering::Relaxed)
    }

    /// Called when a packet is sent.
    pub fn on_packet_sent(&self) {
        self.stats.record_sent();
    }

    /// Called when a packet is acknowledged (response received).
    ///
    /// Increases congestion window according to TCP-like slow start/congestion avoidance.
    pub fn on_packet_acked(&self, rtt: Option<Duration>) {
        self.stats.record_acked();

        if let Some(rtt) = rtt {
            self.stats.update_rtt(rtt);
        }

        let current_cwnd = self.cwnd.load(Ordering::Relaxed);
        let ssthresh = self.ssthresh.load(Ordering::Relaxed);

        if current_cwnd < ssthresh {
            // Slow start: exponential growth
            let new_cwnd = (current_cwnd * 2).min(self.max_cwnd);
            self.cwnd.store(new_cwnd, Ordering::Relaxed);
            trace!(cwnd = new_cwnd, "Slow start growth");
        } else {
            // Congestion avoidance: linear growth
            let new_cwnd = (current_cwnd + 1).min(self.max_cwnd);
            self.cwnd.store(new_cwnd, Ordering::Relaxed);
            trace!(cwnd = new_cwnd, "Congestion avoidance growth");
        }
    }

    /// Called when packet loss is detected.
    ///
    /// Reduces congestion window according to TCP congestion control.
    ///
    /// # Panics
    ///
    /// This function may panic if the internal lock is poisoned.
    pub fn on_packet_lost(&self) {
        self.stats.record_retransmission();

        let current_cwnd = self.cwnd.load(Ordering::Relaxed);

        // TCP Reno-style congestion control
        let new_ssthresh = current_cwnd / 2;
        let new_cwnd = new_ssthresh.max(self.min_cwnd);

        self.ssthresh.store(new_ssthresh, Ordering::Relaxed);
        self.cwnd.store(new_cwnd, Ordering::Relaxed);
        *self.last_congestion.lock().unwrap() = Some(Instant::now());

        debug!(
            cwnd = new_cwnd,
            ssthresh = new_ssthresh,
            "Congestion detected, window reduced"
        );
    }

    /// Returns the recommended delay between probes.
    ///
    /// Based on timing template and current network conditions.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Loss rate is 0.0-1.0, multiplied by 100 gives safe range for millis"
    )]
    pub fn recommended_delay(&self) -> Duration {
        let base_delay = match self.timing_template {
            TimingTemplate::Paranoid => Duration::from_millis(300),
            TimingTemplate::Sneaky => Duration::from_millis(100),
            TimingTemplate::Polite => Duration::from_millis(10),
            TimingTemplate::Normal | TimingTemplate::Aggressive | TimingTemplate::Insane => {
                Duration::ZERO
            }
        };

        // If packet loss is high, add extra delay
        let loss_rate = self.stats.packet_loss_rate();
        if loss_rate > 0.1 {
            // More than 10% packet loss
            let extra_delay = Duration::from_millis((loss_rate * 100.0) as u64);
            base_delay + extra_delay
        } else {
            base_delay
        }
    }

    /// Returns true if we should wait before sending more probes.
    #[must_use]
    pub fn should_wait(&self, in_flight: usize) -> bool {
        in_flight >= self.cwnd.load(Ordering::Relaxed)
    }

    /// Returns the recommended batch size for sending probes.
    #[must_use]
    pub fn recommended_batch_size(&self) -> usize {
        self.cwnd.load(Ordering::Relaxed)
    }
}

/// Rate limiter for controlling scan rate.
#[derive(Debug)]
pub struct RateLimiter {
    /// Minimum rate in packets per second (None = no limit).
    min_rate: Option<u64>,
    /// Maximum rate in packets per second (None = no limit).
    max_rate: Option<u64>,
    /// Packets sent in current window.
    window_count: AtomicU64,
    /// Window start time.
    window_start: Mutex<Instant>,
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
            window_start: Mutex::new(Instant::now()),
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
    #[expect(
        clippy::cast_precision_loss,
        reason = "Packet counts fit within f64 precision for rate calculation"
    )]
    #[must_use]
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

/// Adaptive timing controller combining congestion control and rate limiting.
#[derive(Debug)]
pub struct AdaptiveTiming {
    /// Congestion controller.
    congestion: CongestionController,
    /// Rate limiter.
    rate_limiter: RateLimiter,
    /// Last probe time.
    last_probe: Mutex<Instant>,
}

impl AdaptiveTiming {
    /// Creates a new adaptive timing controller.
    ///
    /// # Arguments
    ///
    /// * `timing_template` - Base timing template
    /// * `max_parallel` - Maximum parallel probes (must be > 0)
    /// * `min_rate` - Minimum packets per second
    /// * `max_rate` - Maximum packets per second
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `max_parallel` is 0 or if `min_rate` > `max_rate`.
    #[must_use]
    pub fn new(
        timing_template: TimingTemplate,
        max_parallel: usize,
        min_rate: Option<u64>,
        max_rate: Option<u64>,
    ) -> Self {
        debug_assert!(max_parallel > 0, "max_parallel must be greater than 0");
        debug_assert!(
            min_rate.is_none() || max_rate.is_none() || min_rate <= max_rate,
            "min_rate must be less than or equal to max_rate"
        );
        Self {
            congestion: CongestionController::new(timing_template, max_parallel),
            rate_limiter: RateLimiter::new(min_rate, max_rate),
            last_probe: Mutex::new(Instant::now()),
        }
    }

    /// Returns a reference to the congestion controller.
    #[must_use]
    pub fn congestion(&self) -> &CongestionController {
        &self.congestion
    }

    /// Returns a reference to the rate limiter.
    #[must_use]
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    /// Waits until it's appropriate to send the next probe.
    ///
    /// Returns true if wait was successful, false if rate limited.
    ///
    /// # Panics
    ///
    /// This function may panic if the internal lock is poisoned.
    pub async fn wait_for_next_probe(&self, in_flight: usize) -> bool {
        // Check congestion window
        if self.congestion.should_wait(in_flight) {
            let delay = self.congestion.recommended_delay();
            if delay > Duration::ZERO {
                tokio::time::sleep(delay).await;
            }
        }

        // Check rate limiter
        if let Some(wait_time) = self.rate_limiter.check_rate() {
            tokio::time::sleep(wait_time).await;
        }

        // Apply recommended delay from congestion controller
        let congestion_delay = self.congestion.recommended_delay();
        let elapsed = self.last_probe.lock().unwrap().elapsed();

        if congestion_delay > elapsed {
            tokio::time::sleep(congestion_delay - elapsed).await;
        }

        *self.last_probe.lock().unwrap() = Instant::now();
        self.rate_limiter.record_sent();
        self.congestion.on_packet_sent();

        true
    }

    /// Records a successful probe response.
    pub fn record_response(&self, rtt: Option<Duration>) {
        self.congestion.on_packet_acked(rtt);
    }

    /// Records a probe timeout/lost packet.
    pub fn record_timeout(&self) {
        self.congestion.on_packet_lost();
    }

    /// Returns the recommended timeout for new probes.
    #[must_use]
    pub fn recommended_timeout(&self) -> Duration {
        self.congestion.stats().recommended_timeout()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_stats_rtt_update() {
        let stats = CongestionStats::new();

        // Initial RTT should be 100ms
        assert_eq!(stats.rtt().as_millis(), 100);

        // Update with faster RTT
        stats.update_rtt(Duration::from_millis(50));
        assert!(stats.rtt().as_millis() < 100);

        // Update with slower RTT
        stats.update_rtt(Duration::from_millis(200));
        assert!(stats.rtt().as_millis() > 50);
    }

    #[test]
    fn test_congestion_stats_packet_loss() {
        let stats = CongestionStats::new();

        // Initially no loss
        assert_eq!(stats.packet_loss_rate(), 0.0);

        // Send 10 packets
        for _ in 0..10 {
            stats.record_sent();
        }

        // Ack 7 packets
        for _ in 0..7 {
            stats.record_acked();
        }

        // Should have 30% loss
        assert!((stats.packet_loss_rate() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_congestion_controller_window() {
        let controller = CongestionController::new(TimingTemplate::Normal, 100);

        // Initial window should be conservative
        let initial_cwnd = controller.cwnd();
        assert!(initial_cwnd > 0);
        assert!(initial_cwnd <= 100);

        // Ack packets to grow window
        for _ in 0..10 {
            controller.on_packet_acked(None);
        }

        // Window should have grown
        assert!(controller.cwnd() >= initial_cwnd);
    }

    #[test]
    fn test_congestion_controller_loss() {
        let controller = CongestionController::new(TimingTemplate::Normal, 100);

        // Grow window first
        for _ in 0..20 {
            controller.on_packet_acked(None);
        }

        let cwnd_before = controller.cwnd();

        // Simulate packet loss
        controller.on_packet_lost();

        // Window should decrease
        assert!(controller.cwnd() < cwnd_before);
    }

    #[test]
    fn test_rate_limiter_max_rate() {
        let limiter = RateLimiter::new(None, Some(10)); // Max 10 pps

        // Should be able to send initially
        assert!(limiter.check_rate().is_none());

        // Record many packets quickly
        for _ in 0..20 {
            limiter.record_sent();
        }

        // Should now be rate limited
        assert!(limiter.check_rate().is_some());
    }

    #[test]
    fn test_rate_limiter_current_rate() {
        let limiter = RateLimiter::new(None, None);

        // Initially rate should be 0 or very high
        assert!(limiter.current_rate() >= 0.0);

        // Record some packets
        for _ in 0..10 {
            limiter.record_sent();
        }

        // Rate should be positive
        assert!(limiter.current_rate() > 0.0);
    }

    #[test]
    fn test_adaptive_timing_creation() {
        let timing = AdaptiveTiming::new(TimingTemplate::Aggressive, 50, Some(10), Some(100));

        assert_eq!(timing.congestion().cwnd(), 12); // 50/4 = 12
        assert_eq!(timing.rate_limiter().min_rate(), Some(10));
        assert_eq!(timing.rate_limiter().max_rate(), Some(100));
    }

    #[test]
    fn test_congestion_stats_recommended_timeout() {
        let stats = CongestionStats::new();

        // Default timeout should be based on initial SRTT + 4*RTTVAR
        let timeout = stats.recommended_timeout();
        assert!(timeout.as_millis() >= 100);

        // Update with specific RTT
        stats.update_rtt(Duration::from_millis(50));
        let new_timeout = stats.recommended_timeout();
        assert!(new_timeout > Duration::from_millis(50));
    }
}
