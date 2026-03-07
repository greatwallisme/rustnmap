//! TCP-like congestion control for scanning.
//!
//! This module implements congestion control similar to TCP's slow start,
//! congestion avoidance, and recovery mechanisms. This helps manage scan
//! rate to avoid overwhelming targets or network infrastructure.
//!
//! # Architecture
//!
//! Based on `doc/architecture.md` Section 2.3.4, this implements:
//!
//! ```text
//! CongestionController (TCP-like)
//! ├─ cwnd (congestion window): probes in flight
//! ├─ ssthresh (slow start threshold): when to switch from slow start
//! └─ Phase Detection:
//!    ├─ Slow Start: exponential growth (cwnd *= 2 per RTT)
//!    ├─ Congestion Avoidance: linear growth (cwnd += 1 per RTT)
//!    └─ Recovery: reduce after loss
//! ```
//!
//! # Behavior
//!
//! - **Slow Start**: Double congestion window each RTT until threshold
//! - **Congestion Avoidance**: Increment by 1 each RTT after threshold
//! - **On Loss**: Reduce threshold to cwnd/2, reset cwnd to 1
//!
//! # Examples
//!
//! ```rust
//! use rustnmap_scan::congestion::CongestionControl;
//!
//! let mut cc = CongestionControl::new(10, 100); // initial=1, max=100
//!
//! // Probe sent successfully
//! cc.on_packet_sent();
//!
//! // Packet lost
//! cc.on_packet_loss();
//! ```
//!
//! # References
//!
//! - `doc/architecture.md` Section 2.3.4
//! - `reference/nmap/timing.cc` - Nmap's congestion control
//! - RFC 5681 - TCP Congestion Control

#![warn(missing_docs)]

use std::time::Duration;

/// Congestion control phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Slow start: exponential growth of congestion window.
    SlowStart,
    /// Congestion avoidance: linear growth of congestion window.
    CongestionAvoidance,
    /// Recovery after packet loss.
    Recovery,
}

/// TCP-like congestion control for scanning.
///
/// Manages the number of probes that can be "in flight" simultaneously
/// to avoid overwhelming the target or network.
///
/// # Thread Safety
///
/// This type is `Send + Sync` and can be shared between threads using
/// `Arc<Mutex<CongestionControl>>` for coordinated scanning.
#[derive(Debug, Clone)]
pub struct CongestionControl {
    /// Congestion window (probes in flight).
    cwnd: u32,
    /// Slow start threshold.
    ssthresh: u32,
    /// Maximum congestion window.
    max_cwnd: u32,
    /// Current phase (slow start, congestion avoidance, or recovery).
    phase: Phase,
    /// Number of packets acknowledged in current RTT.
    packets_acked: u32,
    /// Time when current RTT started.
    rtt_start: Option<std::time::Instant>,
}

impl CongestionControl {
    /// Creates a new congestion controller.
    ///
    /// # Arguments
    ///
    /// * `initial_cwnd` - Initial congestion window (default: 1)
    /// * `max_cwnd` - Maximum congestion window (e.g., 100 for T3 Normal)
    ///
    /// # Returns
    ///
    /// A new `CongestionControl` instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_scan::congestion::CongestionControl;
    ///
    /// let cc = CongestionControl::new(1, 100);
    /// assert_eq!(cc.cwnd(), 1);
    /// ```
    #[must_use]
    pub const fn new(initial_cwnd: u32, max_cwnd: u32) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: u32::MAX, // Start with infinite threshold (always slow start)
            max_cwnd,
            phase: Phase::SlowStart,
            packets_acked: 0,
            rtt_start: None,
        }
    }

    /// Returns the current congestion window.
    ///
    /// This is the maximum number of probes that should be in flight.
    ///
    /// # Returns
    ///
    /// Current congestion window size.
    #[must_use]
    pub const fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Returns the slow start threshold.
    ///
    /// # Returns
    ///
    /// Current slow start threshold.
    #[must_use]
    pub const fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Returns true if more packets can be sent.
    ///
    /// Checks if the number of unacknowledged packets is less than
    /// the congestion window.
    ///
    /// # Arguments
    ///
    /// * `unacked` - Number of packets sent but not yet acknowledged
    ///
    /// # Returns
    ///
    /// `true` if more packets can be sent, `false` if at congestion window limit.
    #[must_use]
    pub const fn can_send(&self, unacked: u32) -> bool {
        unacked < self.cwnd
    }

    /// Records a packet being sent.
    ///
    /// Updates congestion window based on phase:
    /// - **Slow Start**: cwnd *= 2 (exponential), capped at ssthresh
    /// - **Congestion Avoidance**: cwnd += 1 (linear)
    ///
    /// The window growth is clamped to `max_cwnd`.
    pub fn on_packet_sent(&mut self) {
        // Track packets sent in current RTT
        self.packets_acked = self.packets_acked.saturating_add(1);

        // Start RTT timer if not already running
        if self.rtt_start.is_none() {
            self.rtt_start = Some(std::time::Instant::now());
        }

        // Update congestion window based on phase
        if self.cwnd < self.ssthresh {
            // Slow Start: exponential growth, but cap at ssthresh
            let new_cwnd = self.cwnd.saturating_mul(2);
            self.cwnd = new_cwnd.min(self.ssthresh).min(self.max_cwnd);
            self.phase = Phase::SlowStart;
        } else {
            // Congestion Avoidance: linear growth
            // Add 1 for each ACK (but not more than max)
            self.cwnd = self.cwnd.saturating_add(1).min(self.max_cwnd);
            self.phase = Phase::CongestionAvoidance;
        }
    }

    /// Records a packet loss.
    ///
    /// On packet loss:
    /// - Set ssthresh = cwnd / 2
    /// - Reset cwnd = 1
    /// - Enter recovery phase
    ///
    /// This follows TCP's behavior on congestion indication.
    pub fn on_packet_loss(&mut self) {
        // Set threshold to half of current window
        self.ssthresh = self.cwnd / 2;
        // Ensure threshold is at least 1
        self.ssthresh = self.ssthresh.max(1);

        // Reset to initial window
        self.cwnd = 1;

        // Enter recovery phase
        self.phase = Phase::Recovery;

        // Reset RTT tracking
        self.packets_acked = 0;
        self.rtt_start = None;
    }

    /// Records a timeout (no response for entire window).
    ///
    /// This is more severe than a single packet loss and triggers
    /// a more aggressive reduction.
    pub fn on_timeout(&mut self) {
        // More aggressive reduction on timeout
        self.ssthresh = self.cwnd / 2;
        self.ssthresh = self.ssthresh.max(1);

        // Reset to initial window
        self.cwnd = 1;

        self.phase = Phase::Recovery;
        self.packets_acked = 0;
        self.rtt_start = None;
    }

    /// Ends the current RTT period.
    ///
    /// Called when an RTT completes to reset the ACK counter.
    /// In TCP, this happens when a cumulative ACK is received.
    ///
    /// For scanning, we typically call this after receiving responses
    /// for the current window of probes.
    pub fn end_rtt(&mut self) {
        self.packets_acked = 0;
        self.rtt_start = None;
    }

    /// Returns the current RTT duration.
    ///
    /// # Returns
    ///
    /// Duration since current RTT started, or `None` if no RTT in progress.
    #[must_use]
    pub fn current_rtt(&self) -> Option<Duration> {
        self.rtt_start.map(|start| start.elapsed())
    }

    /// Resets the congestion controller to initial state.
    ///
    /// Useful when starting a new scan or changing targets.
    pub fn reset(&mut self) {
        self.cwnd = 1;
        self.ssthresh = u32::MAX;
        self.phase = Phase::SlowStart;
        self.packets_acked = 0;
        self.rtt_start = None;
    }
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::new(1, 100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_control_new() {
        let cc = CongestionControl::new(1, 100);
        assert_eq!(cc.cwnd(), 1);
        assert_eq!(cc.ssthresh(), u32::MAX);
    }

    #[test]
    fn test_congestion_control_can_send() {
        let cc = CongestionControl::new(2, 100);
        assert!(cc.can_send(0));
        assert!(cc.can_send(1));
        assert!(!cc.can_send(2)); // At cwnd limit
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionControl::new(1, 100);

        // In slow start, cwnd doubles each ACK
        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 2); // 1 * 2

        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 4); // 2 * 2

        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 8); // 4 * 2
    }

    #[test]
    fn test_congestion_avoidance_growth() {
        let mut cc = CongestionControl::new(1, 100);

        // Set ssthresh to trigger congestion avoidance
        cc.ssthresh = 5;

        // Initial growth (still in slow start)
        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 2);

        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 4);

        // Now in congestion avoidance (linear growth)
        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 5); // 4 + 1

        cc.on_packet_sent();
        assert_eq!(cc.cwnd(), 6); // 5 + 1
    }

    #[test]
    fn test_packet_loss_reduction() {
        let mut cc = CongestionControl::new(1, 100);

        // Grow to cwnd = 16
        for _ in 0..4 {
            cc.on_packet_sent();
        }
        assert_eq!(cc.cwnd(), 16);

        // Simulate packet loss
        cc.on_packet_loss();

        // Should reduce: ssthresh = 16/2 = 8, cwnd = 1
        assert_eq!(cc.ssthresh(), 8);
        assert_eq!(cc.cwnd(), 1);
    }

    #[test]
    fn test_timeout_reduction() {
        let mut cc = CongestionControl::new(1, 100);

        // Grow to cwnd = 16
        for _ in 0..4 {
            cc.on_packet_sent();
        }
        assert_eq!(cc.cwnd(), 16);

        // Simulate timeout
        cc.on_timeout();

        // Should reduce: ssthresh = 16/2 = 8, cwnd = 1
        assert_eq!(cc.ssthresh(), 8);
        assert_eq!(cc.cwnd(), 1);
    }

    #[test]
    fn test_max_cwnd_clamp() {
        let mut cc = CongestionControl::new(1, 10);

        // Grow beyond max_cwnd
        for _ in 0..10 {
            cc.on_packet_sent();
        }

        // Should be clamped to max_cwnd
        assert_eq!(cc.cwnd(), 10);
    }

    #[test]
    fn test_reset() {
        let mut cc = CongestionControl::new(1, 100);

        // Grow and modify state
        for _ in 0..3 {
            cc.on_packet_sent();
        }
        assert_eq!(cc.cwnd(), 8);
        assert_eq!(cc.ssthresh(), u32::MAX);

        // Reset
        cc.reset();

        // Should be back to initial state
        assert_eq!(cc.cwnd(), 1);
        assert_eq!(cc.ssthresh(), u32::MAX);
    }

    #[test]
    fn test_default() {
        let cc = CongestionControl::default();
        assert_eq!(cc.cwnd(), 1);
        assert_eq!(cc.ssthresh(), u32::MAX);
    }
}
