//! Parallel port scanning engine inspired by Nmap's `UltraScan` architecture.
//!
//! This module implements high-performance parallel scanning that sends multiple
//! probes concurrently instead of sequentially waiting for each response.
//!
//! # Architecture
//!
//! The engine maintains a list of "outstanding" probes (sent but not yet responded)
//! and uses multiple concurrent tasks:
//! - A sender task that batches probes up to the parallelism limit
//! - A receiver task that continuously processes incoming responses
//! - A matcher that correlates responses to outstanding probes
//!
//! # Performance
//!
//! This architecture provides 20-30x speedup over sequential scanning for
//! large port ranges (e.g., Fast Scan with 100 ports).
//!
//! # Example
//!
//! ```no_run
//! use rustnmap_scan::ultrascan::ParallelScanEngine;
//! use std::net::Ipv4Addr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = ParallelScanEngine::new(
//!     Ipv4Addr::new(192, 168, 1, 100),
//!     rustnmap_common::ScanConfig::default(),
//! )?;
//!
//! let ports = vec![22, 80, 443];
//! let results = engine.scan_ports("192.168.1.1".parse()?, &ports).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc as StdArc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::packet_adapter::{create_stealth_engine, ScannerPacketEngine};
use rustnmap_common::{Port, PortState, RateLimiter, ScanConfig};
use rustnmap_net::raw_socket::{parse_tcp_response, RawSocket, TcpPacketBuilder};
use rustnmap_packet::BpfFilter;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout as tokio_timeout;

// ============================================================================
// Internal Congestion Control (minimal implementation for ultrascan)
// ============================================================================

/// Internal congestion statistics for adaptive timing.
///
/// Uses EWMA (Exponentially Weighted Moving Average) for RTT tracking,
/// following RFC 2988: SRTT = (1-1/8)*SRTT + (1/8)*RTT
///
/// Implements nmap's `cc_scale` mechanism for adaptive congestion window growth
/// when packet loss is detected. See `timing.cc:209-218` in nmap source.
#[derive(Debug)]
struct InternalCongestionStats {
    /// Initial RTT timeout from config.
    ///
    /// This is used for the first probe before any RTT measurement.
    /// See nmap timing.cc:82: `to->timeout = o.initialRttTimeout() * 1000;`
    initial_rtt: Duration,
    /// Maximum RTT timeout from config.
    ///
    /// This is the maximum allowed timeout for any probe.
    /// See nmap timing.cc:84: `to->timeout = MIN(o.maxRttTimeout() * 1000, to->timeout);`
    max_rtt: Duration,
    /// Smoothed RTT in microseconds.
    srtt_micros: std::sync::atomic::AtomicU64,
    /// RTT variance in microseconds.
    rttvar_micros: std::sync::atomic::AtomicU64,
    /// Whether this is the first RTT measurement.
    ///
    /// Nmap uses -1 for SRTT/RTTVAR to indicate "not initialized", but we use a separate flag
    /// to avoid needing `AtomicI64`.
    first_measurement: std::sync::atomic::AtomicBool,
    /// Total packets sent.
    packets_sent: std::sync::atomic::AtomicU64,
    /// Total packets acknowledged.
    packets_acked: std::sync::atomic::AtomicU64,
    /// Number of replies we would expect if every probe produced a reply.
    ///
    /// This is incremented when a probe gets a reply OR times out.
    /// See nmap `timing.h:87-91` and `scan_engine.cc:1608-1612`.
    num_replies_expected: std::sync::atomic::AtomicU64,
    /// Number of replies we've actually received.
    ///
    /// This is incremented only when an actual reply is received.
    /// See nmap `timing.h:92-93` and `timing.cc:222`.
    num_replies_received: std::sync::atomic::AtomicU64,
}

impl InternalCongestionStats {
    /// Creates new congestion statistics with the given initial and max RTT.
    ///
    /// Uses nmap T3 (Normal) defaults for RTTVAR:
    /// - Initial SRTT: 1000ms (`INITIAL_RTT_TIMEOUT`)
    /// - Initial RTTVAR: 1000ms (clamped between 5ms-2000ms, based on SRTT)
    ///
    /// # Panics
    ///
    /// Panics if `initial_rtt` is larger than 30 seconds (overflow in u64).
    #[expect(
        clippy::cast_possible_truncation,
        reason = "RTT values are bounded to reasonable network latencies (< 30s)"
    )]
    fn new(initial_rtt: Duration, max_rtt: Duration) -> Self {
        let srtt_micros = initial_rtt.as_micros() as u64;
        // Nmap: rttvar = box(5000, 2000000, srtt) = clamp(srtt, 5ms, 2000ms)
        let rttvar_micros = srtt_micros.clamp(5_000, 2_000_000);
        Self {
            initial_rtt,
            max_rtt,
            srtt_micros: std::sync::atomic::AtomicU64::new(srtt_micros),
            rttvar_micros: std::sync::atomic::AtomicU64::new(rttvar_micros),
            // Track if this is the first RTT measurement (nmap uses -1 sentinel)
            first_measurement: std::sync::atomic::AtomicBool::new(true),
            packets_sent: std::sync::atomic::AtomicU64::new(0),
            packets_acked: std::sync::atomic::AtomicU64::new(0),
            num_replies_expected: std::sync::atomic::AtomicU64::new(0),
            num_replies_received: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Updates RTT estimate using EWMA.
    ///
    /// For the first measurement, uses the measurement directly (nmap behavior).
    /// See nmap `timing.cc:adjust_timeouts2` (lines 99-167).
    #[expect(
        clippy::cast_possible_truncation,
        reason = "RTT values are bounded to reasonable network latencies (< 30s)"
    )]
    fn update_rtt(&self, rtt: Duration) {
        use std::sync::atomic::Ordering;

        let rtt_micros = rtt.as_micros() as u64;

        // Check if this is the first measurement (nmap uses -1 sentinel)
        if self
            .first_measurement
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            // First measurement: use RTT directly (nmap timing.cc:119-124)
            self.srtt_micros.store(rtt_micros, Ordering::Relaxed);
            // RTTVAR = clamp(RTT, 5ms, 2000ms) - nmap: box(5000, 2000000, delta)
            let clamped_rttvar = rtt_micros.clamp(5_000, 2_000_000);
            self.rttvar_micros.store(clamped_rttvar, Ordering::Relaxed);
            return;
        }

        // Subsequent measurements: RFC 2988 EWMA
        let old_srtt = self.srtt_micros.load(Ordering::Relaxed);
        let old_rttvar = self.rttvar_micros.load(Ordering::Relaxed);

        // RFC 2988: SRTT = (7/8)*SRTT + (1/8)*RTT
        let new_srtt = (7 * old_srtt + rtt_micros) / 8;
        // RTTVAR = (3/4)*RTTVAR + (1/4)*|SRTT-RTT|
        let diff = new_srtt.abs_diff(rtt_micros);
        let new_rttvar = (3 * old_rttvar + diff) / 4;

        // Clamp RTTVAR to nmap's bounds: 5ms to 2000ms
        let clamped_rttvar = new_rttvar.clamp(5_000, 2_000_000);

        self.srtt_micros.store(new_srtt, Ordering::Relaxed);
        self.rttvar_micros.store(clamped_rttvar, Ordering::Relaxed);
    }

    /// Returns the recommended timeout: SRTT + 4*RTTVAR.
    ///
    /// The result is clamped to:
    /// - Lower bound: `MIN_RTT_TIMEOUT` (100ms) from nmap
    /// - Upper bound: `max_rtt` from timing template config
    ///
    /// For the first probe (before any RTT measurement), returns `initial_rtt` directly.
    /// This matches nmap's behavior: `to->timeout = o.initialRttTimeout() * 1000;`
    /// (see timing.cc:82).
    ///
    /// The upper bound uses `max_rtt` from config instead of a fixed constant,
    /// allowing T5 (Insane) to properly use 300ms max timeout.
    fn recommended_timeout(&self) -> Duration {
        use std::sync::atomic::Ordering;
        // Check if this is the first measurement
        if self.first_measurement.load(Ordering::Relaxed) {
            // First probe: use initial_rtt directly (nmap timing.cc:82)
            // Also clamp to max_rtt to ensure initial timeout doesn't exceed max
            self.initial_rtt.min(self.max_rtt)
        } else {
            // Subsequent probes: use SRTT + 4*RTTVAR
            let srtt = self.srtt_micros.load(Ordering::Relaxed);
            let rttvar = self.rttvar_micros.load(Ordering::Relaxed);
            let timeout_micros = srtt.saturating_add(4 * rttvar);
            // Clamp to nmap's MIN_RTT_TIMEOUT (100ms) and config's max_rtt
            #[expect(
                clippy::cast_possible_truncation,
                reason = "max_rtt is in milliseconds, fits in u64"
            )]
            let max_micros = self.max_rtt.as_micros() as u64;
            let clamped = timeout_micros.clamp(100_000, max_micros);
            Duration::from_micros(clamped)
        }
    }

    /// Records a packet sent.
    fn record_sent(&self) {
        use std::sync::atomic::Ordering;
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a packet acknowledged.
    fn record_acked(&self) {
        use std::sync::atomic::Ordering;
        self.packets_acked.fetch_add(1, Ordering::Relaxed);
        // Increment num_replies_received when we actually get a reply
        // See nmap timing.cc:222
        self.num_replies_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a probe that got a reply OR timed out.
    ///
    /// This increments `num_replies_expected`, which is used to calculate
    /// the `cc_scale` factor for adaptive congestion window growth.
    /// See nmap `timing.h:87-91` and `scan_engine.cc:1608-1612`.
    fn record_expected(&self) {
        use std::sync::atomic::Ordering;
        self.num_replies_expected.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the congestion control scaling factor.
    ///
    /// This implements nmap's `cc_scale` mechanism from `timing.cc:209-218`.
    /// When packet loss occurs, this factor can be > 1, allowing the congestion
    /// window to grow faster to compensate for lost packets.
    ///
    /// # Formula
    ///
    /// ```text
    /// ratio = num_replies_expected / num_replies_received
    /// cc_scale = MIN(ratio, 50)
    /// ```
    ///
    /// - No packet loss: ratio = 1, `cc_scale` = 1 (normal growth)
    /// - Some packet loss: ratio > 1, `cc_scale` > 1 (accelerated growth)
    /// - Maximum: `cc_scale` = 50 (50x acceleration)
    ///
    /// # Returns
    ///
    /// The scaling factor, from 1.0 (no loss) to 50.0 (maximum acceleration).
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "Packet counts are bounded (u64) and f64 precision is sufficient for ratios up to 50x"
    )]
    fn cc_scale(&self) -> f64 {
        use std::sync::atomic::Ordering;
        let received = self.num_replies_received.load(Ordering::Relaxed);
        if received == 0 {
            // No replies yet, use normal scaling
            return 1.0;
        }
        let expected = self.num_replies_expected.load(Ordering::Relaxed);
        let ratio = expected as f64 / received as f64;
        // nmap's cc_scale_max = 50 (timing.cc:280)
        ratio.min(50.0)
    }
}

/// Internal congestion controller for adaptive parallelism.
///
/// Implements nmap's congestion control (NOT TCP Reno):
/// - Slow start: LINEAR growth (+1 per ACK)
/// - Congestion avoidance: very slow (+1 per cwnd ACKs)
#[derive(Debug)]
pub struct InternalCongestionController {
    stats: std::sync::Arc<InternalCongestionStats>,
    cwnd: std::sync::atomic::AtomicUsize,
    ssthresh: std::sync::atomic::AtomicUsize,
    /// ACK counter for congestion avoidance (increment once per cwnd ACKs).
    ca_ack_counter: std::sync::atomic::AtomicUsize,
    max_cwnd: usize,
    /// Congestion avoidance increment (`ca_incr`).
    /// From nmap `timing.cc:276-279`:
    /// - `timing_level` < 4 (T0-T3): `ca_incr` = 1
    /// - `timing_level` >= 4 (T4-T5): `ca_incr` = 2
    ca_incr: u8,
    /// The loop iteration number when we last reduced cwnd.
    /// Used to prevent multiple cwnd reductions in the same iteration.
    /// See nmap `timing.cc:last_drop` and `scan_engine.cc:1608-1612`.
    last_drop_iteration: std::sync::atomic::AtomicUsize,
}

impl InternalCongestionController {
    /// Creates a new congestion controller.
    ///
    /// Uses nmap's default initial values from `timing.cc:272-273`:
    /// - `group_initial_cwnd = 10` (matches `box(low_cwnd, max_cwnd, 10)`)
    /// - `initial_ssthresh = 75`
    ///
    /// From nmap `timing.cc:276-279`:
    /// - `timing_level` < 4: `ca_incr` = 1
    /// - `timing_level` >= 4: `ca_incr` = 2
    fn new(max_cwnd: usize, timing_level: u8, initial_rtt: Duration, max_rtt: Duration) -> Self {
        // Nmap timing.cc:272 - group_initial_cwnd = box(low_cwnd, max_cwnd, 10)
        // low_cwnd=1, max_cwnd=300, box() returns 10 since 1 < 10 < 300
        const GROUP_INITIAL_CWND: usize = 10;

        // Nmap timing.cc:281 - initial_ssthresh = 75
        const INITIAL_SSTHRESH: usize = 75;

        // Nmap timing.cc:276-279
        // "The congestion window grows faster with more aggressive timing."
        let ca_incr = if timing_level < 4 { 1 } else { 2 };

        Self {
            stats: std::sync::Arc::new(InternalCongestionStats::new(initial_rtt, max_rtt)),
            cwnd: std::sync::atomic::AtomicUsize::new(GROUP_INITIAL_CWND),
            ssthresh: std::sync::atomic::AtomicUsize::new(INITIAL_SSTHRESH),
            ca_ack_counter: std::sync::atomic::AtomicUsize::new(0),
            max_cwnd,
            ca_incr,
            // Initialize to 0 (before any iterations) so first timeout always triggers drop
            last_drop_iteration: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Returns current congestion window.
    fn cwnd(&self) -> usize {
        use std::sync::atomic::Ordering;
        self.cwnd.load(Ordering::Relaxed)
    }

    /// Called when a packet is sent.
    fn on_packet_sent(&self) {
        self.stats.record_sent();
    }

    /// Called when a packet is acknowledged.
    ///
    /// Uses nmap's LINEAR slow start growth (not exponential TCP Reno).
    /// From `timing.cc:224-237`:
    /// - Slow start: `cwnd += slow_incr * cc_scale * scale` (linear +1 per ACK)
    /// - Congestion avoidance: `cwnd += ca_incr / cwnd * cc_scale * scale`
    ///   which means +`ca_incr` once per cwnd ACKs (integer division)
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "cwnd values are bounded (max 300) and ca_incr is small (1-2); f64 precision and casting are safe"
    )]
    fn on_packet_acked(&self, rtt: Option<Duration>) {
        use std::sync::atomic::Ordering;

        self.stats.record_acked();
        if let Some(rtt) = rtt {
            self.stats.update_rtt(rtt);
        }

        // Get the cc_scale factor for adaptive growth when packet loss occurs
        let cc_scale = self.stats.cc_scale();

        let current_cwnd = self.cwnd.load(Ordering::Relaxed);
        let ssthresh = self.ssthresh.load(Ordering::Relaxed);

        if current_cwnd < ssthresh {
            // Nmap timing.cc:227 - cwnd += perf->slow_incr * cc_scale(perf) * scale
            // slow_incr = 1, scale = 1 (single scans use scale=1)
            // Apply cc_scale to accelerate growth when packet loss is detected
            let increment = (1.0_f64 * cc_scale).ceil() as usize;
            let new_cwnd = (current_cwnd + increment).min(self.max_cwnd);
            self.cwnd.store(new_cwnd, Ordering::Relaxed);
        } else {
            // Nmap timing.cc:237 - cwnd += perf->ca_incr / cwnd * cc_scale(perf) * scale
            // Apply cc_scale to accelerate growth when packet loss is detected
            let ack_count = self.ca_ack_counter.fetch_add(1, Ordering::Relaxed) + 1;
            // Calculate how many ACKs we need before incrementing cwnd
            // With cc_scale, we need fewer ACKs when there's packet loss
            let acks_needed = if cc_scale > 1.0 {
                // Scale down the ACK threshold when cc_scale > 1
                // This makes cwnd grow faster when packet loss is detected
                (current_cwnd as f64 / cc_scale).ceil() as usize
            } else {
                current_cwnd
            };

            if ack_count >= acks_needed {
                // Reset counter and increment cwnd by ca_incr
                self.ca_ack_counter.store(0, Ordering::Relaxed);
                // Apply cc_scale to the increment as well
                let increment = (f64::from(self.ca_incr) * cc_scale).ceil() as usize;
                let new_cwnd = (current_cwnd + increment).min(self.max_cwnd);
                self.cwnd.store(new_cwnd, Ordering::Relaxed);
            }
        }
    }

    /// Records a probe that got a reply OR timed out.
    ///
    /// This must be called when:
    /// 1. A probe receives a reply (call before `on_packet_acked`)
    /// 2. A probe times out (call when retrying or marking as filtered)
    ///
    /// See nmap `timing.h:87-91` and `scan_engine.cc:1608-1612`.
    fn record_expected(&self) {
        self.stats.record_expected();
    }

    /// Called when packet loss is detected.
    ///
    /// This implements nmap's GROUP congestion control response to packet loss
    /// from `timing.cc:drop_group()`. Group scans use less aggressive cwnd reduction
    /// than host scans to maintain reasonable parallelism.
    ///
    /// From nmap `timing.cc:258-262`:
    /// - `cwnd = MAX(low_cwnd, cwnd / group_drop_cwnd_divisor)` where divisor = 2
    /// - `ssthresh = max(in_flight / group_drop_ssthresh_divisor, 2)` where divisor varies by timing
    ///
    /// # Nmap single-host bypass
    ///
    /// In nmap, when `numIncompleteHosts < 2`, group congestion control is
    /// bypassed entirely (`scan_engine.cc:393`). Since `scan_ports` always
    /// targets a single host, we enforce a minimum cwnd floor equal to
    /// `GROUP_INITIAL_CWND` (10) to prevent cwnd collapse that would
    /// serialize probe sending.
    ///
    /// # Arguments
    ///
    /// * `current_iteration` - The current loop iteration number
    fn on_packet_lost(&self, current_iteration: usize) {
        use std::sync::atomic::Ordering;

        // Get the last drop iteration
        let last_drop = self.last_drop_iteration.load(Ordering::Relaxed);

        // Only reduce cwnd if this is a new iteration (not the same as the last drop)
        // This prevents multiple cwnd reductions in the same loop iteration
        if current_iteration <= last_drop {
            // Already reduced cwnd in this iteration - skip
            return;
        }

        let current_cwnd = self.cwnd.load(Ordering::Relaxed);
        let new_ssthresh = (current_cwnd / 2).max(2);
        // Nmap scan_engine.cc:393 - for single-host scans, group congestion
        // control is bypassed. Since scan_ports targets one host, enforce a
        // minimum cwnd of GROUP_INITIAL_CWND (10) to prevent serialization.
        const GROUP_INITIAL_CWND: usize = 10;
        let new_cwnd = (current_cwnd / 2).max(GROUP_INITIAL_CWND);

        self.ssthresh.store(new_ssthresh, Ordering::Relaxed);
        self.cwnd.store(new_cwnd, Ordering::Relaxed);

        // Update last_drop to current iteration
        self.last_drop_iteration.store(current_iteration, Ordering::Relaxed);
    }

    /// Returns recommended timeout.
    fn recommended_timeout(&self) -> Duration {
        self.stats.recommended_timeout()
    }

    /// Returns recommended timeout for first probe (clamped for Fast Scan).
    ///
    /// This is a performance optimization for Fast Scan mode where initial RTT
    /// can be too conservative (1000ms for T3). We clamp to 200ms max
    /// to avoid cascading cwnd collapse caused by premature timeouts.
    fn recommended_timeout_for_first_probe(&self) -> Duration {
        let base_timeout = self.stats.recommended_timeout();
        // For first probe, clamp to 200ms max for Fast Scan performance
        // This prevents the cascading cwnd collapse when initial RTT is too long
        base_timeout.min(Duration::from_millis(200))
    }
}
/// Ethernet header size.
const ETH_HDR_SIZE: usize = 14;

/// Default maximum number of probes to have outstanding at once.
///
/// Matches nmap's default `max_parallelism` (`timing.cc:271`):
/// `max_cwnd = MAX(low_cwnd, o.max_parallelism ? o.max_parallelism : 300)`
///
/// This is a trade-off between performance and packet loss.
/// Higher values can cause more congestion and packet drops.
pub const DEFAULT_MAX_PARALLELISM: usize = 300;

/// Maximum number of probes to send per batch before waiting for responses.
///
/// This matches nmap's batch limit from `scan_engine.cc:326-327`:
/// ```cpp
/// // Limit sends between waits to avoid overflowing pcap buffer
/// recentsends = USI->gstats->probes_sent - USI->gstats->probes_sent_at_last_wait;
/// if (recentsends >= 50)
///     return false;
/// ```
///
/// This is critical for performance because:
/// 1. Prevents pcap buffer overflow
/// 2. Ensures regular response processing
/// 3. Improves congestion control responsiveness
const BATCH_SIZE: usize = 50;

/// Default timeout for the entire scan operation.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(300);

/// Source port range for outbound probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// Ethernet header size for `AF_PACKET`.
const ETH_HEADER_SIZE: usize = 14;

/// ICMP Type 3 - Destination Unreachable.
const ICMP_TYPE_DEST_UNREACH: u8 = 3;
/// ICMP Code 3 - Port Unreachable.
const ICMP_CODE_PORT_UNREACH: u8 = 3;

/// Information about a UDP probe that has been sent but not yet responded to.
#[derive(Debug, Clone)]
struct UdpOutstandingProbe {
    /// Target IP address.
    target: Ipv4Addr,
    /// Target port number.
    port: Port,
    /// Our source port.
    src_port: Port,
    /// When this probe was sent.
    sent_time: Instant,
    /// Number of retry attempts.
    retry_count: u32,
}

/// Parsed ICMP response information.
#[derive(Debug, Clone)]
struct IcmpResponse {
    /// Original destination IP (the target we probed).
    orig_dst_ip: Ipv4Addr,
    /// Original destination port (the port we probed).
    orig_dst_port: Port,
    /// ICMP type (3 = Destination Unreachable).
    icmp_type: u8,
    /// ICMP code (3 = Port Unreachable).
    icmp_code: u8,
}

impl IcmpResponse {
    /// Determines the port state from ICMP type and code.
    #[must_use]
    const fn port_state(&self) -> PortState {
        if self.icmp_type == ICMP_TYPE_DEST_UNREACH && self.icmp_code == ICMP_CODE_PORT_UNREACH {
            PortState::Closed
        } else {
            // Other ICMP types (filtered, admin prohibited, etc.)
            PortState::Filtered
        }
    }
}

/// Information about a probe that has been sent but not yet responded to.
#[derive(Debug, Clone)]
struct OutstandingProbe {
    /// Target IP address.
    target: Ipv4Addr,
    /// Target port number.
    port: Port,
    /// Our TCP sequence number.
    seq: u32,
    /// Our source port.
    src_port: Port,
    /// When this probe was sent.
    sent_time: Instant,
    /// Number of retry attempts.
    retry_count: u32,
}

/// A received packet with parsed TCP information.
///
/// This contains the raw parsed data from a received TCP packet.
/// The source port in the response is the destination port we probed.
#[derive(Debug, Clone)]
struct ReceivedPacket {
    /// Source IP of the response (our target).
    src_ip: Ipv4Addr,
    /// Source port of the response (the port we probed).
    src_port: Port,
    /// TCP flags from the response.
    flags: u8,
    /// Sequence number from the response (available for debugging via `seq()`).
    seq: u32,
    /// ACK number from the response.
    ack: u32,
}

impl ReceivedPacket {
    /// Creates a new received packet.
    #[must_use]
    const fn new(src_ip: Ipv4Addr, src_port: Port, flags: u8, seq: u32, ack: u32) -> Self {
        Self {
            src_ip,
            src_port,
            flags,
            seq,
            ack,
        }
    }

    /// Returns the sequence number from the response.
    ///
    /// This is primarily used for debugging and validation purposes.
    #[must_use]
    const fn seq(&self) -> u32 {
        self.seq
    }

    /// Determines the port state from TCP flags.
    #[must_use]
    fn port_state(&self) -> PortState {
        let syn_received = (self.flags & 0x02) != 0;
        let ack_received = (self.flags & 0x10) != 0;
        let rst_received = (self.flags & 0x04) != 0;

        if syn_received && ack_received {
            PortState::Open
        } else if rst_received {
            PortState::Closed
        } else {
            PortState::Filtered
        }
    }
}

/// High-performance parallel scanning engine.
///
/// This engine implements Nmap's `UltraScan` architecture, sending multiple
/// probes concurrently and processing responses asynchronously.
///
/// # Architecture
///
/// 1. **Batch Sending**: Sends multiple probes without waiting for responses
/// 2. **Async Receiving**: Background task continuously receives packets
/// 3. **Response Matching**: Correlates responses to outstanding probes
/// 4. **Timeout Handling**: Retries or times out probes that don't respond
/// 5. **Congestion Control**: TCP-like adaptive timeout and parallelism
/// 6. **Rate Limiting**: Min/max rate enforcement for bandwidth control
///
/// # Performance
///
/// For scanning 100 ports:
/// - Sequential: ~100 seconds (1 second per port)
/// - Parallel: ~3-5 seconds (20-30x faster)
#[derive(Debug)]
pub struct ParallelScanEngine {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: StdArc<RawSocket>,
    /// Packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Scanner configuration for timing parameters.
    config: ScanConfig,
    /// Congestion controller for adaptive timing.
    congestion: Arc<InternalCongestionController>,
    /// Rate limiter for min/max rate enforcement.
    rate_limiter: RateLimiter,
    /// Maximum parallelism (max outstanding probes).
    max_parallelism: usize,
    /// Timeout for the entire scan.
    scan_timeout: Duration,
    /// Tracks when the last probe was sent for enforcing `scan_delay`.
    ///
    /// This implements nmap's `enforce_scan_delay()` from `timing.cc:172-206`.
    /// The scan delay is a minimum time that must elapse between sending probes,
    /// independent of rate limiting.
    /// Tracks when the last probe was sent for enforcing `scan_delay`.
    ///
    /// This implements nmap's `enforce_scan_delay()` from `timing.cc:172-206`.
    /// The scan delay is a minimum time that must elapse between sending probes,
    /// independent of rate limiting.
    ///
    /// `None` means no probe has been sent yet (first call should not delay).
    last_probe_send_time: Arc<Mutex<Option<Instant>>>,
}

impl ParallelScanEngine {
    /// Creates a new parallel scan engine.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A new `ParallelScanEngine` instance, or an error if raw socket creation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(
        local_addr: Ipv4Addr,
        config: ScanConfig,
    ) -> Result<Self, rustnmap_common::ScanError> {
        let socket = StdArc::new(
            // Use IPPROTO_RAW to receive all IP packets, not just TCP.
            // This prevents kernel TCP stack from interfering with packet reception.
            // We manually filter for TCP responses in parse_packet().
            RawSocket::with_protocol(255).map_err(|e| {
                rustnmap_common::ScanError::PermissionDenied {
                    operation: format!("create raw socket: {e}"),
                }
            })?,
        );

        // Create ScannerPacketEngine for zero-copy packet capture using PACKET_MMAP V2.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        let max_parallel = DEFAULT_MAX_PARALLELISM;

        // Create internal congestion controller for adaptive timing
        // Uses timing_level from config to set ca_incr (T4/T5 use ca_incr=2)
        let congestion = Arc::new(InternalCongestionController::new(
            max_parallel,
            config.timing_level,
            config.initial_rtt,
            config.max_rtt,
        ));

        // Create rate limiter for min/max rate enforcement
        let rate_limiter = RateLimiter::new(config.min_rate, config.max_rate);

        // Initialize last probe send time to now so the first probe respects scan_delay.
        // This is important when the engine is created after host discovery - we want
        // the first port probe to wait for scan_delay after the discovery phase.
        // See nmap's behavior where scan_delay is enforced after host discovery probes.
        let last_probe_send_time = Arc::new(Mutex::new(Some(Instant::now())));

        Ok(Self {
            local_addr,
            socket,
            packet_engine,
            config,
            congestion,
            rate_limiter,
            max_parallelism: max_parallel,
            scan_timeout: DEFAULT_SCAN_TIMEOUT,
            last_probe_send_time,
        })
    }

    /// Creates an `AF_PACKET` socket for TCP response capture.
    ///
    /// This is critical for receiving TCP RST responses that raw socket misses.
    /// The socket captures at L2 (data link layer) like libpcap, ensuring all
    /// Sets the maximum parallelism.
    ///
    /// # Arguments
    ///
    /// * `value` - Maximum number of probes to have outstanding
    #[must_use]
    pub fn with_max_parallelism(mut self, value: usize) -> Self {
        self.max_parallelism = value;
        // Recreate congestion controller with new max and existing timing_level
        self.congestion = Arc::new(InternalCongestionController::new(
            value,
            self.config.timing_level,
            self.config.initial_rtt,
            self.config.max_rtt,
        ));
        self
    }

    /// Returns the adaptive probe timeout based on current network conditions.
    ///
    /// Uses the congestion controller's recommended timeout which is calculated
    /// as: SRTT + 4 * RTTVAR (RFC 2988 formula).
    #[must_use]
    pub fn adaptive_probe_timeout(&self) -> Duration {
        self.congestion.recommended_timeout()
    }

    /// Returns the current congestion window (adaptive parallelism).
    #[must_use]
    pub fn current_cwnd(&self) -> usize {
        self.congestion.cwnd()
    }

    /// Returns a reference to the congestion controller.
    #[must_use]
    pub fn congestion(&self) -> &InternalCongestionController {
        &self.congestion
    }

    /// Enforces the `scan_delay` between probes.
    ///
    /// This implements nmap's `enforce_scan_delay()` from `timing.cc:172-206`.
    /// The scan delay is a minimum time that must elapse between sending probes,
    /// independent of rate limiting.
    ///
    /// If the time elapsed since the last probe is less than `scan_delay`,
    /// this method sleeps for the remaining time.
    ///
    /// # Behavior
    ///
    /// - First call: Returns immediately (no delay), like nmap's `init == -1` check
    /// - Subsequent calls: Enforces `scan_delay` between probes
    async fn enforce_scan_delay(&self) {
        let scan_delay = self.config.scan_delay;
        if scan_delay == Duration::ZERO {
            return;
        }

        // Calculate time since last probe
        let elapsed = {
            let last_opt = *self.last_probe_send_time.lock().await;
            match last_opt {
                None => {
                    // First call - initialize and return immediately
                    // See nmap timing.cc:183-188
                    *self.last_probe_send_time.lock().await = Some(Instant::now());
                    return;
                }
                Some(last) => last.elapsed(),
            }
        };

        if elapsed < scan_delay {
            // Sleep for remaining time
            let remaining = scan_delay - elapsed;
            tokio::time::sleep(remaining).await;
        }

        // Update last probe send time to now
        *self.last_probe_send_time.lock().await = Some(Instant::now());
    }

    /// Scans multiple ports on a target in parallel.
    ///
    /// This is the main entry point for parallel scanning. It sends all probes
    /// in batches and processes responses asynchronously.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `ports` - Port numbers to scan
    ///
    /// # Returns
    ///
    /// A map of port numbers to their states, or an error if scanning fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet transmission fails
    /// - The scan timeout expires
    /// - Response processing fails
    #[expect(
        clippy::too_many_lines,
        reason = "Port scanning requires handling send, receive, timeout, and result collection in one method"
    )]
    pub async fn scan_ports(
        &self,
        target: Ipv4Addr,
        ports: &[Port],
    ) -> Result<HashMap<Port, PortState>, rustnmap_common::ScanError> {
        let start_time = Instant::now();

        // Channel for received packets from the receiver task
        let (packet_tx, mut packet_rx) = mpsc::unbounded_channel();

        // Clone the sender for the receiver task
        // We'll keep the original and drop it when done to signal completion
        let receiver_handle = self.start_receiver_task(packet_tx.clone());

        // Store packet_tx for later drop - when dropped, receiver will detect closure

        // Outstanding probes: (target, port) -> probe info
        let mut outstanding: HashMap<(Ipv4Addr, Port), OutstandingProbe> = HashMap::new();
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let mut ports_iter = ports.iter().copied().peekable();
        let mut retry_probes: Vec<OutstandingProbe> = Vec::new();

        // Track probes sent in current batch (nmap batch limit: 50)
        // See scan_engine.cc:326-327
        let mut probes_sent_this_batch: usize = 0;

        // Adaptive retry tracking (nmap scan_engine.cc:675-683)
        // max_successful_tryno: highest retry count that received a response
        // allowedTryno = MAX(1, max_successful_tryno + 1), capped by config.max_retries
        // This prevents wasting time retrying filtered ports 10 times when all
        // responsive ports answered on the first try.
        let mut max_successful_tryno: u32 = 0;

        #[cfg(feature = "diagnostic")]
        let mut total_send_time = Duration::ZERO;
        #[cfg(feature = "diagnostic")]
        let mut total_wait_time = Duration::ZERO;
        // Track loop iterations for congestion control (needed for on_packet_lost)
        let mut loop_iterations: usize = 0;
        #[cfg(feature = "diagnostic")]
        let mut packets_received = 0;

        // Temporary timing instrumentation (only when diagnostic feature is enabled)
        #[cfg(feature = "diagnostic")]
        let mut diag_send_total = Duration::ZERO;
        #[cfg(feature = "diagnostic")]
        let mut diag_wait_total = Duration::ZERO;
        #[cfg(feature = "diagnostic")]
        let mut diag_timeout_total = Duration::ZERO;
        #[cfg(feature = "diagnostic")]
        let mut diag_retry_total = Duration::ZERO;
        #[cfg(feature = "diagnostic")]
        let mut diag_total_sent: usize = 0;
        #[cfg(feature = "diagnostic")]
        let mut diag_total_retries: usize = 0;
        #[cfg(feature = "diagnostic")]
        let mut diag_total_timeouts: usize = 0;

        // Main scan loop
        while ports_iter.peek().is_some() || !outstanding.is_empty() {
            loop_iterations += 1;

            // Get adaptive parallelism from congestion controller
            let current_cwnd = self.congestion.cwnd();

            #[cfg(feature = "diagnostic")]
            if loop_iterations <= 5 || loop_iterations % 100 == 0 {
                let timeout = self.congestion.recommended_timeout();
                eprintln!(
                    "[DIAG] iter={loop_iterations} cwnd={current_cwnd} outstanding={} ports_left={} timeout={}ms elapsed={}ms",
                    outstanding.len(),
                    ports_iter.size_hint().0,
                    timeout.as_millis(),
                    start_time.elapsed().as_millis(),
                );
            }

            #[cfg(feature = "diagnostic")]
            if loop_iterations == 1 || loop_iterations % 50 == 0 {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/rustnmap_diagnostic.txt")
                {
                    let _ = writeln!(
                        file,
                        "Iteration {}: cwnd={}, outstanding={}, ports_left={}",
                        loop_iterations,
                        current_cwnd,
                        outstanding.len(),
                        if ports_iter.peek().is_some() { "yes" } else { "no" }
                    );
                }
            }
            // Check for scan timeout
            if start_time.elapsed() > self.scan_timeout {
                // Time out remaining outstanding probes
                for probe in outstanding.values() {
                    results.entry(probe.port).or_insert(PortState::Filtered);
                }
                break;
            }

            // Get adaptive parallelism from congestion controller
            let current_cwnd = self.congestion.cwnd();

            #[cfg(feature = "diagnostic")]
            if loop_iterations == 1 || loop_iterations % 50 == 0 {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/rustnmap_diagnostic.txt")
                {
                    let _ = writeln!(
                        file,
                        "Iteration {}: cwnd={}, outstanding={}, ports_left={}",
                        loop_iterations,
                        current_cwnd,
                        outstanding.len(),
                        ports_iter.peek().map(|_| "yes").unwrap_or("no")
                    );
                }
            }

            #[cfg(feature = "diagnostic")]
            let send_start = Instant::now();

            #[cfg(feature = "diagnostic")]
            let diag_send_start = Instant::now();
            #[cfg(feature = "diagnostic")]
            let diag_sent_before = diag_total_sent;

            // Send more probes if we haven't reached congestion window
            // AND we haven't reached the batch limit (nmap: 50 probes per batch)
            while outstanding.len() < current_cwnd
                && outstanding.len() < self.max_parallelism
                && probes_sent_this_batch < BATCH_SIZE
            {
                // Check rate limiter before sending
                if let Some(wait_time) = self.rate_limiter.check_rate() {
                    // Wait for rate limit
                    tokio::time::sleep(wait_time).await;
                    // Re-check parallelism after waiting
                    if outstanding.len() >= current_cwnd
                        || outstanding.len() >= self.max_parallelism
                        || probes_sent_this_batch >= BATCH_SIZE
                    {
                        break;
                    }
                }

                if let Some(port) = ports_iter.next() {
                    // Enforce scan_delay before sending each probe
                    // This implements nmap's enforce_scan_delay() from timing.cc:172-206
                    self.enforce_scan_delay().await;
                    self.send_probe(target, port, &mut outstanding)?;
                    // Record packet sent for congestion stats and rate limiting
                    self.congestion.on_packet_sent();
                    self.rate_limiter.record_sent();
                    probes_sent_this_batch += 1;
                    #[cfg(feature = "diagnostic")]
                    {
                        diag_total_sent += 1;
                    }
                } else {
                    break;
                }
            }

            #[cfg(feature = "diagnostic")]
            {
                total_send_time += send_start.elapsed();
                diag_send_total += diag_send_start.elapsed();
            }

            // Wait for packets and drain all available responses (nmap waitForResponses pattern)
            // Calculate optimal wait time:
            // - If we have more ports to send, use short wait (send more probes soon)
            // - If all probes sent, wait until the earliest probe timeout
            let has_more_ports = ports_iter.peek().is_some();
            let probe_timeout = self.congestion.recommended_timeout();

            // Find the earliest timeout among outstanding probes
            let earliest_timeout = outstanding
                .values()
                .map(|p| {
                    let elapsed = p.sent_time.elapsed();
                    if elapsed >= probe_timeout {
                        Duration::ZERO // Already timed out
                    } else {
                        probe_timeout - elapsed
                    }
                })
                .min()
                .unwrap_or(Duration::from_millis(100));

            let initial_wait = if has_more_ports {
                // Still have ports to scan - use short wait to send more probes
                // Reduced from 10ms to 1ms for faster polling
                Duration::from_millis(1)
            } else if !outstanding.is_empty() {
                // All probes sent, wait for earliest timeout (but not longer than 100ms per iteration)
                earliest_timeout.min(Duration::from_millis(100))
            } else {
                // No outstanding probes - short wait
                Duration::from_millis(1)
            };
            let mut wait_duration = initial_wait;

            #[cfg(feature = "diagnostic")]
            let wait_start = Instant::now();
            #[cfg(feature = "diagnostic")]
            let diag_wait_start = Instant::now();

            let wait_phase_start = Instant::now(); // Track total time in this wait phase

            loop {
                // nmap's 200ms upper limit: even if packets keep arriving, return after 200ms
                // See scan_engine_raw.cc:1626 - prevents infinite waiting
                if wait_phase_start.elapsed() > Duration::from_millis(200) {
                    break;
                }

                match tokio_timeout(wait_duration, packet_rx.recv()).await {
                    Ok(Some(packet)) => {
                        #[cfg(feature = "diagnostic")]
                        {
                            packets_received += 1;
                        }
                        // Match the packet to an outstanding probe
                        let probe_key = (packet.src_ip, packet.src_port);
                        if let Some(probe) = outstanding.remove(&probe_key) {
                            // For SYN-ACK responses, verify the ACK matches our sequence number.
                            // For RST responses, seq is typically 0 -- only validate ACK.
                            let expected_ack = probe.seq.wrapping_add(1);
                            let rst_received = (packet.flags & 0x04) != 0;
                            let valid_response = if rst_received {
                                // RST packets: accept if ACK matches (seq may be 0)
                                packet.ack == expected_ack
                            } else {
                                // SYN-ACK and other responses: validate both ACK and non-zero seq
                                packet.ack == expected_ack && packet.seq() != 0
                            };
                            if valid_response {
                                // Calculate RTT for this probe
                                let rtt = probe.sent_time.elapsed();
                                // Track highest successful retry count (nmap allowedTryno)
                                if probe.retry_count > max_successful_tryno {
                                    max_successful_tryno = probe.retry_count;
                                }
                                // Record that we expected a reply (got one!)
                                // See nmap scan_engine.cc:1608-1612 (ultrascan_adjust_timing)
                                self.congestion.record_expected();
                                // Record successful response with RTT for congestion control
                                self.congestion.on_packet_acked(Some(rtt));
                                results.insert(packet.src_port, packet.port_state());
                            } else {
                                // Unexpected ACK or invalid seq - put the probe back
                                outstanding.insert(probe_key, probe);
                            }
                        }
                        // If we can't find a matching probe, this packet is unrelated traffic - ignore

                        // Keep short timeout for draining remaining packets (nmap uses 2ms)
                        // This is critical for performance - don't increase to 10ms!
                        wait_duration = Duration::from_millis(1);
                    }
                    Ok(None) => {
                        // Channel closed, receiver task ended
                        break;
                    }
                    Err(_) => {
                        // Timeout - no more packets available
                        break;
                    }
                }
            }

            #[cfg(feature = "diagnostic")]
            {
                total_wait_time += wait_start.elapsed();
                diag_wait_total += diag_wait_start.elapsed();
            }

            // Check for probe timeouts and handle retries
            #[cfg(feature = "diagnostic")]
            let diag_timeout_start = Instant::now();
            #[cfg(feature = "diagnostic")]
            let diag_outstanding_before = outstanding.len();
            self.check_timeouts(&mut outstanding, &mut retry_probes, &mut results, loop_iterations, max_successful_tryno);
            #[cfg(feature = "diagnostic")]
            {
                let diag_timed_out = diag_outstanding_before - outstanding.len();
                diag_total_timeouts += diag_timed_out;
                diag_timeout_total += diag_timeout_start.elapsed();
            }

            // Reset batch counter only after sending a full batch and draining responses
            // This matches nmap's behavior: reset after waitForResponses() when batch is complete
            if probes_sent_this_batch >= BATCH_SIZE {
                probes_sent_this_batch = 0;
            }

            // Re-send retry probes
            // Note: Retry probes are NOT limited by cwnd because they already timed out
            // and need to be retried to reach max_retries. This matches nmap's behavior.
            // Only max_parallelism limits retry probes to prevent resource exhaustion.
            #[cfg(feature = "diagnostic")]
            let diag_retry_start = Instant::now();
            for probe in retry_probes.drain(..) {
                if outstanding.len() < self.max_parallelism {
                    // Check rate limiter before resending
                    if let Some(wait_time) = self.rate_limiter.check_rate() {
                        tokio::time::sleep(wait_time).await;
                    }
                    self.resend_probe(probe, &mut outstanding)?;
                    self.rate_limiter.record_sent();
                    #[cfg(feature = "diagnostic")]
                    {
                        diag_total_retries += 1;
                    }
                } else {
                    // Can't resend due to parallelism limit, mark as filtered
                    results.entry(probe.port).or_insert(PortState::Filtered);
                }
            }
            #[cfg(feature = "diagnostic")]
            {
                diag_retry_total += diag_retry_start.elapsed();
            }
        }

        // Print diagnostic summary
        #[cfg(feature = "diagnostic")]
        {
            let total_time = start_time.elapsed();
            eprintln!("\n=== SCAN TIMING DIAGNOSTIC ===");
            eprintln!("Total: {total_time:?}");
            eprintln!("Send:    {diag_send_total:?} (sent {diag_total_sent} probes)");
            eprintln!("Wait:    {diag_wait_total:?}");
            eprintln!("Timeout: {diag_timeout_total:?} ({diag_total_timeouts} timed out)");
            eprintln!("Retry:   {diag_retry_total:?} ({diag_total_retries} retries)");
            eprintln!("Iterations: {loop_iterations}");
            eprintln!("Results: {} ports", results.len());
            eprintln!("==============================\n");
        }

        // Explicitly drop the sender to signal the receiver task to stop
        drop(packet_tx);

        // Wait for receiver task to complete with timeout
        // Use a short timeout since the receiver should exit quickly when channel is closed
        let _ = tokio::time::timeout(Duration::from_millis(200), receiver_handle).await;

        #[cfg(feature = "diagnostic")]
        {
            use std::io::Write;
            let total_time = start_time.elapsed();
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rustnmap_diagnostic.txt")
            {
                let _ = writeln!(file, "\n=== TCP SYN Scan Timing ===");
                let _ = writeln!(file, "Total: {:?}", total_time);
                let _ = writeln!(
                    file,
                    "Send: {:?} ({:.1}%)",
                    total_send_time,
                    (total_send_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0
                );
                let _ = writeln!(
                    file,
                    "Wait: {:?} ({:.1}%)",
                    total_wait_time,
                    (total_wait_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0
                );
                let _ = writeln!(file, "Iterations: {}", loop_iterations);
                let _ = writeln!(file, "Packets: {}", packets_received);
            }
        }

        Ok(results)
    }

    /// Starts the background receiver task.
    ///
    /// This task continuously receives packets using `ScannerPacketEngine` for zero-copy
    /// `PACKET_MMAP` V2 capture. Falls back to raw socket if packet engine is not available.
    fn start_receiver_task(
        &self,
        packet_tx: mpsc::UnboundedSender<ReceivedPacket>,
    ) -> JoinHandle<()> {
        const MAX_BATCH: usize = 32;
        let socket = StdArc::clone(&self.socket);
        let packet_engine = self.packet_engine.clone();
        tokio::spawn(async move {
            loop {
                // Check if channel is closed before blocking on recv
                if packet_tx.is_closed() {
                    break;
                }

                // Try ScannerPacketEngine first (zero-copy `PACKET_MMAP` V2)
                // Fall back to raw socket if packet engine is not available
                if let Some(ref engine) = packet_engine {
                    // Use ScannerPacketEngine for zero-copy capture
                    let engine = Arc::clone(engine);
                    let tx_clone = packet_tx.clone();

                    // Start the packet engine - ignore AlreadyStarted error
                    let _ = engine.lock().await.start().await;

                    // Process packets in a batch
                    let mut batch_count = 0;

                    while batch_count < MAX_BATCH {
                        // Check if channel is still open
                        if tx_clone.is_closed() {
                            break;
                        }

                        // Lock the engine and receive with timeout
                        match engine
                            .lock()
                            .await
                            .recv_with_timeout(Duration::from_millis(100))
                            .await
                        {
                            Ok(Some(data)) => {
                                // Parse packet (handles Ethernet header internally)
                                if let Some(packet) = Self::parse_packet(&data) {
                                    if tx_clone.send(packet).is_err() {
                                        break;
                                    }
                                }
                                batch_count += 1;
                            }
                            Ok(None) => {
                                // Timeout, continue
                                break;
                            }
                            Err(_) => {
                                // Error, break and let outer loop handle it
                                break;
                            }
                        }
                    }

                    // Yield if no packets were received
                    if batch_count == 0 {
                        tokio::task::yield_now().await;
                    }
                } else {
                    // Fall back to raw socket (L3 capture - may miss some TCP responses)
                    let socket_clone = StdArc::clone(&socket);
                    let tx_clone = packet_tx.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let mut recv_buf = vec![0u8; 65535];
                        match socket_clone
                            .recv_packet(&mut recv_buf, Some(Duration::from_millis(50)))
                        {
                            Ok(len) => Ok((len, recv_buf)),
                            Err(e) => Err(e),
                        }
                    })
                    .await;

                    match result {
                        Ok(Ok((len, recv_buf))) if len > 0 => {
                            // Raw socket path: parse packet from buffer
                            if let Some(packet) = Self::parse_packet(&recv_buf[..len]) {
                                if tx_clone.send(packet).is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Fatal error or task was cancelled, stop receiving
                            break;
                        }
                        _ => {
                            // Timeout or no data, yield and continue
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
        })
    }

    /// Parses a received packet into a `ReceivedPacket`.
    ///
    /// Returns `None` if the packet cannot be parsed as a TCP packet.
    fn parse_packet(data: &[u8]) -> Option<ReceivedPacket> {
        // Skip Ethernet header (14 bytes) to get to IP header
        let ip_data = if data.len() > ETH_HDR_SIZE {
            &data[ETH_HDR_SIZE..]
        } else {
            return None;
        };

        if let Some((flags, seq, ack, src_port, _dst_port, src_ip)) = parse_tcp_response(ip_data) {
            Some(ReceivedPacket::new(src_ip, src_port, flags, seq, ack))
        } else {
            None
        }
    }

    /// Sends a single SYN probe to the target.
    fn send_probe(
        &self,
        target: Ipv4Addr,
        port: Port,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
    ) -> Result<(), rustnmap_common::ScanError> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP SYN packet
        let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, port)
            .seq(seq)
            .syn()
            .window(65_535)
            .build();

        // Send the packet
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(target), port);
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        // Track the outstanding probe
        outstanding.insert(
            (target, port),
            OutstandingProbe {
                target,
                port,
                seq,
                src_port,
                sent_time: Instant::now(),
                retry_count: 0,
            },
        );

        Ok(())
    }

    /// Re-sends a probe (for retries).
    fn resend_probe(
        &self,
        mut probe: OutstandingProbe,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
    ) -> Result<(), rustnmap_common::ScanError> {
        probe.retry_count += 1;
        probe.sent_time = Instant::now();

        // Rebuild and resend the packet
        let packet =
            TcpPacketBuilder::new(self.local_addr, probe.target, probe.src_port, probe.port)
                .seq(probe.seq)
                .syn()
                .window(65_535)
                .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(probe.target), probe.port);
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        outstanding.insert((probe.target, probe.port), probe);
        Ok(())
    }

    /// Checks for timed-out probes and handles retries.
    ///
    /// Uses adaptive timeout from congestion controller based on SRTT + 4*RTTVAR.
    /// Records packet loss for congestion control when timeouts occur.
    ///
    /// # Arguments
    ///
    /// * `outstanding` - Outstanding probes to check
    /// * `retry_probes` - Vector to collect probes that need retrying
    /// * `results` - Results map to update
    /// * `current_iteration` - Current loop iteration (for congestion control drop tracking)
    /// * `max_successful_tryno` - Highest retry count that received a response
    fn check_timeouts(
        &self,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
        retry_probes: &mut Vec<OutstandingProbe>,
        results: &mut HashMap<Port, PortState>,
        current_iteration: usize,
        max_successful_tryno: u32,
    ) {
        let now = Instant::now();
        // Adaptive retry limit (nmap scan_engine.cc:675-683)
        // allowedTryno = MAX(1, max_successful_tryno + 1), capped by config.max_retries
        // This prevents wasting time on filtered ports when responsive ports
        // answered on the first try.
        let tryno_cap = u32::from(self.config.max_retries);
        let allowed_tryno = 1_u32.max(max_successful_tryno + 1).min(tryno_cap);

        // Get adaptive probe timeout from congestion controller
        let probe_timeout = self.congestion.recommended_timeout();

        // Collect timed-out probes
        let timed_out: Vec<_> = outstanding
            .iter()
            .filter(|(_, p)| now.duration_since(p.sent_time) >= probe_timeout)
            .map(|(k, p)| (*k, p.clone()))
            .collect();

        for (key, probe) in timed_out {
            // Record that we expected a reply (probe timed out without response)
            self.congestion.record_expected();

            if probe.retry_count < allowed_tryno {
                // Retry the probe
                outstanding.remove(&key);
                retry_probes.push(probe);
                // Record packet loss for congestion control
                self.congestion.on_packet_lost(current_iteration);
            } else {
                // Adaptive retry limit reached, mark as filtered
                outstanding.remove(&key);
                results.entry(probe.port).or_insert(PortState::Filtered);
                // Record packet loss for congestion control
                self.congestion.on_packet_lost(current_iteration);
            }
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        let offset = (std::process::id() % 1000) as u16;
        SOURCE_PORT_START + offset
    }

    /// Generates a random initial sequence number.
    #[must_use]
    fn generate_sequence_number() -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Lower bits provide sufficient entropy"
        )]
        let now_lower = now as u32;
        let pid = std::process::id();
        now_lower.wrapping_add(pid)
    }

    // ========================================================================
    // UDP Parallel Scanning
    // ========================================================================

    /// Scans multiple UDP ports on a target in parallel.
    ///
    /// This implements nmap's `ultra_scan` architecture for UDP scanning:
    /// - Sends multiple UDP probes concurrently (up to cwnd limit)
    /// - Waits for ICMP Port Unreachable responses in unified receive loop
    /// - Handles retransmissions for timed-out probes
    /// - Uses adaptive timing based on RTT measurements
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `ports` - UDP port numbers to scan
    ///
    /// # Returns
    ///
    /// A map of port numbers to their states, or an error if scanning fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet transmission fails
    /// - The scan timeout expires
    #[expect(
        clippy::too_many_lines,
        reason = "UDP parallel scanning requires send, receive, timeout, and result collection"
    )]
    pub async fn scan_udp_ports(
        &self,
        target: Ipv4Addr,
        ports: &[Port],
    ) -> Result<HashMap<Port, PortState>, rustnmap_common::ScanError> {
        let start_time = Instant::now();

        // Create dedicated packet engine with ICMP BPF filter BEFORE starting receiver
        // This ensures the filter is applied before any packets can arrive
        let scanner_engine = create_stealth_engine(Some(self.local_addr), self.config.clone());

        if let Some(ref engine) = scanner_engine {
            // Enable BPF filter to capture only ICMP packets destined to local IP
            // This prevents kernel buffer overflow under network load
            let filter = BpfFilter::icmp_dst(u32::from(self.local_addr));
            let _ = engine.lock().await.set_filter(&filter);

            // Start the packet engine
            let _ = engine.lock().await.start().await;
        }

        // Channel for received ICMP responses
        let (icmp_tx, mut icmp_rx) = mpsc::unbounded_channel();

        // Ready signal to ensure receiver is polling before we send probes
        let (ready_tx, ready_rx) = oneshot::channel();

        // Start ICMP receiver task with packet engine
        let receiver_handle =
            self.start_icmp_receiver_task(scanner_engine, icmp_tx.clone(), ready_tx);

        // Wait for receiver to be ready (with timeout to prevent deadlock)
        if tokio::time::timeout(Duration::from_millis(200), ready_rx)
            .await
            .is_err()
        {
            // Timeout waiting for receiver - log warning but continue
            // The receiver might still work, just took too long to signal ready
        }

        // REMOVED: The 10ms delay was unnecessary for PACKET_MMAP V2.
        // The receiver is already signaled ready via the channel above.

        // Outstanding UDP probes: (target, port) -> probe info
        let mut outstanding: HashMap<(Ipv4Addr, Port), UdpOutstandingProbe> = HashMap::new();
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let mut ports_iter = ports.iter().copied().peekable();
        let mut retry_probes: Vec<UdpOutstandingProbe> = Vec::new();

        // Track probes sent in current batch
        let mut probes_sent_this_batch: usize = 0;

        // Track loop iterations for congestion control (needed for on_packet_lost)
        let mut loop_iterations: usize = 0;

        // Main scan loop - follows nmap ultra_scan pattern
        while ports_iter.peek().is_some() || !outstanding.is_empty() {
            loop_iterations += 1;
            // Check for scan timeout
            if start_time.elapsed() > self.scan_timeout {
                // Mark remaining probes as open|filtered
                for probe in outstanding.values() {
                    results
                        .entry(probe.port)
                        .or_insert(PortState::OpenOrFiltered);
                }
                break;
            }

            // Get adaptive parallelism
            let current_cwnd = self.congestion.cwnd();

            // Send more probes if within limits
            while outstanding.len() < current_cwnd
                && outstanding.len() < self.max_parallelism
                && probes_sent_this_batch < BATCH_SIZE
            {
                // Check rate limiter
                if let Some(wait_time) = self.rate_limiter.check_rate() {
                    tokio::time::sleep(wait_time).await;
                    if outstanding.len() >= current_cwnd
                        || outstanding.len() >= self.max_parallelism
                        || probes_sent_this_batch >= BATCH_SIZE
                    {
                        break;
                    }
                }

                if let Some(port) = ports_iter.next() {
                    // Enforce scan_delay before sending each probe
                    // This implements nmap's enforce_scan_delay() from timing.cc:172-206
                    // Note: For T4/T5, scan_delay is 0ms by default
                    // AdaptiveDelay will dynamically increase delay if packet loss is detected
                    self.enforce_scan_delay().await;
                    self.send_udp_probe(target, port, &mut outstanding)?;
                    self.congestion.on_packet_sent();
                    self.rate_limiter.record_sent();
                    probes_sent_this_batch += 1;

                    // REMOVED: Fixed 50ms sleep was incorrect nmap interpretation
                    // Nmap's 50ms is for boostScanDelay() which is only called when
                    // packet loss is detected (see timing.cc:1900-1906), NOT after
                    // every probe. The enforce_scan_delay() above correctly handles
                    // timing using config.scan_delay (0ms for T4/T5) and
                    // AdaptiveDelay for dynamic adjustment on packet loss.
                } else {
                    break;
                }
            }

            // Wait for ICMP responses (unified wait - nmap pattern)
            let has_more_ports = ports_iter.peek().is_some();
            let probe_timeout = self.congestion.recommended_timeout();

            // Calculate earliest timeout for debugging/monitoring purposes
            // This represents when the first outstanding probe will timeout
            let _earliest_timeout = outstanding
                .values()
                .map(|p| {
                    let elapsed = p.sent_time.elapsed();
                    if elapsed >= probe_timeout {
                        Duration::ZERO
                    } else {
                        probe_timeout - elapsed
                    }
                })
                .min()
                .unwrap_or(Duration::from_millis(100));

            // Timing-aware wait: use very short initial wait, then let drain loop handle it
            // ICMP responses typically arrive in 20-100ms, but polling with short intervals
            // is more efficient than long waits
            let initial_wait = if has_more_ports {
                // Sending more probes - use short wait to stay responsive
                Duration::from_millis(10)
            } else if !outstanding.is_empty() {
                // All probes sent - use short poll, drain loop will extend as needed
                Duration::from_millis(10)
            } else {
                Duration::ZERO
            };
            let mut wait_duration = initial_wait;

            // Drain all available ICMP responses
            loop {
                match tokio_timeout(wait_duration, icmp_rx.recv()).await {
                    Ok(Some(icmp_resp)) => {
                        // Match ICMP response to outstanding probe
                        let probe_key = (icmp_resp.orig_dst_ip, icmp_resp.orig_dst_port);
                        if let Some(probe) = outstanding.remove(&probe_key) {
                            // Calculate RTT
                            let rtt = probe.sent_time.elapsed();
                            self.congestion.record_expected();
                            self.congestion.on_packet_acked(Some(rtt));
                            results.insert(probe.port, icmp_resp.port_state());
                        }
                        // Continue draining with short timeout
                        wait_duration = Duration::from_millis(10);
                    }
                    Ok(None) => {
                        // Channel closed
                        break;
                    }
                    Err(_) => {
                        // Timeout - no more responses
                        break;
                    }
                }
            }

            // Only check timeouts when we're done sending all probes
            // Checking timeouts while still sending causes premature timeouts
            if !has_more_ports {
                // Check for probe timeouts and handle retries
                self.check_udp_timeouts(&mut outstanding, &mut retry_probes, &mut results, loop_iterations);
            }

            // Reset batch counter
            if probes_sent_this_batch >= BATCH_SIZE {
                probes_sent_this_batch = 0;
            }

            // Re-send retry probes
            for probe in retry_probes.drain(..) {
                let current_cwnd = self.congestion.cwnd();
                if outstanding.len() < current_cwnd && outstanding.len() < self.max_parallelism {
                    if let Some(wait_time) = self.rate_limiter.check_rate() {
                        tokio::time::sleep(wait_time).await;
                    }
                    self.resend_udp_probe(probe, &mut outstanding)?;
                    self.rate_limiter.record_sent();
                } else {
                    // Can't resend - mark as open|filtered
                    results
                        .entry(probe.port)
                        .or_insert(PortState::OpenOrFiltered);
                }
            }
        }

        // Final wait for any remaining ICMP responses
        // nmap approach: use timing-based wait, not fixed 2000ms
        // For T4/T5: use probe_timeout (typically 100-300ms)
        // For T0-T3: use probe_timeout (can be longer)
        // Only wait if there are outstanding probes that might still receive responses
        if !outstanding.is_empty() {
            let probe_timeout = self.congestion.recommended_timeout();
            let final_wait = probe_timeout;
            let final_start = Instant::now();
            while final_start.elapsed() < final_wait {
                match tokio_timeout(Duration::from_millis(10), icmp_rx.recv()).await {
                    Ok(Some(icmp_resp)) => {
                        // Match ICMP response to outstanding probe
                        let probe_key = (icmp_resp.orig_dst_ip, icmp_resp.orig_dst_port);
                        if let Some(probe) = outstanding.remove(&probe_key) {
                            results.insert(probe.port, icmp_resp.port_state());
                        }
                    }
                    Ok(None) => {
                        // Channel closed - stop waiting
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue waiting until final_wait is reached
                    }
                }
            }
        }

        // Mark any remaining outstanding probes as open|filtered
        for probe in outstanding.values() {
            results
                .entry(probe.port)
                .or_insert(PortState::OpenOrFiltered);
        }

        // Signal receiver to stop
        drop(icmp_tx);
        let _ = tokio::time::timeout(Duration::from_millis(200), receiver_handle).await;

        Ok(results)
    }

    /// Sends a single UDP probe to the target.
    fn send_udp_probe(
        &self,
        target: Ipv4Addr,
        port: Port,
        outstanding: &mut HashMap<(Ipv4Addr, Port), UdpOutstandingProbe>,
    ) -> Result<(), rustnmap_common::ScanError> {
        use rustnmap_net::raw_socket::UdpPacketBuilder;

        let src_port = Self::generate_source_port();

        // Build UDP packet
        let packet = UdpPacketBuilder::new(self.local_addr, target, src_port, port).build();

        // Send the packet
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(target), port);
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        // Track the outstanding probe
        outstanding.insert(
            (target, port),
            UdpOutstandingProbe {
                target,
                port,
                src_port,
                sent_time: Instant::now(),
                retry_count: 0,
            },
        );

        Ok(())
    }

    /// Re-sends a UDP probe (for retries).
    fn resend_udp_probe(
        &self,
        mut probe: UdpOutstandingProbe,
        outstanding: &mut HashMap<(Ipv4Addr, Port), UdpOutstandingProbe>,
    ) -> Result<(), rustnmap_common::ScanError> {
        use rustnmap_net::raw_socket::UdpPacketBuilder;

        probe.retry_count += 1;
        probe.sent_time = Instant::now();

        // Rebuild and resend
        let packet =
            UdpPacketBuilder::new(self.local_addr, probe.target, probe.src_port, probe.port)
                .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(probe.target), probe.port);
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        outstanding.insert((probe.target, probe.port), probe);
        Ok(())
    }

    /// Checks for timed-out UDP probes and handles retries.
    ///
    /// # Arguments
    ///
    /// * `outstanding` - Outstanding UDP probes to check
    /// * `retry_probes` - Vector to collect probes that need retrying
    /// * `results` - Results map to update
    /// * `current_iteration` - Current loop iteration (for congestion control drop tracking)
    fn check_udp_timeouts(
        &self,
        outstanding: &mut HashMap<(Ipv4Addr, Port), UdpOutstandingProbe>,
        retry_probes: &mut Vec<UdpOutstandingProbe>,
        results: &mut HashMap<Port, PortState>,
        current_iteration: usize,
    ) {
        let now = Instant::now();
        let max_retries = u32::from(self.config.max_retries);
        // UDP scans need longer timeout for ICMP responses
        // Nmap uses 1 second initial timeout; we use minimum 500ms for reliability
        let probe_timeout = self
            .congestion
            .recommended_timeout()
            .max(Duration::from_millis(500));

        let timed_out: Vec<_> = outstanding
            .iter()
            .filter(|(_, p)| now.duration_since(p.sent_time) >= probe_timeout)
            .map(|(k, p)| (*k, p.clone()))
            .collect();

        for (key, probe) in timed_out {
            self.congestion.record_expected();

            if probe.retry_count < max_retries {
                outstanding.remove(&key);
                retry_probes.push(probe);
                self.congestion.on_packet_lost(current_iteration);
            } else {
                // Max retries - mark as open|filtered (no response)
                outstanding.remove(&key);
                results
                    .entry(probe.port)
                    .or_insert(PortState::OpenOrFiltered);
                self.congestion.on_packet_lost(current_iteration);
            }
        }
    }

    /// Starts the ICMP receiver task for UDP scanning.
    ///
    /// Uses `PACKET_MMAP` V2 with BPF filter for ICMP reception.
    /// This matches nmap's approach of using libpcap with a BPF filter to capture
    /// only ICMP packets destined to the local IP address.
    fn start_icmp_receiver_task(
        &self,
        scanner_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
        icmp_tx: mpsc::UnboundedSender<IcmpResponse>,
        ready_tx: oneshot::Sender<()>,
    ) -> JoinHandle<()> {
        let local_addr = self.local_addr;

        // Use tokio::spawn for async receiver with PACKET_MMAP V2
        tokio::spawn(async move {
            // Use the pre-created packet engine with BPF filter
            if let Some(engine) = scanner_engine {
                let mut ready_tx = Some(ready_tx);
                let timeout = Duration::from_millis(100);

                loop {
                    // Check if channel is closed before receiving
                    if icmp_tx.is_closed() {
                        break;
                    }

                    // Signal ready AFTER we're actually in the receive loop
                    // This ensures we're polling before the sender starts
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }

                    // Receive packet with timeout
                    let result = engine.lock().await.recv_with_timeout(timeout).await;

                    match result {
                        Ok(Some(data)) => {
                            // Skip Ethernet header (14 bytes) to get IP packet
                            let ip_data = if data.len() > ETH_HEADER_SIZE {
                                &data[ETH_HEADER_SIZE..]
                            } else {
                                &data[..]
                            };

                            // BPF filter already ensured this is ICMP destined to us
                            // But we still need to parse and validate the ICMP response
                            if let Some(icmp) = Self::parse_icmp_response(ip_data, local_addr) {
                                if icmp_tx.send(icmp).is_err() {
                                    break; // Channel closed
                                }
                            }
                        }
                        Ok(None) => {
                            // Timeout - check if channel is still open and continue waiting
                            if icmp_tx.is_closed() {
                                break;
                            }
                        }
                        Err(_) => {
                            // Error receiving - check if channel is still open
                            if icmp_tx.is_closed() {
                                break;
                            }
                            // Brief pause before retry
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        })
    }

    /// Parses an ICMP response from raw packet data.
    ///
    /// Returns `Some(IcmpResponse)` if this is an ICMP Port Unreachable
    /// message that matches one of our probes.
    fn parse_icmp_response(data: &[u8], local_addr: Ipv4Addr) -> Option<IcmpResponse> {
        // Minimum: IP header (20) + ICMP header (8) + inner IP header (20) + inner UDP header (8)
        if data.len() < 56 {
            return None;
        }

        // Check IP header
        let version_ihl = data[0];
        let version = version_ihl >> 4;
        if version != 4 {
            return None;
        }

        // Check protocol field (byte 9) - must be ICMP (1)
        let protocol = data[9];
        if protocol != 1 {
            return None;
        }

        // Calculate IP header length
        let ihl = u32::from(version_ihl & 0x0F) * 4;
        if data.len() < usize::try_from(ihl + 8).ok()? {
            return None;
        }

        // Parse ICMP header (after IP header)
        let icmp_start = usize::try_from(ihl).ok()?;
        let icmp_type = data[icmp_start];
        let icmp_code = data[icmp_start + 1];

        // Only process Destination Unreachable (type 3)
        if icmp_type != ICMP_TYPE_DEST_UNREACH {
            return None;
        }

        // Inner IP header starts after ICMP header (8 bytes)
        let inner_ip_start = icmp_start + 8;
        if data.len() < inner_ip_start + 28 {
            return None;
        }

        // Parse inner IP header
        // Inner packet is our original probe:
        // - Source IP (bytes 12-15) = our local_addr
        // - Destination IP (bytes 16-19) = target IP we probed
        let inner_src_ip = Ipv4Addr::new(
            data[inner_ip_start + 12],
            data[inner_ip_start + 13],
            data[inner_ip_start + 14],
            data[inner_ip_start + 15],
        );

        // Verify this ICMP is for our probe (source should be our local IP)
        // Note: We skip this check if local_addr is unspecified (0.0.0.0)
        if local_addr != Ipv4Addr::UNSPECIFIED && inner_src_ip != local_addr {
            return None;
        }

        // Get inner IP header length
        let inner_ihl = u32::from(data[inner_ip_start] & 0x0F) * 4;
        let inner_udp_start = inner_ip_start + usize::try_from(inner_ihl).ok()?;

        if data.len() < inner_udp_start + 8 {
            return None;
        }

        // Check inner protocol is UDP (17)
        let inner_protocol = data[inner_ip_start + 9];
        if inner_protocol != 17 {
            return None;
        }

        // Parse inner UDP header - get destination port (the port we probed)
        let orig_dst_port =
            u16::from_be_bytes([data[inner_udp_start + 2], data[inner_udp_start + 3]]);

        // Get original destination IP (the target we probed) - bytes 16-19 of inner IP header
        let orig_dst_ip = Ipv4Addr::new(
            data[inner_ip_start + 16],
            data[inner_ip_start + 17],
            data[inner_ip_start + 18],
            data[inner_ip_start + 19],
        );

        Some(IcmpResponse {
            orig_dst_ip,
            orig_dst_port,
            icmp_type,
            icmp_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = ParallelScanEngine::new(local_addr, config);

        // May fail if not running as root
        if let Ok(engine) = result {
            assert_eq!(engine.local_addr, local_addr);
            assert_eq!(engine.max_parallelism, DEFAULT_MAX_PARALLELISM);
            // Verify congestion controller is initialized
            assert!(engine.current_cwnd() > 0);
        }
    }

    #[tokio::test]
    async fn test_parallelism_configuration() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(engine) = ParallelScanEngine::new(local_addr, config) {
            let engine = engine.with_max_parallelism(200);

            assert_eq!(engine.max_parallelism, 200);
        }
    }

    #[tokio::test]
    async fn test_adaptive_timeout() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(engine) = ParallelScanEngine::new(local_addr, config) {
            // Adaptive timeout should be within reasonable bounds
            let timeout = engine.adaptive_probe_timeout();
            assert!(timeout.as_millis() >= 100); // At least 100ms
            assert!(timeout.as_secs() <= 30); // At most 30 seconds
        }
    }

    #[test]
    fn test_received_packet_creation() {
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let packet = ReceivedPacket::new(target, 80, 0x12, 1000, 1001);

        assert_eq!(packet.src_ip, target);
        assert_eq!(packet.src_port, 80);
        assert_eq!(packet.flags, 0x12);
        assert_eq!(packet.seq, 1000);
        assert_eq!(packet.ack, 1001);
    }

    #[test]
    fn test_port_state_from_flags() {
        // SYN-ACK (flags = 0x12) -> Open
        let syn_ack = ReceivedPacket::new(Ipv4Addr::LOCALHOST, 80, 0x12, 1000, 1001);
        assert_eq!(syn_ack.port_state(), PortState::Open);

        // RST (flags = 0x04) -> Closed
        let rst = ReceivedPacket::new(Ipv4Addr::LOCALHOST, 80, 0x04, 1000, 1001);
        assert_eq!(rst.port_state(), PortState::Closed);

        // Other flags -> Filtered
        let other = ReceivedPacket::new(Ipv4Addr::LOCALHOST, 80, 0x01, 1000, 1001);
        assert_eq!(other.port_state(), PortState::Filtered);
    }
}
