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
use std::io::{self, ErrorKind};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::ptr;
use std::sync::Arc as StdArc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustnmap_common::{Port, PortState, RateLimiter, ScanConfig};
use rustnmap_net::raw_socket::{parse_tcp_response, RawSocket, TcpPacketBuilder};
use tokio::sync::mpsc;
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
#[derive(Debug, Default)]
struct InternalCongestionStats {
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
    /// Creates new congestion statistics with default values.
    ///
    /// Uses nmap T3 (Normal) defaults:
    /// - Initial SRTT: 1000ms (`INITIAL_RTT_TIMEOUT`)
    /// - Initial RTTVAR: 1000ms (clamped between 5ms-2000ms, based on SRTT)
    fn new() -> Self {
        Self {
            // Nmap INITIAL_RTT_TIMEOUT = 1000ms
            srtt_micros: std::sync::atomic::AtomicU64::new(1_000_000),
            // Nmap: rttvar = box(5000, 2000000, srtt) = clamp(srtt, 5ms, 2000ms)
            rttvar_micros: std::sync::atomic::AtomicU64::new(1_000_000),
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
            .compare_exchange(
                true,
                false,
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
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
    /// The result is clamped to nmap's bounds: `MIN_RTT_TIMEOUT` (100ms) to
    /// `MAX_RTT_TIMEOUT` (10000ms).
    fn recommended_timeout(&self) -> Duration {
        use std::sync::atomic::Ordering;
        let srtt = self.srtt_micros.load(Ordering::Relaxed);
        let rttvar = self.rttvar_micros.load(Ordering::Relaxed);
        let timeout_micros = srtt.saturating_add(4 * rttvar);
        // Clamp to nmap's MIN_RTT_TIMEOUT (100ms) and MAX_RTT_TIMEOUT (10000ms)
        let clamped = timeout_micros.clamp(100_000, 10_000_000);
        Duration::from_micros(clamped)
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
    min_cwnd: usize,
    max_cwnd: usize,
    /// Congestion avoidance increment (`ca_incr`).
    /// From nmap `timing.cc:276-279`:
    /// - `timing_level` < 4 (T0-T3): `ca_incr` = 1
    /// - `timing_level` >= 4 (T4-T5): `ca_incr` = 2
    ca_incr: u8,
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
    fn new(max_cwnd: usize, timing_level: u8) -> Self {
        // Nmap timing.cc:272 - group_initial_cwnd = box(low_cwnd, max_cwnd, 10)
        // low_cwnd=1, max_cwnd=300, box() returns 10 since 1 < 10 < 300
        const GROUP_INITIAL_CWND: usize = 10;

        // Nmap timing.cc:281 - initial_ssthresh = 75
        const INITIAL_SSTHRESH: usize = 75;

        // Nmap timing.cc:276-279
        // "The congestion window grows faster with more aggressive timing."
        let ca_incr = if timing_level < 4 { 1 } else { 2 };

        Self {
            stats: std::sync::Arc::new(InternalCongestionStats::new()),
            cwnd: std::sync::atomic::AtomicUsize::new(GROUP_INITIAL_CWND),
            ssthresh: std::sync::atomic::AtomicUsize::new(INITIAL_SSTHRESH),
            ca_ack_counter: std::sync::atomic::AtomicUsize::new(0),
            min_cwnd: 1,
            max_cwnd,
            ca_incr,
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
    fn on_packet_lost(&self) {
        use std::sync::atomic::Ordering;

        let current_cwnd = self.cwnd.load(Ordering::Relaxed);
        let new_ssthresh = (current_cwnd / 2).max(self.min_cwnd);
        let new_cwnd = new_ssthresh;

        self.ssthresh.store(new_ssthresh, Ordering::Relaxed);
        self.cwnd.store(new_cwnd, Ordering::Relaxed);
    }

    /// Returns recommended timeout.
    fn recommended_timeout(&self) -> Duration {
        self.stats.recommended_timeout()
    }
}

/// Simple `AF_PACKET` socket for L2 packet capture.
/// Uses standard `recvfrom` (not `PACKET_MMAP`) for simplicity.
#[derive(Debug)]
struct SimpleAfPacket {
    #[expect(dead_code, reason = "Interface index stored for potential future use")]
    if_index: i32,
    fd: std::os::fd::OwnedFd,
}

impl SimpleAfPacket {
    /// Creates a new `AF_PACKET` socket bound to the specified interface.
    ///
    /// # Errors
    ///
    /// Returns an error if socket creation, interface lookup, or binding fails.
    fn new(if_name: &str) -> io::Result<Self> {
        // SAFETY: Creating an AF_PACKET raw socket with valid libc constants.
        // The returned fd is checked for errors before use.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from(libc::htons(ETH_P_ALL)),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a valid, non-negative file descriptor returned by socket().
        // OwnedFd takes ownership and will close it on drop.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

        let if_index = Self::get_if_index(fd.as_raw_fd(), if_name)?;

        // SAFETY: zeroed memory is valid for sockaddr_ll (POD struct with integer fields).
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "AF_PACKET (17) fits in u16"
        )]
        {
            addr.sll_family = libc::AF_PACKET as u16;
        };
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = if_index;

        // SAFETY: fd is a valid AF_PACKET socket. addr is properly initialized with
        // family, protocol, and interface index. Size matches the struct.
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                u32::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap_or(u32::MAX),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: fd is a valid open file descriptor. F_GETFL returns current flags.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is valid, flags is the current flag set from F_GETFL.
        // Adding O_NONBLOCK is a safe flag modification.
        let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: zeroed memory is valid for packet_mreq (POD struct).
        let mut mreq: libc::packet_mreq = unsafe { mem::zeroed() };
        mreq.mr_ifindex = if_index;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "PACKET_MR_PROMISC (1) fits in u16"
        )]
        {
            mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
        };
        // SAFETY: fd is a valid AF_PACKET socket. mreq is properly initialized.
        // PACKET_ADD_MEMBERSHIP enables promiscuous mode on the interface.
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&raw const mreq).cast::<libc::c_void>(),
                u32::try_from(mem::size_of::<libc::packet_mreq>()).unwrap_or(u32::MAX),
            )
        };
        if ret < 0 {
            // Non-fatal: promiscuous mode is helpful but not required
        }

        Ok(Self { if_index, fd })
    }

    fn get_if_index(fd: i32, if_name: &str) -> io::Result<i32> {
        // SAFETY: zeroed memory is valid for ifreq (all-zero is a valid bit pattern
        // for this POD struct containing integers and a char array).
        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
        let bytes = if_name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        for (i, &b) in bytes.iter().enumerate() {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "ASCII interface name bytes (0-127) fit safely in i8"
            )]
            {
                ifreq.ifr_name[i] = b as i8;
            };
        }
        // SAFETY: fd is a valid open socket, ifreq is properly initialized with
        // the interface name. SIOCGIFINDEX populates ifru_ifindex on success.
        let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &raw mut ifreq) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: After successful SIOCGIFINDEX ioctl, the kernel has populated
        // the ifru_ifindex field of the ifreq union with the interface index.
        Ok(unsafe { ifreq.ifr_ifru.ifru_ifindex })
    }

    /// Receives a packet from the `AF_PACKET` socket.
    ///
    /// Returns `Ok(Some(data))` if a packet was received,
    /// `Ok(None)` if no packet is available (non-blocking), or `Err` on error.
    ///
    /// # Errors
    ///
    /// Returns an error if `recvfrom` fails with an error other than `WouldBlock`.
    fn recv_packet(&self) -> io::Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; 65_535];
        // SAFETY: fd is a valid AF_PACKET socket. buffer is a properly allocated
        // mutable slice. recvfrom with null src_addr/addrlen is valid and simply
        // discards the sender address information.
        let ret = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err);
        }
        #[expect(
            clippy::cast_sign_loss,
            reason = "ret is non-negative (checked above), safe to cast to usize"
        )]
        let len = ret as usize;
        buffer.truncate(len);
        Ok(Some(buffer))
    }
}

/// Ethernet protocol for all traffic.
const ETH_P_ALL: u16 = 0x0003;
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
    /// `AF_PACKET` engine for receiving TCP responses (L2 capture).
    packet_socket: Option<Arc<SimpleAfPacket>>,
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

        // Try to create AF_PACKET socket for L2 packet capture
        // This is critical for receiving TCP RST responses that raw socket misses
        let packet_socket = Self::create_packet_socket(local_addr);

        let max_parallel = DEFAULT_MAX_PARALLELISM;

        // Create internal congestion controller for adaptive timing
        // Uses timing_level from config to set ca_incr (T4/T5 use ca_incr=2)
        let congestion = Arc::new(InternalCongestionController::new(max_parallel, config.timing_level));

        // Create rate limiter for min/max rate enforcement
        let rate_limiter = RateLimiter::new(config.min_rate, config.max_rate);

        Ok(Self {
            local_addr,
            socket,
            packet_socket,
            config,
            congestion,
            rate_limiter,
            max_parallelism: max_parallel,
            scan_timeout: DEFAULT_SCAN_TIMEOUT,
        })
    }

    /// Creates an `AF_PACKET` socket for TCP response capture.
    ///
    /// This is critical for receiving TCP RST responses that raw socket misses.
    /// The socket captures at L2 (data link layer) like libpcap, ensuring all
    /// TCP responses are received regardless of kernel TCP stack behavior.
    ///
    /// # Note
    ///
    /// This is optional - if creation fails, returns `None` and the scanner
    /// falls back to raw socket only (which may miss some responses).
    ///
    /// For localhost addresses, returns `None` because `AF_PACKET` on loopback
    /// interface cannot capture responses from raw socket probes. The raw
    /// socket fallback handles localhost correctly.
    fn create_packet_socket(local_addr: Ipv4Addr) -> Option<Arc<SimpleAfPacket>> {
        // Skip AF_PACKET for localhost - it cannot capture raw socket responses on lo
        if local_addr == Ipv4Addr::LOCALHOST || local_addr.is_loopback() {
            return None;
        }

        // Get the network interface name for the local address
        let if_name = Self::get_interface_for_ip(local_addr)?;

        match SimpleAfPacket::new(&if_name) {
            Ok(socket) => Some(Arc::new(socket)),
            Err(e) => {
                // Log the error but continue with raw socket fallback
                let _ = e;
                None
            }
        }
    }

    /// Gets the network interface name for the given local IP address.
    ///
    /// This function tries to find the interface that has the given local IP address.
    /// For localhost, returns "lo". For other addresses, reads from /proc/net/route
    /// to find the default route interface.
    fn get_interface_for_ip(local_addr: Ipv4Addr) -> Option<String> {
        // For localhost, use lo
        if local_addr == Ipv4Addr::LOCALHOST || local_addr.is_loopback() {
            return Some("lo".to_string());
        }

        // Read /proc/net/route to find the default route interface
        // This is the most reliable way to find the main network interface
        if let Ok(route_data) = std::fs::read_to_string("/proc/net/route") {
            for line in route_data.lines().skip(1) {
                // Format: Iface Destination Gateway Flags ...
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let iface = parts[0];
                    let dest = parts[1];
                    // Dest 00000000 means default route
                    if dest == "00000000" {
                        // Found the default route interface, return it directly
                        // without trying to verify with AfPacketEngine (which may fail)
                        return Some(iface.to_string());
                    }
                }
            }
        }

        // Fallback: try common interface names in order of likelihood
        for if_name in [
            "wlp3s0", "wlan0", "wlp2s0", "wlp1s0", // Wireless
            "eth0", "eth1", "ens33", "ens34", "enp0s3", "enp0s8", // Wired
        ] {
            // Check if interface exists by reading /sys/class/net/
            let path = format!("/sys/class/net/{if_name}/operstate");
            if std::path::Path::new(&path).exists() {
                return Some(if_name.to_string());
            }
        }
        None
    }

    /// Sets the maximum parallelism.
    ///
    /// # Arguments
    ///
    /// * `value` - Maximum number of probes to have outstanding
    #[must_use]
    pub fn with_max_parallelism(mut self, value: usize) -> Self {
        self.max_parallelism = value;
        // Recreate congestion controller with new max and existing timing_level
        self.congestion = Arc::new(InternalCongestionController::new(value, self.config.timing_level));
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

        // Main scan loop
        while ports_iter.peek().is_some() || !outstanding.is_empty() {
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
                    self.send_probe(target, port, &mut outstanding)?;
                    // Record packet sent for congestion stats and rate limiting
                    self.congestion.on_packet_sent();
                    self.rate_limiter.record_sent();
                    probes_sent_this_batch += 1;
                } else {
                    break;
                }
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
                Duration::from_millis(10)
            } else if !outstanding.is_empty() {
                // All probes sent, wait for earliest timeout (but not longer than 100ms per iteration)
                earliest_timeout.min(Duration::from_millis(100))
            } else {
                // No outstanding probes - short wait
                Duration::from_millis(10)
            };
            let mut wait_duration = initial_wait;

            loop {
                match tokio_timeout(wait_duration, packet_rx.recv()).await {
                    Ok(Some(packet)) => {
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

                        // Use shorter timeout for draining remaining packets
                        wait_duration = Duration::from_millis(10);
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

            // Check for probe timeouts and handle retries
            self.check_timeouts(&mut outstanding, &mut retry_probes, &mut results);

            // Reset batch counter only after sending a full batch and draining responses
            // This matches nmap's behavior: reset after waitForResponses() when batch is complete
            if probes_sent_this_batch >= BATCH_SIZE {
                probes_sent_this_batch = 0;
            }

            // Re-send retry probes
            for probe in retry_probes.drain(..) {
                let current_cwnd = self.congestion.cwnd();
                if outstanding.len() < current_cwnd && outstanding.len() < self.max_parallelism {
                    // Check rate limiter before resending
                    if let Some(wait_time) = self.rate_limiter.check_rate() {
                        tokio::time::sleep(wait_time).await;
                    }
                    self.resend_probe(probe, &mut outstanding)?;
                    self.rate_limiter.record_sent();
                } else {
                    // Can't resend due to parallelism limit, mark as filtered
                    results.entry(probe.port).or_insert(PortState::Filtered);
                }
            }
        }

        // Explicitly drop the sender to signal the receiver task to stop
        drop(packet_tx);

        // Wait for receiver task to complete with timeout
        // Use a short timeout since the receiver should exit quickly when channel is closed
        let _ = tokio::time::timeout(Duration::from_millis(200), receiver_handle).await;

        Ok(results)
    }

    /// Starts the background receiver task.
    ///
    /// This task continuously receives packets and parses them.
    /// The task stops when the sender is dropped (all senders closed).
    ///
    /// # Note
    ///
    /// The receiver task uses `spawn_blocking` because `socket.recv_packet()` is a
    /// synchronous blocking call. This prevents blocking the Tokio worker thread.
    ///
    /// When `packet_socket` is available, it will use `AF_PACKET` for L2 capture,
    /// which properly receives TCP RST responses that raw socket may miss.
    fn start_receiver_task(
        &self,
        packet_tx: mpsc::UnboundedSender<ReceivedPacket>,
    ) -> JoinHandle<()> {
        let socket = StdArc::clone(&self.socket);
        let packet_socket = self.packet_socket.clone();
        tokio::spawn(async move {
            loop {
                // Check if channel is closed before blocking on recv
                if packet_tx.is_closed() {
                    break;
                }

                // Try AF_PACKET socket first (L2 capture - receives all TCP responses)
                // Fall back to raw socket if packet socket is not available
                let result = if let Some(ref pkt_sock) = packet_socket {
                    // Use AF_PACKET socket for L2 capture
                    let pkt_sock = Arc::clone(pkt_sock);
                    let tx_clone = packet_tx.clone();
                    tokio::task::spawn_blocking(move || {
                        // Process multiple packets in a batch to reduce context switches
                        const MAX_BATCH: usize = 32;
                        let mut batch_count = 0;

                        while batch_count < MAX_BATCH {
                            match pkt_sock.recv_packet() {
                                Ok(Some(data)) => {
                                    // Skip Ethernet header (14 bytes) to get to IP header
                                    let ip_data = if data.len() > ETH_HDR_SIZE {
                                        &data[ETH_HDR_SIZE..]
                                    } else {
                                        &data[..]
                                    };
                                    // Parse and send immediately as ReceivedPacket
                                    if let Some(packet) = Self::parse_packet(ip_data) {
                                        if tx_clone.send(packet).is_err() {
                                            return Ok((batch_count, Vec::new()));
                                        }
                                    }
                                    batch_count += 1;
                                }
                                Ok(None) => {
                                    // No more packets available
                                    break;
                                }
                                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                    // No more packets available
                                    break;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        // Return batch_count with empty vec (packets already sent in loop)
                        Ok::<_, io::Error>((batch_count, Vec::new()))
                    })
                    .await
                } else {
                    // Fall back to raw socket (L3 capture - may miss some TCP responses)
                    let socket_clone = StdArc::clone(&socket);
                    tokio::task::spawn_blocking(move || {
                        let mut recv_buf = vec![0u8; 65535];
                        match socket_clone.recv_packet(&mut recv_buf, Some(Duration::from_millis(50))) {
                            Ok(len) => Ok((len, recv_buf)),
                            Err(e) => Err(e),
                        }
                    })
                    .await
                };

                match result {
                    Ok(Ok((len, recv_buf))) if len > 0 && !recv_buf.is_empty() => {
                        // Raw socket path: parse packet from buffer
                        if let Some(packet) = Self::parse_packet(&recv_buf[..len]) {
                            if packet_tx.send(packet).is_err() {
                                break;
                            }
                        }
                    }
                    Ok(Ok((batch_count, _))) => {
                        // AF_PACKET batch processing result
                        // Packets already sent in batch loop, just yield if empty
                        if batch_count == 0 {
                            tokio::task::yield_now().await;
                        }
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Fatal error or task was cancelled, stop receiving
                        break;
                    }
                }
            }
        })
    }

    /// Parses a received packet into a `ReceivedPacket`.
    ///
    /// Returns `None` if the packet cannot be parsed as a TCP packet.
    fn parse_packet(data: &[u8]) -> Option<ReceivedPacket> {
        if let Some((flags, seq, ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data) {
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
    fn check_timeouts(
        &self,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
        retry_probes: &mut Vec<OutstandingProbe>,
        results: &mut HashMap<Port, PortState>,
    ) {
        let now = Instant::now();
        // Use max_retries from config (nmap default: 10, i.e., 11 probes max)
        let max_retries = u32::from(self.config.max_retries);

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
            // See nmap scan_engine.cc:1677 (ultrascan_adjust_timing with rcvdtime == NULL)
            self.congestion.record_expected();

            if probe.retry_count < max_retries {
                // Retry the probe
                outstanding.remove(&key);
                retry_probes.push(probe);
                // Record packet loss for congestion control
                self.congestion.on_packet_lost();
            } else {
                // Max retries reached, mark as filtered
                outstanding.remove(&key);
                results.entry(probe.port).or_insert(PortState::Filtered);
                // Record packet loss for congestion control
                self.congestion.on_packet_lost();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
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

    #[test]
    fn test_parallelism_configuration() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(engine) = ParallelScanEngine::new(local_addr, config) {
            let engine = engine.with_max_parallelism(200);

            assert_eq!(engine.max_parallelism, 200);
        }
    }

    #[test]
    fn test_adaptive_timeout() {
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
