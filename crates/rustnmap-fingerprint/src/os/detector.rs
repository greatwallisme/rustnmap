//! OS detection engine.
//!
//! Executes OS detection probes and matches fingerprints
//! to determine the target operating system.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, trace};

use super::{
    database::{FingerprintDatabase, OsMatch},
    fingerprint::{
        EcnFingerprint, IcmpTestResult, IpIdPattern, IpIdSeqClass, IsnClass,
        OsFingerprint, SeqFingerprint, TestResult, UdpTestResult,
    },
};
use crate::Result;
use rustnmap_net::raw_socket::{
    parse_icmpv6_echo_reply, parse_ipv6_tcp_response, Icmpv6PacketBuilder, Ipv6TcpPacketBuilder,
    Ipv6UdpPacketBuilder, RawSocket,
};
use rustnmap_packet::{BpfFilter, MmapPacketEngine, PacketEngine, RingConfig};

/// OS detection engine.
///
/// Sends specialized probes and analyzes responses to generate
/// a fingerprint for matching against known OS fingerprints.
/// Supports both IPv4 and IPv6 targets.
#[derive(Debug)]
pub struct OsDetector {
    /// OS fingerprint database shared across detection tasks via Arc.
    db: Arc<FingerprintDatabase>,

    /// Number of sequence probes to send.
    seq_count: usize,

    /// Local IPv4 address for probes.
    local_addr_v4: Ipv4Addr,

    /// Local IPv6 address for probes (optional).
    local_addr_v6: Option<Ipv6Addr>,

    /// Open TCP port on target (for SEQ, T1, T3 probes).
    open_port: u16,

    /// Closed TCP port on target (for T2, T4-T7 probes).
    closed_port: u16,

    /// Closed UDP port on target (for U1 probe).
    closed_udp_port: u16,

    /// Probe timeout.
    timeout: Duration,

    /// Delay between SEQ probes (100ms as per Nmap spec).
    seq_probe_delay: Duration,
}

/// Response from a single SEQ probe.
#[derive(Debug, Clone)]
struct SeqProbeResponse {
    /// TCP sequence number from SYN-ACK.
    isn: u32,
    /// IP ID from response.
    ip_id: u16,
    /// TCP timestamp value.
    timestamp: Option<u32>,
    /// TCP window size (used for WIN fingerprint section).
    window: u16,
    /// Raw TCP option bytes (used for OPS fingerprint section).
    raw_options: Vec<u8>,
    /// Time when this probe was sent (for ISR/SP rate calculation).
    send_time: std::time::Instant,
}

/// TCP flags constants.
mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const _RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// Ethernet header length in bytes (6 dst MAC + 6 src MAC + 2 EtherType).
const ETH_HEADER_LEN: usize = 14;

/// Source port offset between probe groups to avoid kernel TCP state interference.
/// Each probe group (SEQ, OPS, ECN, T1-T7) uses a different source port to prevent
/// the kernel's TCP stack from interfering with subsequent probes to the same
/// port pair (SYN-ACK responses from SEQ would cause kernel RST, which could
/// cause the target to reject later SYNs to the same port pair).
const SRC_PORT_OFFSET_PER_GROUP: u16 = 100;

/// Probe option sets matching nmap's prbOpts[] in osscan2.cc.
///
/// Indices 0-5: SEQ/OPS/WIN probes (6 probes with different options)
/// Index 6: ECN probe
/// Indices 7-12: T1-T7 probes
///
/// Each entry is (option_bytes, window_size).
static PROBE_OPTIONS: &[(&[u8], u16)] = &[
    // 0: WScale(10), NOP, MSS(1460), Timestamp, SACK | win=1
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x05, 0xB4, // MSS=1460
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        1,
    ),
    // 1: MSS(1400), WScale(0), SACK, Timestamp, EOL | win=63
    (
        &[
            0x02, 0x04, 0x05, 0x78, // MSS=1400
            0x03, 0x03, 0x00, // WScale=0
            0x04, 0x02, // SACK
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x00, // EOL
        ],
        63,
    ),
    // 2: Timestamp, NOP, NOP, WScale(5), NOP, MSS(640), EOL | win=4
    (
        &[
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x01, 0x01, // NOP NOP
            0x03, 0x03, 0x05, // WScale=5
            0x01, // NOP
            0x02, 0x04, 0x02, 0x80, // MSS=640
        ],
        4,
    ),
    // 3: SACK, Timestamp, WScale(10), EOL | win=4
    (
        &[
            0x04, 0x02, // SACK
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x03, 0x03, 0x0A, // WScale=10
            0x00, // EOL
        ],
        4,
    ),
    // 4: MSS(536), SACK, Timestamp, WScale(10), EOL | win=16
    (
        &[
            0x02, 0x04, 0x02, 0x18, // MSS=536
            0x04, 0x02, // SACK
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x03, 0x03, 0x0A, // WScale=10
            0x00, // EOL
        ],
        16,
    ),
    // 5: MSS(265), SACK, Timestamp | win=512
    (
        &[
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x04, 0x02, // SACK
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
        ],
        512,
    ),
    // 6: ECN probe: WScale(10), NOP, MSS(1460), SACK, NOP, NOP | win=3
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x05, 0xB4, // MSS=1460
            0x04, 0x02, // SACK
            0x01, 0x01, // NOP NOP
        ],
        3,
    ),
    // 7: T1: WScale(10), NOP, MSS(265), Timestamp, SACK | win=128
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        128,
    ),
    // 8: T2: same options as T1 | win=256
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        256,
    ),
    // 9: T3: same options as T1 | win=1024
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        1024,
    ),
    // 10: T4: same options as T1 | win=31337
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        31337,
    ),
    // 11: T5: same options as T1 | win=32768
    (
        &[
            0x03, 0x03, 0x0A, // WScale=10
            0x01, // NOP
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        32768,
    ),
    // 12: T6: WScale(15), NOP, MSS(265), Timestamp, SACK | win=65535
    (
        &[
            0x03, 0x03, 0x0F, // WScale=15
            0x01, // NOP
            0x02, 0x04, 0x01, 0x09, // MSS=265
            0x08, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x04, 0x02, // SACK
        ],
        65535,
    ),
];

/// Drains all pending packets from the `MmapPacketEngine` ring buffer.
///
/// After changing the BPF filter, stale frames that passed the previous filter
/// may still be queued. This function consumes and discards them so that the
/// next receive loop only sees packets matching the new filter.
fn drain_engine(engine: &mut MmapPacketEngine) {
    let mut drained = 0u32;
    while let Ok(Some(_)) = engine.try_recv_zero_copy() {
        drained += 1;
    }
    if drained > 0 {
        trace!("drain_engine: discarded {drained} stale packets");
    }
}

/// Swaps byte order of a u32 (little-endian to big-endian or vice versa).
fn swap_bytes_u32(val: u32) -> u32 {
    ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24)
}

/// Resolves the network interface name and creates a `MmapPacketEngine` for the
/// interface that routes to the given local IPv4 address.
///
/// Reads `/proc/net/route` to find the interface whose network contains
/// `local_addr`. Prefers more specific routes (higher mask value).
///
/// The route table hex values are in little-endian byte order, so they must
/// be byte-swapped before comparing with `u32::from(Ipv4Addr)` (host order).
fn resolve_interface_for_ip(local_addr: Ipv4Addr) -> Result<(String, MmapPacketEngine)> {
    let local_u32 = u32::from(local_addr);
    let route_data =
        std::fs::read_to_string("/proc/net/route").map_err(|e| crate::FingerprintError::Network {
            operation: "read /proc/net/route".to_string(),
            reason: e.to_string(),
        })?;

    let mut best_iface: Option<String> = None;
    let mut best_mask: u32 = 0;

    for line in route_data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }

        let iface = fields[0];
        let dest_hex = fields[1];
        let mask_hex = fields[7];

        // /proc/net/route hex values are little-endian; swap to host order
        let dest_raw = u32::from_str_radix(dest_hex, 16).unwrap_or(0);
        let mask_raw = u32::from_str_radix(mask_hex, 16).unwrap_or(0);
        let dest = swap_bytes_u32(dest_raw);
        let mask = swap_bytes_u32(mask_raw);

        if (local_u32 & mask) == dest && mask >= best_mask {
            best_mask = mask;
            best_iface = Some(iface.to_string());
        }
    }

    let if_name = best_iface.ok_or_else(|| crate::FingerprintError::Network {
        operation: "resolve interface".to_string(),
        reason: format!("no route found for local address {local_addr}"),
    })?;

    // Small ring buffer for OS detection: a few packets per probe
    let config = RingConfig::default();
    let engine = MmapPacketEngine::new(&if_name, config).map_err(|e| {
        crate::FingerprintError::Network {
            operation: format!("create MmapPacketEngine on {if_name}"),
            reason: e.to_string(),
        }
    })?;

    Ok((if_name, engine))
}

/// TCP response data from a BPF-filtered MmapPacketEngine capture.
///
/// Contains both the parsed TCP response fields and the raw TCP option bytes
/// needed for OS fingerprint matching.
#[derive(Debug, Clone)]
struct TcpResponseData {
    /// Parsed TCP response from `parse_tcp_response_full`.
    response: rustnmap_net::raw_socket::TcpResponse,
    /// Raw TCP option bytes (between fixed 20-byte TCP header and data offset).
    raw_options: Vec<u8>,
}

/// Receives a TCP response packet via `MmapPacketEngine` with BPF filtering.
///
/// Polls `try_recv_zero_copy()` in a loop with short sleeps until a matching
/// TCP response is found or the timeout expires.
///
/// The packet data from `MmapPacketEngine` includes a 14-byte Ethernet header,
/// which is stripped before passing to `parse_tcp_response_full`.
fn recv_tcp_response_bpf(
    engine: &mut MmapPacketEngine,
    expected_src_port: u16,
    expected_dst_port: u16,
    timeout: Duration,
) -> Result<Option<TcpResponseData>> {
    let deadline = std::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(1);
    let mut poll_count = 0u32;
    let mut ok_some_count = 0u32;
    let mut ok_none_count = 0u32;
    let mut err_count = 0u32;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            debug!(
                "recv_tcp_response_bpf: timed out after {poll_count} polls \
                 (some={ok_some_count} none={ok_none_count} err={err_count}) \
                 expecting sp={expected_src_port} dp={expected_dst_port}"
            );
            return Ok(None);
        }
        poll_count += 1;

        match engine.try_recv_zero_copy() {
            Ok(Some(pkt)) => {
                ok_some_count += 1;
                let d = pkt.data();
                trace!(
                    "recv_tcp_response_bpf: got {} bytes, expecting sp={} dp={}",
                    d.len(),
                    expected_src_port,
                    expected_dst_port
                );
                // Skip Ethernet header (14 bytes), then parse IP+TCP
                if d.len() > ETH_HEADER_LEN {
                    let ip_data = &d[ETH_HEADER_LEN..];
                    if let Some(response) = rustnmap_net::raw_socket::parse_tcp_response_full(ip_data)
                    {
                        trace!(
                            "recv_tcp_response_bpf: parsed sp={} dp={} flags=0x{:02x}",
                            response.src_port,
                            response.dst_port,
                            response.flags
                        );
                        if response.src_port == expected_src_port
                            && response.dst_port == expected_dst_port
                        {
                            // Extract raw TCP options from the mmap packet data
                            let ip_hlen = (ip_data[0] & 0x0F) as usize * 4;
                            let raw_options = if ip_data.len() >= ip_hlen + 20 {
                                let tcp_doff =
                                    (ip_data[ip_hlen + 12] >> 4) as usize * 4;
                                if tcp_doff > 20 && ip_data.len() >= ip_hlen + tcp_doff {
                                    ip_data[ip_hlen + 20..ip_hlen + tcp_doff].to_vec()
                                } else {
                                    Vec::new()
                                }
                            } else {
                                Vec::new()
                            };

                            return Ok(Some(TcpResponseData { response, raw_options }));
                        }
                    }
                }
                // Packet dropped here (ZeroCopyPacket released, frame returned to kernel)
            }
            Ok(None) => {
                ok_none_count += 1;
                // No packet available yet, sleep briefly
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                err_count += 1;
                if err_count <= 3 {
                    debug!("recv_tcp_response_bpf: error: {e}");
                }
                std::thread::sleep(poll_interval);
            }
        }
    }
}

impl OsDetector {
    /// Create new OS detector with IPv4 support.
    #[must_use]
    pub fn new(db: FingerprintDatabase, local_addr: Ipv4Addr) -> Self {
        Self {
            db: Arc::new(db),
            seq_count: 6,
            local_addr_v4: local_addr,
            local_addr_v6: None,
            open_port: 80,
            closed_port: 443,
            closed_udp_port: 33434,
            timeout: Duration::from_secs(3),
            seq_probe_delay: Duration::from_millis(100),
        }
    }

    /// Create new OS detector with dual-stack support.
    #[must_use]
    pub fn new_dual_stack(
        db: FingerprintDatabase,
        local_addr_v4: Ipv4Addr,
        local_addr_v6: Ipv6Addr,
    ) -> Self {
        Self {
            db: Arc::new(db),
            seq_count: 6,
            local_addr_v4,
            local_addr_v6: Some(local_addr_v6),
            open_port: 80,
            closed_port: 443,
            closed_udp_port: 33434,
            timeout: Duration::from_secs(3),
            seq_probe_delay: Duration::from_millis(100),
        }
    }

    /// Create new OS detector with a reference to the database.
    #[cfg(test)]
    #[must_use]
    pub fn new_with_ref(db: &FingerprintDatabase, local_addr: Ipv4Addr) -> Self {
        Self {
            db: Arc::new(db.clone()),
            seq_count: 6,
            local_addr_v4: local_addr,
            local_addr_v6: None,
            open_port: 80,
            closed_port: 443,
            closed_udp_port: 33434,
            timeout: Duration::from_secs(3),
            seq_probe_delay: Duration::from_millis(100),
        }
    }

    /// Set local IPv6 address for dual-stack detection.
    #[must_use]
    pub fn with_local_v6(mut self, addr: Ipv6Addr) -> Self {
        self.local_addr_v6 = Some(addr);
        self
    }

    /// Set number of sequence probes for ISN analysis.
    #[must_use]
    pub fn with_seq_count(mut self, count: usize) -> Self {
        self.seq_count = count.clamp(1, 20);
        self
    }

    /// Set the open port for probes that need it.
    #[must_use]
    pub fn with_open_port(mut self, port: u16) -> Self {
        self.open_port = port;
        self
    }

    /// Set the closed TCP port for probes that need it.
    #[must_use]
    pub fn with_closed_port(mut self, port: u16) -> Self {
        self.closed_port = port;
        self
    }

    /// Set the closed UDP port for U1 probe.
    #[must_use]
    pub fn with_closed_udp_port(mut self, port: u16) -> Self {
        self.closed_udp_port = port;
        self
    }

    /// Set probe timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Detect OS for a target host.
    ///
    /// # Errors
    ///
    /// Returns an error if network operations fail or no OS matches are found.
    pub async fn detect_os(&self, target: &SocketAddr) -> Result<Vec<OsMatch>> {
        info!("Starting OS detection for {}", target);

        match target.ip() {
            IpAddr::V4(addr) => self.detect_os_v4(addr).await,
            IpAddr::V6(addr) => self.detect_os_v6(addr).await,
        }
    }

    /// Detect OS for an IPv4 target.
    async fn detect_os_v4(&self, target: Ipv4Addr) -> Result<Vec<OsMatch>> {
        // Build fingerprint from collected probe responses
        let fingerprint = self.build_fingerprint(target).await?;

        // Match against database
        let matches = self.db.find_matches(&fingerprint);

        info!("Found {} OS matches for {}", matches.len(), target);

        Ok(matches)
    }

    /// Detect OS for an IPv6 target.
    ///
    /// IPv6 OS detection uses similar probe techniques but with IPv6-specific
    /// packet structures and ICMPv6 instead of ICMP.
    async fn detect_os_v6(&self, target: Ipv6Addr) -> Result<Vec<OsMatch>> {
        let local_v6 = self
            .local_addr_v6
            .ok_or_else(|| crate::FingerprintError::Network {
                operation: "IPv6 OS detection".to_string(),
                reason: "IPv6 local address not configured".to_string(),
            })?;

        // Build IPv6 fingerprint from collected probe responses
        let fingerprint = self.build_fingerprint_v6(target, local_v6).await?;

        // Match against database
        let matches = self.db.find_matches(&fingerprint);

        info!("Found {} OS matches for {}", matches.len(), target);

        Ok(matches)
    }

    /// Build OS fingerprint from probe responses.
    async fn build_fingerprint(&self, target: Ipv4Addr) -> Result<OsFingerprint> {
        let mut fingerprint = OsFingerprint::new();

        // Create one MmapPacketEngine for all TCP probes (SEQ, ECN, T1-T7)
        let (_if_name, mut engine) = resolve_interface_for_ip(self.local_addr_v4)?;
        engine.start().await.map_err(|e| crate::FingerprintError::Network {
            operation: "start MmapPacketEngine for OS detection".to_string(),
            reason: e.to_string(),
        })?;

        // Send SEQ probes (6 SYN probes to open port with 100ms intervals)
        // Each probe uses different options/window; responses provide OPS and WIN data
        debug!("Sending SEQ probes to {}:{}", target, self.open_port);
        let seq_responses = self.send_seq_probes(target, &mut engine).await?;
        let seq_fp = self.analyze_seq_responses(&seq_responses);
        fingerprint.seq = Some(seq_fp);

        // Populate OPS(O1-O6) and WIN(W1-W6) from SEQ probe responses.
        // Nmap collects these from the 6 SYN-ACK responses, NOT from T1-T6 tests.
        for (i, resp) in seq_responses.iter().enumerate() {
            let test_name = format!("T{}", i + 1);
            fingerprint.win.insert(test_name.clone(), resp.window);
        }
        // Store raw options from SEQ responses for the OPS fingerprint section
        fingerprint.seq_raw_options = seq_responses.iter().map(|r| r.raw_options.clone()).collect();

        // Drain stale packets before ECN phase (filter will change)
        drain_engine(&mut engine);

        // Send ECN probe
        debug!("Sending ECN probe to {}:{}", target, self.open_port);
        let ecn_fp = self.send_ecn_probe(target, &mut engine).await?;
        fingerprint.ecn = Some(ecn_fp);

        // Drain stale packets before T1-T7 phase (filter will change per test)
        drain_engine(&mut engine);

        // Send T1-T7 TCP tests
        debug!("Sending T1-T7 TCP tests to {}", target);
        let tcp_tests = self.send_tcp_tests(target, &mut engine).await?;
        for test in &tcp_tests {
            fingerprint.tests.insert(test.name.clone(), test.clone());
        }

        let _ = engine.stop().await;

        // Send IE (ICMP Echo) probes
        debug!("Sending IE probes to {}", target);
        let ie_fp = self.send_icmp_probes(target).await?;
        fingerprint.ie = Some(ie_fp);

        // Send U1 (UDP) probe
        debug!("Sending U1 probe to {}:{}", target, self.closed_udp_port);
        let u1_fp = self.send_udp_probe(target).await?;
        fingerprint.u1 = Some(u1_fp);

        // Analyze IP ID patterns from SEQ responses (TI)
        let ip_id_pattern = Self::analyze_ip_id_patterns(&seq_responses);
        fingerprint.ip_id = Some(ip_id_pattern);

        // Classify CI (closed port TCP IP ID sequence) from T4-T7 responses
        // These probes go to the closed port, and their IP IDs determine CI
        let tcp_closed_ip_ids: Vec<u16> = ["T4", "T5", "T6", "T7"]
            .iter()
            .filter_map(|name| {
                fingerprint
                    .tests
                    .get(*name)
                    .and_then(|t| t.ip_id)
            })
            .collect();
        if let Some(seq) = fingerprint.seq.as_mut() {
            seq.ci = Self::classify_ip_id_sequence_nmap(&tcp_closed_ip_ids);
        }

        // Classify II (ICMP IP ID sequence) from IE probe responses
        let icmp_ip_ids: Vec<u16> = fingerprint
            .ie
            .as_ref()
            .map(|ie| {
                let mut ids = Vec::new();
                if let Some(id) = ie.ip_id1 {
                    ids.push(id);
                }
                if let Some(id) = ie.ip_id2 {
                    ids.push(id);
                }
                ids
            })
            .unwrap_or_default();
        if let Some(seq) = fingerprint.seq.as_mut() {
            seq.ii = Self::classify_ip_id_sequence_nmap(&icmp_ip_ids);
        }

        // SS (Shared IP ID sequence) - both TCP and ICMP must be incremental
        if let Some(ref seq) = fingerprint.seq {
            let tcp_incr = matches!(
                seq.ti,
                IpIdSeqClass::Incremental | IpIdSeqClass::Incremental257
            );
            let icmp_incr = matches!(
                seq.ii,
                IpIdSeqClass::Incremental | IpIdSeqClass::Incremental257
            );
            let tcp_last = seq_responses.last().map(|r| r.ip_id).unwrap_or(0);
            let icmp_first = icmp_ip_ids.first().copied().unwrap_or(0);
            let tcp_first = seq_responses.first().map(|r| r.ip_id).unwrap_or(0);
            trace!(
                "SS check: tcp_incr={}, icmp_incr={}, tcp_first={}, tcp_last={}, icmp_ids={:?}",
                tcp_incr, icmp_incr, tcp_first, tcp_last, icmp_ip_ids
            );
            if tcp_incr && icmp_incr {
                let count = seq_responses.len();
                let shared = if count > 1 {
                    let avg = (u32::from(tcp_last).wrapping_sub(u32::from(tcp_first)))
                        / (count - 1) as u32;
                    let threshold = tcp_last.wrapping_add(avg.saturating_mul(3) as u16);
                    trace!("SS: avg={}, threshold={}, icmp_first={}, shared={}", avg, threshold, icmp_first, icmp_first < threshold);
                    icmp_first < threshold
                } else {
                    false
                };
                if shared {
                    if let Some(seq) = fingerprint.seq.as_mut() {
                        seq.ss = 1; // "S" = shared
                    }
                }
            }
        }

        Ok(fingerprint)
    }

    /// Build IPv6 OS fingerprint from probe responses.
    ///
    /// This implements IPv6 OS detection using similar probe techniques to IPv4,
    /// but with IPv6-specific packet structures and ICMPv6 instead of ICMP.
    #[allow(clippy::cast_possible_truncation, reason = "Flow label is 20-bit")]
    async fn build_fingerprint_v6(
        &self,
        target: Ipv6Addr,
        local_v6: Ipv6Addr,
    ) -> Result<OsFingerprint> {
        let mut fingerprint = OsFingerprint::new();

        // Create IPv6 raw socket for TCP
        let socket_tcp =
            RawSocket::with_protocol_ipv6(6).map_err(|e| crate::FingerprintError::Network {
                operation: "create IPv6 TCP socket".to_string(),
                reason: e.to_string(),
            })?;

        // Create IPv6 raw socket for ICMPv6
        let socket_icmp =
            RawSocket::with_protocol_ipv6(58).map_err(|e| crate::FingerprintError::Network {
                operation: "create IPv6 ICMP socket".to_string(),
                reason: e.to_string(),
            })?;

        // Send IPv6 SEQ probes (similar to IPv4 but with IPv6 packets)
        debug!("Sending IPv6 SEQ probes to [{}]:{}", target, self.open_port);
        let seq_responses = self
            .send_seq_probes_v6(target, local_v6, &socket_tcp)
            .await?;
        let seq_fp = self.analyze_seq_responses(&seq_responses);
        fingerprint.seq = Some(seq_fp);

        // Send IPv6 TCP tests
        debug!("Sending IPv6 TCP tests to [{}]", target);
        let tcp_tests = self
            .send_tcp_tests_v6(target, local_v6, &socket_tcp)
            .await?;
        for test in &tcp_tests {
            fingerprint.tests.insert(test.name.clone(), test.clone());
        }

        // Send ICMPv6 Echo probes
        debug!("Sending ICMPv6 Echo probes to [{}]", target);
        let ie_fp = self
            .send_icmpv6_probes(target, local_v6, &socket_icmp)
            .await?;
        fingerprint.ie = Some(ie_fp);

        // Send IPv6 UDP probe
        debug!(
            "Sending IPv6 UDP probe to [{}]:{}",
            target, self.closed_udp_port
        );
        let u1_fp = self
            .send_udp_probe_v6(target, local_v6, &socket_tcp)
            .await?;
        fingerprint.u1 = Some(u1_fp);

        // IPv6 uses flow labels instead of IP ID
        // IPv6 flow labels are typically 0 for most traffic
        fingerprint.ip_id = Some(IpIdPattern {
            zero: true,
            incremental: false,
            seq_class: IpIdSeqClass::Random,
        });

        Ok(fingerprint)
    }

    /// Send IPv6 SEQ probes to analyze TCP ISN generation.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "i is bounded by seq_count which is small"
    )]
    async fn send_seq_probes_v6(
        &self,
        target: Ipv6Addr,
        local_v6: Ipv6Addr,
        socket: &RawSocket,
    ) -> Result<Vec<SeqProbeResponse>> {
        let mut responses = Vec::with_capacity(self.seq_count);
        let src_port = Self::generate_source_port(0);

        for i in 0..self.seq_count {
            let seq = Self::generate_sequence_number() + (i as u32 * 1000);

            // Build IPv6 TCP SYN packet with options for OS detection
            let (options, window) = Self::get_probe_options(i);
            let packet = Ipv6TcpPacketBuilder::new(local_v6, target, src_port, self.open_port)
                .seq(seq)
                .syn()
                .window(window)
                .options(options)
                .build();

            let dst_sockaddr = SocketAddr::new(IpAddr::V6(target), self.open_port);

            let send_time = std::time::Instant::now();

            // Send the packet
            socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
                crate::FingerprintError::Network {
                    operation: "send IPv6 SEQ probe".to_string(),
                    reason: e.to_string(),
                }
            })?;

            // Wait for response
            let mut recv_buf = vec![0u8; 65535];
            match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
                Ok(len) if len > 0 => {
                    if let Some((flags, resp_seq, _ack, resp_src_port)) =
                        parse_ipv6_tcp_response(&recv_buf[..len])
                    {
                        // Verify this is a SYN-ACK response
                        if resp_src_port == self.open_port
                            && (flags & tcp_flags::SYN) != 0
                            && (flags & tcp_flags::ACK) != 0
                        {
                            responses.push(SeqProbeResponse {
                                isn: resp_seq,
                                ip_id: 0, // IPv6 doesn't have IP ID
                                timestamp: None,
                                window: 65535,
                                raw_options: Vec::new(),
                                send_time,
                            });
                        }
                    }
                }
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => {
                    return Err(crate::FingerprintError::Network {
                        operation: "receive IPv6 SEQ response".to_string(),
                        reason: e.to_string(),
                    });
                }
            }

            // Delay between probes
            tokio::time::sleep(self.seq_probe_delay).await;
        }

        Ok(responses)
    }

    /// Send IPv6 TCP tests (T1-T7).
    async fn send_tcp_tests_v6(
        &self,
        target: Ipv6Addr,
        local_v6: Ipv6Addr,
        socket: &RawSocket,
    ) -> Result<Vec<TestResult>> {
        let mut tests = Vec::new();
        let src_port = Self::generate_source_port(0);

        // T1: SYN to open port with options (probe set 7)
        let (options, window) = Self::get_probe_options(7);
        let packet = Ipv6TcpPacketBuilder::new(local_v6, target, src_port, self.open_port)
            .syn()
            .window(window)
            .options(options)
            .build();

        let dst_sockaddr = SocketAddr::new(IpAddr::V6(target), self.open_port);
        socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send T1 probe".to_string(),
                reason: e.to_string(),
            }
        })?;

        let mut recv_buf = vec![0u8; 65535];
        if let Ok(len) = socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            if len > 0 {
                if let Some((flags, _seq, _ack, _src_port)) =
                    parse_ipv6_tcp_response(&recv_buf[..len])
                {
                    tests.push(TestResult {
                        name: "T1".to_string(),
                        flags,
                        window: Some(65535),
                        mss: None,
                        wscale: None,
                        sack: false,
                        timestamp: false,
                        responded: flags != 0,
                        df: false,
                        ttl: None,
                        ip_id: None,
                        sent_seq: 0,
                        sent_ack: 0,
                        resp_seq: 0,
                        resp_ack: 0,
                        raw_options: Vec::new(),
                    });
                }
            }
        }

        // Additional T2-T7 tests would go here in a full implementation
        // For brevity, we implement T1 only

        Ok(tests)
    }

    /// Send ICMPv6 Echo probes.
    async fn send_icmpv6_probes(
        &self,
        target: Ipv6Addr,
        local_v6: Ipv6Addr,
        socket: &RawSocket,
    ) -> Result<IcmpTestResult> {
        let identifier = Self::generate_sequence_number() as u16;

        // Build ICMPv6 Echo Request
        let packet = Icmpv6PacketBuilder::new(local_v6, target)
            .identifier(identifier)
            .sequence(1)
            .payload(&[0u8; 56]) // Standard ping payload size
            .build();

        let dst_sockaddr = SocketAddr::new(IpAddr::V6(target), 0);
        socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send ICMPv6 echo".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Wait for response
        let mut recv_buf = vec![0u8; 65535];
        let got_response = match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            Ok(len) if len > 0 => {
                if let Some((resp_id, resp_seq)) = parse_icmpv6_echo_reply(&recv_buf[..len]) {
                    resp_id == identifier && resp_seq == 1
                } else {
                    false
                }
            }
            _ => false,
        };

        Ok(IcmpTestResult {
            responded1: got_response,
            responded2: false,
            df1: false,
            df2: false,
            ttl1: Some(64),
            ttl2: None,
            ipll: None,
            ip_id1: None,
            ip_id2: None,
            tos1: None,
            tos2: None,
            data1: None,
            data2: None,
        })
    }

    /// Send IPv6 UDP probe.
    async fn send_udp_probe_v6(
        &self,
        target: Ipv6Addr,
        local_v6: Ipv6Addr,
        socket: &RawSocket,
    ) -> Result<UdpTestResult> {
        use rustnmap_net::raw_socket::parse_ipv6_udp_response;

        let src_port = Self::generate_source_port(0);

        // Build IPv6 UDP packet
        let packet =
            Ipv6UdpPacketBuilder::new(local_v6, target, src_port, self.closed_udp_port).build();

        let dst_sockaddr = SocketAddr::new(IpAddr::V6(target), self.closed_udp_port);
        socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send IPv6 UDP probe".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Wait for response
        let mut recv_buf = vec![0u8; 65535];
        let got_response = match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            Ok(len) if len > 0 => parse_ipv6_udp_response(&recv_buf[..len]).is_some(),
            _ => false,
        };

        Ok(UdpTestResult {
            responded: got_response,
            df: false,
            ttl: None,
            ip_id: None,
            ip_len: None,
            unused: None,
            icmp_code: None,
        })
    }

    /// Send SEQ probes to analyze TCP ISN generation.
    ///
    /// Sends 6 TCP SYN probes to an open port with 100ms intervals.
    /// Each probe uses a different TCP option set and window size
    /// (matching nmap's prbOpts[0-5] and prbWindowSz[0-5]).
    /// The responses provide OPS(O1-O6) and WIN(W1-W6) fingerprint data.
    ///
    /// Uses `MmapPacketEngine` with BPF filtering to receive responses,
    /// avoiding the unrelated-traffic flooding problem of IPPROTO_TCP raw sockets.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "i is bounded by seq_count which is small"
    )]
    async fn send_seq_probes(&self, target: Ipv4Addr, engine: &mut MmapPacketEngine) -> Result<Vec<SeqProbeResponse>> {
        use rustnmap_net::raw_socket::{RawSocket, TcpPacketBuilder};

        // IPPROTO_TCP raw socket for SENDING only
        let socket =
            RawSocket::with_protocol(6).map_err(|e| crate::FingerprintError::Network {
                operation: "create raw socket for send".to_string(),
                reason: e.to_string(),
            })?;

        let base_src_port = Self::generate_source_port(0);

        let mut responses = Vec::with_capacity(self.seq_count);

        for i in 0..self.seq_count {
            // Each SEQ probe uses a different source port, option set, and window size
            let src_port = base_src_port.wrapping_add(i as u16);
            let seq = Self::generate_sequence_number() + (i as u32 * 1000);

            // Use nmap's probe option set for this probe index (0-5)
            let (options, window) = Self::get_probe_options(i);

            // BPF filter for this specific probe
            let target_nbo = u32::from_be_bytes(target.octets());
            let filter = BpfFilter::tcp_response(target_nbo, self.open_port, src_port);
            engine.set_filter(&filter.to_sock_fprog()).map_err(|e| {
                crate::FingerprintError::Network {
                    operation: format!("set BPF filter for SEQ probe {i}"),
                    reason: e.to_string(),
                }
            })?;

            drain_engine(engine);

            let packet =
                TcpPacketBuilder::new(self.local_addr_v4, target, src_port, self.open_port)
                    .seq(seq)
                    .syn()
                    .window(window)
                    .options(options)
                    .build();

            let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), self.open_port);

            let send_time = std::time::Instant::now();

            // Send via RawSocket
            socket
                .send_packet(&packet, &dst_sockaddr)
                .map_err(|e| crate::FingerprintError::Network {
                    operation: "send SEQ probe".to_string(),
                    reason: e.to_string(),
                })?;

            // Receive via MmapPacketEngine with BPF filter
            debug!("SEQ probe {i}: waiting for response (timeout={:?})", self.timeout);
            if let Some(data) =
                recv_tcp_response_bpf(engine, self.open_port, src_port, self.timeout)?
            {
                let response = data.response;
                if (response.flags & tcp_flags::SYN) != 0
                    && (response.flags & tcp_flags::ACK) != 0
                {
                    responses.push(SeqProbeResponse {
                        isn: response.seq,
                        ip_id: response.ip_id,
                        timestamp: response.options.timestamp_value,
                        window: response.window,
                        raw_options: data.raw_options,
                        send_time,
                    });
                }
            }

            // Wait 100ms between probes (as per Nmap spec)
            if i < self.seq_count - 1 {
                tokio::time::sleep(self.seq_probe_delay).await;
            }
        }

        Ok(responses)
    }

    /// Analyze SEQ probe responses to determine ISN characteristics.
    #[allow(
        clippy::unused_self,
        reason = "Intentional: API consistency for potential future instance-based analysis"
    )]
    fn analyze_seq_responses(&self, responses: &[SeqProbeResponse]) -> SeqFingerprint {
        let mut fp = SeqFingerprint::new();

        if responses.len() < 2 {
            return fp;
        }

        // Extract ISN values
        let isns: Vec<u32> = responses.iter().map(|r| r.isn).collect();

        // Calculate differences between consecutive ISNs using nmap's MOD_DIFF
        // MOD_DIFF(a,b) = MIN(a - b, b - a) - takes the shorter wrap-around distance
        let diffs: Vec<u32> = isns
            .windows(2)
            .map(|w| {
                let fwd = w[1].wrapping_sub(w[0]);
                let bwd = w[0].wrapping_sub(w[1]);
                fwd.min(bwd)
            })
            .collect();

        // Calculate GCD of differences
        let gcd = Self::calculate_gcd_list(&diffs);
        fp.gcd = gcd;

        // Determine ISN class based on GCD and differences
        fp.class = Self::classify_isn_pattern(&isns, &diffs, gcd);

        // Calculate ISR and SP using nmap's time-based formulas
        // Requires >= 4 responses (matching nmap's check in osscan2.cc)
        if responses.len() >= 4 {
            let (isr, sp) = Self::calculate_isr_sp(responses, &diffs, gcd);
            fp.isr = isr;
            fp.sp = sp;
        }

        // Analyze timestamps
        let timestamps: Vec<u32> = responses.iter().filter_map(|r| r.timestamp).collect();
        fp.timestamps.clone_from(&timestamps);

        // Debug: log ISN values and diffs for ISR/SP analysis
        for (i, r) in responses.iter().enumerate() {
            trace!(
                "SEQ response {}: ISN=0x{:08X}, ip_id={}, window={}, timestamp={:?}, send_time={:?}",
                i, r.isn, r.ip_id, r.window, r.timestamp, r.send_time.elapsed()
            );
        }
        for (i, &d) in diffs.iter().enumerate() {
            let td = responses[i + 1].send_time.duration_since(responses[i].send_time);
            trace!("SEQ diff {}: 0x{:08X} ({}) time_delta={:?}", i, d, d, td);
        }

        if !timestamps.is_empty() {
            fp.timestamp = true;
            fp.ts_val = Self::classify_timestamp_rate_with_time(responses);
        }

        // Analyze IP ID patterns using nmap's get_diffs/identify_sequence algorithm
        let ip_ids: Vec<u16> = responses.iter().map(|r| r.ip_id).collect();
        fp.ti = Self::classify_ip_id_sequence_nmap(&ip_ids);

        trace!("SEQ analysis: GCD={}, ISR={}, SP={}", fp.gcd, fp.isr, fp.sp);

        fp
    }

    /// Calculate ISR and SP using nmap's exact formulas from osscan2.cc.
    ///
    /// ISR = round(log2(avg_isn_rate_per_sec) * 8)
    /// SP = round(log2(stddev_of_isn_rates) * 8)
    ///
    /// When GCD > 9, rates are divided by GCD before computing stddev
    /// (matching nmap's compromise to avoid artificial low values).
    #[allow(
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        reason = "ISR/SP are clamped to u8 range after float calculation"
    )]
    fn calculate_isr_sp(
        responses: &[SeqProbeResponse],
        diffs: &[u32],
        gcd: u32,
    ) -> (u8, u8) {
        // Calculate individual ISN rates (per second) using actual time deltas
        let mut rates: Vec<f64> = Vec::with_capacity(diffs.len());
        for i in 0..diffs.len() {
            let time_delta =
                responses[i + 1].send_time.duration_since(responses[i].send_time);
            let usec = time_delta.as_micros() as f64;
            // nmap: if time delta is 0, set to 1 to avoid division by zero
            let usec = if usec < 1.0 { 1.0 } else { usec };
            // Rate = diff * 1_000_000 / usec (ISN per second)
            rates.push(f64::from(diffs[i]) * 1_000_000.0 / usec);
        }

        if rates.is_empty() {
            return (0, 0);
        }

        // ISR: average rate, then round(log2(avg) * 8)
        let avg_rate: f64 = rates.iter().sum::<f64>() / rates.len() as f64;

        if gcd == 0 {
            // Constant ISN (all same)
            return (0, 0);
        }

        let isr = (avg_rate.log2() * 8.0 + 0.5).clamp(0.0, 255.0) as u8;

        // SP: stddev of rates (optionally divided by GCD), then round(log2(stddev) * 8)
        // nmap: divide by GCD if > 9 to avoid artificial low values
        let div_gcd = if gcd > 9 { f64::from(gcd) } else { 1.0 };
        let avg_rate_div = avg_rate / div_gcd;

        // Use population variance with (N-1) denominator (nmap uses responses - 2)
        // since we have (responses - 1) diffs and divide by (responses - 2)
        let sum_sq: f64 = rates
            .iter()
            .map(|&r| {
                let diff = r / div_gcd - avg_rate_div;
                diff * diff
            })
            .sum();

        // nmap divides by (responses - 2) which equals rates.len() - 1
        let n = rates.len();
        let variance = if n > 1 { sum_sq / (n - 1) as f64 } else { 0.0 };
        let stddev = variance.sqrt();

        let sp = if stddev <= 1.0 {
            0
        } else {
            (stddev.log2() * 8.0 + 0.5).clamp(0.0, 255.0) as u8
        };

        (isr, sp)
    }

    /// Classify IP ID sequence using nmap's get_diffs + identify_sequence algorithm.
    ///
    /// Steps (from nmap osscan2.cc):
    /// 1. Calculate u32 diffs between consecutive IP IDs
    /// 2. If any diff > 20000, classify as Random
    /// 3. If all IP IDs are zero, classify as Fixed (Z)
    /// 4. Otherwise run identify_sequence:
    ///    - All diffs == 0 → Constant (rare, but maps to hex value)
    ///    - Any diff > 1000 (not mult of 256 or >= 25600) → Random Positive Increments (RI)
    ///    - All diffs mult of 256 and <= 5120 → Broken Incremental (BI)
    ///    - All diffs mult of 2 → Incremental by 2 (I)
    ///    - All diffs < 10 → Incremental (I)
    ///    - Otherwise → Unknown
    #[allow(clippy::cast_possible_wrap, reason = "u16 diff wrapping is intentional")]
    fn classify_ip_id_sequence_nmap(ip_ids: &[u16]) -> IpIdSeqClass {
        if ip_ids.len() < 2 {
            return IpIdSeqClass::Unknown;
        }

        // Calculate u32 diffs (wrapping subtraction, masked to 16-bit)
        let diffs: Vec<u32> = ip_ids
            .windows(2)
            .map(|w| {
                let diff = u32::from(w[1]).wrapping_sub(u32::from(w[0]));
                diff & 0xFFFF // Mask to 16-bit range as nmap does
            })
            .collect();

        // Step 1: Check for Random (any diff > 20000)
        for &diff in &diffs {
            if diff > 20000 {
                return IpIdSeqClass::Random;
            }
        }

        // Step 2: Check if all zeros
        if ip_ids.iter().all(|&id| id == 0) {
            return IpIdSeqClass::Fixed;
        }

        // Step 3: identify_sequence algorithm

        // Check for Constant (all diffs zero) - before other checks
        // In nmap this returns IPID_SEQ_CONSTANT which maps to hex value of ipids[0]
        // We use Fixed since we don't have a separate Constant variant
        if diffs.iter().all(|&d| d == 0) {
            return IpIdSeqClass::Fixed;
        }

        // Check for Random Positive Increments (any diff > 1000 and
        // (not mult of 256 OR >= 25600))
        for &diff in &diffs {
            if diff > 1000 && (diff % 256 != 0 || diff >= 25600) {
                return IpIdSeqClass::Random; // Maps to RI in nmap, but we use Random
            }
        }

        // Check flags for remaining classifications
        let all_mult_256_and_le_5120 = diffs.iter().all(|&d| d <= 5120 && d % 256 == 0);
        if all_mult_256_and_le_5120 {
            return IpIdSeqClass::Incremental257; // Broken Incremental (BI)
        }

        let all_even = diffs.iter().all(|&d| d % 2 == 0);
        if all_even {
            // Incremental by 2 - maps to I in nmap
            return IpIdSeqClass::Incremental;
        }

        let all_small = diffs.iter().all(|&d| d < 10);
        if all_small {
            return IpIdSeqClass::Incremental;
        }

        IpIdSeqClass::Unknown
    }

    /// Calculate GCD of a list of numbers.
    fn calculate_gcd_list(nums: &[u32]) -> u32 {
        if nums.is_empty() {
            return 0;
        }
        if nums.len() == 1 {
            return nums[0];
        }

        nums.iter().copied().reduce(Self::gcd).unwrap_or(0)
    }

    /// Calculate GCD of two numbers using Euclidean algorithm.
    fn gcd(mut a: u32, mut b: u32) -> u32 {
        while b != 0 {
            let temp = b;
            b = a % b;
            a = temp;
        }
        a
    }

    /// Classify ISN generation pattern.
    #[allow(
        clippy::cast_lossless,
        reason = "u32 to u64 is always safe, no precision loss"
    )]
    fn classify_isn_pattern(_isns: &[u32], diffs: &[u32], gcd: u32) -> IsnClass {
        // Check for zero differences (all same ISN)
        if diffs.iter().all(|&d| d == 0) {
            return IsnClass::Incremental { increment: 0 };
        }

        // Check if all differences are the same (incremental)
        let first_diff = diffs[0];
        if diffs.iter().all(|&d| d == first_diff) {
            return IsnClass::Incremental {
                increment: first_diff,
            };
        }

        // Check for time-based (large differences)
        #[allow(clippy::cast_possible_truncation)]
        let avg_diff = diffs.iter().map(|&d| u64::from(d)).sum::<u64>() / diffs.len() as u64;
        if avg_diff > 10_000_000 {
            return IsnClass::Time;
        }

        // Check for GCD-based (differences are multiples of GCD)
        if gcd > 1 && gcd < 1000 {
            return IsnClass::Gcd { gcd };
        }

        // Check for random (high variance)
        let variance = Self::calculate_variance(diffs);
        if variance > 1_000_000_000 {
            return IsnClass::Random;
        }

        IsnClass::Unknown
    }

    /// Calculate variance of a slice of numbers.
    #[allow(
        clippy::cast_lossless,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "Mathematical calculations with verified ranges"
    )]
    fn calculate_variance(nums: &[u32]) -> u64 {
        if nums.len() < 2 {
            return 0;
        }
        let mean = nums.iter().map(|&n| u64::from(n)).sum::<u64>() / nums.len() as u64;
        let sum_sq_diff: u64 = nums
            .iter()
            .map(|&n| {
                let diff = i64::from(n) - mean as i64;
                (diff * diff) as u64
            })
            .sum();
        sum_sq_diff / nums.len() as u64
    }

    /// Classify timestamp rate using actual time deltas between probes.
    ///
    /// Matches nmap's algorithm from osscan2.cc:
    /// - avg_hz <= 5.66 → 1
    /// - 70 < avg_hz <= 150 → 7
    /// - 150 < avg_hz <= 350 → 8
    /// - else → round(log2(avg_hz))
    ///
    /// Returns the raw integer value that nmap outputs as hex in TS field.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "log2 result fits in u8 for realistic Hz values"
    )]
    fn classify_timestamp_rate_with_time(responses: &[SeqProbeResponse]) -> u8 {
        let timestamps: Vec<(u32, std::time::Instant)> = responses
            .iter()
            .filter_map(|r| r.timestamp.map(|ts| (ts, r.send_time)))
            .collect();

        if timestamps.len() < 2 {
            return 0;
        }

        // Calculate average Hz using actual time deltas
        let mut avg_hz = 0.0;
        let mut count = 0;
        for w in timestamps.windows(2) {
            let ts_diff = f64::from(w[1].0.wrapping_sub(w[0].0));
            let time_usec = w[1]
                .1
                .duration_since(w[0].1)
                .as_micros() as f64;
            if time_usec > 0.0 {
                avg_hz += ts_diff / (time_usec / 1_000_000.0);
                count += 1;
            }
        }

        if count == 0 {
            return 0;
        }

        avg_hz /= count as f64;

        // nmap's classification thresholds from osscan2.cc lines 2528-2547
        if avg_hz <= 5.66 {
            1
        } else if avg_hz > 70.0 && avg_hz <= 150.0 {
            7
        } else if avg_hz > 150.0 && avg_hz <= 350.0 {
            8
        } else {
            (0.5 + (avg_hz.ln() / 2.0_f64.ln())) as u8
        }
    }

    /// Analyze IP ID patterns from SEQ responses.
    fn analyze_ip_id_patterns(responses: &[SeqProbeResponse]) -> IpIdPattern {
        let ip_ids: Vec<u16> = responses.iter().map(|r| r.ip_id).collect();

        IpIdPattern {
            zero: ip_ids.iter().all(|&id| id == 0),
            incremental: ip_ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1)),
            seq_class: Self::classify_ip_id_sequence_nmap(&ip_ids),
        }
    }

    /// Send ECN probe.
    ///
    /// Sends a TCP SYN packet with ECN flags (ECE and CWR) set.
    /// Uses `MmapPacketEngine` with BPF filtering to receive the response.
    #[allow(clippy::unused_async)]
    async fn send_ecn_probe(&self, target: Ipv4Addr, engine: &mut MmapPacketEngine) -> Result<EcnFingerprint> {
        use rustnmap_net::raw_socket::{RawSocket, TcpPacketBuilder};

        // IPPROTO_TCP raw socket for SENDING only
        let socket =
            RawSocket::with_protocol(6).map_err(|e| crate::FingerprintError::Network {
                operation: "create raw socket for send".to_string(),
                reason: e.to_string(),
            })?;

        let src_port = Self::generate_source_port(1);
        let seq = Self::generate_sequence_number();

        // ECN probe uses option set 6 (no timestamp) and window=3 (per nmap)
        let (options, window) = Self::get_probe_options(6);
        let packet = TcpPacketBuilder::new(self.local_addr_v4, target, src_port, self.open_port)
            .seq(seq)
            .syn()
            .window(window)
            .options(options)
            .build();

        // Modify packet to set ECN flags (ECE=0x40, CWR=0x80)
        let mut packet = packet;
        let ip_header_len = 20;
        let tcp_flags_offset = ip_header_len + 13;
        packet[tcp_flags_offset] |= tcp_flags::ECE | tcp_flags::CWR;

        // Zero checksum field before recalculating (RFC 1071: checksum is
        // computed over the segment with the checksum field set to zero).
        // Without this, the old checksum value is included in the sum,
        // producing an incorrect result (~0xFFFF = 0x0000).
        packet[ip_header_len + 16] = 0;
        packet[ip_header_len + 17] = 0;
        let tcp_checksum = Self::recalculate_tcp_checksum(&packet, ip_header_len);
        packet[ip_header_len + 16] = (tcp_checksum >> 8) as u8;
        packet[ip_header_len + 17] = (tcp_checksum & 0xFF) as u8;

        // BPF filter: capture TCP from target:open_port -> local:src_port
        let target_nbo = u32::from_be_bytes(target.octets());
        let filter = BpfFilter::tcp_response(target_nbo, self.open_port, src_port);
        engine.set_filter(&filter.to_sock_fprog()).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "set BPF filter for ECN probe".to_string(),
                reason: e.to_string(),
            }
        })?;

        let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), self.open_port);

        socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| crate::FingerprintError::Network {
                operation: "send ECN probe".to_string(),
                reason: e.to_string(),
            })?;

        let mut fp = EcnFingerprint::new();

        if let Some(data) =
            recv_tcp_response_bpf(engine, self.open_port, src_port, self.timeout)?
        {
            let response = data.response;
            fp.ece = (response.flags & tcp_flags::ECE) != 0;
            fp.cwr = (response.flags & tcp_flags::CWR) != 0;
            fp.df = response.df;
            fp.ttl = Some(response.ttl);
            fp.window = Some(response.window);
            fp.raw_options = data.raw_options;
        }

        Ok(fp)
    }

    /// Recalculate TCP checksum after modifying flags.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Checksum calculation: sum is guaranteed to fit in u16 after reduction"
    )]
    fn recalculate_tcp_checksum(packet: &[u8], ip_header_len: usize) -> u16 {
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let tcp_segment = &packet[ip_header_len..];

        let mut sum = 0u32;

        // Pseudo-header: source IP
        for octet in src_ip.octets().chunks(2) {
            sum += u32::from(u16::from_be_bytes([octet[0], octet[1]]));
        }
        // Pseudo-header: destination IP
        for octet in dst_ip.octets().chunks(2) {
            sum += u32::from(u16::from_be_bytes([octet[0], octet[1]]));
        }
        // Pseudo-header: protocol (TCP = 6)
        sum += 6u32;
        // Pseudo-header: TCP segment length
        sum += u32::try_from(tcp_segment.len()).unwrap_or(0);

        // TCP segment
        let len = tcp_segment.len();
        for i in (0..len).step_by(2) {
            if i + 1 < len {
                sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
            } else {
                sum += u32::from(tcp_segment[i]) << 8;
            }
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Send T1-T7 TCP test probes using pipelined send-then-collect.
    ///
    /// All 7 probes are sent first, then responses are collected in a single
    /// receive loop. This reduces total probe time from 7*RTT to 1-2*RTT,
    /// matching nmap's cwnd-based parallel probe approach.
    ///
    /// T1: SYN to open port (standard)
    /// T2: NULL to open port (no flags)
    /// T3: SYN+FIN+PSH+URG to open port
    /// T4: ACK to closed port
    /// T5: SYN to closed port
    /// T6: ACK to closed port
    /// T7: FIN+PSH+URG to closed port
    #[allow(clippy::unused_async)]
    async fn send_tcp_tests(&self, target: Ipv4Addr, engine: &mut MmapPacketEngine) -> Result<Vec<TestResult>> {
        use rustnmap_net::raw_socket::{RawSocket, TcpPacketBuilder};

        let tests = [
            ("T1", self.open_port, tcp_flags::SYN),
            ("T2", self.open_port, 0), // NULL
            (
                "T3",
                self.open_port,
                tcp_flags::SYN | tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG,
            ),
            ("T4", self.closed_port, tcp_flags::ACK),
            ("T5", self.closed_port, tcp_flags::SYN),
            ("T6", self.closed_port, tcp_flags::ACK),
            (
                "T7",
                self.closed_port,
                tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG,
            ),
        ];

        // Set broad BPF filter: accept any TCP from target IP, match ports in software
        let target_nbo = u32::from_be_bytes(target.octets());
        let filter = BpfFilter::tcp_response_from_ip(target_nbo);
        engine.set_filter(&filter.to_sock_fprog()).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "set broad BPF filter for T1-T7".to_string(),
                reason: e.to_string(),
            }
        })?;
        drain_engine(engine);

        // Single RawSocket reused for all probes
        let socket = RawSocket::with_protocol(6).map_err(|e| crate::FingerprintError::Network {
            operation: "create socket for T1-T7".to_string(),
            reason: e.to_string(),
        })?;

        // Phase 1: Build and send all probes
        struct ProbeInfo {
            name: &'static str,
            src_port: u16,
            dst_port: u16,
            sent_seq: u32,
        }

        let mut probe_infos: Vec<ProbeInfo> = Vec::with_capacity(tests.len());

        for (test_idx, (name, port, flags)) in tests.iter().enumerate() {
            let src_port = Self::generate_source_port(2 + test_idx as u16);
            let seq = Self::generate_sequence_number();
            let (options, window) = Self::get_probe_options(7 + test_idx);

            let packet = TcpPacketBuilder::new(self.local_addr_v4, target, src_port, *port)
                .seq(seq)
                .window(window)
                .options(options)
                .build();

            let mut packet = packet;
            let ip_header_len = 20;
            packet[ip_header_len + 13] = *flags;

            // Recalculate checksum
            packet[ip_header_len + 16] = 0;
            packet[ip_header_len + 17] = 0;
            let tcp_checksum = Self::recalculate_tcp_checksum(&packet, ip_header_len);
            packet[ip_header_len + 16] = (tcp_checksum >> 8) as u8;
            packet[ip_header_len + 17] = (tcp_checksum & 0xFF) as u8;

            let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), *port);
            socket
                .send_packet(&packet, &dst_sockaddr)
                .map_err(|e| crate::FingerprintError::Network {
                    operation: format!("send {name} probe"),
                    reason: e.to_string(),
                })?;
            debug!("TCP test {name}: sent flags=0x{flags:02x} to {target}:{port} from :{src_port}");

            probe_infos.push(ProbeInfo {
                name,
                src_port,
                dst_port: *port,
                sent_seq: seq,
            });
        }

        // Phase 2: Collect all responses in a single receive loop
        let mut results: Vec<(String, TestResult)> = Vec::with_capacity(tests.len());
        let deadline = std::time::Instant::now() + self.timeout;
        let poll_interval = Duration::from_millis(1);

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match engine.try_recv_zero_copy() {
                Ok(Some(pkt)) => {
                    let d = pkt.data();
                    if d.len() > ETH_HEADER_LEN {
                        let ip_data = &d[ETH_HEADER_LEN..];
                        if let Some(response) = rustnmap_net::raw_socket::parse_tcp_response_full(ip_data) {
                            // Match response to probe by src_port (target's src = our dst_port)
                            if let Some(info) = probe_infos
                                .iter()
                                .find(|p| response.src_port == p.dst_port && response.dst_port == p.src_port)
                            {
                                // Check if we already have a result for this probe
                                let already_matched = results.iter().any(|(n, _)| n == info.name);
                                if !already_matched {
                                    debug!(
                                        "TCP test {}: GOT RESPONSE flags=0x{:02x} sp={} dp={} win={}",
                                        info.name, response.flags, response.src_port,
                                        response.dst_port, response.window
                                    );

                                    let mut result = TestResult::new(info.name);
                                    result.sent_seq = info.sent_seq;
                                    result = result
                                        .with_flags(response.flags)
                                        .with_window(response.window)
                                        .with_ip_fields(response.df, response.ttl, response.ip_id);
                                    result.mss = response.options.mss;
                                    result.wscale = response.options.wscale;
                                    result.sack = response.options.sack;
                                    result.timestamp = response.options.timestamp;
                                    result.resp_seq = response.seq;
                                    result.resp_ack = response.ack;

                                    // Extract raw TCP options
                                    let ip_hlen = (ip_data[0] & 0x0F) as usize * 4;
                                    let raw_options = if ip_data.len() >= ip_hlen + 20 {
                                        let tcp_doff =
                                            (ip_data[ip_hlen + 12] >> 4) as usize * 4;
                                        if tcp_doff > 20 && ip_data.len() >= ip_hlen + tcp_doff {
                                            ip_data[ip_hlen + 20..ip_hlen + tcp_doff].to_vec()
                                        } else {
                                            Vec::new()
                                        }
                                    } else {
                                        Vec::new()
                                    };
                                    result.raw_options = raw_options;

                                    results.push((info.name.to_string(), result));

                                    // Early exit if all probes have responses
                                    if results.len() == tests.len() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(None) => {
                    std::thread::sleep(poll_interval);
                }
                Err(_) => {
                    std::thread::sleep(poll_interval);
                }
            }
        }

        // Build final results in original order, filling in missing probes
        let mut final_results = Vec::with_capacity(tests.len());
        for (name, _port, _flags) in &tests {
            if let Some(pos) = results.iter().position(|(n, _)| n == *name) {
                final_results.push(results.remove(pos).1);
            } else {
                debug!("TCP test {name}: NO RESPONSE");
                let mut result = TestResult::new(*name);
                result.sent_seq = probe_infos.iter().find(|p| p.name == *name).map(|p| p.sent_seq).unwrap_or(0);
                final_results.push(result);
            }
        }

        Ok(final_results)
    }

    /// Send IE (ICMP Echo) probes.
    ///
    /// Sends 2 ICMP echo requests with different IP options.
    #[allow(clippy::unused_async)]
    async fn send_icmp_probes(&self, target: Ipv4Addr) -> Result<IcmpTestResult> {
        use rustnmap_net::raw_socket::{IcmpPacketBuilder, RawSocket};

        // Use IPPROTO_ICMP (1) for receiving ICMP responses
        let socket = RawSocket::with_protocol(1).map_err(|e| crate::FingerprintError::Network {
            operation: "create raw socket".to_string(),
            reason: e.to_string(),
        })?;

        let mut result = IcmpTestResult::new();

        // Send first ICMP echo request
        let packet1 = IcmpPacketBuilder::new(self.local_addr_v4, target)
            .identifier(0x1234)
            .sequence(0)
            .payload(&[0u8; 120]) // Nmap uses 120 bytes of payload
            .build();

        let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), 0);

        socket.send_packet(&packet1, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send IE probe 1".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Wait for response
        let mut recv_buf = vec![0u8; 65535];
        match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            Ok(len) if len > 0 => {
                if let Some((id, seq)) =
                    rustnmap_net::raw_socket::parse_icmp_echo_reply(&recv_buf[..len])
                {
                    if id == 0x1234 && seq == 0 {
                        // Parse IP header fields from response
                        let df = (recv_buf[6] & 0x40) != 0;
                        let ttl = recv_buf[8];
                        let ip_id = u16::from_be_bytes([recv_buf[4], recv_buf[5]]);
                        let tos = recv_buf[1];
                        // Total length includes IP header + ICMP header + payload
                        let total_len = u16::from_be_bytes([recv_buf[2], recv_buf[3]]);
                        let data_len = total_len.saturating_sub(28); // IP(20) + ICMP(8)

                        result = result.with_response1(df, ttl, ip_id, tos, data_len);
                    }
                }
            }
            Ok(_) | Err(_) => {}
        }

        // Send second ICMP echo request with different payload
        let packet2 = IcmpPacketBuilder::new(self.local_addr_v4, target)
            .identifier(0x1234)
            .sequence(1)
            .payload(&[0xFFu8; 150]) // Different payload size and content
            .build();

        socket.send_packet(&packet2, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send IE probe 2".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Wait for response
        match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            Ok(len) if len > 0 => {
                if let Some((id, seq)) =
                    rustnmap_net::raw_socket::parse_icmp_echo_reply(&recv_buf[..len])
                {
                    if id == 0x1234 && seq == 1 {
                        let df = (recv_buf[6] & 0x40) != 0;
                        let ttl = recv_buf[8];
                        let ip_id = u16::from_be_bytes([recv_buf[4], recv_buf[5]]);
                        let tos = recv_buf[1];
                        let total_len = u16::from_be_bytes([recv_buf[2], recv_buf[3]]);
                        let data_len = total_len.saturating_sub(28);

                        result = result.with_response2(df, ttl, ip_id, tos, data_len);
                    }
                }
            }
            Ok(_) | Err(_) => {}
        }

        Ok(result)
    }

    /// Send U1 UDP probe.
    ///
    /// Sends a UDP packet to a closed port and analyzes the ICMP response.
    #[allow(clippy::unused_async)]
    async fn send_udp_probe(&self, target: Ipv4Addr) -> Result<UdpTestResult> {
        use rustnmap_net::raw_socket::{RawSocket, UdpPacketBuilder};

        // Use IPPROTO_ICMP (1) for receiving ICMP responses (Port Unreachable)
        let socket = RawSocket::with_protocol(1).map_err(|e| crate::FingerprintError::Network {
            operation: "create raw socket".to_string(),
            reason: e.to_string(),
        })?;

        let src_port = Self::generate_source_port(3);

        // Build UDP packet with specific payload (Nmap uses 300 bytes)
        let payload = vec![0x41u8; 300]; // 'A' repeated 300 times
        let packet =
            UdpPacketBuilder::new(self.local_addr_v4, target, src_port, self.closed_udp_port)
                .payload(&payload)
                .build();

        let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), self.closed_udp_port);

        socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send U1 probe".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Wait for ICMP response
        let mut recv_buf = vec![0u8; 65535];
        let mut result = UdpTestResult::new();

        match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            Ok(len) if len > 0 => {
                if let Some(rustnmap_net::raw_socket::IcmpResponse::DestinationUnreachable {
                    code,
                    original_dst_ip: _,
                    original_dst_port: _,
                }) = rustnmap_net::raw_socket::parse_icmp_response(&recv_buf[..len])
                {
                    let df = (recv_buf[6] & 0x40) != 0;
                    let ttl = recv_buf[8];
                    let ip_id = u16::from_be_bytes([recv_buf[4], recv_buf[5]]);
                    let total_len = u16::from_be_bytes([recv_buf[2], recv_buf[3]]);

                    result = result
                        .with_icmp_response(code.into())
                        .with_ip_fields(df, ttl, ip_id, total_len);
                }
            }
            Ok(_) | Err(_) => {}
        }

        Ok(result)
    }

    /// Get probe options and window size by index from the nmap probe table.
    ///
    /// Indices 0-5: SEQ/OPS/WIN probes
    /// Index 6: ECN probe
    /// Indices 7-12: T1-T7 probes
    fn get_probe_options(index: usize) -> (&'static [u8], u16) {
        if index < PROBE_OPTIONS.len() {
            PROBE_OPTIONS[index]
        } else {
            // Fallback: use T1 options
            PROBE_OPTIONS[7]
        }
    }

    /// Generates a source port with a group offset.
    ///
    /// Each probe group (SEQ, ECN, T1-T7) uses a different offset to avoid
    /// kernel TCP state interference from earlier probes.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Process ID modulo 20000 fits in u16 range"
    )]
    fn generate_source_port(group_offset: u16) -> u16 {
        let base = 40000 + (std::process::id() % 20000) as u16;
        base.wrapping_add(group_offset * SRC_PORT_OFFSET_PER_GROUP)
    }

    /// Generates a random initial sequence number.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Using lower 32 bits of nanosecond timestamp for sequence number"
    )]
    fn generate_sequence_number() -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        (now as u32).wrapping_add(std::process::id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_new() {
        let db = FingerprintDatabase::empty();
        let local_addr = Ipv4Addr::LOCALHOST;
        let detector = OsDetector::new(db, local_addr);

        assert_eq!(detector.seq_count, 6);
    }

    #[test]
    fn test_with_seq_count() {
        let db = FingerprintDatabase::empty();
        let local_addr = Ipv4Addr::LOCALHOST;
        let detector = OsDetector::new_with_ref(&db, local_addr).with_seq_count(15);

        assert_eq!(detector.seq_count, 15);
    }

    #[test]
    fn test_seq_count_clamp() {
        let db = FingerprintDatabase::empty();
        let local_addr = Ipv4Addr::LOCALHOST;
        let detector = OsDetector::new_with_ref(&db, local_addr).with_seq_count(30);

        assert_eq!(detector.seq_count, 20); // Clamped to max

        let detector = OsDetector::new_with_ref(&db, local_addr).with_seq_count(0);
        assert_eq!(detector.seq_count, 1); // Clamped to min
    }

    #[test]
    fn test_gcd_calculation() {
        assert_eq!(OsDetector::gcd(48, 18), 6);
        assert_eq!(OsDetector::gcd(100, 35), 5);
        assert_eq!(OsDetector::gcd(7, 13), 1);
        assert_eq!(OsDetector::gcd(0, 5), 5);
    }

    #[test]
    fn test_calculate_gcd_list() {
        assert_eq!(OsDetector::calculate_gcd_list(&[48, 18, 30]), 6);
        assert_eq!(OsDetector::calculate_gcd_list(&[100, 35, 50]), 5);
        assert_eq!(OsDetector::calculate_gcd_list(&[7, 13, 19]), 1);
    }

    #[test]
    fn test_classify_isn_pattern() {
        // Test incremental pattern
        let isns: Vec<u32> = vec![1000, 2000, 3000, 4000];
        let diffs: Vec<u32> = isns.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
        let pattern = OsDetector::classify_isn_pattern(&isns, &diffs, 1000);
        assert!(matches!(pattern, IsnClass::Incremental { increment: 1000 }));

        // Test random pattern (high variance - values spanning large range)
        let isns: Vec<u32> = vec![1000, 4_000_000_000, 2_000_000_000, 3_500_000_000];
        let diffs: Vec<u32> = isns.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
        let pattern = OsDetector::classify_isn_pattern(&isns, &diffs, 1);
        // High variance should classify as Random
        assert!(matches!(pattern, IsnClass::Random | IsnClass::Time));
    }

    #[test]
    fn test_classify_ip_id_sequence_nmap() {
        // Test incremental (diffs all < 10)
        let ip_ids = vec![100, 101, 102, 103];
        assert_eq!(
            OsDetector::classify_ip_id_sequence_nmap(&ip_ids),
            IpIdSeqClass::Incremental
        );

        // Test constant (all same non-zero) - all diffs are 0
        // Matches nmap's IPID_SEQ_CONSTANT check before other classifications
        let ip_ids = vec![100, 100, 100, 100];
        assert_eq!(
            OsDetector::classify_ip_id_sequence_nmap(&ip_ids),
            IpIdSeqClass::Fixed
        );

        // Test zeros (fixed)
        let ip_ids = vec![0, 0, 0, 0];
        assert_eq!(
            OsDetector::classify_ip_id_sequence_nmap(&ip_ids),
            IpIdSeqClass::Fixed
        );

        // Test random (diff > 20000)
        let ip_ids = vec![100, 50000, 200, 30000];
        assert_eq!(
            OsDetector::classify_ip_id_sequence_nmap(&ip_ids),
            IpIdSeqClass::Random
        );

        // Test broken incremental (diffs are mult of 256, <= 5120)
        // e.g., 0x0001, 0x0101, 0x0201 → diffs = 0x0100 (256)
        let ip_ids: Vec<u16> = vec![0x0001, 0x0101, 0x0201, 0x0301];
        assert_eq!(
            OsDetector::classify_ip_id_sequence_nmap(&ip_ids),
            IpIdSeqClass::Incremental257
        );

        // Test incremental by 2 (all diffs even but not all mult of 256)
        let ip_ids = vec![100, 102, 104, 106];
        assert_eq!(
            OsDetector::classify_ip_id_sequence_nmap(&ip_ids),
            IpIdSeqClass::Incremental
        );
    }

    #[test]
    fn test_probe_options_table() {
        // Verify probe option sets are defined correctly
        assert_eq!(PROBE_OPTIONS.len(), 13); // 6 SEQ + 1 ECN + 6 T1-T7

        // SEQ probe 0: WScale(10), NOP, MSS(1460), Timestamp, SACK, win=1
        let (opts, win) = OsDetector::get_probe_options(0);
        assert_eq!(win, 1);
        assert!(!opts.is_empty());

        // ECN probe: win=3
        let (_, win) = OsDetector::get_probe_options(6);
        assert_eq!(win, 3);

        // T1: win=128
        let (_, win) = OsDetector::get_probe_options(7);
        assert_eq!(win, 128);
    }
}
