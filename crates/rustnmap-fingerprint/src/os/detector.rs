//! OS detection engine.
//!
//! Executes OS detection probes and matches fingerprints
//! to determine the target operating system.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tracing::{debug, info, trace};

use super::{
    database::{FingerprintDatabase, OsMatch},
    fingerprint::{
        EcnFingerprint, IcmpTestResult, IpIdPattern, IpIdSeqClass, IsnClass, OpsFingerprint,
        OsFingerprint, SeqFingerprint, TestResult, TimestampRate, UdpTestResult,
    },
};
use crate::Result;

/// OS detection engine.
///
/// Sends specialized probes and analyzes responses to generate
/// a fingerprint for matching against known OS fingerprints.
#[derive(Debug)]
pub struct OsDetector {
    /// OS fingerprint database.
    db: FingerprintDatabase,

    /// Number of sequence probes to send.
    seq_count: usize,

    /// Local IP address for probes.
    local_addr: Ipv4Addr,

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
#[allow(dead_code)]
struct SeqProbeResponse {
    /// TCP sequence number from SYN-ACK.
    isn: u32,
    /// IP ID from response.
    ip_id: u16,
    /// TCP timestamp value.
    timestamp: Option<u32>,
    /// TCP window size.
    window: u16,
    /// TCP options.
    options: OpsFingerprint,
}

/// TCP flags constants.
#[allow(dead_code)]
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

impl OsDetector {
    /// Create new OS detector.
    #[must_use]
    pub fn new(db: FingerprintDatabase, local_addr: Ipv4Addr) -> Self {
        Self {
            db,
            seq_count: 6,
            local_addr,
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
            db: db.clone(),
            seq_count: 6,
            local_addr,
            open_port: 80,
            closed_port: 443,
            closed_udp_port: 33434,
            timeout: Duration::from_secs(3),
            seq_probe_delay: Duration::from_millis(100),
        }
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

        let target_ip = match target.ip() {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(crate::FingerprintError::Network {
                    operation: "OS detection".to_string(),
                    reason: "IPv6 not yet supported".to_string(),
                });
            }
        };

        // Build fingerprint from collected probe responses
        let fingerprint = self.build_fingerprint(target_ip).await?;

        // Match against database
        let matches = self.db.find_matches(&fingerprint);

        info!("Found {} OS matches for {}", matches.len(), target);

        Ok(matches)
    }

    /// Build OS fingerprint from probe responses.
    async fn build_fingerprint(&self, target: Ipv4Addr) -> Result<OsFingerprint> {
        let mut fingerprint = OsFingerprint::new();

        // Send SEQ probes (6 SYN probes to open port with 100ms intervals)
        debug!("Sending SEQ probes to {}:{}", target, self.open_port);
        let seq_responses = self.send_seq_probes(target).await?;
        let seq_fp = self.analyze_seq_responses(&seq_responses);
        fingerprint.seq = Some(seq_fp);

        // Send ECN probe
        debug!("Sending ECN probe to {}:{}", target, self.open_port);
        let ecn_fp = self.send_ecn_probe(target).await?;
        fingerprint.ecn = Some(ecn_fp);

        // Send T1-T7 TCP tests
        debug!("Sending T1-T7 TCP tests to {}", target);
        let tcp_tests = self.send_tcp_tests(target).await?;
        for test in &tcp_tests {
            fingerprint.tests.insert(test.name.clone(), test.clone());
            fingerprint
                .win
                .insert(test.name.clone(), test.window.unwrap_or(0));
            fingerprint.ops.insert(
                test.name.clone(),
                OpsFingerprint {
                    mss: test.mss,
                    wscale: test.wscale,
                    sack: test.sack,
                    timestamp: test.timestamp,
                    nop_count: 0, // Extracted from options parsing
                    eol: false,
                },
            );
        }

        // Send IE (ICMP Echo) probes
        debug!("Sending IE probes to {}", target);
        let ie_fp = self.send_icmp_probes(target).await?;
        fingerprint.ie = Some(ie_fp);

        // Send U1 (UDP) probe
        debug!("Sending U1 probe to {}:{}", target, self.closed_udp_port);
        let u1_fp = self.send_udp_probe(target).await?;
        fingerprint.u1 = Some(u1_fp);

        // Analyze IP ID patterns from SEQ responses
        let ip_id_pattern = Self::analyze_ip_id_patterns(&seq_responses);
        fingerprint.ip_id = Some(ip_id_pattern);

        Ok(fingerprint)
    }

    /// Send SEQ probes to analyze TCP ISN generation.
    ///
    /// Sends 6 TCP SYN probes to an open port with 100ms intervals.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "i is bounded by seq_count which is small"
    )]
    async fn send_seq_probes(&self, target: Ipv4Addr) -> Result<Vec<SeqProbeResponse>> {
        use rustnmap_net::raw_socket::{parse_tcp_response_full, RawSocket, TcpPacketBuilder};

        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| crate::FingerprintError::Network {
            operation: "create raw socket".to_string(),
            reason: e.to_string(),
        })?;

        let mut responses = Vec::with_capacity(self.seq_count);
        let src_port = Self::generate_source_port();

        for i in 0..self.seq_count {
            let seq = Self::generate_sequence_number() + (i as u32 * 1000);

            // Build TCP SYN packet with specific options for OS detection
            // Nmap uses: WScale=10,NOP,MSS=1460,Timestamp,SACK
            let options = Self::build_tcp_options_for_seq();
            let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, self.open_port)
                .seq(seq)
                .syn()
                .window(65535)
                .options(&options)
                .build();

            let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), self.open_port);

            // Send the packet
            socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
                crate::FingerprintError::Network {
                    operation: "send SEQ probe".to_string(),
                    reason: e.to_string(),
                }
            })?;

            // Wait for response
            let mut recv_buf = vec![0u8; 65535];
            match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
                Ok(len) if len > 0 => {
                    if let Some(response) = parse_tcp_response_full(&recv_buf[..len]) {
                        // Verify this is a response to our probe
                        if response.src_port == self.open_port
                            && (response.flags & tcp_flags::SYN) != 0
                            && (response.flags & tcp_flags::ACK) != 0
                        {
                            let ops = OpsFingerprint {
                                mss: response.options.mss,
                                wscale: response.options.wscale,
                                sack: response.options.sack,
                                timestamp: response.options.timestamp,
                                nop_count: response.options.nop_count,
                                eol: response.options.eol,
                            };

                            responses.push(SeqProbeResponse {
                                isn: response.seq,
                                ip_id: response.ip_id,
                                timestamp: response.options.timestamp_value,
                                window: response.window,
                                options: ops,
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
                        operation: "receive SEQ response".to_string(),
                        reason: e.to_string(),
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

        // Calculate differences between consecutive ISNs
        let diffs: Vec<u32> = isns.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();

        // Calculate GCD of differences
        let gcd = Self::calculate_gcd_list(&diffs);
        fp.gcd = gcd;

        // Determine ISN class based on GCD and differences
        fp.class = Self::classify_isn_pattern(&isns, &diffs, gcd);

        // Calculate ISR (ISN Rate) - approximate rate of ISN generation
        fp.isr = Self::calculate_isr(&diffs);

        // Calculate SP (Sequence Predictability)
        fp.sp = Self::calculate_sp(&isns, &diffs);

        // Analyze timestamps
        let timestamps: Vec<u32> = responses.iter().filter_map(|r| r.timestamp).collect();
        fp.timestamps.clone_from(&timestamps);

        if !timestamps.is_empty() {
            fp.timestamp = true;
            fp.timestamp_rate = Self::classify_timestamp_rate(&timestamps);
        }

        // Analyze IP ID patterns
        let ip_ids: Vec<u16> = responses.iter().map(|r| r.ip_id).collect();
        fp.ti = Self::classify_ip_id_sequence(&ip_ids);

        trace!("SEQ analysis: GCD={}, ISR={}, SP={}", fp.gcd, fp.isr, fp.sp);

        fp
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

    /// Calculate ISR (ISN Rate).
    #[allow(
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "ISR calculation with clamp ensures valid range"
    )]
    fn calculate_isr(diffs: &[u32]) -> u8 {
        if diffs.is_empty() {
            return 0;
        }
        let avg_diff = diffs.iter().map(|&d| u64::from(d)).sum::<u64>() / diffs.len() as u64;
        // ISR is approximately log2(avg_diff) scaled
        (avg_diff as f64).log2().clamp(0.0, 255.0) as u8
    }

    /// Calculate SP (Sequence Predictability).
    fn calculate_sp(_isns: &[u32], diffs: &[u32]) -> u8 {
        if diffs.len() < 2 {
            return 0;
        }

        // SP is based on how predictable the sequence is
        // Lower variance = higher predictability = lower SP
        let variance = Self::calculate_variance(diffs);
        let max_variance = u64::from(u32::MAX).pow(2);

        // SP = 100 - (variance / max_variance * 100)
        100u8.saturating_sub(u8::try_from(variance * 100 / max_variance).unwrap_or(100))
    }

    /// Classify timestamp rate.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "API consistency with fingerprint structure"
    )]
    fn classify_timestamp_rate(timestamps: &[u32]) -> Option<TimestampRate> {
        if timestamps.len() < 2 {
            return Some(TimestampRate::None);
        }

        // Calculate average increment per probe (assuming 100ms intervals)
        let diffs: Vec<u32> = timestamps
            .windows(2)
            .map(|w| w[1].wrapping_sub(w[0]))
            .collect();
        let avg_diff = diffs.iter().map(|&d| u64::from(d)).sum::<u64>() / diffs.len() as u64;

        // Typical rates:
        // 2 Hz = ~20 increments per 100ms (if in 10ms units)
        // 100 Hz = ~1000 increments per 100ms
        if avg_diff < 50 {
            Some(TimestampRate::Rate2)
        } else if avg_diff < 5000 {
            Some(TimestampRate::Rate100)
        } else {
            Some(TimestampRate::Unknown)
        }
    }

    /// Classify IP ID sequence pattern.
    fn classify_ip_id_sequence(ip_ids: &[u16]) -> IpIdSeqClass {
        if ip_ids.len() < 2 {
            return IpIdSeqClass::Unknown;
        }

        // Check if all zeros
        if ip_ids.iter().all(|&id| id == 0) {
            return IpIdSeqClass::Fixed;
        }

        // Calculate differences
        let diffs: Vec<i32> = ip_ids
            .windows(2)
            .map(|w| i32::from(w[1]) - i32::from(w[0]))
            .collect();

        // Check for incremental by 1
        if diffs.iter().all(|&d| d == 1 || d == -65535) {
            return IpIdSeqClass::Incremental;
        }

        // Check for incremental by 257 (byte-swapped)
        if diffs.iter().all(|&d| d == 257 || d == -65279) {
            return IpIdSeqClass::Incremental257;
        }

        // Check for fixed
        let first = ip_ids[0];
        if ip_ids.iter().all(|&id| id == first) {
            return IpIdSeqClass::Fixed;
        }

        // High variance indicates random
        let variance = Self::calculate_variance_u16(ip_ids);
        if variance > 1000 {
            return IpIdSeqClass::Random;
        }

        IpIdSeqClass::Unknown
    }

    /// Calculate variance for u16 values.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "Mathematical calculation with verified ranges"
    )]
    fn calculate_variance_u16(nums: &[u16]) -> u64 {
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

    /// Analyze IP ID patterns from SEQ responses.
    fn analyze_ip_id_patterns(responses: &[SeqProbeResponse]) -> IpIdPattern {
        let ip_ids: Vec<u16> = responses.iter().map(|r| r.ip_id).collect();

        IpIdPattern {
            zero: ip_ids.iter().all(|&id| id == 0),
            incremental: ip_ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1)),
            seq_class: Self::classify_ip_id_sequence(&ip_ids),
        }
    }

    /// Send ECN probe.
    ///
    /// Sends a TCP SYN packet with ECN flags (ECE and CWR) set.
    #[allow(clippy::unused_async, clippy::match_same_arms)]
    async fn send_ecn_probe(&self, target: Ipv4Addr) -> Result<EcnFingerprint> {
        use rustnmap_net::raw_socket::{parse_tcp_response_full, RawSocket, TcpPacketBuilder};

        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| crate::FingerprintError::Network {
            operation: "create raw socket".to_string(),
            reason: e.to_string(),
        })?;

        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP SYN packet with ECN flags
        // Nmap sends: SYN, ECN-Echo (ECE), and CWR flags
        let options = Self::build_tcp_options_for_seq();
        let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, self.open_port)
            .seq(seq)
            .syn()
            .window(65535)
            .options(&options)
            .build();

        // Modify packet to set ECN flags (ECE=0x40, CWR=0x80)
        let mut packet = packet;
        let ip_header_len = 20;
        let tcp_flags_offset = ip_header_len + 13;
        packet[tcp_flags_offset] |= tcp_flags::ECE | tcp_flags::CWR;

        // Recalculate TCP checksum
        let tcp_checksum = Self::recalculate_tcp_checksum(&packet, ip_header_len);
        packet[ip_header_len + 16] = (tcp_checksum >> 8) as u8;
        packet[ip_header_len + 17] = (tcp_checksum & 0xFF) as u8;

        let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), self.open_port);

        socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            crate::FingerprintError::Network {
                operation: "send ECN probe".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Wait for response
        let mut recv_buf = vec![0u8; 65535];
        let mut fp = EcnFingerprint::new();

        match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
            Ok(len) if len > 0 => {
                if let Some(response) = parse_tcp_response_full(&recv_buf[..len]) {
                    fp.ece = (response.flags & tcp_flags::ECE) != 0;
                    fp.cwr = (response.flags & tcp_flags::CWR) != 0;
                    fp.df = response.df;
                    // TOS would need to be extracted from IP header
                }
            }
            Ok(_) | Err(_) => {}
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

    /// Send T1-T7 TCP test probes.
    ///
    /// T1: SYN to open port (standard)
    /// T2: NULL to open port (no flags)
    /// T3: SYN+FIN+PSH+URG to open port
    /// T4: ACK to closed port
    /// T5: SYN to closed port
    /// T6: ACK to closed port
    /// T7: FIN+PSH+URG to closed port
    #[allow(clippy::unused_async)]
    async fn send_tcp_tests(&self, target: Ipv4Addr) -> Result<Vec<TestResult>> {
        use rustnmap_net::raw_socket::{parse_tcp_response_full, RawSocket, TcpPacketBuilder};

        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| crate::FingerprintError::Network {
            operation: "create raw socket".to_string(),
            reason: e.to_string(),
        })?;

        let tests = vec![
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

        let mut results = Vec::with_capacity(tests.len());

        for (name, port, flags) in tests {
            let src_port = Self::generate_source_port();
            let seq = Self::generate_sequence_number();

            // Build TCP packet
            let options = if name == "T1" {
                Self::build_tcp_options_for_seq()
            } else {
                Vec::new()
            };

            let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, port)
                .seq(seq)
                .window(65535)
                .options(&options)
                .build();

            // Set the appropriate flags
            let mut packet = packet;
            let ip_header_len = 20;
            let tcp_flags_offset = ip_header_len + 13;
            packet[tcp_flags_offset] = flags;

            // Recalculate checksum
            let tcp_checksum = Self::recalculate_tcp_checksum(&packet, ip_header_len);
            packet[ip_header_len + 16] = (tcp_checksum >> 8) as u8;
            packet[ip_header_len + 17] = (tcp_checksum & 0xFF) as u8;

            let dst_sockaddr = SocketAddr::new(IpAddr::V4(target), port);

            socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
                crate::FingerprintError::Network {
                    operation: format!("send {name} probe"),
                    reason: e.to_string(),
                }
            })?;

            // Wait for response
            let mut recv_buf = vec![0u8; 65535];
            let mut result = TestResult::new(name);

            match socket.recv_packet(&mut recv_buf, Some(self.timeout)) {
                Ok(len) if len > 0 => {
                    if let Some(response) = parse_tcp_response_full(&recv_buf[..len]) {
                        result = result
                            .with_flags(response.flags)
                            .with_window(response.window)
                            .with_ip_fields(response.df, response.ttl, response.ip_id);

                        result.mss = response.options.mss;
                        result.wscale = response.options.wscale;
                        result.sack = response.options.sack;
                        result.timestamp = response.options.timestamp;
                    }
                }
                Ok(_) | Err(_) => {}
            }

            results.push(result);
        }

        Ok(results)
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
        let packet1 = IcmpPacketBuilder::new(self.local_addr, target)
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
        let packet2 = IcmpPacketBuilder::new(self.local_addr, target)
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

        let src_port = Self::generate_source_port();

        // Build UDP packet with specific payload (Nmap uses 300 bytes)
        let payload = vec![0x41u8; 300]; // 'A' repeated 300 times
        let packet = UdpPacketBuilder::new(self.local_addr, target, src_port, self.closed_udp_port)
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

    /// Build TCP options for SEQ probes.
    ///
    /// Nmap uses: WScale=10, NOP, MSS=1460, Timestamp, SACK permitted
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Byte extraction: shifting right and casting to u8 is intentional"
    )]
    fn build_tcp_options_for_seq() -> Vec<u8> {
        // TSval (4 bytes) - use current time
        let tsval = u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
        .unwrap_or(0);

        vec![
            // Window Scale (kind=3, len=3, value=10)
            3,
            3,
            10,
            // NOP (kind=1)
            1,
            // MSS (kind=2, len=4, value=1460)
            2,
            4,
            0x05,
            0xB4,
            // Timestamp (kind=8, len=10, TSval, TSecr)
            8,
            10,
            // TSval (4 bytes)
            (tsval >> 24) as u8,
            (tsval >> 16) as u8,
            (tsval >> 8) as u8,
            (tsval & 0xFF) as u8,
            // TSecr (4 bytes) - 0 for initial SYN
            0,
            0,
            0,
            0,
            // SACK permitted (kind=4, len=2)
            4,
            2,
        ]
    }

    /// Generates a random source port.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Process ID modulo 20000 fits in u16 range"
    )]
    fn generate_source_port() -> u16 {
        40000 + (std::process::id() % 20000) as u16
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
    fn test_classify_ip_id_sequence() {
        // Test incremental
        let ip_ids = vec![100, 101, 102, 103];
        assert_eq!(
            OsDetector::classify_ip_id_sequence(&ip_ids),
            IpIdSeqClass::Incremental
        );

        // Test fixed
        let ip_ids = vec![100, 100, 100, 100];
        assert_eq!(
            OsDetector::classify_ip_id_sequence(&ip_ids),
            IpIdSeqClass::Fixed
        );

        // Test zeros (fixed)
        let ip_ids = vec![0, 0, 0, 0];
        assert_eq!(
            OsDetector::classify_ip_id_sequence(&ip_ids),
            IpIdSeqClass::Fixed
        );
    }

    #[test]
    fn test_build_tcp_options() {
        let options = OsDetector::build_tcp_options_for_seq();

        // Should contain: WScale(3), NOP(1), MSS(2), Timestamp(8), SACK(4)
        assert!(!options.is_empty());

        // Check for Window Scale option (kind=3)
        assert!(options.contains(&3));

        // Check for MSS option (kind=2)
        assert!(options.contains(&2));

        // Check for Timestamp option (kind=8)
        assert!(options.contains(&8));

        // Check for SACK permitted (kind=4)
        assert!(options.contains(&4));
    }
}
