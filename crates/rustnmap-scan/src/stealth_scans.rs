// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Stealth TCP scanner implementations for `RustNmap`.
//!
//! This module provides alternative TCP scanning techniques that exploit
//! RFC 793 TCP behavior to perform stealthy port scanning. These scans
//! do not complete the TCP handshake, making them harder to detect.
//!
//! # Scan Types
//!
//! - **TCP FIN Scan** (`TcpFinScanner`): Sends FIN flag only
//! - **TCP NULL Scan** (`TcpNullScanner`): Sends no flags
//! - **TCP Xmas Scan** (`TcpXmasScanner`): Sends FIN+PSH+URG flags
//! - **TCP ACK Scan** (`TcpAckScanner`): Sends ACK flag only (firewall detection)
//! - **TCP Maimon Scan** (`TcpMaimonScanner`): Sends FIN+ACK flags
//! - **TCP Window Scan** (`TcpWindowScanner`): Sends ACK flag, analyzes window size in RST
//!
//! # Port State Determination
//!
//! For FIN/NULL/Xmas/Maimon scans:
//! - No response -> Port Open|Filtered
//! - RST received -> Port Closed
//! - ICMP unreachable -> Filtered
//!
//! For ACK scan:
//! - RST received -> Port Unfiltered
//! - No response/ICMP -> Port Filtered
//!
//! For Window scan:
//! - RST + Window > 0 -> Port Closed (on some systems like HP-UX)
//! - RST + Window = 0 -> Port Open (on some systems)
//! - No response/ICMP -> Port Filtered

#![warn(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::packet_adapter::{create_stealth_engine, ScannerPacketEngine};
use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_evasion::DecoyScheduler;
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_tcp_response, parse_tcp_response_with_window, IcmpResponse,
    IcmpUnreachableCode, RawSocket, TcpPacketBuilder,
};
use rustnmap_target::Target;
use tokio::sync::Mutex;

/// Default source port range for outbound probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// Maximum batch size for batch scanning operations.
/// Limits memory usage and prevents overwhelming the network.
pub const MAX_BATCH_SIZE: usize = 1024;

// ============================================================================
// Adaptive Timing (nmap-style RTT estimation)
// ============================================================================

/// Adaptive timing for stealth scans using nmap's RTT estimation algorithm.
///
/// Uses EWMA (Exponentially Weighted Moving Average) for RTT tracking,
/// following RFC 2988: `SRTT = (7/8)*SRTT + (1/8)*RTT`
///
/// The timeout is calculated as: `SRTT + 4*RTTVAR`, clamped to nmap's bounds
/// (100ms to 10000ms).
///
/// See nmap `timing.cc:adjust_timeouts2` (lines 99-167).
#[derive(Debug)]
struct AdaptiveTiming {
    /// Smoothed RTT in microseconds.
    srtt_micros: u64,
    /// RTT variance in microseconds.
    rttvar_micros: u64,
    /// Whether this is the first RTT measurement.
    first_measurement: bool,
}

impl AdaptiveTiming {
    /// Creates new adaptive timing with nmap T3 (Normal) defaults.
    ///
    /// Initial values:
    /// - SRTT: 1000ms (`INITIAL_RTT_TIMEOUT`)
    /// - RTTVAR: 500ms (srtt / 2, matching nmap `timing.cc:124`)
    const fn new() -> Self {
        Self {
            // Nmap INITIAL_RTT_TIMEOUT = 1000ms
            srtt_micros: 1_000_000,
            // Nmap timing.cc:124: rttvar = box(5000, 2000000, srtt) = clamp(srtt, 5ms, 2s)
            // Before first measurement, nmap sets rttvar = srtt/2 (RFC 6298 Section 2.3)
            rttvar_micros: 500_000,
            first_measurement: true,
        }
    }

    /// Creates adaptive timing with initial RTT from config.
    ///
    /// Uses the config's `initial_rtt` to seed the timing estimator,
    /// matching nmap's behavior of using `initialRttTimeout` before
    /// any measurements are available.
    fn with_initial_rtt(initial_rtt: Duration) -> Self {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "initial_rtt is always within reasonable bounds (< 30s)"
        )]
        let srtt_micros = initial_rtt.as_micros() as u64;
        // Nmap timing.cc:124: rttvar = clamp(srtt, 5ms, 2s)
        let rttvar_micros = (srtt_micros / 2).clamp(5_000, 2_000_000);
        Self {
            srtt_micros,
            rttvar_micros,
            first_measurement: true,
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
    fn update_rtt(&mut self, rtt: Duration) {
        let rtt_micros = rtt.as_micros() as u64;

        if self.first_measurement {
            // First measurement: use RTT directly (nmap timing.cc:119-124)
            self.srtt_micros = rtt_micros;
            // RTTVAR = clamp(RTT, 5ms, 2000ms) - nmap: box(5000, 2000000, delta)
            self.rttvar_micros = rtt_micros.clamp(5_000, 2_000_000);
            self.first_measurement = false;
            return;
        }

        // Subsequent measurements: RFC 2988 EWMA
        // SRTT = (7/8)*SRTT + (1/8)*RTT
        let new_srtt = (7 * self.srtt_micros + rtt_micros) / 8;
        // RTTVAR = (3/4)*RTTVAR + (1/4)*|SRTT-RTT|
        let diff = new_srtt.abs_diff(rtt_micros);
        let new_rttvar = (3 * self.rttvar_micros + diff) / 4;

        // Clamp RTTVAR to nmap's bounds: 5ms to 2000ms
        self.rttvar_micros = new_rttvar.clamp(5_000, 2_000_000);
        self.srtt_micros = new_srtt;
    }

    /// Returns the recommended timeout.
    ///
    /// Before any RTT measurements, returns the initial RTT (1000ms).
    /// After measurements, returns `SRTT + 4*RTTVAR`, clamped to nmap's bounds
    /// (`MIN_RTT_TIMEOUT` 100ms to `MAX_RTT_TIMEOUT` 10000ms).
    ///
    /// This matches nmap's behavior in `timing.cc`:
    /// - If `to.srtt == -1`: use `initialRttTimeout`
    /// - Otherwise: use `srtt + 4*rttvar`
    #[must_use]
    fn recommended_timeout(&self) -> Duration {
        if self.first_measurement {
            // No measurements yet - use initial RTT (nmap behavior)
            return Duration::from_micros(self.srtt_micros);
        }
        let timeout_micros = self.srtt_micros.saturating_add(4 * self.rttvar_micros);
        // Clamp to nmap's MIN_RTT_TIMEOUT (100ms) and MAX_RTT_TIMEOUT (10000ms)
        let clamped = timeout_micros.clamp(100_000, 10_000_000);
        Duration::from_micros(clamped)
    }
}

impl Default for AdaptiveTiming {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP flag constants for reference.
mod tcp_flags {
    /// RST flag (0x04).
    pub const RST: u8 = 0x04;
}

/// TCP FIN scanner using raw sockets.
///
/// Sends TCP packets with only the FIN flag set. According to RFC 793,
/// closed ports should respond with RST, while open ports should
/// ignore the packet (no response).
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpFinScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional decoy scheduler for decoy scanning.
    decoy_scheduler: Option<DecoyScheduler>,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Tracks whether packet engine has been started.
    #[allow(
        dead_code,
        reason = "Reserved for Phase 3.4 async receive path migration"
    )]
    packet_engine_started: std::sync::atomic::AtomicBool,
}

impl TcpFinScanner {
    /// Creates a new TCP FIN scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpFinScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        Self::with_decoy(local_addr, config, None)
    }

    /// Creates a new TCP FIN scanner with optional decoy support.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes (real IP)
    /// * `config` - Scanner configuration
    /// * `decoy_scheduler` - Optional decoy scheduler for decoy scanning
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpFinScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn with_decoy(
        local_addr: Ipv4Addr,
        config: ScanConfig,
        decoy_scheduler: Option<DecoyScheduler>,
    ) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP packets, not just TCP.
        // This is necessary because using IPPROTO_TCP causes the kernel's
        // TCP stack to consume RST responses before the raw socket can read them.
        let socket = RawSocket::with_protocol(255).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Try to create packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_engine,
            packet_engine_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Receives a packet using the `PACKET_MMAP` engine (preferred) or raw socket fallback.
    fn recv_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        if let Some(ref engine_arc) = self.packet_engine {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;
                    if !self
                        .packet_engine_started
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = engine.start().await.map_err(|e| {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        });
                        self.packet_engine_started
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_fin_probe(dst_addr, port)
    }

    /// Sends a TCP FIN probe and determines port state from response.
    fn send_fin_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .fin()
            .window(65535)
            .badsum_if(self.config.badsum)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        // Use a receive loop to filter out non-matching responses
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered); // Timeout exceeded
            } else {
                timeout - elapsed
            };

            // The packet engine provides PACKET_MMAP V2 zero-copy capture but requires async context.
            // This synchronous method uses raw socket reception for packet capture.
            // Future migration will make this method async to leverage the packet engine.
            let remaining_timeout = remaining_timeout.min(Duration::from_millis(200));

            // Use raw socket reception for this synchronous method
            let data = match self
                .socket
                .recv_packet(recv_buf.as_mut_slice(), Some(remaining_timeout))
            {
                Ok(len) if len > 0 => (&recv_buf[..len], len),
                Ok(_) => return Ok(PortState::OpenOrFiltered),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(PortState::OpenOrFiltered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _resp_dst_port, src_ip)) =
                parse_tcp_response(data.0)
            {
                // For stealth scans, we sent from our_source_port to dst_port
                // The RST response comes from dst_port to our_source_port
                // So we check if src_ip == target and src_port == dst_port (target sent RST)
                // and resp_dst_port matches our source port
                if src_ip == dst_addr && src_port == dst_port {
                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }
                    // Non-RST response (shouldn't happen for FIN scan)
                    return Ok(PortState::Filtered);
                }
                // Response for different host/port - continue waiting
            } else if let Some(icmp_resp) = parse_icmp_response(data.0) {
                // Check if this ICMP response is for our probe
                if let Some(state) = Self::handle_icmp_response(icmp_resp, dst_addr, dst_port) {
                    return Ok(state);
                }
                // ICMP response for different probe - continue waiting
            }
            // Loop continues to next iteration
        }
    }

    /// Handles ICMP response to determine port state.
    ///
    /// Returns `None` if the ICMP response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the ICMP response is for our probe.
    fn handle_icmp_response(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => Some(PortState::Closed),
                    _ => Some(PortState::Filtered),
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Mix PID with current time for randomness
        let pid_component = (std::process::id() % 1000) as u16;
        let time_component = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 1000) as u16;
        let offset = (pid_component + time_component) % 1000;
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

    /// Scans multiple ports in batch mode for improved performance.
    ///
    /// This method sends all probes first, then collects responses,
    /// providing significant performance improvement over serial scanning.
    ///
    /// When decoy scanning is enabled, each port receives multiple probes
    /// (one from each decoy IP + one from the real IP). Only responses to
    /// probes sent from the real IP are tracked and processed.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `HashMap` mapping port numbers to their detected states.
    ///
    /// # Performance
    ///
    /// For scanning N ports:
    /// - Serial: ~N * `initial_rtt` (e.g., N * 1000ms)
    /// - Batch: ~`initial_rtt` (e.g., 1000ms total)
    /// - With D decoys: ~`initial_rtt` (same batch time, D+1x packets)
    ///
    /// # Errors
    ///
    /// Scans multiple ports in batch mode with nmap-style retransmissions.
    ///
    /// Sends FIN probes, collects responses, and resends probes for unresponsive
    /// ports up to `max_retries` times with exponential backoff.
    /// This handles rate limiting and packet loss like nmap does.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing a map of port numbers to port states.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission or reception fails.
    ///
    /// # Port State Mapping
    ///
    /// - RST received -> Closed
    /// - ICMP unreachable -> Filtered (or Closed for Port Unreachable)
    /// - No response after retries -> Open|Filtered
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning with retransmissions requires handling send, receive, retry, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        // Limit batch size to prevent memory issues
        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();

        // Track ports that still need responses (not yet classified)
        let mut pending_ports: std::collections::HashSet<Port> =
            ports_to_scan.iter().copied().collect();
        let mut results: HashMap<Port, PortState> = HashMap::new();

        // Maximum retries from config (nmap default: 2, cap at 3 for stealth scans)
        // Using a lower cap because stealth scans are more likely to be rate-limited
        let max_retries = u32::from(self.config.max_retries.min(3));

        // Adaptive timing for nmap-style RTT estimation
        let mut timing = AdaptiveTiming::with_initial_rtt(self.config.initial_rtt);

        // Start packet engine BEFORE sending any probes to ensure the ring buffer
        // is ready to capture responses. Without this, RST responses that arrive
        // between probe sending and first recv_packet() call are lost.
        if let Some(ref engine_arc) = self.packet_engine {
            if !self
                .packet_engine_started
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut engine = engine_arc.lock().await;
                        let _ = engine.start().await;
                    });
                });
                self.packet_engine_started
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Nmap-style retry loop with adaptive timeout
        for _retry_round in 0..=max_retries {
            if pending_ports.is_empty() {
                break; // All ports have been classified
            }

            // Phase 1: Send probes for pending ports only
            // Forward map: (dst_port, src_port) -> (seq, sent_time)
            let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
            // Reverse map: src_port -> dst_port for O(1) TCP response matching
            let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
            // Port tracking: dst_port -> set of src_ports for O(1) ICMP matching
            let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

            for dst_port in &pending_ports {
                let src_port = Self::generate_source_port();
                let seq = Self::generate_sequence_number();

                // Handle decoy scanning: send from multiple source IPs
                if let Some(scheduler) = &self.decoy_scheduler {
                    let mut scheduler = scheduler.clone();
                    scheduler.reset();

                    while let Some(src_ip) = scheduler.next_source() {
                        let src_ipv4 = match src_ip {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => continue,
                        };

                        let packet = TcpPacketBuilder::new(src_ipv4, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .fin()
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                        let port_sockaddr =
                            SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                        self.socket
                            .send_packet(&packet, &port_sockaddr)
                            .map_err(|e| {
                                rustnmap_common::ScanError::Network(
                                    rustnmap_common::Error::Network(
                                        rustnmap_common::error::NetworkError::SendError {
                                            source: e,
                                        },
                                    ),
                                )
                            })?;

                        // Only track probes sent from the real IP
                        if scheduler.is_real_ip(&src_ip) {
                            outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                            src_to_dst.insert(src_port, *dst_port);
                            port_srcs.entry(*dst_port).or_default().insert(src_port);
                        }
                    }
                } else {
                    // No decoy: original behavior
                    let packet =
                        TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .fin()
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
                        })?;

                    outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                    src_to_dst.insert(src_port, *dst_port);
                    port_srcs.entry(*dst_port).or_default().insert(src_port);
                }
            }

            // Phase 2: Collect responses with adaptive timeout
            // Nmap-style: timeout = SRTT + 4*RTTVAR (clamped to 100ms-10000ms)
            let current_timeout = timing.recommended_timeout();
            let deadline = Instant::now() + current_timeout;
            let mut recv_buf = vec![0u8; 65535];

            while Instant::now() < deadline && !outstanding.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                // Use packet engine (PACKET_MMAP) for reception when available.
                // IPPROTO_RAW socket is send-only on Linux; packet engine uses AF_PACKET which can receive.
                let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining) {
                    Ok(Some(len)) if len > 0 => {
                        // PACKET_MMAP captures at Ethernet layer, skip 14-byte header
                        let packet_data = if self.packet_engine.is_some() && len > 14 {
                            &recv_buf[14..len]
                        } else {
                            &recv_buf[..len]
                        };
                        (packet_data, len)
                    }
                    Ok(Some(_) | None) => continue,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                };

                // Check for TCP response
                if let Some((flags, _seq, _ack, src_port, dst_port, src_ip)) =
                    parse_tcp_response(data.0)
                {
                    if src_ip == dst_addr {
                        // For stealth scans, RST responses come FROM the target port TO our source port
                        if let Some(scanned_port) = src_to_dst.remove(&dst_port) {
                            // Update RTT estimate for adaptive timing
                            if let Some((_, sent_time)) = outstanding.get(&(scanned_port, src_port))
                            {
                                timing.update_rtt(sent_time.elapsed());
                            }
                            let state = if (flags & tcp_flags::RST) != 0 {
                                PortState::Closed
                            } else {
                                PortState::Filtered
                            };
                            results.insert(scanned_port, state);
                            pending_ports.remove(&scanned_port);
                            outstanding.remove(&(scanned_port, src_port));
                            if let Some(srcs) = port_srcs.get_mut(&scanned_port) {
                                srcs.remove(&src_port);
                                if srcs.is_empty() {
                                    port_srcs.remove(&scanned_port);
                                }
                            }
                        }
                    }
                } else if let Some(IcmpResponse::DestinationUnreachable {
                    code,
                    original_dst_ip,
                    original_dst_port,
                }) = parse_icmp_response(data.0)
                {
                    if original_dst_ip == dst_addr {
                        if let Some(srcs) = port_srcs.remove(&original_dst_port) {
                            // Update RTT for first src_port ( ICMP doesn't have original src_port)
                            if let Some(&first_src) = srcs.iter().next() {
                                if let Some((_, sent_time)) =
                                    outstanding.get(&(original_dst_port, first_src))
                                {
                                    timing.update_rtt(sent_time.elapsed());
                                }
                            }
                            let state = match code {
                                IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                                _ => PortState::Filtered,
                            };
                            results.insert(original_dst_port, state);
                            pending_ports.remove(&original_dst_port);
                            for src_port in srcs {
                                outstanding.remove(&(original_dst_port, src_port));
                                src_to_dst.remove(&src_port);
                            }
                        }
                    }
                }
            }
            // No artificial delay between retry rounds - nmap doesn't have this
        }

        // Phase 3: Mark remaining ports as Open|Filtered (no response after all retries)
        for port in pending_ports {
            results.entry(port).or_insert(PortState::OpenOrFiltered);
        }

        Ok(results)
    }
}

impl PortScanner for TcpFinScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP NULL scanner using raw sockets.
///
/// Sends TCP packets with no flags set. According to RFC 793,
/// closed ports should respond with RST, while open ports should
/// ignore the packet (no response).
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpNullScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional decoy scheduler for decoy scanning.
    decoy_scheduler: Option<DecoyScheduler>,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Tracks whether packet engine has been started.
    #[allow(
        dead_code,
        reason = "Reserved for Phase 3.4 async receive path migration"
    )]
    packet_engine_started: std::sync::atomic::AtomicBool,
}

impl TcpNullScanner {
    /// Creates a new TCP NULL scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpNullScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        Self::with_decoy(local_addr, config, None)
    }

    /// Creates a new TCP NULL scanner with optional decoy support.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes (real IP)
    /// * `config` - Scanner configuration
    /// * `decoy_scheduler` - Optional decoy scheduler for decoy scanning
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpNullScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn with_decoy(
        local_addr: Ipv4Addr,
        config: ScanConfig,
        decoy_scheduler: Option<DecoyScheduler>,
    ) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP packets, not just TCP.
        // This is necessary because using IPPROTO_TCP causes the kernel's
        // TCP stack to consume RST responses before the raw socket can read them.
        let socket = RawSocket::with_protocol(255).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Try to create packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_engine,
            packet_engine_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Receives a packet using the `PACKET_MMAP` engine (preferred) or raw socket fallback.
    fn recv_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        if let Some(ref engine_arc) = self.packet_engine {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;
                    if !self
                        .packet_engine_started
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = engine.start().await.map_err(|e| {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        });
                        self.packet_engine_started
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_null_probe(dst_addr, port)
    }

    /// Sends a TCP NULL probe (no flags) and determines port state from response.
    fn send_null_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with NO flags set
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .window(65_535)
            .badsum_if(self.config.badsum)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        // Use a receive loop to filter out non-matching responses
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered); // Timeout exceeded
            } else {
                timeout - elapsed
            };

            // The packet engine provides PACKET_MMAP V2 zero-copy capture but requires async context.
            // This synchronous method uses raw socket reception for packet capture.
            // Future migration will make this method async to leverage the packet engine.
            let remaining_timeout = remaining_timeout.min(Duration::from_millis(200));

            // Use raw socket reception for this synchronous method
            let data = match self
                .socket
                .recv_packet(recv_buf.as_mut_slice(), Some(remaining_timeout))
            {
                Ok(len) if len > 0 => (&recv_buf[..len], len),
                Ok(_) => return Ok(PortState::OpenOrFiltered),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(PortState::OpenOrFiltered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) =
                parse_tcp_response(data.0)
            {
                // Only process responses from our target for our destination port
                if src_ip == dst_addr && src_port == dst_port {
                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }
                    // Non-RST response (shouldn't happen for NULL scan)
                    return Ok(PortState::Filtered);
                }
                // Response for different host/port - continue waiting
            } else if let Some(icmp_resp) = parse_icmp_response(data.0) {
                // Check if this ICMP response is for our probe
                if let Some(state) = Self::handle_icmp_response(icmp_resp, dst_addr, dst_port) {
                    return Ok(state);
                }
                // ICMP response for different probe - continue waiting
            }
            // Loop continues to next iteration
        }
    }

    /// Handles ICMP response to determine port state.
    ///
    /// Returns `None` if the ICMP response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the ICMP response is for our probe.
    fn handle_icmp_response(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => Some(PortState::Closed),
                    _ => Some(PortState::Filtered),
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Mix PID with current time for randomness
        let pid_component = (std::process::id() % 1000) as u16;
        let time_component = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 1000) as u16;
        let offset = (pid_component + time_component) % 1000;
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

    /// Scans multiple ports in batch mode with nmap-style retransmissions.
    ///
    /// Sends NULL probes (no flags), collects responses, and resends probes for
    /// unresponsive ports up to `max_retries` times with exponential backoff.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing a map of port numbers to port states.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission or reception fails.
    ///
    /// # Port State Mapping
    ///
    /// - RST received -> Closed
    /// - ICMP unreachable -> Filtered (or Closed for Port Unreachable)
    /// - No response after retries -> Open|Filtered
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning with retransmissions requires handling send, receive, retry, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        // Limit batch size to prevent memory issues
        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();

        // Track ports that still need responses (not yet classified)
        let mut pending_ports: std::collections::HashSet<Port> =
            ports_to_scan.iter().copied().collect();
        let mut results: HashMap<Port, PortState> = HashMap::new();

        // Maximum retries from config (nmap default: 2, cap at 3 for stealth scans)
        let max_retries = u32::from(self.config.max_retries.min(3));

        // Adaptive timing for nmap-style RTT estimation
        let mut timing = AdaptiveTiming::with_initial_rtt(self.config.initial_rtt);

        // Start packet engine BEFORE sending any probes to ensure the ring buffer
        // is ready to capture responses. Without this, RST responses that arrive
        // between probe sending and first recv_packet() call are lost.
        if let Some(ref engine_arc) = self.packet_engine {
            if !self
                .packet_engine_started
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut engine = engine_arc.lock().await;
                        let _ = engine.start().await;
                    });
                });
                self.packet_engine_started
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Nmap-style retry loop with adaptive timeout
        for _retry_round in 0..=max_retries {
            if pending_ports.is_empty() {
                break; // All ports have been classified
            }

            // Phase 1: Send probes for pending ports only
            let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
            let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
            let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

            for dst_port in &pending_ports {
                let src_port = Self::generate_source_port();
                let seq = Self::generate_sequence_number();

                // Handle decoy scanning: send from multiple source IPs
                if let Some(scheduler) = &self.decoy_scheduler {
                    let mut scheduler = scheduler.clone();
                    scheduler.reset();

                    while let Some(src_ip) = scheduler.next_source() {
                        let src_ipv4 = match src_ip {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => continue,
                        };

                        // NULL scan: no flags set
                        let packet = TcpPacketBuilder::new(src_ipv4, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                        let port_sockaddr =
                            SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                        self.socket
                            .send_packet(&packet, &port_sockaddr)
                            .map_err(|e| {
                                rustnmap_common::ScanError::Network(
                                    rustnmap_common::Error::Network(
                                        rustnmap_common::error::NetworkError::SendError {
                                            source: e,
                                        },
                                    ),
                                )
                            })?;

                        if scheduler.is_real_ip(&src_ip) {
                            outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                            src_to_dst.insert(src_port, *dst_port);
                            port_srcs.entry(*dst_port).or_default().insert(src_port);
                        }
                    }
                } else {
                    let packet =
                        TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
                        })?;

                    outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                    src_to_dst.insert(src_port, *dst_port);
                    port_srcs.entry(*dst_port).or_default().insert(src_port);
                }
            }

            // Phase 2: Collect responses with adaptive timeout
            // Nmap-style: timeout = SRTT + 4*RTTVAR (clamped to 100ms-10000ms)
            let current_timeout = timing.recommended_timeout();
            let deadline = Instant::now() + current_timeout;
            let mut recv_buf = vec![0u8; 65535];

            while Instant::now() < deadline && !outstanding.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                // Use packet engine (PACKET_MMAP) for reception when available.
                // IPPROTO_RAW socket is send-only on Linux; packet engine uses AF_PACKET which can receive.
                let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining) {
                    Ok(Some(len)) if len > 0 => {
                        // PACKET_MMAP captures at Ethernet layer, skip 14-byte header
                        let packet_data = if self.packet_engine.is_some() && len > 14 {
                            &recv_buf[14..len]
                        } else {
                            &recv_buf[..len]
                        };
                        (packet_data, len)
                    }
                    Ok(Some(_) | None) => continue,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                };

                if let Some((flags, _seq, _ack, _resp_src_port, resp_dst_port, src_ip)) =
                    parse_tcp_response(data.0)
                {
                    if src_ip == dst_addr {
                        // RST responses come FROM target port TO our source port.
                        // src_to_dst maps our_source_port -> target_port, so use resp_dst_port (our source port) as key.
                        if let Some(scanned_port) = src_to_dst.remove(&resp_dst_port) {
                            // Update RTT estimate for adaptive timing
                            if let Some((_, sent_time)) =
                                outstanding.get(&(scanned_port, resp_dst_port))
                            {
                                timing.update_rtt(sent_time.elapsed());
                            }
                            let state = if (flags & tcp_flags::RST) != 0 {
                                PortState::Closed
                            } else {
                                PortState::Filtered
                            };
                            results.insert(scanned_port, state);
                            pending_ports.remove(&scanned_port);
                            outstanding.remove(&(scanned_port, resp_dst_port));
                            if let Some(srcs) = port_srcs.get_mut(&scanned_port) {
                                srcs.remove(&resp_dst_port);
                                if srcs.is_empty() {
                                    port_srcs.remove(&scanned_port);
                                }
                            }
                        }
                    }
                } else if let Some(IcmpResponse::DestinationUnreachable {
                    code,
                    original_dst_ip,
                    original_dst_port,
                }) = parse_icmp_response(data.0)
                {
                    if original_dst_ip == dst_addr {
                        if let Some(srcs) = port_srcs.remove(&original_dst_port) {
                            // Update RTT for first src_port
                            if let Some(&first_src) = srcs.iter().next() {
                                if let Some((_, sent_time)) =
                                    outstanding.get(&(original_dst_port, first_src))
                                {
                                    timing.update_rtt(sent_time.elapsed());
                                }
                            }
                            let state = match code {
                                IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                                _ => PortState::Filtered,
                            };
                            results.insert(original_dst_port, state);
                            pending_ports.remove(&original_dst_port);
                            for src_port in srcs {
                                outstanding.remove(&(original_dst_port, src_port));
                                src_to_dst.remove(&src_port);
                            }
                        }
                    }
                }
            }
            // No artificial delay between retry rounds - nmap doesn't have this
        }

        // Phase 3: Mark remaining ports as Open|Filtered (no response after all retries)
        for port in pending_ports {
            results.entry(port).or_insert(PortState::OpenOrFiltered);
        }

        Ok(results)
    }
}

impl PortScanner for TcpNullScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP Xmas scanner using raw sockets.
///
/// Sends TCP packets with FIN, PSH, and URG flags set ("lights up like a Christmas tree").
/// According to RFC 793, closed ports should respond with RST, while open ports should
/// ignore the packet (no response).
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpXmasScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional decoy scheduler for decoy scanning.
    decoy_scheduler: Option<DecoyScheduler>,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Tracks whether packet engine has been started.
    #[allow(
        dead_code,
        reason = "Reserved for Phase 3.4 async receive path migration"
    )]
    packet_engine_started: std::sync::atomic::AtomicBool,
}

impl TcpXmasScanner {
    /// Creates a new TCP Xmas scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpXmasScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        Self::with_decoy(local_addr, config, None)
    }

    /// Creates a new TCP Xmas scanner with optional decoy support.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes (real IP)
    /// * `config` - Scanner configuration
    /// * `decoy_scheduler` - Optional decoy scheduler for decoy scanning
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpXmasScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn with_decoy(
        local_addr: Ipv4Addr,
        config: ScanConfig,
        decoy_scheduler: Option<DecoyScheduler>,
    ) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP packets, not just TCP.
        // This is necessary because using IPPROTO_TCP causes the kernel's
        // TCP stack to consume RST responses before the raw socket can read them.
        let socket = RawSocket::with_protocol(255).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Try to create packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_engine,
            packet_engine_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Receives a packet using the `PACKET_MMAP` engine (preferred) or raw socket fallback.
    fn recv_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        if let Some(ref engine_arc) = self.packet_engine {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;
                    if !self
                        .packet_engine_started
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = engine.start().await.map_err(|e| {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        });
                        self.packet_engine_started
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_xmas_probe(dst_addr, port)
    }

    /// Sends a TCP Xmas probe (FIN+PSH+URG) and determines port state from response.
    fn send_xmas_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with FIN+PSH+URG flags (Xmas tree)
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .fin()
            .psh()
            .urg()
            .window(65535)
            .badsum_if(self.config.badsum)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        // Use a receive loop to filter out non-matching responses
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered); // Timeout exceeded
            } else {
                timeout - elapsed
            };

            // The packet engine provides PACKET_MMAP V2 zero-copy capture but requires async context.
            // This synchronous method uses raw socket reception for packet capture.
            // Future migration will make this method async to leverage the packet engine.
            let remaining_timeout = remaining_timeout.min(Duration::from_millis(200));

            // Use raw socket reception for this synchronous method
            let data = match self
                .socket
                .recv_packet(recv_buf.as_mut_slice(), Some(remaining_timeout))
            {
                Ok(len) if len > 0 => (&recv_buf[..len], len),
                Ok(_) => return Ok(PortState::OpenOrFiltered),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(PortState::OpenOrFiltered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) =
                parse_tcp_response(data.0)
            {
                // Only process responses from our target for our destination port
                if src_ip == dst_addr && src_port == dst_port {
                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }
                    // Non-RST response (shouldn't happen for Xmas scan)
                    return Ok(PortState::Filtered);
                }
                // Response for different host/port - continue waiting
            } else if let Some(icmp_resp) = parse_icmp_response(data.0) {
                // Check if this ICMP response is for our probe
                if let Some(state) = Self::handle_icmp_response(icmp_resp, dst_addr, dst_port) {
                    return Ok(state);
                }
                // ICMP response for different probe - continue waiting
            }
            // Loop continues to next iteration
        }
    }

    /// Handles ICMP response to determine port state.
    ///
    /// Returns `None` if the ICMP response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the ICMP response is for our probe.
    fn handle_icmp_response(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => Some(PortState::Closed),
                    _ => Some(PortState::Filtered),
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Mix PID with current time for randomness
        let pid_component = (std::process::id() % 1000) as u16;
        let time_component = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 1000) as u16;
        let offset = (pid_component + time_component) % 1000;
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

    /// Scans multiple ports in batch mode with nmap-style retransmissions.
    ///
    /// Sends XMAS probes (FIN+PSH+URG flags), collects responses, and resends
    /// probes for unresponsive ports up to `max_retries` times with exponential backoff.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing a map of port numbers to port states.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission or reception fails.
    ///
    /// # Port State Mapping
    ///
    /// - RST received -> Closed
    /// - ICMP unreachable -> Filtered (or Closed for Port Unreachable)
    /// - No response after retries -> Open|Filtered
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning with retransmissions requires handling send, receive, retry, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        // Limit batch size to prevent memory issues
        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();

        // Track ports that still need responses (not yet classified)
        let mut pending_ports: std::collections::HashSet<Port> =
            ports_to_scan.iter().copied().collect();
        let mut results: HashMap<Port, PortState> = HashMap::new();

        // Maximum retries from config (nmap default: 2, cap at 3 for stealth scans)
        let max_retries = u32::from(self.config.max_retries.min(3));

        // Adaptive timing for nmap-style RTT estimation
        let mut timing = AdaptiveTiming::with_initial_rtt(self.config.initial_rtt);

        // Start packet engine BEFORE sending any probes to ensure the ring buffer
        // is ready to capture responses. Without this, RST responses that arrive
        // between probe sending and first recv_packet() call are lost.
        if let Some(ref engine_arc) = self.packet_engine {
            if !self
                .packet_engine_started
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut engine = engine_arc.lock().await;
                        let _ = engine.start().await;
                    });
                });
                self.packet_engine_started
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Nmap-style retry loop with adaptive timeout
        for _retry_round in 0..=max_retries {
            if pending_ports.is_empty() {
                break; // All ports have been classified
            }

            // Phase 1: Send probes for pending ports only
            let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
            let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
            let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

            for dst_port in &pending_ports {
                let src_port = Self::generate_source_port();
                let seq = Self::generate_sequence_number();

                // Handle decoy scanning: send from multiple source IPs
                if let Some(scheduler) = &self.decoy_scheduler {
                    let mut scheduler = scheduler.clone();
                    scheduler.reset();

                    while let Some(src_ip) = scheduler.next_source() {
                        let src_ipv4 = match src_ip {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => continue,
                        };

                        // XMAS scan: FIN+PSH+URG flags
                        let packet = TcpPacketBuilder::new(src_ipv4, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .fin()
                            .psh()
                            .urg()
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                        let port_sockaddr =
                            SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                        self.socket
                            .send_packet(&packet, &port_sockaddr)
                            .map_err(|e| {
                                rustnmap_common::ScanError::Network(
                                    rustnmap_common::Error::Network(
                                        rustnmap_common::error::NetworkError::SendError {
                                            source: e,
                                        },
                                    ),
                                )
                            })?;

                        if scheduler.is_real_ip(&src_ip) {
                            outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                            src_to_dst.insert(src_port, *dst_port);
                            port_srcs.entry(*dst_port).or_default().insert(src_port);
                        }
                    }
                } else {
                    let packet =
                        TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .fin()
                            .psh()
                            .urg()
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
                        })?;

                    outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                    src_to_dst.insert(src_port, *dst_port);
                    port_srcs.entry(*dst_port).or_default().insert(src_port);
                }
            }

            // Phase 2: Collect responses with adaptive timeout
            // Nmap-style: timeout = SRTT + 4*RTTVAR (clamped to 100ms-10000ms)
            let current_timeout = timing.recommended_timeout();
            let deadline = Instant::now() + current_timeout;
            let mut recv_buf = vec![0u8; 65535];

            while Instant::now() < deadline && !outstanding.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                // Use packet engine (PACKET_MMAP) for reception when available.
                // IPPROTO_RAW socket is send-only on Linux; packet engine uses AF_PACKET which can receive.
                let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining) {
                    Ok(Some(len)) if len > 0 => {
                        // PACKET_MMAP captures at Ethernet layer, skip 14-byte header
                        let packet_data = if self.packet_engine.is_some() && len > 14 {
                            &recv_buf[14..len]
                        } else {
                            &recv_buf[..len]
                        };
                        (packet_data, len)
                    }
                    Ok(Some(_) | None) => continue,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                };

                if let Some((flags, _seq, _ack, _resp_src_port, resp_dst_port, src_ip)) =
                    parse_tcp_response(data.0)
                {
                    if src_ip == dst_addr {
                        // RST responses come FROM target port TO our source port.
                        // src_to_dst maps our_source_port -> target_port, so use resp_dst_port (our source port) as key.
                        if let Some(scanned_port) = src_to_dst.remove(&resp_dst_port) {
                            // Update RTT estimate for adaptive timing
                            if let Some((_, sent_time)) =
                                outstanding.get(&(scanned_port, resp_dst_port))
                            {
                                timing.update_rtt(sent_time.elapsed());
                            }
                            let state = if (flags & tcp_flags::RST) != 0 {
                                PortState::Closed
                            } else {
                                PortState::Filtered
                            };
                            results.insert(scanned_port, state);
                            pending_ports.remove(&scanned_port);
                            outstanding.remove(&(scanned_port, resp_dst_port));
                            if let Some(srcs) = port_srcs.get_mut(&scanned_port) {
                                srcs.remove(&resp_dst_port);
                                if srcs.is_empty() {
                                    port_srcs.remove(&scanned_port);
                                }
                            }
                        }
                    }
                } else if let Some(IcmpResponse::DestinationUnreachable {
                    code,
                    original_dst_ip,
                    original_dst_port,
                }) = parse_icmp_response(data.0)
                {
                    if original_dst_ip == dst_addr {
                        if let Some(srcs) = port_srcs.remove(&original_dst_port) {
                            // Update RTT for first src_port
                            if let Some(&first_src) = srcs.iter().next() {
                                if let Some((_, sent_time)) =
                                    outstanding.get(&(original_dst_port, first_src))
                                {
                                    timing.update_rtt(sent_time.elapsed());
                                }
                            }
                            let state = match code {
                                IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                                _ => PortState::Filtered,
                            };
                            results.insert(original_dst_port, state);
                            pending_ports.remove(&original_dst_port);
                            for src_port in srcs {
                                outstanding.remove(&(original_dst_port, src_port));
                                src_to_dst.remove(&src_port);
                            }
                        }
                    }
                }
            }
            // No artificial delay between retry rounds - nmap doesn't have this
        }

        // Phase 3: Mark remaining ports as Open|Filtered (no response after all retries)
        for port in pending_ports {
            results.entry(port).or_insert(PortState::OpenOrFiltered);
        }

        Ok(results)
    }
}

impl PortScanner for TcpXmasScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP ACK scanner using raw sockets.
///
/// Sends TCP packets with only the ACK flag set. This scan type is used
/// for firewall/ACL detection rather than determining port state.
///
/// # Port State Mapping
///
/// - RST received -> Unfiltered (port is reachable)
/// - No response/ICMP -> Filtered
///
/// Note: ACK scan cannot distinguish between open and closed ports.
/// It only determines if a port is filtered by a firewall.
#[derive(Debug)]
pub struct TcpAckScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Tracks whether packet engine has been started.
    #[allow(
        dead_code,
        reason = "Reserved for Phase 3.4 async receive path migration"
    )]
    packet_engine_started: std::sync::atomic::AtomicBool,
}

impl TcpAckScanner {
    /// Receives a packet using either the packet engine or raw socket.
    ///
    /// This helper method provides a unified interface for packet reception,
    /// preferring the `PACKET_MMAP` engine when available for zero-copy capture.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive packet data into
    /// * `timeout` - Maximum time to wait for a packet
    ///
    /// # Returns
    ///
    /// `Ok(Some(len))` if a packet was received, `Ok(None)` on timeout,
    /// or an error if reception fails.
    fn recv_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        // If packet engine is available, use it for zero-copy capture
        if let Some(ref engine_arc) = self.packet_engine {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;

                    // Start engine if not yet started.
                    // If already started, the engine will return AlreadyStarted error,
                    // which we ignore because the engine is ready for use.
                    if !self
                        .packet_engine_started
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = engine.start().await.map_err(|e| {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        });
                        self.packet_engine_started
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }

                    // Receive with timeout
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None), // Timeout
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            // Fall back to raw socket reception
            // Convert io::Result<usize> to io::Result<Option<usize>>
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }

    /// Creates a new TCP ACK scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpAckScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP packets, not just TCP.
        // This is necessary because using IPPROTO_TCP causes the kernel's
        // TCP stack to consume RST responses before the raw socket can read them.
        let socket = RawSocket::with_protocol(255).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Try to create packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            config,
            packet_engine,
            packet_engine_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_ack_probe(dst_addr, port)
    }

    /// Sends a TCP ACK probe and determines port state from response.
    fn send_ack_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with ACK flag only
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .ack_flag()
            .window(65535)
            .badsum_if(self.config.badsum)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        // Use a receive loop to filter out non-matching responses
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::Filtered); // Timeout exceeded - no response means filtered
            } else {
                timeout - elapsed
            };

            // Receive response via packet engine (PACKET_MMAP) or raw socket
            let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining_timeout) {
                Ok(Some(len)) if len > 0 => {
                    // PACKET_MMAP captures at Ethernet layer, need to skip 14-byte Ethernet header
                    // Raw socket captures at IP layer, no skip needed
                    let packet_data = if self.packet_engine.is_some() {
                        if len > 14 {
                            &recv_buf[14..len]
                        } else {
                            &recv_buf[..len]
                        }
                    } else {
                        &recv_buf[..len]
                    };
                    (packet_data, len)
                }
                Ok(Some(_) | None) => return Ok(PortState::Filtered),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(PortState::Filtered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, resp_src_port, _resp_dst_port, src_ip)) =
                parse_tcp_response(data.0)
            {
                // For ACK scan, we sent from src_port to dst_port
                // The RST response comes from dst_port to src_port
                // So we check if src_ip == target and resp_src_port == dst_port (target sent RST)
                if src_ip == dst_addr && resp_src_port == dst_port {
                    // For ACK scan, RST means the port is unfiltered (reachable)
                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Unfiltered);
                    }
                    // Non-RST response (shouldn't happen for ACK scan)
                    return Ok(PortState::Filtered);
                }
                // Response for different host/port - continue waiting
            } else if let Some(icmp_resp) = parse_icmp_response(data.0) {
                // Check if this ICMP response is for our probe
                if let Some(state) =
                    Self::handle_icmp_response_with_match(icmp_resp, dst_addr, dst_port)
                {
                    return Ok(state);
                }
                // ICMP response for different probe - continue waiting
            }
            // Loop continues to next iteration
        }
    }

    /// Handles ICMP response for ACK scan.
    ///
    /// Returns `None` if the ICMP response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the ICMP response is for our probe.
    fn handle_icmp_response_with_match(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                // For ACK scan, ICMP unreachable means filtered
                let _ = code;
                Some(PortState::Filtered)
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Mix PID with current time for randomness
        let pid_component = (std::process::id() % 1000) as u16;
        let time_component = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 1000) as u16;
        let offset = (pid_component + time_component) % 1000;
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

    /// Scans multiple ports in batch mode with nmap-style retransmissions.
    ///
    /// Sends ACK probes, collects responses, and resends probes for unresponsive
    /// ports up to `max_retries` times with exponential backoff.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing a map of port numbers to port states.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission or reception fails.
    ///
    /// # Port State Mapping
    ///
    /// - RST received -> Unfiltered
    /// - ICMP unreachable -> Filtered
    /// - No response after retries -> Filtered
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning with retransmissions requires handling send, receive, retry, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        // Limit batch size to prevent memory issues
        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();

        // Track ports that still need responses (not yet classified)
        let mut pending_ports: std::collections::HashSet<Port> =
            ports_to_scan.iter().copied().collect();
        let mut results: HashMap<Port, PortState> = HashMap::new();

        // Maximum retries from config (nmap default: 2, cap at 3 for stealth scans)
        let max_retries = u32::from(self.config.max_retries.min(3));

        // Adaptive timing for nmap-style RTT estimation
        let mut timing = AdaptiveTiming::with_initial_rtt(self.config.initial_rtt);

        // Start packet engine BEFORE sending any probes to ensure the ring buffer
        // is ready to capture responses. Without this, RST responses that arrive
        // between probe sending and first recv_packet() call are lost.
        if let Some(ref engine_arc) = self.packet_engine {
            if !self
                .packet_engine_started
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut engine = engine_arc.lock().await;
                        let _ = engine.start().await;
                    });
                });
                self.packet_engine_started
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Nmap-style retry loop with adaptive timeout
        for _retry_round in 0..=max_retries {
            if pending_ports.is_empty() {
                break; // All ports have been classified
            }

            // Phase 1: Send probes for pending ports only
            // Use same source port for all probes in this round
            let src_port = Self::generate_source_port();
            let round_start = Instant::now();

            for dst_port in &pending_ports {
                let seq = Self::generate_sequence_number();

                // Build TCP packet with ACK flag only
                let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                    .seq(seq)
                    .ack_flag()
                    .window(65535)
                    .badsum_if(self.config.badsum)
                    .build();

                let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                self.socket
                    .send_packet(&packet, &port_sockaddr)
                    .map_err(|e| {
                        rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::SendError { source: e },
                        ))
                    })?;
            }

            // Phase 2: Collect responses with adaptive timeout
            // Nmap-style: timeout = SRTT + 4*RTTVAR (clamped to 100ms-10000ms)
            let current_timeout = timing.recommended_timeout();
            let deadline = Instant::now() + current_timeout;
            let mut recv_buf = vec![0u8; 65535];

            while Instant::now() < deadline && !pending_ports.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                // Use packet engine (PACKET_MMAP) or raw socket reception
                let remaining = remaining.min(Duration::from_millis(200));

                // Receive response via packet engine or raw socket
                let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining) {
                    Ok(Some(len)) if len > 0 => {
                        // PACKET_MMAP captures at Ethernet layer, need to skip 14-byte Ethernet header
                        // Raw socket captures at IP layer, no skip needed
                        let packet_data = if self.packet_engine.is_some() {
                            if len > 14 {
                                &recv_buf[14..len]
                            } else {
                                &recv_buf[..len]
                            }
                        } else {
                            &recv_buf[..len]
                        };
                        (packet_data, len)
                    }
                    Ok(Some(_) | None) => continue,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                };

                // Check for TCP response
                if let Some((flags, _seq, _ack, resp_src_port, _resp_dst_port, src_ip)) =
                    parse_tcp_response(data.0)
                {
                    if src_ip == dst_addr && pending_ports.remove(&resp_src_port) {
                        // Update RTT estimate for adaptive timing
                        timing.update_rtt(round_start.elapsed());
                        // For ACK scan, RST means unfiltered
                        let state = if (flags & tcp_flags::RST) != 0 {
                            PortState::Unfiltered
                        } else {
                            PortState::Filtered
                        };
                        results.insert(resp_src_port, state);
                    }
                } else if let Some(IcmpResponse::DestinationUnreachable {
                    original_dst_ip,
                    original_dst_port,
                    ..
                }) = parse_icmp_response(data.0)
                {
                    if original_dst_ip == dst_addr && pending_ports.remove(&original_dst_port) {
                        // Update RTT estimate for adaptive timing
                        timing.update_rtt(round_start.elapsed());
                        // ICMP unreachable means filtered
                        results.insert(original_dst_port, PortState::Filtered);
                    }
                }
            }
            // No artificial delay between retry rounds - nmap doesn't have this
        }

        // Phase 3: Mark remaining ports as Filtered (no response after all retries)
        for port in pending_ports {
            results.entry(port).or_insert(PortState::Filtered);
        }

        Ok(results)
    }
}

impl PortScanner for TcpAckScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP Maimon scanner using raw sockets.
///
/// Sends TCP packets with FIN and ACK flags set. Named after Uriel Maimon
/// who described this technique. Similar to FIN scan but includes ACK flag.
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpMaimonScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional decoy scheduler for decoy scanning.
    decoy_scheduler: Option<DecoyScheduler>,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Tracks whether packet engine has been started.
    #[allow(
        dead_code,
        reason = "Reserved for Phase 3.4 async receive path migration"
    )]
    packet_engine_started: std::sync::atomic::AtomicBool,
}

impl TcpMaimonScanner {
    /// Creates a new TCP Maimon scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpMaimonScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        Self::with_decoy(local_addr, config, None)
    }

    /// Creates a new TCP Maimon scanner with optional decoy support.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes (real IP)
    /// * `config` - Scanner configuration
    /// * `decoy_scheduler` - Optional decoy scheduler for decoy scanning
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpMaimonScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn with_decoy(
        local_addr: Ipv4Addr,
        config: ScanConfig,
        decoy_scheduler: Option<DecoyScheduler>,
    ) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP packets, not just TCP.
        // This is necessary because using IPPROTO_TCP causes the kernel's
        // TCP stack to consume RST responses before the raw socket can read them.
        let socket = RawSocket::with_protocol(255).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Try to create packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_engine,
            packet_engine_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Receives a packet using the `PACKET_MMAP` engine (preferred) or raw socket fallback.
    fn recv_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        if let Some(ref engine_arc) = self.packet_engine {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;
                    if !self
                        .packet_engine_started
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = engine.start().await.map_err(|e| {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        });
                        self.packet_engine_started
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_maimon_probe(dst_addr, port)
    }

    /// Sends a TCP Maimon probe (FIN+ACK) and determines port state from response.
    fn send_maimon_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with FIN+ACK flags
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .fin()
            .ack_flag()
            .window(65535)
            .badsum_if(self.config.badsum)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        // Use a receive loop to filter out non-matching responses
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered); // Timeout exceeded
            } else {
                timeout - elapsed
            };

            // Receive response via raw socket
            let data = match self
                .socket
                .recv_packet(recv_buf.as_mut_slice(), Some(remaining_timeout))
            {
                Ok(len) if len > 0 => (&recv_buf[..len], len),
                Ok(_) => return Ok(PortState::OpenOrFiltered),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(PortState::OpenOrFiltered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) =
                parse_tcp_response(data.0)
            {
                // Only process responses from our target for our destination port
                if src_ip == dst_addr && src_port == dst_port {
                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }
                    // Non-RST response (shouldn't happen for Maimon scan)
                    return Ok(PortState::Filtered);
                }
                // Response for different host/port - continue waiting
            } else if let Some(icmp_resp) = parse_icmp_response(data.0) {
                // Check if this ICMP response is for our probe
                if let Some(state) = Self::handle_icmp_response(icmp_resp, dst_addr, dst_port) {
                    return Ok(state);
                }
                // ICMP response for different probe - continue waiting
            }
            // Loop continues to next iteration
        }
    }

    /// Handles ICMP response to determine port state.
    ///
    /// Returns `None` if the ICMP response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the ICMP response is for our probe.
    fn handle_icmp_response(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => Some(PortState::Closed),
                    _ => Some(PortState::Filtered),
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Mix PID with current time for randomness
        let pid_component = (std::process::id() % 1000) as u16;
        let time_component = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 1000) as u16;
        let offset = (pid_component + time_component) % 1000;
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

    /// Scans multiple ports in batch mode with nmap-style retransmissions.
    ///
    /// Sends MAIMON probes (FIN+ACK flags), collects responses, and resends
    /// probes for unresponsive ports up to `max_retries` times with exponential backoff.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing a map of port numbers to port states.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission or reception fails.
    ///
    /// # Port State Mapping
    ///
    /// - RST received -> Closed
    /// - ICMP unreachable -> Filtered (or Closed for Port Unreachable)
    /// - No response after retries -> Open|Filtered
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning with retransmissions requires handling send, receive, retry, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        // Limit batch size to prevent memory issues
        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();

        // Track ports that still need responses (not yet classified)
        let mut pending_ports: std::collections::HashSet<Port> =
            ports_to_scan.iter().copied().collect();
        let mut results: HashMap<Port, PortState> = HashMap::new();

        // Maximum retries from config (nmap default: 2, cap at 3 for stealth scans)
        let max_retries = u32::from(self.config.max_retries.min(3));

        // Adaptive timing for nmap-style RTT estimation
        let mut timing = AdaptiveTiming::with_initial_rtt(self.config.initial_rtt);

        // Start packet engine BEFORE sending any probes to ensure the ring buffer
        // is ready to capture responses. Without this, RST responses that arrive
        // between probe sending and first recv_packet() call are lost.
        if let Some(ref engine_arc) = self.packet_engine {
            if !self
                .packet_engine_started
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut engine = engine_arc.lock().await;
                        let _ = engine.start().await;
                    });
                });
                self.packet_engine_started
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Nmap-style retry loop with adaptive timeout
        for _retry_round in 0..=max_retries {
            if pending_ports.is_empty() {
                break; // All ports have been classified
            }

            // Phase 1: Send probes for pending ports only
            let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
            let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
            let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

            for dst_port in &pending_ports {
                let src_port = Self::generate_source_port();
                let seq = Self::generate_sequence_number();

                // Handle decoy scanning: send from multiple source IPs
                if let Some(scheduler) = &self.decoy_scheduler {
                    let mut scheduler = scheduler.clone();
                    scheduler.reset();

                    while let Some(src_ip) = scheduler.next_source() {
                        let src_ipv4 = match src_ip {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => continue,
                        };

                        // MAIMON scan: FIN+ACK flags
                        let packet = TcpPacketBuilder::new(src_ipv4, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .fin()
                            .ack_flag()
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                        let port_sockaddr =
                            SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                        self.socket
                            .send_packet(&packet, &port_sockaddr)
                            .map_err(|e| {
                                rustnmap_common::ScanError::Network(
                                    rustnmap_common::Error::Network(
                                        rustnmap_common::error::NetworkError::SendError {
                                            source: e,
                                        },
                                    ),
                                )
                            })?;

                        if scheduler.is_real_ip(&src_ip) {
                            outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                            src_to_dst.insert(src_port, *dst_port);
                            port_srcs.entry(*dst_port).or_default().insert(src_port);
                        }
                    }
                } else {
                    let packet =
                        TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                            .seq(seq)
                            .fin()
                            .ack_flag()
                            .window(65535)
                            .badsum_if(self.config.badsum)
                            .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
                        })?;

                    outstanding.insert((*dst_port, src_port), (seq, Instant::now()));
                    src_to_dst.insert(src_port, *dst_port);
                    port_srcs.entry(*dst_port).or_default().insert(src_port);
                }
            }

            // Phase 2: Collect responses with adaptive timeout
            // Nmap-style: timeout = SRTT + 4*RTTVAR (clamped to 100ms-10000ms)
            let current_timeout = timing.recommended_timeout();
            let deadline = Instant::now() + current_timeout;
            let mut recv_buf = vec![0u8; 65535];

            while Instant::now() < deadline && !outstanding.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                // Use packet engine (PACKET_MMAP) for reception when available.
                // IPPROTO_RAW socket is send-only on Linux; packet engine uses AF_PACKET which can receive.
                let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining) {
                    Ok(Some(len)) if len > 0 => {
                        // PACKET_MMAP captures at Ethernet layer, skip 14-byte header
                        let packet_data = if self.packet_engine.is_some() && len > 14 {
                            &recv_buf[14..len]
                        } else {
                            &recv_buf[..len]
                        };
                        (packet_data, len)
                    }
                    Ok(Some(_) | None) => continue,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                };

                if let Some((flags, _seq, _ack, _resp_src_port, resp_dst_port, src_ip)) =
                    parse_tcp_response(data.0)
                {
                    if src_ip == dst_addr {
                        // RST responses come FROM target port TO our source port.
                        // src_to_dst maps our_source_port -> target_port, so use resp_dst_port (our source port) as key.
                        if let Some(scanned_port) = src_to_dst.remove(&resp_dst_port) {
                            // Update RTT estimate for adaptive timing
                            if let Some((_, sent_time)) =
                                outstanding.get(&(scanned_port, resp_dst_port))
                            {
                                timing.update_rtt(sent_time.elapsed());
                            }
                            let state = if (flags & tcp_flags::RST) != 0 {
                                PortState::Closed
                            } else {
                                PortState::Filtered
                            };
                            results.insert(scanned_port, state);
                            pending_ports.remove(&scanned_port);
                            outstanding.remove(&(scanned_port, resp_dst_port));
                            if let Some(srcs) = port_srcs.get_mut(&scanned_port) {
                                srcs.remove(&resp_dst_port);
                                if srcs.is_empty() {
                                    port_srcs.remove(&scanned_port);
                                }
                            }
                        }
                    }
                } else if let Some(IcmpResponse::DestinationUnreachable {
                    code,
                    original_dst_ip,
                    original_dst_port,
                }) = parse_icmp_response(data.0)
                {
                    if original_dst_ip == dst_addr {
                        if let Some(srcs) = port_srcs.remove(&original_dst_port) {
                            // Update RTT for first src_port
                            if let Some(&first_src) = srcs.iter().next() {
                                if let Some((_, sent_time)) =
                                    outstanding.get(&(original_dst_port, first_src))
                                {
                                    timing.update_rtt(sent_time.elapsed());
                                }
                            }
                            let state = match code {
                                IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                                _ => PortState::Filtered,
                            };
                            results.insert(original_dst_port, state);
                            pending_ports.remove(&original_dst_port);
                            for src_port in srcs {
                                outstanding.remove(&(original_dst_port, src_port));
                                src_to_dst.remove(&src_port);
                            }
                        }
                    }
                }
            }
            // No artificial delay between retry rounds - nmap doesn't have this
        }

        // Phase 3: Mark remaining ports as Open|Filtered (no response after all retries)
        for port in pending_ports {
            results.entry(port).or_insert(PortState::OpenOrFiltered);
        }

        Ok(results)
    }
}

impl PortScanner for TcpMaimonScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP Window scanner using raw sockets.
///
/// Sends TCP packets with the ACK flag set and analyzes the TCP Window field
/// in RST responses. This scan type exploits differences in TCP stack
/// implementations where some systems (like HP-UX, AIX) return RST packets
/// with non-zero window sizes for closed ports.
///
/// # Port State Mapping
///
/// - RST with Window > 0 -> Port Closed (on some systems like HP-UX)
/// - RST with Window = 0 -> Port Open (on some systems)
/// - No response/ICMP -> Port Filtered
///
/// Note: Window scan behavior varies by target OS. Not all systems
/// exhibit different window sizes in RST responses.
#[derive(Debug)]
pub struct TcpWindowScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Tracks whether packet engine has been started.
    packet_engine_started: std::sync::atomic::AtomicBool,
}

impl TcpWindowScanner {
    /// Receives a packet using either the packet engine or raw socket.
    ///
    /// This helper method provides a unified interface for packet reception,
    /// preferring the `PACKET_MMAP` engine when available for zero-copy capture.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive packet data into
    /// * `timeout` - Maximum time to wait for a packet
    ///
    /// # Returns
    ///
    /// `Ok(Some(len))` if a packet was received, `Ok(None)` on timeout,
    /// or an error if reception fails.
    fn recv_packet(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        // If packet engine is available, use it for zero-copy capture
        if let Some(ref engine_arc) = self.packet_engine {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;

                    // Start engine if not yet started.
                    // If already started, the engine will return AlreadyStarted error,
                    // which we ignore because the engine is ready for use.
                    if !self
                        .packet_engine_started
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = engine.start().await.map_err(|e| {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        });
                        self.packet_engine_started
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }

                    // Receive with timeout
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None), // Timeout
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            // Fall back to raw socket reception
            // Convert io::Result<usize> to io::Result<Option<usize>>
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }

    /// Creates a new TCP Window scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpWindowScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP packets, not just TCP.
        // This is necessary because using IPPROTO_TCP causes the kernel's
        // TCP stack to consume RST responses before the raw socket can read them.
        let socket = RawSocket::with_protocol(255).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Try to create packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            config,
            packet_engine,
            packet_engine_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_window_probe(dst_addr, port)
    }

    /// Sends a TCP Window probe (ACK) and determines port state from RST window field.
    fn send_window_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with ACK flag only (same as ACK scan)
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .ack_flag()
            .window(65535)
            .badsum_if(self.config.badsum)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        // Use a receive loop to filter out non-matching responses
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::Filtered); // Timeout exceeded - no response means filtered
            } else {
                timeout - elapsed
            };

            // Receive response via packet engine (PACKET_MMAP) or raw socket
            let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining_timeout) {
                Ok(Some(len)) if len > 0 => {
                    // PACKET_MMAP captures at Ethernet layer, need to skip 14-byte Ethernet header
                    // Raw socket captures at IP layer, no skip needed
                    let packet_data = if self.packet_engine.is_some() {
                        if len > 14 {
                            &recv_buf[14..len]
                        } else {
                            &recv_buf[..len]
                        }
                    } else {
                        &recv_buf[..len]
                    };
                    (packet_data, len)
                }
                Ok(Some(_) | None) => return Ok(PortState::Filtered),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(PortState::Filtered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            };

            // Use parse_tcp_response first to get the source IP for matching
            if let Some((flags, _seq, _ack, resp_src_port, _resp_dst_port, src_ip)) =
                parse_tcp_response(data.0)
            {
                // For Window scan, we sent from src_port to dst_port
                // The RST response comes from dst_port to src_port
                // So we check if src_ip == target and resp_src_port == dst_port (target sent RST)
                if src_ip == dst_addr && resp_src_port == dst_port {
                    // Check for RST flag
                    if (flags & tcp_flags::RST) != 0 {
                        // Window scan: analyze window size in RST response
                        // Need to parse the window field from the TCP header
                        // TCP window is at offset 14-15 from TCP header start
                        let ip_header_len = ((data.0[0] & 0x0F) as usize) * 4;
                        let tcp_start = ip_header_len;
                        if data.0.len() >= tcp_start + 16 {
                            let window = u16::from_be_bytes([
                                data.0[tcp_start + 14],
                                data.0[tcp_start + 15],
                            ]);
                            // Window scan: analyze window size in RST response
                            // Linux (and most systems): Window == 0 -> Closed
                            // Some systems (HP-UX, old BSD): Window > 0 -> Open
                            if window == 0 {
                                return Ok(PortState::Closed);
                            }
                            return Ok(PortState::Open);
                        }
                        // Can't parse window, default to Closed
                        return Ok(PortState::Closed);
                    }
                    // Non-RST response (shouldn't happen for Window scan)
                    return Ok(PortState::Filtered);
                }
                // Response for different host/port - continue waiting
            } else if let Some(icmp_resp) = parse_icmp_response(data.0) {
                // Check if this ICMP response is for our probe
                if let Some(state) =
                    Self::handle_icmp_response_with_match(icmp_resp, dst_addr, dst_port)
                {
                    return Ok(state);
                }
                // ICMP response for different probe - continue waiting
            }
            // Loop continues to next iteration
        }
    }

    /// Handles ICMP response for Window scan.
    ///
    /// Returns `None` if the ICMP response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the ICMP response is for our probe.
    fn handle_icmp_response_with_match(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                // For Window scan, ICMP unreachable means filtered
                let _ = code;
                Some(PortState::Filtered)
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Mix PID with current time for randomness
        let pid_component = (std::process::id() % 1000) as u16;
        let time_component = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 1000) as u16;
        let offset = (pid_component + time_component) % 1000;
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

    /// Scans multiple ports in batch mode with nmap-style retransmissions.
    ///
    /// Sends ACK probes, collects responses, and resends probes for unresponsive
    /// ports up to `max_retries` times with exponential backoff.
    /// This handles rate limiting and packet loss like nmap does.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `ports` - List of ports to scan
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing a map of port numbers to port states.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission or reception fails.
    ///
    /// # Port State Mapping
    ///
    /// - RST + Window > 0 -> Open
    /// - RST + Window == 0 -> Closed
    /// - ICMP unreachable -> Filtered
    /// - No response after retries -> Filtered
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning with retransmissions requires handling send, receive, retry, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        // Limit batch size to prevent memory issues
        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();

        // Track ports that still need responses (not yet classified)
        let mut pending_ports: std::collections::HashSet<Port> =
            ports_to_scan.iter().copied().collect();
        let mut results: HashMap<Port, PortState> = HashMap::new();

        // Maximum retries from config (nmap default: 2, cap at 3 for stealth scans)
        // Using a lower cap because stealth scans are more likely to be rate-limited
        let max_retries = u32::from(self.config.max_retries.min(3));

        // Adaptive timing for nmap-style RTT estimation
        let mut timing = AdaptiveTiming::with_initial_rtt(self.config.initial_rtt);

        // Start packet engine BEFORE sending any probes to ensure the ring buffer
        // is ready to capture responses. Without this, RST responses that arrive
        // between probe sending and first recv_packet() call are lost.
        if let Some(ref engine_arc) = self.packet_engine {
            if !self
                .packet_engine_started
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut engine = engine_arc.lock().await;
                        let _ = engine.start().await;
                    });
                });
                self.packet_engine_started
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Nmap-style retry loop with adaptive timeout
        for _retry_round in 0..=max_retries {
            if pending_ports.is_empty() {
                break; // All ports have been classified
            }

            // Phase 1: Send probes for pending ports only
            let src_port = Self::generate_source_port();
            let round_start = Instant::now();

            for dst_port in &pending_ports {
                let seq = Self::generate_sequence_number();

                // Build TCP packet with ACK flag only
                let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                    .seq(seq)
                    .ack_flag()
                    .window(65535)
                    .badsum_if(self.config.badsum)
                    .build();

                let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                self.socket
                    .send_packet(&packet, &port_sockaddr)
                    .map_err(|e| {
                        rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::SendError { source: e },
                        ))
                    })?;
            }

            // Phase 2: Collect responses with adaptive timeout
            // Nmap-style: timeout = SRTT + 4*RTTVAR (clamped to 100ms-10000ms)
            let current_timeout = timing.recommended_timeout();
            let deadline = Instant::now() + current_timeout;
            let mut recv_buf = vec![0u8; 65535];

            while Instant::now() < deadline && !pending_ports.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                // Use packet engine (PACKET_MMAP) or raw socket reception
                let remaining = remaining.min(Duration::from_millis(200));

                // Receive response via packet engine or raw socket
                let data = match self.recv_packet(recv_buf.as_mut_slice(), remaining) {
                    Ok(Some(len)) if len > 0 => {
                        // PACKET_MMAP captures at Ethernet layer, need to skip 14-byte Ethernet header
                        // Raw socket captures at IP layer, no skip needed
                        let packet_data = if self.packet_engine.is_some() {
                            if len > 14 {
                                &recv_buf[14..len]
                            } else {
                                &recv_buf[..len]
                            }
                        } else {
                            &recv_buf[..len]
                        };
                        (packet_data, len)
                    }
                    Ok(Some(_) | None) => continue,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                };

                // Check for TCP response with window field
                if let Some((flags, _seq, _ack, resp_src_port, _resp_dst_port, src_ip, window)) =
                    parse_tcp_response_with_window(data.0)
                {
                    if src_ip == dst_addr && pending_ports.contains(&resp_src_port) {
                        // Update RTT estimate for adaptive timing
                        timing.update_rtt(round_start.elapsed());
                        // For Window scan, analyze TCP window field in RST response
                        let state = if (flags & tcp_flags::RST) != 0 {
                            // Window scan: Window == 0 = Closed (Linux), Window > 0 = Open (some systems)
                            if window == 0 {
                                PortState::Closed
                            } else {
                                PortState::Open
                            }
                        } else {
                            PortState::Filtered
                        };
                        results.insert(resp_src_port, state);
                        pending_ports.remove(&resp_src_port);
                    }
                } else if let Some(IcmpResponse::DestinationUnreachable {
                    original_dst_ip,
                    original_dst_port,
                    ..
                }) = parse_icmp_response(data.0)
                {
                    if original_dst_ip == dst_addr && pending_ports.remove(&original_dst_port) {
                        // Update RTT estimate for adaptive timing
                        timing.update_rtt(round_start.elapsed());
                        // ICMP unreachable means filtered
                        results.insert(original_dst_port, PortState::Filtered);
                    }
                }
            }
            // No artificial delay between retry rounds - nmap doesn't have this
        }

        // Phase 3: Mark remaining ports as Filtered (no response after all retries)
        for port in pending_ports {
            results.entry(port).or_insert(PortState::Filtered);
        }

        Ok(results)
    }
}

impl PortScanner for TcpWindowScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fin_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpFinScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_fin_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpFinScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[tokio::test]
    async fn test_null_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpNullScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_null_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpNullScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[tokio::test]
    async fn test_xmas_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpXmasScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_xmas_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpXmasScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[tokio::test]
    async fn test_ack_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpAckScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_ack_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpAckScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[tokio::test]
    async fn test_maimon_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpMaimonScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_maimon_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpMaimonScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_generate_source_port() {
        let port = TcpFinScanner::generate_source_port();
        assert!(port >= SOURCE_PORT_START);
        assert!(port < SOURCE_PORT_START + 1000);
    }

    #[test]
    fn test_generate_sequence_number() {
        let seq1 = TcpFinScanner::generate_sequence_number();
        let seq2 = TcpFinScanner::generate_sequence_number();
        let diff = seq1.abs_diff(seq2);
        assert!(
            diff < 1_000_000,
            "Sequence numbers should be close in value"
        );
    }

    #[test]
    fn test_fin_handle_icmp_port_unreachable() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: dst_port,
        };

        let result = TcpFinScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, Some(PortState::Closed));
    }

    #[test]
    fn test_fin_handle_icmp_admin_prohibited() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: dst_ip,
            original_dst_port: dst_port,
        };

        let result = TcpFinScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, Some(PortState::Filtered));
    }

    #[test]
    fn test_fin_handle_icmp_mismatch() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: 443, // Different port
        };

        let result = TcpFinScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        // Non-matching ICMP responses return None to continue waiting
        assert_eq!(result, None);
    }

    #[test]
    fn test_ack_handle_icmp() {
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            original_dst_port: 80,
        };
        let expected_dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let expected_dst_port = 80;

        let result = TcpAckScanner::handle_icmp_response_with_match(
            icmp_resp,
            expected_dst_ip,
            expected_dst_port,
        );
        assert_eq!(result, Some(PortState::Filtered));
    }

    #[test]
    fn test_tcp_flags() {
        assert_eq!(tcp_flags::RST, 0x04);
    }

    #[tokio::test]
    async fn test_window_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpWindowScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_window_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpWindowScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_window_handle_icmp() {
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            original_dst_port: 80,
        };
        let expected_dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let expected_dst_port = 80;

        let result = TcpWindowScanner::handle_icmp_response_with_match(
            icmp_resp,
            expected_dst_ip,
            expected_dst_port,
        );
        assert_eq!(result, Some(PortState::Filtered));
    }
}
