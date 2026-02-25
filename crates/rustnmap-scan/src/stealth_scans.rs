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
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_evasion::DecoyScheduler;
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_tcp_response, parse_tcp_response_full, IcmpResponse,
    IcmpUnreachableCode, RawSocket, TcpPacketBuilder,
};
use rustnmap_target::Target;

/// Default source port range for outbound probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// Maximum batch size for batch scanning operations.
/// Limits memory usage and prevents overwhelming the network.
pub const MAX_BATCH_SIZE: usize = 1024;

/// Ethernet protocol for all traffic.
const ETH_P_ALL: u16 = 0x0003;
/// Ethernet header size.
const ETH_HDR_SIZE: usize = 14;

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

    /// Receives a packet from the `AF_PACKET` socket with a timeout.
    ///
    /// Uses `poll()` to wait for data availability before receiving.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for data
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(data))` if a packet was received,
    /// `Ok(None)` if timeout elapsed without data, or `Err` on error.
    ///
    /// # Errors
    ///
    /// Returns an error if `poll()` or `recvfrom()` fails.
    fn recv_packet_with_timeout(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        // SAFETY: pollfd is a POD struct. Zeroed memory is valid initialization.
        let mut pollfd: libc::pollfd = unsafe { mem::zeroed() };
        pollfd.fd = self.fd.as_raw_fd();
        pollfd.events = libc::POLLIN;

        // Convert timeout to milliseconds for poll()
        // Round up to ensure at least 1ms poll for non-zero timeouts
        let timeout_ms = if timeout.is_zero() {
            0
        } else {
            timeout
                .as_millis()
                .try_into()
                .unwrap_or(i32::MAX)
                .max(1)
        };

        // SAFETY: pollfd is properly initialized with fd and events.
        // nfds is 1 (single pollfd). timeout is valid in milliseconds.
        let ret = unsafe { libc::poll(&raw mut pollfd, 1, timeout_ms) };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if ret == 0 {
            // Poll timeout - no data available
            return Ok(None);
        }

        // Data is available, receive it
        self.recv_packet()
    }
}

/// TCP flag constants for reference.
mod tcp_flags {
    /// RST flag (0x04).
    pub const RST: u8 = 0x04;
}

/// Creates an `AF_PACKET` socket for the given local address.
///
/// This function attempts to create an `AF_PACKET` socket bound to the
/// network interface that corresponds to the given local IP address.
///
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
    let if_name = get_interface_for_ip(local_addr)?;

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
    /// Optional `AF_PACKET` socket for L2 packet capture.
    packet_socket: Option<Arc<SimpleAfPacket>>,
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

        // Try to create AF_PACKET socket for L2 packet capture.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_socket = create_packet_socket(local_addr);

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_socket,
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

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining_timeout.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
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
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, resp_dst_port, src_ip)) = parse_tcp_response(data.0) {
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
    /// Returns an error if:
    /// - Packet transmission fails due to network issues
    /// - Raw socket receive fails with a non-timeout error
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning requires handling send, receive, and result collection in one method for clarity"
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

        // Phase 1: Send all probes
        // Forward map: (dst_port, src_port) -> (seq, sent_time)
        let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
        // Reverse map: src_port -> dst_port for O(1) TCP response matching
        let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
        // Port tracking: dst_port -> set of src_ports for O(1) ICMP matching
        let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

        for dst_port in &ports_to_scan {
            let src_port = Self::generate_source_port();
            let seq = Self::generate_sequence_number();

            // Handle decoy scanning: send from multiple source IPs
            if let Some(scheduler) = &self.decoy_scheduler {
                let mut scheduler = scheduler.clone();
                scheduler.reset();

                while let Some(src_ip) = scheduler.next_source() {
                    let src_ipv4 = match src_ip {
                        IpAddr::V4(addr) => addr,
                        IpAddr::V6(_) => continue, // Skip IPv6 for now
                    };

                    let packet = TcpPacketBuilder::new(src_ipv4, dst_addr, src_port, *dst_port)
                        .seq(seq)
                        .fin()
                        .window(65535)
                        .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
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
                let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                    .seq(seq)
                    .fin()
                    .window(65535)
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

        // Phase 2: Collect responses until timeout
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let deadline = Instant::now() + self.config.initial_rtt;
        let mut recv_buf = vec![0u8; 65535];
        let mut _af_packet_count = 0;
        let mut _raw_socket_count = 0;

        while Instant::now() < deadline && !outstanding.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        _af_packet_count += 1;
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
                    .socket
                    .recv_packet(recv_buf.as_mut_slice(), Some(remaining))
                {
                    Ok(len) if len > 0 => {
                        _raw_socket_count += 1;
                        (&recv_buf[..len], len)
                    }
                    Ok(_) => continue,
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
                }
            };

            // Check for TCP response
            if let Some((flags, _seq, _ack, src_port, dst_port, src_ip)) = parse_tcp_response(data.0) {
                if src_ip == dst_addr {
                    // For stealth scans, RST responses come FROM the target port TO our source port
                    // So we match based on dst_port (our source port) instead of src_port
                    if let Some(scanned_port) = src_to_dst.remove(&dst_port) {
                        let state = if (flags & tcp_flags::RST) != 0 {
                            PortState::Closed
                        } else {
                            PortState::Filtered
                        };
                        results.insert(scanned_port, state);
                        // O(1) removal instead of O(n) retain
                        outstanding.remove(&(scanned_port, src_port));
                        // Also remove from port_srcs
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
                // O(1) check if we have probes for this port
                if original_dst_ip == dst_addr {
                    if let Some(srcs) = port_srcs.remove(&original_dst_port) {
                        let state = match code {
                            IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                            _ => PortState::Filtered,
                        };
                        results.insert(original_dst_port, state);
                        // Remove all src_ports for this dst_port
                        for src_port in srcs {
                            outstanding.remove(&(original_dst_port, src_port));
                            src_to_dst.remove(&src_port);
                        }
                    }
                }
            }
        }

        // Phase 3: Mark remaining ports as Open|Filtered (no response)
        for (dst_port, _) in outstanding.keys() {
            results
                .entry(*dst_port)
                .or_insert(PortState::OpenOrFiltered);
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
    /// Optional `AF_PACKET` socket for L2 packet capture.
    packet_socket: Option<Arc<SimpleAfPacket>>,
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

        // Try to create AF_PACKET socket for L2 packet capture.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_socket = create_packet_socket(local_addr);

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_socket,
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

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining_timeout.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
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
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data.0) {
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

    /// Scans multiple ports in batch mode for improved performance.
    ///
    /// See [`TcpFinScanner::scan_ports_batch`] for detailed documentation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet transmission fails due to network issues
    /// - Raw socket receive fails with a non-timeout error
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning requires handling send, receive, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();
        // Forward map: (dst_port, src_port) -> (seq, sent_time)
        let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
        // Reverse map: src_port -> dst_port for O(1) TCP response matching
        let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
        // Port tracking: dst_port -> set of src_ports for O(1) ICMP matching
        let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

        // Phase 1: Send all probes (NULL = no flags)
        for dst_port in &ports_to_scan {
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
                        .window(65535)
                        .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
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
                let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                    .seq(seq)
                    .window(65535)
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

        // Phase 2: Collect responses
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let deadline = Instant::now() + self.config.initial_rtt;
        let mut recv_buf = vec![0u8; 65535];
        let mut _af_packet_count = 0;
        let mut _raw_socket_count = 0;

        while Instant::now() < deadline && !outstanding.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        _af_packet_count += 1;
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
                    .socket
                    .recv_packet(recv_buf.as_mut_slice(), Some(remaining))
                {
                    Ok(len) if len > 0 => {
                        _raw_socket_count += 1;
                        (&recv_buf[..len], len)
                    }
                    Ok(_) => continue,
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
                }
            };

            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data.0) {
                if src_ip == dst_addr {
                    // O(1) lookup
                    if let Some(dst_port) = src_to_dst.remove(&src_port) {
                        let state = if (flags & tcp_flags::RST) != 0 {
                            PortState::Closed
                        } else {
                            PortState::Filtered
                        };
                        results.insert(dst_port, state);
                        outstanding.remove(&(dst_port, src_port));
                        if let Some(srcs) = port_srcs.get_mut(&dst_port) {
                            srcs.remove(&src_port);
                            if srcs.is_empty() {
                                port_srcs.remove(&dst_port);
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
                        let state = match code {
                            IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                            _ => PortState::Filtered,
                        };
                        results.insert(original_dst_port, state);
                        for src_port in srcs {
                            outstanding.remove(&(original_dst_port, src_port));
                            src_to_dst.remove(&src_port);
                        }
                    }
                }
            }
        }

        // Phase 3: Mark remaining as Open|Filtered
        for (dst_port, _) in outstanding.keys() {
            results
                .entry(*dst_port)
                .or_insert(PortState::OpenOrFiltered);
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
    /// Optional `AF_PACKET` socket for L2 packet capture.
    packet_socket: Option<Arc<SimpleAfPacket>>,
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

        // Try to create AF_PACKET socket for L2 packet capture.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_socket = create_packet_socket(local_addr);

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_socket,
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

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining_timeout.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
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
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data.0) {
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

    /// Scans multiple ports in batch mode for improved performance.
    ///
    /// See [`TcpFinScanner::scan_ports_batch`] for detailed documentation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet transmission fails due to network issues
    /// - Raw socket receive fails with a non-timeout error
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning requires handling send, receive, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();
        let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
        let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
        let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

        // Phase 1: Send all probes (XMAS = FIN+PSH+URG)
        for dst_port in &ports_to_scan {
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
                        .psh()
                        .urg()
                        .window(65535)
                        .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
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
                let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                    .seq(seq)
                    .fin()
                    .psh()
                    .urg()
                    .window(65535)
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

        // Phase 2: Collect responses
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let deadline = Instant::now() + self.config.initial_rtt;
        let mut recv_buf = vec![0u8; 65535];
        let mut _af_packet_count = 0;
        let mut _raw_socket_count = 0;

        while Instant::now() < deadline && !outstanding.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        _af_packet_count += 1;
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
                    .socket
                    .recv_packet(recv_buf.as_mut_slice(), Some(remaining))
                {
                    Ok(len) if len > 0 => {
                        _raw_socket_count += 1;
                        (&recv_buf[..len], len)
                    }
                    Ok(_) => continue,
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
                }
            };

            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data.0) {
                if src_ip == dst_addr {
                    if let Some(dst_port) = src_to_dst.remove(&src_port) {
                        let state = if (flags & tcp_flags::RST) != 0 {
                            PortState::Closed
                        } else {
                            PortState::Filtered
                        };
                        results.insert(dst_port, state);
                        outstanding.remove(&(dst_port, src_port));
                        if let Some(srcs) = port_srcs.get_mut(&dst_port) {
                            srcs.remove(&src_port);
                            if srcs.is_empty() {
                                port_srcs.remove(&dst_port);
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
                        let state = match code {
                            IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                            _ => PortState::Filtered,
                        };
                        results.insert(original_dst_port, state);
                        for src_port in srcs {
                            outstanding.remove(&(original_dst_port, src_port));
                            src_to_dst.remove(&src_port);
                        }
                    }
                }
            }
        }

        // Phase 3: Mark remaining as Open|Filtered
        for (dst_port, _) in outstanding.keys() {
            results
                .entry(*dst_port)
                .or_insert(PortState::OpenOrFiltered);
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
    /// Optional `AF_PACKET` socket for L2 packet capture.
    packet_socket: Option<Arc<SimpleAfPacket>>,
}

impl TcpAckScanner {
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

        // Try to create AF_PACKET socket for L2 packet capture.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_socket = create_packet_socket(local_addr);

        Ok(Self {
            local_addr,
            socket,
            config,
            packet_socket,
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

        // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
        // Fall back to raw socket if packet socket is not available
        #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
        let mut packet_data = None;
        let received = if let Some(ref pkt_sock) = self.packet_socket {
            match pkt_sock.recv_packet() {
                Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                    packet_data = Some(data);
                    packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                }
                _ => None,
            }
        } else {
            None
        };

        // Fall back to raw socket if AF_PACKET didn't receive data
        let data = if let Some((slice, len)) = received {
            (slice, len)
        } else {
            match self
                .socket
                .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
            {
                Ok(len) if len > 0 => (&recv_buf[..len], len),
                Ok(_) => return Ok(PortState::Filtered),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
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
            }
        };

        // Check for TCP response first
        if let Some((flags, _seq, _ack, src_port, _dst_port, _src_ip)) = parse_tcp_response(data.0) {
            if src_port != dst_port {
                return Ok(PortState::Filtered);
            }

            // For ACK scan, RST means the port is unfiltered (reachable)
            if (flags & tcp_flags::RST) != 0 {
                return Ok(PortState::Unfiltered);
            }

            return Ok(PortState::Filtered);
        }

        // Check for ICMP response
        if let Some(icmp_resp) = parse_icmp_response(data.0) {
            return Ok(Self::handle_icmp_response(icmp_resp));
        }

        Ok(PortState::Filtered)
    }

    /// Handles ICMP response for ACK scan.
    fn handle_icmp_response(_icmp_resp: IcmpResponse) -> PortState {
        PortState::Filtered
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
    /// Optional `AF_PACKET` socket for L2 packet capture.
    packet_socket: Option<Arc<SimpleAfPacket>>,
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

        // Try to create AF_PACKET socket for L2 packet capture.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_socket = create_packet_socket(local_addr);

        Ok(Self {
            local_addr,
            socket,
            config,
            decoy_scheduler,
            packet_socket,
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

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining_timeout.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
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
                }
            };

            // Check for TCP response first
            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data.0) {
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

    /// Scans multiple ports in batch mode for improved performance.
    ///
    /// See [`TcpFinScanner::scan_ports_batch`] for detailed documentation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet transmission fails due to network issues
    /// - Raw socket receive fails with a non-timeout error
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning requires handling send, receive, and result collection in one method for clarity"
    )]
    pub fn scan_ports_batch(
        &self,
        dst_addr: Ipv4Addr,
        ports: &[Port],
    ) -> ScanResult<HashMap<Port, PortState>> {
        if ports.is_empty() {
            return Ok(HashMap::new());
        }

        let ports_to_scan: Vec<Port> = ports.iter().copied().take(MAX_BATCH_SIZE).collect();
        let mut outstanding: HashMap<(Port, u16), (u32, Instant)> = HashMap::new();
        let mut src_to_dst: HashMap<u16, Port> = HashMap::new();
        let mut port_srcs: HashMap<Port, std::collections::HashSet<u16>> = HashMap::new();

        // Phase 1: Send all probes (Maimon = FIN+ACK)
        for dst_port in &ports_to_scan {
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
                        .ack_flag()
                        .window(65535)
                        .build();

                    let port_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), *dst_port);
                    self.socket
                        .send_packet(&packet, &port_sockaddr)
                        .map_err(|e| {
                            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::SendError { source: e },
                            ))
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
                let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, *dst_port)
                    .seq(seq)
                    .fin()
                    .ack_flag()
                    .window(65535)
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

        // Phase 2: Collect responses
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let deadline = Instant::now() + self.config.initial_rtt;
        let mut recv_buf = vec![0u8; 65535];
        let mut _af_packet_count = 0;
        let mut _raw_socket_count = 0;

        while Instant::now() < deadline && !outstanding.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
            // Use a short timeout (200ms or remaining timeout) to wait for RST responses
            // Fall back to raw socket if packet socket is not available or times out
            #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
            let mut packet_data = None;
            let packet_timeout = remaining.min(Duration::from_millis(200));
            let received = if let Some(ref pkt_sock) = self.packet_socket {
                match pkt_sock.recv_packet_with_timeout(packet_timeout) {
                    Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                        _af_packet_count += 1;
                        packet_data = Some(data);
                        packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Fall back to raw socket if AF_PACKET didn't receive data
            let data = if let Some((slice, len)) = received {
                (slice, len)
            } else {
                match self
                    .socket
                    .recv_packet(recv_buf.as_mut_slice(), Some(remaining))
                {
                    Ok(len) if len > 0 => {
                        _raw_socket_count += 1;
                        (&recv_buf[..len], len)
                    }
                    Ok(_) => continue,
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
                }
            };

            if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(data.0) {
                if src_ip == dst_addr {
                    if let Some(dst_port) = src_to_dst.remove(&src_port) {
                        let state = if (flags & tcp_flags::RST) != 0 {
                            PortState::Closed
                        } else {
                            PortState::Filtered
                        };
                        results.insert(dst_port, state);
                        outstanding.remove(&(dst_port, src_port));
                        if let Some(srcs) = port_srcs.get_mut(&dst_port) {
                            srcs.remove(&src_port);
                            if srcs.is_empty() {
                                port_srcs.remove(&dst_port);
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
                        let state = match code {
                            IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                            _ => PortState::Filtered,
                        };
                        results.insert(original_dst_port, state);
                        for src_port in srcs {
                            outstanding.remove(&(original_dst_port, src_port));
                            src_to_dst.remove(&src_port);
                        }
                    }
                }
            }
        }

        // Phase 3: Mark remaining as Open|Filtered
        for (dst_port, _) in outstanding.keys() {
            results
                .entry(*dst_port)
                .or_insert(PortState::OpenOrFiltered);
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
    /// Optional `AF_PACKET` socket for L2 packet capture.
    packet_socket: Option<Arc<SimpleAfPacket>>,
}

impl TcpWindowScanner {
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

        // Try to create AF_PACKET socket for L2 packet capture.
        // This allows receiving RST responses that the kernel TCP stack would otherwise consume.
        let packet_socket = create_packet_socket(local_addr);

        Ok(Self {
            local_addr,
            socket,
            config,
            packet_socket,
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

        // Try AF_PACKET first if available (L2 capture - receives all TCP responses)
        // Fall back to raw socket if packet socket is not available
        #[expect(unused_assignments, reason = "packet_data extends lifetime of received data")]
        let mut packet_data = None;
        let received = if let Some(ref pkt_sock) = self.packet_socket {
            match pkt_sock.recv_packet() {
                Ok(Some(data)) if data.len() > ETH_HDR_SIZE => {
                    packet_data = Some(data);
                    packet_data.as_ref().map(|d| (&d[ETH_HDR_SIZE..], d.len() - ETH_HDR_SIZE))
                }
                _ => None,
            }
        } else {
            None
        };

        // Fall back to raw socket if AF_PACKET didn't receive data
        let data = if let Some((slice, len)) = received {
            (slice, len)
        } else {
            match self
                .socket
                .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
            {
                Ok(len) if len > 0 => (&recv_buf[..len], len),
                Ok(_) => return Ok(PortState::Filtered),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
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
            }
        };

        // Use full TCP response parser to get window field
        if let Some(tcp_resp) = parse_tcp_response_full(data.0) {
            if tcp_resp.src_port != dst_port {
                return Ok(PortState::Filtered);
            }

            // Check for RST flag
            if (tcp_resp.flags & tcp_flags::RST) != 0 {
                // Window scan: analyze window size in RST response
                // Some systems (HP-UX, AIX) return non-zero window for closed ports
                if tcp_resp.window > 0 {
                    return Ok(PortState::Closed);
                }
                return Ok(PortState::Open);
            }

            return Ok(PortState::Filtered);
        }

        // Check for ICMP response
        if let Some(icmp_resp) = parse_icmp_response(data.0) {
            return Ok(Self::handle_icmp_response(icmp_resp));
        }

        Ok(PortState::Filtered)
    }

    /// Handles ICMP response for Window scan.
    fn handle_icmp_response(_icmp_resp: IcmpResponse) -> PortState {
        PortState::Filtered
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

    #[test]
    fn test_fin_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpFinScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_fin_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpFinScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_null_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpNullScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_null_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpNullScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_xmas_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpXmasScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_xmas_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpXmasScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_ack_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpAckScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_ack_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpAckScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_maimon_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpMaimonScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_maimon_scanner_requires_root() {
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

        let result = TcpAckScanner::handle_icmp_response(icmp_resp);
        assert_eq!(result, PortState::Filtered);
    }

    #[test]
    fn test_tcp_flags() {
        assert_eq!(tcp_flags::RST, 0x04);
    }

    #[test]
    fn test_window_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpWindowScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_window_scanner_requires_root() {
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

        let result = TcpWindowScanner::handle_icmp_response(icmp_resp);
        assert_eq!(result, PortState::Filtered);
    }
}
