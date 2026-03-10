//! Network primitives and socket abstractions for `RustNmap`.
//!
//! This crate provides low-level network access including raw socket creation,
//! packet I/O, and network interface management.

#![warn(missing_docs)]

use rustnmap_common::Result;

/// Creates a raw socket for packet capture and injection.
///
/// # Errors
///
/// Returns an error if the socket cannot be created due to insufficient permissions
/// or system limitations.
pub fn create_raw_socket() -> Result<raw_socket::RawSocket> {
    raw_socket::RawSocket::new()
}

/// Raw socket module for Linux packet I/O.
pub mod raw_socket {
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::time::Duration;

    use rustnmap_common::{Ipv4Addr, Port};

    /// Raw socket handle for packet I/O.
    #[derive(Debug)]
    pub struct RawSocket {
        /// The owned file descriptor for the socket.
        fd: OwnedFd,
    }

    impl RawSocket {
        /// Creates a new raw socket using `IPPROTO_RAW` (255).
        ///
        /// This creates a socket that can send packets with custom IP headers.
        /// For receiving responses, use [`Self::with_protocol`] with the
        /// specific protocol (e.g., `IPPROTO_TCP` for TCP responses).
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The process lacks `CAP_NET_RAW` capability
        /// - The system runs out of file descriptors
        /// - The socket protocol is not supported
        pub fn new() -> super::Result<Self> {
            Self::with_protocol(255)
        }

        /// Creates a raw socket for a specific IP protocol.
        ///
        /// # Arguments
        ///
        /// * `protocol` - The IP protocol number (e.g., 6 for TCP, 17 for UDP, 1 for ICMP)
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The process lacks `CAP_NET_RAW` capability
        /// - The system runs out of file descriptors
        /// - The socket protocol is not supported
        ///
        /// # Examples
        ///
        /// ```rust,no_run
        /// use rustnmap_net::raw_socket::RawSocket;
        ///
        /// // Create a TCP raw socket for receiving TCP responses
        /// let tcp_socket = RawSocket::with_protocol(6).unwrap();
        ///
        /// // Create a UDP raw socket for receiving UDP responses
        /// let udp_socket = RawSocket::with_protocol(17).unwrap();
        /// ```
        pub fn with_protocol(protocol: u8) -> super::Result<Self> {
            use rustnmap_common::error::NetworkError;
            use rustnmap_common::Error;
            use socket2::{Domain, Protocol, Type};

            let socket = socket2::Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(i32::from(protocol))),
            )
            .map_err(|e| Error::Network(NetworkError::RawSocketCreation { source: e }))?;

            // Enable IP_HDRINCL so we can provide our own IP header when sending.
            // IPPROTO_RAW (255) sets this automatically, but other protocols do not.
            // Without this, the kernel prepends its own IP header, corrupting our
            // carefully crafted packet (source IP, identification, TTL, etc.).
            let enable: libc::c_int = 1;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "size_of<c_int> is always 4, safely fits in socklen_t"
            )]
            // SAFETY: setsockopt with valid fd, valid option pointer, and correct size
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    (&raw const enable).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(Error::Network(NetworkError::RawSocketCreation {
                    source: std::io::Error::last_os_error(),
                }));
            }

            // Socket uses blocking mode with SO_RCVTIMEO for timeouts.
            // Non-blocking mode would ignore SO_RCVTIMEO and require poll/select.

            Ok(Self { fd: socket.into() })
        }

        /// Creates a raw IPv6 socket for a specific IP protocol.
        ///
        /// # Arguments
        ///
        /// * `protocol` - The IP protocol number (e.g., 6 for TCP, 17 for UDP, 58 for `ICMPv6`)
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The process lacks `CAP_NET_RAW` capability
        /// - The system runs out of file descriptors
        /// - The socket protocol is not supported
        ///
        /// # Examples
        ///
        /// ```rust,no_run
        /// use rustnmap_net::raw_socket::RawSocket;
        ///
        /// // Create an IPv6 TCP raw socket for receiving TCP responses
        /// let tcp_socket = RawSocket::with_protocol_ipv6(6).unwrap();
        ///
        /// // Create an IPv6 UDP raw socket for receiving UDP responses
        /// let udp_socket = RawSocket::with_protocol_ipv6(17).unwrap();
        /// ```
        pub fn with_protocol_ipv6(protocol: u8) -> super::Result<Self> {
            use rustnmap_common::error::NetworkError;
            use rustnmap_common::Error;
            use socket2::{Domain, Protocol, Type};

            let socket = socket2::Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(i32::from(protocol))),
            )
            .map_err(|e| Error::Network(NetworkError::RawSocketCreation { source: e }))?;

            // Socket uses blocking mode with SO_RCVTIMEO for timeouts.
            // Non-blocking mode would ignore SO_RCVTIMEO and require poll/select.

            Ok(Self { fd: socket.into() })
        }

        /// Sends a raw packet.
        ///
        /// # Arguments
        ///
        /// * `packet` - The raw packet bytes to send
        /// * `addr` - The destination address
        ///
        /// # Errors
        ///
        /// Returns an error if the packet cannot be sent.
        ///
        /// # Safety
        ///
        /// The caller must ensure the packet is properly formatted.
        pub fn send_packet(&self, packet: &[u8], addr: &SocketAddr) -> io::Result<usize> {
            let flags = libc::MSG_NOSIGNAL;
            let sockaddr = socket2::SockAddr::from(*addr);

            // SAFETY: sendto with valid fd, valid packet buffer, and valid address
            let result = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    flags,
                    sockaddr.as_ptr().cast::<libc::sockaddr>(),
                    sockaddr.len(),
                )
            };

            if result < 0 {
                return Err(io::Error::last_os_error());
            }

            #[expect(
                clippy::cast_sign_loss,
                reason = "sendto returns non-negative on success"
            )]
            {
                Ok(result as usize)
            }
        }

        /// Sets the TTL (Time To Live) for packets sent on this socket.
        ///
        /// # Arguments
        ///
        /// * `ttl` - The TTL value (0-255)
        ///
        /// # Errors
        ///
        /// Returns an error if the TTL cannot be set.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "size_of<u32> is always 4, safely fits in socklen_t"
        )]
        pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
            // SAFETY: setsockopt with valid fd and valid ttl value
            let ret = unsafe {
                libc::setsockopt(
                    self.fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_TTL,
                    (&raw const ttl).cast::<libc::c_void>(),
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }

        /// Binds the raw socket to a specific source IP address.
        ///
        /// This is critical for localhost scanning: when targeting 127.0.0.1,
        /// the socket must be bound to a loopback address so that responses
        /// are routed via the loopback interface and can be captured.
        ///
        /// Without binding, the kernel selects the source address based on
        /// the routing table, which typically results in the primary interface
        /// address being used even for loopback targets.
        ///
        /// # Arguments
        ///
        /// * `src_addr` - The source IP address to bind to
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The address is already in use
        /// - The address is not available on this host
        /// - Permission denied
        ///
        /// # Example
        ///
        /// ```rust,no_run
        /// use rustnmap_net::raw_socket::RawSocket;
        /// use std::net::Ipv4Addr;
        ///
        /// // Create a raw socket for localhost scanning
        /// let socket = RawSocket::with_protocol(6).unwrap();
        /// socket.bind(Ipv4Addr::new(127, 0, 0, 1)).unwrap();
        /// ```
        pub fn bind(&self, src_addr: Ipv4Addr) -> io::Result<()> {
            let addr_bytes = src_addr.octets();

            // Create sockaddr_in structure for binding
            #[expect(
                clippy::cast_possible_truncation,
                reason = "AF_INET (2) always fits in sa_family_t (u16)"
            )]
            let sin_family = libc::AF_INET as libc::sa_family_t;
            let sockaddr = libc::sockaddr_in {
                sin_family,
                sin_port: 0, // Let kernel choose port
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([
                        addr_bytes[3],
                        addr_bytes[2],
                        addr_bytes[1],
                        addr_bytes[0],
                    ]),
                },
                sin_zero: [0; 8],
            };

            // SAFETY: bind() with valid fd and valid sockaddr pointer
            // The size_of::<sockaddr_in>() is 16 bytes, which always fits in socklen_t (u32)
            #[expect(
                clippy::cast_possible_truncation,
                reason = "size_of::<sockaddr_in>() is 16, always fits in socklen_t"
            )]
            let ret = unsafe {
                libc::bind(
                    self.fd.as_raw_fd(),
                    (&raw const sockaddr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }

        /// Receives a raw packet.
        ///
        /// # Arguments
        ///
        /// * `buf` - The buffer to receive data into
        /// * `timeout` - Optional timeout for the receive operation
        ///
        /// # Errors
        ///
        /// Returns an error if the receive operation fails or times out.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "OS types may have different sizes"
        )]
        pub fn recv_packet(&self, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
            // Set timeout if specified
            if let Some(to) = timeout {
                let tv = libc::timeval {
                    #[expect(clippy::cast_possible_wrap, reason = "time_t on Linux is i64")]
                    tv_sec: to.as_secs() as libc::time_t,
                    tv_usec: libc::suseconds_t::from(to.subsec_micros()),
                };
                // SAFETY: setsockopt with valid fd and valid timeval pointer
                let ret = unsafe {
                    libc::setsockopt(
                        self.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&raw const tv).cast::<libc::c_void>(),
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            // SAFETY: recvfrom with valid fd and valid buffer
            let result = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if result < 0 {
                return Err(io::Error::last_os_error());
            }

            #[expect(
                clippy::cast_sign_loss,
                reason = "recvfrom returns non-negative on success"
            )]
            {
                Ok(result as usize)
            }
        }
    }

    /// TCP packet builder for constructing raw TCP packets.
    #[derive(Debug)]
    pub struct TcpPacketBuilder {
        /// Source IP address.
        src_ip: Ipv4Addr,
        /// Destination IP address.
        dst_ip: Ipv4Addr,
        /// Source port.
        src_port: Port,
        /// Destination port.
        dst_port: Port,
        /// Sequence number.
        seq: u32,
        /// Acknowledgment number.
        ack: u32,
        /// TCP flags.
        flags: u8,
        /// Window size.
        window: u16,
        /// TCP options.
        options: Vec<u8>,
        /// IP identification field.
        identification: u16,
    }

    impl TcpPacketBuilder {
        /// Creates a new TCP packet builder with random IP identification.
        #[must_use]
        pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: Port, dst_port: Port) -> Self {
            use rand::Rng;
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq: 0,
                ack: 0,
                flags: 0,
                window: 65535,
                options: Vec::new(),
                identification: rand::rng().random(),
            }
        }

        /// Sets the sequence number.
        #[must_use]
        pub const fn seq(mut self, seq: u32) -> Self {
            self.seq = seq;
            self
        }

        /// Sets the acknowledgment number.
        #[must_use]
        pub const fn ack(mut self, ack: u32) -> Self {
            self.ack = ack;
            self
        }

        /// Sets the SYN flag.
        #[must_use]
        pub const fn syn(mut self) -> Self {
            self.flags |= 0x02;
            self
        }

        /// Sets the ACK flag.
        #[must_use]
        pub const fn ack_flag(mut self) -> Self {
            self.flags |= 0x10;
            self
        }

        /// Sets the RST flag.
        #[must_use]
        pub const fn rst(mut self) -> Self {
            self.flags |= 0x04;
            self
        }

        /// Sets the FIN flag.
        #[must_use]
        pub const fn fin(mut self) -> Self {
            self.flags |= 0x01;
            self
        }

        /// Sets the PSH (Push) flag.
        #[must_use]
        pub const fn psh(mut self) -> Self {
            self.flags |= 0x08;
            self
        }

        /// Sets the URG (Urgent) flag.
        #[must_use]
        pub const fn urg(mut self) -> Self {
            self.flags |= 0x20;
            self
        }

        /// Sets the window size.
        #[must_use]
        pub const fn window(mut self, window: u16) -> Self {
            self.window = window;
            self
        }

        /// Adds TCP options.
        #[must_use]
        pub fn options(mut self, options: &[u8]) -> Self {
            self.options = options.to_vec();
            self
        }

        /// Builds the TCP SYN packet.
        ///
        /// Returns a complete IP packet with TCP header and payload.
        #[must_use]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Byte extraction from integers requires truncation"
        )]
        pub fn build(self) -> Vec<u8> {
            // Calculate TCP header length (including options)
            let tcp_header_len = 20 + self.options.len();
            let tcp_header_len_words = (tcp_header_len / 4) as u8;

            // IP header (20 bytes) + TCP header + options
            let ip_header_len = 20;
            let total_len = ip_header_len + tcp_header_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build IP header
            // Version (4) and IHL (5 for 20-byte header) = 0x45
            packet.push(0x45);
            // DSCP and ECN = 0
            packet.push(0);
            // Total length (16 bits)
            packet.push((total_len >> 8) as u8);
            packet.push((total_len & 0xFF) as u8);
            // Identification (16 bits)
            packet.push((self.identification >> 8) as u8);
            packet.push((self.identification & 0xFF) as u8);
            // Flags and fragment offset (16 bits) - don't fragment
            packet.push(0x40);
            packet.push(0);
            // TTL (8 bits)
            packet.push(64);
            // Protocol (8 bits) - TCP = 6
            packet.push(6);
            // Header checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Source IP (32 bits)
            packet.extend_from_slice(&self.src_ip.octets());
            // Destination IP (32 bits)
            packet.extend_from_slice(&self.dst_ip.octets());

            // Build TCP header
            let tcp_header_start = packet.len();
            // Source port (16 bits)
            packet.push((self.src_port >> 8) as u8);
            packet.push((self.src_port & 0xFF) as u8);
            // Destination port (16 bits)
            packet.push((self.dst_port >> 8) as u8);
            packet.push((self.dst_port & 0xFF) as u8);
            // Sequence number (32 bits)
            packet.push((self.seq >> 24) as u8);
            packet.push((self.seq >> 16) as u8);
            packet.push((self.seq >> 8) as u8);
            packet.push((self.seq & 0xFF) as u8);
            // Acknowledgment number (32 bits)
            packet.push((self.ack >> 24) as u8);
            packet.push((self.ack >> 16) as u8);
            packet.push((self.ack >> 8) as u8);
            packet.push((self.ack & 0xFF) as u8);
            // Data offset (4 bits) and reserved (4 bits)
            packet.push(tcp_header_len_words << 4);
            // Flags (8 bits)
            packet.push(self.flags);
            // Window size (16 bits)
            packet.push((self.window >> 8) as u8);
            packet.push((self.window & 0xFF) as u8);
            // Checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Urgent pointer (16 bits)
            packet.push(0);
            packet.push(0);
            // Options
            packet.extend_from_slice(&self.options);

            // Calculate TCP checksum
            let tcp_checksum =
                Self::calculate_tcp_checksum(self.src_ip, self.dst_ip, &packet[tcp_header_start..]);
            packet[tcp_header_start + 16] = (tcp_checksum >> 8) as u8;
            packet[tcp_header_start + 17] = (tcp_checksum & 0xFF) as u8;

            // Calculate IP checksum
            let ip_checksum = Self::calculate_ip_checksum(&packet[..ip_header_len]);
            packet[10] = (ip_checksum >> 8) as u8;
            packet[11] = (ip_checksum & 0xFF) as u8;

            packet
        }

        /// Calculates the IP header checksum.
        fn calculate_ip_checksum(header: &[u8]) -> u16 {
            let mut sum = 0u32;
            let len = header.len();

            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
                } else {
                    sum += u32::from(header[i]) << 8;
                }
            }

            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                !(sum as u16)
            }
        }

        /// Calculates the TCP checksum with pseudo-header.
        fn calculate_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
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

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                !(sum as u16)
            }
        }
    }

    /// TCP options parsed from a TCP header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TcpOptions {
        /// Maximum Segment Size option value.
        pub mss: Option<u16>,
        /// Window scale option value.
        pub wscale: Option<u8>,
        /// Selective ACK permitted.
        pub sack: bool,
        /// Timestamp option present.
        pub timestamp: bool,
        /// Timestamp echo reply value (if present).
        pub timestamp_echo: Option<u32>,
        /// Timestamp value (if present).
        pub timestamp_value: Option<u32>,
        /// Number of NOP options.
        pub nop_count: u8,
        /// End of Options List present.
        pub eol: bool,
    }

    impl TcpOptions {
        /// Create empty TCP options.
        #[must_use]
        pub const fn new() -> Self {
            Self {
                mss: None,
                wscale: None,
                sack: false,
                timestamp: false,
                timestamp_echo: None,
                timestamp_value: None,
                nop_count: 0,
                eol: false,
            }
        }
    }

    impl Default for TcpOptions {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Parses TCP options from a TCP header.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    /// * `tcp_start` - The starting offset of the TCP header in the packet
    ///
    /// # Returns
    ///
    /// `Some(TcpOptions)` if options were successfully parsed, `None` otherwise.
    #[must_use]
    pub fn parse_tcp_options(packet: &[u8], tcp_start: usize) -> Option<TcpOptions> {
        if packet.len() < tcp_start + 20 {
            return None;
        }

        let data_offset = (packet[tcp_start + 12] >> 4) as usize;
        let header_len = data_offset * 4;

        if header_len <= 20 {
            // No options present
            return Some(TcpOptions::new());
        }

        let options_start = tcp_start + 20;
        let options_len = header_len - 20;

        if packet.len() < options_start + options_len {
            return None;
        }

        let mut options = TcpOptions::new();
        let mut i = 0;

        while i < options_len {
            let opt_type = packet[options_start + i];

            match opt_type {
                0 => {
                    // End of Option List (EOL)
                    options.eol = true;
                    break;
                }
                1 => {
                    // NOP (No Operation)
                    options.nop_count += 1;
                    i += 1;
                }
                2 => {
                    // MSS (Maximum Segment Size) - length 4
                    if i + 3 < options_len {
                        options.mss = Some(u16::from_be_bytes([
                            packet[options_start + i + 2],
                            packet[options_start + i + 3],
                        ]));
                    }
                    i += 4;
                }
                3 => {
                    // Window Scale - length 3
                    if i + 2 < options_len {
                        options.wscale = Some(packet[options_start + i + 2]);
                    }
                    i += 3;
                }
                4 => {
                    // SACK Permitted - length 2
                    options.sack = true;
                    i += 2;
                }
                8 => {
                    // Timestamp - length 10
                    if i + 9 < options_len {
                        options.timestamp = true;
                        options.timestamp_value = Some(u32::from_be_bytes([
                            packet[options_start + i + 2],
                            packet[options_start + i + 3],
                            packet[options_start + i + 4],
                            packet[options_start + i + 5],
                        ]));
                        options.timestamp_echo = Some(u32::from_be_bytes([
                            packet[options_start + i + 6],
                            packet[options_start + i + 7],
                            packet[options_start + i + 8],
                            packet[options_start + i + 9],
                        ]));
                    }
                    i += 10;
                }
                _ => {
                    // Unknown option - try to skip based on length byte
                    if i + 1 < options_len {
                        let len = packet[options_start + i + 1] as usize;
                        if len > 0 && len <= options_len - i {
                            i += len;
                        } else {
                            i += 1;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
        }

        Some(options)
    }

    /// Parsed TCP response with all header fields and options.
    #[derive(Debug, Clone, Copy)]
    pub struct TcpResponse {
        /// TCP flags.
        pub flags: u8,
        /// Sequence number.
        pub seq: u32,
        /// Acknowledgment number.
        pub ack: u32,
        /// Source port.
        pub src_port: Port,
        /// Destination port.
        pub dst_port: Port,
        /// Window size.
        pub window: u16,
        /// IP ID field.
        pub ip_id: u16,
        /// Don't Fragment bit.
        pub df: bool,
        /// Time To Live.
        pub ttl: u8,
        /// TCP options.
        pub options: TcpOptions,
    }

    /// Parses a TCP response packet.
    ///
    /// Returns the TCP flags, sequence number, acknowledgment number, source port,
    /// destination port, and source IP address if the packet is a valid TCP response.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((flags, seq, ack, src_port, dst_port, src_ip))` if valid TCP packet, `None` otherwise.
    #[must_use]
    pub fn parse_tcp_response(packet: &[u8]) -> Option<(u8, u32, u32, Port, Port, Ipv4Addr)> {
        // Minimum IP header + TCP header
        if packet.len() < 40 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be TCP = 6)
        if packet[9] != 6 {
            return None;
        }

        // Parse source IP address (bytes 12-15 of IP header)
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

        // Parse TCP header
        let tcp_start = ip_header_len;
        if packet.len() < tcp_start + 20 {
            return None;
        }

        // Source port
        let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
        // Destination port
        let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);
        // Sequence number
        let seq = u32::from_be_bytes([
            packet[tcp_start + 4],
            packet[tcp_start + 5],
            packet[tcp_start + 6],
            packet[tcp_start + 7],
        ]);
        // Acknowledgment number
        let ack = u32::from_be_bytes([
            packet[tcp_start + 8],
            packet[tcp_start + 9],
            packet[tcp_start + 10],
            packet[tcp_start + 11],
        ]);
        // Flags
        let flags = packet[tcp_start + 13];

        Some((flags, seq, ack, src_port, dst_port, src_ip))
    }

    /// Parses a TCP response packet and extracts the window field.
    ///
    /// This is used by Window scan to determine port state based on
    /// the TCP window value in RST responses.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((flags, seq, ack, src_port, dst_port, src_ip, window))` if valid TCP packet, `None` otherwise.
    #[must_use]
    pub fn parse_tcp_response_with_window(
        packet: &[u8],
    ) -> Option<(u8, u32, u32, Port, Port, Ipv4Addr, u16)> {
        // Minimum IP header + TCP header
        if packet.len() < 40 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be TCP = 6)
        if packet[9] != 6 {
            return None;
        }

        // Parse source IP address (bytes 12-15 of IP header)
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

        // Parse TCP header
        let tcp_start = ip_header_len;
        if packet.len() < tcp_start + 20 {
            return None;
        }

        // Source port
        let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
        // Destination port
        let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);
        // Sequence number
        let seq = u32::from_be_bytes([
            packet[tcp_start + 4],
            packet[tcp_start + 5],
            packet[tcp_start + 6],
            packet[tcp_start + 7],
        ]);
        // Acknowledgment number
        let ack = u32::from_be_bytes([
            packet[tcp_start + 8],
            packet[tcp_start + 9],
            packet[tcp_start + 10],
            packet[tcp_start + 11],
        ]);
        // Flags
        let flags = packet[tcp_start + 13];
        // Window (bytes 14-15 of TCP header)
        let window = u16::from_be_bytes([packet[tcp_start + 14], packet[tcp_start + 15]]);

        Some((flags, seq, ack, src_port, dst_port, src_ip, window))
    }

    /// Parses a full TCP response packet with all fields and options.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some(TcpResponse)` if valid TCP packet, `None` otherwise.
    #[must_use]
    pub fn parse_tcp_response_full(packet: &[u8]) -> Option<TcpResponse> {
        // Minimum IP header + TCP header
        if packet.len() < 40 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be TCP = 6)
        if packet[9] != 6 {
            return None;
        }

        // Parse IP fields
        let ip_id = u16::from_be_bytes([packet[4], packet[5]]);
        let df = (packet[6] & 0x40) != 0;
        let ttl = packet[8];

        // Parse TCP header
        let tcp_start = ip_header_len;
        if packet.len() < tcp_start + 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);
        let seq = u32::from_be_bytes([
            packet[tcp_start + 4],
            packet[tcp_start + 5],
            packet[tcp_start + 6],
            packet[tcp_start + 7],
        ]);
        let ack = u32::from_be_bytes([
            packet[tcp_start + 8],
            packet[tcp_start + 9],
            packet[tcp_start + 10],
            packet[tcp_start + 11],
        ]);
        let flags = packet[tcp_start + 13];
        let window = u16::from_be_bytes([packet[tcp_start + 14], packet[tcp_start + 15]]);

        // Parse TCP options
        let options = parse_tcp_options(packet, tcp_start).unwrap_or_default();

        Some(TcpResponse {
            flags,
            seq,
            ack,
            src_port,
            dst_port,
            window,
            ip_id,
            df,
            ttl,
            options,
        })
    }

    /// UDP packet builder for constructing raw UDP packets.
    #[derive(Debug)]
    pub struct UdpPacketBuilder {
        /// Source IP address.
        src_ip: Ipv4Addr,
        /// Destination IP address.
        dst_ip: Ipv4Addr,
        /// Source port.
        src_port: Port,
        /// Destination port.
        dst_port: Port,
        /// UDP payload.
        payload: Vec<u8>,
        /// IP identification field.
        identification: u16,
    }

    impl UdpPacketBuilder {
        /// Creates a new UDP packet builder with random IP identification.
        #[must_use]
        pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: Port, dst_port: Port) -> Self {
            use rand::Rng;
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                payload: Vec::new(),
                identification: rand::rng().random(),
            }
        }

        /// Sets the UDP payload.
        #[must_use]
        pub fn payload(mut self, payload: &[u8]) -> Self {
            self.payload = payload.to_vec();
            self
        }

        /// Builds the UDP packet.
        ///
        /// Returns a complete IP packet with UDP header and payload.
        #[must_use]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Byte extraction from integers requires truncation"
        )]
        pub fn build(self) -> Vec<u8> {
            // UDP header is 8 bytes
            let udp_header_len = 8;
            let udp_payload_len = self.payload.len();
            let udp_total_len = udp_header_len + udp_payload_len;

            // IP header (20 bytes) + UDP header + payload
            let ip_header_len = 20;
            let total_len = ip_header_len + udp_total_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build IP header
            // Version (4) and IHL (5 for 20-byte header) = 0x45
            packet.push(0x45);
            // DSCP and ECN = 0
            packet.push(0);
            // Total length (16 bits)
            packet.push((total_len >> 8) as u8);
            packet.push((total_len & 0xFF) as u8);
            // Identification (16 bits)
            packet.push((self.identification >> 8) as u8);
            packet.push((self.identification & 0xFF) as u8);
            // Flags and fragment offset (16 bits) - don't fragment
            packet.push(0x40);
            packet.push(0);
            // TTL (8 bits)
            packet.push(64);
            // Protocol (8 bits) - UDP = 17
            packet.push(17);
            // Header checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Source IP (32 bits)
            packet.extend_from_slice(&self.src_ip.octets());
            // Destination IP (32 bits)
            packet.extend_from_slice(&self.dst_ip.octets());

            // Build UDP header
            let udp_header_start = packet.len();
            // Source port (16 bits)
            packet.push((self.src_port >> 8) as u8);
            packet.push((self.src_port & 0xFF) as u8);
            // Destination port (16 bits)
            packet.push((self.dst_port >> 8) as u8);
            packet.push((self.dst_port & 0xFF) as u8);
            // Length (16 bits) - header + payload
            packet.push((udp_total_len >> 8) as u8);
            packet.push((udp_total_len & 0xFF) as u8);
            // Checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Payload
            packet.extend_from_slice(&self.payload);

            // Calculate UDP checksum
            let udp_checksum =
                Self::calculate_udp_checksum(self.src_ip, self.dst_ip, &packet[udp_header_start..]);
            packet[udp_header_start + 6] = (udp_checksum >> 8) as u8;
            packet[udp_header_start + 7] = (udp_checksum & 0xFF) as u8;

            // Calculate IP checksum
            let ip_checksum = Self::calculate_ip_checksum(&packet[..ip_header_len]);
            packet[10] = (ip_checksum >> 8) as u8;
            packet[11] = (ip_checksum & 0xFF) as u8;

            packet
        }

        /// Calculates the IP header checksum.
        fn calculate_ip_checksum(header: &[u8]) -> u16 {
            let mut sum = 0u32;
            let len = header.len();

            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
                } else {
                    sum += u32::from(header[i]) << 8;
                }
            }

            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                !(sum as u16)
            }
        }

        /// Calculates the UDP checksum with pseudo-header.
        fn calculate_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
            let mut sum = 0u32;

            // Pseudo-header: source IP
            for octet in src_ip.octets().chunks(2) {
                sum += u32::from(u16::from_be_bytes([octet[0], octet[1]]));
            }
            // Pseudo-header: destination IP
            for octet in dst_ip.octets().chunks(2) {
                sum += u32::from(u16::from_be_bytes([octet[0], octet[1]]));
            }
            // Pseudo-header: protocol (UDP = 17)
            sum += 17u32;
            // Pseudo-header: UDP segment length
            sum += u32::try_from(udp_segment.len()).unwrap_or(0);

            // UDP segment
            let len = udp_segment.len();
            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u32::from(u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]));
                } else {
                    sum += u32::from(udp_segment[i]) << 8;
                }
            }

            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                let checksum = !(sum as u16);
                // UDP checksum of 0 means no checksum, so use 0xFFFF instead
                if checksum == 0 {
                    0xFFFF
                } else {
                    checksum
                }
            }
        }
    }

    /// Parses a UDP response packet.
    ///
    /// Returns the source port and payload if the packet is a valid UDP response.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((src_port, payload))` if valid UDP packet, `None` otherwise.
    #[must_use]
    pub fn parse_udp_response(packet: &[u8]) -> Option<(Port, Vec<u8>)> {
        // Minimum IP header + UDP header
        if packet.len() < 28 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be UDP = 17)
        if packet[9] != 17 {
            return None;
        }

        // Parse UDP header
        let udp_start = ip_header_len;
        if packet.len() < udp_start + 8 {
            return None;
        }

        // Source port
        let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);

        // UDP length (header + payload)
        let udp_len = u16::from_be_bytes([packet[udp_start + 4], packet[udp_start + 5]]) as usize;
        let payload_len = udp_len.saturating_sub(8);

        // Extract payload
        let payload_start = udp_start + 8;
        let payload_end = (payload_start + payload_len).min(packet.len());
        let payload = packet[payload_start..payload_end].to_vec();

        Some((src_port, payload))
    }

    /// ICMP Destination Unreachable codes relevant to UDP scanning.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IcmpUnreachableCode {
        /// Network unreachable (Code 0).
        NetworkUnreachable,
        /// Host unreachable (Code 1).
        HostUnreachable,
        /// Protocol unreachable (Code 2).
        ProtocolUnreachable,
        /// Port unreachable (Code 3) - indicates closed UDP port.
        PortUnreachable,
        /// Fragmentation required but DF set (Code 4).
        FragmentationNeeded,
        /// Source route failed (Code 5).
        SourceRouteFailed,
        /// Destination network unknown (Code 6).
        NetworkUnknown,
        /// Destination host unknown (Code 7).
        HostUnknown,
        /// Source host isolated (Code 8).
        SourceHostIsolated,
        /// Communication with destination network administratively prohibited (Code 9).
        NetworkProhibited,
        /// Communication with destination host administratively prohibited (Code 10).
        HostProhibited,
        /// Destination network unreachable for type of service (Code 11).
        NetworkUnreachableForTos,
        /// Destination host unreachable for type of service (Code 12).
        HostUnreachableForTos,
        /// Communication administratively prohibited (Code 13) - indicates filtered.
        AdminProhibited,
        /// Host precedence violation (Code 14).
        HostPrecedenceViolation,
        /// Precedence cutoff in effect (Code 15).
        PrecedenceCutoff,
        /// Unknown code.
        Unknown(u8),
    }

    impl From<u8> for IcmpUnreachableCode {
        fn from(code: u8) -> Self {
            match code {
                0 => Self::NetworkUnreachable,
                1 => Self::HostUnreachable,
                2 => Self::ProtocolUnreachable,
                3 => Self::PortUnreachable,
                4 => Self::FragmentationNeeded,
                5 => Self::SourceRouteFailed,
                6 => Self::NetworkUnknown,
                7 => Self::HostUnknown,
                8 => Self::SourceHostIsolated,
                9 => Self::NetworkProhibited,
                10 => Self::HostProhibited,
                11 => Self::NetworkUnreachableForTos,
                12 => Self::HostUnreachableForTos,
                13 => Self::AdminProhibited,
                14 => Self::HostPrecedenceViolation,
                15 => Self::PrecedenceCutoff,
                n => Self::Unknown(n),
            }
        }
    }

    impl From<IcmpUnreachableCode> for u8 {
        fn from(code: IcmpUnreachableCode) -> Self {
            match code {
                IcmpUnreachableCode::NetworkUnreachable => 0,
                IcmpUnreachableCode::HostUnreachable => 1,
                IcmpUnreachableCode::ProtocolUnreachable => 2,
                IcmpUnreachableCode::PortUnreachable => 3,
                IcmpUnreachableCode::FragmentationNeeded => 4,
                IcmpUnreachableCode::SourceRouteFailed => 5,
                IcmpUnreachableCode::NetworkUnknown => 6,
                IcmpUnreachableCode::HostUnknown => 7,
                IcmpUnreachableCode::SourceHostIsolated => 8,
                IcmpUnreachableCode::NetworkProhibited => 9,
                IcmpUnreachableCode::HostProhibited => 10,
                IcmpUnreachableCode::NetworkUnreachableForTos => 11,
                IcmpUnreachableCode::HostUnreachableForTos => 12,
                IcmpUnreachableCode::AdminProhibited => 13,
                IcmpUnreachableCode::HostPrecedenceViolation => 14,
                IcmpUnreachableCode::PrecedenceCutoff => 15,
                IcmpUnreachableCode::Unknown(n) => n,
            }
        }
    }

    /// ICMP response information for UDP scanning and traceroute.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IcmpResponse {
        /// ICMP Destination Unreachable with code.
        DestinationUnreachable {
            /// The unreachable code.
            code: IcmpUnreachableCode,
            /// Original destination IP from the ICMP payload.
            original_dst_ip: Ipv4Addr,
            /// Original destination port from the ICMP payload.
            original_dst_port: Port,
        },
        /// ICMP Time Exceeded (TTL expired) - used by traceroute.
        TimeExceeded {
            /// ICMP code (0 = TTL expired in transit, 1 = Fragment reassembly time exceeded).
            code: u8,
            /// Original destination IP from the ICMP payload.
            original_dst_ip: Ipv4Addr,
            /// Original destination port from the ICMP payload.
            original_dst_port: Port,
        },
        /// Other ICMP type.
        Other {
            /// ICMP type.
            icmp_type: u8,
            /// ICMP code.
            icmp_code: u8,
        },
    }

    /// ICMP packet builder for constructing ICMP packets.
    #[derive(Debug)]
    pub struct IcmpPacketBuilder {
        /// Source IP address.
        src_ip: Ipv4Addr,
        /// Destination IP address.
        dst_ip: Ipv4Addr,
        /// ICMP type.
        icmp_type: u8,
        /// ICMP code.
        icmp_code: u8,
        /// ICMP identifier (echo request/reply ID).
        identifier: u16,
        /// ICMP sequence number.
        sequence: u16,
        /// ICMP payload/data.
        payload: Vec<u8>,
        /// IP header identification field.
        ip_identification: u16,
    }

    impl IcmpPacketBuilder {
        /// Creates a new ICMP packet builder for echo request with random IP identification.
        #[must_use]
        pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
            use rand::Rng;
            Self {
                src_ip,
                dst_ip,
                icmp_type: 8, // Echo Request
                icmp_code: 0,
                identifier: 0,
                sequence: 0,
                payload: Vec::new(),
                ip_identification: rand::rng().random(),
            }
        }

        /// Creates a new ICMP packet builder for timestamp request with random IP identification.
        #[must_use]
        pub fn timestamp_request(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
            use rand::Rng;
            Self {
                src_ip,
                dst_ip,
                icmp_type: 13, // Timestamp Request
                icmp_code: 0,
                identifier: 0,
                sequence: 0,
                payload: vec![0; 12], // Originate, Receive, Transmit timestamps (4 bytes each)
                ip_identification: rand::rng().random(),
            }
        }

        /// Sets the ICMP identifier.
        #[must_use]
        pub const fn identifier(mut self, identifier: u16) -> Self {
            self.identifier = identifier;
            self
        }

        /// Sets the ICMP sequence number.
        #[must_use]
        pub const fn sequence(mut self, sequence: u16) -> Self {
            self.sequence = sequence;
            self
        }

        /// Sets the ICMP payload.
        #[must_use]
        pub fn payload(mut self, payload: &[u8]) -> Self {
            self.payload = payload.to_vec();
            self
        }

        /// Builds the ICMP packet.
        ///
        /// Returns a complete IP packet with ICMP header and payload.
        #[must_use]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Byte extraction from integers requires truncation"
        )]
        pub fn build(self) -> Vec<u8> {
            // ICMP header is 8 bytes + payload
            let icmp_header_len = 8;
            let icmp_payload_len = self.payload.len();
            let icmp_total_len = icmp_header_len + icmp_payload_len;

            // IP header (20 bytes) + ICMP header + payload
            let ip_header_len = 20;
            let total_len = ip_header_len + icmp_total_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build IP header
            // Version (4) and IHL (5 for 20-byte header) = 0x45
            packet.push(0x45);
            // DSCP and ECN = 0
            packet.push(0);
            // Total length (16 bits)
            packet.push((total_len >> 8) as u8);
            packet.push((total_len & 0xFF) as u8);
            // IP Identification (16 bits)
            packet.push((self.ip_identification >> 8) as u8);
            packet.push((self.ip_identification & 0xFF) as u8);
            // Flags and fragment offset (16 bits) - don't fragment
            packet.push(0x40);
            packet.push(0);
            // TTL (8 bits)
            packet.push(64);
            // Protocol (8 bits) - ICMP = 1
            packet.push(1);
            // Header checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Source IP (32 bits)
            packet.extend_from_slice(&self.src_ip.octets());
            // Destination IP (32 bits)
            packet.extend_from_slice(&self.dst_ip.octets());

            // Build ICMP header
            let icmp_header_start = packet.len();
            // ICMP Type (8 bits)
            packet.push(self.icmp_type);
            // ICMP Code (8 bits)
            packet.push(self.icmp_code);
            // Checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Identifier (16 bits)
            packet.push((self.identifier >> 8) as u8);
            packet.push((self.identifier & 0xFF) as u8);
            // Sequence Number (16 bits)
            packet.push((self.sequence >> 8) as u8);
            packet.push((self.sequence & 0xFF) as u8);
            // Payload
            packet.extend_from_slice(&self.payload);

            // Calculate ICMP checksum
            let icmp_checksum = Self::calculate_checksum(&packet[icmp_header_start..]);
            packet[icmp_header_start + 2] = (icmp_checksum >> 8) as u8;
            packet[icmp_header_start + 3] = (icmp_checksum & 0xFF) as u8;

            // Calculate IP checksum
            let ip_checksum = Self::calculate_ip_checksum(&packet[..ip_header_len]);
            packet[10] = (ip_checksum >> 8) as u8;
            packet[11] = (ip_checksum & 0xFF) as u8;

            packet
        }

        /// Calculates the IP header checksum.
        fn calculate_ip_checksum(header: &[u8]) -> u16 {
            let mut sum = 0u32;
            let len = header.len();

            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
                } else {
                    sum += u32::from(header[i]) << 8;
                }
            }

            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                !(sum as u16)
            }
        }

        /// Calculates the ICMP checksum.
        fn calculate_checksum(data: &[u8]) -> u16 {
            let mut sum = 0u32;
            let len = data.len();

            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
                } else {
                    sum += u32::from(data[i]) << 8;
                }
            }

            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                !(sum as u16)
            }
        }
    }

    /// Parses an ICMP echo reply packet.
    ///
    /// Returns the identifier and sequence number if the packet is a valid
    /// ICMP echo reply.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((identifier, sequence))` if valid ICMP echo reply, `None` otherwise.
    #[must_use]
    pub fn parse_icmp_echo_reply(packet: &[u8]) -> Option<(u16, u16)> {
        // Minimum IP header + ICMP header
        if packet.len() < 28 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be ICMP = 1)
        if packet[9] != 1 {
            return None;
        }

        // Parse ICMP header
        let icmp_start = ip_header_len;
        if packet.len() < icmp_start + 8 {
            return None;
        }

        let icmp_type = packet[icmp_start];
        let icmp_code = packet[icmp_start + 1];

        // Echo Reply is Type 0, Code 0
        if icmp_type != 0 || icmp_code != 0 {
            return None;
        }

        // Extract identifier and sequence
        let identifier = u16::from_be_bytes([packet[icmp_start + 4], packet[icmp_start + 5]]);
        let sequence = u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]]);

        Some((identifier, sequence))
    }

    /// Parses an ICMP timestamp reply packet.
    ///
    /// Returns the identifier, sequence number, and timestamps if the packet
    /// is a valid ICMP timestamp reply.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((identifier, sequence, originate, receive, transmit))` if valid,
    /// `None` otherwise.
    #[must_use]
    pub fn parse_icmp_timestamp_reply(packet: &[u8]) -> Option<(u16, u16, u32, u32, u32)> {
        // Minimum IP header + ICMP header + timestamp data
        if packet.len() < 40 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be ICMP = 1)
        if packet[9] != 1 {
            return None;
        }

        // Parse ICMP header
        let icmp_start = ip_header_len;
        if packet.len() < icmp_start + 20 {
            return None;
        }

        let icmp_type = packet[icmp_start];
        let icmp_code = packet[icmp_start + 1];

        // Timestamp Reply is Type 14, Code 0
        if icmp_type != 14 || icmp_code != 0 {
            return None;
        }

        // Extract identifier and sequence
        let identifier = u16::from_be_bytes([packet[icmp_start + 4], packet[icmp_start + 5]]);
        let sequence = u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]]);

        // Extract timestamps (milliseconds since midnight UTC)
        let originate = u32::from_be_bytes([
            packet[icmp_start + 8],
            packet[icmp_start + 9],
            packet[icmp_start + 10],
            packet[icmp_start + 11],
        ]);
        let receive = u32::from_be_bytes([
            packet[icmp_start + 12],
            packet[icmp_start + 13],
            packet[icmp_start + 14],
            packet[icmp_start + 15],
        ]);
        let transmit = u32::from_be_bytes([
            packet[icmp_start + 16],
            packet[icmp_start + 17],
            packet[icmp_start + 18],
            packet[icmp_start + 19],
        ]);

        Some((identifier, sequence, originate, receive, transmit))
    }

    /// Parses an ICMP response packet.
    ///
    /// Returns ICMP response information if the packet is a valid ICMP packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some(IcmpResponse)` if valid ICMP packet, `None` otherwise.
    #[must_use]
    pub fn parse_icmp_response(packet: &[u8]) -> Option<IcmpResponse> {
        // Minimum IP header + ICMP header
        if packet.len() < 28 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be ICMP = 1)
        if packet[9] != 1 {
            return None;
        }

        // Parse ICMP header
        let icmp_start = ip_header_len;
        if packet.len() < icmp_start + 8 {
            return None;
        }

        let icmp_type = packet[icmp_start];
        let icmp_code = packet[icmp_start + 1];

        // ICMP Destination Unreachable is Type 3
        if icmp_type == 3 {
            // ICMP payload contains the original IP header + first 8 bytes of transport header
            let payload_start = icmp_start + 8;
            if packet.len() < payload_start + 28 {
                // Not enough data to extract original headers
                return Some(IcmpResponse::DestinationUnreachable {
                    code: icmp_code.into(),
                    original_dst_ip: Ipv4Addr::UNSPECIFIED,
                    original_dst_port: 0,
                });
            }

            // Parse original IP header from ICMP payload
            let orig_ip_start = payload_start;
            let orig_ip_header_len = (packet[orig_ip_start] & 0x0F) as usize * 4;

            // Extract original destination IP (bytes 16-19 of original IP header)
            let orig_dst_ip = Ipv4Addr::new(
                packet[orig_ip_start + 16],
                packet[orig_ip_start + 17],
                packet[orig_ip_start + 18],
                packet[orig_ip_start + 19],
            );

            // Extract original destination port from UDP/TCP header
            // UDP/TCP header: src_port (2 bytes) + dst_port (2 bytes) + ...
            // We need dst_port, so offset by 2 from transport_start
            let orig_transport_start = orig_ip_start + orig_ip_header_len;
            let orig_dst_port = if packet.len() >= orig_transport_start + 4 {
                u16::from_be_bytes([
                    packet[orig_transport_start + 2],
                    packet[orig_transport_start + 3],
                ])
            } else {
                0
            };

            return Some(IcmpResponse::DestinationUnreachable {
                code: icmp_code.into(),
                original_dst_ip: orig_dst_ip,
                original_dst_port: orig_dst_port,
            });
        }

        // ICMP Time Exceeded is Type 11
        if icmp_type == 11 {
            // ICMP payload contains the original IP header + first 8 bytes of transport header
            let payload_start = icmp_start + 8;
            if packet.len() < payload_start + 28 {
                // Not enough data to extract original headers
                return Some(IcmpResponse::Other {
                    icmp_type,
                    icmp_code,
                });
            }

            // Parse original IP header from ICMP payload
            let orig_ip_start = payload_start;
            let orig_ip_header_len = (packet[orig_ip_start] & 0x0F) as usize * 4;

            // Extract original destination IP (bytes 16-19 of original IP header)
            let orig_dst_ip = Ipv4Addr::new(
                packet[orig_ip_start + 16],
                packet[orig_ip_start + 17],
                packet[orig_ip_start + 18],
                packet[orig_ip_start + 19],
            );

            // Extract original destination port from UDP/TCP header
            // UDP/TCP header: src_port (2 bytes) + dst_port (2 bytes) + ...
            // We need dst_port, so offset by 2 from transport_start
            let orig_transport_start = orig_ip_start + orig_ip_header_len;
            let orig_dst_port = if packet.len() >= orig_transport_start + 4 {
                u16::from_be_bytes([
                    packet[orig_transport_start + 2],
                    packet[orig_transport_start + 3],
                ])
            } else {
                0
            };

            return Some(IcmpResponse::TimeExceeded {
                code: icmp_code,
                original_dst_ip: orig_dst_ip,
                original_dst_port: orig_dst_port,
            });
        }

        Some(IcmpResponse::Other {
            icmp_type,
            icmp_code,
        })
    }

    /// Parses an ICMP Time Exceeded response and returns the source IP of the responder.
    ///
    /// This is useful for traceroute to identify the router that dropped the packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some(source_ip)` if valid ICMP Time Exceeded packet, `None` otherwise.
    #[must_use]
    pub fn parse_icmp_time_exceeded(packet: &[u8]) -> Option<Ipv4Addr> {
        // Minimum IP header + ICMP header
        if packet.len() < 28 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;

        // Check protocol (must be ICMP = 1)
        if packet[9] != 1 {
            return None;
        }

        // Parse ICMP header
        let icmp_start = ip_header_len;
        if packet.len() < icmp_start + 8 {
            return None;
        }

        let icmp_type = packet[icmp_start];
        let icmp_code = packet[icmp_start + 1];

        // ICMP Time Exceeded is Type 11
        if icmp_type != 11 {
            return None;
        }

        // Extract source IP from the IP header (bytes 12-15)
        let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

        // Verify this is a valid Time Exceeded code (0 = TTL expired, 1 = Fragment reassembly)
        if icmp_code > 1 {
            return None;
        }

        Some(source_ip)
    }

    /// ARP packet builder for constructing ARP request packets.
    #[derive(Debug)]
    pub struct ArpPacketBuilder {
        /// Source MAC address.
        src_mac: rustnmap_common::MacAddr,
        /// Source IP address.
        src_ip: Ipv4Addr,
        /// Target IP address (the one we want to resolve).
        target_ip: Ipv4Addr,
    }

    impl ArpPacketBuilder {
        /// Creates a new ARP packet builder.
        #[must_use]
        pub const fn new(
            src_mac: rustnmap_common::MacAddr,
            src_ip: Ipv4Addr,
            target_ip: Ipv4Addr,
        ) -> Self {
            Self {
                src_mac,
                src_ip,
                target_ip,
            }
        }

        /// Builds the ARP request packet.
        ///
        /// Returns a complete Ethernet frame with ARP request.
        /// The destination MAC is set to broadcast (ff:ff:ff:ff:ff:ff).
        #[must_use]
        pub fn build(self) -> Vec<u8> {
            // Ethernet header (14 bytes) + ARP payload (28 bytes)
            let eth_header_len = 14;
            let arp_len = 28;
            let total_len = eth_header_len + arp_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build Ethernet header
            // Destination MAC (broadcast)
            packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            // Source MAC
            packet.extend_from_slice(&self.src_mac.bytes());
            // EtherType (ARP = 0x0806)
            packet.push(0x08);
            packet.push(0x06);

            // Build ARP header
            // Hardware type (Ethernet = 1)
            packet.push(0x00);
            packet.push(0x01);
            // Protocol type (IPv4 = 0x0800)
            packet.push(0x08);
            packet.push(0x00);
            // Hardware address length (6 for MAC)
            packet.push(6);
            // Protocol address length (4 for IPv4)
            packet.push(4);
            // Operation (1 = Request)
            packet.push(0x00);
            packet.push(0x01);
            // Sender hardware address (source MAC)
            packet.extend_from_slice(&self.src_mac.bytes());
            // Sender protocol address (source IP)
            packet.extend_from_slice(&self.src_ip.octets());
            // Target hardware address (unknown, set to 00:00:00:00:00:00)
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            // Target protocol address (target IP)
            packet.extend_from_slice(&self.target_ip.octets());

            packet
        }
    }

    /// Parses an ARP reply packet.
    ///
    /// Returns the sender MAC and IP addresses if the packet is a valid
    /// ARP reply.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes (Ethernet frame)
    ///
    /// # Returns
    ///
    /// `Some((sender_mac, sender_ip))` if valid ARP reply, `None` otherwise.
    #[must_use]
    pub fn parse_arp_reply(packet: &[u8]) -> Option<(rustnmap_common::MacAddr, Ipv4Addr)> {
        // Minimum Ethernet header + ARP header
        if packet.len() < 42 {
            return None;
        }

        // Check EtherType (must be ARP = 0x0806)
        let ether_type = u16::from_be_bytes([packet[12], packet[13]]);
        if ether_type != 0x0806 {
            return None;
        }

        let arp_start = 14;

        // Check hardware type (must be Ethernet = 1)
        let hw_type = u16::from_be_bytes([packet[arp_start], packet[arp_start + 1]]);
        if hw_type != 1 {
            return None;
        }

        // Check protocol type (must be IPv4 = 0x0800)
        let proto_type = u16::from_be_bytes([packet[arp_start + 2], packet[arp_start + 3]]);
        if proto_type != 0x0800 {
            return None;
        }

        // Check hardware address length (must be 6)
        if packet[arp_start + 4] != 6 {
            return None;
        }

        // Check protocol address length (must be 4)
        if packet[arp_start + 5] != 4 {
            return None;
        }

        // Check operation (must be Reply = 2)
        let operation = u16::from_be_bytes([packet[arp_start + 6], packet[arp_start + 7]]);
        if operation != 2 {
            return None;
        }

        // Extract sender MAC (bytes 8-13)
        let sender_mac = rustnmap_common::MacAddr::new([
            packet[arp_start + 8],
            packet[arp_start + 9],
            packet[arp_start + 10],
            packet[arp_start + 11],
            packet[arp_start + 12],
            packet[arp_start + 13],
        ]);

        // Extract sender IP (bytes 14-17)
        let sender_ip = Ipv4Addr::new(
            packet[arp_start + 14],
            packet[arp_start + 15],
            packet[arp_start + 16],
            packet[arp_start + 17],
        );

        Some((sender_mac, sender_ip))
    }

    /// IPv6 UDP packet builder for constructing raw UDP packets over IPv6.
    #[derive(Debug)]
    pub struct Ipv6UdpPacketBuilder {
        /// Source IP address.
        src_ip: std::net::Ipv6Addr,
        /// Destination IP address.
        dst_ip: std::net::Ipv6Addr,
        /// Source port.
        src_port: Port,
        /// Destination port.
        dst_port: Port,
        /// UDP payload.
        payload: Vec<u8>,
        /// Flow label (20 bits).
        flow_label: u32,
        /// Hop limit (TTL equivalent).
        hop_limit: u8,
    }

    impl Ipv6UdpPacketBuilder {
        /// Creates a new IPv6 UDP packet builder.
        #[must_use]
        pub const fn new(
            src_ip: std::net::Ipv6Addr,
            dst_ip: std::net::Ipv6Addr,
            src_port: Port,
            dst_port: Port,
        ) -> Self {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                payload: Vec::new(),
                flow_label: 0,
                hop_limit: 64,
            }
        }

        /// Sets the UDP payload.
        #[must_use]
        pub fn payload(mut self, payload: &[u8]) -> Self {
            self.payload = payload.to_vec();
            self
        }

        /// Sets the flow label (20 bits, will be masked).
        #[must_use]
        pub const fn flow_label(mut self, flow_label: u32) -> Self {
            self.flow_label = flow_label & 0x000F_FFFF;
            self
        }

        /// Sets the hop limit.
        #[must_use]
        pub const fn hop_limit(mut self, hop_limit: u8) -> Self {
            self.hop_limit = hop_limit;
            self
        }

        /// Builds the IPv6 UDP packet.
        ///
        /// Returns a complete IPv6 packet with UDP header and payload.
        #[must_use]
        pub fn build(self) -> Vec<u8> {
            // UDP header is 8 bytes + payload
            let udp_header_len = 8;
            let udp_payload_len = self.payload.len();
            let udp_total_len = udp_header_len + udp_payload_len;

            // IPv6 header is 40 bytes
            let ipv6_header_len = 40;
            let total_len = ipv6_header_len + udp_total_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build IPv6 header
            // Version (4 bits = 6) + Traffic class first 4 bits + Flow label first 4 bits
            let version_tc_fl = (6u32 << 28) | (self.flow_label & 0x000F_FFFF);
            packet.extend_from_slice(&version_tc_fl.to_be_bytes());

            // Payload length (16 bits) - just the UDP packet
            packet.extend_from_slice(&u16::try_from(udp_total_len).unwrap_or(0).to_be_bytes());

            // Next header (8 bits) - UDP = 17
            packet.push(17);

            // Hop limit (8 bits)
            packet.push(self.hop_limit);

            // Source IP (128 bits)
            packet.extend_from_slice(&self.src_ip.octets());

            // Destination IP (128 bits)
            packet.extend_from_slice(&self.dst_ip.octets());

            // Build UDP header
            let udp_header_start = packet.len();
            // Source port (16 bits)
            packet.extend_from_slice(&self.src_port.to_be_bytes());
            // Destination port (16 bits)
            packet.extend_from_slice(&self.dst_port.to_be_bytes());
            // Length (16 bits) - header + payload
            packet.extend_from_slice(&u16::try_from(udp_total_len).unwrap_or(0).to_be_bytes());
            // Checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Payload
            packet.extend_from_slice(&self.payload);

            // Calculate UDP checksum with IPv6 pseudo-header
            let udp_checksum = Self::calculate_udp_checksum_ipv6(
                self.src_ip,
                self.dst_ip,
                &packet[udp_header_start..],
            );
            packet[udp_header_start + 6] = (udp_checksum >> 8) as u8;
            packet[udp_header_start + 7] = (udp_checksum & 0xFF) as u8;

            packet
        }

        /// Calculates the UDP checksum with IPv6 pseudo-header.
        fn calculate_udp_checksum_ipv6(
            src_ip: std::net::Ipv6Addr,
            dst_ip: std::net::Ipv6Addr,
            udp_segment: &[u8],
        ) -> u16 {
            let mut sum = 0u128;

            // IPv6 pseudo-header: source IP (128 bits)
            for chunk in src_ip.octets().chunks(2) {
                sum += u128::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }

            // IPv6 pseudo-header: destination IP (128 bits)
            for chunk in dst_ip.octets().chunks(2) {
                sum += u128::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }

            // IPv6 pseudo-header: UDP length (32 bits, upper 16 bits should be 0)
            let udp_len = u32::try_from(udp_segment.len()).unwrap_or(0);
            sum += u128::from(udp_len);

            // IPv6 pseudo-header: zero (24 bits) + next header (8 bits)
            sum += 17u128; // UDP protocol number

            // UDP segment
            let len = udp_segment.len();
            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u128::from(u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]));
                } else {
                    sum += u128::from(udp_segment[i]) << 8;
                }
            }

            // Fold the sum
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                let checksum = !(sum as u16);
                // UDP checksum of 0 means no checksum, so use 0xFFFF instead
                if checksum == 0 {
                    0xFFFF
                } else {
                    checksum
                }
            }
        }
    }

    /// Parses an IPv6 UDP response packet.
    ///
    /// Returns the source port and payload if the packet is a valid IPv6 UDP response.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((src_port, payload))` if valid IPv6 UDP packet, `None` otherwise.
    #[must_use]
    pub fn parse_ipv6_udp_response(packet: &[u8]) -> Option<(Port, Vec<u8>)> {
        // Minimum IPv6 header + UDP header
        if packet.len() < 48 {
            return None;
        }

        // Check IP version (must be 6)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 6 {
            return None;
        }

        // Check next header (must be UDP = 17)
        if packet[6] != 17 {
            return None;
        }

        // IPv6 header is fixed at 40 bytes
        let udp_start = 40;

        if packet.len() < udp_start + 8 {
            return None;
        }

        // Source port
        let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);

        // UDP length (header + payload)
        let udp_len = u16::from_be_bytes([packet[udp_start + 4], packet[udp_start + 5]]) as usize;
        let payload_len = udp_len.saturating_sub(8);

        // Extract payload
        let payload_start = udp_start + 8;
        let payload_end = (payload_start + payload_len).min(packet.len());
        let payload = packet[payload_start..payload_end].to_vec();

        Some((src_port, payload))
    }

    /// `ICMPv6` packet types for IPv6 OS detection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Icmpv6Type {
        /// Echo Request (Type 128)
        EchoRequest,
        /// Echo Reply (Type 129)
        EchoReply,
        /// Neighbor Solicitation (Type 135)
        NeighborSolicitation,
        /// Neighbor Advertisement (Type 136)
        NeighborAdvertisement,
        /// Unknown type
        Unknown(u8),
    }

    impl From<u8> for Icmpv6Type {
        fn from(t: u8) -> Self {
            match t {
                128 => Self::EchoRequest,
                129 => Self::EchoReply,
                135 => Self::NeighborSolicitation,
                136 => Self::NeighborAdvertisement,
                n => Self::Unknown(n),
            }
        }
    }

    impl From<Icmpv6Type> for u8 {
        fn from(t: Icmpv6Type) -> Self {
            match t {
                Icmpv6Type::EchoRequest => 128,
                Icmpv6Type::EchoReply => 129,
                Icmpv6Type::NeighborSolicitation => 135,
                Icmpv6Type::NeighborAdvertisement => 136,
                Icmpv6Type::Unknown(n) => n,
            }
        }
    }

    /// `ICMPv6` Destination Unreachable codes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Icmpv6UnreachableCode {
        /// No route to destination (Code 0)
        NoRoute,
        /// Communication administratively prohibited (Code 1)
        AdminProhibited,
        /// Beyond scope of source address (Code 2)
        BeyondScope,
        /// Address unreachable (Code 3)
        AddressUnreachable,
        /// Port unreachable (Code 4) - indicates closed UDP port
        PortUnreachable,
        /// Source address failed ingress/egress policy (Code 5)
        PolicyFailed,
        /// Reject route to destination (Code 6)
        RejectRoute,
        /// Unknown code
        Unknown(u8),
    }

    impl From<u8> for Icmpv6UnreachableCode {
        fn from(code: u8) -> Self {
            match code {
                0 => Self::NoRoute,
                1 => Self::AdminProhibited,
                2 => Self::BeyondScope,
                3 => Self::AddressUnreachable,
                4 => Self::PortUnreachable,
                5 => Self::PolicyFailed,
                6 => Self::RejectRoute,
                n => Self::Unknown(n),
            }
        }
    }

    /// `ICMPv6` packet builder for constructing `ICMPv6` packets.
    #[derive(Debug)]
    pub struct Icmpv6PacketBuilder {
        /// Source IP address.
        src_ip: std::net::Ipv6Addr,
        /// Destination IP address.
        dst_ip: std::net::Ipv6Addr,
        /// `ICMPv6` type.
        icmp_type: Icmpv6Type,
        /// `ICMPv6` code.
        icmp_code: u8,
        /// `ICMPv6` identifier (echo request/reply ID).
        identifier: u16,
        /// `ICMPv6` sequence number.
        sequence: u16,
        /// `ICMPv6` payload/data.
        payload: Vec<u8>,
        /// Flow label.
        flow_label: u32,
        /// Hop limit.
        hop_limit: u8,
    }

    impl Icmpv6PacketBuilder {
        /// Creates a new `ICMPv6` packet builder for echo request.
        #[must_use]
        pub const fn new(src_ip: std::net::Ipv6Addr, dst_ip: std::net::Ipv6Addr) -> Self {
            Self {
                src_ip,
                dst_ip,
                icmp_type: Icmpv6Type::EchoRequest,
                icmp_code: 0,
                identifier: 0,
                sequence: 0,
                payload: Vec::new(),
                flow_label: 0,
                hop_limit: 64,
            }
        }

        /// Sets the `ICMPv6` identifier.
        #[must_use]
        pub const fn identifier(mut self, identifier: u16) -> Self {
            self.identifier = identifier;
            self
        }

        /// Sets the `ICMPv6` sequence number.
        #[must_use]
        pub const fn sequence(mut self, sequence: u16) -> Self {
            self.sequence = sequence;
            self
        }

        /// Sets the `ICMPv6` payload.
        #[must_use]
        pub fn payload(mut self, payload: &[u8]) -> Self {
            self.payload = payload.to_vec();
            self
        }

        /// Sets the flow label (20 bits, will be masked).
        #[must_use]
        pub const fn flow_label(mut self, flow_label: u32) -> Self {
            self.flow_label = flow_label & 0x000F_FFFF;
            self
        }

        /// Sets the hop limit.
        #[must_use]
        pub const fn hop_limit(mut self, hop_limit: u8) -> Self {
            self.hop_limit = hop_limit;
            self
        }

        /// Builds the `ICMPv6` packet.
        ///
        /// Returns a complete IPv6 packet with `ICMPv6` header and payload.
        #[must_use]
        pub fn build(self) -> Vec<u8> {
            // ICMPv6 header is 8 bytes + payload
            let icmp_header_len = 8;
            let icmp_payload_len = self.payload.len();
            let icmp_total_len = icmp_header_len + icmp_payload_len;

            // IPv6 header is 40 bytes
            let ipv6_header_len = 40;
            let total_len = ipv6_header_len + icmp_total_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build IPv6 header
            // Version (4 bits = 6) + Traffic class first 4 bits + Flow label first 4 bits
            let version_tc_fl = (6u32 << 28) | (self.flow_label & 0x000F_FFFF);
            packet.extend_from_slice(&version_tc_fl.to_be_bytes());

            // Payload length (16 bits) - just the ICMPv6 packet
            packet.extend_from_slice(&u16::try_from(icmp_total_len).unwrap_or(0).to_be_bytes());

            // Next header (8 bits) - ICMPv6 = 58
            packet.push(58);

            // Hop limit (8 bits)
            packet.push(self.hop_limit);

            // Source IP (128 bits)
            packet.extend_from_slice(&self.src_ip.octets());

            // Destination IP (128 bits)
            packet.extend_from_slice(&self.dst_ip.octets());

            // Build ICMPv6 header
            let icmp_header_start = packet.len();
            // ICMPv6 Type (8 bits)
            packet.push(u8::from(self.icmp_type));
            // ICMPv6 Code (8 bits)
            packet.push(self.icmp_code);
            // Checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Identifier (16 bits)
            packet.extend_from_slice(&self.identifier.to_be_bytes());
            // Sequence Number (16 bits)
            packet.extend_from_slice(&self.sequence.to_be_bytes());
            // Payload
            packet.extend_from_slice(&self.payload);

            // Calculate ICMPv6 checksum with IPv6 pseudo-header
            let icmp_checksum = Self::calculate_icmpv6_checksum(
                self.src_ip,
                self.dst_ip,
                &packet[icmp_header_start..],
            );
            packet[icmp_header_start + 2] = (icmp_checksum >> 8) as u8;
            packet[icmp_header_start + 3] = (icmp_checksum & 0xFF) as u8;

            packet
        }

        /// Calculates the `ICMPv6` checksum with IPv6 pseudo-header.
        fn calculate_icmpv6_checksum(
            src_ip: std::net::Ipv6Addr,
            dst_ip: std::net::Ipv6Addr,
            icmp_packet: &[u8],
        ) -> u16 {
            let mut sum = 0u128;

            // IPv6 pseudo-header: source IP (128 bits)
            for chunk in src_ip.octets().chunks(2) {
                sum += u128::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }

            // IPv6 pseudo-header: destination IP (128 bits)
            for chunk in dst_ip.octets().chunks(2) {
                sum += u128::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }

            // IPv6 pseudo-header: ICMPv6 length (32 bits, upper 16 bits should be 0)
            let icmp_len = u32::try_from(icmp_packet.len()).unwrap_or(0);
            sum += u128::from(icmp_len);

            // IPv6 pseudo-header: zero (24 bits) + next header (8 bits)
            sum += 58u128; // ICMPv6 protocol number

            // ICMPv6 packet
            let len = icmp_packet.len();
            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u128::from(u16::from_be_bytes([icmp_packet[i], icmp_packet[i + 1]]));
                } else {
                    sum += u128::from(icmp_packet[i]) << 8;
                }
            }

            // Fold the sum
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                // ICMPv6 checksum of 0 is valid, unlike UDP
                !(sum as u16)
            }
        }
    }

    /// Parses an `ICMPv6` echo reply packet.
    ///
    /// Returns the identifier and sequence number if the packet is a valid
    /// `ICMPv6` echo reply.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((identifier, sequence))` if valid `ICMPv6` echo reply, `None` otherwise.
    #[must_use]
    pub fn parse_icmpv6_echo_reply(packet: &[u8]) -> Option<(u16, u16)> {
        // Minimum IPv6 header + ICMPv6 header
        if packet.len() < 48 {
            return None;
        }

        // Check IP version (must be 6)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 6 {
            return None;
        }

        // Check next header (must be ICMPv6 = 58)
        if packet[6] != 58 {
            return None;
        }

        // IPv6 header is fixed at 40 bytes
        let icmp_start = 40;

        if packet.len() < icmp_start + 8 {
            return None;
        }

        let icmp_type = packet[icmp_start];
        let icmp_code = packet[icmp_start + 1];

        // Echo Reply is Type 129, Code 0
        if icmp_type != 129 || icmp_code != 0 {
            return None;
        }

        // Extract identifier and sequence
        let identifier = u16::from_be_bytes([packet[icmp_start + 4], packet[icmp_start + 5]]);
        let sequence = u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]]);

        Some((identifier, sequence))
    }

    /// Parses an `ICMPv6` Destination Unreachable response.
    ///
    /// Returns the unreachable code and original destination info.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((code, original_dst_ip, original_dst_port))` if valid `ICMPv6` unreachable, `None` otherwise.
    #[must_use]
    pub fn parse_icmpv6_unreachable(
        packet: &[u8],
    ) -> Option<(Icmpv6UnreachableCode, std::net::Ipv6Addr, Port)> {
        // Minimum IPv6 header + ICMPv6 header + original IPv6 header + 8 bytes
        if packet.len() < 96 {
            return None;
        }

        // Check IP version (must be 6)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 6 {
            return None;
        }

        // Check next header (must be ICMPv6 = 58)
        if packet[6] != 58 {
            return None;
        }

        // IPv6 header is fixed at 40 bytes
        let icmp_start = 40;

        let icmp_type = packet[icmp_start];

        // Destination Unreachable is Type 1
        if icmp_type != 1 {
            return None;
        }

        let code = Icmpv6UnreachableCode::from(packet[icmp_start + 1]);

        // ICMPv6 payload contains the original IPv6 packet (as much as possible)
        // The original IPv6 header starts at icmp_start + 8
        let orig_ip_start = icmp_start + 8;

        if packet.len() < orig_ip_start + 48 {
            // Not enough data for original IPv6 header + 8 bytes of transport
            return Some((code, std::net::Ipv6Addr::UNSPECIFIED, 0));
        }

        // Extract original destination IP (bytes 24-39 from original IPv6 header start)
        let orig_dst_ip = std::net::Ipv6Addr::new(
            u16::from_be_bytes([packet[orig_ip_start + 24], packet[orig_ip_start + 25]]),
            u16::from_be_bytes([packet[orig_ip_start + 26], packet[orig_ip_start + 27]]),
            u16::from_be_bytes([packet[orig_ip_start + 28], packet[orig_ip_start + 29]]),
            u16::from_be_bytes([packet[orig_ip_start + 30], packet[orig_ip_start + 31]]),
            u16::from_be_bytes([packet[orig_ip_start + 32], packet[orig_ip_start + 33]]),
            u16::from_be_bytes([packet[orig_ip_start + 34], packet[orig_ip_start + 35]]),
            u16::from_be_bytes([packet[orig_ip_start + 36], packet[orig_ip_start + 37]]),
            u16::from_be_bytes([packet[orig_ip_start + 38], packet[orig_ip_start + 39]]),
        );

        // Original IPv6 header is 40 bytes, transport header starts at orig_ip_start + 40
        let orig_transport_start = orig_ip_start + 40;
        let orig_dst_port = if packet.len() >= orig_transport_start + 2 {
            u16::from_be_bytes([
                packet[orig_transport_start],
                packet[orig_transport_start + 1],
            ])
        } else {
            0
        };

        Some((code, orig_dst_ip, orig_dst_port))
    }

    /// IPv6 TCP packet builder for constructing raw TCP packets over IPv6.
    #[derive(Debug)]
    pub struct Ipv6TcpPacketBuilder {
        /// Source IP address.
        src_ip: std::net::Ipv6Addr,
        /// Destination IP address.
        dst_ip: std::net::Ipv6Addr,
        /// Source port.
        src_port: Port,
        /// Destination port.
        dst_port: Port,
        /// Sequence number.
        seq: u32,
        /// Acknowledgment number.
        ack: u32,
        /// TCP flags.
        flags: u8,
        /// Window size.
        window: u16,
        /// TCP options.
        options: Vec<u8>,
        /// Flow label.
        flow_label: u32,
        /// Hop limit.
        hop_limit: u8,
    }

    impl Ipv6TcpPacketBuilder {
        /// Creates a new IPv6 TCP packet builder.
        #[must_use]
        pub const fn new(
            src_ip: std::net::Ipv6Addr,
            dst_ip: std::net::Ipv6Addr,
            src_port: Port,
            dst_port: Port,
        ) -> Self {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq: 0,
                ack: 0,
                flags: 0,
                window: 65535,
                options: Vec::new(),
                flow_label: 0,
                hop_limit: 64,
            }
        }

        /// Sets the sequence number.
        #[must_use]
        pub const fn seq(mut self, seq: u32) -> Self {
            self.seq = seq;
            self
        }

        /// Sets the acknowledgment number.
        #[must_use]
        pub const fn ack(mut self, ack: u32) -> Self {
            self.ack = ack;
            self
        }

        /// Sets the SYN flag.
        #[must_use]
        pub const fn syn(mut self) -> Self {
            self.flags |= 0x02;
            self
        }

        /// Sets the ACK flag.
        #[must_use]
        pub const fn ack_flag(mut self) -> Self {
            self.flags |= 0x10;
            self
        }

        /// Sets the RST flag.
        #[must_use]
        pub const fn rst(mut self) -> Self {
            self.flags |= 0x04;
            self
        }

        /// Sets the FIN flag.
        #[must_use]
        pub const fn fin(mut self) -> Self {
            self.flags |= 0x01;
            self
        }

        /// Sets the PSH (Push) flag.
        #[must_use]
        pub const fn psh(mut self) -> Self {
            self.flags |= 0x08;
            self
        }

        /// Sets the window size.
        #[must_use]
        pub const fn window(mut self, window: u16) -> Self {
            self.window = window;
            self
        }

        /// Adds TCP options.
        #[must_use]
        pub fn options(mut self, options: &[u8]) -> Self {
            self.options = options.to_vec();
            self
        }

        /// Sets the flow label (20 bits, will be masked).
        #[must_use]
        pub const fn flow_label(mut self, flow_label: u32) -> Self {
            self.flow_label = flow_label & 0x000F_FFFF;
            self
        }

        /// Sets the hop limit.
        #[must_use]
        pub const fn hop_limit(mut self, hop_limit: u8) -> Self {
            self.hop_limit = hop_limit;
            self
        }

        /// Builds the IPv6 TCP packet.
        ///
        /// Returns a complete IPv6 packet with TCP header.
        #[must_use]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Byte extraction from integers requires truncation"
        )]
        pub fn build(self) -> Vec<u8> {
            // Calculate TCP header length (including options)
            let tcp_header_len = 20 + self.options.len();
            let tcp_header_len_words = (tcp_header_len / 4) as u8;

            // IPv6 header is 40 bytes + TCP header + options
            let ipv6_header_len = 40;
            let total_len = ipv6_header_len + tcp_header_len;

            let mut packet = Vec::with_capacity(total_len);

            // Build IPv6 header
            // Version (4 bits = 6) + Traffic class first 4 bits + Flow label first 4 bits
            let version_tc_fl = (6u32 << 28) | (self.flow_label & 0x000F_FFFF);
            packet.extend_from_slice(&version_tc_fl.to_be_bytes());

            // Payload length (16 bits) - just the TCP packet
            packet.extend_from_slice(&u16::try_from(tcp_header_len).unwrap_or(0).to_be_bytes());

            // Next header (8 bits) - TCP = 6
            packet.push(6);

            // Hop limit (8 bits)
            packet.push(self.hop_limit);

            // Source IP (128 bits)
            packet.extend_from_slice(&self.src_ip.octets());

            // Destination IP (128 bits)
            packet.extend_from_slice(&self.dst_ip.octets());

            // Build TCP header
            let tcp_header_start = packet.len();
            // Source port (16 bits)
            packet.extend_from_slice(&self.src_port.to_be_bytes());
            // Destination port (16 bits)
            packet.extend_from_slice(&self.dst_port.to_be_bytes());
            // Sequence number (32 bits)
            packet.extend_from_slice(&self.seq.to_be_bytes());
            // Acknowledgment number (32 bits)
            packet.extend_from_slice(&self.ack.to_be_bytes());
            // Data offset (4 bits) and reserved (4 bits)
            packet.push(tcp_header_len_words << 4);
            // Flags (8 bits)
            packet.push(self.flags);
            // Window size (16 bits)
            packet.extend_from_slice(&self.window.to_be_bytes());
            // Checksum (16 bits) - calculated later
            packet.push(0);
            packet.push(0);
            // Urgent pointer (16 bits)
            packet.push(0);
            packet.push(0);
            // Options
            packet.extend_from_slice(&self.options);

            // Calculate TCP checksum with IPv6 pseudo-header
            let tcp_checksum = Self::calculate_tcp_checksum_ipv6(
                self.src_ip,
                self.dst_ip,
                &packet[tcp_header_start..],
            );
            packet[tcp_header_start + 16] = (tcp_checksum >> 8) as u8;
            packet[tcp_header_start + 17] = (tcp_checksum & 0xFF) as u8;

            packet
        }

        /// Calculates the TCP checksum with IPv6 pseudo-header.
        fn calculate_tcp_checksum_ipv6(
            src_ip: std::net::Ipv6Addr,
            dst_ip: std::net::Ipv6Addr,
            tcp_segment: &[u8],
        ) -> u16 {
            let mut sum = 0u128;

            // IPv6 pseudo-header: source IP (128 bits)
            for chunk in src_ip.octets().chunks(2) {
                sum += u128::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }

            // IPv6 pseudo-header: destination IP (128 bits)
            for chunk in dst_ip.octets().chunks(2) {
                sum += u128::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }

            // IPv6 pseudo-header: TCP length (32 bits, upper 16 bits should be 0)
            let tcp_len = u32::try_from(tcp_segment.len()).unwrap_or(0);
            sum += u128::from(tcp_len);

            // IPv6 pseudo-header: zero (24 bits) + next header (8 bits)
            sum += 6u128; // TCP protocol number

            // TCP segment
            let len = tcp_segment.len();
            for i in (0..len).step_by(2) {
                if i + 1 < len {
                    sum += u128::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
                } else {
                    sum += u128::from(tcp_segment[i]) << 8;
                }
            }

            // Fold the sum
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Truncation is intentional for checksum calculation
            #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
            {
                !(sum as u16)
            }
        }
    }

    /// Parses an IPv6 TCP response packet.
    ///
    /// Returns TCP flags, sequence number, acknowledgment number, and source port.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((flags, seq, ack, src_port))` if valid IPv6 TCP packet, `None` otherwise.
    #[must_use]
    pub fn parse_ipv6_tcp_response(packet: &[u8]) -> Option<(u8, u32, u32, Port)> {
        // Minimum IPv6 header + TCP header
        if packet.len() < 60 {
            return None;
        }

        // Check IP version (must be 6)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 6 {
            return None;
        }

        // Check next header (must be TCP = 6)
        if packet[6] != 6 {
            return None;
        }

        // IPv6 header is fixed at 40 bytes
        let tcp_start = 40;

        if packet.len() < tcp_start + 20 {
            return None;
        }

        // Source port
        let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
        // Sequence number
        let seq = u32::from_be_bytes([
            packet[tcp_start + 4],
            packet[tcp_start + 5],
            packet[tcp_start + 6],
            packet[tcp_start + 7],
        ]);
        // Acknowledgment number
        let ack = u32::from_be_bytes([
            packet[tcp_start + 8],
            packet[tcp_start + 9],
            packet[tcp_start + 10],
            packet[tcp_start + 11],
        ]);
        // Flags
        let flags = packet[tcp_start + 13];

        Some((flags, seq, ack, src_port))
    }
}
