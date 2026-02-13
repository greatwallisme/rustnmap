//! Network primitives and socket abstractions for `RustNmap`.
//!
//! This crate provides low-level network access including raw socket creation,
//! packet I/O, and network interface management.

#![warn(missing_docs)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "Dependency version conflict in transitive deps"
)]

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
        /// Creates a new raw socket.
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The process lacks `CAP_NET_RAW` capability
        /// - The system runs out of file descriptors
        /// - The socket protocol is not supported
        pub fn new() -> super::Result<Self> {
            use rustnmap_common::error::NetworkError;
            use rustnmap_common::Error;
            use socket2::{Domain, Protocol, Type};

            // Use IP protocol 0 for raw IP packet capture
            let socket = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0)))
                .map_err(|e| Error::Network(NetworkError::RawSocketCreation { source: e }))?;

            // Set socket options for better performance
            socket
                .set_nonblocking(true)
                .map_err(|e| Error::Network(NetworkError::RawSocketCreation { source: e }))?;

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

            #[expect(clippy::cast_sign_loss, reason = "sendto returns non-negative on success")]
            {
                Ok(result as usize)
            }
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

            // Reset timeout to default (blocking)
            if timeout.is_some() {
                let tv = libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                };
                // SAFETY: setsockopt with valid fd and valid timeval pointer
                unsafe {
                    libc::setsockopt(
                        self.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&raw const tv).cast::<libc::c_void>(),
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    );
                }
            }

            if result < 0 {
                return Err(io::Error::last_os_error());
            }

            #[expect(clippy::cast_sign_loss, reason = "recvfrom returns non-negative on success")]
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
    }

    impl TcpPacketBuilder {
        /// Creates a new TCP packet builder.
        #[must_use]
        pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: Port, dst_port: Port) -> Self {
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
            }
        }

        /// Sets the sequence number.
        #[must_use]
        pub fn seq(mut self, seq: u32) -> Self {
            self.seq = seq;
            self
        }

        /// Sets the acknowledgment number.
        #[must_use]
        pub fn ack(mut self, ack: u32) -> Self {
            self.ack = ack;
            self
        }

        /// Sets the SYN flag.
        #[must_use]
        pub fn syn(mut self) -> Self {
            self.flags |= 0x02;
            self
        }

        /// Sets the ACK flag.
        #[must_use]
        pub fn ack_flag(mut self) -> Self {
            self.flags |= 0x10;
            self
        }

        /// Sets the RST flag.
        #[must_use]
        pub fn rst(mut self) -> Self {
            self.flags |= 0x04;
            self
        }

        /// Sets the FIN flag.
        #[must_use]
        pub fn fin(mut self) -> Self {
            self.flags |= 0x01;
            self
        }

        /// Sets the window size.
        #[must_use]
        pub fn window(mut self, window: u16) -> Self {
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
            // Identification (16 bits) - use 0 for now
            packet.push(0);
            packet.push(0);
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
            let tcp_checksum = Self::calculate_tcp_checksum(
                self.src_ip,
                self.dst_ip,
                &packet[tcp_header_start..],
            );
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

    /// Parses a TCP response packet.
    ///
    /// Returns the TCP flags, sequence number, acknowledgment number, and source port
    /// if the packet is a valid TCP response.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some((flags, seq, ack, src_port))` if valid TCP packet, `None` otherwise.
    #[must_use]
    pub fn parse_tcp_response(packet: &[u8]) -> Option<(u8, u32, u32, Port)> {
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

        // Parse TCP header
        let tcp_start = ip_header_len;
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
