//! Probe packet construction and parsing for network scanning.
//!
//! This module provides utilities for building and parsing network probes
//! used across different scanning techniques.

#![warn(missing_docs)]

use rustnmap_common::{Ipv4Addr, Port};

/// Maximum TCP packet size for scanning probes.
///
/// SYN probes are minimal (no payload), typically 20-40 bytes IP + 20 bytes TCP.
pub const MAX_TCP_PROBE_SIZE: usize = 128;

/// Default TTL for outgoing probe packets.
///
/// Matches common network scanning practice for TTL.
pub const DEFAULT_TTL: u8 = 64;

/// TCP window size for SYN scans.
///
/// Value suggests a capable receiver during TCP handshake.
pub const TCP_WINDOW_SIZE: u16 = 1024;

/// Identification field for IP packets.
///
/// Will be randomized in production for stealth.
pub const IP_IDENTIFICATION: u16 = 0x1234;

/// Probe sequence number.
///
/// Each probe gets a unique sequence number for matching responses.
pub type ProbeSeq = u32;

/// Probe acknowledgment number.
pub type ProbeAck = u32;

/// TCP protocol number for IP header.
const TCP_PROTOCOL: u8 = 6;

/// TCP flag: Synchronize (SYN).
pub const TCP_FLAGS_SYN: u8 = 0x02;

/// Constructs a TCP SYN probe packet.
///
/// # Arguments
///
/// * `src_addr` - Source IP address
/// * `dst_addr` - Destination IP address
/// * `src_port` - Source port number
/// * `dst_port` - Destination port number
/// * `seq` - TCP sequence number
/// * `payload` - Optional custom payload data to append
///
/// # Returns
///
/// The constructed SYN probe packet as a `Vec<u8>`.
///
/// # Panics
///
/// Panics if the payload length exceeds 65535 bytes (TCP maximum segment size).
pub fn build_tcp_syn_probe(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: Port,
    dst_port: Port,
    seq: ProbeSeq,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let payload_len = payload.map_or(0, <[u8]>::len);
    // Total IP header length (20) + TCP header length (20) + payload
    let total_len: u16 = 40 + u16::try_from(payload_len).expect("payload too large");

    // Allocate buffer for the probe packet
    let mut probe = vec![0u8; usize::from(total_len)];

    // === IP Header (20 bytes) ===
    // Version (4 bits) = 4, IHL (4 bits) = 5 (20 bytes = 5 * 4)
    probe[0] = 0x45;
    // Type of Service = 0 (forwarding priority)
    probe[1] = 0;
    // Total Length = total_len
    probe[2..4].copy_from_slice(&total_len.to_be_bytes());
    // Identification
    probe[4..6].copy_from_slice(&IP_IDENTIFICATION.to_be_bytes());
    // Flags + Fragment Offset = 0
    probe[6..8].copy_from_slice(&[0u8; 2]);
    // TTL
    probe[8] = DEFAULT_TTL;
    // Protocol = TCP (6)
    probe[9] = TCP_PROTOCOL;
    // Checksum = 0 (filled in later)
    probe[10..12].copy_from_slice(&[0u8; 2]);
    // Source Address
    probe[12..16].copy_from_slice(&src_addr.octets());
    // Destination Address
    probe[16..20].copy_from_slice(&dst_addr.octets());

    // Calculate IP checksum (covering bytes 0-19, skip checksum field itself)
    let checksum = checksum_data(&probe[..20]);
    probe[10..12].copy_from_slice(&checksum.to_be_bytes());

    // === TCP Header (starts at offset 20) ===
    let tcp_offset: usize = 20;

    // Source Port
    probe[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());

    // Destination Port
    probe[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());

    // Sequence Number
    probe[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());

    // Acknowledgment Number = 0
    probe[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&[0u8; 4]);

    // Data Offset (5) = 0x50 (no options)
    probe[tcp_offset + 12] = 0x50;

    // Flags (SYN = 0x02)
    probe[tcp_offset + 13] = TCP_FLAGS_SYN;

    // Window Size
    probe[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&TCP_WINDOW_SIZE.to_be_bytes());

    // Checksum: zero field before calculation, then fill in below
    probe[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&[0u8; 2]);

    // Urgent Pointer = 0
    probe[tcp_offset + 18..tcp_offset + 20].copy_from_slice(&[0u8; 2]);

    // Append custom payload if provided
    if let Some(data) = payload {
        let payload_start = tcp_offset + 20;
        probe[payload_start..payload_start + data.len()].copy_from_slice(data);
    }

    // Calculate TCP checksum (covering TCP header + data)
    let tcp_checksum = tcp_checksum_data(
        src_addr,
        dst_addr,
        &probe[tcp_offset..tcp_offset + 20 + payload_len],
    );
    probe[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    probe
}

/// Parsed response indicating port state.
///
/// Represents the result of parsing a TCP response packet
/// to determine if a port is open, closed, or filtered.
#[derive(Debug, PartialEq, Eq)]
pub enum TcpProbeResponse {
    /// No valid response received (timeout or filtered).
    NoResponse,

    /// SYN-ACK response received - port is open.
    ///
    /// Contains the acknowledgment number, sequence number, and
    /// advertised window size from the response.
    SynAck {
        /// Acknowledgment number from the SYN-ACK.
        ack: ProbeAck,
        /// Sequence number from the SYN-ACK.
        seq: ProbeSeq,
        /// TCP window size advertised by the responder.
        window: u16,
    },

    /// RST response received - port is closed.
    ///
    /// Contains the sequence number from the reset packet.
    Rst {
        /// Sequence number from the RST packet.
        seq: ProbeSeq,
    },

    /// RST-ACK response received - port is closed.
    ///
    /// Contains both acknowledgment and sequence numbers.
    RstAck {
        /// Acknowledgment number from the RST-ACK.
        ack: ProbeAck,
        /// Sequence number from the RST-ACK.
        seq: ProbeSeq,
    },
}

/// Parses a TCP response packet.
///
/// # Arguments
///
/// * `packet` - Raw packet bytes received
/// * `_expected_seq` - Expected sequence number (unused in current impl)
///
/// # Returns
///
/// Parsed TCP probe response indicating port state.
#[must_use]
pub fn parse_tcp_response(packet: &[u8], _expected_seq: ProbeSeq) -> TcpProbeResponse {
    // Minimum packet size check (IP header 20 + TCP header 20)
    if packet.len() < 40 {
        return TcpProbeResponse::NoResponse;
    }

    // Verify IP version and header length
    let ip_version = packet[0] >> 4;
    if ip_version != 4 {
        return TcpProbeResponse::NoResponse;
    }

    let ip_header_len: usize = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ip_header_len + 20 {
        return TcpProbeResponse::NoResponse;
    }

    // Extract TCP header fields
    let tcp_offset = ip_header_len;

    // Check if packet has TCP data flags
    let flags = packet[tcp_offset + 13];

    // Extract sequence and acknowledgment numbers
    let seq_bytes = packet[tcp_offset + 4..tcp_offset + 8]
        .try_into()
        .unwrap_or([0u8; 4]);
    let seq = u32::from_be_bytes(seq_bytes);

    let ack_bytes = packet[tcp_offset + 8..tcp_offset + 12]
        .try_into()
        .unwrap_or([0u8; 4]);
    let ack = u32::from_be_bytes(ack_bytes);

    // Extract window size
    let window_bytes = packet[tcp_offset + 14..tcp_offset + 16]
        .try_into()
        .unwrap_or([0u8; 2]);
    let window = u16::from_be_bytes(window_bytes);

    // Parse TCP flags to determine response type
    let has_syn = (flags & 0x02) != 0;
    let has_ack = (flags & 0x10) != 0;
    let has_rst = (flags & 0x04) != 0;

    if has_syn && has_ack {
        TcpProbeResponse::SynAck { ack, seq, window }
    } else if has_rst && has_ack {
        TcpProbeResponse::RstAck { ack, seq }
    } else if has_rst {
        TcpProbeResponse::Rst { seq }
    } else {
        TcpProbeResponse::NoResponse
    }
}

/// Computes Internet checksum for the given data.
///
/// Standard RFC 1071 internet checksum algorithm.
///
/// # Arguments
///
/// * `data` - Data to compute checksum for
///
/// # Returns
///
/// The 16-bit checksum value.
#[expect(
    clippy::cast_possible_truncation,
    reason = "Loop folds sum to 16 bits; cast is safe"
)]
fn checksum_data(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Process 16-bit words
    let mut chunk = data.chunks_exact(2);
    for word in &mut chunk {
        let value = u16::from_be_bytes([word[0], word[1]]);
        sum = sum.wrapping_add(u32::from(value));
    }

    // Handle remaining byte if odd length
    if let Some(&remainder) = chunk.remainder().first() {
        sum = sum.wrapping_add(u32::from(remainder) << 8);
    }

    // Fold 32-bit sum to 16 bits using one's complement arithmetic
    while sum >> 16 != 0 {
        sum = sum.wrapping_add(sum >> 16);
    }

    // The checksum is the one's complement of the sum (RFC 1071)
    !(sum as u16)
}

/// Computes TCP checksum including pseudo-header.
///
/// # Arguments
///
/// * `src_addr` - Source IP address
/// * `dst_addr` - Destination IP address
/// * `tcp_data` - TCP segment data
///
/// # Returns
///
/// The 16-bit TCP checksum value.
#[expect(
    clippy::cast_possible_truncation,
    reason = "TCP max segment is 65535 bytes; cast to u16 is safe for valid TCP"
)]
fn tcp_checksum_data(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    // Build pseudo-header for TCP checksum
    let mut pseudo_header = Vec::with_capacity(12 + tcp_data.len());

    // Source address
    pseudo_header.extend_from_slice(&src_addr.octets());
    // Destination address
    pseudo_header.extend_from_slice(&dst_addr.octets());
    // Reserved (1 byte) + Protocol (1 byte = TCP)
    pseudo_header.push(0);
    pseudo_header.push(TCP_PROTOCOL);
    // TCP length - safe cast as TCP max segment is 65535 bytes
    pseudo_header.extend_from_slice(&(tcp_data.len() as u16).to_be_bytes());
    // TCP data
    pseudo_header.extend_from_slice(tcp_data);

    checksum_data(&pseudo_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tcp_syn_probe_size() {
        let probe = build_tcp_syn_probe(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            12345,
            80,
            1000,
            None,
        );

        // IP header (20) + TCP header (20) = 40 bytes
        assert_eq!(probe.len(), 40);
    }

    #[test]
    fn test_build_tcp_syn_probe_with_payload() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let probe = build_tcp_syn_probe(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            12345,
            80,
            1000,
            Some(payload),
        );

        // IP header (20) + TCP header (20) + payload
        assert_eq!(probe.len(), 40 + payload.len());

        // Verify payload is at the end
        let payload_start = 40;
        assert_eq!(&probe[payload_start..], payload.as_slice());
    }

    #[test]
    fn test_build_tcp_syn_probe_fields() {
        let probe = build_tcp_syn_probe(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(10, 0, 0, 1),
            65000,
            443,
            0xDEAD_BEEF,
            None,
        );

        // Check IP version and IHL
        assert_eq!(probe[0], 0x45);

        // Check TTL
        assert_eq!(probe[8], DEFAULT_TTL);

        // Check protocol is TCP
        assert_eq!(probe[9], TCP_PROTOCOL);

        // Check source address
        assert_eq!(&probe[12..16], &[192, 168, 1, 100]);

        // Check destination address
        assert_eq!(&probe[16..20], &[10, 0, 0, 1]);

        // Check TCP source port
        let tcp_offset = 20;
        let src_port = u16::from_be_bytes([probe[tcp_offset], probe[tcp_offset + 1]]);
        assert_eq!(src_port, 65000);

        // Check TCP destination port
        let dst_port = u16::from_be_bytes([probe[tcp_offset + 2], probe[tcp_offset + 3]]);
        assert_eq!(dst_port, 443);

        // Check TCP sequence number
        let seq = u32::from_be_bytes([
            probe[tcp_offset + 4],
            probe[tcp_offset + 5],
            probe[tcp_offset + 6],
            probe[tcp_offset + 7],
        ]);
        assert_eq!(seq, 0xDEAD_BEEF);

        // Check SYN flag is set
        assert!(probe[tcp_offset + 13] & 0x02 != 0);
    }

    #[test]
    fn test_parse_tcp_response_too_short() {
        let short_packet = [0u8; 20];
        let response = parse_tcp_response(&short_packet, 1000);
        assert_eq!(response, TcpProbeResponse::NoResponse);
    }

    #[test]
    fn test_parse_tcp_response_syn_ack() {
        let mut packet = [0u8; 54];
        // IP header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]); // Dest
                                                        // TCP header starts at 20
        let tcp_offset = 20;
        packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&1000u32.to_be_bytes()); // Seq
        packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&2000u32.to_be_bytes()); // Ack
        packet[tcp_offset + 13] = 0x12; // SYN+ACK flags
        packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&1024u16.to_be_bytes()); // Window

        let response = parse_tcp_response(&packet, 1000);
        assert!(matches!(response, TcpProbeResponse::SynAck { .. }));
        match response {
            TcpProbeResponse::SynAck { ack, seq, window } => {
                assert_eq!(seq, 1000);
                assert_eq!(ack, 2000);
                assert_eq!(window, 1024);
            }
            _ => panic!("Response should be SynAck"),
        }
    }

    #[test]
    fn test_parse_tcp_response_rst() {
        let mut packet = [0u8; 54];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let tcp_offset = 20;
        packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&5000u32.to_be_bytes()); // Seq
        packet[tcp_offset + 13] = 0x04; // RST flag

        let response = parse_tcp_response(&packet, 1000);
        assert!(matches!(response, TcpProbeResponse::Rst { .. }));
        match response {
            TcpProbeResponse::Rst { seq } => {
                assert_eq!(seq, 5000);
            }
            _ => panic!("Response should be Rst"),
        }
    }

    #[test]
    fn test_checksum_round_trip() {
        let data: [u8; 10] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let checksum = checksum_data(&data);

        // Verify checksum by adding it back using the same algorithm
        // The test should process all 5 words (10 bytes / 2)
        let mut sum: u32 = 0;
        let mut i = 0;
        while i < data.len() - 1 {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum = sum.wrapping_add(u32::from(word));
            i += 2;
        }
        // Add the checksum directly (it's already a u16 value)
        sum = sum.wrapping_add(u32::from(checksum));

        // Fold to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // Sum should be 0xFFFF (all bits set)
        assert_eq!(sum, 0xffff);
    }
}
