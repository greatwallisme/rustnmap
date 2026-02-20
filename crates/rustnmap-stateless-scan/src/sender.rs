// rustnmap-stateless-scan
// Copyright (C) 2026  greatwallisme

//! Stateless SYN packet sender.

use crate::cookie::{current_timestamp, CookieGenerator};
use rustnmap_common::Result;
use rustnmap_core::session::{PacketBuffer, PacketEngine};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;

/// Stateless SYN packet sender.
///
/// Sends TCP SYN packets without maintaining connection state.
/// Uses cookie encoding for response matching.
pub struct StatelessSender {
    /// Packet engine for raw packet transmission.
    packet_engine: Arc<dyn PacketEngine>,
    /// Cookie generator for encoding.
    cookie_gen: CookieGenerator,
    /// Local IP address.
    local_ip: IpAddr,
    /// Source port for RST packets.
    rst_source_port: u16,
}

impl std::fmt::Debug for StatelessSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatelessSender")
            .field("packet_engine", &"PacketEngine")
            .field("cookie_gen", &self.cookie_gen)
            .field("local_ip", &self.local_ip)
            .field("rst_source_port", &self.rst_source_port)
            .finish()
    }
}

impl StatelessSender {
    /// Create a new stateless sender.
    ///
    /// # Arguments
    ///
    /// * `packet_engine` - Raw packet engine
    /// * `cookie_gen` - Cookie generator
    /// * `local_ip` - Local IP address for packets
    pub fn new(
        packet_engine: Arc<dyn PacketEngine>,
        cookie_gen: CookieGenerator,
        local_ip: IpAddr,
    ) -> Self {
        Self {
            packet_engine,
            cookie_gen,
            local_ip,
            rst_source_port: 0, // Will be set on first use
        }
    }

    /// Send a single SYN packet to target.
    ///
    /// # Errors
    ///
    /// Returns an error if packet creation or sending fails.
    pub async fn send_syn(&self, target: IpAddr, port: u16) -> Result<()> {
        let (source_port, seq_num) = self.cookie_gen.generate_packet_params(target, port);

        // Build TCP SYN packet
        let packet = self.build_syn_packet(target, port, source_port, seq_num)?;

        // Send packet - convert CoreError to rustnmap_common::Error
        self.packet_engine
            .send_packet(packet)
            .await
            .map_err(|e| rustnmap_common::Error::Other(e.to_string()))?;

        debug!(
            "Sent SYN to {}:{} from {}:{}",
            target, port, self.local_ip, source_port
        );

        Ok(())
    }

    /// Send batch of SYN packets.
    ///
    /// # Arguments
    ///
    /// * `targets` - Slice of (`target_ip`, port) tuples
    ///
    /// # Returns
    ///
    /// Number of packets successfully sent.
    ///
    /// # Errors
    ///
    /// Returns an error if batch sending fails.
    pub async fn send_batch(&self, targets: &[(IpAddr, u16)]) -> Result<usize> {
        let mut packets = Vec::with_capacity(targets.len());

        for &(target, port) in targets {
            let (source_port, seq_num) = self.cookie_gen.generate_packet_params(target, port);
            let packet = self.build_syn_packet(target, port, source_port, seq_num)?;
            packets.push(packet);
        }

        // Send all packets - convert CoreError to rustnmap_common::Error
        let sent = self
            .packet_engine
            .send_batch(&packets)
            .await
            .map_err(|e| rustnmap_common::Error::Other(e.to_string()))?;

        debug!("Sent {} SYN packets in batch", sent);

        Ok(sent)
    }

    /// Send batch with rate limiting.
    ///
    /// # Arguments
    ///
    /// * `targets` - Slice of (`target_ip`, port) tuples
    /// * `rate_limiter` - Rate limiter channel
    ///
    /// # Returns
    ///
    /// Number of packets successfully sent.
    ///
    /// # Errors
    ///
    /// Returns an error if batch sending fails.
    pub async fn send_batch_with_rate_limit(
        &self,
        targets: &[(IpAddr, u16)],
        mut rate_limiter: mpsc::Receiver<()>,
    ) -> Result<usize> {
        let mut sent = 0;

        for chunk in targets.chunks(100) {
            // Wait for rate limit
            let _ = rate_limiter.recv().await;

            let chunk_sent = self.send_batch(chunk).await?;
            sent += chunk_sent;
        }

        Ok(sent)
    }

    /// Send RST packet to close connection.
    ///
    /// # Errors
    ///
    /// Returns an error if packet sending fails.
    pub async fn send_rst(&mut self, target: IpAddr, dest_port: u16, ack_num: u32) -> Result<()> {
        if self.rst_source_port == 0 {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "Timestamp modulo 64511 always fits in u16"
            )]
            let port_offset = current_timestamp() as u16 % 64511;
            self.rst_source_port = 1024 + port_offset;
        }

        let packet = self.build_rst_packet(target, dest_port, self.rst_source_port, ack_num)?;
        self.packet_engine
            .send_packet(packet)
            .await
            .map_err(|e| rustnmap_common::Error::Other(e.to_string()))?;

        debug!("Sent RST to {}:{} seq={}", target, dest_port, ack_num);

        Ok(())
    }

    /// Build TCP SYN packet.
    fn build_syn_packet(
        &self,
        target: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq: u32,
    ) -> Result<PacketBuffer> {
        // Use pnet to build packet
        let mut packet = vec![0u8; 40]; // 20 bytes IP + 20 bytes TCP

        // Build IP header
        self.build_ip_header(&mut packet, target)?;

        // Build TCP header
        Self::build_tcp_header(&mut packet[20..], source_port, dest_port, seq, true, false);

        Ok(PacketBuffer::from_data(packet))
    }

    /// Build TCP RST packet.
    fn build_rst_packet(
        &self,
        target: IpAddr,
        dest_port: u16,
        source_port: u16,
        seq: u32,
    ) -> Result<PacketBuffer> {
        let mut packet = vec![0u8; 40];

        self.build_ip_header(&mut packet, target)?;
        Self::build_tcp_header(&mut packet[20..], source_port, dest_port, seq, false, true);

        Ok(PacketBuffer::from_data(packet))
    }

    /// Build IP header (simplified IPv4).
    fn build_ip_header(&self, packet: &mut [u8], target: IpAddr) -> Result<()> {
        let IpAddr::V4(dest_ip) = target else {
            return Err(rustnmap_common::Error::Other(
                "IPv6 not supported in stateless mode".into(),
            ));
        };

        let IpAddr::V4(source_ip) = self.local_ip else {
            return Err(rustnmap_common::Error::Other(
                "IPv6 not supported in stateless mode".into(),
            ));
        };

        // Version + IHL
        packet[0] = 0x45;
        // TOS
        packet[1] = 0;
        // Total length
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Packet length always fits in u16 (max 65535 bytes)"
        )]
        let total_len: u16 = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        // Identification
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Timestamp lower 16 bits used for identification"
        )]
        let ident: u16 = current_timestamp() as u16;
        packet[4..6].copy_from_slice(&ident.to_be_bytes());
        // Flags + Fragment offset (Don't Fragment)
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        // TTL
        packet[8] = 64;
        // Protocol (TCP)
        packet[9] = 6;
        // Checksum (0 for now, let kernel handle it)
        packet[10..12].copy_from_slice(&[0, 0]);
        // Source IP
        packet[12..16].copy_from_slice(&source_ip.octets());
        // Dest IP
        packet[16..20].copy_from_slice(&dest_ip.octets());

        Ok(())
    }

    /// Build TCP header.
    ///
    /// # Arguments
    ///
    /// * `packet` - TCP packet buffer (20 bytes)
    /// * `source_port` - Source port
    /// * `dest_port` - Destination port
    /// * `seq` - Sequence number
    /// * `syn` - SYN flag
    /// * `rst` - RST flag
    fn build_tcp_header(
        packet: &mut [u8],
        source_port: u16,
        dest_port: u16,
        seq: u32,
        syn: bool,
        rst: bool,
    ) {
        // Source port
        packet[0..2].copy_from_slice(&source_port.to_be_bytes());
        // Dest port
        packet[2..4].copy_from_slice(&dest_port.to_be_bytes());
        // Sequence number
        packet[4..8].copy_from_slice(&seq.to_be_bytes());
        // Acknowledgment number (0 for SYN, seq for RST)
        let ack = if rst { seq } else { 0 };
        packet[8..12].copy_from_slice(&ack.to_be_bytes());
        // Data offset (5 = 20 bytes, no options) + Reserved + Flags
        let data_offset = 5 << 4;
        let flags = if syn { 0x02 } else { 0 } | if rst { 0x04 } else { 0 };
        packet[12] = data_offset;
        packet[13] = flags;
        // Window size
        packet[14..16].copy_from_slice(&1024u16.to_be_bytes());
        // Checksum (0 for now)
        packet[16..18].copy_from_slice(&[0, 0]);
        // Urgent pointer
        packet[18..20].copy_from_slice(&[0, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_core::error::CoreError;
    use std::pin::Pin;

    struct MockPacketEngine;

    #[tokio::test]
    async fn test_mock_sender() {
        let cookie_gen = CookieGenerator::default();
        let local_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

        let _sender = StatelessSender::new(Arc::new(MockPacketEngine), cookie_gen, local_ip);
    }

    #[async_trait::async_trait]
    impl PacketEngine for MockPacketEngine {
        async fn send_packet(
            &self,
            _packet: PacketBuffer,
        ) -> std::result::Result<usize, CoreError> {
            Ok(0)
        }

        async fn send_batch(
            &self,
            _packets: &[PacketBuffer],
        ) -> std::result::Result<usize, CoreError> {
            Ok(0)
        }

        fn recv_stream(&self) -> Pin<Box<dyn futures_util::Stream<Item = PacketBuffer> + Send>> {
            use futures_util::stream::empty;
            Box::pin(empty())
        }

        fn set_bpf(
            &self,
            _filter: &rustnmap_core::session::BpfProg,
        ) -> std::result::Result<(), CoreError> {
            Ok(())
        }

        fn local_mac(&self) -> Option<rustnmap_common::MacAddr> {
            None
        }

        fn if_index(&self) -> libc::c_uint {
            0
        }
    }
}
