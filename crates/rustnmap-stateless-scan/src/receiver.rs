// rustnmap-stateless-scan
// Copyright (C) 2026  greatwallisme

//! Stateless response receiver.

use crate::cookie::{CookieGenerator, VerifyResult};
use futures_util::StreamExt;
use rustnmap_common::Result;
use rustnmap_core::session::PacketEngine;
use rustnmap_output::models::{HostResult, PortResult, PortState, Protocol};
use rustnmap_packet::PacketBuffer;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;

/// Scan event from receiver.
#[derive(Debug, Clone)]
pub struct ReceiveEvent {
    /// Target IP that responded.
    pub target: IpAddr,
    /// Open port.
    pub port: u16,
    /// Source port from response.
    pub source_port: u16,
    /// Sequence number from response.
    pub ack_num: u32,
}

/// Stateless SYN-ACK receiver.
///
/// Receives and validates TCP SYN-ACK responses using cookie verification.
pub struct StatelessReceiver {
    /// Packet engine for raw packet reception.
    packet_engine: Arc<dyn PacketEngine>,
    /// Cookie generator for verification.
    cookie_gen: CookieGenerator,
    /// Results channel.
    results_tx: mpsc::Sender<ReceiveEvent>,
    /// Maximum cookie age for replay protection.
    max_age: Duration,
}

impl std::fmt::Debug for StatelessReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatelessReceiver")
            .field("packet_engine", &"PacketEngine")
            .field("cookie_gen", &self.cookie_gen)
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

impl StatelessReceiver {
    /// Create a new stateless receiver.
    pub fn new(
        packet_engine: Arc<dyn PacketEngine>,
        cookie_gen: CookieGenerator,
        results_tx: mpsc::Sender<ReceiveEvent>,
        max_age: Duration,
    ) -> Self {
        Self {
            packet_engine,
            cookie_gen,
            results_tx,
            max_age,
        }
    }

    /// Run the receive loop.
    ///
    /// # Errors
    ///
    /// Returns an error if packet reception fails.
    pub async fn recv_loop(&self) -> Result<()> {
        let mut stream = self.packet_engine.recv_stream();

        while let Some(packet) = stream.next().await {
            // Parse packet
            if let Some(event) = Self::parse_packet(&packet) {
                // Verify cookie with destination port for production-grade verification
                match self.cookie_gen.verify(
                    event.target,
                    event.port, // Destination port we originally probed
                    event.source_port,
                    event.ack_num,
                    self.max_age,
                ) {
                    VerifyResult::Valid => {
                        debug!("Valid SYN-ACK from {}:{} ", event.target, event.port);

                        // Send to results channel
                        if self.results_tx.send(event).await.is_err() {
                            break; // Channel closed
                        }
                    }
                    VerifyResult::Invalid => {
                        debug!("Invalid cookie, dropping packet");
                    }
                    VerifyResult::Expired => {
                        debug!("Expired cookie, possible replay");
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse TCP packet and extract SYN-ACK info.
    fn parse_packet(packet: &PacketBuffer) -> Option<ReceiveEvent> {
        let data = packet.data();

        // Minimum packet size: 20 bytes IP + 20 bytes TCP = 40 bytes
        if data.len() < 40 {
            return None;
        }

        // Parse IP header
        let ip_header_len = ((data[0] & 0x0F) as usize) * 4;
        if data.len() < ip_header_len + 20 {
            return None;
        }

        // Extract source IP
        let source_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));

        // Parse TCP header (starts after IP header)
        let tcp_start = ip_header_len;
        if data.len() < tcp_start + 20 {
            return None;
        }

        let source_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
        let dest_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);
        let _seq_num = u32::from_be_bytes([
            data[tcp_start + 4],
            data[tcp_start + 5],
            data[tcp_start + 6],
            data[tcp_start + 7],
        ]);
        let ack_num = u32::from_be_bytes([
            data[tcp_start + 8],
            data[tcp_start + 9],
            data[tcp_start + 10],
            data[tcp_start + 11],
        ]);

        // Check flags (byte 13 of TCP header)
        let flags = data[tcp_start + 13];
        let syn = (flags & 0x02) != 0;
        let ack = (flags & 0x10) != 0;

        // Only process SYN-ACK packets
        if !syn || !ack {
            return None;
        }

        Some(ReceiveEvent {
            target: source_ip,
            port: dest_port,
            source_port,
            ack_num,
        })
    }

    /// Convert receive event to [`HostResult`].
    #[must_use]
    pub fn event_to_host_result(event: &ReceiveEvent) -> HostResult {
        let port_result = PortResult {
            number: event.port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            state_reason: "syn-ack".to_string(),
            state_ttl: None,
            service: None,
            scripts: vec![],
        };

        HostResult {
            ip: event.target,
            hostname: None,
            mac: None,
            status: rustnmap_output::models::HostStatus::Up,
            status_reason: "user".to_string(),
            latency: Duration::ZERO,
            ports: vec![port_result],
            os_matches: vec![],
            scripts: vec![],
            traceroute: None,
            times: rustnmap_output::models::HostTimes {
                srtt: None,
                rttvar: None,
                timeout: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receive_event_creation() {
        let event = ReceiveEvent {
            target: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 80,
            source_port: 12345,
            ack_num: 1000,
        };

        assert_eq!(event.port, 80);
        assert_eq!(event.source_port, 12345);
    }
}
