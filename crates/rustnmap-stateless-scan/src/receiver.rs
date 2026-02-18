// rustnmap-stateless-scan
// Copyright (C) 2026  greatwallisme

//! Stateless response receiver.

use crate::cookie::{CookieGenerator, VerifyResult};
use rustnmap_common::Result;
use rustnmap_core::session::PacketEngine;
use rustnmap_output::models::{HostResult, PortResult, PortState, Protocol};
use rustnmap_packet::PacketBuffer;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
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
            if let Some(event) = self.parse_packet(&packet) {
                // Verify cookie
                match self.cookie_gen.verify(
                    event.target,
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
    fn parse_packet(&self, packet: &PacketBuffer) -> Option<ReceiveEvent> {
        // Get packet data - assuming PacketBuffer has a way to access data
        // This is a simplified implementation
        // In production, you'd need to access the actual packet bytes

        // For now, return None as PacketBuffer internals need to be accessed
        // through proper methods
        None
    }

    /// Convert receive event to HostResult.
    #[must_use]
    pub fn event_to_host_result(event: &ReceiveEvent) -> HostResult {
        let port_result = PortResult {
            port: event.port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            reason: Some("syn-ack".to_string()),
            service: None,
        };

        HostResult {
            ip: event.target,
            hostname: None,
            mac: None,
            status: rustnmap_output::models::HostStatus::Up,
            ports: vec![port_result],
            os_match: None,
            scripts: vec![],
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
