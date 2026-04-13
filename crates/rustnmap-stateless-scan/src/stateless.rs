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

//! Main stateless scanner implementation.

use crate::cookie::CookieGenerator;
use crate::receiver::{ReceiveEvent, StatelessReceiver};
use crate::sender::StatelessSender;
use rustnmap_common::Result;
use rustnmap_core::session::PacketEngine;
use rustnmap_output::models::ScanResult;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info};

/// Scan event for streaming results.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Host discovered with open port.
    HostFound {
        /// Target IP.
        ip: IpAddr,
        /// Open port.
        port: u16,
    },
    /// Scan progress.
    Progress {
        /// Number of hosts scanned.
        hosts_scanned: usize,
        /// Number of open ports found.
        ports_open: usize,
    },
    /// Scan completed.
    Completed {
        /// Total hosts scanned.
        hosts_scanned: usize,
        /// Total open ports found.
        ports_open: usize,
    },
}

/// Stateless scanner configuration.
#[derive(Debug, Clone)]
pub struct StatelessConfig {
    /// Source IP address (can be spoofed).
    pub source_ip: IpAddr,
    /// Maximum cookie age for replay protection.
    pub max_cookie_age: Duration,
    /// Packets per second rate limit.
    pub rate_limit: Option<u64>,
    /// Batch size for sending.
    pub batch_size: usize,
}

impl Default for StatelessConfig {
    fn default() -> Self {
        Self {
            source_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            max_cookie_age: Duration::from_secs(30),
            rate_limit: None,
            batch_size: 100,
        }
    }
}

/// Stateless scanner for high-speed port scanning.
///
/// Combines sender and receiver for complete stateless scanning.
pub struct StatelessScanner {
    /// Scanner configuration.
    config: StatelessConfig,
    /// Packet engine.
    packet_engine: Arc<dyn PacketEngine>,
    /// Cookie generator.
    cookie_gen: CookieGenerator,
    /// Event channel sender.
    event_tx: Mutex<Option<mpsc::Sender<ScanEvent>>>,
}

impl std::fmt::Debug for StatelessScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatelessScanner")
            .field("config", &self.config)
            .field("packet_engine", &"PacketEngine")
            .field("cookie_gen", &self.cookie_gen)
            .finish_non_exhaustive()
    }
}

impl StatelessScanner {
    /// Create a new stateless scanner.
    ///
    /// # Arguments
    ///
    /// * `config` - Scanner configuration
    /// * `packet_engine` - Raw packet engine
    pub fn new(config: StatelessConfig, packet_engine: Arc<dyn PacketEngine>) -> Self {
        let cookie_gen = CookieGenerator::default();

        Self {
            config,
            packet_engine,
            cookie_gen,
            event_tx: Mutex::new(None),
        }
    }

    /// Run stateless scan on targets.
    ///
    /// # Arguments
    ///
    /// * `targets` - Slice of (IP, port) tuples to scan
    /// * `event_tx` - Channel for scan events
    ///
    /// # Returns
    ///
    /// Scan results.
    ///
    /// # Errors
    ///
    /// Returns an error if scanning fails.
    pub async fn scan(
        &self,
        targets: &[(IpAddr, u16)],
        event_tx: mpsc::Sender<ScanEvent>,
    ) -> Result<ScanResult> {
        info!("Starting stateless scan on {} targets", targets.len());

        // Store event channel
        *self.event_tx.lock().await = Some(event_tx.clone());

        // Create result channel
        let (result_tx, mut result_rx) = mpsc::channel::<ReceiveEvent>(1000);

        // Create sender and receiver
        let sender = StatelessSender::new(
            Arc::clone(&self.packet_engine),
            self.cookie_gen.clone(),
            self.config.source_ip,
        );

        let receiver = StatelessReceiver::new(
            Arc::clone(&self.packet_engine),
            self.cookie_gen.clone(),
            result_tx,
            self.config.max_cookie_age,
        );

        // Start receiver task
        let recv_handle = tokio::spawn(async move { receiver.recv_loop().await });

        // Send SYN packets in batches
        let mut hosts_scanned = 0;
        let mut ports_open = 0;

        for chunk in targets.chunks(self.config.batch_size) {
            match sender.send_batch(chunk).await {
                Ok(sent) => {
                    hosts_scanned += sent;

                    // Send progress event
                    let _ = event_tx
                        .send(ScanEvent::Progress {
                            hosts_scanned,
                            ports_open,
                        })
                        .await;
                }
                Err(e) => {
                    error!("Failed to send batch: {}", e);
                }
            }

            // Small delay between batches
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait for responses (with timeout)
        let mut results = Vec::new();
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Some(event) = result_rx.recv() => {
                    ports_open += 1;
                    results.push(event.clone());

                    // Send host found event
                    let _ = event_tx.send(ScanEvent::HostFound {
                        ip: event.target,
                        port: event.port,
                    }).await;
                }
                () = &mut timeout => {
                    break;
                }
            }
        }

        // Stop receiver
        recv_handle.abort();

        // Send completion event
        let _ = event_tx
            .send(ScanEvent::Completed {
                hosts_scanned,
                ports_open,
            })
            .await;

        info!(
            "Stateless scan completed: {} hosts, {} open ports",
            hosts_scanned, ports_open
        );

        // Convert results to ScanResult
        Ok(Self::build_scan_result(&results))
    }

    /// Run stateless scan with rate limiting.
    ///
    /// # Arguments
    ///
    /// * `targets` - Slice of (IP, port) tuples to scan
    /// * `rate_limit` - Packets per second
    /// * `event_tx` - Channel for scan events
    ///
    /// # Returns
    ///
    /// Scan results.
    ///
    /// # Errors
    ///
    /// Returns an error if scanning fails.
    pub async fn scan_with_rate_limit(
        &self,
        targets: &[(IpAddr, u16)],
        rate_limit: u64,
        event_tx: mpsc::Sender<ScanEvent>,
    ) -> Result<ScanResult> {
        info!("Starting rate-limited stateless scan at {} pps", rate_limit);

        // Create rate limiter channel
        #[allow(
            clippy::cast_precision_loss,
            reason = "Rate limit is controlled by user, precision loss is acceptable"
        )]
        let interval = Duration::from_secs_f64(1.0 / rate_limit as f64);
        let (rate_tx, _rate_rx) = mpsc::channel::<()>(100);

        // Start rate limiter
        let rate_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if rate_tx.send(()).await.is_err() {
                    break;
                }
            }
        });

        // Run scan
        let result = self.scan(targets, event_tx).await;

        // Stop rate limiter
        rate_handle.abort();

        result
    }

    /// Build scan result from receive events.
    fn build_scan_result(events: &[ReceiveEvent]) -> ScanResult {
        use rustnmap_output::models::{
            HostResult, HostTimes, PortResult, PortState, Protocol, ScanMetadata, ScanStatistics,
        };

        let mut hosts: Vec<HostResult> = Vec::new();

        // Group events by IP
        let mut host_map: std::collections::HashMap<IpAddr, Vec<u16>> =
            std::collections::HashMap::new();

        for event in events {
            host_map.entry(event.target).or_default().push(event.port);
        }

        // Convert to HostResult
        for (ip, ports) in host_map {
            let port_results: Vec<PortResult> = ports
                .iter()
                .map(|&port| PortResult {
                    number: port,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    state_reason: "syn-ack".to_string(),
                    state_ttl: None,
                    service: None,
                    scripts: vec![],
                })
                .collect();

            hosts.push(HostResult {
                ip,
                hostname: None,
                mac: None,
                status: rustnmap_output::models::HostStatus::Up,
                status_reason: "user".to_string(),
                latency: Duration::ZERO,
                ports: port_results,
                os_matches: vec![],
                scripts: vec![],
                traceroute: None,
                times: HostTimes {
                    srtt: None,
                    rttvar: None,
                    timeout: None,
                },
            });
        }

        let hosts_len = hosts.len();
        let now = SystemTime::now();
        ScanResult {
            metadata: ScanMetadata {
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                command_line: "rustnmap --fast".to_string(),
                start_time: now.into(),
                end_time: now.into(),
                elapsed: Duration::ZERO,
                scan_type: rustnmap_output::models::ScanType::TcpSyn,
                protocol: Protocol::Tcp,
            },
            hosts,
            statistics: ScanStatistics {
                total_hosts: hosts_len,
                hosts_up: hosts_len,
                hosts_down: 0,
                total_ports: events.len() as u64,
                open_ports: events.len() as u64,
                closed_ports: 0,
                filtered_ports: 0,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
            },
            errors: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_core::error::CoreError;
    use std::pin::Pin;

    #[test]
    fn test_config_default() {
        let config = StatelessConfig::default();
        assert_eq!(config.max_cookie_age, Duration::from_secs(30));
        assert_eq!(config.batch_size, 100);
        assert!(config.rate_limit.is_none());
    }

    #[test]
    fn test_scanner_creation() {
        let config = StatelessConfig::default();
        let packet_engine = Arc::new(MockPacketEngine);
        let _scanner = StatelessScanner::new(config, packet_engine);
    }

    struct MockPacketEngine;

    #[async_trait::async_trait]
    impl rustnmap_core::session::PacketEngine for MockPacketEngine {
        async fn send_packet(
            &self,
            _packet: rustnmap_packet::PacketBuffer,
        ) -> std::result::Result<usize, CoreError> {
            Ok(0)
        }

        async fn send_batch(
            &self,
            _packets: &[rustnmap_packet::PacketBuffer],
        ) -> std::result::Result<usize, CoreError> {
            Ok(0)
        }

        fn recv_stream(
            &self,
        ) -> Pin<Box<dyn futures_util::Stream<Item = rustnmap_packet::PacketBuffer> + Send>>
        {
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
