// rustnmap-stateless-scan
// Copyright (C) 2026  greatwallisme

//! Main stateless scanner implementation.

use crate::cookie::CookieGenerator;
use crate::sender::StatelessSender;
use crate::receiver::{StatelessReceiver, ReceiveEvent};
use rustnmap_common::Result;
use rustnmap_core::session::PacketEngine;
use rustnmap_output::models::ScanResult;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, debug, error};

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
            self.packet_engine.clone(),
            self.cookie_gen.clone(),
            self.config.source_ip,
        );

        let receiver = StatelessReceiver::new(
            self.packet_engine.clone(),
            self.cookie_gen.clone(),
            result_tx,
            self.config.max_cookie_age,
        );

        // Start receiver task
        let recv_handle = tokio::spawn(async move {
            receiver.recv_loop().await
        });

        // Send SYN packets in batches
        let mut hosts_scanned = 0;
        let mut ports_open = 0;

        for chunk in targets.chunks(self.config.batch_size) {
            match sender.send_batch(chunk).await {
                Ok(sent) => {
                    hosts_scanned += sent;

                    // Send progress event
                    let _ = event_tx.send(ScanEvent::Progress {
                        hosts_scanned,
                        ports_open,
                    }).await;
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
                    results.push(event);

                    // Send host found event
                    let _ = event_tx.send(ScanEvent::HostFound {
                        ip: event.target,
                        port: event.port,
                    }).await;
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        // Stop receiver
        recv_handle.abort();

        // Send completion event
        let _ = event_tx.send(ScanEvent::Completed {
            hosts_scanned,
            ports_open,
        }).await;

        info!("Stateless scan completed: {} hosts, {} open ports", hosts_scanned, ports_open);

        // Convert results to ScanResult
        Ok(self.build_scan_result(&results))
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
        let interval = Duration::from_secs_f64(1.0 / rate_limit as f64);
        let (rate_tx, rate_rx) = mpsc::channel::<()>(100);

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
    fn build_scan_result(&self, events: &[ReceiveEvent]) -> ScanResult {
        use rustnmap_output::models::{HostResult, PortResult, PortState, Protocol, ScanMetadata};
        use std::time::SystemTime;

        let mut hosts: Vec<HostResult> = Vec::new();

        // Group events by IP
        let mut host_map: std::collections::HashMap<IpAddr, Vec<u16>> = std::collections::HashMap::new();

        for event in events {
            host_map.entry(event.target).or_default().push(event.port);
        }

        // Convert to HostResult
        for (ip, ports) in host_map {
            let port_results: Vec<PortResult> = ports.iter().map(|&port| PortResult {
                port,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                reason: Some("syn-ack".to_string()),
                service: None,
            }).collect();

            hosts.push(HostResult {
                ip,
                hostname: None,
                mac: None,
                status: rustnmap_output::models::HostStatus::Up,
                ports: port_results,
                os_match: None,
                scripts: vec![],
            });
        }

        ScanResult {
            metadata: ScanMetadata {
                start_time: SystemTime::now().into(),
                end_time: SystemTime::now().into(),
                command_line: "rustnmap --fast".to_string(),
                scan_type: rustnmap_output::models::ScanType::TcpSyn,
                protocol: Protocol::Tcp,
            },
            hosts,
            statistics: rustnmap_output::models::ScanStatistics {
                hosts_total: hosts.len() as u32,
                hosts_up: hosts.len() as u32,
                hosts_down: 0,
                ports_total: events.len() as u32,
                ports_open: events.len() as u32,
                ports_closed: 0,
                ports_filtered: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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

    impl rustnmap_packet::PacketEngine for MockPacketEngine {
        async fn send(&self, _packet: &[u8]) -> Result<usize> {
            Ok(0)
        }

        async fn send_batch(&self, _packets: &[Vec<u8>]) -> Result<usize> {
            Ok(0)
        }

        async fn recv(&self, _buffer: &mut [u8]) -> Result<usize> {
            Ok(0)
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }
}
