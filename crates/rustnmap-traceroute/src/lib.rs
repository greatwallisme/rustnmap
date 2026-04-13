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

//! Network route tracing for `RustNmap`.
//!
//! This crate provides traceroute functionality including:
//! - UDP traceroute (standard)
//! - TCP traceroute (SYN, ACK)
//! - ICMP traceroute (Echo)
//! - TTL-based hop discovery
//! - AS number lookup
//! - Geographic location

#![warn(missing_docs)]

pub mod error;
pub mod hops;
pub mod icmp;
pub mod probe;
pub mod tcp;
pub mod udp;

// Re-exports
pub use error::{Result, TracerouteError};
pub use hops::{HopInfo, PathMtu};
pub use icmp::IcmpTraceroute;
pub use probe::{ProbeConfig, ProbeResponse, ProbeType, ProbeType as TracerouteProbeType};
pub use tcp::{TcpAckTraceroute, TcpSynTraceroute};
pub use udp::UdpTraceroute;

use rand::Rng;
use rustnmap_common::Ipv4Addr;
use std::time::Duration;
use tokio::time::sleep;

/// Main traceroute engine.
#[derive(Debug)]
pub struct Traceroute {
    config: TracerouteConfig,
    local_addr: Ipv4Addr,
}

/// Traceroute configuration options.
#[derive(Debug, Clone)]
pub struct TracerouteConfig {
    /// Maximum number of hops to trace.
    max_hops: u8,

    /// Number of probes per hop.
    probes_per_hop: u8,

    /// Timeout for each probe.
    probe_timeout: Duration,

    /// Minimum time between probes.
    min_wait: Duration,

    /// Maximum time between probes.
    max_wait: Duration,

    /// Initial TTL value.
    initial_ttl: u8,

    /// Source port to use (0 for automatic).
    source_port: u16,

    /// Destination port (protocol-dependent).
    dest_port: u16,

    /// Resolve hostnames for hops.
    resolve_hostnames: bool,

    /// Probe type to use.
    probe_type: ProbeType,
}

/// Result of a traceroute operation.
#[derive(Debug, Clone)]
pub struct TracerouteResult {
    /// Target address that was traced.
    target: Ipv4Addr,

    /// List of hops discovered.
    hops: Vec<HopInfo>,

    /// Path MTU if discovered.
    path_mtu: Option<PathMtu>,

    /// Whether the destination was reached.
    completed: bool,

    /// Total duration of the trace.
    duration: Duration,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            max_hops: 30,
            probes_per_hop: 3,
            probe_timeout: Duration::from_millis(1000),
            min_wait: Duration::from_millis(0),
            max_wait: Duration::from_millis(0),
            initial_ttl: 1,
            source_port: 0,
            dest_port: 33434,
            resolve_hostnames: false,
            probe_type: ProbeType::Udp,
        }
    }
}

impl TracerouteConfig {
    /// Creates a new default traceroute configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_hops: 30,
            probes_per_hop: 3,
            probe_timeout: Duration::from_millis(1000),
            min_wait: Duration::from_millis(0),
            max_wait: Duration::from_millis(0),
            initial_ttl: 1,
            source_port: 0,
            dest_port: 33434,
            resolve_hostnames: false,
            probe_type: ProbeType::Udp,
        }
    }

    /// Sets the maximum number of hops to trace.
    #[must_use]
    pub const fn with_max_hops(mut self, max_hops: u8) -> Self {
        self.max_hops = max_hops;
        self
    }

    /// Sets the number of probes per hop.
    #[must_use]
    pub const fn with_probes_per_hop(mut self, probes: u8) -> Self {
        self.probes_per_hop = probes;
        self
    }

    /// Sets the timeout for each probe.
    #[must_use]
    pub const fn with_probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// Sets the probe type.
    #[must_use]
    pub const fn with_probe_type(mut self, probe_type: ProbeType) -> Self {
        self.probe_type = probe_type;
        self
    }

    /// Sets the destination port.
    #[must_use]
    pub const fn with_dest_port(mut self, port: u16) -> Self {
        self.dest_port = port;
        self
    }

    /// Enable hostname resolution.
    #[must_use]
    pub const fn with_resolve_hostnames(mut self, resolve: bool) -> Self {
        self.resolve_hostnames = resolve;
        self
    }

    /// Returns the probe type.
    #[must_use]
    pub const fn probe_type(&self) -> ProbeType {
        self.probe_type
    }

    /// Returns the destination port.
    #[must_use]
    pub const fn dest_port(&self) -> u16 {
        self.dest_port
    }

    /// Returns the probe timeout.
    #[must_use]
    pub const fn probe_timeout(&self) -> Duration {
        self.probe_timeout
    }

    /// Returns the number of probes per hop.
    #[must_use]
    pub const fn probes_per_hop(&self) -> u8 {
        self.probes_per_hop
    }

    /// Returns the maximum number of hops.
    #[must_use]
    pub const fn max_hops(&self) -> u8 {
        self.max_hops
    }

    /// Returns the initial TTL.
    #[must_use]
    pub const fn initial_ttl(&self) -> u8 {
        self.initial_ttl
    }

    /// Returns whether hostname resolution is enabled.
    #[must_use]
    pub const fn resolve_hostnames(&self) -> bool {
        self.resolve_hostnames
    }

    /// Returns the source port (0 for automatic).
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }

    /// Sets the source port (0 for automatic).
    #[must_use]
    pub const fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = port;
        self
    }
}

impl Traceroute {
    /// Creates a new traceroute instance with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Traceroute configuration
    /// * `local_addr` - Local IP address to use for sending probes
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(config: TracerouteConfig, local_addr: Ipv4Addr) -> Result<Self> {
        if config.max_hops == 0 {
            return Err(TracerouteError::InvalidConfig {
                reason: "max_hops must be > 0".to_string(),
            });
        }
        if config.probes_per_hop == 0 {
            return Err(TracerouteError::InvalidConfig {
                reason: "probes_per_hop must be > 0".to_string(),
            });
        }

        Ok(Self { config, local_addr })
    }

    /// Creates a traceroute with default configuration.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for sending probes
    #[must_use]
    pub const fn with_default_config(local_addr: Ipv4Addr) -> Self {
        Self {
            config: TracerouteConfig::new(),
            local_addr,
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &TracerouteConfig {
        &self.config
    }

    /// Returns the local address.
    #[must_use]
    pub const fn local_addr(&self) -> Ipv4Addr {
        self.local_addr
    }

    /// Traces the route to the given target.
    ///
    /// This is the main entry point for traceroute operations. The method
    /// sends probes with incrementally increasing TTL values until
    /// the destination is reached or `max_hops` is exceeded.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Raw socket cannot be created (insufficient permissions)
    /// - Probe send/receive fails
    /// - Target is unreachable
    pub async fn trace(&self, target: Ipv4Addr) -> Result<TracerouteResult> {
        let start = std::time::Instant::now();
        let mut hops = Vec::new();
        let mut completed = false;

        for ttl in self.config.initial_ttl..=self.config.max_hops {
            let hop = self.probe_hop(target, ttl).await?;

            // Check if we reached the destination
            if let Some(ip) = hop.ip() {
                if ip == target {
                    completed = true;
                }
            }

            hops.push(hop);

            if completed {
                break;
            }
        }

        let duration = start.elapsed();

        Ok(TracerouteResult {
            target,
            hops,
            path_mtu: None,
            completed,
            duration,
        })
    }

    /// Sends probes for a single hop (TTL value).
    async fn probe_hop(&self, target: Ipv4Addr, ttl: u8) -> Result<HopInfo> {
        let mut rtts = Vec::with_capacity(self.config.probes_per_hop as usize);
        let mut last_ip: Option<Ipv4Addr> = None;
        let last_hostname: Option<String> = None;
        let mut probes_sent = 0;
        let mut probes_received = 0;

        for probe_num in 0..self.config.probes_per_hop {
            let probe_start = std::time::Instant::now();

            match self.send_probe(target, ttl).await {
                Ok(Some(response)) => {
                    let rtt = probe_start.elapsed();
                    rtts.push(rtt);
                    last_ip = Some(response.ip());
                    probes_received += 1;
                }
                Ok(None) => {
                    // Timeout - no response
                }
                Err(e) => {
                    // Log error but continue with other probes
                    tracing::debug!("Probe error at TTL {}: {}", ttl, e);
                }
            }

            probes_sent += 1;

            // Wait between probes if not the last one
            if probe_num + 1 < self.config.probes_per_hop {
                let wait = if self.config.max_wait > self.config.min_wait {
                    let mut rng = rand::thread_rng();
                    let diff = u64::try_from(
                        self.config.max_wait.as_millis() - self.config.min_wait.as_millis(),
                    )?;
                    self.config.min_wait + Duration::from_millis(rng.gen_range(0..=diff))
                } else {
                    self.config.min_wait
                };
                sleep(wait).await;
            }
        }

        // Calculate packet loss
        #[allow(
            clippy::cast_precision_loss,
            reason = "f32 has limited mantissa, precision loss acceptable for packet loss calculations"
        )]
        let loss = if probes_sent > 0 {
            1.0 - (probes_received as f32 / probes_sent as f32)
        } else {
            1.0
        };

        Ok(HopInfo::new(ttl, last_ip, last_hostname, rtts, loss))
    }

    /// Sends a single probe packet using the configured probe type.
    ///
    /// # Arguments
    ///
    /// * `target` - Target IP address
    /// * `ttl` - Time-to-live value for this probe
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(ProbeResponse))` if a response was received,
    /// `Ok(None)` if the probe timed out, or an error if sending failed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Raw socket cannot be created (insufficient permissions)
    /// - Probe send/receive fails
    async fn send_probe(&self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        // Use tokio::task::spawn_blocking for the blocking socket operations
        let config = self.config.clone();
        let local_addr = self.local_addr;

        tokio::task::spawn_blocking(move || match config.probe_type {
            ProbeType::Udp => {
                let mut tracer = UdpTraceroute::new(config, local_addr)?;
                tracer.send_probe(target, ttl)
            }
            ProbeType::TcpSyn => {
                let dest_port = config.dest_port;
                let mut tracer = TcpSynTraceroute::new(config, local_addr)?;
                tracer.send_probe(target, ttl, dest_port)
            }
            ProbeType::TcpAck => {
                let dest_port = config.dest_port;
                let mut tracer = TcpAckTraceroute::new(config, local_addr)?;
                tracer.send_probe(target, ttl, dest_port)
            }
            ProbeType::Icmp => {
                let mut tracer = IcmpTraceroute::new(config, local_addr)?;
                tracer.send_probe(target, ttl)
            }
        })
        .await
        .map_err(|e| TracerouteError::Other(format!("Task join error: {e}")))?
    }
}

impl TracerouteResult {
    /// Returns the target address.
    #[must_use]
    pub const fn target(&self) -> Ipv4Addr {
        self.target
    }

    /// Returns the list of discovered hops.
    #[must_use]
    pub fn hops(&self) -> &[HopInfo] {
        &self.hops
    }

    /// Returns the number of hops discovered.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Returns the path MTU if discovered.
    #[must_use]
    pub const fn path_mtu(&self) -> Option<&PathMtu> {
        self.path_mtu.as_ref()
    }

    /// Returns whether the trace completed (reached destination).
    #[must_use]
    pub const fn completed(&self) -> bool {
        self.completed
    }

    /// Returns the total duration of the trace.
    #[must_use]
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Formats the result as a string (human-readable).
    #[must_use]
    pub fn format(&self) -> String {
        use std::fmt::Write;

        let mut output = String::new();
        writeln!(
            output,
            "traceroute to {}, {} hops max",
            self.target,
            self.hops.len()
        )
        .unwrap();

        for hop in &self.hops {
            let ip = hop
                .ip()
                .map_or_else(|| "*".to_string(), |ip| ip.to_string());
            let _ = write!(output, "  {:2}  {}", hop.ttl(), ip);

            if let Some(avg_rtt) = hop.avg_rtt() {
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "f64 has limited mantissa, precision loss acceptable for RTT calculations"
                )]
                let _ = write!(output, " {:.2} ms", avg_rtt.as_micros() as f64 / 1000.0);
            }

            if let Some(hostname) = hop.hostname() {
                let _ = write!(output, " ({hostname})");
            }
            let _ = writeln!(output);
        }

        if self.completed {
            #[allow(
                clippy::cast_precision_loss,
                reason = "f64 has limited mantissa, precision loss acceptable for duration calculations"
            )]
            let duration_ms = self.duration.as_micros() as f64 / 1000.0;
            writeln!(output, "\nReached destination in {duration_ms:.2} ms",).unwrap();
        }

        output
    }
}

impl std::fmt::Display for TracerouteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TracerouteConfig::new();
        assert_eq!(config.max_hops, 30);
        assert_eq!(config.probes_per_hop, 3);
    }

    #[test]
    fn test_config_builder() {
        let config = TracerouteConfig::new()
            .with_max_hops(20)
            .with_probes_per_hop(5)
            .with_probe_type(ProbeType::Icmp);

        assert_eq!(config.max_hops, 20);
        assert_eq!(config.probes_per_hop, 5);
        assert_eq!(config.probe_type, ProbeType::Icmp);
    }

    #[test]
    fn test_traceroute_new() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;
        let tracer = Traceroute::new(config, local_addr);
        tracer.unwrap();
    }

    #[test]
    fn test_traceroute_invalid_max_hops() {
        let config = TracerouteConfig::new().with_max_hops(0);
        let local_addr = Ipv4Addr::LOCALHOST;
        let tracer = Traceroute::new(config, local_addr);
        tracer.unwrap_err();
    }

    #[test]
    fn test_traceroute_invalid_probes_per_hop() {
        let config = TracerouteConfig::new().with_probes_per_hop(0);
        let local_addr = Ipv4Addr::LOCALHOST;
        let tracer = Traceroute::new(config, local_addr);
        tracer.unwrap_err();
    }

    #[test]
    fn test_hop_info_new() {
        let hop = HopInfo::new(1, None, None, vec![], 0.0);
        assert_eq!(hop.ttl(), 1);
        assert!(hop.ip().is_none());
        assert!(hop.avg_rtt().is_none());
    }

    #[test]
    fn test_hop_info_with_ip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let hop = HopInfo::new(1, Some(ip), None, vec![], 0.0);
        assert_eq!(hop.ttl(), 1);
        assert_eq!(hop.ip(), Some(ip));
        assert!(hop.responded());
    }

    #[test]
    fn test_hop_info_with_rtts() {
        let rtts = vec![
            Duration::from_millis(10),
            Duration::from_millis(12),
            Duration::from_millis(11),
        ];
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let hop = HopInfo::new(1, Some(ip), None, rtts.clone(), 0.0);

        assert_eq!(hop.ttl(), 1);
        assert_eq!(hop.ip(), Some(ip));
        assert_eq!(hop.probe_count(), 3);
        assert!(hop.avg_rtt().is_some());
    }

    #[test]
    fn test_hop_info_avg_rtt_empty() {
        let hop = HopInfo::new(1, None, None, vec![], 0.0);
        assert!(hop.avg_rtt().is_none());
    }

    #[test]
    #[allow(clippy::float_cmp, reason = "comparing exact f32 values set in test")]
    fn test_hop_info_loss() {
        let hop = HopInfo::new(1, Some(Ipv4Addr::new(192, 168, 1, 1)), None, vec![], 0.5);
        assert_eq!(hop.loss(), 0.5);
    }

    #[test]
    fn test_path_mtu_new() {
        let mtu = PathMtu::new(1500, 5);
        assert_eq!(mtu.value(), 1500);
        assert_eq!(mtu.ttl(), 5);
    }

    #[test]
    fn test_probe_type_display() {
        assert_eq!(format!("{}", ProbeType::Udp), "UDP");
        assert_eq!(format!("{}", ProbeType::TcpSyn), "TCP-SYN");
        assert_eq!(format!("{}", ProbeType::TcpAck), "TCP-ACK");
        assert_eq!(format!("{}", ProbeType::Icmp), "ICMP");
    }

    #[test]
    fn test_config_accessors() {
        let config = TracerouteConfig::new()
            .with_max_hops(25)
            .with_probes_per_hop(5)
            .with_dest_port(80)
            .with_probe_type(ProbeType::TcpSyn)
            .with_resolve_hostnames(true);

        assert_eq!(config.max_hops(), 25);
        assert_eq!(config.probes_per_hop(), 5);
        assert_eq!(config.dest_port(), 80);
        assert_eq!(config.probe_type(), ProbeType::TcpSyn);
        assert!(config.resolve_hostnames());
    }
}
