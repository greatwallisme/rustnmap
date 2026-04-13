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

//! Scan state management for tracking host and port states.
//!
//! This module provides the `ScanState` struct for tracking the progress
//! and results of scanning operations, including host states, port states,
//! and overall scan progress.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustnmap_output::models::HostStatus;

/// Port scan status enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortScanStatus {
    /// Unknown state (initial).
    #[default]
    Unknown,
    /// Port is open.
    Open,
    /// Port is closed.
    Closed,
    /// Port is filtered.
    Filtered,
    /// Port is unfiltered.
    Unfiltered,
    /// Port is open or filtered.
    OpenOrFiltered,
    /// Port is closed or filtered.
    ClosedOrFiltered,
}

/// Scan progress tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    /// Total number of targets to scan.
    pub total_targets: u64,
    /// Number of targets completed.
    pub completed_targets: u64,
    /// Number of targets currently being scanned.
    pub active_targets: u64,
    /// Number of targets pending.
    pub pending_targets: u64,
    /// Current scan phase.
    pub current_phase: String,
    /// Scan start time.
    pub start_time: Option<Instant>,
    /// Estimated time remaining.
    pub eta: Option<Duration>,
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self {
            total_targets: 0,
            completed_targets: 0,
            active_targets: 0,
            pending_targets: 0,
            current_phase: "initializing".to_string(),
            start_time: None,
            eta: None,
        }
    }
}

impl ScanProgress {
    /// Creates a new scan progress tracker.
    #[must_use]
    pub fn new(total_targets: u64) -> Self {
        Self {
            total_targets,
            pending_targets: total_targets,
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Records that a target has started scanning.
    pub fn target_started(&mut self) {
        self.pending_targets = self.pending_targets.saturating_sub(1);
        self.active_targets += 1;
    }

    /// Records that a target has completed scanning.
    pub fn target_completed(&mut self) {
        self.active_targets = self.active_targets.saturating_sub(1);
        self.completed_targets += 1;
        self.update_eta();
    }

    /// Updates the current phase.
    pub fn set_phase(&mut self, phase: impl Into<String>) {
        self.current_phase = phase.into();
    }

    /// Updates the estimated time remaining.
    fn update_eta(&mut self) {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed();
            if self.completed_targets > 0 {
                let avg_time_per_target =
                    elapsed / u32::try_from(self.completed_targets).unwrap_or(1);
                let remaining = self.total_targets - self.completed_targets;
                self.eta = Some(avg_time_per_target * u32::try_from(remaining).unwrap_or(0));
            }
        }
    }

    /// Returns the completion percentage (0-100).
    ///
    /// Returns 0 if `total_targets` is 0 to avoid division by zero.
    /// The returned value is clamped to 100 in case of overflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_core::state::ScanProgress;
    ///
    /// let progress = ScanProgress::new(100);
    /// assert_eq!(progress.completion_percentage(), 0);
    /// ```
    #[must_use]
    pub fn completion_percentage(&self) -> u8 {
        if self.total_targets == 0 {
            return 0;
        }
        u8::try_from((self.completed_targets * 100) / self.total_targets).unwrap_or(100)
    }

    /// Returns true if the scan is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completed_targets >= self.total_targets
    }
}

/// State for a single host during scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostState {
    /// IP address of the host.
    pub ip: IpAddr,
    /// Current host status.
    pub status: HostStatus,
    /// Reason for the status determination.
    pub status_reason: String,
    /// Discovery method used.
    pub discovery_method: Option<String>,
    /// Round-trip time to the host.
    pub rtt: Option<Duration>,
    /// Number of retry attempts.
    pub retry_count: u32,
    /// Time when host scanning started.
    pub scan_start: Option<Instant>,
    /// Time when host scanning completed.
    pub scan_end: Option<Instant>,
    /// OS fingerprint match (if detected).
    pub os_match: Option<String>,
    /// MAC address (if available).
    pub mac_address: Option<String>,
    /// Vendor name (if available).
    pub vendor: Option<String>,
}

impl HostState {
    /// Creates a new host state for the given IP.
    #[must_use]
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            status: HostStatus::Unknown,
            status_reason: String::new(),
            discovery_method: None,
            rtt: None,
            retry_count: 0,
            scan_start: None,
            scan_end: None,
            os_match: None,
            mac_address: None,
            vendor: None,
        }
    }

    /// Records the start of host scanning.
    pub fn mark_scan_started(&mut self) {
        self.scan_start = Some(Instant::now());
    }

    /// Records the completion of host scanning.
    pub fn mark_scan_completed(&mut self) {
        self.scan_end = Some(Instant::now());
    }

    /// Increments the retry count.
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    /// Returns the scan duration if completed.
    #[must_use]
    pub fn scan_duration(&self) -> Option<Duration> {
        match (self.scan_start, self.scan_end) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            (Some(start), None) => Some(start.elapsed()),
            _ => None,
        }
    }
}

impl Default for HostState {
    fn default() -> Self {
        Self::new(IpAddr::from([0, 0, 0, 0]))
    }
}

/// State for a single port during scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortScanState {
    /// Current port state.
    pub state: PortScanStatus,
    /// Reason for the state determination.
    pub reason: PortReason,
    /// TTL from response packet.
    pub ttl: Option<u8>,
    /// Window size from response (for TCP).
    pub window_size: Option<u16>,
    /// Number of probe attempts.
    pub probe_count: u32,
    /// Time when port scanning started.
    pub scan_start: Option<Instant>,
    /// Time when port scanning completed.
    pub scan_end: Option<Instant>,
    /// Service information (if detected).
    pub service_detected: bool,
}

impl Default for PortScanState {
    fn default() -> Self {
        Self {
            state: PortScanStatus::Unknown,
            reason: PortReason::None,
            ttl: None,
            window_size: None,
            probe_count: 0,
            scan_start: None,
            scan_end: None,
            service_detected: false,
        }
    }
}

impl PortScanState {
    /// Creates a new port scan state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: PortScanStatus::Unknown,
            reason: PortReason::None,
            ttl: None,
            window_size: None,
            probe_count: 0,
            scan_start: None,
            scan_end: None,
            service_detected: false,
        }
    }

    /// Records the start of port scanning.
    pub fn mark_scan_started(&mut self) {
        self.scan_start = Some(Instant::now());
    }

    /// Records the completion of port scanning.
    pub fn mark_scan_completed(&mut self) {
        self.scan_end = Some(Instant::now());
    }

    /// Increments the probe count.
    pub fn increment_probe(&mut self) {
        self.probe_count += 1;
    }

    /// Sets the port state with a reason.
    pub fn set_state(&mut self, state: PortScanStatus, reason: PortReason) {
        self.state = state;
        self.reason = reason;
    }

    /// Returns the scan duration if available.
    #[must_use]
    pub fn scan_duration(&self) -> Option<Duration> {
        match (self.scan_start, self.scan_end) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            (Some(start), None) => Some(start.elapsed()),
            _ => None,
        }
    }
}

/// Reason for port state determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortReason {
    /// No reason set.
    #[default]
    None,
    /// SYN-ACK received (port open).
    SynAck,
    /// RST received (port closed).
    Rst,
    /// RST-ACK received.
    RstAck,
    /// ICMP unreachable received.
    IcmpUnreachable,
    /// ICMP host unreachable.
    IcmpHostUnreachable,
    /// ICMP port unreachable.
    IcmpPortUnreachable,
    /// ICMP admin prohibited.
    IcmpAdminProhibited,
    /// Timeout (no response).
    Timeout,
    /// Connection refused.
    ConnRefused,
    /// Connection reset.
    ConnReset,
    /// Protocol unreachable.
    ProtoUnreachable,
    /// No route to host.
    NoRoute,
    /// ARP response received.
    ArpResponse,
    /// ND response received.
    NdResponse,
    /// Response received (generic).
    Response,
    /// User request.
    UserRequest,
    /// Other reason.
    Other,
}

impl std::fmt::Display for PortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::SynAck => write!(f, "syn-ack"),
            Self::Rst => write!(f, "reset"),
            Self::RstAck => write!(f, "rst-ack"),
            Self::IcmpUnreachable => write!(f, "icmp-unreachable"),
            Self::IcmpHostUnreachable => write!(f, "icmp-host-unreachable"),
            Self::IcmpPortUnreachable => write!(f, "icmp-port-unreachable"),
            Self::IcmpAdminProhibited => write!(f, "icmp-admin-prohibited"),
            Self::Timeout => write!(f, "timeout"),
            Self::ConnRefused => write!(f, "conn-refused"),
            Self::ConnReset => write!(f, "conn-reset"),
            Self::ProtoUnreachable => write!(f, "proto-unreachable"),
            Self::NoRoute => write!(f, "no-route"),
            Self::ArpResponse => write!(f, "arp-response"),
            Self::NdResponse => write!(f, "nd-response"),
            Self::Response => write!(f, "response"),
            Self::UserRequest => write!(f, "user-request"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Global scan state manager.
#[derive(Debug)]
pub struct GlobalScanState {
    /// Host states by IP address.
    hosts: HashMap<IpAddr, HostState>,
    /// Port states by (IP, port).
    ports: HashMap<(IpAddr, u16), PortScanState>,
    /// Scan progress.
    progress: ScanProgress,
    /// Total packets sent.
    packets_sent: AtomicU64,
    /// Total packets received.
    packets_received: AtomicU64,
    /// Scan start time.
    start_time: Instant,
}

impl GlobalScanState {
    /// Creates a new global scan state.
    #[must_use]
    pub fn new(total_targets: u64) -> Self {
        Self {
            hosts: HashMap::new(),
            ports: HashMap::new(),
            progress: ScanProgress::new(total_targets),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Gets or creates a host state.
    pub fn host_state(&mut self, ip: IpAddr) -> &mut HostState {
        self.hosts.entry(ip).or_insert_with(|| HostState::new(ip))
    }

    /// Gets a host state if it exists.
    #[must_use]
    pub fn get_host_state(&self, ip: IpAddr) -> Option<&HostState> {
        self.hosts.get(&ip)
    }

    /// Gets or creates a port state.
    pub fn port_state(&mut self, ip: IpAddr, port: u16) -> &mut PortScanState {
        self.ports.entry((ip, port)).or_default()
    }

    /// Gets a port state if it exists.
    #[must_use]
    pub fn get_port_state(&self, ip: IpAddr, port: u16) -> Option<&PortScanState> {
        self.ports.get(&(ip, port))
    }

    /// Returns the scan progress.
    #[must_use]
    pub const fn progress(&self) -> &ScanProgress {
        &self.progress
    }

    /// Returns a mutable reference to scan progress.
    pub fn progress_mut(&mut self) -> &mut ScanProgress {
        &mut self.progress
    }

    /// Records that a packet was sent.
    pub fn record_packet_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a packet was received.
    pub fn record_packet_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total packets sent.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Returns the total packets received.
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Returns the elapsed time since scan start.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Returns the number of hosts.
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Returns the number of ports.
    #[must_use]
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Returns all host states.
    #[must_use]
    pub fn hosts(&self) -> &HashMap<IpAddr, HostState> {
        &self.hosts
    }

    /// Returns all port states.
    #[must_use]
    pub fn ports(&self) -> &HashMap<(IpAddr, u16), PortScanState> {
        &self.ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_common::Ipv4Addr;

    // Re-export PortScanStatus for tests
    use super::PortScanStatus as PortState;

    #[test]
    fn test_scan_progress_new() {
        let progress = ScanProgress::new(100);
        assert_eq!(progress.total_targets, 100);
        assert_eq!(progress.pending_targets, 100);
        assert_eq!(progress.completion_percentage(), 0);
    }

    #[test]
    fn test_scan_progress_target_completion() {
        let mut progress = ScanProgress::new(100);
        progress.target_started();
        assert_eq!(progress.active_targets, 1);
        assert_eq!(progress.pending_targets, 99);

        progress.target_completed();
        assert_eq!(progress.active_targets, 0);
        assert_eq!(progress.completed_targets, 1);
    }

    #[test]
    fn test_scan_progress_percentage() {
        let mut progress = ScanProgress::new(100);
        progress.completed_targets = 50;
        assert_eq!(progress.completion_percentage(), 50);

        progress.completed_targets = 100;
        assert_eq!(progress.completion_percentage(), 100);
        assert!(progress.is_complete());
    }

    #[test]
    fn test_host_state_new() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let state = HostState::new(ip);
        assert_eq!(state.ip, ip);
        assert_eq!(state.status, HostStatus::Unknown);
        assert_eq!(state.retry_count, 0);
    }

    #[test]
    fn test_host_state_scan_timing() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut state = HostState::new(ip);

        state.mark_scan_started();
        assert!(state.scan_start.is_some());
        assert!(state.scan_end.is_none());

        state.mark_scan_completed();
        assert!(state.scan_end.is_some());
        assert!(state.scan_duration().is_some());
    }

    #[test]
    fn test_port_scan_state() {
        let mut state = PortScanState::new();
        assert_eq!(state.state, PortState::Unknown);
        assert_eq!(state.reason, PortReason::None);

        state.set_state(PortState::Open, PortReason::SynAck);
        assert_eq!(state.state, PortState::Open);
        assert_eq!(state.reason, PortReason::SynAck);

        state.increment_probe();
        assert_eq!(state.probe_count, 1);
    }

    #[test]
    fn test_port_reason_display() {
        assert_eq!(PortReason::SynAck.to_string(), "syn-ack");
        assert_eq!(PortReason::Timeout.to_string(), "timeout");
        assert_eq!(
            PortReason::IcmpPortUnreachable.to_string(),
            "icmp-port-unreachable"
        );
    }

    #[test]
    fn test_global_scan_state() {
        let mut state = GlobalScanState::new(10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let host = state.host_state(ip);
        host.status = HostStatus::Up;

        let port = state.port_state(ip, 80);
        port.state = PortState::Open;

        assert_eq!(state.host_count(), 1);
        assert_eq!(state.port_count(), 1);

        let retrieved_host = state.get_host_state(ip).unwrap();
        assert_eq!(retrieved_host.status, HostStatus::Up);

        let retrieved_port = state.get_port_state(ip, 80).unwrap();
        assert_eq!(retrieved_port.state, PortState::Open);
    }

    #[test]
    fn test_global_scan_state_packets() {
        let state = GlobalScanState::new(10);
        state.record_packet_sent();
        state.record_packet_sent();
        state.record_packet_received();

        assert_eq!(state.packets_sent(), 2);
        assert_eq!(state.packets_received(), 1);
    }
}
