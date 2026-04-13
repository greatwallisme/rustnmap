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

//! Port scanning implementations for `RustNmap`.
//!
//! This crate provides the core scanning functionality including TCP SYN scan,
//! TCP Connect scan, UDP scan, IP Protocol scan, and stealth scan implementations
//! (FIN, NULL, Xmas, ACK, Maimon, Window, Idle).

#![warn(missing_docs)]

pub mod adaptive_delay;
pub mod congestion;
pub mod connect_scan;
pub mod ftp_bounce_scan;
pub mod icmp_handler;
pub mod idle_scan;
pub mod ip_protocol_scan;
pub mod packet_adapter;
pub mod probe;
pub mod scanner;
pub mod stealth_scans;
pub mod syn_scan;
pub mod timeout;
pub mod udp_payload;
pub mod udp_scan;
pub mod ultrascan;

// Re-exports
pub use adaptive_delay::AdaptiveDelay;
pub use congestion::CongestionControl;
pub use connect_scan::TcpConnectScanner;
pub use ftp_bounce_scan::FtpBounceScanner;
pub use icmp_handler::{classify_icmp_error, IcmpAction};
pub use idle_scan::IdleScanner;
pub use ip_protocol_scan::IpProtocolScanner;
pub use packet_adapter::ScannerPacketEngine;
pub use scanner::{PortScanner, ScanResult, TimingTemplate};
pub use stealth_scans::{
    TcpAckScanner, TcpFinScanner, TcpMaimonScanner, TcpNullScanner, TcpWindowScanner,
    TcpXmasScanner,
};
pub use syn_scan::TcpSynScanner;
pub use timeout::TimeoutTracker;
pub use udp_scan::UdpScanner;
pub use ultrascan::ParallelScanEngine;

// Re-export ScanConfig and ScanError from rustnmap_common
pub use rustnmap_common::{ScanConfig, ScanError};
