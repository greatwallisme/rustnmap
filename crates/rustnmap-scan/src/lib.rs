//! Port scanning implementations for `RustNmap`.
//!
//! This crate provides the core scanning functionality including TCP SYN scan,
//! TCP Connect scan, UDP scan, IP Protocol scan, and stealth scan implementations
//! (FIN, NULL, Xmas, ACK, Maimon, Window, Idle).

#![warn(missing_docs)]

pub mod connect_scan;
pub mod ftp_bounce_scan;
pub mod idle_scan;
pub mod ip_protocol_scan;
pub mod probe;
pub mod scanner;
pub mod stealth_scans;
pub mod syn_scan;
pub mod timeout;
pub mod ultrascan;
pub mod udp_scan;

// Re-exports
pub use connect_scan::TcpConnectScanner;
pub use ftp_bounce_scan::FtpBounceScanner;
pub use idle_scan::IdleScanner;
pub use ip_protocol_scan::IpProtocolScanner;
pub use scanner::{PortScanner, ScanResult, TimingTemplate};
pub use stealth_scans::{
    TcpAckScanner, TcpFinScanner, TcpMaimonScanner, TcpNullScanner, TcpWindowScanner,
    TcpXmasScanner,
};
pub use syn_scan::TcpSynScanner;
pub use timeout::TimeoutTracker;
pub use ultrascan::ParallelScanEngine;
pub use udp_scan::UdpScanner;

// Re-export ScanConfig and ScanError from rustnmap_common
pub use rustnmap_common::{ScanConfig, ScanError};
