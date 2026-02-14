//! Port scanning implementations for `RustNmap`.
//!
//! This crate provides the core scanning functionality including TCP SYN scan,
//! TCP Connect scan, UDP scan, and stealth scan implementations (FIN, NULL, Xmas, ACK, Maimon).

#![warn(missing_docs)]
// Transitive dependency version conflicts are unavoidable in large workspaces
#![allow(
    clippy::multiple_crate_versions,
    reason = "Third-party dependency version conflicts cannot be resolved"
)]

pub mod connect_scan;
pub mod probe;
pub mod scanner;
pub mod stealth_scans;
pub mod syn_scan;
pub mod timeout;
pub mod udp_scan;

// Re-exports
pub use connect_scan::TcpConnectScanner;
pub use scanner::{PortScanner, ScanResult, TimingTemplate};
pub use stealth_scans::{
    TcpAckScanner, TcpFinScanner, TcpMaimonScanner, TcpNullScanner, TcpXmasScanner,
};
pub use syn_scan::TcpSynScanner;
pub use timeout::TimeoutTracker;
pub use udp_scan::UdpScanner;

// Re-export ScanConfig and ScanError from rustnmap_common
pub use rustnmap_common::{ScanConfig, ScanError};
