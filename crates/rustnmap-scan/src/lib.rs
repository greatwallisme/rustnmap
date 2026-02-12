//! Port scanning implementations for `RustNmap`.
//!
//! This crate provides the core scanning functionality including TCP SYN scan,
//! TCP Connect scan, and UDP scan implementations.

#![warn(missing_docs)]
// Transitive dependency version conflicts are unavoidable in large workspaces
#![allow(
    clippy::multiple_crate_versions,
    reason = "Third-party dependency version conflicts cannot be resolved"
)]

pub mod connect_scan;
pub mod probe;
pub mod scanner;
pub mod syn_scan;
pub mod timeout;

// Re-exports
pub use connect_scan::TcpConnectScanner;
pub use scanner::{PortScanner, ScanConfig, ScanError, TimingTemplate};
pub use syn_scan::TcpSynScanner;
pub use timeout::TimeoutTracker;
