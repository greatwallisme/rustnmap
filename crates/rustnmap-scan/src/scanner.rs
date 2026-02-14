//! Port scanner trait and common scanning functionality.
//!
//! This module defines the [`PortScanner`] trait that all scanning implementations
//! must use, along with common scanning configuration types.

use rustnmap_common::{Port, PortState, Protocol, ScanError};
use rustnmap_target::Target;

/// Result type for scanning operations.
pub type ScanResult<T> = Result<T, ScanError>;

/// Trait defining the interface for port scanners.
///
/// All scanning implementations (TCP SYN, TCP Connect, UDP, etc.) must
/// implement this trait to provide a consistent interface.
pub trait PortScanner {
    /// Scans a single port on a target.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be performed due to network
    /// issues or permissions.
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState>;

    /// Returns true if this scanner requires root privileges.
    #[must_use]
    fn requires_root(&self) -> bool {
        false
    }
}

// Re-export from rustnmap_common for backward compatibility
pub use rustnmap_common::TimingTemplate;
