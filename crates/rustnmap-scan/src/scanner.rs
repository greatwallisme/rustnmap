//! Port scanner trait and common scanning functionality.
//!
//! This module defines the [`PortScanner`] trait that all scanning implementations
//! must use, along with common scanning configuration types.

use async_trait::async_trait;
use rustnmap_common::{Port, PortState, Protocol, ScanError};
use rustnmap_target::Target;

/// Result type for scanning operations.
pub type ScanResult<T> = Result<T, ScanError>;

/// Trait defining the interface for port scanners.
///
/// All scanning implementations (TCP SYN, TCP Connect, UDP, etc.) must
/// implement this trait to provide a consistent interface.
///
/// # Migration Notes
///
/// The async version of this trait (`AsyncPortScanner`) is preferred for new
/// implementations and for scanners that need to use async packet capture.
/// The sync version is retained for backward compatibility.
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

/// Async version of the [`PortScanner`] trait for scanners using async I/O.
///
/// This trait is intended for scanners that use async packet capture
/// (e.g., `ScannerPacketEngine` with `PACKET_MMAP` V2).
///
/// # Migration Path
///
/// Scanners can implement both `PortScanner` (sync) and `AsyncPortScanner` (async):
/// - The sync version can use `tokio::task::spawn_blocking` for compatibility
/// - The async version provides true async I/O for better performance
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_scan::scanner::AsyncPortScanner;
/// use rustnmap_target::Target;
///
/// # async fn example(scanner: UdpScanner, target: Target) -> Result<(), Box<dyn std::error::Error>> {
/// let state = scanner.scan_port_async(&target, 80, Protocol::UDP).await?;
/// # Ok(())
/// # }
/// ```
#[async_trait]
pub trait AsyncPortScanner: Send + Sync {
    /// Asynchronously scans a single port on a target.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be performed due to network
    /// issues or permissions.
    async fn scan_port_async(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState>;

    /// Returns true if this scanner requires root privileges.
    #[must_use]
    fn requires_root(&self) -> bool {
        false
    }
}

// Re-export from rustnmap_common for backward compatibility
pub use rustnmap_common::TimingTemplate;
