//! Core scan orchestrator for `RustNmap`.
//!
//! This crate provides the central coordination layer for all scanning operations,
//! managing the flow from host discovery through port scanning, service detection,
//! OS fingerprinting, and NSE script execution.
//!
//! # Architecture
//!
//! The core orchestrator follows a pipeline architecture:
//!
//! ```text
//! Target Parsing -> Host Discovery -> Port Scanning -> Service Detection
//!                                                        |
//!                                                        v
//! NSE Scripts <- OS Fingerprinting <- Result Aggregation
//! ```
//!
//! # Key Components
//!
//! - [`ScanSession`]: The central context holding all scan state and dependencies
//! - [`ScanOrchestrator`]: Coordinates the execution of all scan phases
//! - [`TaskScheduler`]: Manages concurrent execution of scan tasks
//! - [`ScanState`]: Tracks the state of individual hosts and ports during scanning
//!
//! # Example
//!
//! ```no_run
//! use rustnmap_core::{ScanSession, ScanOrchestrator, ScanConfig};
//! use rustnmap_target::TargetParser;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//!
//! // Parse targets
//! let parser = TargetParser::new();
//! let targets = parser.parse("192.168.1.0/24")?;
//!
//! // Create scan configuration
//! let config = ScanConfig::default();
//!
//! // Create scan session
//! let session = ScanSession::new(config, targets)?;
//!
//! // Create and run orchestrator
//! let orchestrator = ScanOrchestrator::new(Arc::new(session));
//! let results = orchestrator.run().await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![allow(
    clippy::allow_attributes_without_reason,
    reason = "Allow attributes are used extensively for incremental development"
)]

pub mod error;
pub mod orchestrator;
pub mod scheduler;
pub mod session;
pub mod state;

// Re-exports for convenience
pub use error::{CoreError, Result};
pub use orchestrator::{ScanOrchestrator, ScanPhase, ScanPipeline};
pub use scheduler::{ScheduledTask, TaskPriority, TaskScheduler};
pub use session::{OutputSink, PacketEngine, ScanConfig, ScanSession, ScanStats};
pub use state::{GlobalScanState, HostState, PortScanState, ScanProgress};

/// Version of the rustnmap-core crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of concurrent hosts to scan.
///
/// This limit prevents overwhelming the local system and target network.
pub const MAX_CONCURRENT_HOSTS: usize = 256;

/// Maximum number of concurrent ports to scan per host.
///
/// This limit balances scan speed with accuracy and resource usage.
pub const MAX_CONCURRENT_PORTS: usize = 1024;

/// Default host group size for batch processing.
///
/// Based on Nmap's default of scanning hosts in groups for efficiency.
pub const DEFAULT_HOST_GROUP_SIZE: usize = 4;

/// Minimum scan duration before progress updates are emitted.
pub const PROGRESS_UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_format() {
        // Version should be valid semver
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "Version should be in semver format");
    }

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "compile-time constant sanity check")]
    fn test_constants_are_positive() {
        assert!(MAX_CONCURRENT_HOSTS > 0);
        assert!(MAX_CONCURRENT_PORTS > 0);
        assert!(DEFAULT_HOST_GROUP_SIZE > 0);
    }
}
