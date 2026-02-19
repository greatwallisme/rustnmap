//! `RustNmap` SDK - High-level Rust API for network scanning
//!
//! This crate provides a fluent Builder pattern API for programmatically
//! using `RustNmap`'s scanning capabilities in your Rust applications.
//!
//! # Example
//!
//! ```rust,no_run
//! use rustnmap_sdk::{Scanner, ScanOutput};
//! use anyhow::Result;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create scanner
//!     let scanner = Scanner::new()?;
//!
//!     // Run a scan
//!     let result = scanner
//!         .targets(["192.168.1.0/24"])
//!         .ports("1-1000")
//!         .syn_scan()
//!         .service_detection(true)
//!         .run()
//!         .await?;
//!
//!     // Process results
//!     for host in &result.hosts {
//!         println!("{}: {} open ports", host.ip, host.ports.len());
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod builder;
pub mod error;
pub mod models;
pub mod profile;
pub mod remote;

pub use builder::{Scanner, ScannerBuilder};
pub use error::{ScanError, ScanResult};
pub use models::{HostResult, PortResult, ScanOutput, ScanStatus, ServiceInfo};
pub use profile::ScanProfile;
pub use remote::{ApiConfig, RemoteScanner};
