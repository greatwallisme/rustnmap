//! Database management for fingerprint data.
//!
//! This module provides functionality for managing, updating, and
//! querying fingerprint databases including:
//!
//! - **MAC Prefix Database**: Vendor lookup from MAC addresses
//! - **Service Database**: Port-to-service name lookups
//! - **Protocol Database**: Protocol number-to-name lookups
//! - **RPC Database**: RPC program number-to-name lookups
//! - **Database Updater**: Download and update databases from Nmap
//!
//! # Example
//!
//! ```no_run
//! use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions, MacPrefixDatabase};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Update all databases
//! let updater = DatabaseUpdater::new();
//! let result = updater.update_all("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
//! println!("Updated {} databases", result.updated_count);
//!
//! // Load and query MAC prefix database
//! let mac_db = MacPrefixDatabase::load_from_file("/var/lib/rustnmap/nmap-mac-prefixes").await?;
//! if let Some(vendor) = mac_db.lookup("00:00:0C:12:34:56") {
//!     println!("Vendor: {}", vendor);
//! }
//! # Ok(())
//! # }
//! ```

mod mac;
mod protocols;
mod rpc;
mod services;
mod updater;

pub use mac::{MacPrefixDatabase, MacVendorInfo};
pub use protocols::{ProtocolDatabase, ProtocolEntry};
pub use rpc::{RpcDatabase, RpcEntry};
pub use services::{ServiceDatabase, ServiceEntry, ServiceProtocol};
pub use updater::{CustomUrls, DatabaseUpdateDetail, DatabaseUpdater, UpdateOptions, UpdateResult};
