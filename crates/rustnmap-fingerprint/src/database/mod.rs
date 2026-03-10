//! Database management for fingerprint data.
//!
//! This module provides functionality for managing, updating, and
//! querying fingerprint databases including:
//!
//! - **MAC Prefix Database**: Vendor lookup from MAC addresses
//! - **Protocol Database**: Protocol number-to-name lookups
//! - **RPC Database**: RPC program number-to-name lookups
//! - **Database Updater**: Download and update databases from Nmap
//!
//! # Example
//!
//! ```
//! use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions, MacPrefixDatabase};
//! #
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Update all databases
//! let updater = DatabaseUpdater::new();
//! let result = updater.update_all("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
//! // Updated count is available in result.updated_count
//!
//! // Load and query MAC prefix database
//! let mac_db = MacPrefixDatabase::load_from_file("/var/lib/rustnmap/nmap-mac-prefixes").await?;
//! if let Some(_vendor) = mac_db.lookup("00:00:0C:12:34:56") {
//!     // Vendor name is returned
//! }
//! # Ok(())
//! # }
//! ```

//! **Note**: The ServiceDatabase has been removed from this module to avoid duplication.
//! Use `rustnmap_common::ServiceDatabase::global()` for port-to-service name lookups.

mod mac;
mod protocols;
mod rpc;
mod updater;

pub use mac::{MacPrefixDatabase, MacVendorInfo};
pub use protocols::{ProtocolDatabase, ProtocolEntry};
pub use rpc::{RpcDatabase, RpcEntry};
pub use updater::{CustomUrls, DatabaseUpdateDetail, DatabaseUpdater, UpdateOptions, UpdateResult};
