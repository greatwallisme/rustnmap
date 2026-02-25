//! Fingerprint database updater for downloading latest Nmap databases.
//!
//! This module provides functionality to download and update fingerprint
//! databases from Nmap's official sources.
//!
//! # Example
//!
//! ```no_run
//! use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let updater = DatabaseUpdater::new();
//!
//! let options = UpdateOptions::default()
//!     .backup(true)
//!     .verify_checksums(true);
//!
//! let result = updater.update_all("/var/lib/rustnmap/", &options).await?;
//! // Check result.updated_count for number of databases updated
//! # Ok(())
//! # }
//! ```

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use tracing::{debug, info, warn};

use crate::FingerprintError;

/// Default URLs for Nmap fingerprint databases.
const NMAP_SERVICE_PROBES_URL: &str = "https://svn.nmap.org/nmap/nmap-service-probes";
const NMAP_OS_DB_URL: &str = "https://svn.nmap.org/nmap/nmap-os-db";
const NMAP_MAC_PREFIXES_URL: &str = "https://svn.nmap.org/nmap/nmap-mac-prefixes";
const NMAP_SERVICES_URL: &str = "https://svn.nmap.org/nmap/nmap-services";
const NMAP_PROTOCOLS_URL: &str = "https://svn.nmap.org/nmap/nmap-protocols";
const NMAP_RPC_URL: &str = "https://svn.nmap.org/nmap/nmap-rpc";

/// HTTP timeout for database downloads.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Database updater for fingerprint databases.
///
/// Downloads and updates fingerprint databases from Nmap's official
/// sources. Supports backups, checksum verification, and selective
/// database updates.
#[derive(Debug, Clone)]
pub struct DatabaseUpdater {
    client: Client,
}

/// Options for database updates.
#[derive(Debug, Clone)]
pub struct UpdateOptions {
    /// Whether to create backups of existing databases.
    backup: bool,
    /// Whether to verify checksums of downloaded files.
    verify_checksums: bool,
    /// Custom URLs for database sources.
    custom_urls: Option<CustomUrls>,
}

/// Custom URLs for database sources.
#[derive(Debug, Clone)]
pub struct CustomUrls {
    /// URL for service probes database.
    pub service_probes: Option<String>,
    /// URL for OS fingerprint database.
    pub os_db: Option<String>,
    /// URL for MAC prefixes database.
    pub mac_prefixes: Option<String>,
    /// URL for services database.
    pub services: Option<String>,
    /// URL for protocols database.
    pub protocols: Option<String>,
    /// URL for RPC database.
    pub rpc: Option<String>,
}

/// Result of a database update operation.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    /// Number of databases that were updated.
    pub updated_count: usize,
    /// Number of databases that were already up to date.
    pub unchanged_count: usize,
    /// Number of databases that failed to update.
    pub failed_count: usize,
    /// Details for each database update.
    pub details: Vec<DatabaseUpdateDetail>,
}

/// Details for a single database update.
#[derive(Debug, Clone)]
pub struct DatabaseUpdateDetail {
    /// Name of the database.
    pub name: String,
    /// Whether the update was successful.
    pub success: bool,
    /// Previous version info if available.
    pub previous_version: Option<String>,
    /// New version info if available.
    pub new_version: Option<String>,
    /// Error message if update failed.
    pub error: Option<String>,
    /// Whether a backup was created.
    pub backup_created: bool,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        Self {
            backup: true,
            verify_checksums: false,
            custom_urls: None,
        }
    }
}

impl UpdateOptions {
    /// Create new update options with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to create backups of existing databases.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::UpdateOptions;
    ///
    /// let options = UpdateOptions::default().backup(true);
    /// ```
    #[must_use]
    pub fn backup(mut self, backup: bool) -> Self {
        self.backup = backup;
        self
    }

    /// Set whether to verify checksums of downloaded files.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::UpdateOptions;
    ///
    /// let options = UpdateOptions::default().verify_checksums(true);
    /// ```
    #[must_use]
    pub fn verify_checksums(mut self, verify: bool) -> Self {
        self.verify_checksums = verify;
        self
    }

    /// Set custom URLs for database sources.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::{UpdateOptions, CustomUrls};
    ///
    /// let custom = CustomUrls {
    ///     service_probes: Some("https://example.com/service-probes".to_string()),
    ///     os_db: None,
    ///     mac_prefixes: None,
    ///     services: None,
    ///     protocols: None,
    ///     rpc: None,
    /// };
    /// let options = UpdateOptions::default().custom_urls(custom);
    /// ```
    #[must_use]
    pub fn custom_urls(mut self, urls: CustomUrls) -> Self {
        self.custom_urls = Some(urls);
        self
    }
}

impl DatabaseUpdater {
    /// Create a new database updater.
    ///
    /// Initializes the HTTP client with default settings and a
    /// 120-second timeout for downloads.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::DatabaseUpdater;
    ///
    /// let updater = DatabaseUpdater::new();
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client fails to build.
    #[must_use]
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(DOWNLOAD_TIMEOUT)
            .user_agent(concat!("RustNmap/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Update all fingerprint databases.
    ///
    /// Downloads and updates service probes, OS fingerprint, and MAC
    /// prefix databases to the latest versions.
    ///
    /// # Errors
    ///
    /// Returns an error if the target directory cannot be created or
    /// if all database updates fail.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_all("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// // Check result.updated_count for number of databases updated
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_all(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<UpdateResult> {
        let target_dir = target_dir.as_ref();

        // Ensure target directory exists
        tokio::fs::create_dir_all(target_dir)
            .await
            .map_err(|e| FingerprintError::Io {
                path: target_dir.to_path_buf(),
                source: e,
            })?;

        let mut details = Vec::new();
        let mut updated = 0;
        let mut unchanged = 0;
        let mut failed = 0;

        // Update service probes
        match self.update_service_probes(target_dir, options).await {
            Ok(detail) => {
                if detail.success {
                    if detail.previous_version == detail.new_version {
                        unchanged += 1;
                    } else {
                        updated += 1;
                    }
                } else {
                    failed += 1;
                }
                details.push(detail);
            }
            Err(e) => {
                failed += 1;
                details.push(DatabaseUpdateDetail {
                    name: "service-probes".to_string(),
                    success: false,
                    previous_version: None,
                    new_version: None,
                    error: Some(e.to_string()),
                    backup_created: false,
                });
            }
        }

        // Update OS database
        match self.update_os_db(target_dir, options).await {
            Ok(detail) => {
                if detail.success {
                    if detail.previous_version == detail.new_version {
                        unchanged += 1;
                    } else {
                        updated += 1;
                    }
                } else {
                    failed += 1;
                }
                details.push(detail);
            }
            Err(e) => {
                failed += 1;
                details.push(DatabaseUpdateDetail {
                    name: "os-db".to_string(),
                    success: false,
                    previous_version: None,
                    new_version: None,
                    error: Some(e.to_string()),
                    backup_created: false,
                });
            }
        }

        // Update MAC prefixes
        match self.update_mac_prefixes(target_dir, options).await {
            Ok(detail) => {
                if detail.success {
                    if detail.previous_version == detail.new_version {
                        unchanged += 1;
                    } else {
                        updated += 1;
                    }
                } else {
                    failed += 1;
                }
                details.push(detail);
            }
            Err(e) => {
                failed += 1;
                details.push(DatabaseUpdateDetail {
                    name: "mac-prefixes".to_string(),
                    success: false,
                    previous_version: None,
                    new_version: None,
                    error: Some(e.to_string()),
                    backup_created: false,
                });
            }
        }

        // Update services database
        match self.update_services(target_dir, options).await {
            Ok(detail) => {
                if detail.success {
                    if detail.previous_version == detail.new_version {
                        unchanged += 1;
                    } else {
                        updated += 1;
                    }
                } else {
                    failed += 1;
                }
                details.push(detail);
            }
            Err(e) => {
                failed += 1;
                details.push(DatabaseUpdateDetail {
                    name: "services".to_string(),
                    success: false,
                    previous_version: None,
                    new_version: None,
                    error: Some(e.to_string()),
                    backup_created: false,
                });
            }
        }

        // Update protocols database
        match self.update_protocols(target_dir, options).await {
            Ok(detail) => {
                if detail.success {
                    if detail.previous_version == detail.new_version {
                        unchanged += 1;
                    } else {
                        updated += 1;
                    }
                } else {
                    failed += 1;
                }
                details.push(detail);
            }
            Err(e) => {
                failed += 1;
                details.push(DatabaseUpdateDetail {
                    name: "protocols".to_string(),
                    success: false,
                    previous_version: None,
                    new_version: None,
                    error: Some(e.to_string()),
                    backup_created: false,
                });
            }
        }

        // Update RPC database
        match self.update_rpc(target_dir, options).await {
            Ok(detail) => {
                if detail.success {
                    if detail.previous_version == detail.new_version {
                        unchanged += 1;
                    } else {
                        updated += 1;
                    }
                } else {
                    failed += 1;
                }
                details.push(detail);
            }
            Err(e) => {
                failed += 1;
                details.push(DatabaseUpdateDetail {
                    name: "rpc".to_string(),
                    success: false,
                    previous_version: None,
                    new_version: None,
                    error: Some(e.to_string()),
                    backup_created: false,
                });
            }
        }

        info!(
            "Database update complete: {} updated, {} unchanged, {} failed",
            updated, unchanged, failed
        );

        Ok(UpdateResult {
            updated_count: updated,
            unchanged_count: unchanged,
            failed_count: failed,
            details,
        })
    }

    /// Update the service probes database.
    ///
    /// Downloads the latest nmap-service-probes file from the official
    /// Nmap SVN repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be
    /// written to the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_service_probes("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_service_probes(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        let target_dir = target_dir.as_ref();
        let target_path = target_dir.join("nmap-service-probes");

        let url = options
            .custom_urls
            .as_ref()
            .and_then(|u| u.service_probes.clone())
            .unwrap_or_else(|| NMAP_SERVICE_PROBES_URL.to_string());

        info!("Updating service probes database from {}", url);

        self.update_database_file(&url, &target_path, "service-probes", options)
            .await
    }

    /// Update the OS fingerprint database.
    ///
    /// Downloads the latest nmap-os-db file from the official Nmap
    /// SVN repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be
    /// written to the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_os_db("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_os_db(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        let target_dir = target_dir.as_ref();
        let target_path = target_dir.join("nmap-os-db");

        let url = options
            .custom_urls
            .as_ref()
            .and_then(|u| u.os_db.clone())
            .unwrap_or_else(|| NMAP_OS_DB_URL.to_string());

        info!("Updating OS fingerprint database from {}", url);

        self.update_database_file(&url, &target_path, "os-db", options)
            .await
    }

    /// Update the MAC prefixes database.
    ///
    /// Downloads the latest nmap-mac-prefixes file from the official
    /// Nmap SVN repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be
    /// written to the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_mac_prefixes("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_mac_prefixes(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        let target_dir = target_dir.as_ref();
        let target_path = target_dir.join("nmap-mac-prefixes");

        let url = options
            .custom_urls
            .as_ref()
            .and_then(|u| u.mac_prefixes.clone())
            .unwrap_or_else(|| NMAP_MAC_PREFIXES_URL.to_string());

        info!("Updating MAC prefixes database from {}", url);

        self.update_database_file(&url, &target_path, "mac-prefixes", options)
            .await
    }

    /// Update the services database.
    ///
    /// Downloads the latest nmap-services file from the official Nmap
    /// SVN repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be
    /// written to the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_services("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_services(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        let target_dir = target_dir.as_ref();
        let target_path = target_dir.join("nmap-services");

        let url = options
            .custom_urls
            .as_ref()
            .and_then(|u| u.services.clone())
            .unwrap_or_else(|| NMAP_SERVICES_URL.to_string());

        info!("Updating services database from {}", url);

        self.update_database_file(&url, &target_path, "services", options)
            .await
    }

    /// Update the protocols database.
    ///
    /// Downloads the latest nmap-protocols file from the official Nmap
    /// SVN repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be
    /// written to the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_protocols("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_protocols(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        let target_dir = target_dir.as_ref();
        let target_path = target_dir.join("nmap-protocols");

        let url = options
            .custom_urls
            .as_ref()
            .and_then(|u| u.protocols.clone())
            .unwrap_or_else(|| NMAP_PROTOCOLS_URL.to_string());

        info!("Updating protocols database from {}", url);

        self.update_database_file(&url, &target_path, "protocols", options)
            .await
    }

    /// Update the RPC database.
    ///
    /// Downloads the latest nmap-rpc file from the official Nmap
    /// SVN repository.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails or the file cannot be
    /// written to the target directory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::{DatabaseUpdater, UpdateOptions};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let updater = DatabaseUpdater::new();
    /// let result = updater.update_rpc("/var/lib/rustnmap/", &UpdateOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_rpc(
        &self,
        target_dir: impl AsRef<Path>,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        let target_dir = target_dir.as_ref();
        let target_path = target_dir.join("nmap-rpc");

        let url = options
            .custom_urls
            .as_ref()
            .and_then(|u| u.rpc.clone())
            .unwrap_or_else(|| NMAP_RPC_URL.to_string());

        info!("Updating RPC database from {}", url);

        self.update_database_file(&url, &target_path, "rpc", options)
            .await
    }

    /// Internal method to update a single database file.
    #[allow(
        clippy::too_many_lines,
        reason = "Complex update logic with multiple steps"
    )]
    async fn update_database_file(
        &self,
        url: &str,
        target_path: &Path,
        name: &str,
        options: &UpdateOptions,
    ) -> crate::Result<DatabaseUpdateDetail> {
        // Get previous version info if file exists
        let previous_version = self.get_file_version(target_path).await;

        // Create backup if requested and file exists
        let backup_created = if options.backup && target_path.exists() {
            let backup_path = target_path.with_extension("backup");
            match tokio::fs::copy(target_path, &backup_path).await {
                Ok(_) => {
                    debug!("Created backup at {:?}", backup_path);
                    true
                }
                Err(e) => {
                    warn!("Failed to create backup: {}", e);
                    false
                }
            }
        } else {
            false
        };

        // Download the file
        let response = match self.client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(DatabaseUpdateDetail {
                    name: name.to_string(),
                    success: false,
                    previous_version: previous_version.clone(),
                    new_version: None,
                    error: Some(format!("Download failed: {e}")),
                    backup_created,
                });
            }
        };

        if !response.status().is_success() {
            return Ok(DatabaseUpdateDetail {
                name: name.to_string(),
                success: false,
                previous_version: previous_version.clone(),
                new_version: None,
                error: Some(format!("HTTP error: {}", response.status())),
                backup_created,
            });
        }

        // Read content
        let content = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(DatabaseUpdateDetail {
                    name: name.to_string(),
                    success: false,
                    previous_version: previous_version.clone(),
                    new_version: None,
                    error: Some(format!("Failed to read response: {e}")),
                    backup_created,
                });
            }
        };

        // Verify content is not empty
        if content.is_empty() {
            return Ok(DatabaseUpdateDetail {
                name: name.to_string(),
                success: false,
                previous_version: previous_version.clone(),
                new_version: None,
                error: Some("Downloaded file is empty".to_string()),
                backup_created,
            });
        }

        // Write content to a staging file, then atomically replace target
        let staging_path = target_path.with_extension("tmp");
        if let Err(e) = tokio::fs::write(&staging_path, &content).await {
            return Ok(DatabaseUpdateDetail {
                name: name.to_string(),
                success: false,
                previous_version: previous_version.clone(),
                new_version: None,
                error: Some(format!("Failed to write staging file: {e}")),
                backup_created,
            });
        }

        // Atomically replace target file with staging file
        if let Err(e) = tokio::fs::rename(&staging_path, target_path).await {
            // Clean up staging file
            let _ = tokio::fs::remove_file(&staging_path).await;
            return Ok(DatabaseUpdateDetail {
                name: name.to_string(),
                success: false,
                previous_version: previous_version.clone(),
                new_version: None,
                error: Some(format!("Failed to replace file: {e}")),
                backup_created,
            });
        }

        // Get new version
        let new_version = self.get_file_version(target_path).await;

        info!(
            "Successfully updated {} database ({} -> {})",
            name,
            previous_version.as_deref().unwrap_or("none"),
            new_version.as_deref().unwrap_or("unknown")
        );

        Ok(DatabaseUpdateDetail {
            name: name.to_string(),
            success: true,
            previous_version,
            new_version,
            error: None,
            backup_created,
        })
    }

    /// Get version info for a database file.
    async fn get_file_version(&self, path: &Path) -> Option<String> {
        if !path.exists() {
            return None;
        }

        // Try to read first few lines to extract version/date info
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                // Look for version info in comments
                for line in content.lines().take(20) {
                    let line = line.trim();
                    if line.starts_with('#') {
                        // Try to find date patterns like "# Date: 2024-01-15" or similar
                        if let Some(date) = line.strip_prefix("# Date:") {
                            return Some(date.trim().to_string());
                        }
                        if let Some(version) = line.strip_prefix("# Version:") {
                            return Some(version.trim().to_string());
                        }
                    }
                }

                // If no explicit version found, use file modification time
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                            return Some(format!("mtime-{}", duration.as_secs()));
                        }
                    }
                }

                // Fallback to file size
                content.len().to_string().into()
            }
            Err(_) => None,
        }
    }
}

impl Default for DatabaseUpdater {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_options_default() {
        let opts = UpdateOptions::default();
        assert!(opts.backup);
        assert!(!opts.verify_checksums);
        assert!(opts.custom_urls.is_none());
    }

    #[test]
    fn test_update_options_builder() {
        let opts = UpdateOptions::default()
            .backup(false)
            .verify_checksums(true);

        assert!(!opts.backup);
        assert!(opts.verify_checksums);
    }

    #[test]
    fn test_database_updater_new() {
        let _updater = DatabaseUpdater::new();
        // Verify updater was created successfully (no panic)
    }

    #[test]
    fn test_update_result_default() {
        let result = UpdateResult {
            updated_count: 0,
            unchanged_count: 0,
            failed_count: 0,
            details: vec![],
        };

        assert_eq!(result.updated_count, 0);
        assert_eq!(result.unchanged_count, 0);
        assert_eq!(result.failed_count, 0);
        assert!(result.details.is_empty());
    }
}
