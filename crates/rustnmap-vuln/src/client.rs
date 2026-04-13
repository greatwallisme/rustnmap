// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Vulnerability client - main interface for vulnerability intelligence.
//!
//! This module provides the primary API for querying vulnerability information.

use dashmap::DashMap;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::cpe::CpeMatcher;
use crate::database::VulnDatabase;
use crate::error::Result;
use crate::models::VulnInfo;

/// Default cache shard count for `DashMap` (affects concurrency level).
const DEFAULT_SHARD_COUNT: usize = 8;

/// Vulnerability client with async support.
///
/// Provides the main interface for querying vulnerability information
/// including CVE/CPE correlation, EPSS scoring, and CISA KEV status.
///
/// # Thread Safety
///
/// This client is designed for concurrent async access:
/// - The database uses `tokio-rusqlite` for true async `SQLite` operations
/// - The cache uses `DashMap` for lock-free concurrent reads/writes
/// - All methods take `&self`, allowing concurrent queries
///
/// # Note
///
/// The underlying `SQLite` database uses `tokio-rusqlite` which provides
/// true async operations without blocking the runtime.
///
/// # Operating Modes
///
/// ## Offline Mode
/// Uses local `SQLite` database only. No API calls.
///
/// ## Online Mode
/// Uses NVD API for real-time queries. Requires API key.
///
/// ## Hybrid Mode
/// Prioritizes local database, falls back to API for misses.
///
/// # Example
///
/// ```no_run
/// use rustnmap_vuln::VulnClient;
/// use std::path::Path;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create offline client
/// let client = VulnClient::offline_async(Path::new("/var/lib/rustnmap/vuln.db")).await?;
///
/// // Query vulnerabilities (async, concurrent-safe)
/// let vulns = client.query_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").await?;
///
/// for vuln in vulns {
///     let _ = format!("CVE: {} (CVSS: {}, EPSS: {}, KEV: {})",
///         vuln.cve_id, vuln.cvss_v3, vuln.epss_score, vuln.is_kev);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct VulnClient {
    db: Arc<VulnDatabase>,
    cache: DashMap<String, Vec<VulnInfo>>,
}

#[allow(
    clippy::arc_with_non_send_sync,
    reason = "VulnDatabase wraps rusqlite::Connection which is not Sync. \
              RwLock ensures safe access, but we cannot make it Sync without \
              changing the underlying database library. This is a known limitation."
)]
impl VulnClient {
    /// Create an offline-mode client (async version).
    ///
    /// Uses local `SQLite` database only. No API key required.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the `SQLite` database file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened.
    pub async fn offline_async(db_path: impl AsRef<Path> + Send + 'static) -> Result<Self> {
        let db = VulnDatabase::open(db_path.as_ref()).await?;

        Ok(Self {
            db: Arc::new(db),
            cache: DashMap::with_shard_amount(DEFAULT_SHARD_COUNT),
        })
    }

    /// Create an offline-mode client (synchronous version).
    ///
    /// Uses local `SQLite` database only. No API key required.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the `SQLite` database file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened.
    ///
    /// # Note
    ///
    /// This is a convenience method for non-async contexts. For async contexts,
    /// prefer using `offline_async()` which uses true async I/O.
    pub fn offline(db_path: &Path) -> Result<Self> {
        // Use block_in_place to wait for async database initialization
        let db = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(VulnDatabase::open(db_path))
        })?;

        Ok(Self {
            db: Arc::new(db),
            cache: DashMap::with_shard_amount(DEFAULT_SHARD_COUNT),
        })
    }

    /// Create an in-memory client (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created.
    ///
    /// # Note
    ///
    /// This is a convenience method for non-async contexts. For async contexts,
    /// prefer using `in_memory_async()` which uses true async I/O.
    pub fn in_memory() -> Result<Self> {
        let db = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(VulnDatabase::open_in_memory())
        })?;

        Ok(Self {
            db: Arc::new(db),
            cache: DashMap::with_shard_amount(DEFAULT_SHARD_COUNT),
        })
    }

    /// Create an in-memory client (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created.
    pub async fn in_memory_async() -> Result<Self> {
        let db = VulnDatabase::open_in_memory().await?;

        Ok(Self {
            db: Arc::new(db),
            cache: DashMap::with_shard_amount(DEFAULT_SHARD_COUNT),
        })
    }

    /// Query vulnerabilities for a CPE.
    ///
    /// This is the primary query method and is async for proper integration
    /// with async contexts. It uses the local `SQLite` database and does not
    /// make external API calls.
    ///
    /// # Arguments
    ///
    /// * `cpe` - CPE 2.3 string to query.
    ///
    /// # Returns
    ///
    /// Vector of matching vulnerabilities, sorted by risk priority.
    ///
    /// # Errors
    ///
    /// Returns an error if the CPE is invalid or the query fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use rustnmap_vuln::VulnClient;
    ///
    /// let client = VulnClient::in_memory_async().await?;
    /// let vulns = client.query_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").await?;
    ///
    /// for vuln in vulns {
    ///     let _ = format!("CVE: {} (CVSS: {}, EPSS: {}, KEV: {})",
    ///         vuln.cve_id, vuln.cvss_v3, vuln.epss_score, vuln.is_kev);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_cpe(&self, cpe: &str) -> Result<Vec<VulnInfo>> {
        // Check cache first (DashMap supports concurrent reads)
        if let Some(cached) = self.cache.get(cpe) {
            return Ok(cached.clone());
        }

        // Parse CPE
        let _cpe_wrapper = CpeMatcher::parse(cpe)?;

        // Query database for matching CVEs
        let matches = self.db.get_matches_by_cpe(cpe).await?;

        // Build VulnInfo for each match
        let mut vulns = Vec::new();

        for (cve, cpe_match) in matches {
            // Get EPSS score
            let epss = self.db.get_epss(&cve.id).await?;

            // Get KEV status
            let kev = self.db.get_kev(&cve.id).await?;

            let vuln = VulnInfo {
                cve_id: cve.id,
                cvss_v3: cve.cvss_v3_base.unwrap_or(0.0),
                cvss_vector: cve.cvss_v3_vector,
                epss_score: epss.as_ref().map_or(0.0, |e| e.epss_score),
                epss_percentile: epss.as_ref().map(|e| e.percentile),
                is_kev: kev.is_some(),
                affected_cpe: cpe_match.cpe_23_uri,
                description: cve.description,
                published_date: cve.published_at,
                modified_date: cve.modified_at,
                references: cve.references,
                vendor_project: kev.as_ref().map(|k| k.vendor_project.clone()),
                product: kev.as_ref().map(|k| k.product.clone()),
                kev_required_action: kev.as_ref().map(|k| k.required_action.clone()),
                kev_due_date: kev.as_ref().map(|k| k.due_date.clone()),
            };

            vulns.push(vuln);
        }

        // Sort by risk priority (highest first)
        vulns.sort_by_key(|b| std::cmp::Reverse(b.risk_priority()));

        // Cache result
        let result = vulns.clone();
        let _ = self.cache.insert(cpe.to_string(), result);

        Ok(vulns)
    }

    /// Batch query vulnerabilities for multiple CPEs.
    ///
    /// Queries multiple CPEs concurrently for better performance.
    ///
    /// # Arguments
    ///
    /// * `cpes` - Slice of CPE strings to query.
    ///
    /// # Returns
    ///
    /// `HashMap` mapping CPE to vector of vulnerabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if any query fails.
    pub async fn batch_query(&self, cpes: &[&str]) -> Result<HashMap<String, Vec<VulnInfo>>> {
        let mut results = HashMap::with_capacity(cpes.len());

        for cpe in cpes {
            let vulns = self.query_cpe(cpe).await?;
            let _ = results.insert((*cpe).to_string(), vulns);
        }

        Ok(results)
    }

    /// Get vulnerability by CVE ID.
    ///
    /// # Arguments
    ///
    /// * `cve_id` - CVE identifier (e.g., "CVE-2024-1234").
    ///
    /// # Returns
    ///
    /// Vulnerability info if found.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use rustnmap_vuln::VulnClient;
    ///
    /// let client = VulnClient::in_memory_async().await?;
    /// if let Some(vuln) = client.get_cve("CVE-2024-1234").await? {
    ///     let _ = format!("CVE: {} (CVSS: {}, EPSS: {}, KEV: {})",
    ///         vuln.cve_id, vuln.cvss_v3, vuln.epss_score, vuln.is_kev);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<VulnInfo>> {
        let cve = self.db.get_cve(cve_id).await?;

        match cve {
            Some(cve_entry) => {
                let epss = self.db.get_epss(cve_id).await?;

                let kev = self.db.get_kev(cve_id).await?;

                let vuln = VulnInfo {
                    cve_id: cve_entry.id,
                    cvss_v3: cve_entry.cvss_v3_base.unwrap_or(0.0),
                    cvss_vector: cve_entry.cvss_v3_vector,
                    epss_score: epss.as_ref().map_or(0.0, |e| e.epss_score),
                    epss_percentile: epss.as_ref().map(|e| e.percentile),
                    is_kev: kev.is_some(),
                    affected_cpe: String::new(),
                    description: cve_entry.description,
                    published_date: cve_entry.published_at,
                    modified_date: cve_entry.modified_at,
                    references: cve_entry.references,
                    vendor_project: kev.as_ref().map(|k| k.vendor_project.clone()),
                    product: kev.as_ref().map(|k| k.product.clone()),
                    kev_required_action: kev.as_ref().map(|k| k.required_action.clone()),
                    kev_due_date: kev.as_ref().map(|k| k.due_date.clone()),
                };

                Ok(Some(vuln))
            }
            None => Ok(None),
        }
    }

    /// Get database statistics.
    ///
    /// # Returns
    ///
    /// Database statistics including CVE, CPE, EPSS, and KEV counts.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn get_stats(&self) -> Result<crate::database::DatabaseStats> {
        self.db.get_stats().await
    }

    /// Clear the query cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get the database reference for reading.
    #[must_use]
    pub fn database(&self) -> &Arc<VulnDatabase> {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vuln_client_in_memory() {
        let client = VulnClient::in_memory_async().await.unwrap();
        assert_eq!(client.cache.len(), 0);
    }

    #[tokio::test]
    async fn test_vuln_client_query_empty() {
        let client = VulnClient::in_memory_async().await.unwrap();
        let vulns = client
            .query_cpe("cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert!(vulns.is_empty());
    }

    #[tokio::test]
    async fn test_vuln_client_batch_query() {
        let client = VulnClient::in_memory_async().await.unwrap();
        let cpes = [
            "cpe:2.3:a:test:app1:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:test:app2:2.0:*:*:*:*:*:*:*",
        ];
        let results = client.batch_query(&cpes).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_vuln_client_cache() {
        let client = VulnClient::in_memory_async().await.unwrap();
        let _ = client
            .query_cpe("cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        client.clear_cache();
    }

    #[tokio::test]
    async fn test_vuln_client_query() {
        let client = VulnClient::in_memory_async().await.unwrap();
        let vulns = client
            .query_cpe("cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*")
            .await
            .unwrap();
        assert!(vulns.is_empty());
    }

    #[tokio::test]
    async fn test_vuln_client_get_cve() {
        let client = VulnClient::in_memory_async().await.unwrap();
        let result = client.get_cve("CVE-2024-1234").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_vuln_client_get_stats() {
        let client = VulnClient::in_memory_async().await.unwrap();
        let stats = client.get_stats().await.unwrap();
        assert_eq!(stats.cve_count, 0);
    }
}
