//! Vulnerability client - main interface for vulnerability intelligence.
//!
//! This module provides the primary API for querying vulnerability information.

use std::path::Path;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::collections::HashMap;

use crate::cpe::CpeMatcher;
use crate::database::VulnDatabase;
use crate::epss::EpssEngine;
use crate::error::Result;
use crate::kev::KevEngine;
use crate::models::VulnInfo;

/// Default LRU cache size.
const DEFAULT_CACHE_SIZE: usize = 1000;

/// Vulnerability client.
///
/// Provides the main interface for querying vulnerability information
/// including CVE/CPE correlation, EPSS scoring, and CISA KEV status.
///
/// # Operating Modes
///
/// ## Offline Mode
/// Uses local SQLite database only. No API calls.
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
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create offline client
/// let mut client = VulnClient::offline(Path::new("/var/lib/rustnmap/vuln.db"))?;
///
/// // Query vulnerabilities
/// let vulns = client.query_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")?;
///
/// for vuln in vulns {
///     println!("CVE: {} (CVSS: {}, EPSS: {}, KEV: {})",
///         vuln.cve_id, vuln.cvss_v3, vuln.epss_score, vuln.is_kev);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct VulnClient {
    db: VulnDatabase,
    #[allow(dead_code)]
    epss: EpssEngine,
    #[allow(dead_code)]
    kev: KevEngine,
    cache: Option<LruCache<String, Vec<VulnInfo>>>,
}

impl VulnClient {
    /// Create an offline-mode client.
    ///
    /// Uses local SQLite database only. No API key required.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the SQLite database file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened.
    pub fn offline(db_path: &Path) -> Result<Self> {
        let db = VulnDatabase::open(db_path)?;

        Ok(Self {
            db,
            epss: EpssEngine::new(),
            kev: KevEngine::new(),
            cache: Some(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap())),
        })
    }

    /// Create an in-memory client (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created.
    pub fn in_memory() -> Result<Self> {
        let db = VulnDatabase::open_in_memory()?;

        Ok(Self {
            db,
            epss: EpssEngine::new(),
            kev: KevEngine::new(),
            cache: Some(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap())),
        })
    }

    /// Query vulnerabilities for a CPE.
    ///
    /// # Arguments
    ///
    /// * `cpe` - CPE 2.3 string to query.
    ///
    /// # Returns
    ///
    /// Vector of matching vulnerabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn query_cpe(&mut self, cpe: &str) -> Result<Vec<VulnInfo>> {
        // Check cache first
        if let Some(cache) = &mut self.cache {
            if let Some(cached) = cache.get(cpe) {
                return Ok(cached.clone());
            }
        }

        // Parse CPE
        let _cpe_wrapper = CpeMatcher::parse(cpe)?;

        // Query database for matching CVEs
        let matches = self.db.get_matches_by_cpe(cpe)?;

        // Build VulnInfo for each match
        let mut vulns = Vec::new();

        for (cve, cpe_match) in matches {
            // Get EPSS score
            let epss = EpssEngine::get_score(&self.db, &cve.id)?;

            // Get KEV status
            let kev = KevEngine::get_entry(&self.db, &cve.id)?;

            let vuln = VulnInfo {
                cve_id: cve.id,
                cvss_v3: cve.cvss_v3_base.unwrap_or(0.0),
                cvss_vector: cve.cvss_v3_vector,
                epss_score: epss.as_ref().map(|e| e.epss_score).unwrap_or(0.0),
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
        vulns.sort_by(|a, b| b.risk_priority().cmp(&a.risk_priority()));

        // Cache result
        if let Some(cache) = &mut self.cache {
            cache.put(cpe.to_string(), vulns.clone());
        }

        Ok(vulns)
    }

    /// Batch query vulnerabilities for multiple CPEs.
    ///
    /// # Arguments
    ///
    /// * `cpes` - Slice of CPE strings to query.
    ///
    /// # Returns
    ///
    /// HashMap mapping CPE to vector of vulnerabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if any query fails.
    pub fn batch_query(&mut self, cpes: &[&str]) -> Result<HashMap<String, Vec<VulnInfo>>> {
        let mut results = HashMap::new();

        for cpe in cpes {
            let vulns = self.query_cpe(cpe)?;
            results.insert(cpe.to_string(), vulns);
        }

        Ok(results)
    }

    /// Get vulnerability by CVE ID.
    ///
    /// # Arguments
    ///
    /// * `cve_id` - CVE identifier.
    ///
    /// # Returns
    ///
    /// Vulnerability info if found.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_cve(&self, cve_id: &str) -> Result<Option<VulnInfo>> {
        let cve = self.db.get_cve(cve_id)?;

        match cve {
            Some(cve_entry) => {
                let epss = EpssEngine::get_score(&self.db, cve_id)?;
                let kev = KevEngine::get_entry(&self.db, cve_id)?;

                let vuln = VulnInfo {
                    cve_id: cve_entry.id,
                    cvss_v3: cve_entry.cvss_v3_base.unwrap_or(0.0),
                    cvss_vector: cve_entry.cvss_v3_vector,
                    epss_score: epss.as_ref().map(|e| e.epss_score).unwrap_or(0.0),
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
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_stats(&self) -> Result<crate::database::DatabaseStats> {
        self.db.get_stats()
    }

    /// Clear the query cache.
    pub fn clear_cache(&mut self) {
        if let Some(cache) = &mut self.cache {
            cache.clear();
        }
    }

    /// Get the database reference.
    #[must_use]
    pub fn database(&self) -> &VulnDatabase {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln_client_in_memory() {
        let client = VulnClient::in_memory().unwrap();
        let stats = client.get_stats().unwrap();
        assert_eq!(stats.cve_count, 0);
    }

    #[test]
    fn test_vuln_client_query_empty() {
        let mut client = VulnClient::in_memory().unwrap();
        let vulns = client.query_cpe("cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*").unwrap();
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_vuln_client_batch_query() {
        let mut client = VulnClient::in_memory().unwrap();
        let cpes = vec![
            "cpe:2.3:a:test:app1:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:test:app2:2.0:*:*:*:*:*:*:*",
        ];
        let results = client.batch_query(&cpes).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_vuln_client_cache() {
        let mut client = VulnClient::in_memory().unwrap();
        let _ = client.query_cpe("cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*").unwrap();
        client.clear_cache();
    }
}
