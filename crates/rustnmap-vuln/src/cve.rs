//! CVE (Common Vulnerabilities and Exposures) correlation.
//!
//! This module provides CVE lookup and correlation functionality.

use crate::database::VulnDatabase;
use crate::error::Result;
use crate::models::CveEntry;

/// CVE correlation engine.
#[derive(Debug)]
pub struct CveEngine {
    db: VulnDatabase,
}

impl CveEngine {
    /// Create a new CVE engine with a database.
    ///
    /// # Arguments
    ///
    /// * `db` - The vulnerability database.
    #[must_use]
    pub const fn new(db: VulnDatabase) -> Self {
        Self { db }
    }

    /// Get a CVE entry by ID.
    ///
    /// # Arguments
    ///
    /// * `cve_id` - CVE identifier (e.g., "CVE-2024-1234").
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<CveEntry>> {
        self.db.get_cve(cve_id).await
    }

    /// Get the database reference.
    #[must_use]
    pub const fn database(&self) -> &VulnDatabase {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cve_engine_creation() {
        let db = VulnDatabase::open_in_memory().await.unwrap();
        let engine = CveEngine::new(db);
        engine.database().get_stats().await.unwrap();
    }
}
