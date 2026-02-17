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
    #[must_use]
    pub fn new(db: VulnDatabase) -> Self {
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
    pub fn get_cve(&self, cve_id: &str) -> Result<Option<CveEntry>> {
        self.db.get_cve(cve_id)
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
    fn test_cve_engine_creation() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let engine = CveEngine::new(db);
        assert!(engine.database().get_stats().is_ok());
    }
}
