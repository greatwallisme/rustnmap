//! `SQLite` database operations for vulnerability intelligence.
//!
//! Uses `tokio-rusqlite` for async `SQLite` operations.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};
use std::path::Path;
use tracing::debug;

use crate::error::{Result, VulnError};
use crate::models::{CpeMatch, CveEntry, EpssRecord, KevEntry};

/// Vulnerability database wrapper.
///
/// Provides SQLite-based storage for CVE, CPE, EPSS, and KEV data.
/// Uses `tokio-rusqlite` for async database operations.
#[derive(Debug, Clone)]
pub struct VulnDatabase {
    conn: tokio_rusqlite::Connection,
}

impl VulnDatabase {
    /// Open or create a vulnerability database.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the `SQLite` database file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or created.
    pub async fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                VulnError::config(format!("Failed to create database directory: {e}"))
            })?;
        }

        let conn = tokio_rusqlite::Connection::open(path)
            .await
            .map_err(|e| VulnError::database(format!("Failed to open database: {e}")))?;

        let db = Self { conn };
        db.init_schema().await?;

        Ok(db)
    }

    /// Open an in-memory database (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created.
    pub async fn open_in_memory() -> Result<Self> {
        let conn = tokio_rusqlite::Connection::open_in_memory()
            .await
            .map_err(|e| VulnError::database(format!("Failed to open in-memory database: {e}")))?;

        let db = Self { conn };
        db.init_schema().await?;
        Ok(db)
    }

    /// Initialize the database schema.
    async fn init_schema(&self) -> Result<()> {
        let queries = [
            // CVE table
            "CREATE TABLE IF NOT EXISTS cve (
                id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                cvss_v3_base REAL,
                cvss_v3_vector TEXT,
                published_at TEXT NOT NULL,
                modified_at TEXT
            )",
            // CVE references table
            "CREATE TABLE IF NOT EXISTS cve_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                url TEXT NOT NULL,
                FOREIGN KEY (cve_id) REFERENCES cve(id)
            )",
            // CPE match table
            "CREATE TABLE IF NOT EXISTS cpe_match (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                cpe_23_uri TEXT NOT NULL,
                version_start_excluding TEXT,
                version_end_excluding TEXT,
                version_start_including TEXT,
                version_end_including TEXT,
                vulnerable INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (cve_id) REFERENCES cve(id)
            )",
            // EPSS table
            "CREATE TABLE IF NOT EXISTS epss (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL NOT NULL,
                percentile REAL NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (cve_id) REFERENCES cve(id)
            )",
            // KEV table
            "CREATE TABLE IF NOT EXISTS kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT NOT NULL,
                product TEXT NOT NULL,
                date_added TEXT NOT NULL,
                required_action TEXT,
                due_date TEXT,
                notes TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve(id)
            )",
            // Indexes for performance
            "CREATE INDEX IF NOT EXISTS idx_cve_published ON cve(published_at)",
            "CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve(cvss_v3_base DESC)",
            "CREATE INDEX IF NOT EXISTS idx_cpe_match_cve ON cpe_match(cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_cpe_match_cpe ON cpe_match(cpe_23_uri)",
            "CREATE INDEX IF NOT EXISTS idx_epss_score ON epss(epss_score DESC)",
            "CREATE INDEX IF NOT EXISTS idx_kev_date ON kev(date_added DESC)",
        ];

        for query in queries {
            self.conn
                .call(move |conn| conn.execute(query, []).map_err(tokio_rusqlite::Error::from))
                .await
                .map_err(|e| VulnError::database(format!("Failed to execute schema query: {e}")))?;
        }

        debug!("Database schema initialized");
        Ok(())
    }

    /// Insert a CVE entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub async fn insert_cve(&self, cve: &CveEntry) -> Result<()> {
        let cve = cve.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO cve (id, description, cvss_v3_base, cvss_v3_vector, published_at, modified_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        cve.id,
                        cve.description,
                        cve.cvss_v3_base,
                        cve.cvss_v3_vector,
                        cve.published_at.to_rfc3339(),
                        cve.modified_at.map(|d| d.to_rfc3339()),
                    ],
                )
                .map_err(tokio_rusqlite::Error::from)?;

                // Insert references
                for url in &cve.references {
                    conn.execute(
                        "INSERT INTO cve_references (cve_id, url) VALUES (?1, ?2)",
                        params![cve.id, url],
                    )
                    .map_err(tokio_rusqlite::Error::from)?;
                }

                Ok(())
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to insert CVE: {e}")))?;

        Ok(())
    }

    /// Insert a CPE match.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub async fn insert_cpe_match(&self, cpe_match: &CpeMatch) -> Result<()> {
        let cpe_match = cpe_match.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO cpe_match (cve_id, cpe_23_uri, version_start_excluding,
                 version_end_excluding, version_start_including, version_end_including, vulnerable)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        cpe_match.cve_id,
                        cpe_match.cpe_23_uri,
                        cpe_match.version_start_excluding,
                        cpe_match.version_end_excluding,
                        cpe_match.version_start_including,
                        cpe_match.version_end_including,
                        i32::from(cpe_match.vulnerable),
                    ],
                )
                .map_err(tokio_rusqlite::Error::from)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to insert CPE match: {e}")))?;

        Ok(())
    }

    /// Insert an EPSS record.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub async fn insert_epss(&self, epss: &EpssRecord) -> Result<()> {
        let epss = epss.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO epss (cve_id, epss_score, percentile, date)
                 VALUES (?1, ?2, ?3, ?4)",
                    params![epss.cve_id, epss.epss_score, epss.percentile, epss.date],
                )
                .map_err(tokio_rusqlite::Error::from)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to insert EPSS: {e}")))?;

        Ok(())
    }

    /// Insert a KEV entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub async fn insert_kev(&self, kev: &KevEntry) -> Result<()> {
        let kev = kev.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO kev (cve_id, vendor_project, product, date_added,
                 required_action, due_date, notes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        kev.cve_id,
                        kev.vendor_project,
                        kev.product,
                        kev.date_added,
                        kev.required_action,
                        kev.due_date,
                        kev.notes,
                    ],
                )
                .map_err(tokio_rusqlite::Error::from)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to insert KEV: {e}")))?;

        Ok(())
    }

    /// Get CVE by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    #[allow(
        clippy::type_complexity,
        reason = "Complex tuple type is necessary for row mapping, extracting to struct would add unnecessary complexity"
    )]
    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<CveEntry>> {
        let cve_id = cve_id.to_string();
        let result = self
            .conn
            .call(move |conn| {
                // Query main CVE data
                let cve_data: Option<(
                    String,
                    String,
                    Option<f32>,
                    Option<String>,
                    String,
                    Option<String>,
                )> = conn
                    .query_row(
                        "SELECT id, description, cvss_v3_base, cvss_v3_vector, published_at, modified_at
                         FROM cve WHERE id = ?1",
                        params![cve_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<f32>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, Option<String>>(5)?,
                            ))
                        },
                    )
                    .optional()?;

                let Some((
                    id,
                    description,
                    cvss_v3_base,
                    cvss_v3_vector,
                    published_at_str,
                    modified_at_str,
                )) = cve_data
                else {
                    return Ok(None);
                };

                // Parse dates
                let published_at = DateTime::parse_from_rfc3339(&published_at_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|_e| {
                        rusqlite::Error::InvalidColumnType(
                            4,
                            "published_at".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })
                    .map_err(tokio_rusqlite::Error::from)?;

                let modified_at = modified_at_str
                    .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
                    .transpose()
                    .map_err(|_e| {
                        rusqlite::Error::InvalidColumnType(
                            5,
                            "modified_at".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })
                    .map_err(tokio_rusqlite::Error::from)?;

                // Get references
                let mut ref_stmt = conn
                    .prepare("SELECT url FROM cve_references WHERE cve_id = ?1")
                    .map_err(tokio_rusqlite::Error::from)?;

                let references: Vec<String> = ref_stmt
                    .query_map(params![id.as_str()], |row| row.get::<_, String>(0))?
                    .filter_map(std::result::Result::ok)
                    .collect();

                Ok(Some(CveEntry {
                    id,
                    description,
                    cvss_v3_base,
                    cvss_v3_vector,
                    published_at,
                    modified_at,
                    references,
                }))
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to query CVE: {e}")))?;

        Ok(result)
    }

    /// Get CPE matches for a CVE.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn get_cpe_matches(&self, cve_id: &str) -> Result<Vec<CpeMatch>> {
        let cve_id = cve_id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT cve_id, cpe_23_uri, version_start_excluding, version_end_excluding,
                            version_start_including, version_end_including, vulnerable
                         FROM cpe_match WHERE cve_id = ?1",
                    )
                    .map_err(tokio_rusqlite::Error::from)?;

                let matches = stmt
                    .query_map(params![cve_id], |row| {
                        Ok(CpeMatch {
                            cve_id: row.get(0)?,
                            cpe_23_uri: row.get(1)?,
                            version_start_excluding: row.get(2)?,
                            version_end_excluding: row.get(3)?,
                            version_start_including: row.get(4)?,
                            version_end_including: row.get(5)?,
                            vulnerable: row.get::<_, i32>(6)? != 0,
                        })
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect();

                Ok(matches)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to query CPE matches: {e}")))
    }

    /// Get EPSS score for a CVE.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn get_epss(&self, cve_id: &str) -> Result<Option<EpssRecord>> {
        let cve_id = cve_id.to_string();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT cve_id, epss_score, percentile, date FROM epss WHERE cve_id = ?1",
                    params![cve_id],
                    |row| {
                        Ok(EpssRecord {
                            cve_id: row.get(0)?,
                            epss_score: row.get(1)?,
                            percentile: row.get(2)?,
                            date: row.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(tokio_rusqlite::Error::from)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to query EPSS: {e}")))
    }

    /// Get KEV status for a CVE.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn get_kev(&self, cve_id: &str) -> Result<Option<KevEntry>> {
        let cve_id = cve_id.to_string();
        self.conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT cve_id, vendor_project, product, date_added, required_action, due_date, notes
                     FROM kev WHERE cve_id = ?1",
                    params![cve_id],
                    |row| {
                        Ok(KevEntry {
                            cve_id: row.get(0)?,
                            vendor_project: row.get(1)?,
                            product: row.get(2)?,
                            date_added: row.get(3)?,
                            required_action: row.get(4)?,
                            due_date: row.get(5)?,
                            notes: row.get(6)?,
                        })
                    },
                )
                .optional()
                .map_err(tokio_rusqlite::Error::from)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to query KEV: {e}")))
    }

    /// Get CPE matches for a CPE pattern.
    ///
    /// # Arguments
    ///
    /// * `cpe_pattern` - CPE pattern to search for (supports wildcards).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn get_matches_by_cpe(&self, cpe_pattern: &str) -> Result<Vec<(CveEntry, CpeMatch)>> {
        let pattern = cpe_pattern.replace('*', "%");
        self.conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT c.id, c.description, c.cvss_v3_base, c.cvss_v3_vector, c.published_at, c.modified_at,
                            m.cpe_23_uri, m.version_start_excluding, m.version_end_excluding,
                            m.version_start_including, m.version_end_including, m.vulnerable
                         FROM cve c
                         JOIN cpe_match m ON c.id = m.cve_id
                         WHERE m.cpe_23_uri LIKE ?1 AND m.vulnerable = 1",
                    )
                    .map_err(tokio_rusqlite::Error::from)?;

                let results = stmt
                    .query_map(params![pattern], |row| {
                        let id: String = row.get(0)?;
                        let description: String = row.get(1)?;
                        let cvss_v3_base: Option<f32> = row.get(2)?;
                        let cvss_v3_vector: Option<String> = row.get(3)?;
                        let published_at: String = row.get(4)?;
                        let modified_at: Option<String> = row.get(5)?;

                        let cpe_match = CpeMatch {
                            cve_id: id.clone(),
                            cpe_23_uri: row.get(6)?,
                            version_start_excluding: row.get(7)?,
                            version_end_excluding: row.get(8)?,
                            version_start_including: row.get(9)?,
                            version_end_including: row.get(10)?,
                            vulnerable: row.get::<_, i32>(11)? != 0,
                        };

                        let published = DateTime::parse_from_rfc3339(&published_at)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| {
                                rusqlite::Error::InvalidColumnType(
                                    4,
                                    format!("published_at parse error: {e}"),
                                    rusqlite::types::Type::Text,
                                )
                            })?;

                        let modified = modified_at
                            .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
                            .transpose()
                            .map_err(|e| {
                                rusqlite::Error::InvalidColumnType(
                                    5,
                                    format!("modified_at parse error: {e}"),
                                    rusqlite::types::Type::Text,
                                )
                            })?;

                        let cve = CveEntry {
                            id,
                            description,
                            cvss_v3_base,
                            cvss_v3_vector,
                            published_at: published,
                            modified_at: modified,
                            references: Vec::new(),
                        };

                        Ok((cve, cpe_match))
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect();

                Ok(results)
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to query CPE matches: {e}")))
    }

    /// Get database statistics.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    #[allow(
        clippy::cast_sign_loss,
        reason = "COUNT(*) always returns non-negative i64, safe to cast to u64"
    )]
    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        let (cve_count, cpe_match_count, epss_count, kev_count) = self
            .conn
            .call(|conn| {
                let cve_count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM cve", [], |row| row.get(0))
                    .map_err(tokio_rusqlite::Error::from)?;
                let cpe_match_count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM cpe_match", [], |row| row.get(0))
                    .map_err(tokio_rusqlite::Error::from)?;
                let epss_count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM epss", [], |row| row.get(0))
                    .map_err(tokio_rusqlite::Error::from)?;
                let kev_count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM kev", [], |row| row.get(0))
                    .map_err(tokio_rusqlite::Error::from)?;
                Ok((cve_count, cpe_match_count, epss_count, kev_count))
            })
            .await
            .map_err(|e| VulnError::database(format!("Failed to query stats: {e}")))?;

        Ok(DatabaseStats {
            cve_count: cve_count as u64,
            cpe_count: cpe_match_count as u64,
            epss_count: epss_count as u64,
            kev_count: kev_count as u64,
        })
    }

    /// Run database vacuum to optimize size.
    ///
    /// # Errors
    ///
    /// Returns an error if vacuum fails.
    pub async fn vacuum(&self) -> Result<()> {
        self.conn
            .call(|conn| {
                conn.execute("VACUUM", [])
                    .map_err(tokio_rusqlite::Error::from)?;
                Ok(())
            })
            .await
            .map_err(|e| VulnError::database(format!("Vacuum failed: {e}")))
    }
}

/// Database statistics.
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    /// Number of CVE entries.
    pub cve_count: u64,
    /// Number of CPE match entries.
    pub cpe_count: u64,
    /// Number of EPSS entries.
    pub epss_count: u64,
    /// Number of KEV entries.
    pub kev_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_creation() {
        let db = VulnDatabase::open_in_memory().await.unwrap();
        let stats = db.get_stats().await.unwrap();
        assert_eq!(stats.cve_count, 0);
    }

    #[tokio::test]
    async fn test_insert_and_query_cve() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test vulnerability".to_string(),
            cvss_v3_base: Some(9.8),
            cvss_v3_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
            published_at: Utc::now(),
            modified_at: None,
            references: vec!["https://example.com".to_string()],
        };

        db.insert_cve(&cve).await.unwrap();

        let result = db.get_cve("CVE-2024-1234").await.unwrap().unwrap();
        assert_eq!(result.id, "CVE-2024-1234");
        assert_eq!(result.cvss_v3_base, Some(9.8));
    }

    #[tokio::test]
    async fn test_insert_and_query_epss() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

        // Insert CVE first (foreign key requirement)
        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test".to_string(),
            cvss_v3_base: None,
            cvss_v3_vector: None,
            published_at: Utc::now(),
            modified_at: None,
            references: vec![],
        };
        db.insert_cve(&cve).await.unwrap();

        let epss = EpssRecord {
            cve_id: "CVE-2024-1234".to_string(),
            epss_score: 0.85,
            percentile: 0.95,
            date: "2024-01-15".to_string(),
        };

        db.insert_epss(&epss).await.unwrap();

        let result = db.get_epss("CVE-2024-1234").await.unwrap().unwrap();
        assert!((result.epss_score - 0.85).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_insert_and_query_kev() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

        // Insert CVE first (foreign key requirement)
        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test".to_string(),
            cvss_v3_base: None,
            cvss_v3_vector: None,
            published_at: Utc::now(),
            modified_at: None,
            references: vec![],
        };
        db.insert_cve(&cve).await.unwrap();

        let kev = KevEntry {
            cve_id: "CVE-2024-1234".to_string(),
            vendor_project: "Apache".to_string(),
            product: "HTTP Server".to_string(),
            date_added: "2024-01-15".to_string(),
            required_action: "Apply update".to_string(),
            due_date: "2024-02-15".to_string(),
            notes: None,
        };

        db.insert_kev(&kev).await.unwrap();

        let result = db.get_kev("CVE-2024-1234").await.unwrap().unwrap();
        assert_eq!(result.vendor_project, "Apache");
    }
}
