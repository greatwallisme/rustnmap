// rustnmap-scan-management
// Copyright (C) 2026  greatwallisme

//! `SQLite` database operations for scan persistence.

use crate::error::{Result, ScanManagementError};
use crate::models::{ScanStatus, ScanSummary, StoredHost, StoredScan};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use rustnmap_output::ScanResult;
use rustnmap_output::models::ScanType;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Database configuration.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Path to the database file.
    pub path: String,
    /// Enable foreign keys.
    pub foreign_keys: bool,
    /// Journal mode.
    pub journal_mode: String,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            path: "~/.rustnmap/scans.db".to_string(),
            foreign_keys: true,
            journal_mode: "WAL".to_string(),
        }
    }
}

/// Scan database manager.
#[derive(Debug)]
pub struct ScanDatabase {
    conn: Arc<Mutex<Connection>>,
    config: DbConfig,
}

impl ScanDatabase {
    /// Open or create the database.
    pub fn open(config: DbConfig) -> Result<Self> {
        let path = shellexpand::tilde(&config.path).to_string();

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        let conn = Connection::open_with_flags(&path, flags)?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            config,
        };

        db.init_schema()?;
        Ok(db)
    }

    /// Initialize database schema.
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.blocking_lock();

        // Enable foreign keys
        if self.config.foreign_keys {
            conn.execute("PRAGMA foreign_keys = ON", [])?;
        }

        // Set journal mode
        conn.execute_batch(&format!("PRAGMA journal_mode = {}", self.config.journal_mode))?;

        // Create scans table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                command_line TEXT,
                target_spec TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                options_json TEXT,
                status TEXT NOT NULL DEFAULT 'completed',
                created_by TEXT,
                profile_name TEXT
            )",
            [],
        )?;

        // Create host_results table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS host_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip_addr TEXT NOT NULL,
                hostname TEXT,
                mac_addr TEXT,
                status TEXT NOT NULL,
                os_match TEXT,
                os_accuracy INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                UNIQUE(scan_id, ip_addr)
            )",
            [],
        )?;

        // Create port_results table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS port_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                service_version TEXT,
                cpe TEXT,
                reason TEXT,
                FOREIGN KEY (host_id) REFERENCES host_results(id),
                UNIQUE(host_id, port, protocol)
            )",
            [],
        )?;

        // Create vulnerability_results table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vulnerability_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                cvss_v3 REAL,
                epss_score REAL,
                is_kev BOOLEAN DEFAULT FALSE,
                affected_cpe TEXT,
                FOREIGN KEY (host_id) REFERENCES host_results(id)
            )",
            [],
        )?;

        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_spec)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_results_ip ON host_results(ip_addr)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_port_results_state ON port_results(state)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerability_cve ON vulnerability_results(cve_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerability_kev ON vulnerability_results(is_kev)",
            [],
        )?;

        Ok(())
    }

    /// Save scan results to the database.
    pub async fn save_scan(&self, result: &ScanResult, target_spec: &str, created_by: Option<&str>) -> Result<String> {
        let stored_scan = StoredScan::from_scan_result(result, target_spec, created_by);

        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;

        // Insert scan metadata
        tx.execute(
            "INSERT INTO scans (id, started_at, completed_at, command_line, target_spec, scan_type, options_json, status, created_by, profile_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                stored_scan.id,
                stored_scan.started_at.to_rfc3339(),
                stored_scan.completed_at.map(|t| t.to_rfc3339()),
                stored_scan.command_line,
                stored_scan.target_spec,
                format!("{:?}", stored_scan.scan_type),
                stored_scan.options_json,
                format!("{:?}", stored_scan.status),
                stored_scan.created_by,
                stored_scan.profile_name,
            ],
        )?;

        // Insert hosts and their ports
        if let Some(scan_result) = &stored_scan.results {
            for host in &scan_result.hosts {
                let stored_host = StoredHost::from_host_result(host, &stored_scan.id);

                tx.execute(
                    "INSERT INTO host_results (scan_id, ip_addr, hostname, mac_addr, status, os_match, os_accuracy)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        stored_host.scan_id,
                        stored_host.ip_addr,
                        stored_host.hostname,
                        stored_host.mac_addr,
                        stored_host.status,
                        stored_host.os_match,
                        stored_host.os_accuracy,
                    ],
                )?;

                let host_id = tx.last_insert_rowid();

                // Insert ports
                for port in &stored_host.ports {
                    tx.execute(
                        "INSERT INTO port_results (host_id, port, protocol, state, service_name, service_version, cpe, reason)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            host_id,
                            port.port,
                            port.protocol,
                            port.state,
                            port.service_name,
                            port.service_version,
                            port.cpe,
                            port.reason,
                        ],
                    )?;
                }
            }
        }

        tx.commit()?;
        Ok(stored_scan.id)
    }

    /// Get scan by ID.
    pub async fn get_scan(&self, id: &str) -> Result<Option<StoredScan>> {
        let conn = self.conn.lock().await;

        let mut stmt = conn.prepare(
            "SELECT id, started_at, completed_at, command_line, target_spec, scan_type, options_json, status, created_by, profile_name
             FROM scans WHERE id = ?1",
        )?;

        let row = stmt.query_row(params![id], |row| {
            let started_at: String = row.get(1)?;
            let completed_at: Option<String> = row.get(2)?;
            let scan_type: String = row.get(5)?;
            let status: String = row.get(7)?;

            let started_dt = DateTime::parse_from_rfc3339(&started_at)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e)))?;

            let completed_dt = completed_at
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e)))
                })
                .transpose()?;

            let parsed_scan_type = parse_scan_type(&scan_type)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))))?;

            let parsed_status = parse_scan_status(&status)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))))?;

            Ok(StoredScan {
                id: row.get(0)?,
                started_at: started_dt,
                completed_at: completed_dt,
                command_line: row.get(3)?,
                target_spec: row.get(4)?,
                scan_type: parsed_scan_type,
                options_json: row.get(6)?,
                status: parsed_status,
                created_by: row.get(8)?,
                profile_name: row.get(9)?,
                results: None,
            })
        });

        match row {
            Ok(scan) => Ok(Some(scan)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List scans with optional filtering.
    pub async fn list_scans(
        &self,
        filter: &crate::history::ScanFilter,
    ) -> Result<Vec<ScanSummary>> {
        let conn = self.conn.lock().await;

        let mut query = String::from(
            "SELECT s.id, s.started_at, s.completed_at, s.target_spec, s.scan_type, s.status,
                    COUNT(DISTINCT h.id) as hosts_count,
                    SUM(CASE WHEN h.status = 'up' THEN 1 ELSE 0 END) as hosts_up,
                    COUNT(DISTINCT p.id) as ports_open,
                    COUNT(DISTINCT v.id) as vulns_count
             FROM scans s
             LEFT JOIN host_results h ON s.id = h.scan_id
             LEFT JOIN port_results p ON h.id = p.host_id
             LEFT JOIN vulnerability_results v ON h.id = v.host_id
             WHERE 1=1"
        );

        let mut params: Vec<String> = Vec::new();
        let mut param_index = 0;

        if let Some(since) = &filter.since {
            query.push_str(&format!(" AND s.started_at >= ?{}", param_index + 1));
            params.push(since.to_rfc3339());
            param_index += 1;
        }

        if let Some(until) = &filter.until {
            query.push_str(&format!(" AND s.started_at <= ?{}", param_index + 1));
            params.push(until.to_rfc3339());
            param_index += 1;
        }

        if let Some(target) = &filter.target {
            query.push_str(&format!(" AND s.target_spec LIKE ?{}", param_index + 1));
            params.push(format!("%{}%", target));
            param_index += 1;
        }

        query.push_str(" GROUP BY s.id");
        query.push_str(" ORDER BY s.started_at DESC");

        if let Some(limit) = &filter.limit {
            query.push_str(&format!(" LIMIT ?{}", param_index + 1));
            params.push(limit.to_string());
        }

        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter().map(std::string::String::as_str)), |row| {
            let started_at: String = row.get(1)?;
            let completed_at: Option<String> = row.get(2)?;
            let scan_type: String = row.get(4)?;
            let status: String = row.get(5)?;

            let started_dt = DateTime::parse_from_rfc3339(&started_at)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e)))?;

            let completed_dt = completed_at
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e)))
                })
                .transpose()?;

            let parsed_scan_type = parse_scan_type(&scan_type)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))))?;

            let parsed_status = parse_scan_status(&status)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))))?;

            Ok(ScanSummary {
                id: row.get(0)?,
                started_at: started_dt,
                completed_at: completed_dt,
                target_spec: row.get(3)?,
                scan_type: parsed_scan_type,
                status: parsed_status,
                hosts_count: row.get(6)?,
                hosts_up: row.get(7)?,
                ports_open: row.get(8)?,
                vulnerabilities_count: row.get(9)?,
                profile_name: None,
            })
        })?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }

        Ok(summaries)
    }

    /// Delete old scans.
    pub async fn prune_old_scans(&self, retention_days: u32) -> Result<usize> {
        let conn = self.conn.lock().await;

        let cutoff = Utc::now() - chrono::Duration::days(i64::from(retention_days));

        // First get IDs to delete (for cascade)
        let mut stmt = conn.prepare("DELETE FROM vulnerability_results WHERE host_id IN (SELECT id FROM host_results WHERE scan_id IN (SELECT id FROM scans WHERE started_at < ?1))")?;
        stmt.execute(params![cutoff.to_rfc3339()])?;

        let mut stmt = conn.prepare("DELETE FROM port_results WHERE host_id IN (SELECT id FROM host_results WHERE scan_id IN (SELECT id FROM scans WHERE started_at < ?1))")?;
        stmt.execute(params![cutoff.to_rfc3339()])?;

        let mut stmt = conn.prepare("DELETE FROM host_results WHERE scan_id IN (SELECT id FROM scans WHERE started_at < ?1)")?;
        stmt.execute(params![cutoff.to_rfc3339()])?;

        let mut stmt = conn.prepare("DELETE FROM scans WHERE started_at < ?1")?;
        let deleted = stmt.execute(params![cutoff.to_rfc3339()])?;

        Ok(deleted)
    }
}

fn parse_scan_type(s: &str) -> Result<ScanType> {
    match s.to_lowercase().as_str() {
        "tcpsyn" | "tcp_syn" | "syn" => Ok(ScanType::TcpSyn),
        "tcpconnect" | "tcp_connect" | "connect" => Ok(ScanType::TcpConnect),
        "tcpfin" | "tcp_fin" | "fin" => Ok(ScanType::TcpFin),
        "tcpnull" | "tcp_null" | "null" => Ok(ScanType::TcpNull),
        "tcpxmas" | "tcp_xmas" | "xmas" => Ok(ScanType::TcpXmas),
        "tcpmaimon" | "tcp_maimon" | "maimon" => Ok(ScanType::TcpMaimon),
        "udp" => Ok(ScanType::Udp),
        "sctpinit" | "sctp_init" | "init" => Ok(ScanType::SctpInit),
        "sctpcookie" | "sctp_cookie" | "cookie" => Ok(ScanType::SctpCookie),
        "ipprotocol" | "ip_protocol" | "ip" => Ok(ScanType::IpProtocol),
        "ping" => Ok(ScanType::Ping),
        "tcpack" | "tcp_ack" | "ack" => Ok(ScanType::TcpAck),
        "tcpwindow" | "tcp_window" | "window" => Ok(ScanType::TcpWindow),
        _ => Err(ScanManagementError::InvalidStatus(format!("Invalid scan type: {}", s))),
    }
}

fn parse_scan_status(s: &str) -> Result<ScanStatus> {
    match s.to_lowercase().as_str() {
        "running" => Ok(ScanStatus::Running),
        "completed" => Ok(ScanStatus::Completed),
        "failed" => Ok(ScanStatus::Failed),
        "cancelled" => Ok(ScanStatus::Cancelled),
        _ => Err(ScanManagementError::InvalidStatus(format!("Invalid scan status: {}", s))),
    }
}
