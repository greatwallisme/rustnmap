# Scan Management Module (rustnmap-scan-management)

> **Version**: 2.0.0 (In Development)
> **Phase**: Phase 3 (Week 8-9)
> **Priority**: P1

---

## Overview

The scan management module provides persistent storage of scan results, historical queries, result diffing, and configuration profile management. This is a key component in upgrading RustNmap 2.0 from a one-shot scanning tool to a continuous security monitoring platform.

---

## Features

### 1. Scan Result Persistence

- Store historical scan results using SQLite
- Query by time, target, or scan type
- Optional automatic cleanup of expired data

### 2. Scan Result Diff

- Compare differences between two scan results
- Identify newly discovered and disappeared hosts
- Detect port changes and service version changes
- Identify newly discovered vulnerabilities

### 3. Scan History Queries

- Query by time range
- Query by target
- Query by scan type
- Export history records

### 4. Configuration as Code (YAML Profiles)

- YAML-format configuration files
- Support inheritance and overrides
- Version control and reuse

---

## Database Design

### Schema

```sql
-- Scan task table
CREATE TABLE IF NOT EXISTS scans (
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
);

-- Host results table
CREATE TABLE IF NOT EXISTS host_results (
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
);

-- Port results table
CREATE TABLE IF NOT EXISTS port_results (
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
);

-- Vulnerability results table
CREATE TABLE IF NOT EXISTS vulnerability_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    cvss_v3 REAL,
    epss_score REAL,
    is_kev BOOLEAN DEFAULT FALSE,
    affected_cpe TEXT,
    FOREIGN KEY (host_id) REFERENCES host_results(id)
);

-- Indexes
CREATE INDEX idx_scans_started_at ON scans(started_at);
CREATE INDEX idx_scans_target ON scans(target_spec);
CREATE INDEX idx_host_results_ip ON host_results(ip_addr);
CREATE INDEX idx_port_results_state ON port_results(state);
CREATE INDEX idx_vulnerability_cve ON vulnerability_results(cve_id);
CREATE INDEX idx_vulnerability_kev ON vulnerability_results(is_kev);
```

---

## Core API

### ScanHistory (Historical Queries)

```rust
/// Scan history manager
pub struct ScanHistory {
    db: Arc<SqliteConnection>,
}

impl ScanHistory {
    /// Open or create database
    pub async fn open(db_path: &Path) -> Result<Self>;

    /// Save scan result
    pub async fn save_scan(&self, result: &ScanResult) -> Result<String>;

    /// List scans with filter
    pub async fn list_scans(&self, filter: ScanFilter) -> Result<Vec<ScanSummary>>;

    /// Get scan details
    pub async fn get_scan(&self, id: &str) -> Result<ScanResult>;

    /// Get historical scans for a target
    pub async fn get_target_history(&self, target: &str) -> Result<Vec<ScanSummary>>;

    /// Delete expired scans
    pub async fn prune_old_scans(&self, retention_days: u32) -> Result<usize>;
}

/// Scan filter
pub struct ScanFilter {
    /// Time range start
    pub since: Option<DateTime<Utc>>,

    /// Time range end
    pub until: Option<DateTime<Utc>>,

    /// Target filter
    pub target: Option<String>,

    /// Scan type filter
    pub scan_type: Option<ScanType>,

    /// Status filter
    pub status: Option<ScanStatus>,

    /// Results per page
    pub limit: Option<usize>,

    /// Offset
    pub offset: Option<usize>,
}
```

### ScanDiff (Result Comparison)

```rust
/// Scan comparison tool
pub struct ScanDiff {
    before: ScanResult,
    after: ScanResult,
}

impl ScanDiff {
    /// Create comparison
    pub fn new(before: ScanResult, after: ScanResult) -> Self;

    /// Load from database and compare
    pub async fn from_history(
        history: &ScanHistory,
        before_id: &str,
        after_id: &str
    ) -> Result<Self>;

    /// Get host changes
    pub fn host_changes(&self) -> HostChanges;

    /// Get port changes
    pub fn port_changes(&self) -> PortChanges;

    /// Get vulnerability changes
    pub fn vulnerability_changes(&self) -> VulnerabilityChanges;

    /// Generate comparison report
    pub fn generate_report(&self, format: DiffFormat) -> String;
}

/// Host changes
pub struct HostChanges {
    /// Newly discovered hosts
    pub added: Vec<IpAddr>,

    /// Disappeared hosts
    pub removed: Vec<IpAddr>,

    /// Hosts with status changes
    pub status_changed: Vec<HostStatusChange>,
}

/// Port changes
pub struct PortChanges {
    /// Port changes per host
    pub by_host: HashMap<IpAddr, HostPortChanges>,
}

pub struct HostPortChanges {
    /// Newly opened ports
    pub added: Vec<PortChange>,

    /// Closed ports
    pub removed: Vec<PortChange>,

    /// Ports with state changes
    pub state_changed: Vec<PortChange>,

    /// Ports with service version changes
    pub service_changed: Vec<PortChange>,
}

/// Vulnerability changes
pub struct VulnerabilityChanges {
    /// Newly discovered vulnerabilities
    pub added: Vec<VulnChange>,

    /// Fixed vulnerabilities
    pub fixed: Vec<VulnChange>,

    /// Vulnerabilities with risk level changes
    pub risk_changed: Vec<VulnChange>,
}
```

### ScanProfile (Configuration Management)

```rust
/// Scan configuration profile
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanProfile {
    /// Profile name
    pub name: String,

    /// Profile description
    pub description: Option<String>,

    /// Target list
    pub targets: Vec<String>,

    /// Excluded targets
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Scan configuration
    pub scan: ScanConfig,

    /// Output configuration
    pub output: OutputConfig,

    /// Inherited profile
    #[serde(rename = "extends")]
    pub extends_from: Option<String>,
}

/// Scan configuration
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanConfig {
    /// Scan type
    #[serde(rename = "type")]
    pub scan_type: String,

    /// Port range
    pub ports: Option<String>,

    /// Service detection
    #[serde(default)]
    pub service_detection: bool,

    /// OS detection
    #[serde(default)]
    pub os_detection: bool,

    /// NSE scripts
    #[serde(default)]
    pub scripts: Vec<String>,

    /// Vulnerability scanning
    #[serde(default)]
    pub vulnerability_scan: bool,

    /// Timing template
    #[serde(default = "default_timing")]
    pub timing: String,
}

impl ScanProfile {
    /// Load from file
    pub fn from_file(path: &Path) -> Result<Self>;

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()>;

    /// Parse from string
    pub fn from_yaml(yaml: &str) -> Result<Self>;

    /// Validate configuration
    pub fn validate(&self) -> Result<()>;

    /// Apply default values
    pub fn with_defaults(mut self) -> Self;
}
```

---

## CLI Options

### History Queries

```bash
# List all scans
rustnmap --history

# List recent scans
rustnmap --history --limit 10

# Query by time range
rustnmap --history --since 2026-01-01 --until 2026-02-01

# Query by target
rustnmap --history --target 192.168.1.10

# View scan details
rustnmap --history --scan-id scan_001
```

### Scan Comparison

```bash
# Compare two scans
rustnmap --diff scan_20240101.xml scan_20240201.xml

# Compare from database
rustnmap --diff --from-history scan_001 scan_002

# Generate detailed report
rustnmap --diff scan_001 scan_002 --format markdown --output diff.md

# Show only vulnerability changes
rustnmap --diff scan_001 scan_002 --vulns-only
```

### Configuration Profiles

```bash
# Scan using a profile
rustnmap --profile scan-profiles/weekly-internal.yaml

# List available profiles
rustnmap --list-profiles

# Validate a profile
rustnmap --validate-profile scan-profiles/weekly-internal.yaml

# Generate a profile template
rustnmap --generate-profile > my-scan.yaml
```

---

## Usage Examples

### Saving Scan Results

```rust
use rustnmap_sdk::{Scanner, ScanHistory};

#[tokio::main]
async fn main() -> Result<()> {
    let scanner = Scanner::new()?;

    // Execute scan
    let result = scanner
        .targets(["192.168.1.0/24"])
        .syn_scan()
        .service_detection(true)
        .run()
        .await?;

    // Save to database
    let history = ScanHistory::open("~/.rustnmap/scans.db").await?;
    let scan_id = history.save_scan(&result).await?;

    println!("Scan saved with ID: {}", scan_id);

    Ok(())
}
```

### Comparing Scan Results

```rust
use rustnmap_sdk::{ScanHistory, ScanDiff, DiffFormat};

#[tokio::main]
async fn main() -> Result<()> {
    let history = ScanHistory::open("~/.rustnmap/scans.db").await?;

    // Get the two most recent scans
    let scans = history.list_scans(ScanFilter {
        target: Some("192.168.1.0/24".to_string()),
        limit: Some(2),
        ..Default::default()
    }).await?;

    if scans.len() < 2 {
        println!("Need at least 2 scans for comparison");
        return Ok(());
    }

    // Load and compare
    let before = history.get_scan(&scans[1].id).await?;
    let after = history.get_scan(&scans[0].id).await?;

    let diff = ScanDiff::new(before, after);

    // Output comparison report
    let host_changes = diff.host_changes();
    println!("=== Host Changes ===");
    println!("Added: {:?}", host_changes.added);
    println!("Removed: {:?}", host_changes.removed);

    let vuln_changes = diff.vulnerability_changes();
    println!("\n=== Vulnerability Changes ===");
    println!("New vulnerabilities: {}", vuln_changes.added.len());
    for vuln in &vuln_changes.added {
        println!("  - {} (CVSS {})", vuln.cve_id, vuln.new_cvss);
    }

    Ok(())
}
```

### Using Configuration Profiles

```rust
use rustnmap_sdk::{Scanner, ScanProfile};

#[tokio::main]
async fn main() -> Result<()> {
    // Load profile
    let profile = ScanProfile::from_file("scan-profiles/weekly-internal.yaml")?;

    // Validate configuration
    profile.validate()?;

    // Execute scan
    let scanner = Scanner::new()?;
    let result = scanner
        .from_profile(profile)
        .run()
        .await?;

    println!("Scan completed: {} hosts up", result.statistics.hosts_up);

    Ok(())
}
```

---

## Configuration File Examples

### Weekly Internal Network Scan

```yaml
# scan-profiles/weekly-internal.yaml
name: Weekly Internal Network Scan
description: Weekly internal network security baseline check
targets:
  - 192.168.0.0/16
  - 10.0.0.0/8
exclude:
  - 10.0.0.1  # Gateway, skip
scan:
  type: syn
  ports: "1-10000"
  service_detection: true
  os_detection: true
  scripts: ["default", "vuln"]
  timing: T3
output:
  formats: [json, html, sarif]
  directory: /var/lib/rustnmap/reports/
  save_to_history: true
```

### Quick Port Scan

```yaml
# scan-profiles/quick-scan.yaml
name: Quick Scan
description: Fast check of common ports
targets: []  # Specify from command line
scan:
  type: syn
  ports: "21,22,23,25,80,443,3306,3389,5432,8080"
  service_detection: false
  os_detection: false
  timing: T4
output:
  formats: [normal]
```

### Full Vulnerability Scan

```yaml
# scan-profiles/full-vuln-scan.yaml
name: Full Vulnerability Scan
description: Comprehensive vulnerability detection scan
targets: []  # Specify from command line
scan:
  type: syn
  ports: "1-65535"
  service_detection: true
  version_intensity: 7
  os_detection: true
  scripts:
    - default
    - vuln
    - exploit
  vulnerability_scan: true
  epss_threshold: 0.3
  timing: T3
output:
  formats: [json, sarif, html]
  save_to_history: true
```

---

## Comparison Report Format

### Markdown Format Example

```markdown
# Scan Result Comparison Report

**Comparison**: scan_20240101 -> scan_20240201
**Generated**: 2026-02-17

## Host Changes

### New Hosts (2)
- 192.168.1.50 (first discovered)
- 192.168.1.51 (first discovered)

### Disappeared Hosts (1)
- 192.168.1.30 (was online previously, no response this time)

## Port Changes

### 192.168.1.10
- New port: 8443/tcp (open)
- Service change: 80/tcp (nginx 1.18.0 -> nginx 1.24.0)

### 192.168.1.15
- Closed port: 21/tcp (closed)

## Vulnerability Changes

### New Vulnerabilities (1)
- CVE-2024-XXXXX (CVSS 8.1) - 192.168.1.10

## Statistics

| Metric | Previous | Current | Change |
|--------|----------|---------|--------|
| Online hosts | 45 | 46 | +1 |
| Open ports | 123 | 124 | +1 |
| Critical vulnerabilities | 5 | 6 | +1 |
```

---

## Performance Optimization

### Batch Insert

```rust
/// Batch save scan results (with transaction)
pub async fn save_scan_batch(&self, result: &ScanResult) -> Result<String> {
    let mut tx = self.db.begin().await?;

    // Save scan metadata
    let scan_id = save_scan_metadata(&mut tx, result).await?;

    // Batch save hosts
    for host in &result.hosts {
        let host_id = save_host(&mut tx, scan_id, host).await?;

        // Batch save ports
        save_ports_batch(&mut tx, host_id, &host.ports).await?;

        // Batch save vulnerabilities
        save_vulnerabilities_batch(&mut tx, host_id, &host.vulnerabilities).await?;
    }

    tx.commit().await?;
    Ok(scan_id)
}
```

### Query Optimization

```sql
-- Use covering index
CREATE INDEX idx_port_results_covering
ON port_results(host_id, state, port, protocol);

-- Use materialized view (simulated with table in SQLite)
CREATE TABLE IF NOT EXISTS mv_host_summary AS
SELECT
    scan_id,
    ip_addr,
    COUNT(*) as port_count,
    SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_port_count
FROM host_results
JOIN port_results ON host_results.id = port_results.host_id
GROUP BY scan_id, ip_addr;
```

---

## Alignment with RETHINK.md

| Section | Corresponding Content |
|---------|----------------------|
| 9.2.1 Scan Diff | Result comparison feature |
| 9.2.2 Result Persistence | SQLite storage |
| 9.2.4 Configuration as Code | YAML Profiles |
| 12.3 Phase 3 | Scan management capabilities (Week 8-9) |
| 14.2 Phase 1-3 | OutputSink and persistence integration |

---

## Next Steps

1. **Week 8**: Implement SQLite database schema and save logic
2. **Week 8**: Implement history query API
3. **Week 9**: Implement diff engine and report generation
4. **Week 9**: Implement YAML profile parsing and validation

---

## References

- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Serde YAML](https://docs.rs/serde_yaml)
- [SQLx (Alternative)](https://docs.rs/sqlx)
