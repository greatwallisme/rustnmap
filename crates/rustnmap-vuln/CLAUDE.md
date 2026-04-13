# rustnmap-vuln

Vulnerability intelligence for RustNmap.

## Purpose

CVE/CPE lookup, EPSS (Exploit Prediction Scoring System), and CISA Known Exploited Vulnerabilities (KEV) feed integration. Backed by SQLite for local caching.

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `VulnDatabase` | `database.rs` | SQLite-backed vulnerability storage |
| `NvdClient` | `client.rs` | NVD API client for CVE lookups |
| `CveProcessor` | `cve.rs` | CVE data parsing and matching |
| `CpeParser` | `cpe.rs` | CPE string parsing |
| `EpssClient` | `epss.rs` | EPSS score lookups |
| `KevClient` | `kev.rs` | CISA KEV feed integration |

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-output | Output models |
| rusqlite / tokio-rusqlite | SQLite storage |
| reqwest | NVD API calls |
| cpe | CPE parsing |
| dashmap | Concurrent cache |

## Testing

```bash
cargo test -p rustnmap-vuln
```
