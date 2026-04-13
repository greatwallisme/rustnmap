# rustnmap-scan-management

Scan persistence, diff, and YAML profiles for RustNmap.

## Purpose

Stores scan results in SQLite, computes diffs between scans to detect changes, and manages YAML scan profiles for reusable configurations.

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| `ScanDatabase` | `database.rs` | SQLite persistence for scan results |
| `ScanDiffer` | `diff.rs` | Diff engine comparing scan results |
| `ScanHistory` | `history.rs` | Historical scan tracking and queries |
| `ProfileManager` | `profile.rs` | YAML scan profile CRUD |

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| rustnmap-output | Output models |
| rustnmap-vuln | Vulnerability data |
| rusqlite | SQLite storage |
| serde_yaml | YAML profile parsing |
| uuid | Scan ID generation |

## Testing

```bash
cargo test -p rustnmap-scan-management
```
