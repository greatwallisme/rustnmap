# rustnmap-output

Output formatters for RustNmap network scanner.

## Purpose

Implements all 5 Nmap-compatible output formats with proper serialization and file handling.

## Output Formats

| Format | Extension | Module |
|--------|-----------|--------|
| Normal | `.nmap` | `normal.rs` |
| XML | `.xml` | `xml.rs` |
| JSON | `.json` | `json.rs` |
| Grepable | `.gnmap` | `grepable.rs` |
| Script Kiddie | `.txt` | `script_kiddie.rs` |

## Key Components

### Formatters

- `OutputFormatter` - Common formatter trait
- `NormalFormatter` - Human-readable output
- `XmlFormatter` - Machine-parseable XML
- `JsonFormatter` - JSON output with pretty/compact modes
- `GrepableFormatter` - grep-friendly format
- `ScriptKiddieFormatter` - Leetspeak format (for fun)

### Output Models

- `ScanResult` - Complete scan results
- `HostResult` - Per-host results
- `PortResult` - Per-port results
- `ScriptOutput` - NSE script output

## Dependencies

| Crate | Purpose |
|-------|---------|
| serde | Serialization framework |
| serde_json | JSON output |
| quick-xml | XML output |
| chrono | Timestamps |
| tokio | Async file I/O |

## Testing

```bash
cargo test -p rustnmap-output
```

## Usage

```rust
use rustnmap_output::{XmlFormatter, OutputFormatter};

let formatter = XmlFormatter::new();
let output = formatter.format(&scan_result)?;
```

## Format Differences

- **Normal**: Human-readable, detailed
- **XML**: Best for programmatic parsing
- **JSON**: Modern API-friendly format
- **Grepable**: Single-line per host for shell scripts
- **Script Kiddie**: Fun leetspeak transformation
