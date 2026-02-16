# rustnmap-cli

Command-line interface for RustNmap network scanner.

## Purpose

Provides the main `rustnmap` binary with argument parsing, progress display, and integration of all workspace crates.

## Key Components

### CLI Arguments

- `Args` - Complete CLI argument structure using `clap`
- 60+ options matching Nmap functionality
- Validation and error handling

### Command Processing

- `Cli` - Main CLI controller
- `run_scan()` - Execute scan with all options
- `build_config()` - Convert Args to ScanConfig

### Output

- Progress bars via `indicatif`
- Colored terminal output via `console`
- Multiple output file handling

### Binary

```
rustnmap [options] <target>
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| clap | Argument parsing |
| console | Terminal colors |
| indicatif | Progress bars |
| rustnmap-common | Common types |
| rustnmap-core | Orchestration |
| rustnmap-target | Target parsing |
| rustnmap-scan | Port scanning |
| rustnmap-fingerprint | Service/OS detection |
| rustnmap-nse | Script engine |
| rustnmap-output | Output formatting |
| rustnmap-evasion | Evasion techniques |
| tokio | Async runtime |
| tracing | Logging |

## Testing

```bash
cargo test -p rustnmap-cli
```

## Usage Examples

```bash
# Basic SYN scan
rustnmap -sS 192.168.1.1

# Full scan with service detection
rustnmap -sS -sV -O 192.168.1.0/24

# With NSE scripts
rustnmap -sV --script=http-title 192.168.1.1

# Multiple output formats
rustnmap -sS -oA scanresults 192.168.1.0/24
```

## Key Options

| Option | Description |
|--------|-------------|
| `-sS` | SYN scan |
| `-sT` | Connect scan |
| `-sU` | UDP scan |
| `-sV` | Service detection |
| `-O` | OS detection |
| `-p` | Port specification |
| `-T<0-5>` | Timing template |
| `--script` | NSE scripts |
| `-oN/-oX/-oJ/-oG` | Output formats |
