# RustNmap Benchmark Test Suite

This directory contains comprehensive testing infrastructure for rustnmap, including comparison tests against nmap and standalone CLI validation tests.

---

## Maintenance

- Update test expectations as nmap/rustnmap behavior changes
- Add new CLI options to rustnmap_test.sh as they are implemented
- Keep test suite coverage at 100% of defined test configurations
- Review generated reports in `benchmarks/reports/` after test runs

---

## Notes

- Tests require sudo privileges for raw socket operations
- The rustnmap and nmap binaries are already configured in `/etc/sudoers`
- 5-second delays between scans for reliability
- No external dependencies required for shell scripts
- Test configurations remain in TOML files for consistency

---

## Directory Structure

```
benchmarks/
├── README.md                # This file
├── comparison_test.sh       # rustnmap vs nmap comparison tests (41 tests)
├── rustnmap_test.sh         # rustnmap CLI validation tests (104 tests)
├── test_configs/            # Test configuration TOML files
│   ├── basic_scan.toml
│   ├── service_detection.toml
│   ├── os_detection.toml
│   ├── advanced_scan.toml
│   ├── stealth_extended.toml
│   ├── timing_tests.toml
│   ├── output_formats.toml
│   └── multi_target.toml
├── logs/                    # Test execution logs (gitignored)
├── reports/                 # Generated test reports (gitignored)
└── test_outputs/            # Output files from format tests (gitignored)
```

## Test Scripts Comparison

| Feature | comparison_test.sh | rustnmap_test.sh |
|---------|-------------------|------------------|
| **Purpose** | Compare rustnmap vs nmap | Test rustnmap CLI only |
| **Tests** | 41 comparison tests | 104 CLI option tests |
| **Coverage** | Common scan types | ALL 85 CLI options |
| **Focus** | Functional parity | Comprehensive CLI validation |
| **Output** | Pass/fail comparison | Individual option validation |

---

## Quick Start

### 1. Configure Target (Optional)

```bash
# Default test target (scanme.nmap.org)
export TARGET_IP="${TARGET_IP:-45.33.32.156}"

# Alternate target (localhost for testing)
export ALT_TARGET="${ALT_TARGET:-127.0.0.1}"

# Custom ports
export TEST_PORTS="${TEST_PORTS:-22,80,113,443,8080}"
```

### 2. Build rustnmap

```bash
cargo build --release
```

### 3. Run Tests

```bash
# Comparison tests (rustnmap vs nmap)
./benchmarks/comparison_test.sh

# Standalone rustnmap CLI tests
./benchmarks/rustnmap_test.sh

# Custom target/ports
TARGET_IP=192.168.1.1 ./benchmarks/comparison_test.sh
TEST_PORTS="22,80,443" ./benchmarks/comparison_test.sh
```

---

## Test Suite 1: comparison_test.sh

Compares rustnmap output against nmap to verify functional parity.

### Usage

```bash
# Run all 41 comparison tests
./benchmarks/comparison_test.sh

# Custom target/ports
TARGET_IP=192.168.1.1 ./benchmarks/comparison_test.sh
TEST_PORTS="22,80,443" ./benchmarks/comparison_test.sh
```

### Test Categories (41 tests)

| Category | Tests | Description |
|----------|-------|-------------|
| Basic Scans | 5 | SYN, Connect, UDP, Fast, Top Ports |
| Stealth Scans | 6 | FIN, NULL, XMAS, MAIMON, ACK, Window |
| Advanced Scans | 6 | Evasion techniques (decoy, source port, fragment) |
| Timing Templates | 6 | T0-T5 timing levels |
| Output Formats | 5 | Normal, XML, Grepable, JSON, List |
| Multi-Target | 5 | Range, hostlist, exclude, randomize |
| Service Detection | 4 | Version detection, intensity, aggressive |
| OS Detection | 4 | OS detection, limit, guess |

### Output

- **Logs**: `logs/comparison_*.log` - Detailed execution logs
- **Reports**: `reports/comparison_report_*.txt` - Pass/fail summary

### Test Interpretation

Each test compares:
- **Port States**: OPEN, CLOSED, FILTERED, UNFILTERED, OPEN|FILTERED
- **Service Detection**: Version information accuracy
- **Performance**: Execution time comparison

A test passes when both scanners produce equivalent port states.

---

## Test Suite 2: rustnmap_test.sh

Validates ALL 85 rustnmap CLI options across 12 categories.

### Usage

```bash
# Run all 104 CLI tests
./benchmarks/rustnmap_test.sh

# Custom target
TARGET_IP=192.168.1.1 ./benchmarks/rustnmap_test.sh

# Custom ports
TEST_PORTS="22,80,443" ./benchmarks/rustnmap_test.sh
```

### Test Coverage (104 tests covering 85 CLI options)

| Category | CLI Options | Tests |
|----------|-------------|-------|
| 1. Target Specification | 5 | 5 |
| 2. Scan Types | 9 | 9 |
| 3. Port Specification | 6 | 7 |
| 4. Service/OS Detection | 6 | 8 |
| 5. Timing/Performance | 6 | 11 |
| 6. Firewall/IDS Evasion | 9 | 8 |
| 7. Output Formats | 18 | 21 |
| 8. Scripting (NSE) | 4 | 5 |
| 9. Miscellaneous | 9 | 9 |
| 10. Scan Management 2.0 | 14 | 8 |
| 11. Configuration | 2 | 2 |
| 12. Edge Cases/Validation | - | 11 |

### Detailed Test Categories

#### 1. Target Specification (5 tests)
Single IP, hostname, CIDR notation, range, multiple targets

#### 2. Scan Types (9 tests)
`-sS` SYN, `-sT` Connect, `-sU` UDP, `-sF` FIN, `-sN` NULL, `-sX` XMAS, `-sM` MAIMON, `-sA` ACK, `-sW` Window

#### 3. Port Specification (7 tests)
`-p` specific ports, `-p-` all ports, `--exclude-port`, `--top-ports`, `-F` fast scan, `--protocol`

#### 4. Service/OS Detection (8 tests)
`-A` aggressive, `-sV` service detection, `--version-intensity` (0-9), `-O` OS detection, `--osscan-limit`, `--osscan-guess`

#### 5. Timing/Performance (11 tests)
`-T0` through `-T5` timing templates, `--scan-delay`, `--min-parallelism`, `--max-parallelism`, `--min-rate`, `--max-rate`

#### 6. Firewall/IDS Evasion (8 tests)
`-D` decoy, `-S` spoof IP, `-e` interface, `-f` fragment, `-g` source port, `--data-length`, `--data-hex`, `--data-string`

#### 7. Output Formats (21 tests)
`-oN/-oX/-oG/-oJ/-oA` output files, `--output-ndjson`, `--output-markdown`, `--output-script-kiddie`, `--no-output`, `--stream`, `--append-output`, `-v/-vv/-vvv` verbose, `-q` quiet, `-d/-dd/-ddd` debug, `--reasons`, `--open`, `--packet-trace`, `--if-list`

#### 8. Scripting (5 tests)
`--script`, `--script-args`, `--script-help`, `--script-updatedb`

#### 9. Miscellaneous (9 tests)
`--traceroute`, `--traceroute-hops`, `-i` input file, `--randomize-hosts`, `--host-group-size`, `--ping-type`, `--disable-ping`, `--host-timeout`, `--print-urls`

#### 10. Scan Management 2.0 (8 tests)
`--list-profiles`, `--generate-profile`, `--validate-profile`, `--history`, `--history --target`, `--history --scan-type-filter`, `--history --since/--until`, `--history --db-path`

#### 11. Configuration (2 tests)
`--datadir`, `--dns-server`

#### 12. Edge Cases (11 tests)
Invalid input validation (timing, intensity, MTU, port conflicts), boundary value tests

### Output

- **Logs**: `logs/rustnmap_test_*.log` - Detailed execution logs
- **Reports**: `reports/rustnmap_test_report_*.txt` - Summary with pass/fail
- **Test Outputs**: `test_outputs/` - Generated output files (XML, JSON, etc.)

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_IP` | 45.33.32.156 | Primary test target (scanme.nmap.org) |
| `ALT_TARGET` | 127.0.0.1 | Alternate target for local tests |
| `TEST_PORTS` | 22,80,113,443,8080 | Ports to test |
| `RUSTNMAP_BIN` | ./target/release/rustnmap | Path to rustnmap binary |
| `NMAP_BIN` | /usr/bin/nmap | Path to nmap binary (comparison tests only) |

---

## Development

### Adding New Tests

**comparison_test.sh**: Tests are organized by suite functions. Add new tests to the appropriate function.

**rustnmap_test.sh**: Add tests to category functions:

```bash
run_test "Description" \
    "sudo $RUSTNMAP_BIN --new-option value target"
```

### Running Specific Categories

For development, comment out other test categories in `main()`:

```bash
main() {
    cargo build --release
    # Only run specific category
    test_timing_performance
    # Generate report
}
```
