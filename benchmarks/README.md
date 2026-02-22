# RustNmap vs Nmap Comparison Tests

This directory contains comprehensive comparison testing between rustnmap and nmap.

## Directory Structure

```
benchmarks/
├── COMPARISON_PLAN.md       # Testing plan and progress tracking
├── README.md                # This file
├── pyproject.toml           # Python dependencies (uv)
├── comparison_test.py       # Main test runner
├── compare_scans.py         # Scan comparison logic
├── test_configs/            # Test configuration TOML files
│   ├── basic_scan.toml
│   ├── service_detection.toml
│   ├── os_detection.toml
│   └── advanced_scan.toml
└── reports/                 # Generated comparison reports (gitignored)
```

## Quick Start

### 1. Install Python Dependencies

```bash
cd benchmarks
uv sync
```

### 2. Configure Target

Edit `../.env` to set your test target:

```bash
# .env file in project root
TEST_TARGET_IP=45.33.32.156
```

### 3. Run Tests

```bash
# Run all comparison tests
just bench-compare

# Run specific test suite
just bench-compare-basic
just bench-compare-service
just bench-compare-os
just bench-compare-advanced

# Run with custom target
just bench-compare-target 192.168.1.1
```

## Test Categories

### Basic Scans
- SYN Scan
- Connect Scan
- UDP Scan
- Fast Scan (top 100 ports)
- Top Ports

### Service Detection
- Version Detection
- Version Detection with Intensity
- Aggressive Scan

### OS Detection
- OS Detection
- OS Detection with Limit
- OS Detection with Guess

### Advanced Scans
- FIN Scan
- NULL Scan
- XMAS Scan
- MAIMON Scan
- Timing Template
- Min/Max Rate

## Report Formats

Tests generate two report formats:

- **Text**: Human-readable summary in `reports/comparison_report_*.txt`
- **JSON**: Machine-readable data in `reports/comparison_report_*.json`

## Python API

You can also run tests programmatically:

```python
import asyncio
from comparison_test import ComparisonTestRunner, TestConfig

async def run_tests():
    config = TestConfig.from_env()
    runner = ComparisonTestRunner(config)
    results = await runner.run_all_tests()
    runner.generate_reports(results)

asyncio.run(run_tests())
```

## Development

### Adding New Test Cases

Edit the TOML files in `test_configs/`:

```toml
[[test_case]]
name = "My New Test"
description = "Test description"
command_template = "{scanner} -sS -p {ports} {target}"
expected_fields = ["PORT", "STATE", "SERVICE"]
```

### Running with uv

```bash
# Install dependencies
uv sync

# Run tests directly
uv run python comparison_test.py --suite basic

# Run with verbose output
uv run python comparison_test.py -v
```

## Notes

- Tests require sudo privileges for raw socket operations
- The rustnmap and nmap binaries are already configured in `/etc/sudoers`
- Test timeout is configurable via `SCAN_TIMEOUT` in `.env`
- Performance metrics include speedup factor comparing rustnmap vs nmap
