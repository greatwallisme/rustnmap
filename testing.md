# RustNmap Testing Guide

This document describes how to configure and run tests for RustNmap.

## Test Configuration

Integration tests can be configured via environment variables or a `.env` file in the project root.

### Quick Start

1. Copy the example configuration:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` to match your test environment:
   ```bash
   # Set your test target IP (default: 127.0.0.1)
   TEST_TARGET_IP=192.168.1.100

   # Set open ports on your localhost (default: 22,8501)
   TEST_LOCAL_OPEN_PORTS=22,8080

   # Set closed ports for testing (default: 54321,65432)
   TEST_LOCAL_CLOSED_PORTS=54321,65432
   ```

3. Run tests:
   ```bash
   # Run all tests
   cargo test

   # Run only unit tests (fast, no network)
   cargo test --lib

   # Run integration tests against configured target
   cargo test --test scan_target_test -- --ignored
   ```

## Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_TARGET_IP` | External test target IP address | `127.0.0.1` |
| `TEST_TARGET_PORTS` | Ports to scan on external target | `22,80,443,3389,8080` |
| `TEST_LOCAL_OPEN_PORTS` | Known open ports on localhost | `22,8501` |
| `TEST_LOCAL_CLOSED_PORTS` | Known closed ports on localhost | `54321,65432` |
| `TEST_SCAN_TIMEOUT_SECS` | Scan timeout in seconds | `30` |
| `TEST_MAX_RETRIES` | Maximum retries for discovery | `2` |

## Test Categories

### Unit Tests

Fast, isolated tests that don't require network access:
```bash
cargo test --lib
```

### Localhost Integration Tests

Tests against localhost that require specific ports to be open/closed:
```bash
# Tests that don't require root
cargo test --test tcp_scan_test test_connect_scan

# Tests that require root/CAP_NET_RAW
cargo test --test tcp_scan_test test_syn_scan -- --ignored
```

### External Target Tests

Tests against configured external target (set via `TEST_TARGET_IP`):
```bash
# Configure target in .env first
cargo test --test scan_target_test -- --ignored
```

## Security Notes

- **Never commit `.env` files** - they may contain sensitive network information
- The `.env` file is listed in `.gitignore` by default
- Use `.env.example` as a template and document any required variables

## Troubleshooting

### Tests fail with "no open ports available"

Set `TEST_LOCAL_OPEN_PORTS` to ports actually listening on your localhost:
```bash
# Check what ports are open
ss -tln | grep LISTEN

# Update .env
TEST_LOCAL_OPEN_PORTS=22,8080
```

### Root privilege tests skipped

Tests requiring raw sockets need root or CAP_NET_RAW:
```bash
# Run with sudo
sudo cargo test --test tcp_scan_test test_syn_scan

# Or grant capability to the test binary (persistent)
sudo setcap cap_net_raw+eip target/debug/deps/tcp_scan_test-*
```
