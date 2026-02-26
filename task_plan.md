# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-26 15:20
**Status**: Phase 26 COMPLETE - All stealth scans passing, RND decoy support implemented

---

## Final Benchmark Results (2026-02-26 15:17)

**Overall**: 39/41 tests passed (95.1%)

### Extended Stealth Scans - 7/7 PASS

| Scan Type | rustnmap | nmap | Speedup | Status |
|-----------|----------|------|---------|--------|
| FIN Scan | 1594ms | 4796ms | **3.01x** | PASS |
| NULL Scan | 1591ms | 6493ms | **4.08x** | PASS |
| XMAS Scan | 1646ms | 4814ms | **2.92x** | PASS |
| MAIMON Scan | 1568ms | 5552ms | **3.54x** | PASS |
| ACK Scan | 635ms | 662ms | **1.04x** | PASS |
| Window Scan | 606ms | 805ms | **1.33x** | PASS |
| Stealth with Decoys | 834ms | 798ms | 0.96x | PASS |

### Known Non-Issues

| Test | Status | Reason |
|------|--------|--------|
| JSON Output | FAIL | nmap doesn't support JSON (exit=255) - test config issue |

---

## Phase 26: RND Decoy Support - COMPLETE

### Problem

The stealth scan with decoys test failed because rustnmap didn't support nmap's `RND:number` syntax:
- nmap command: `nmap -sS -D RND:10 -p 22,80 45.33.32.156`
- rustnmap command: `rustnmap --scan-syn -D RND:10 -p 22,80 45.33.32.156`
- rustnmap exited with code 1 (parse error)

### Solution

Modified `parse_decoy_ips` function in `crates/rustnmap-cli/src/cli.rs` to:
1. Parse `RND:number` syntax to generate random decoy IP addresses
2. Generate public IP addresses (avoid reserved ranges)
3. Use deterministic random generation based on time and PID

### Files Modified

- `crates/rustnmap-cli/src/cli.rs` - Added RND:number parsing in `parse_decoy_ips`
- `crates/rustnmap-cli/src/args.rs` - Added RND:number validation in `Args::validate`
- `crates/rustnmap-scan/src/stealth_scans.rs` - Removed unfulfilled lint expectation

---

## Phase 25: ACK/Window Batch Scanning - COMPLETE

### Test Results (2026-02-26 14:52)

All stealth scan types now pass with speed improvements over nmap.

### Key Fixes

1. Added `parse_tcp_response_with_window` function for Window scan
2. Implemented `scan_ports_batch` for TcpAckScanner and TcpWindowScanner
3. Fixed response matching logic using response source port

---

## Historical Phases

### Phase 24: ACK/Window Verification - COMPLETE
### Phase 23: ACK/Window Receive Loop - COMPLETE
### Phase 22: Test Log Analysis - COMPLETE
### Phase 21: Benchmark Failure Analysis - COMPLETE
### Phase 20: 50-probe Batch Limit - COMPLETE
### Phase 19: Small Port Scan Optimization - FAILED (wrong approach)
### Phase 18: cc_scale Implementation - COMPLETE
### Phase 17: Nmap Database Integration - COMPLETE
