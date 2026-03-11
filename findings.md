# Research Findings

> **Updated**: 2026-03-10 22:55
> **Status**: Congestion Control Root Cause Identified - Partial Fix Applied

---

## POST-REFACTORING PERFORMANCE ANALYSIS (2026-03-10)

### Benchmark Results

**Test**: `./benchmarks/comparison_test.sh`
**Date**: 2026-03-10 22:22
**Results**: 39 tests, 38 passed, 97.4% pass rate

### Critical Performance Findings

#### 1. Single Target Optimization Recovery - FAILED

**Expected**: 20-23% improvement over nmap (historical obs #2049)
**Actual**: 10% slower than nmap

| Metric | Value | Notes |
|--------|-------|-------|
| rustnmap (after fix) | 825ms | Average 3 runs |
| nmap baseline | 747ms | Average 3 runs |
| **Gap** | **78ms slower** | 10.4% slower, not faster |

**Conclusion**: The previously effective optimization no longer provides the expected benefit. Possible reasons:
- Test conditions changed (network, target responsiveness)
- Other bottlenecks emerged
- The optimization was incorrectly recorded or implemented

#### 2. Fast Scan Performance Crisis

**Data**:
```
Test: Fast Scan (-F)
rustnmap: 6352ms (100 ports, 6.11s)
nmap: 3913ms (100 ports, 2.42s)
Ratio: 0.62x (1.6x slower)
Gap: 2439ms (62% slower)
```

**Analysis**:
- Both scan exactly 100 ports
- rustnmap takes 2.5x longer than nmap
- This is NOT a small difference - major architectural issue

**Code Path**:
```
CLI: fast_scan=true → PortSpec::Top(100) → core scanning
```

#### 3. IPv6 Disaster

**Data**:
```
Test: IPv6 (::1)
rustnmap: 258ms
nmap: 47ms
Ratio: 0.18x (5.5x slower)
```

**Conclusion**: IPv6 has the worst performance of all tests

#### 4. Multi-Target Overhead

**Data**:
```
Test: Two Targets
rustnmap: 1643ms
nmap: 774ms
Ratio: 0.47x (2.1x slower)
```

**Analysis**: Processing 2 targets takes 2.1x longer than nmap

---

## CONGESTION CONTROL INVESTIGATION (2026-03-10 22:55)

### Initial Discovery

**File**: `crates/rustnmap-scan/src/ultrascan.rs:428`

**Issue Found**: Using `cwnd = 1` on packet loss (host scan behavior) instead of `cwnd = cwnd / 2` (group scan behavior)

**Fix Attempted**: Changed to group scan behavior matching nmap's `drop_group()`:
```rust
// Before (incorrect):
let new_cwnd = 1;

// After (matches nmap group scan):
let new_cwnd = (current_cwnd / 2).max(1);
```

**Result**: NO PERFORMANCE IMPROVEMENT

| Metric | Before Fix | After Fix | Change |
|--------|------------|-----------|--------|
| Fast Scan time | 6.5s | 6.5s | **0%** |
| Wait time % | 96.6% | 96.6% | **0%** |
| Iterations | 363 | 368 | Worse |

### Diagnostic Data (After Fix)

```
=== TCP SYN Scan Timing ===
Total: 6.3s
Send: 5ms (0.1%)
Wait: 6.1s (96.7%)
Iterations: 363
Packets: 1264
```

**Congestion Window Values**:
- Iteration 1: cwnd=10
- Iteration 50: cwnd=2
- Iteration 100: cwnd=3
- Iteration 150+: cwnd=1
- Iteration 300+: cwnd=5-15

### Conclusion

**This is NOT the root cause**. The congestion control fix is correct (matches nmap's behavior) but does not improve performance, indicating:

1. **Deeper architectural issue exists** - Something else is fundamentally limiting performance
2. **Packet reception problem** - High timeout rate suggests packets not being received properly
3. **Loop structure inefficiency** - 363 iterations for 100 ports is abnormal

### Real Root Cause - STILL UNKNOWN

The 2.6x performance gap (6.5s vs 2.4s) remains UNEXPLAINED.

---

## ROOT CAUSE ANALYSIS FRAMEWORK

### Step 1: Verify What Changed

**Major Refactoring**: lexopt migration (commit 0231d9d)
- Migrated from clap to lexopt
- Affected only rustnmap-cli
- Should not affect core scanning performance

**Potential Issues**:
- CLI argument parsing overhead?
- Default configuration changes?
- Timing template defaults changed?

### Step 2: Compare Scan Characteristics

| Test | Ports Scanned | rustnmap | nmap | Issue |
|------|---------------|----------|------|-------|
| SYN Scan (explicit) | 3 | 865ms | 761ms | ~1.14x slower |
| Fast Scan | 100 | 6352ms | 3913ms | ~1.62x slower |

**Question**: Why is scanning 100 ports so much slower than 3 ports?

### Step 3: Investigate Bottleneck Location

**Historical Data** (obs #2015, #2020):
- Wait time: 63.3% of scan loop time
- Async overhead: 413ms outside scan loop

**Questions**:
1. Is rustnmap using more aggressive timeouts for Fast Scan?
2. Is there per-port setup overhead?
3. Are packets being sent at the same rate as nmap?

---

## OPEN QUESTIONS

1. **Why does Fast Scan (100 ports) perform so much worse than SYN Scan (3 ports)?**
   - 100 ports: 6352ms = 63.5ms/port
   - 3 ports: 865ms = 288ms/port
   - Should be faster per-port for larger scans, not slower

2. **What timing configuration does nmap use for Fast Scan?**
   - Does nmap automatically use T4/T5 for Fast Scan?
   - Does rustnmap use T3 (default)?

3. **Why is IPv6 5.5x slower than nmap?**
   - Socket creation overhead?
   - Different packet handling path?
   - DNS resolution?

4. **Why did the single-target optimization stop working?**
   - Different network conditions?
   - Implementation issue?
   - Was it ever actually effective?

---

## REFERENCE: Nmap Fast Scan Behavior

Need to investigate:
1. Does nmap change timing template for `-F`?
2. Does nmap use different send rates?
3. Does nmap batch port probes differently?

**Research Method**:
```bash
# Check nmap timing with -F
nmap -sS -F -v 45.33.32.156 2>&1 | grep -i timing

# Check scan delay
nmap -sS -F -v 45.33.32.156 2>&1 | grep -i delay

# Check packet rate
nmap -sS -F -v 45.33.32.156 2>&1 | grep -i rate
```

---

## FILES TO INVESTIGATE

1. **Timing Configuration**
   - `crates/rustnmap-cli/src/cli.rs` - build_config
   - `crates/rustnmap-core/src/orchestrator.rs` - run_host_discovery
   - `crates/rustnmap-core/src/timing.rs` - timing templates

2. **Port List Processing**
   - `crates/rustnmap-target/src/top_ports.rs` - TopN port list
   - `crates/rustnmap-cli/src/cli.rs` - parse_port_spec

3. **IPv6 Handling**
   - `crates/rustnmap-net/src/` - Socket creation
   - `crates/rustnmap-packet/src/` - Packet construction

---

## ARCHIVE

### API Module Completion (2026-03-10)
- ✅ Phase 1-8: All complete
- 93 tests passing
- Zero warnings/errors
- Shell test script working

### CLI Compatibility (2026-03-10)
- ✅ Fixed compound short options (-sS, -sT, -sU, etc.)
- ✅ Fixed long options (-oX, -oG, --exclude-ports, etc.)
- ✅ Benchmark script updated to use nmap-compatible options

### Previous Session Archive
See earlier sections for database integration, NSE fixes, etc.
