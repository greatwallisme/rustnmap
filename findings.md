# Research Findings

> **Updated**: 2026-03-11 03:00
> **Status**: Major Progress - 91% of target achieved

---

## IMPORTANT: User Requirements

1. **Speed must be >= 0.95x of nmap** (within 5%) - Currently 0.91x ❌
2. **Accuracy must match nmap exactly** - Currently 100% ✅

**Current Status**: Close to meeting requirements, need 4% more speed improvement

---

## CURRENT BENCHMARK RESULTS (2026-03-11 03:00)

### After Cwnd Floor + Adaptive Retry Fixes

| Test | rustnmap | nmap | Ratio | Status |
|------|----------|------|-------|--------|
| Fast Scan | 2.62s | 2.38s | **0.91x** | ❌ 9% slower (need 4% improvement) |
| Top Ports | 2.59s | 2.37s | **0.92x** | ❌ 8% slower (need 3% improvement) |
| SYN Scan (3 ports) | 0.53s | 0.72s | **1.36x** | ✅ 36% FASTER |
| Accuracy | 100% | 100% | **1.00x** | ✅ PERFECT |

### Progress Tracking

| Version | Fast Scan | Ratio | Improvement |
|---------|-----------|-------|-------------|
| Initial (200ms clamp) | 4.73s | 0.84x | Baseline |
| Current (cwnd floor + adaptive retry) | 2.62s | 0.91x | +44% |
| Target (0.95x) | 2.26s | 0.95x | Need +14% more |

---

## ROOT CAUSE ANALYSIS - COMPLETED

### Problem 1: Cwnd Collapse (FIXED ✅)

**Root Cause**: Congestion window collapsed to 1 on packet loss, serializing probe sending

**Fix Applied**: Set minimum cwnd floor to 10 (GROUP_INITIAL_CWND)
- Location: `crates/rustnmap-scan/src/ultrascan.rs:454`
- Code: `let new_cwnd = (current_cwnd / 2).max(GROUP_INITIAL_CWND);`
- Rationale: Nmap bypasses group congestion control for single-host scans

**Impact**: 40% performance improvement (6.16s → 3.72s)

### Problem 2: Fixed Retry Limit (FIXED ✅)

**Root Cause**: Fixed max_retries=10 for all ports, wasting time on filtered ports

**Fix Applied**: Adaptive retry limit based on max_successful_tryno
- Location: `crates/rustnmap-scan/src/ultrascan.rs:893-898`
- Logic: `allowedTryno = MAX(1, max_successful_tryno + 1)`
- Rationale: Matches nmap's behavior (scan_engine.cc:675-683)

**Impact**: Reduced retries from 10 to 1-2 for filtered ports

### Problem 3: 200ms Clamp Too Aggressive (FIXED ✅)

**Root Cause**: Initial RTT clamped to 200ms caused timeouts for targets with RTT > 200ms

**Fix Applied**: Removed 200ms clamp, use initial_rtt directly
- Location: `crates/rustnmap-scan/src/ultrascan.rs:195`
- Code: `self.initial_rtt.min(self.max_rtt)` (no 200ms clamp)

**Impact**: Prevents premature timeouts for high-latency targets

---

## ACCURACY VERIFICATION - COMPLETED ✅

### Test: Fast Scan (-F) on 45.33.32.156

**nmap results**:
```
22/tcp  open     ssh
80/tcp  open     http
135/tcp filtered msrpc
139/tcp filtered netbios-ssn
445/tcp filtered microsoft-ds
```

**rustnmap results**:
```
22/tcp  open    ssh
80/tcp  open    http
135/tcp filtered msrpc
139/tcp filtered netbios-ssn
445/tcp filtered microsoft-ds
```

**Conclusion**: ✅ PERFECT ACCURACY - All ports match exactly

---

## REMAINING GAP ANALYSIS

### Fast Scan: 2.62s vs nmap 2.38s

**Gap**: 0.24s (9% slower)
**Target**: 2.26s (0.95x)
**Need**: 0.36s improvement

**Diagnostic Data** (from instrumentation):
- Total: 2.62s
- Send: 2.03ms (0.08%)
- Wait: 2.59s (98.9%)
- Timeout: 0.10ms
- Retry: 0.19ms
- Iterations: 108
- Probes sent: 100
- Timeouts: 8
- Retries: 4

**Analysis**:
- 98.9% of time spent waiting for responses
- Only 0.08% spent sending packets
- Bottleneck is in the wait/timeout logic

**Possible Optimization Areas**:
1. **Timeout calculation** - Are we waiting too long?
2. **Polling frequency** - Are we checking responses efficiently?
3. **Response processing** - Any overhead in packet handling?
4. **Congestion control** - Is cwnd still limiting throughput?

---

## NEXT INVESTIGATION NEEDED

### 1. Analyze Wait Time Breakdown

The diagnostic shows 98.9% wait time. Need to understand:
- How much is legitimate network RTT?
- How much is unnecessary waiting?
- Is the polling loop efficient?

### 2. Compare with nmap's Timing

Run nmap with timing diagnostics to see:
- How long does nmap wait?
- What's nmap's polling strategy?
- Any differences in timeout calculation?

### 3. Profile the Wait Loop

Add more detailed instrumentation:
- Time per poll iteration
- Number of polls per response
- Overhead of each poll

---

## FILES MODIFIED

| File | Change | Status |
|------|--------|--------|
| `ultrascan.rs:454` | Cwnd floor = 10 | Committed |
| `ultrascan.rs:893-898` | Adaptive retry | Committed |
| `ultrascan.rs:195` | Remove 200ms clamp | Committed |
| `ultrascan.rs:925-935, 1179-1188` | Fix diagnostic behind feature flag | Pending commit |
| `task_plan.md` | Updated status | Updated |
| `progress.md` | Updated log | Updated |
| `findings.md` | This file | Updated |

---

## Session 2026-03-11: Diagnostic Output Fix

### Problem Discovered

During verification testing, rustnmap was performing **below expectations** (0.86x instead of expected 1.00x). Investigation revealed that **diagnostic output code was NOT behind the `#[cfg(feature = "diagnostic")]` feature flag**.

### Root Cause

The following diagnostic code was **always executing**:
- `eprintln!("[DIAG] iter=...")` - Every 5 or 100 iterations (hundreds per scan)
- `eprintln!("=== SCAN TIMING DIAGNOSTIC ===")` - At end of scan
- All timing variables (`diag_send_total`, `diag_wait_total`, etc.)

**Impact**: Each `eprintln!` call involves:
1. Formatted string creation
2. System call to write to stderr
3. Potential I/O waiting

This added significant overhead, especially for scans with many iterations.

### Fix Applied

Wrapped all diagnostic code with `#[cfg(feature = "diagnostic")]`:
- Line 925-935: Iteration progress output
- Lines 910-916: Diagnostic variable declarations
- Lines 996-997, 1027, 1030, 1043: Send timing
- Lines 1081, 1149: Wait timing
- Lines 1154-1159: Timeout timing
- Lines 1171-1190: Retry timing
- Lines 1179-1188: Summary output

### Test Results After Fix

| Test Type | nmap avg | rustnmap avg | Ratio | Status |
|-----------|----------|--------------|-------|--------|
| Fast Scan (5 runs) | 3532ms | 3040ms | **1.16x** | ✅ Faster |
| SYN Scan (5 ports) | 747ms | 839ms | **0.89x** | ⚠️ 11% slower |
| SYN Scan (100 ports) | ~2800ms | ~3040ms | **0.92x** | ⚠️ 8% slower |

### Key Findings

1. **rustnmap is more consistent**: 11% variance vs 76% for nmap
2. **Fast Scan meets target**: 1.16x average (but individual runs vary 0.86x - 1.52x)
3. **Small port count scans have higher relative overhead**: SYN scan with 5 ports shows 0.88x

### Remaining Gap

**Small port count scans** (e.g., 5 ports) still show 0.88-0.89x performance. Possible causes:
- Per-scan initialization overhead
- Socket setup/teardown cost
- Less opportunity for parallelism to show benefit

**Next investigation**: Profile per-scan overhead vs per-probe cost.
