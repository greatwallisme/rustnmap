# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-03-03 16:00
**Status**: Phase 38 - T1 FIXED, UDP FAILED

---

## Phase 38: Timing and Performance Fixes (2026-03-03)

### ✅ T1 Sneaky Timing - FIXED

**Bug Location:** `crates/rustnmap-core/src/orchestrator.rs` and `crates/rustnmap-scan/src/ultrascan.rs`

**Root Causes:**
1. orchestrator.rs using wrong scan_delay source (session.config vs timing_config)
2. enforce_scan_delay() first probe delay bug

**Solution:**
1. Fixed orchestrator.rs to use `timing_config.scan_delay`
2. Fixed enforce_scan_delay() to return immediately on first call
3. Changed `last_probe_send_time` to `Option<Instant>`

**Verification:**
- nmap T1 (2 ports): 76.12s
- rustnmap T1 (2 ports): 76.85s
- **Status: ✅ PASS (difference < 1s)**

### ❌ UDP Scan Performance - FAILED

**Problem:** UDP scan is 30x slower than nmap

**Measured Results:**
| Metric | rustnmap | nmap | Gap |
|--------|----------|------|-----|
| 1 port UDP | 20.40s | ~0.7s | **30x slower** |
| 3 ports UDP | 61.83s | 3.08s | **20x slower** |

**What Was Tried:**
1. Fixed `recommended_timeout()` to use `initial_rtt` (1000ms) for first probe instead of SRTT + 4*RTTVAR (5000ms)
2. Result: Improved from 63s to 20s (3x faster), but still **30x slower than nmap**

**Root Cause Analysis (Incomplete):**
- Fixed the first probe timeout, but nmap is still much faster
- Possible remaining issues:
  - nmap might use fewer retries for UDP
  - nmap might reduce timeout faster after no responses
  - Different retry strategy
  - Other implementation differences

**Status:** ❌ FAILED - Did NOT achieve nmap parity

### Files Modified

- `crates/rustnmap-core/src/orchestrator.rs` - Fixed scan_delay source
- `crates/rustnmap-scan/src/ultrascan.rs` - Fixed enforce_scan_delay() and recommended_timeout()

---
1. Fixed orchestrator.rs to use `timing_config.scan_delay`
2. Fixed enforce_scan_delay() to return immediately on first call
3. Changed `last_probe_send_time` to `Option<Instant>`

**Verification:**
- nmap T1 (2 ports): 76.12s
- rustnmap T1 (2 ports): 76.85s
- Difference: < 1s ✅

#### UDP Scan Timeout - FIXED ✅
**Bug Location:** `crates/rustnmap-scan/src/ultrascan.rs`

**Root Cause:**
- `recommended_timeout()` using SRTT + 4*RTTVAR (5000ms) for first probe
- nmap uses `initialRttTimeout()` (1000ms) for first probe (timing.cc:82)

**Solution:**
- Added `initial_rtt` field to `InternalCongestionStats`
- Modified `recommended_timeout()` to use `initial_rtt` for first probe
- Subsequent probes still use SRTT + 4*RTTVAR

**Verification:**
- Before fix: 63.65s (single port)
- After fix: 20.40s (single port)
- Improvement: 3.1x faster ✅
- nmap comparison: 0.7s/port vs rustnmap 6.8s/port (remaining 7x gap due to nmap's more sophisticated timeout adjustment)

### Files Modified
- ✅ `crates/rustnmap-core/src/orchestrator.rs` - Fixed scan_delay source
- ✅ `crates/rustnmap-scan/src/ultrascan.rs` - Fixed enforce_scan_delay() and recommended_timeout()

---

## Phase 37: OS Detection Fix - COMPLETE (2026-03-02)
