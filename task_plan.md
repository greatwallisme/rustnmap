# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-03-02 16:00
**Status**: Phase 36 - REMAINING PERFORMANCE ISSUES

---

## Phase 36: Remaining Performance Issues (2026-03-02)

### Completed in Phase 35

FIN/NULL/XMAS/MAIMON scans fixed - now at 0.93-0.98x nmap speed.

### Remaining Critical Issues (Speed < 0.5x)

| Test | Speed | Rustnmap | Nmap | Issue |
|------|-------|----------|------|-------|
| UDP Scan | **0.25x** | 3192ms | 823ms | 4x slower |
| OS Detection Limit | **0.30x** | 44776ms | 13572ms | 3.3x slower |
| Two Targets | **0.40x** | 1855ms | 746ms | 2.5x slower |
| OS Detection Guess | **0.41x** | 39032ms | 16229ms | 2.4x slower |
| Window Scan | **0.45x** | 1660ms | 762ms | 2.2x slower |
| OS Detection | **0.45x** | 36066ms | 16363ms | 2.2x slower |
| ACK Scan | **0.50x** | 1656ms | 833ms | 2x slower |

### Failed Tests

| Test | Issue |
|------|-------|
| Port Range | State mismatch: port 80 = filtered (should be open) |

### Priority Order for Investigation

1. **CRITICAL: UDP Scan** - 4x slower, likely timeout/retry issue
2. **CRITICAL: OS Detection** - All variants 2-3x slower, fingerprint matching engine
3. **HIGH: Multi-target** - Two Targets test 2.5x slower
4. **HIGH: ACK/Window Scans** - 2x slower despite adaptive timing fix
5. **MEDIUM: Port Range failure** - State detection bug

---

## Phase 35: COMPLETE - Stealth Scan Adaptive Timing

### What Was Done

1. Added `AdaptiveTiming` struct for nmap-style RTT estimation
2. Fixed initial timeout calculation (use initial_rtt until first measurement)
3. Removed 100ms artificial delay between retry rounds
4. Updated all 6 batch scanners (FIN, NULL, XMAS, MAIMON, ACK, Window)

### Results

| Scan | Before | After | Nmap | Speed |
|------|--------|-------|------|-------|
| FIN | 22283ms | 5001ms | 4698ms | **0.93x** |
| NULL | 22331ms | 5182ms | 4898ms | **0.94x** |
| XMAS | 22832ms | 4970ms | 4907ms | **0.98x** |
| MAIMON | 22632ms | 4925ms | 4647ms | **0.94x** |

**4-5x improvement! FIN/NULL/XMAS/MAIMON now at par with nmap.**

### Bug Found During Implementation

Initial implementation used `srtt + 4*rttvar` from the start, but with initial values:
- srtt = 1000ms, rttvar = 1000ms
- timeout = 1000 + 4*1000 = 5000ms
- 4 rounds = 20 seconds!

**Fix:** Use `initial_rtt` until first RTT measurement, then switch to `srtt + 4*rttvar`.

---

## Current Benchmark Results (2026-03-02 15:30)

```
Total Tests: 39
Passed: 37
Failed: 1
Skipped: 3
Pass Rate: 94.8%
```

### Performance Summary

| Category | Tests | Status |
|----------|-------|--------|
| Faster than nmap | Connect, Aggressive, IPv6 | GOOD |
| At par (0.9-1.1x) | FIN, NULL, XMAS, MAIMON, Fast+Top | FIXED |
| Slow but acceptable (0.5-0.9x) | SYN, Fast, Top Ports, XML, Grepable | OK |
| Too slow (< 0.5x) | UDP, OS Detection, Window, ACK, Two Targets | NEEDS WORK |

---

## Next Steps

1. Investigate UDP scan performance (0.25x)
2. Investigate OS Detection performance (0.30-0.45x)
3. Fix Port Range state detection bug
4. Investigate ACK/Window scan performance (0.45-0.50x)
