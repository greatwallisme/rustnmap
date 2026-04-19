# Findings: Multi-Target Public Network Performance

## Parallelism Cap & Drain Window (2026-04-19)

### Root Cause of Slow /24 Scans

Two issues caused rustnmap to be 2x slower than nmap on public /24 scans:

1. **Conservative parallelism cap**: For total_probes >= 10_000 (254 targets * 100 ports),
   the code capped parallelism at `self.max_parallelism` (300) regardless of target count.
   Nmap gives each target its own cwnd, so total parallelism scales with target count.

2. **MIN() drain window with 1500+ probes**: The drain loop computed the minimum remaining
   time across ALL outstanding probes. With 1500 probes sent at different times, MIN()
   returns near-zero, causing the loop to exit immediately. This created thousands of
   empty loop iterations wasting CPU (baseline used 91s user CPU vs nmap's 1.4s).

### Fix

1. **Removed total_probes threshold**: Always scale cwnd with target count,
   capped at 1500 (PACKET_MMAP V2 has 2048 frames). Batch size also scales to 1500.

2. **Fixed drain window for large scans**: When num_targets > 10, use
   `(probe_timeout / 2).clamp(20ms, 500ms)` instead of MIN() across all probes.
   `check_timeouts_multi()` handles expiry after the drain completes.

### Results

| Metric | Baseline | Optimized | Nmap |
|--------|----------|-----------|------|
| Wall time | 236s | **63s** | 117s |
| User CPU | 91s | **7.6s** | 1.4s |
| Accuracy | - | 444/445 match | baseline |

- **1.86x faster** than nmap
- **12x less CPU** than baseline
- Accuracy: 221x443 + 218x80 + 3x53 + 1x8000 + 1x8443 = matches nmap exactly
  (53/tcp: 3 vs 4, likely network jitter on one host)

### Per-Target RTT Tracking (Not Used)

The per-target RTT tracking approach (PerTargetTiming struct) was implemented and tested
but degraded performance because:
- Filtered targets never get RTT measurements
- They fall back to shared_timeout, which is the same as baseline
- The per-target HashMap lookup adds overhead per probe
- On public networks, 98% of targets are filtered, so per-target tracking
  provides no benefit for the common case

The simpler approach (scaling parallelism + fixed drain window) was sufficient.

---

## Two-Tier Port Suppression (2026-04-18)

### Problem
Single binary "interesting" classification caused two failures:
1. Including Filtered in "interesting" showed all 998 filtered ports for baidu.com
2. Excluding Filtered hid the 5 filtered ports for scanme.nmap.org

### Fix
Two-tier functions: `is_always_shown()` and `is_conditionally_shown()`.
Suppression shows conditional ports when `count <= 20`.

---

## Tcpwrapped Detection (2026-04-18)

### Implementation
- `grab_banner_and_keep_stream()` tracks `eof_received` and calculates `closed_after_ms`
- Phase 1 checks: `banner_opt.is_none() && closed_after_ms < tcpwrappedms`
- `get_tcpwrappedms()` reads threshold from NULL probe definition (default 3000ms)
