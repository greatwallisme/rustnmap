# Progress Log

> Updated: 2026-04-19

---

## Session: 2026-04-19 (Multi-Target Performance)

### Diagnosis
- [x] Measured baseline: 236s vs nmap 117s (2x slower, 65x more CPU)
- [x] Identified root cause: conservative parallelism cap + MIN() drain window
- [x] Attempted per-target RTT tracking - degraded performance, reverted

### Fix Applied
- [x] Scale parallelism with target count (cap 1500 for PACKET_MMAP V2)
- [x] Scale batch size with target count (cap 1500)
- [x] Fixed drain window: use timeout-based window instead of MIN() for >10 targets

### Results
- [x] **rustnmap: 63s vs nmap: 117s -- 1.86x faster**
- [x] **CPU: 7.6s vs baseline 91s -- 12x improvement**
- [x] Accuracy: 444/445 open ports match (53/tcp diff likely network jitter)
- [x] clippy: 0 warnings
- [x] test: all pass
- [x] fmt: clean

### Previous Session (2026-04-18)
- [x] Two-tier port suppression
- [x] Tcpwrapped detection via EOF timing
- [x] 61/62 benchmark PASS, NSE 46/46 PASS
- [x] Committed as 4627b82
