# Progress Log

> Updated: 2026-04-18

---

## Session: 2026-04-18

### Output Format Fixes
- [x] Fixed filtered port display: two-tier system (always-show vs conditional-show)
- [x] `is_always_shown()`: Open, OpenOrFiltered, Unfiltered
- [x] `is_conditionally_shown()`: Filtered, ClosedOrFiltered, etc. (shown when <= 20)
- [x] Nmap-matching output for scanme.nmap.org (5 filtered shown) and baidu.com (998 filtered suppressed)

### Tcpwrapped Detection
- [x] Added EOF timing tracking in `grab_banner_and_keep_stream()` (returns `closed_after_ms`)
- [x] Added tcpwrapped detection: no banner + EOF before tcpwrappedms (3000ms) threshold
- [x] Added `get_tcpwrappedms()` reading from NULL probe definition
- [x] Port 31337 now correctly shows "tcpwrapped" instead of "Elite"

### Verification
- [x] Benchmark: 61/62 PASS, 0 failures
- [x] Clippy: zero warnings, fmt: clean
- [x] scanme.nmap.org: 4 open + 5 filtered, "Not shown: 991 closed"
- [x] baidu.com: 2 open, "Not shown: 998 filtered"
- [x] 32-target /27 scan: 3.6x faster than nmap

### Remaining
- [ ] Service Info OS/CPE aggregation line (low priority)
