# Findings: Accuracy & Speed Optimization

## Two-Tier Port Suppression (2026-04-18)

### Problem
Single binary "interesting" classification caused two failures:
1. Including Filtered in "interesting" showed all 998 filtered ports for baidu.com
2. Excluding Filtered hid the 5 filtered ports for scanme.nmap.org

### Root Cause
Nmap uses a nuanced approach:
- Always show: Open, OpenOrFiltered, Unfiltered
- Show conditionally: Filtered (when few, e.g., <= 20)
- Always suppress: Closed, Unknown

### Evidence
- scanme.nmap.org: 4 open + 5 filtered + 991 closed → shows 9, suppresses 991 closed
- baidu.com: 2 open + 998 filtered → shows 2, suppresses 998 filtered
- The threshold of 20 correctly handles both cases

### Fix
Two-tier functions: `is_always_shown()` and `is_conditionally_shown()`.
Suppression shows conditional ports when `count <= 20`.

---

## Tcpwrapped Detection (2026-04-18)

### How nmap detects tcpwrapped
From nmap-service-probes NULL probe:
```
tcpwrappedms 3000
```
If connection closes before 3000ms with no banner data → tcpwrapped.

### Implementation
- `grab_banner_and_keep_stream()` tracks `eof_received` and calculates `closed_after_ms`
- Phase 1 checks: `banner_opt.is_none() && closed_after_ms < tcpwrappedms`
- `get_tcpwrappedms()` reads threshold from NULL probe definition (default 3000ms)

### Key insight
tcpwrapped detection must happen in Phase 1 (banner grab), not Phase 2 (active probes).
The NULL probe establishes the baseline timing. Active probes might succeed on tcpwrapped
ports that reject NULL but accept specific payloads.

---

## Multi-Target PACKET_MMAP Interface Mismatch (2026-04-18)

### Fix
Detect target source address and create engine for correct interface.

### Impact
- Two-target scan: 0.93x -> 1.3x
- 32-target /27 scan: 3.6x faster than nmap
