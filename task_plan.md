# Task Plan: Accuracy & Speed Optimization

## Goal
Exceed nmap in BOTH accuracy AND speed. Handle real-world network conditions. No fake speed via timeout reduction.

---

## Current State (2026-04-18)

### Benchmark: 61/62 PASS (98.3%), 0 failures, 3 skipped (Idle/Zombie needs zombie host)

### Speed: ALL tests >= 1.0x

| Category | Speed | Notes |
|----------|-------|-------|
| SYN Scan | 1.3x | |
| Connect Scan | 4.2x | |
| UDP Scan | 1.1x | |
| FIN/NULL/XMAS | 2.6-2.8x | |
| Service Detection | 1.5x | |
| Aggressive Scan | 4.1x | |
| OS Detection | 1.2x | |
| 32 Targets /27 | 3.6x | |

### Accuracy Issues (Remaining)

| Issue | Severity | Status |
|-------|----------|--------|
| Filtered port output (closed vs filtered) | HIGH | FIXED |
| Service version port 31337 "Elite" vs "tcpwrapped" | MEDIUM | FIXED |
| Service version port 22 in -A mode | MEDIUM | PENDING |
| Service Info OS/CPE line missing | LOW | PENDING |
| OS detection precision (94% vs 96%) | LOW | PENDING |

---

## Completed Phases

### Phase 1: Output Format - Filtered Port Display [COMPLETE]
- Root cause: `is_interesting_port()` excluded `Filtered` state
- Nmap shows filtered ports as they indicate firewall presence
- Fix: `is_interesting_port` returns true for all non-Closed states
- Also fixed `determine_suppression_info` to correctly summarize mixed states
- Result: 991 closed + 5 filtered now correctly separated, matching nmap exactly

### Phase 2: Exclude Port Accuracy Fix [COMPLETE]
### Phase 3: SCTP/IP Protocol Scan Accuracy Fix [COMPLETE]
### Phase 4: Min/Max Rate Speed [COMPLETE]
### Phase 5: Multi-Target Parallel Scanning [COMPLETE]
### Phase 6: Adaptive Parallelism Scaling [COMPLETE]
### Phase 7: Port Suppression Threshold [COMPLETE]

---

## Remaining Work

### Phase 8: Service Detection Accuracy [IN PROGRESS]
- [x] Port 31337: "Elite" -> "tcpwrapped" (added tcpwrapped detection via EOF timing)
- [x] Filtered port display: two-tier suppression (show when <= 20, suppress when many)
- [x] Output matches nmap exactly for both scanme.nmap.org and baidu.com
- [ ] Service Info line: missing OS/CPE aggregation (low priority)
