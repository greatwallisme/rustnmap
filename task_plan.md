# Task Plan: Rustnmap Performance & Accuracy Overhaul

## Goal
Fix rustnmap to match nmap's speed and accuracy for network scanning.

## Baseline Measurements (2026-04-14)
- Command: `rustnmap -Pn -vv 192.168.15.0/24` vs `nmap -Pn -vv 192.168.15.0/24`
- Nmap: 256 IPs, 32 hosts up, **20.5 seconds**
- Rustnmap: 255 IPs, 255 hosts up, **397.4 seconds (19x slower)**

## Issues Found

### ISSUE 1: Output Formatting - Closed Ports Not Suppressed [HIGH]
- Nmap shows `Not shown: N closed tcp ports (reset)` summary line
- Rustnmap dumps ALL closed ports individually - noise, not useful
- Location: `crates/rustnmap-output/` or `crates/rustnmap-cli/src/cli.rs`

### ISSUE 2: Accuracy - Ports Incorrectly Marked as Filtered [CRITICAL]
- Nmap correctly identifies open/closed/filtered
- Rustnmap marks most ports as "filtered" - response matching broken
- Root cause: scan engine not receiving or matching TCP RST responses

### ISSUE 3: Speed - 19x Slower Than Nmap [CRITICAL]
- 397s vs 20.5s for same scan
- Possible causes:
  a. Per-target packet engine creation overhead
  b. Sequential host scanning instead of true parallel
  c. Response receive loop timing issues
  d. Congestion control too conservative

### ISSUE 4: Host Count Mismatch
- Nmap reports 32 hosts up, Rustnmap reports 255
- With -Pn both skip discovery, but nmap still filters non-responsive hosts

## Phase 1: Root Cause Investigation [in_progress]
- [x] Run comparison scans
- [x] Read ultrascan engine code
- [ ] Read output formatting code
- [ ] Profile single-host scan to isolate speed issues
- [ ] Verify packet engine response capture
- [ ] Check response matching logic

## Phase 2: Fix Output Formatting [pending]
- Suppress closed ports with summary line (nmap behavior)
- Show only open, filtered, open|filtered ports

## Phase 3: Fix Scanning Engine [pending]
- Fix response matching (accuracy)
- Optimize parallel scanning (speed)
- Fix packet engine reuse

## Phase 4: Verify [pending]
- Run full comparison test
- Zero warnings/errors
