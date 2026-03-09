# Progress Log: TCP Scan Performance Investigation

> **Created**: 2026-03-09
> **Updated**: 2026-03-09 10:42
> **Status**: Phase 1 - Diagnostic Instrumentation (IN PROGRESS)

---

## Session Goal

**Make rustnmap FASTER than nmap while maintaining 100% accuracy**

---

## Current Session (2026-03-09 10:42)

### Diagnostic Instrumentation Added

Added timing measurements to `ultrascan.rs` to identify bottleneck:
- Measures time spent sending probes
- Measures time spent waiting for responses
- Counts loop iterations and packets received
- Gated behind `diagnostic` feature flag
- Writes results to `/tmp/rustnmap_diagnostic.txt`

**Files Modified**:
- `crates/rustnmap-scan/src/ultrascan.rs` - Added timing instrumentation
- `crates/rustnmap-scan/Cargo.toml` - Added `diagnostic` feature

**Status**: Code compiles successfully, ready to test

---

## Current Performance (Measured Data)

### Test Configuration
- Target: 45.33.32.156 (scanme.nmap.org)
- Ports: 22, 80, 113, 443, 8080 (5 ports)
- Timing: T4 (Aggressive)
- Scan type: TCP SYN

### Test Results (2026-03-09)

| Test Run | nmap | rustnmap | rustnmap/nmap ratio |
|----------|------|---------|-------------------|
| Test 1 | 725ms | 1270ms | 1.75x slower |
| Test 2 | 734ms | 1234ms | 1.68x slower |
| Test 3 | 712ms | 1304ms | 1.83x slower |
| **Average** | **724ms** | **1269ms** | **1.75x slower** |

### Accuracy Verification
Both tools detect the same ports:
- 22/tcp: open
- 80/tcp: open
- 113/tcp: closed
- 443/tcp: closed
- 8080/tcp: closed

### Localhost Test (127.0.0.1, same 5 ports)
| nmap | rustnmap | Ratio |
|------|---------|-------|
| 112ms | 398ms | 3.55x slower |

---

## Known Facts

### 1. Code Path Discovery
TcpSyn scan uses `ParallelScanEngine::scan_ports()` (not batch mode)
- Orchestrator calls `run_port_scanning_parallel()` for SYN scans
- Batch mode changes to `TcpSynScanner` are not used

### 2. Timing Parameters (T4/Aggressive)
From `crates/rustnmap-common/src/scan.rs`:
- `initial_rtt`: 500ms
- `max_rtt`: 1250ms
- `scan_delay`: 0ms
- `max_retries`: 6

### 3. Current Wait Logic (ultrascan.rs:919-928)
```rust
let initial_wait = if has_more_ports {
    Duration::from_millis(10)
} else if !outstanding.is_empty() {
    earliest_timeout.min(Duration::from_millis(100))  // 100ms cap
} else {
    Duration::from_millis(10)
};
```

### 4. Receiver Task Timeout (ultrascan.rs:1059)
```rust
recv_with_timeout(Duration::from_millis(100))
```

### 5. Test Session Log (2026-03-09 02:30)

**Attempt 1**: Removed 100ms wait cap
- Modified: `earliest_timeout.min(Duration::from_millis(100))` → `earliest_timeout`
- Result: No performance change (still ~1.75x slower)
- Conclusion: 100ms cap is not the bottleneck

**Attempt 2**: Started to change receiver timeout 100ms → 10ms
- **STOPPED by user**: "你确定你不是在瞎JB改吗"
- Realization: Making changes without root cause analysis

**Reverted all changes** to establish baseline

---

## Nmap Reference (Observed Behavior)

From `reference/nmap/scan_engine.cc`:

### Main Loop Structure
```c
while (!USI.incompleteHostsEmpty()) {
    doAnyPings(&USI);
    doAnyOutstandingRetransmits(&USI);
    doAnyRetryStackRetransmits(&USI);
    doAnyNewProbes(&USI);
    printAnyStats(&USI);
    waitForResponses(&USI);  // Critical: processes ALL responses
    processData(&USI);
}
```

### waitForResponses Pattern
```c
do {
    gotone = false;
    USI->sendOK(&stime);  // Calculate wait time
    gotone = get_pcap_result(USI, &stime);  // Wait for packets
} while (gotone && USI->gstats->num_probes_active > 0);
```

Loop continues while:
- Packets are arriving (`gotone == true`)
- AND there are active probes

### get_pcap_result Timeout
```c
to_usec = TIMEVAL_SUBTRACT(*stime, USI->now);
if (to_usec < 2000) to_usec = 2000;  // Minimum 2ms
ip_tmp = readip_pcap(..., to_usec, ...);
```

---

## Current Investigation Status

**Phase 1: Root Cause Investigation** (IN PROGRESS)

Questions to answer:
1. Where exactly is the 560ms difference spent?
2. What does nmap do differently in the receive loop?
3. Is the bottleneck in async overhead or algorithmic difference?

**NOT DONE YET**:
- No timing instrumentation added
- No comparison of packet receive patterns
- No analysis of nmap's sendOK() return values

---

## Next Steps (Systematic Approach)

1. **Add timing instrumentation** to measure:
   - Time spent in main loop iterations
   - Time spent waiting for responses
   - Time spent processing packets

2. **Compare nmap's behavior**:
   - What is stime value from sendOK()?
   - How many packets arrive per waitForResponses() call?
   - What is the actual packet receive pattern?

3. **Identify bottleneck** BEFORE making changes
   - Is it async overhead?
   - Is it wait time calculation?
   - Is it something else entirely?

---

## Error Log

| Error | Action | Resolution |
|-------|--------|------------|
| Compilation error in stealth_scans.rs | Made syntax changes | Reverted all changes |
| Performance didn't improve after fix | Tried another fix immediately | Stopped by user, reverted |
| Making changes without root cause | Continuing to modify code | Reverted, need proper analysis |
