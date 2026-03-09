# Task Plan: TCP SYN Scan Performance Investigation

> **Created**: 2026-03-09
> **Updated**: 2026-03-09 02:40
> **Status**: Phase 1 - Root Cause Investigation (IN PROGRESS)
> **Goal**: rustnmap MUST be FASTER than nmap while maintaining 100% accuracy

---

## Current Performance (Measured Data)

### Test Configuration
- Target: 45.33.32.156 (scanme.nmap.org)
- Ports: 22, 80, 113, 443, 8080
- Timing: T4 (Aggressive)
- Scan type: TCP SYN

### Measured Results (3 runs, 2026-03-09)
| Run | nmap | rustnmap | Difference |
|-----|------|---------|------------|
| 1 | 725ms | 1270ms | +545ms |
| 2 | 734ms | 1234ms | +500ms |
| 3 | 712ms | 1304ms | +592ms |
| **Average** | **724ms** | **1269ms** | **+545ms** |

**Fact**: rustnmap is 1.75x slower on average

### Accuracy Check
Both tools produce identical port state results:
```
22/tcp   open    ssh
80/tcp   open    http
113/tcp  closed  ident
443/tcp  closed  https
8080/tcp closed  http-proxy
```

---

## Phase 1: Root Cause Investigation (IN PROGRESS)

### Status
- ❌ Attempted fix: Remove 100ms wait cap → No improvement
- ❌ Stopped before making random changes
- ✅ Reverted to baseline for proper investigation
- ⏸ Need to identify actual bottleneck

### Known Facts

**Fact 1**: Code Path
- TcpSyn scan uses `ParallelScanEngine::scan_ports()`
- NOT the batch mode path in orchestrator

**Fact 2**: Wait Logic (ultrascan.rs:919-928)
```rust
let initial_wait = if has_more_ports {
    Duration::from_millis(10)
} else if !outstanding.is_empty() {
    earliest_timeout.min(Duration::from_millis(100))  // 100ms cap
} else {
    Duration::from_millis(10)
};
```

**Fact 3**: Receiver Timeout (ultrascan.rs:1059)
```rust
recv_with_timeout(Duration::from_millis(100))
```

**Fact 4**: Nmap's waitForResponses Pattern
```c
do {
    gotone = false;
    USI->sendOK(&stime);  // Calculate dynamic wait time
    gotone = get_pcap_result(USI, &stime);
} while (gotone && USI->gstats->num_probes_active > 0);
```
Continues while packets are arriving AND probes are active.

**Fact 5**: T4 Timing Parameters
- `initial_rtt`: 500ms
- `max_rtt`: 1250ms
- `scan_delay`: 0ms
- `max_retries`: 6

---

## Investigation Tasks (NOT STARTED)

### Task 1.1: Measure Time Distribution
**Goal**: Understand where 545ms is spent

**Add instrumentation to measure**:
- Time to send all probes
- Time spent in receive loops
- Number of main loop iterations
- Number of packets received per iteration

**Files**: `ultrascan.rs:scan_ports()`

### Task 1.2: Compare Nmap's Wait Time Calculation
**Goal**: Understand nmap's sendOK() behavior

**Questions**:
- What is the `stime` value from sendOK()?
- How does it change during the scan?
- Is it different from our `earliest_timeout`?

**Files**: `reference/nmap/scan_engine.cc:sendOK()`

### Task 1.3: Analyze Packet Receive Pattern
**Goal**: Compare packet processing patterns

**Measure**:
- How many packets arrive per waitForResponses() call?
- What is the time between first and last packet?
- Does nmap drain all packets before returning?

---

## Phase 2: Hypothesis Testing (NOT STARTED)

**Waiting for Phase 1 to complete before forming hypotheses**

---

## Phase 3: Implementation (BLOCKED)

**Blocked until root cause is identified**

---

## Session Log

### 2026-03-09 02:00 - Started Investigation
- Ran baseline tests: rustnmap 1.75x slower
- Verified accuracy: identical results

### 2026-03-09 02:15 - Attempted Fix 1
- Removed 100ms wait cap in ultrascan.rs
- Retested: No improvement (still 1.75x slower)
- Conclusion: 100ms cap is not the bottleneck

### 2026-03-09 02:25 - Attempted Fix 2 (STOPPED)
- Started changing receiver timeout 100ms → 10ms
- User intervention: "你确定你不是在瞎JB改吗"
- Realization: Making changes without root cause

### 2026-03-09 02:30 - Reverted and Restarted
- Reverted all changes
- Started systematic investigation
- Created this plan file

---

## Error Log

| Error | Attempt | Resolution |
|-------|---------|------------|
| Fix didn't improve performance | Removed 100ms cap | Not the bottleneck |
| Making random changes | Changed receiver timeout | User stopped, reverted |
| No root cause identified | Multiple fixes tried | Need proper investigation |
