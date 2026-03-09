# Task Plan: RustNmap Development Roadmap

> **Created**: 2026-03-07
> **Updated**: 2026-03-08 20:00 PM PST
> **Status**: **Phase 10: P0 Bug Fix - NSE Resource Leak** 🔴 ACTIVE

---

## EXECUTIVE SUMMARY

**Current Priority (2026-03-08 20:00 PM PST)**

### P0 BUG: NSE Script Resource Leak 🔴 ACTIVE

**Severity**: P0 - Critical (DoS Vulnerability)
**Type**: Resource Leak / Thread Leak
**Location**: `crates/rustnmap-nse/src/engine.rs:449-514`

**Root Cause**:
```rust
let blocking_task = tokio::task::spawn_blocking(move || {
    // Lua code execution
});
let result = tokio::time::timeout(timeout, blocking_task).await;
// BUG: blocking_task continues running after timeout!
```

**Impact**:
- Scripts with infinite loops continue at 100% CPU after timeout
- Thread pool exhaustion (max ~512 threads)
- DoS vulnerability

**Solution**: Process-based isolation with OS-level kill capability

---

## Phase 10: Fix NSE Script Resource Leak (P0) 🔄 IN PROGRESS

> **Started**: 2026-03-08 20:00 PM PST
> **Priority**: P0 - Critical
> **Reference**: `BUG_REPORT_NSE_RESOURCE_LEAK.md`

### Architecture Decision

**Use Process-Based Isolation** (Bug Report Option 1)

```
┌─────────────────────────────────────────────────────────────────┐
│                    ScriptEngine (Parent Process)                 │
├─────────────────────────────────────────────────────────────────┤
│  execute_script_async()                                          │
│      │                                                           │
│      ├─► spawn rustnmap-nse-runner process                       │
│      │   - Pass: script source, target IP, timeout               │
│      │   - Set: CPU limit (setrlimit), memory limit              │
│      │                                                           │
│      ├─► wait_timeout(timeout, child)                            │
│      │                                                           │
│      └─► On timeout: child.kill() ← OS guarantees termination   │
│                                                                  │
│  Returns: ScriptResult with Timeout status                       │
└─────────────────────────────────────────────────────────────────┘
```

### Task 10.1: Create Script Runner Binary

**Status**: Pending

**File**: `crates/rustnmap-nse/src/bin/runner.rs`

**Requirements**:
- Accept script source via stdin (or --file argument)
- Accept target IP via --target argument
- Accept timeout via --timeout-ms argument
- Execute script in isolated Lua VM
- Output result as JSON to stdout
- Exit codes: 0=success, 1=error, 2=timeout

### Task 10.2: Create ProcessExecutor Module

**Status**: Pending

**File**: `crates/rustnmap-nse/src/process_executor.rs`

**Requirements**:
- Spawn runner process with resource limits
- Use `setrlimit` for CPU time (timeout + margin)
- Use `setrlimit` for memory (MAX_MEMORY_BYTES)
- Wait with `wait_timeout()` pattern
- Kill process on timeout
- Parse JSON output

### Task 10.3: Integrate with ScriptEngine

**Status**: Pending

**File**: `crates/rustnmap-nse/src/engine.rs`

**Changes**:
- Replace `spawn_blocking` with `ProcessExecutor`
- Maintain same public API
- Handle process spawn errors gracefully

### Task 10.4: Update Cargo.toml

**Status**: Pending

**File**: `crates/rustnmap-nse/Cargo.toml`

**Add**:
- `[[bin]]` target for runner
- `rlimit` crate dependency (for setrlimit)

### Task 10.5: Enable and Fix Tests

**Status**: Pending

**Files**:
- `crates/rustnmap-nse/tests/engine.rs`
- Remove `#[ignore]` from timeout test
- Add resource leak verification test

### Task 10.6: Documentation

**Status**: Pending

**Files**:
- Update `crates/rustnmap-nse/CLAUDE.md`
- Update `doc/architecture.md`

### Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| (none yet) | - | - |

---

## PREVIOUS UPDATES (2026-03-08)

### Phase 8-9: All Comparison Tests Passing ✅ COMPLETE

**Pass Rate**: 95% (37/39 tests)

All critical scan types working correctly. See previous sections for details.

---

## REST OF DOCUMENT PRESERVED (Previous Phases)

[Previous phases 1-9 documentation preserved below]
