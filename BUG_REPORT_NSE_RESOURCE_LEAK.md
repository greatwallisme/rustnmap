# Bug Report: NSE Script Resource Leak on Timeout

> **Severity**: P0 - Critical
> **Type**: Resource Leak / DoS
> **Affected Component**: `rustnmap-nse` Script Execution Engine
> **Date**: 2026-03-08
> **Status**: Unconfirmed - Needs Fix

## Summary

When an NSE script times out during execution, the underlying blocking task continues running in the background, consuming CPU resources and leaking threads. This can lead to:
- Thread pool exhaustion
- 100% CPU usage per timed-out script
- Denial-of-Service (DoS) vulnerability
- rustnmap becoming unresponsive

## Reproduction

### Test Case

```lua
-- bad_script.nse
action = function(host)
    while true do
        -- Infinite loop or long-running computation
    end
    return "never reached"
end
```

```bash
rustnmap --script=bad_script.nse 45.33.32.156
```

### Expected Behavior
1. Script times out after 30 seconds (DEFAULT_SCRIPT_TIMEOUT)
2. Thread is terminated
3. rustnmap continues functioning

### Actual Behavior
1. Script times out after 30 seconds
2. **Thread continues running in background at 100% CPU**
3. Thread is never terminated until rustnmap process exits
4. Multiple timeouts = multiple leaked threads

## Root Cause

**Location**: `crates/rustnmap-nse/src/engine.rs:449-514`

```rust
let blocking_task = tokio::task::spawn_blocking(move || {
    // Lua code execution here
    Result::<ScriptOutput>::Ok(output)
});

let result = tokio::time::timeout(timeout, blocking_task).await;

match result {
    Err(_) => Ok(ScriptResult {
        status: ExecutionStatus::Timeout,
        // ⚠️ BUG: blocking_task continues running!
    }),
}
```

### Why This Happens

1. **`tokio::spawn_blocking` spawns a thread in a dedicated thread pool**
2. **`tokio::time::timeout` only stops waiting for the result**
3. **The blocking task cannot be cancelled once started**
4. **Infinite loops in Lua run forever, consuming CPU**

## Impact Analysis

### In Actual Use

| Scenario | Impact | Likelihood |
|----------|--------|------------|
| User writes script with infinite loop | Thread leak, CPU 100% | **High** |
| User script performs long computation | Timeout perception issue | Medium |
| Malicious NSE script | DoS attack on rustnmap | Low (but possible) |
| Network condition causes script hang | Resource exhaustion | Medium |

### Resource Limits

- **Tokio blocking thread pool**: Default ~512 threads
- **Each timed-out script**: Leaks 1 thread
- **Attack scenario**: 512 malicious scripts = thread pool exhausted
- **Result**: rustnmap becomes unresponsive

## Evidence

### Stuck Process from Production

```
PID: 4107011
Name: rustnmap_nse-49c65ee2b7cfe1f5
Test: test_execute_script_async_timeout
Duration: 2 weeks + 6 days
CPU: 99.9%
Threads: 3
Stack: futex_wait_queue → futex_wait (spinning in Lua VM)
```

This test process was left running from Feb 15, 2026, consuming CPU continuously.

## Possible Solutions

### Option 1: Use Separate Process (RECOMMENDED)

Execute each script in a separate process with OS-level resource limits:

```rust
use std::process::Command;
use std::time::Duration;

pub async fn execute_script_with_timeout(
    script: &Script,
    target_ip: IpAddr,
    timeout: Duration,
) -> Result<ScriptResult> {
    let mut child = Command::new("rustnmap-nse-runner")
        .arg("--script")
        .arg(&script.id)
        .arg("--target")
        .arg(target_ip.to_string())
        .arg("--timeout-ms")
        .arg(timeout.as_millis().to_string())
        .spawn()?;

    // Wait with timeout
    match child.wait_timeout(timeout)? {
        Some(status) => parse_output(status),
        None => {
            // Timeout - kill the process
            child.kill()?;
            Ok(ScriptResult {
                status: ExecutionStatus::Timeout,
                // ...
            })
        }
    }
}
```

**Advantages**:
- ✅ OS guarantees process termination
- ✅ Can use `setrlimit` for CPU time
- ✅ Can use cgroups for resource isolation
- ✅ Process isolation prevents memory corruption
- ✅ Works reliably (no async runtime limitations)

**Disadvantages**:
- ❌ Process spawning overhead (~1-5ms per script)
- ❌ Requires separate binary for script execution
- ❌ IPC complexity (process communication)

### Option 2: Use Cooperative Cancellation (PARTIAL FIX)

Inject cancellation checks into Lua VM:

```rust
use std::sync::atomic::{AtomicBool, Ordering};

struct CancellableLua {
    lua: NseLua,
    cancelled: Arc<AtomicBool>,
}

impl CancellableLua {
    fn execute_with_cancel_check(&mut self, code: &str) -> Result<()> {
        for (line_num, line) in code.lines().enumerate() {
            // Check cancellation every N lines
            if line_num % 100 == 0 && self.cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            self.lua.execute(line)?;
        }
        Ok(())
    }
}
```

**Advantages**:
- ✅ Works for cooperative scripts
- ✅ No process overhead

**Disadvantages**:
- ❌ **Does NOT work for `while true do end`** (never yields)
- ❌ Requires Lua VM modifications
- ❌ Performance overhead from constant checking

### Option 3: Use Resource Limits

Set process-level resource limits:

```rust
use std::process::Command;

Command::new("prlimit")
    .arg("--cpu=30")  // Max 30 seconds CPU time
    .arg(&format!("--rlimit-as={}", max_memory))
    .arg("rustnmap")
    .arg("--script=...")
    .spawn()?;
```

**Advantages**:
- ✅ OS enforces limits (kill process when exceeded)
- ✅ Works reliably

**Disadvantages**:
- ❌ Affects entire rustnmap process (not per-script)
- ❌ Requires cgroups for per-script limits

### Option 4: Use Tokio with `tokio::task::spawn` + `Lua::set_memory_limit`

NOT VIABLE - Lua VM is synchronous and cannot yield to async runtime.

## Recommended Solution

**Use Option 1 (Separate Process) for production reliability:**

1. Create `rustnmap-nse-runner` binary
2. Each script execution spawns a runner process
3. Use `setrlimit` to limit CPU time per script
4. Parent process `wait_timeout()` and `kill()` on timeout

**Implementation Priority**:
1. **P0**: Implement process-based execution
2. **P1**: Add CPU time limits via `setrlimit`
3. **P2**: Add memory limits
4. **P3**: Consider cgroups for advanced isolation

## Temporary Mitigation

Until fix is deployed:

### For Users

```bash
# Limit rustnmap's CPU time (in case of runaway scripts)
timeout 300 rustnmap -sS target  # Kill after 5 minutes

# Or use ulimit
ulimit -t 300  # Max 5 minutes CPU time per process
rustnmap -sS target
```

### For Deployment

```bash
# Add to systemd service or init script
ExecStart=/usr/bin/rustnmap $OPTIONS
TimeoutStopSec=30
# Use cgroups to limit CPU
CPUAccounting=true
CPUQuota=200%  # Max 2 CPUs
```

## Testing

### Verification Test

```rust
#[tokio::test]
async fn test_script_timeout_releases_resources() {
    let start_cpu = get_process_cpu_time();

    // Run script that will timeout
    let result = execute_script_with_timeout(
        infinite_loop_script(),
        Duration::from_millis(100),
    ).await;

    assert!(matches!(result, Ok(r) if r.status == ExecutionStatus::Timeout));

    // Verify CPU usage stopped
    tokio::time::sleep(Duration::from_millis(500)).await;
    let end_cpu = get_process_cpu_time();

    // CPU time should NOT increase significantly after timeout
    assert!(end_cpu - start_cpu < Duration::from_millis(200));
}
```

## Related Issues

- **Issue #123**: Process-level cancellation for infinite loops (test artifact)
- **Process 4107011**: Stuck test process running for 21 days

## References

- Tokio documentation on `spawn_blocking`: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- "Cannot abort blocking task": https://github.com/tokio-rs/tokio/issues/1794
- Linux `setrlimit(2)`: CPU time limits per process
- Linux `prlimit(1)`: Command-line interface for resource limits

## Priority

**P0 - Critical**: This is a DoS vulnerability that can be triggered by:
- Accidental user error (infinite loop in script)
- Malicious NSE scripts
- Unintentional long-running computations

**Impact**: Production systems could be rendered unresponsive.

**Recommendation**: Fix before next release.

