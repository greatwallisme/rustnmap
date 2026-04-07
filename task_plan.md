# Task Plan: NSE Performance Optimization

## Goal
Fix NSE scripts that are slower than nmap. Starting point: 46/46 PASS but ~20 scripts slower.
Benchmark report: `benchmarks/reports/nse_comparison_report_20260405_044043.txt`

## Rules
- Do NOT blindly change code without understanding root cause
- Verify each fix individually before moving to the next
- Track actual test results, not assumptions

## Root Cause: Architecture Mismatch (from nmap source study)

**The #1 performance problem**: Our NSE engine creates a **new Lua VM for EVERY portrule evaluation**.
Nmap uses **ONE Lua VM + coroutines** for the entire scan.

| Metric | nmap | rustnmap | Ratio |
|--------|------|----------|-------|
| Lua VMs per scan | 1 | 100+ | 100x |
| Portrule eval (each) | coroutine resume (~0.1ms) | new VM + register libs + load script (~50ms) | 500x |
| 100 portrules total | ~10ms | ~5,000ms | 500x |
| I/O model | nsock async (yield/resume) | blocking socket with timeout | N/A |

### How nmap does it (reference/nmap/nse_main.lua)

1. **`get_chosen_scripts()`** (line 717): Load all scripts ONCE into a single Lua state.
   Each script's top-level code runs in a coroutine to extract `action`, `portrule`, etc.
   The `script_closure_generator` is stored for later.

2. **`Script:new_thread()`** (line 462): For each (script, host, port), create a coroutine that:
   - Re-runs script closure (fast, just populates env)
   - Evaluates rule function
   - If rule matches: yields `ACTION_STARTING`, then executes `action(host, port)`
   - All in ONE coroutine, ONE Lua state

3. **`run()`** (line 892): Event loop manages up to 1000 concurrent coroutines.
   Scripts yield on I/O (via nsock), get resumed when data arrives.

4. **`threads_iters.NSE_SCAN`** (line 1388): Lazy thread iterator:
   ```lua
   for port in cnse.ports(host) do
     for _, script in ipairs(scripts) do
       local thread = script:new_thread("portrule", host, port)
       if thread then yield(thread) end
     end
   end
   ```

---

## Phase 1: Single-VM Portrule Evaluation - PENDING

**Problem**: `evaluate_portrule()` in engine.rs:1004 creates a new `NseLua` VM for every call.
With ~100 default scripts and 1 port, that's 100 VM inits = ~5 seconds.

**Fix**: Load all scripts into ONE Lua VM at engine creation time, evaluate portrules via
coroutine resume (matching nmap's `Script:new_thread` pattern).

**Implementation**:
1. Add `ScriptEngine::preload_scripts()` - loads all script sources into one Lua VM,
   runs each script's top-level code to extract `action`, `portrule` function references
2. Add `ScriptEngine::evaluate_portrules_for_port()` - iterate pre-loaded scripts,
   resume each portrule coroutine with host/port args, collect matches
3. Add `ScriptEngine::execute_matching_scripts()` - for matched scripts, create new
   coroutine that runs `action(host, port)` and yields on I/O

**Impact**: 100 portrule evals: 5000ms -> ~10ms (500x improvement)

---

## Phase 2: Combined Rule+Action Execution - PENDING

**Problem**: Even after portrule matching, `execute_port_script()` creates ANOTHER new VM
to run the action function. This adds ~50-200ms per script.

**Fix**: Reuse the same VM from portrule evaluation. The portrule and action already share
the same script environment in nmap's model. Just resume the coroutine to run action.

**Implementation**:
1. In `new_thread()`-equivalent: create coroutine that runs both rule AND action
2. If rule matches, coroutine yields ACTION_STARTING, then runs action
3. I/O calls yield the coroutine (we need async I/O handling)

**Impact**: Eliminates ~50ms VM init per matching script execution

---

## Phase 3: Async I/O (Coroutine Yield on Socket Ops) - PENDING

**Problem**: Our socket I/O is blocking. When a script does `comm.opencon()`, it blocks
the entire thread. Nmap's nsock yields the coroutine and resumes when data arrives.

**Fix**: Replace blocking socket ops with Tokio-based async I/O that yields Lua coroutines.

**Impact**: Banner scripts that wait 5s on slow servers no longer block other scripts.
Enables true concurrent execution of multiple scripts.

---

## Phase 4: comm.rs Timeout Optimization - ALREADY APPLIED

### Fix 4.1: `receive_all()` linger timeout (APPLIED)
After first successful read, switch to 150ms linger timeout.
This is already in comm.rs (`LINGER_TIMEOUT_MS = 150`).

**Note**: This fix has minimal impact because the benchmark measures total scan time,
not just NSE phase. The 5s overhead is from portrule evaluation (100 new VMs), not from
comm timeouts.

### Fix 4.2: `DEFAULT_TIMEOUT_MS` still 30s
Nmap uses ~7s (calculated via `stdnse.get_timeout`). Our default is still 30s.
This only affects scripts that timeout (NTP), not banner scripts.

---

## Benchmark Results (2026-04-05)

All 46/46 PASS. Performance breakdown by speedup:

| Speedup Range | Count | Scripts | Root Cause |
|---------------|-------|---------|------------|
| >2x (faster) | 5 | FTP, SSL, IMAP, Telnet | nmap slower on these |
| 0.5-2x (parity) | 25 | HTTP, DNS, LDAP, SSH Auth | Acceptable |
| 0.1-0.5x (slower) | 12 | Banner (SSH/SMTP/POP3), NTP, MySQL | Portrule VM overhead |
| <0.1x (very slow) | 4 | SNMP, FCrDNS | UDP scan/service detect (not NSE) |

---

## Bug Fix: UDP IHL Byte Offset (2026-04-05, COMPLETE)

**Root Cause**: `parse_udp_response()` in `ultrascan.rs` used IHL field value (5) as byte offset
instead of multiplying by 4 (IHL=5 words = 20 bytes). This caused src_port to be read from
IP header bytes 5-6 (identification field) instead of bytes 20-21 (actual UDP source port).
Responses couldn't match outstanding probes, so ALL UDP responses were silently dropped.

**Also Fixed**: `start_icmp_receiver_task` now receives `src_addr` parameter instead
of using `self.local_addr`, ensuring the address check matches the BPF filter address.

**Impact**: UDP scan on SNMP port 161: 11.40s (`open|filtered`) -> 0.34s (`open`)

---

## Previous Plan: NSE Script Compatibility Fix (COMPLETE)

### Goal (completed 2026-04-05)
Fix all NSE script failures found in Docker comparison testing.
Starting point: 20/46 scripts PASS (43.4%) on 2026-04-02.
Result: 46/46 PASS (100%)

---

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| UDP recv hangs | 1 | Set read_timeout before recv |
| UDP datagram truncated | 1 | Return full datagram. not min(recv, n) |
| Rust SMB functions overwrite Lua | 1 | Removed Rust protocol functions, kept only constants |
| NseSocket missing buffer field | 1 | Added buffer: Vec::new() to all test constructors |
| 83 clippy errors | 1 | Systematic cleanup across 8 files |
| engine tests fail without runner binary | 1 | Need `cargo build --bin rustnmap-nse-runner` first |
| mlua pairs() ignores __pairs | 1 | Use Lua-side format_table instead of Rust-side iteration |
| ssl-enum-ciphers empty output | 1 | format_table + two-return-value convention |
| runner panic: no reactor running | 1 | Added Tokio runtime in main() |
| http-title: SCRIPT_NAME nil | 1 | Set SCRIPT_NAME global before loading script |
| receive_buf literal matching | 1 | Changed to Lua string.find pattern matching |
