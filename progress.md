# Progress Log: RustNmap Development

> **Updated**: 2026-03-10 23:58
> **Status**: Root Cause FOUND - Ready to Implement Fix

---

## Session: Post-Refactoring Performance Analysis (2026-03-10)

### Root Cause Analysis - COMPLETE
**Problem**: Fast Scan 6.0s vs nmap 2.4s (2.5x slower)
**Diagnostic**: 96.6% wait time, 373 iterations for 100 ports
**Root Cause**: Initial probe timeout too long (1000ms)

### Evidence Trail
1. **Memory Search (#3084-3086, #3088, #3089)**
   - Previous optimization removed per-probe scan_delay
   - But performance regression persists
   - Congestion control fix attempted but didn't help

2. **Code Analysis (ultrascan.rs:189-209)**
   ```rust
   fn recommended_timeout(&self) -> Duration {
       if self.first_measurement.load(Ordering::Relaxed) {
           // First probe: use initial_rtt directly (1000ms for T3)
           self.initial_rtt.min(self.max_rtt)
       }
   }
   ```
   - For T3 Fast Scan: `initial_rtt = 1000ms`
   - nmap uses `MIN(initial_rtt, 1000)` but our code uses full value

3. **Cascading Effect**
   - First probe times out after 1000ms
   - `on_packet_lost()` → cwnd halves
   - Subsequent probes also time out (timeout still 1000ms)
   - cwnd drops to 1 and stays for 150 iterations
   - Each iteration: send 1 probe, wait 10ms, check timeout
   - Result: 373 iterations, 6.0s total time

### Solution Design
Clamp initial RTT timeout to max 200ms for Fast Scan

```rust
fn recommended_timeout(&self) -> Duration {
    if self.first_measurement.load(Ordering::Relaxed) {
        // First probe: clamp to reasonable max for Fast Scan
        self.initial_rtt.min(self.max_rtt).min(Duration::from_millis(200))
    }
}
```

### Implementation Plan
- [ ] Modify `recommended_timeout()` in ultrascan.rs
- [ ] Build with diagnostic feature
- [ ] Run Fast Scan test
- [ ] Verify iterations drop to ~50
- [ ] Run full benchmark
- [ ] Commit if successful

### Expected Outcome
- Fast Scan: 6.0s → ~2.5s (match nmap)
- Iterations: 373 → ~50
- cwnd: No collapse to 1
