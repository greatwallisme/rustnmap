# Findings - RustNmap Packet Capture Architecture Redesign

> **Created**: 2026-02-19
> **Updated**: 2026-03-05
> **Status**: Phase 40 - Architecture Redesign

---

## Phase 40: Architecture Research (2026-03-05)

### Research Summary

Conducted comprehensive research on:
1. Current rustnmap-packet implementation
2. nmap's packet capture architecture
3. Linux PACKET_MMAP V2/V3 implementation
4. Rust async patterns for packet capture
5. **nmap's network volatility handling mechanisms** (NEW)

### Network Volatility Handling Research (Deep Dive)

Based on analysis of nmap source code (`timing.cc`, `scan_engine.cc`, `nsock/`):

#### 1. Adaptive Timing (RFC 2988)
```c
// nmap timing.cc:99-167
void adjust_timeouts2(struct timeval *sent, struct timeval *received,
                      struct timeout_info *to) {
    int rtt = TIMEVAL_SUBTRACT(*received, *sent);
    if (to->srtt == -1) {
        to->srtt = rtt;
        to->rttvar = rtt / 2;
    } else {
        int delta = rtt - to->srtt;
        to->srtt += delta / 8;
        to->rttvar += (abs(delta) - to->rttvar) / 4;
    }
    to->timeout = box(o.minRttTimeout() * 1000, o.maxRttTimeout() * 1000,
                      to->srtt + (to->rttvar << 2));
}
```

**Current Implementation**: `crates/rustnmap-scan/src/timeout.rs` - RFC 2988 compliant

**Gaps**:
- Missing `min_rtt_timeout` and `max_rtt_timeout` clamping
- Missing per-template initial values

#### 2. Congestion Control (TCP-like)
```c
// nmap scan_engine.cc:665-815
void ultra_timing_vals::ack(double scale, const scan_performance_vars *perf) {
    if (cwnd < ssthresh) {
        // Slow start: exponential
        cwnd += perf->slow_incr * scale;
    } else {
        // Congestion avoidance: linear
        cwnd += perf->ca_incr / cwnd * cc_scale(perf) * scale;
    }
}

void ultra_timing_vals::drop(unsigned in_flight, const scan_performance_vars *perf) {
    ssthresh = (int)(cwnd / 2);
    cwnd = std::max(perf->low_cwnd, (int)(cwnd / 2));
}
```

**Current Implementation**: Partial in `crates/rustnmap-scan/src/ultrascan.rs`

**Gaps**:
- Group-level vs host-level drop handling
- `cc_scale()` for window scaling

#### 3. Scan Delay Boost
```c
// nmap scan_engine.cc:2366-2410
void HostScanStats::boostScanDelay() {
    unsigned int newms = 0;
    if (o.timing_level < 4) {
        newms = MIN(10000, MAX(1000, delayms * 10));
    } else {
        newms = MIN(1000, MAX(100, delayms * 2));
    }
    if (newms > delayms) {
        delayms = newms;
        goodResp_since_delay_changed = 0;
    }
}
```

**Current Implementation**: Not fully implemented

**Required**: Dynamic delay boost when drop rate exceeds threshold

#### 4. Rate Limiting
```c
// nmap nmap_ops.cc
o.setMinRate(0.00);    // No minimum by default
o.setMaxRate(0.00);    // No maximum by default
o.setMaxRetransmissions(10);  // T0 default
```

**Current Implementation**: Not implemented

**Required**: Token bucket rate limiter for `--max-rate` / `--min-rate`

#### 5. Error Recovery
| Error Type | nmap Response |
|------------|---------------|
| ICMP_HOST_UNREACH | Mark host down |
| ICMP_NET_UNREACH | Reduce cwnd, boost delay |
| ICMP_PORT_UNREACH (UDP) | Mark port closed |
| ICMP_ADMIN_PROHIBITED | Mark port filtered |
| Timeout | Retry with backoff |

**Current Implementation**: Partial

**Gaps**: Proper ICMP error classification and response

---

## Phase 40: Design Document Review (2026-03-05)

### Critical Missing Technical Details from nmap Research

Based on analysis of `reference/nmap/libpcap/pcap-linux.c`:

#### 1. Socket Option Sequence (CRITICAL)
The design documents miss the **exact ordering requirement**:
```
1. socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
2. setsockopt(PACKET_VERSION, TPACKET_V2)  // MUST come first
3. setsockopt(PACKET_RESERVE, 4)           // MUST come BEFORE PACKET_RX_RING
4. setsockopt(PACKET_RX_RING, &req)        // Ring config
5. mmap()
6. bind()
```

**Gap**: `doc/modules/packet-engineering.md` does not document this sequence.

#### 2. Memory Ordering Requirements
nmap uses C11 atomics with explicit ordering:
```c
#define packet_mmap_acquire(pkt) \
    (__atomic_load_n(&pkt->tp_status, __ATOMIC_ACQUIRE) != TP_STATUS_KERNEL)
#define packet_mmap_release(pkt) \
    (__atomic_store_n(&pkt->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE))
```

**Gap**: Design shows `Ordering::Relaxed` in examples but nmap requires `Acquire/Release`.

#### 3. tpacket_req Field Calculations
nmap's actual calculations (lines 3047-3249):
- `tp_block_size`: Start with `getpagesize()`, double until >= frame_size
- `tp_frame_size`: `TPACKET_ALIGN(macoff + snaplen + reserve)`
- `frames_per_block = tp_block_size / tp_frame_size`
- `tp_block_nr = tp_frame_nr / frames_per_block`

**Gap**: Design shows fixed 2MB blocks but doesn't show the alignment calculations.

#### 4. ENOMEM Recovery Strategy
nmap reduces frame count by 5% iteratively (not 50%):
```c
// lines 3400-3414
while (retry && errno == ENOMEM) {
    req.tp_frame_nr = req.tp_frame_nr * 95 / 100;  // 5% reduction
    // recalculate...
}
```

**Gap**: Design mentions ENOMEM handling but not the 5% iterative reduction strategy.

#### 5. Frame Pointer Array Initialization
After mmap, nmap builds an array of frame pointers:
```c
// lines 3434-3453
for (i = 0; i < handle->cc; ++i) {
    handle->buffer[i] = (u_char *)handlep->mmapbuf + i * req.tp_frame_size;
}
```

**Gap**: Design doesn't show this initialization pattern.

#### 6. VLAN Tag Reconstruction
nmap moves data to insert VLAN tags (lines 4321-4336):
```c
if (VLAN_VALID(h.h2)) {
    memmove((u_char *)h.raw + h.h2->tp_mac + VLAN_TAG_LEN,
            (u_char *)h.raw + h.h2->tp_mac,
            h.h2->tp_len - h.h2->tp_mac);
}
```

**Gap**: Design doesn't cover VLAN tag reconstruction logic.

#### 7. poll() with eventfd for breakloop
nmap uses eventfd for interruptible blocking:
```c
pollinfo[1].fd = handlep->poll_breakloop_fd;
pollinfo[1].events = POLLIN;
```

**Gap**: Design uses AsyncFd but doesn't show the breakloop pattern.

#### 8. Hardware Timestamp Configuration
nmap optionally uses SIOCSHWTSTAMP (lines 3289-3357).

**Gap**: Not mentioned in design - may be optional but should be documented.

### Missing Rust-Specific Patterns

#### 1. async_trait Macro Usage
Design shows `#[async_trait]` but doesn't specify:
- Need to add `async-trait = "0.1"` to dependencies
- Trait methods must have `+ Send` bound for spawning

#### 2. Stream Implementation Details
Design mentions `impl Stream` but doesn't show:
```rust
impl futures::Stream for PacketStream {
    type Item = Result<PacketBuffer, PacketError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<Option<Self::Item>> {
        // ...
    }
}
```

#### 3. Drop Implementation Safety
Design shows Drop but doesn't document:
- `munmap` must be called before `close(fd)`
- Order matters for kernel cleanup
- Need SAFETY comments for all unsafe blocks

#### 4. Error Type Design
Should use `thiserror` pattern:
```rust
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("Socket creation failed: {0}")]
    SocketCreation(#[source] io::Error),
    // ...
}
```

### Document Completeness Matrix

| Requirement | task_plan.md | architecture.md | packet-engineering.md | Status |
|-------------|--------------|-----------------|----------------------|--------|
| Not patch-style | YES | YES | YES | **PASS** |
| Rust async patterns | YES | YES | YES | **FIXED** |
| Rust design patterns | YES | YES | YES | **FIXED** |
| Socket option sequence | YES | YES | YES | **FIXED** |
| Memory ordering | YES | YES | YES | **FIXED** |
| tpacket_req calc | YES | YES | YES | **FIXED** |
| ENOMEM strategy | YES | YES | YES | **FIXED** |
| Frame pointer init | YES | NO | YES | **FIXED** |
| VLAN reconstruction | NO | NO | YES | **FIXED** |
| breakloop pattern | NO | NO | YES | **FIXED** |

### Documentation Updates Completed (2026-03-05)

All critical gaps have been fixed:

1. **doc/modules/packet-engineering.md**:
   - Added "nmap 实现研究" section with all critical patterns
   - Added socket option sequence with error consequences
   - Added tpacket_req calculation formulas
   - Added ENOMEM 5% recovery strategy
   - Added memory ordering requirements (Acquire/Release)
   - Added frame pointer array initialization
   - Added VLAN tag reconstruction logic
   - Added breakloop pattern with eventfd

2. **task_plan.md**:
   - Phase 1.1: Added memory ordering requirements
   - Phase 1.2: Added socket option sequence
   - Phase 1.3: Added tpacket_req calculations and ENOMEM strategy
   - Dependencies: Added async-trait = "0.1"

3. **doc/architecture.md**:
   - Fixed memory ordering in MmapPacketEngine (Acquire/Release)
   - Added SAFETY comments for atomic operations

### Key Findings

#### 1. Current Implementation Analysis

**File:** `crates/rustnmap-packet/src/lib.rs`

**Critical Gap:**
```rust
// Line 764-765 (recv_packet method)
/// This implementation uses recvfrom. Future versions will implement
/// the full `PACKET_MMAP` ring buffer for zero-copy operation.
```

The crate claims PACKET_MMAP V3 support but:
- Only defines constants and config structures
- Never actually calls `mmap()` to create ring buffer
- Uses blocking `recvfrom()` syscall instead

**Code Duplication Found:**
- `SimpleAfPacket` in `ultrascan.rs` (lines 166-211)
- `SimpleAfPacket` in `stealth_scans.rs` (lines 164-211)
- Both use `recvfrom` instead of ring buffer

#### 2. nmap Architecture Insights

**Key Design Decisions from nmap:**
1. Uses **TPACKET_V2** by default (not V3) due to stability issues in kernels < 3.19
2. Ring buffer config: 2MB x 2 blocks = 4MB total
3. nsock event-driven architecture with epoll
4. Adaptive timing with TCP congestion control style
5. Per-block notifications (V2) vs per-frame (V1)

**Files Referenced:**
- `reference/nmap/libpcap/pcap-linux.c` - PACKET_MMAP setup
- `reference/nmap/nsock/` - Event-driven I/O
- `reference/nmap/timing.cc` - Adaptive timing

#### 3. Performance Comparison

| Metric | nmap | rustnmap (current) | Gap |
|--------|-----|--------------------|----|
| Packet capture | PACKET_MMAP V2 | recvfrom | Major |
| Buffer size | 4MB | Socket queue | Major |
| Async I/O | nsock + epoll | spawn_blocking | Major |
| BPF filtering | Kernel-space | Applied but not optimized | Minor |
| Zero-copy | Yes (mmap) | No (copy) | Major |

**Measured Performance Issues:**
- T5 Insane: Unreliable results, ~30% packet loss
- UDP scan: 3x slower than nmap
- T1 Timing: Fixed but limited by architecture

#### 4. Recommended Architecture

```rust
// Core trait
pub trait PacketEngine: Send + Sync {
    async fn start(&mut self) -> Result<(), PacketError>;
    async fn recv(&mut self) -> Result<Option<PacketBuffer>, PacketError>;
    async fn stop(&mut self) -> Result<(), PacketError>;
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), PacketError>;
    fn flush(&self) -> Result<(), PacketError>;
}

// Implementation hierarchy
pub struct MmapPacketEngine { ... }  // PACKET_MMAP V2
pub struct SimplePacketEngine { ... }  // Fallback
pub struct AsyncPacketEngine { ... }  // AsyncFd wrapper
```

**Key Design Patterns:**
- Strategy Pattern: Multiple engine implementations
- Builder Pattern: Engine configuration
- Observer Pattern: Packet handlers
- Channel Pattern: Async packet distribution

---

## Completed Fixes (Phase 39)

### T1 Sneaky Timing - FIXED
**Problem:** 4.8x faster than nmap (16s vs 76s for 2 ports)

**Root Cause:**
1. `ParallelScanEngine` initialized `last_probe_send_time` to `None`
2. Orchestrator didn't enforce `scan_delay` before host discovery
3. Orchestrator didn't enforce `scan_delay` between port probes
4. Engine created fresh after host discovery, losing timing state

**Solution:**
1. Added `enforce_scan_delay()` method to `ScanOrchestrator`
2. Initialize `last_probe_send_time` to `Some(Instant::now())`
3. Call `enforce_scan_delay()` before each probe

**Verification:**
- nmap T1 (2 ports): 76.12s
- rustnmap T1 (2 ports): 76.85s
- Difference: < 1s

### UDP Scan Performance - Still 3x Slower
**Current State:**
- rustnmap UDP: 13.5s (1 port)
- nmap UDP: 4.0s (1 port)
- Gap: 3x slower

**Status:** Architecture redesign required (this phase)

---

## Benchmark History

| Date | Pass | Fail | Skip | Rate | Notes |
|------|------|------|------|------|-------|
| 2026-03-02 17:31 | 36 | 2 | 3 | 92.3% | OS Detection port fix |
| 2026-03-02 16:08 | 37 | 1 | 3 | 94.8% | Stealth timing fix |
| 2026-02-28 | 40 | 1 | 3 | 97.6% | BPF filter implementation |
| 2026-02-27 | 35 | 4 | 2 | 89.7% | |

---

## Technical References

### Linux Kernel
- PACKET_MMAP: Documentation/networking/packet_mmap.txt
- TPACKET V2: include/uapi/linux/if_packet.h
- BPF filters: include/uapi/linux/filter.h

### nmap Source
- libpcap integration: libpcap/pcap-linux.c
- nsock engine: nsock/src/
- Timing: timing.cc, nmap.h

### Rust Patterns
- Async I/O: tokio::io::AsyncFd
- Zero-copy: bytes::Bytes
- Channels: tokio::sync::mpsc
- Atomics: std::sync::atomic with proper ordering

---

## Phase 41: Design Document Coverage Audit (2026-03-05)

### Scope
- Audited `doc/` design documents against 3 requirements:
  1. Not patch-style refactor
  2. Full Rust async/concurrency and Rust design patterns
  3. No missing technical details

### Key Findings

1. **Cross-document architecture conflicts remain (V2 vs V3)**:
   - `doc/structure.md:16` still declares `rustnmap-packet` as "PACKET_MMAP V3"
   - `doc/modules/raw-packet.md:345` still specifies "PACKET_MMAP V3"
   - `doc/modules/stateless-scan.md:438` still references V3 zero-copy receiver
   - `doc/roadmap.md:140` still promotes "AF_PACKET V3" in receive aggregation
   - These conflict with V2 redesign in `doc/architecture.md:217` and `doc/roadmap.md:67`.

2. **nmap reference interpretation is incomplete**:
   - Current docs assert "nmap uses V2" as a fixed conclusion.
   - `reference/nmap/libpcap/pcap-linux.c:2974-3013` shows version negotiation:
     try `TPACKET_V3` first (when not immediate mode), then fallback to `TPACKET_V2`.
   - Missing this negotiation detail can lead to incorrect implementation assumptions.

3. **Async implementation details contain unsafe/non-executable patterns**:
   - `doc/architecture.md:514` creates `File::from_raw_fd(engine.fd)` while engine retains fd ownership.
   - `doc/architecture.md:537-545` spawn block captures `self`/raw pointer patterns that are not valid safe Rust design.
   - These reduce stability and implementation confidence.

4. **Kernel structure details have internal inconsistency**:
   - `doc/modules/packet-engineering.md:324` uses `tp_usec` in a V2 header snippet.
   - Linux `tpacket2_hdr` uses `tp_nsec` (`/usr/include/linux/if_packet.h:146-156`).

5. **Documentation integrity issues remain**:
   - `doc/README.md:44` links `overview.md` (missing)
   - `doc/README.md:83` links `user-guide.md` (missing)
   - Navigation breakage undermines "complete coverage" in practice.

### Requirement Verdict
- Requirement 1 (not patch-style refactor): **PARTIAL**
- Requirement 2 (Rust async/concurrency + design patterns): **PARTIAL**
- Requirement 3 (no missing technical details): **FAIL**

---

## Phase 42: Design Document Re-Check After Fixes (2026-03-05)

### Re-check Summary

After document updates, most critical inconsistencies were fixed:
- V2 baseline aligned in `doc/structure.md`, `doc/modules/raw-packet.md`, `doc/modules/stateless-scan.md`, `doc/roadmap.md`
- nmap V3->V2 negotiation now documented in `doc/architecture.md`
- `File::from_raw_fd(engine.fd)` ownership hazard addressed with fd duplication
- `tp_nsec` vs `tp_usec` corrected

### Remaining Gaps / Optimization Items

1. **TPACKET2 struct definition still mismatches Linux header**
   - Docs still define `tp_padding: [u8; 8]` and claim "48 bytes":
     - `doc/architecture.md:408-421`
     - `doc/modules/packet-engineering.md:312-329`
     - `doc/modules/raw-packet.md:445-460`
   - Linux UAPI defines `tp_padding[4]`:
     - `/usr/include/linux/if_packet.h:146-157`
   - Risk: implementation based on docs may create ABI mismatch.

2. **PacketStream example still has busy-loop wake pattern**
   - `doc/architecture.md:636` uses `cx.waker().wake_by_ref()` on empty queue.
   - This can cause spin behavior / high CPU under no-traffic periods.
   - Better: poll a channel receiver stream (`ReceiverStream`) or register readiness-driven wakeups only.

3. **AsyncFd clone usage in example is likely invalid**
   - `doc/architecture.md:573` uses `let async_fd = self.async_fd.clone();`
   - Tokio `AsyncFd<T>` is not a Clone type in current API; example should use `Arc<AsyncFd<_>>` or move ownership differently.

4. **Residual broken doc links (non-architecture but still doc quality issue)**
   - `doc/manual/README.md:87` -> `../user-guide.md` (deleted)
   - `doc/manual/exit-codes.md:428` -> `../user-guide.md` (deleted)
   - `doc/rustnmap.1:400` points to `doc/user-guide.md` (deleted)

### Updated Verdict
- Requirement 1 (not patch-style refactor): **PASS (with minor doc hygiene pending)**
- Requirement 2 (Rust async/concurrency + patterns): **PARTIAL (examples still need correction)**
- Requirement 3 (no missing technical details): **PARTIAL (TPACKET2 ABI detail still wrong)**

---

## Phase 43: Final Re-Check After Additional Fixes (2026-03-05)

### Verification Outcome

All 5 previously reported issues have been fixed:
1. `tpacket2_hdr` size/padding corrected to 32 bytes + `tp_padding[4]`:
   - `doc/architecture.md:408-422`
   - `doc/modules/packet-engineering.md:312-333`
   - `doc/modules/raw-packet.md:449-475`
   - matches `/usr/include/linux/if_packet.h:146-157`
2. `AsyncFd` ownership/clone issue corrected via `Arc<AsyncFd<OwnedFd>>`:
   - `doc/architecture.md:524-559`, `doc/architecture.md:579`
3. `PacketStream` busy-spin pattern replaced by `ReceiverStream` readiness model:
   - `doc/architecture.md:615-640`
4. nmap V3->V2 negotiation wording aligned in raw-packet docs:
   - `doc/modules/raw-packet.md:349-354`
5. broken links to deleted `user-guide.md` removed:
   - `doc/manual/README.md:87-90`
   - `doc/manual/exit-codes.md:427-429`
   - `doc/rustnmap.1:399-400`

### Minor Remaining Optimization (Non-blocking)
- `doc/architecture.md:660-671` has duplicate `Cargo.toml` dependency blocks (one includes `tokio-stream`, one only `futures`).
  Recommend merging into one authoritative block to avoid ambiguity.

---

## Phase 42: Design Document Systematic Fixes (2026-03-05)

### Scope
Systematic fixes for all issues identified in Phase 41 audit.

### Fixes Applied

#### 1. TPACKET2 结构体定义 (HIGH PRIORITY) - FIXED

| 文件 | 问题 | 修复 |
|------|-------|-----|
| `doc/architecture.md:408-421` | `tp_padding: [u8; 8]`, 48 字节 | 改为 `tp_padding: [u8; 4]`, **32 字节** |
| `doc/modules/packet-engineering.md:312-329` | 同上 | 同上 |
| `doc/modules/raw-packet.md:445-460` | 同上 | 同上 |

**Linux UAPI 参考**: `/usr/include/linux/if_packet.h:146-157`
```c
struct tpacket2_hdr {
    __u32   tp_status;
    __u32   tp_len;
    __u32   tp_snaplen;
    __u16   tp_mac;
    __u16   tp_net;
    __u32   tp_sec;
    __u32   tp_nsec;   // NOT tp_usec!
    __u16   tp_vlan_tci;
    __u16   tp_vlan_tpid;
    __u8    tp_padding[4]; // NOT [8]!
};  // Total: 32 bytes
```

#### 2. AsyncFd Clone API 问题 (HIGH PRIORITY) - FIXED

| 文件 | 问题 | 修复 |
|------|-------|-----|
| `doc/architecture.md:573` | `self.async_fd.clone()` | Tokio `AsyncFd<T>` 不是 Clone，使用 `Arc<AsyncFd<OwnedFd>>` |

**修复方案**:
```rust
pub struct AsyncPacketEngine {
    async_fd: std::sync::Arc<AsyncFd<OwnedFd>>,  // Arc 包装
}

// 在 spawn task 中:
let async_fd = self.async_fd.clone();  // Arc::clone()
```

#### 3. PacketStream Busy-Spin 风险 (MEDIUM PRIORITY) - FIXED

| 文件 | 问题 | 修复 |
|------|-------|-----|
| `doc/architecture.md:636` | 无数据时 `wake_by_ref()` 导致高频自唤醒 | 使用 `ReceiverStream` 包装 channel |

**修复方案**:
```rust
pub struct PacketStream {
    inner: ReceiverStream<Result<PacketBuffer, PacketError>>,
}

impl Stream for PacketStream {
    fn poll_next(...) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)  // 委托给 ReceiverStream
    }
}
```

#### 4. nmap 行为表述统一 (MEDIUM PRIORITY) - ALREADY CONSISTENT

| 文件 | 内容 | 状态 |
|------|-------|------|
| `doc/modules/raw-packet.md:348-354` | "先尝试 V3，再回退 V2" + "扫描器通常使用 immediate mode" | 已正确 |
| `doc/architecture.md:233-254` | 同上 | 已正确 |

#### 5. 残留断链 (LOW PRIORITY) - VERIFIED NO ISSUE

| 文件 | 链接 | 状态 |
|------|------|------|
| `doc/manual/README.md:87` | `../../README.md` | 正确 |
| `doc/manual/exit-codes.md:428` | `README.md` | 正确 |
| `doc/rustnmap.1:400` | `doc/manual/README.md` | 正确 |

**注**: Phase 41 报告的断链目标文件是 `doc/user-guide.md`，但实际链接指向的是 `doc/manual/README.md`。

### Updated Requirement Verdict
- Requirement 1 (not patch-style refactor): **PASS**
- Requirement 2 (Rust async/concurrency + design patterns): **PASS**
- Requirement 3 (no missing technical details): **PASS**

### Files Modified
- `doc/architecture.md` - TPACKET2 大小修正、AsyncFd Arc 模式、ReceiverStream 模式
- `doc/modules/packet-engineering.md` - TPACKET2 大小修正
- `doc/modules/raw-packet.md` - TPACKET2 大小修正
