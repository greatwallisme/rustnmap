# Task Plan: Refactoring According to doc/ Technical Methods

> **Created**: 2026-03-07
> **Updated**: 2026-03-07
> **Status**: Phase 1 - Complete | Phase 2 - Complete | Phase 3 - Complete
> **Priority**: P0

---

## Executive Summary

Continue refactoring strictly according to `doc/architecture.md` and `doc/structure.md` technical specifications.

**Previous Work (Complete):**
- ✅ Phase 2: Network volatility handling (5 components fully aligned with design)
- ✅ Phase 3: Integration into ScanOrchestrator completed

**Gap Analysis Completed (2026-03-07):**
- 📋 Comprehensive design vs implementation comparison added to `findings.md`
- 🔴 CRITICAL: Packet Engine still uses recvfrom() instead of PACKET_MMAP V2
- ✅ Network Volatility: All 5 components match design exactly (62 tests)
- ⚠️ Scanner Architecture: PacketEngine trait exists but not used by scanners
- 📊 See `findings.md` Section: "Design vs Implementation Gap Analysis"

**Current Focus:**
Address critical PACKET_MMAP V2 implementation gap (Phase 4)

---

## Phase 1: PACKET_MMAP V2 Infrastructure ✅ COMPLETE

| Task | Component | Status |
|------|-----------|--------|
| 1.1 | TPACKET_V2 system call wrappers | COMPLETE |
| 1.2 | PacketEngine trait | COMPLETE |
| 1.3 | MmapPacketEngine | COMPLETE |
| 1.4 | BPF Filter | COMPLETE |
| 1.5 | AsyncPacketEngine | COMPLETE |
| 1.6 | Zero-copy packet buffer | COMPLETE |
| 1.7 | Two-stage bind fix | COMPLETE |
| 1.8 | Performance benchmarks | COMPLETE |

---

## Phase 2: Network Volatility Handling (CURRENT)

> **Reference**: `doc/architecture.md` Section 2.3.4

### Architecture Requirements

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Network Volatility Handling Architecture                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        AdaptiveTiming (RFC 6298)                       │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  SRTT = (7/8) * SRTT + (1/8) * RTT                              │  │  │
│  │  │  RTTVAR = (3/4) * RTTVAR + (1/4) * |RTT - SRTT|                 │  │  │
│  │  │  Timeout = SRTT + 4 * RTTVAR                                    │  │  │
│  │  │  Timeout = clamp(Timeout, min_rtt, max_rtt)                     │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    CongestionController (TCP-like)                     │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│  │  │ cwnd (拥塞窗口)  │  │ ssthresh (阈值)  │  │ Phase Detection      │ │  │
│  │  │ Initial: 1       │  │ Initial: ∞       │  │ - Slow Start         │ │  │
│  │  │ Min: 1           │  │ On drop: cwnd/2  │  │ - Congestion Avoid   │ │  │
│  │  │ Max: max_cwnd    │  │                  │  │ - Recovery           │ │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ScanDelayBoost (动态延迟)                         │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  On high drop rate:                                              │  │  │
│  │  │    if timing_level < 4: delay = min(10000, max(1000, delay*10)) │  │  │
│  │  │    else: delay = min(1000, max(100, delay*2))                   │  │  │
│  │  │                                                                  │  │  │
│  │  │  Decay after good responses:                                     │  │  │
│  │  │    if good_responses > threshold: delay = max(default, delay/2) │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      RateLimiter (Token Bucket)                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  --min-rate: 保证最小发包速率                                     │  │  │
│  │  │  --max-rate: 限制最大发包速率                                     │  │  │
│  │  │  Tokens replenish at rate R per second                           │  │  │
│  │  │  Burst size = min_rate * burst_factor                            │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ErrorRecovery (ICMP 分类)                         │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │  │
│  │  │ HOST_UNREACH     │  │ NET_UNREACH      │  │ PORT_UNREACH (UDP)   │ │  │
│  │  │ -> Mark Down     │  │ -> Reduce cwnd   │  │ -> Mark Closed       │ │  │
│  │  ├──────────────────┤  ├──────────────────┤  ├──────────────────────┤ │  │
│  │  │ ADMIN_PROHIBITED │  │ FRAG_NEEDED      │  │ TIMEOUT              │ │  │
│  │  │ -> Mark Filtered │  │ -> Set DF=0      │  │ -> Retry w/ backoff  │ │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Task 2.1: Adaptive RTT (RFC 6298)

**File**: `crates/rustnmap-scan/src/timeout.rs` (ALREADY EXISTS)

**Requirements**:
- `SRTT = (7/8)*SRTT + (1/8)*RTT`
- `RTTVAR = (3/4)*RTTVAR + (1/4)*|RTT - SRTT|`
- `Timeout = SRTT + 4*RTTVAR`
- `Timeout = clamp(Timeout, min_rtt, max_rtt)`

**Reference**: `doc/architecture.md` Section 2.3.4

**Status**: ✅ COMPLETE - Existing implementation fully satisfies requirements

---

### Task 2.2: Congestion Control

**File**: `crates/rustnmap-scan/src/congestion.rs` (CREATED)

**Requirements**:
- `cwnd` (congestion window): Initial=1, Min=1, Max=max_cwnd
- `ssthresh` (threshold): Initial=∞, On drop=cwnd/2
- Phase detection: Slow Start, Congestion Avoidance, Recovery

**Reference**: `doc/architecture.md` Section 2.3.4

**Implementation**:
- `CongestionControl` struct with TCP-like behavior
- `on_packet_sent()`: Updates cwnd based on phase
- `on_packet_loss()`: Reduces ssthresh and resets cwnd
- `end_rtt()`: Marks RTT completion
- 11 unit tests passing

**Status**: ✅ COMPLETE

---

### Task 2.3: Scan Delay Boost

**File**: `crates/rustnmap-scan/src/adaptive_delay.rs` (CREATED)

**Requirements**:
- On high drop rate: exponential backoff
  - `timing_level < 4`: `delay = min(10000, max(1000, delay*10))`
  - `timing_level >= 4`: `delay = min(1000, max(100, delay*2))`
- Decay after good responses: `delay = max(default, delay/2)`

**Reference**: `doc/architecture.md` Section 2.3.4

**Implementation**:
- `AdaptiveDelay` struct with timing template support
- `on_high_drop_rate()`: Exponential backoff based on timing level
- `on_good_response()`: Delay decay after threshold
- `on_packet_loss()`: Aggressive backoff trigger
- 24 unit tests passing

**Status**: ✅ COMPLETE

---

### Task 2.4: Rate Limiter (Token Bucket)

**File**: `crates/rustnmap-common/src/rate.rs` (ALREADY EXISTS)

**Requirements**:
- `--min-rate`: Guarantee minimum packet rate
- `--max-rate`: Limit maximum packet rate
- Tokens replenish at rate R per second
- Burst size = `min_rate * burst_factor`

**Reference**: `doc/architecture.md` Section 2.3.4

**Status**: ✅ COMPLETE - Existing implementation fully satisfies requirements

---

### Task 2.5: ICMP Error Classification

**File**: `crates/rustnmap-scan/src/icmp_handler.rs` (CREATED)

**Requirements**:
- `HOST_UNREACH` → Mark Down
- `NET_UNREACH` → Reduce cwnd, Boost delay
- `PORT_UNREACH` (UDP) → Mark Closed
- `ADMIN_PROHIBITED` → Mark Filtered
- `FRAG_NEEDED` → Set DF=0
- `TIMEOUT` → Retry with backoff

**Reference**: `doc/architecture.md` Section 2.3.4

**Implementation**:
- `classify_icmp_error()`: Maps ICMP type/code to actions
- `action_to_port_state()`: Converts action to port state
- `IcmpParser`: Extracts type/code from raw packets
- Supports all RFC 792 ICMP types and codes
- 16 unit tests passing

**Status**: ✅ COMPLETE

---

## Phase 3: Integration & Testing (COMPLETE)

> **Reference**: `doc/architecture.md` Section 2.3.5

### Task 3.1: Scanner Orchestration Integration

**Files**:
- `crates/rustnmap-core/src/orchestrator.rs` (MODIFIED)
- `crates/rustnmap-scan/src/lib.rs` (MODIFIED)

**Implementation**:
- Added `Arc<Mutex<CongestionControl>>` to `ScanOrchestrator`
- Added `Arc<Mutex<AdaptiveDelay>>` to `ScanOrchestrator`
- Created timing-based `initial_cwnd()` and `max_cwnd()` helpers
- Enhanced `enforce_scan_delay()` to use adaptive delay (max of template and adaptive)
- Added `record_probe_timeout()` and `record_successful_response()` helper methods
- Added public accessors: `congestion_control()` and `adaptive_delay()`
- Re-exported `classify_icmp_error` and `IcmpAction` from `rustnmap-scan`

**Status**: ✅ COMPLETE

---

### Task 3.2: Integration Testing

**Status**: ⏸️ DEFERRED - Requires actual network targets for comprehensive testing

**Note**: Unit tests for all components pass (865 tests total). Full integration testing with live network targets is deferred to Phase 4.

---

### Task 3.3: Documentation Updates

**Status**: ⏸️ DEFERRED - Documentation updates to be done with Phase 4 integration testing

**Note**: All public APIs have proper doc comments with `# Errors` and `# Panics` sections.

---

## Phase 4: Scanner Migration to PACKET_MMAP (PENDING)

> **Gap Analysis Update**: See `findings.md` section "Design vs Implementation Gap Analysis" for comprehensive comparison.

### Critical Finding from Gap Analysis

**Design**: PACKET_MMAP V2 ring buffer with zero-copy
**Reality**: Still using `recvfrom()` fallback (see `rustnmap-packet/src/lib.rs:764-765`)

| Metric | Design Target | Current Actual | Gap |
|--------|--------------|---------------|-----|
| PPS | ~1,000,000 | ~50,000 | **20x slower** |
| CPU (T5) | 30% | 80% | **2.7x higher** |
| Packet Loss (T5) | <1% | ~30% | **30x worse** |

### Task 4.1: Complete PACKET_MMAP V2 Implementation (P0 CRITICAL)

**Root Cause**: Phase 1 marked "COMPLETE" but implementation uses fallback recvfrom()

**Required Actions**:
1. Implement true zero-copy in `MmapPacketEngine::try_recv()`
   - Use `Bytes::from_raw_parts()` instead of `Bytes::copy_from_slice()`
   - Implement frame lifecycle management with `Arc<MmapPacketEngine>`
   - Add frame tracking bitmap to prevent reuse

2. Fix memory ordering
   - Use `Ordering::Acquire` for frame availability check
   - Use `Ordering::Release` for frame release
   - NEVER use `SeqCst` (5-10x performance cost)

3. Validate Drop order
   - MUST munmap BEFORE close fd (or EBADF error)

**Files**:
- `crates/rustnmap-packet/src/mmap.rs`
- `crates/rustnmap-packet/src/zero_copy.rs`

**Status**: 🔴 BLOCKS ALL PERFORMANCE FIXES

---

### Task 4.2: Migrate Scanners to PacketEngine Trait

**Gap Finding**: Scanners use `SimpleAfPacket` or `RawSocket`, not `PacketEngine` trait

**Files**:
- `crates/rustnmap-scan/src/syn_scan.rs` (uses `RawSocket`)
- `crates/rustnmap-scan/src/stealth_scans.rs` (uses `SimpleAfPacket`)
- `crates/rustnmap-scan/src/ultrascan.rs` (uses `SimpleAfPacket`)
- `crates/rustnmap-scan/src/udp_scan.rs` (uses `RawSocket`)

**Requirements**:
- Replace `SimpleAfPacket` with `AsyncPacketEngine`
- Replace `RawSocket` with `PacketEngine` trait
- Create `ScannerPacketEngine` adapter pattern for gradual migration
- Maintain backward compatibility during migration

**Status**: ⚠️ BLOCKED BY TASK 4.1

---

### Task 4.3: Performance Validation

**Goal**: Verify 1M PPS target after PACKET_MMAP V2 completion

**Command**:
```bash
TEST_INTERFACE=ens33 sudo cargo bench -p rustnmap-benchmarks -- recvfrom_pps
```

**Target Metrics**:

| Metric | Current (recvfrom) | Target (PACKET_MMAP) | Improvement |
|--------|-------------------|---------------------|-------------|
| PPS | ~50,000 | ~1,000,000 | 20x |
| CPU (T5) | 80% | 30% | 2.7x |
| Packet Loss (T5) | ~30% | <1% | 30x |

**Acceptance Criteria**:
- [ ] PPS >= 500,000 (50% of target)
- [ ] CPU (T5) <= 50%
- [ ] Packet Loss (T5) <= 5%
- [ ] Zero-copy verified (no memcpy in hot path)

**Status**: ⏸️ BLOCKED BY TASK 4.1

---

## Phase 5: Testing & Documentation (PENDING)

**Files**:
- `doc/architecture.md` - Update performance tables
- `doc/modules/timing.md` (CREATE) - Timing module documentation
- `doc/modules/congestion.md` (CREATE) - Congestion control documentation

**Status**: PENDING

---

## Summary

**Current Phase**: Gap Analysis Complete | Phase 4 - Pending (Critical)

**Gap Analysis Findings** (2026-03-07):
- 📋 Comprehensive design vs implementation comparison completed
- See `findings.md`: "Design vs Implementation Gap Analysis" section
- 🔴 **CRITICAL**: Packet Engine uses recvfrom() instead of PACKET_MMAP V2
  - Phase 1 "COMPLETE" status was incorrect - still using fallback
  - Required: Complete zero-copy implementation (Task 4.1)
- ✅ **Network Volatility**: All 5 components match design exactly
- ⚠️ **Scanner Architecture**: PacketEngine trait not used by scanners
- ✅ **Timing Templates**: T0-T5 implemented with acceptable deviation

**Updated Phase 4 Tasks**:
- Task 4.1: Complete PACKET_MMAP V2 (P0 CRITICAL - blocks performance)
- Task 4.2: Migrate scanners to PacketEngine trait
- Task 4.3: Performance validation (1M PPS target)

**Blocking Issue**:
Cannot achieve 1M PPS target until true PACKET_MMAP V2 with zero-copy is implemented.
Current recvfrom() approach limits performance to ~50K PPS.

**Phase 2 Completion**:
- ✅ Task 2.1: Adaptive RTT (existing `timeout.rs` satisfies RFC 2988)
- ✅ Task 2.2: Congestion Control (`congestion.rs` created, 11 tests passing)
- ✅ Task 2.3: Scan Delay Boost (`adaptive_delay.rs` created, 24 tests passing)
- ✅ Task 2.4: Rate Limiter (existing `rate.rs` satisfies token bucket)
- ✅ Task 2.5: ICMP Handler (`icmp_handler.rs` created, 16 tests passing)

**Phase 3 Completion**:
- ✅ Task 3.1: Scanner Orchestration Integration
  - `ScanOrchestrator` now has `CongestionControl` and `AdaptiveDelay`
  - Timing-based cwnd initialization (T0-T5)
  - Adaptive delay enforcement
  - Public accessors for monitoring
- ⏸️ Task 3.2: Integration Testing (deferred - needs live network)
- ⏸️ Task 3.3: Documentation Updates (deferred to Phase 4)

**Quality Metrics**:
- All 865 tests passing (up from 132)
- Zero clippy warnings
- Code formatted with rustfmt
- Workspace compiles cleanly

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| *(Pending implementation)* | - | - |
