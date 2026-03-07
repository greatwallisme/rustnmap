# Research Findings: Phase 3 - Network Volatility Integration

> **Created**: 2026-03-07
> **Updated**: 2026-03-07
> **Status**: Phase 3 - Complete | Phase 4 - Pending

---

## Phase 1 Complete Summary (Previous Work)

All core PACKET_MMAP V2 infrastructure has been completed:

| Component | Status | Description |
|-----------|--------|-------------|
| TPACKET_V2 Wrappers | COMPLETE | System call bindings, constants, structures |
| PacketEngine Trait | COMPLETE | Core abstraction for async packet I/O |
| MmapPacketEngine | COMPLETE | Ring buffer management, zero-copy operation |
| BPF Filter | COMPLETE | Kernel-space packet filtering |
| AsyncPacketEngine | COMPLETE | Tokio AsyncFd integration |
| ZeroCopyPacket | COMPLETE | True zero-copy packet buffer |
| Two-Stage Bind | COMPLETE | Fixed errno=22 issue |
| Benchmarks | COMPLETE | Performance measurement infrastructure |

**Key Fix Applied**: Two-stage bind pattern following nmap's libpcap implementation:
1. First bind with `protocol=0` (allows ring buffer setup)
2. `PACKET_RX_RING` setup
3. Second bind with `ETH_P_ALL.to_be()` (enables packet reception)

**Reference**: `reference/nmap/libpcap/pcap-linux.c:1297-1302`

---

## Phase 2: Network Volatility Architecture (NEW)

### Reference: `doc/architecture.md` Section 2.3.4

### Architecture Overview

The network volatility handling system consists of 5 core components:

1. **AdaptiveTiming (RFC 6298)** - RTT estimation and timeout calculation
2. **CongestionController** - TCP-like congestion control
3. **ScanDelayBoost** - Dynamic scan delay adjustment
4. **RateLimiter** - Token bucket rate limiting
5. **ErrorRecovery** - ICMP error classification

### Phase 2 Implementation Summary

| Component | File | Status | Test Coverage |
|-----------|------|--------|---------------|
| Adaptive RTT | `timeout.rs` | ✅ COMPLETE (existing) | 5 tests |
| Congestion Control | `congestion.rs` | ✅ COMPLETE (created) | 11 tests |
| Scan Delay Boost | `adaptive_delay.rs` | ✅ COMPLETE (created) | 24 tests |
| Rate Limiter | `rate.rs` | ✅ COMPLETE (existing) | 6 tests |
| ICMP Handler | `icmp_handler.rs` | ✅ COMPLETE (created) | 16 tests |

**Total**: 62 unit tests for network volatility components

### Design Patterns from doc/architecture.md

#### 1. Adaptive RTT (RFC 6298)

```rust
// From doc/architecture.md Section 2.3.4
struct AdaptiveTiming {
    srtt: Duration,      // Smoothed RTT
    rttvar: Duration,    // RTT variance
    min_rtt: Duration,   // Minimum timeout
    max_rtt: Duration,   // Maximum timeout
}

impl AdaptiveTiming {
    fn update_rtt(&mut self, rtt: Duration) -> Duration {
        // SRTT = (7/8) * SRTT + (1/8) * RTT
        self.srtt = self.srtt.mul_f32(7.0/8.0) + rtt.mul_f32(1.0/8.0);

        // RTTVAR = (3/4) * RTTVAR + (1/4) * |RTT - SRTT|
        let rtt_diff = if rtt > self.srtt { rtt - self.srtt } else { self.srtt - rtt };
        self.rttvar = self.rttvar.mul_f32(3.0/4.0) + rtt_diff.mul_f32(1.0/4.0);

        // Timeout = SRTT + 4 * RTTVAR
        let timeout = self.srtt + self.rttvar.mul_f32(4.0);

        // Clamp to [min_rtt, max_rtt]
        timeout.clamp(self.min_rtt, self.max_rtt)
    }
}
```

#### 2. Congestion Control

```rust
// From doc/architecture.md Section 2.3.4
struct CongestionControl {
    cwnd: u32,           // Congestion window (probes in flight)
    ssthresh: u32,       // Slow start threshold
    max_cwnd: u32,       // Maximum window size
    phase: Phase,        // Slow Start, Congestion Avoidance, Recovery
}

enum Phase {
    SlowStart,           // Exponential growth: cwnd *= 2 per RTT
    CongestionAvoidance, // Linear growth: cwnd += 1 per RTT
    Recovery,            // Reduce after loss
}

impl CongestionControl {
    fn on_packet_sent(&mut self) {
        if self.cwnd < self.ssthresh {
            // Slow Start: exponential
            self.cwnd = self.cwnd.saturating_mul(2);
        } else {
            // Congestion Avoidance: linear
            self.cwnd = self.cwnd.saturating_add(1);
        }
        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    fn on_packet_loss(&mut self) {
        self.ssthresh = self.cwnd / 2;
        self.cwnd = 1;
        self.phase = Phase::Recovery;
    }
}
```

#### 3. Scan Delay Boost

```rust
// From doc/architecture.md Section 2.3.4
struct AdaptiveDelay {
    current_delay: Duration,
    default_delay: Duration,
    timing_level: u8,     // 0-5 for T0-T5
    drop_rate: f32,
}

impl AdaptiveDelay {
    fn on_high_drop_rate(&mut self) {
        if self.drop_rate > 0.25 {
            if self.timing_level < 4 {
                // T0-T3: aggressive backoff
                self.current_delay = self.current_delay.mul_f32(10.0);
                self.current_delay = self.current_delay.min(Duration::from_millis(10000));
                self.current_delay = self.current_delay.max(Duration::from_millis(1000));
            } else {
                // T4-T5: moderate backoff
                self.current_delay = self.current_delay.mul_f32(2.0);
                self.current_delay = self.current_delay.min(Duration::from_millis(1000));
                self.current_delay = self.current_delay.max(Duration::from_millis(100));
            }
        }
    }

    fn on_good_response(&mut self) {
        // Decay delay if getting good responses
        self.current_delay = self.current_delay / 2;
        self.current_delay = self.current_delay.max(self.default_delay);
    }
}
```

#### 4. Token Bucket Rate Limiter

```rust
// From doc/architecture.md Section 2.3.4
struct RateLimiter {
    tokens: u64,             // Current tokens
    last_update: Instant,    // Last token replenishment
    min_rate: u64,           // Minimum packets per second
    max_rate: Option<u64>,   // Maximum packets per second (None = unlimited)
    burst_factor: f32,       // Burst size multiplier
}

impl RateLimiter {
    fn try_consume(&mut self) -> bool {
        self.replenish_tokens();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn replenish_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        self.last_update = now;

        // Add tokens based on min_rate
        let new_tokens = (elapsed.as_secs_f64() * self.min_rate as f64) as u64;
        self.tokens = self.tokens.saturating_add(new_tokens);

        // Cap burst size
        let max_burst = (self.min_rate as f32 * self.burst_factor) as u64;
        self.tokens = self.tokens.min(max_burst);
    }
}
```

#### 5. ICMP Error Classification

```rust
// From doc/architecture.md Section 2.3.4
enum IcmpAction {
    MarkDown,           // Host is down
    ReduceCwnd,         // Reduce congestion window
    MarkClosed,         // Port is closed
    MarkFiltered,       // Traffic filtered
    SetDfZero,          // Disable DF bit
    RetryWithBackoff,   // Retry with exponential backoff
}

fn classify_icmp_error(icmp_type: u8, icmp_code: u8) -> IcmpAction {
    match (icmp_type, icmp_code) {
        (3, 0 | 1) => IcmpAction::MarkDown,           // NET_UNREACH
        (3, 2 | 9 | 10) => IcmpAction::MarkDown,      // HOST_UNREACH
        (3, 3) => IcmpAction::MarkDown,               // PORT_UNREACH
        (3, 13) => IcmpAction::MarkFiltered,          // ADMIN_PROHIBITED
        (3, 4) => IcmpAction::SetDfZero,              // FRAG_NEEDED
        _ => IcmpAction::RetryWithBackoff,
    }
}
```

---

## Timing Template Parameters (doc/architecture.md Table)

| Parameter | T0 | T1 | T2 | T3 | T4 | T5 |
|-----------|-----|-----|-----|-----|-----|-----|
| min_rtt_timeout | 100ms | 100ms | 100ms | 100ms | 100ms | 50ms |
| max_rtt_timeout | 10s | 10s | 10s | 10s | 10s | 300ms |
| initial_rtt | 1s | 1s | 1s | 1s | 500ms | 250ms |
| max_retries | 10 | 10 | 10 | 10 | 6 | 2 |
| scan_delay | 5min | 15s | 400ms | 0ms | 0ms | 0ms |
| max_parallelism | 1 | 1 | 1 | dynamic | dynamic | dynamic |
| min_host_group | 1 | 1 | 1 | 1 | 1 | 1 |
| max_host_group | 1 | 1 | 1 | 100 | 100 | 256 |
| min_rate | 0 | 0 | 0 | 0 | 0 | 0 |
| max_rate | 0 | 0 | 0 | 0 | 0 | 0 |
| cwnd_initial | 1 | 1 | 1 | 1 | 1 | 1 |
| cwnd_max | 10 | 10 | 10 | dynamic | dynamic | dynamic |

---

## Key Implementation Decisions

### 1. Use Float for RTT Calculations

RFC 6298 uses fractional multipliers (7/8, 1/8, 3/4, 1/4).
Use `Duration::mul_f32()` for precise fractional arithmetic.

### 2. Clamp Timeouts to Template Range

Each timing template has min/max timeout bounds.
Always clamp calculated timeout to this range.

### 3. Separate Host-Level vs Group-Level Congestion

`doc/architecture.md` mentions:
- Group-level: Drop affects entire host group
- Host-level: Drop affects single host

Implementation needs separate tracking.

### 4. Rate Limiting is Optional

`--min-rate` and `--max-rate` are optional CLI flags.
When not specified, rate limiter is disabled (unlimited).

---

## Dependencies Required

All components use only standard library and existing crates:

| Crate | Purpose |
|-------|---------|
| std | Duration, Instant, arithmetic |
| rustnmap-common | ScanConfig, timing templates |
| tokio | Time utilities for rate limiting |

No new dependencies required.

---

---

## Phase 2 Implementation Details

### Module: `congestion.rs`

**Key Design Decisions**:
- Used `u32::MAX` for initial `ssthresh` to represent infinity
- Phase detection: Slow Start (cwnd < ssthresh) vs Congestion Avoidance (cwnd >= ssthresh)
- RTT tracking with `packets_acked` counter and `rtt_start` timestamp

**API Surface**:
```rust
pub struct CongestionControl {
    cwnd: u32,           // Congestion window
    ssthresh: u32,       // Slow start threshold
    max_cwnd: u32,       // Maximum window
    phase: Phase,        // Current phase (internal)
    packets_acked: u32,  // ACK count for RTT (internal)
    rtt_start: Option<Instant>,  // RTT timer (internal)
}

impl CongestionControl {
    pub fn new(initial_cwnd: u32, max_cwnd: u32) -> Self;
    pub fn cwnd(&self) -> u32;
    pub fn ssthresh(&self) -> u32;
    pub fn can_send(&self, unacked: u32) -> bool;
    pub fn on_packet_sent(&mut self);
    pub fn on_packet_loss(&mut self);
    pub fn on_timeout(&mut self);
    pub fn end_rtt(&mut self);
    pub fn current_rtt(&self) -> Option<Duration>;
    pub fn reset(&mut self);
}
```

### Module: `adaptive_delay.rs`

**Key Design Decisions**:
- Timing level mapping: T0=0, T1=1, T2=2, T3=3, T4=4, T5=5
- Aggressive backoff (10x) for T0-T3, moderate (2x) for T4-T5
- Good response threshold: 5 consecutive responses before delay decay
- Drop rate estimate decay: 0.9 multiplier per good response

**API Surface**:
```rust
pub struct AdaptiveDelay {
    current_delay: Duration,
    default_delay: Duration,
    timing_level: u8,
    good_responses: u8,
    drop_rate: f32,
}

impl AdaptiveDelay {
    pub fn new(template: TimingTemplate) -> Self;
    pub fn delay(&self) -> Duration;
    pub fn timing_level(&self) -> u8;
    pub fn drop_rate(&self) -> f32;
    pub fn on_high_drop_rate(&mut self, drop_rate: f32);
    pub fn on_good_response(&mut self);
    pub fn on_packet_loss(&mut self);
    pub fn set_delay(&mut self, delay: Duration);
    pub fn reset(&mut self);
}
```

### Module: `icmp_handler.rs`

**Key Design Decisions**:
- Const fn for `classify_icmp_error` - can be used in const contexts
- Combined match arms where actions are identical (clippy compliance)
- Parser assumes IPv4 with 20-byte header (validated)

**API Surface**:
```rust
pub enum IcmpAction {
    MarkDown,
    ReduceCwnd,
    MarkClosed,
    MarkFiltered,
    SetDfZero,
    RetryWithBackoff,
    None,
}

pub enum IcmpType { ... }  // repr(u8)
pub enum DestUnreachableCode { ... }  // repr(u8)

pub const fn classify_icmp_error(icmp_type: u8, icmp_code: u8) -> IcmpAction;
pub const fn action_to_port_state(action: IcmpAction) -> Option<PortState>;

pub struct IcmpParser;
impl IcmpParser {
    pub const fn extract_type_code(packet: &[u8]) -> Option<(u8, u8)>;
}
```

### Existing Module: `timeout.rs`

**Discovery**: Existing implementation fully satisfies RFC 2988 requirements:
- `SRTT = (7/8)*SRTT + (1/8)*RTT` ✅
- `RTTVAR = (3/4)*RTTVAR + (1/4)*|RTT - SRTT|` ✅
- `Timeout = SRTT + 4*RTTVAR` ✅
- Clamping to min/max RTT ✅

### Existing Module: `rate.rs` (in rustnmap-common)

**Discovery**: Existing implementation fully satisfies token bucket requirements:
- Lock-free atomics for performance ✅
- `--min-rate` support ✅
- `--max-rate` support ✅
- Pre-computed packet interval for hot path optimization ✅

---

## Testing Strategy

### Unit Tests

- Test RTT calculation with fixed values
- Test congestion state transitions
- Test delay boost behavior
- Test token bucket under various rates

### Integration Tests

- Test with simulated packet loss
- Test with varying RTT
- Test rate limiting with actual traffic
- Test ICMP error handling

---

## References

- `doc/architecture.md` - Full architecture specification
- `doc/structure.md` - Module structure
- RFC 6298 - TCP Retransmission Timer
- `reference/nmap/timing.cc` - Nmap timing implementation
- `reference/nmap/scan_engine.cc` - Nmap scan engine

---

## Next Steps (Phase 3)

1. Integrate network volatility components into scanner orchestration
2. Create integration tests with actual network targets
3. Update documentation with performance metrics
4. Performance validation benchmarks
5. Consider scanner migration to PACKET_MMAP V2 (Phase 3.1)

---

## Phase 3 Integration Findings

### Integration Architecture

The network volatility components have been integrated into `ScanOrchestrator`:

```rust
pub struct ScanOrchestrator {
    // ... existing fields ...
    congestion_control: Arc<Mutex<CongestionControl>>,
    adaptive_delay: Arc<Mutex<AdaptiveDelay>>,
}
```

### Timing-Based Initialization

Helper functions determine congestion window parameters based on timing template:

| Template | Initial CWND | Max CWND |
|----------|-------------|----------|
| T0 Paranoid | 1 | 1 |
| T1 Sneaky | 3 | 5 |
| T2 Polite | 5 | 10 |
| T3 Normal | 10 | 50 |
| T4 Aggressive | 50 | 100 |
| T5 Insane | 100 | 500 |

### Adaptive Delay Enforcement

The `enforce_scan_delay()` method now uses the maximum of template delay and adaptive delay:

```rust
let template_delay = self.session.config.timing_template.scan_config().scan_delay;
let adaptive_delay = { delay_guard.lock().await.delay() };
let scan_delay = template_delay.max(adaptive_delay);
```

This ensures that:
- If network conditions are poor, adaptive delay kicks in
- If network is good, template default is used
- Delay never drops below the template minimum

### Public API for Monitoring

External code can access the volatility components:

```rust
pub fn congestion_control(&self) -> Arc<Mutex<CongestionControl>>
pub fn adaptive_delay(&self) -> Arc<Mutex<AdaptiveDelay>>
```

This enables monitoring and debugging of the volatility state during scans.

### Integration Points for Future Work

The following methods are ready to be called from scanning loops:

1. **`record_probe_timeout()`** - Call when a probe times out
   - Updates congestion control (reduces cwnd)
   - Updates adaptive delay (increases delay)

2. **`record_successful_response()`** - Call on successful probe
   - Updates adaptive delay (may reduce delay)
   - Tracks good responses for decay

3. **`classify_icmp_error()`** - Use when processing ICMP errors
   - Returns appropriate action (MarkDown, ReduceCwnd, etc.)
   - Maps to port states for reporting

---
