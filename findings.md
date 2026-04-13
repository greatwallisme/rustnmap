# Technical Findings

> **Updated**: 2026-04-12 (Post Phase 4 Memory Optimization)

---

## MEMORY OPTIMIZATION RESULTS (Phase 4)

### OS Fingerprint Compact Representation (2026-04-12)

**Problem**: OS detection memory 135MB (4.1x nmap's 33MB). Root cause: `RawFingerprint = HashMap<String, HashMap<String, String>>` with 6036 fingerprints, each storing ~14 sections of ~10 key-value String pairs.

**nmap Reference Analysis** (from C++ source code):
- `string_pool`: Global string interning for common values ("Y", "N", "S", etc.)
- `ShortStr<5>`: Inline 5-char storage for attribute names (no heap allocation)
- `FingerTest tests[NUM_FPTESTS]`: Fixed 13-slot array, not HashMap
- `FingerTestDef::AttrIdx`: Maps attribute name -> index via `std::map<FPstr, u8>`

**Fix**: Compact fingerprint representation:
1. `Section` enum (13 variants): Zero-cost section key replacing String
2. `AttrKey` enum (41 variants): Zero-cost attribute key replacing String
3. `CompactFingerprint`: `[Option<Vec<(AttrKey, Box<str>)>>; 13]` replacing `HashMap<String, HashMap<String, String>>`
4. `CompiledMatchPoints`: Pre-compiled enum-based match points
5. `compare_compact()`: Enum iteration replacing string HashMap lookups

**Files**: `matching.rs` (new types + compare_compact), `database.rs` (compact storage + parsing)

**Result**: 135MB -> 70MB (2.0x nmap, was 4.1x). Per-fingerprint: 20KB -> 3.5KB (5.7x reduction).

### Memory Savings Breakdown

| Component | Before | After | Savings |
|-----------|--------|-------|---------|
| Section name Strings (6036 x 14) | ~2.3MB | 0 (enum) | 2.3MB |
| Attribute name Strings (6036 x 14 x 10) | ~22.9MB | 0 (enum) | 22.9MB |
| HashMap overhead (outer) | ~3MB | ~1.3MB (array) | 1.7MB |
| HashMap overhead (inner, 6036 x 14) | ~31MB | 0 (Vec) | 31MB |
| String value overhead (capacity field) | ~6.5MB | 0 (Box<str>) | 6.5MB |
| **Total estimated** | **~84MB** | **~21MB** | **~63MB** |

---

### OS Detection Speed (2026-04-12)

**Problem**: OS detection 0.78x nmap. Sequential T1-T7 probes with per-probe BPF filter changes caused 7x RTT overhead.

**Root Cause Analysis**:
- Each T1-T7 probe created a new RawSocket, set a BPF filter, sent probe, waited for response
- 7 sequential probes = 7 RTTs minimum
- Per-probe BPF filter changes required `drain_engine()` to flush stale packets
- Total T1-T7 phase: ~700ms vs nmap's ~100ms

**Fix**: Pipelined send-all-then-collect architecture:
1. Set ONE broad BPF filter (src_ip + TCP protocol, no port filtering)
2. Create ONE RawSocket for all probes
3. Phase 1: Send all 7 probes in <1ms
4. Phase 2: Single receive loop matching responses by port in software
5. Early exit when all responses collected

**Files**: `os/detector.rs:1621-1801` (send_tcp_tests), `bpf.rs:985-1008` (tcp_response_from_ip)

**Result**: OS detection 0.78x -> 0.99-1.10x nmap

### Version Detection Speed (2026-04-12)

**Problem**: Version detection 0.83x nmap. Debug timestamps showed 23 ports starting ~100ms apart despite `tokio::spawn` + `join_all`.

**Root Cause**: `ServiceDetector` derived `Clone`, deep-cloning `ProbeDatabase` (HashMap<String, ProbeDefinition> with 103+ probes, each with Vec<MatchRule> containing String patterns). The `.map(|work| detector.clone())` in the orchestrator ran synchronously before spawning, causing sequential ~100ms clone operations.

**Fix**: Wrapped `ProbeDatabase` in `Arc`:
```rust
// Before: expensive deep clone
db: ProbeDatabase,  // Clone = deep copy of all probes

// After: cheap reference count
db: Arc<ProbeDatabase>,  // Clone = Arc::clone (increment refcount)
```

**Files**: `service/detector.rs:102-104` (ServiceDetector), `service/detector.rs:116-121` (new)

**Result**: Version detection 0.83x -> **1.61x** nmap. Memory from ~130MB to 74.5MB.

### OS Detection Memory (2026-04-12)

**Problem**: `OsDetector::new(os_db.clone(), ...)` deep-cloned `FingerprintDatabase` for each host.

**Fix**: Wrapped `FingerprintDatabase` in `Arc<OsDetector>`.

**Files**: `os/detector.rs:34` (db field), `os/detector.rs:435-437` (new)

**Result**: Prevents clone overhead. Base footprint ~135MB remains (6036 fingerprints).

---

## MEMORY OPTIMIZATION RESULTS (Phase 2)

### Fixes Applied

| Fix | Before | After | Reduction |
|-----|--------|-------|-----------|
| Ring buffer: block_nr 256->64 | 16MB mmap | 4MB mmap | -12MB |
| Per-packet engine clone | Arc::new(Self) per packet | Arc::clone(&ring_ref) | -10-20MB alloc churn |
| Debug eprintln in find_matches | 4 calls printing full FPS | Removed | Speed + memory |
| Dual OS fingerprint storage | typed + raw for 5678 entries | raw only | -50-70MB |
| Dead parse_fingerprint code | 460 lines | Removed | Binary size |

### Memory Comparison (2026-04-12 01:52 Benchmark)

| Category | nmap | rustnmap (Before Phase 2) | rustnmap (Current) | Current Ratio |
|----------|------|---------------------------|-------------------|---------------|
| Basic scans | 18.5MB | 44-46MB | 16-24MB | 1.0-1.3x |
| Service detection | 52MB | 167MB | 74.5MB | 1.4x |
| OS detection | 33MB | 208MB | 135MB | 4.1x |
| Aggressive (-A) | 67MB | 268MB | 171MB | 2.6x |
| Host discovery | 11.7MB | 15-17MB | 15-17MB | 1.3x |

---

## OS Fingerprint Memory Analysis

### RawFingerprint Structure

```rust
type RawFingerprint = HashMap<String, HashMap<String, String>>;
// 6036 entries, each with ~14 sections (SEQ, OPS, WIN, ECN, T1-T7, U1, IE)
// Each section: ~10 key-value pairs
// Per fingerprint: ~12KB
// Total: ~74MB just for RawFingerprint data
```

### Common String Patterns (Internable)

Keys repeated 6036x across all fingerprints:
- R, DF, T, TG, S, A, F, O, M, W, RD, Q, P, SI, etc.

Values repeated frequently:
- "Y", "N", "0x0100", hex values, distance values

### Potential Savings from String Interning

| Optimization | Estimated Savings |
|-------------|-------------------|
| Key interning (20 common keys) | ~10MB |
| Value interning ("Y", "N", common hex) | ~5MB |
| Vec<(u8, CompactString)> instead of HashMap | ~20MB |
| Total | ~35MB |

---

## PERFORMANCE ANALYSIS (Phase 1)

### Nmap Architecture vs Rustnmap

| Aspect | Nmap | Rustnmap | Impact |
|--------|------|----------|--------|
| Packet I/O | libpcap + PACKET_MMAP | PACKET_MMAP V2 | Parity |
| Service probes | nsock parallel I/O | tokio::spawn + join_all | Parity |
| OS probes | cwnd-based parallel | Sequential (now pipelined) | FIXED |
| Fingerprint matching | Linear scan | Linear scan (now pre-filtered) | FIXED |
| Timing | RTT-adaptive | RTT-adaptive | Parity |

### Key nmap Timing Parameters

- DEFAULT_SERVICEWAITMS = 5000ms (total time budget for all probes per port)
- Probe timeout = budget - elapsed_so_far
- Connection reuse from banner grab (service_scan.cc lines 2095-2105)
- SEQ probes: 100ms intervals (osscan2.cc)
- T1-T7: Sent in parallel via nsock (not sequential)
