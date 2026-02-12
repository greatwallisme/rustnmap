# Findings: RustNmap Research and Analysis

> **Created**: 2026-02-12
> **Purpose**: Document discoveries, research results, and analysis

---

## Nmap Source Code Analysis

### Key Files Identified

| File | Purpose | Notes |
|------|---------|-------|
| `nmap.cc` | Main entry point | CLI parsing, session initialization |
| `scan_engine.cc` | Scan orchestration | Host parallelization, port scheduling |
| `tcpip.cc` | TCP/IP packet handling | Raw socket operations |
| `Target.cc` | Target management | CIDR expansion, host discovery |
| `portlist.cc` | Port state management | 10-state machine |
| `service_scan.cc` | Service detection | Probe matching |
| `nse_main.cc` | NSE engine | Lua integration |
| `output.cc` | Output formatting | All output formats |

### Port State Machine

Nmap defines 10 distinct port states:

1. **open** - Target accepting connections
2. **closed** - Target responding but not accepting
3. **filtered** - No response, firewall blocking
4. **unfiltered** - Responds but cannot determine open/closed
5. **open|filtered** - Open or filtered (no response)
6. **closed|filtered** - Closed or filtered (error response)
7. **open|closed** - Both conditions detected
8. **filtered|closed** - Filtered or closed
9. **filtered|unfiltered** - Cannot determine
10. **unknown** - State unknown

---

## Linux-Specific Features

### PACKET_MMAP V3

```c
// Key structures from Linux kernel
struct tpacket_req3 {
    unsigned int    tp_block_size;
    unsigned int    tp_block_nr;
    unsigned int    tp_frame_size;
    unsigned int    tp_frame_nr;
    unsigned int    tp_retire_blk_tov;
    unsigned int    tp_sizeof_priv;
    unsigned int    tp_feature_req_word;
};

struct tpacket_block_desc {
    uint32_t h1;
    // ... block header
    uint8_t data[];
};
```

**Key insights**:
- Zero-copy packet access via mmap
- Frame-aligned buffers for DMA
- Block retirement timeout control
- Support for both RX and TX

### Raw Socket Requirements

- `CAP_NET_RAW` capability required (or root)
- Socket family: `AF_PACKET`
- Socket type: `SOCK_RAW` with `htons(ETH_P_ALL)`
- Requires `setsockopt(SO_BINDTODEVICE)` for specific interfaces

---

## Rust Ecosystem Analysis

### Packet I/O Libraries

| Library | Pros | Cons | Decision |
|---------|------|------|----------|
| **pnet** | Mature, comprehensive | Extra indirection | Use for parsing |
| **rawsocket** | Direct, fast | Less feature-rich | Consider for hot path |
| **dpdk-rs** | Extreme performance | Complex setup | Future consideration |

### Async Runtime

| Library | Pros | Cons | Decision |
|---------|------|------|----------|
| **tokio** | Industry standard, excellent ecosystem | Some complexity | CHOSEN |
| async-std | Simpler API | Less adoption | Not chosen |
| smol | Lightweight | Less mature | Not chosen |

### Lua Integration

| Library | Pros | Cons | Decision |
|---------|------|------|----------|
| **mlua** | Lua 5.4 support, async, no build deps | - | CHOSEN |
| rlua | Stable API | Build issues on some platforms | Not chosen |

---

## Performance Optimization Insights

### Zero-Copy Strategy

1. **PACKET_MMAP V3** for kernel bypass
2. **bytes::Bytes** for reference-counted packet slices
3. **memory ordering** for lock-free queues
4. **stack allocation** on hot paths

### Parallelization Strategy

1. **Tokio multi-threaded runtime** - work stealing
2. **Host-level parallelism** - one task per host group
3. **Port batching** - sendmmsg/recvmmsg for packet groups
4. **Lock-free state** - AtomicU64 for packet counters

---

## NSE Script Compatibility

### Nmap NSE API Surface

Required libraries for compatibility:

| Library | Status | Complexity |
|---------|--------|------------|
| `nmap` | Core | High |
| `stdnse` | Core | Medium |
| `http` | Network | High |
| `ssl` | Network | Medium |
| `ssh` | Network | Medium |
| `smb` | Network | High |
| `comm` | Network | Low |
| `shortport` | Utility | Low |
| `datafiles` | Utility | Medium |

---

## Open Questions

| Question | Status | Resolution |
|----------|--------|------------|
| How to handle packet fragmentation? | Open | Need to study nmap.cc IP options |
| NSE script sandbox security model? | Open | Need detailed threat model |
| IPv6 support scope? | Open | Full dual-stack or subset? |
| CentOS 7 kernel 3.10 compatibility? | Open | Feature detection needed |

---

## Reference Documents Read

- [x] `doc/README.md` - Documentation structure
- [x] `doc/architecture.md` - System architecture (needs review)
- [x] `doc/roadmap.md` - Development phases
- [x] `doc/structure.md` - Workspace layout
- [x] `doc/modules/concurrency.md` - Concurrency patterns
- [x] `doc/modules/raw-packet.md` - Packet engine design
- [ ] `doc/modules/*.md` - Other module docs (pending)
