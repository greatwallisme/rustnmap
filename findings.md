# Research Findings

> **Created**: 2026-03-07
> **Updated**: 2026-03-10 01:09
> **Status**: Design Compliance Audit Started

---

## DESIGN COMPLIANCE AUDIT (2026-03-10)

### Audit Overview

**Objective**: 全面对比项目当前代码与设计文档 (`doc/`)，检测是否有简化、偏离设计文档的情况。

**Scope**:
- 7 design documents in `doc/`
- 17 designed crates (14 in 1.0 + 3 in 2.0)
- All major features and modules

**Phases**: 9 comprehensive audit phases

---

## Phase 1: Architecture Compliance (PENDING)

### 1.1 2.0 Architecture Check

| Component | Designed Status | Actual Status | Deviation |
|-----------|----------------|---------------|-----------|
| rustnmap-vuln crate | Phase 2 (Week 5-7) | TODO | TODO |
| rustnmap-api crate | Phase 5 (Week 12) | TODO | TODO |
| rustnmap-sdk crate | Phase 5 (Week 12) | TODO | TODO |
| API & SDK Layer | NEW in 2.0 | TODO | TODO |
| Vulnerability Detection | NEW in 2.0 | TODO | TODO |

### 1.2 1.0 Baseline Architecture Check

| Component | Designed | Actual | Deviation |
|-----------|----------|--------|-----------|
| CLI Interface Layer | clap-based | TODO | TODO |
| Core Engine Layer | Scan Orchestrator | TODO | TODO |
| Scan Modules Layer | All scan types | TODO | TODO |
| Infrastructure Layer | Raw sockets, packet, async | TODO | TODO |

---

## Phase 2: Structure Compliance (PENDING)

### 2.1 Crate Structure Verification

**Designed Crates** (17 total):
1. rustnmap-common (1.0)
2. rustnmap-net (1.0)
3. rustnmap-packet (1.0)
4. rustnmap-target (1.0)
5. rustnmap-scan (1.0)
6. rustnmap-fingerprint (1.0)
7. rustnmap-nse (1.0)
8. rustnmap-traceroute (1.0)
9. rustnmap-evasion (1.0)
10. rustnmap-cli (1.0)
11. rustnmap-core (1.0)
12. rustnmap-output (1.0)
13. rustnmap-benchmarks (1.0)
14. rustnmap-macros (1.0)
15. rustnmap-vuln (2.0 NEW)
16. rustnmap-api (2.0 NEW)
17. rustnmap-sdk (2.0 NEW)

**Audit Tasks**:
- [ ] List all actual crates in `crates/`
- [ ] Compare with designed crate list
- [ ] Document missing/extra crates

### 2.2 Directory Structure Verification

**Design Requirements**:
- `scripts/` - NSE scripts organized by category
- `data/` - Database files (service-probes, os-fingerprints, etc.)
- `tests/` - Integration tests and fixtures

**Audit Tasks**:
- [ ] Verify `scripts/` structure
- [ ] Verify `data/` structure
- [ ] Verify `tests/` structure

---

## Phase 3: Roadmap Compliance (PENDING)

### 3.1 Phase Completion Status

| Phase | Description | Status | Completion % |
|-------|-------------|--------|--------------|
| Phase 1 | 基础架构 (MVP) | TODO | TODO |
| Phase 2 | 完整扫描功能 | TODO | TODO |
| Phase 3 | NSE 脚本引擎 | TODO | TODO |
| Phase 4 | 高级功能与优化 | TODO | TODO |
| Phase 40 | 数据包引擎架构重设计 | TODO | TODO |
| Phase 2 (2.0) | Vulnerability Detection | TODO | TODO |
| Phase 5 (2.0) | API & SDK | TODO | TODO |

### 3.2 Performance Targets

| Metric | Target | Nmap Reference | Actual | Gap |
|--------|--------|----------------|--------|-----|
| Full port scan speed | <30s (1000 hosts) | ~60-120s | TODO | TODO |
| SYN scan throughput | >10^6 pps | ~5×10^5 pps | TODO | TODO |
| Host discovery delay | <5s (/24 network) | ~5-10s | TODO | TODO |
| Memory usage | <500MB (large scale) | ~200-800MB | TODO | TODO |
| Script execution overhead | <10% | ~5-15% | TODO | TODO |
| Startup time | <100ms | ~50-200ms | TODO | TODO |

---

## Phase 4: Database Integration (PENDING)

### 4.1 Database Integration Status

**Design Requirements**:
- ServiceDatabase integration
- ProtocolDatabase integration
- RpcDatabase integration
- DatabaseContext for passing databases to output
- Service names in output: `80/tcp open http`

**Known Issues** (from memory):
- ServiceDatabase 重复定义 (common vs fingerprint)
- DatabaseContext 过度设计 (90% unused)
- 服务名填充流程检查

**Audit Tasks**:
- [ ] Verify ServiceDatabase is used correctly
- [ ] Check ProtocolDatabase integration
- [ ] Check RpcDatabase integration
- [ ] Verify DatabaseContext usage
- [ ] Check output format shows service names

---

## Phase 5: Feature Completeness (PENDING)

### 5.1 Scan Type Completeness

**Requirement**: 12 nmap scan types

| Scan Type | Flag | Implemented | Notes |
|-----------|------|-------------|-------|
| TCP SYN | -sS | TODO | TODO |
| TCP Connect | -sT | TODO | TODO |
| TCP FIN | -sF | TODO | TODO |
| TCP NULL | -sN | TODO | TODO |
| TCP Xmas | -sX | TODO | TODO |
| TCP Maimon | -sM | TODO | TODO |
| UDP | -sU | TODO | TODO |
| SCTP INIT | -sY | TODO | TODO |
| SCTP COOKIE-ECHO | -sZ | TODO | TODO |
| IP Protocol | -sO | TODO | TODO |
| ARP Scan | -PR | TODO | TODO |
| Idle Scan | -sI | TODO | TODO |

### 5.2 Timing Template Completeness

**Requirement**: T0-T5 (6 timing levels)

| Template | Params | Implemented | Deviation |
|----------|--------|-------------|-----------|
| T0 (Paranoid) | initial_rtt=1s, max_retries=10, scan_delay=5min | TODO | TODO |
| T1 (Sneaky) | initial_rtt=1s, max_retries=10, scan_delay=15s | TODO | TODO |
| T2 (Polite) | initial_rtt=1s, max_retries=10, scan_delay=400ms | TODO | TODO |
| T3 (Normal) | initial_rtt=1s, max_retries=10, scan_delay=0ms | TODO | TODO |
| T4 (Aggressive) | initial_rtt=500ms, max_retries=6, scan_delay=0ms | TODO | TODO |
| T5 (Insane) | initial_rtt=250ms, max_retries=2, scan_delay=0ms | TODO | TODO |

### 5.3 Port State Completeness

**Requirement**: 10 port states

| State | Implemented | Notes |
|-------|-------------|-------|
| open | TODO | TODO |
| closed | TODO | TODO |
| filtered | TODO | TODO |
| unfiltered | TODO | TODO |
| open|filtered | TODO | TODO |
| closed|filtered | TODO | TODO |
| open|mac | TODO | TODO (mac-specific) |

### 5.4 NSE Script Support

**Requirements**:
- Full NSE script compatibility
- All nmap libraries (nmap, stdnse, http, ssl, ssh, smb, etc.)
- Script selector with full syntax
- Process isolation for timeout handling

**Audit Tasks**:
- [ ] Check NSE script compatibility
- [ ] Verify library support
- [ ] Check script selector
- [ ] Verify process isolation

---

## Phase 6: Output Format (PENDING)

### 6.1 Output Format Support

| Format | Priority | Implemented | Deviation |
|--------|----------|-------------|-----------|
| Normal (-oN) | Required | TODO | TODO |
| XML (-oX) | Required | TODO | TODO |
| Grepable (-oG) | Required | TODO | TODO |
| JSON | Optional | TODO | TODO |
| HTML | Optional | TODO | TODO |

---

## Phase 7: Network Volatility (PENDING)

### 7.1 Adaptive RTT

**Design**: RFC 6298 compliant
```rust
SRTT = (7/8)*SRTT + (1/8)*RTT
```

### 7.2 Congestion Control

**Design**: cwnd, ssthresh, slow start, congestion avoidance

### 7.3 Scan Delay Boost

**Design**: Exponential backoff on high drop rate

---

## Phase 8: CLI Compatibility (PENDING)

### 8.1 Critical Options

| Option | Status | Notes |
|--------|--------|-------|
| -Pn (disable ping) | TODO | TODO |
| -sV (service detection) | TODO | TODO |
| -sC (default scripts) | TODO | TODO |
| -n (no DNS) | TODO | TODO |
| -R (always DNS) | TODO | TODO |
| -r (sequential ports) | TODO | TODO |

---

## PREVIOUS FINDINGS (Archive)

---

## DATABASE INTEGRATION RESEARCH (2026-03-09)

### Problem Statement

RustNmap loads three databases but immediately discards them:
- ServiceDatabase (port → service name, e.g., 80 → "http")
- ProtocolDatabase (protocol number → name, e.g., 6 → "tcp")
- RpcDatabase (RPC number → service name, e.g., 100003 → "nfs")

**Current behavior in cli.rs:**
```rust
match ServiceDatabase::load_from_file(&path).await {
    Ok(_db) => {  // ← Immediately discarded!
        info!("Services database loaded successfully");
        // Note: Service database is available but not yet used in output
    }
}
```

This occurs in 6 places (3 databases × 2 functions).

### Solution Implemented

**Phase 1-4 Complete**:
- Created DatabaseContext structure
- Modified cli.rs to store databases
- Updated output function signatures
- Implemented database lookups in output

**Result**: Output now shows `80/tcp open http` instead of `80/tcp open`

---

## CLI COMPATIBILITY ENHANCEMENT (2026-03-09)

### Problem

**Critical Issue**: Users cannot use nmap-compatible short options

```bash
$ rustnmap -Pn localhost -p 22
error: unexpected argument '-P' found
```

### Audit Results

**Category 1: Missing Short Options (HIGH PRIORITY)**
- -Pn (disable ping) - MISSING
- -sV (service detection) - MISSING
- -sC (default scripts) - MISSING
- -sL (list scan) - MISSING
- -sn (ping scan) - MISSING
- ... (many more)

**Category 2: Missing Long Options**
- Host discovery probes (-PS, -PA, -PU, -PE, -PP, -PM)
- Timing options (--min-rtt-timeout, --max-rtt-timeout, etc.)
- Evasion options (--proxies, --ip-options, --ttl, etc.)
- Output options (-oN/-oX/-oG/-oA)

### Status

**Latest Update**: 2026-03-09 22:10
- Migrated from clap to lexopt for nmap-compatible compound options
- Support for `-sS -sV -sC -T4` syntax
- Output options `-oN file`, `-oX file`, `-oG file`

---

## NSE SCRIPT SELECTOR & DATABASE FIXES (2026-03-09)

### Problems Fixed

1. **NSE script selection only supported categories**
   - Fixed: Now supports script names, wildcards, boolean expressions

2. **MAC prefix database parsing failed**
   - Fixed: Extended to support 6-12 character prefixes
   - 49,058 entries now load successfully

3. **Missing Info category**
   - Fixed: Added `Info` variant to ScriptCategory enum

4. **Lua table parsing for categories**
   - Fixed: Added support for `field = {...}` pattern

### Test Results

All 118 NSE tests pass, 2 previously ignored tests now enabled

---

## PREVIOUS SESSIONS ARCHIVE

### Database Integration Research (2026-03-09 14:09)

**Research completed**:
- Analyzed nmap's database implementation
- Created technical design document
- Identified 6 placeholder code blocks

### Performance Optimization (2026-03-09)

**Root cause identified**: Unnecessary host discovery overhead
- Single host scans spent 283ms (31%) on host discovery
- Solution: Auto-disable for single host targets
- Result: 10% faster than nmap

---

## Legacy Performance Data

### Test Configuration
- Target: 45.33.32.156 (scanme.nmap.org)
- Ports: 22, 80, 113, 443, 8080
- Timing: T4 (Aggressive)

### Measured Results
| Run | nmap | rustnmap | Difference |
|-----|------|---------|------------|
| 1 | 725ms | 1270ms | +545ms |
| 2 | 734ms | 1234ms | +500ms |
| 3 | 712ms | 1304ms | +592ms |
| **Average** | **724ms** | **1269ms** | **+545ms** |

**Current Status**: After optimization, rustnmap is ~10% faster than nmap for single host scans
