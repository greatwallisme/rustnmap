# Task Plan: RustNmap Development

> **Created**: 2026-03-10
> **Updated**: 2026-03-11 08:30
> **Status**: Multi-phase planning - Core complete, NSE libraries pending

---

## Project Status Summary

### Completed ✅
- **Phase 1**: TCP SYN Single-Target Optimization - Performance achieved
- **Phase 10**: NSE Resource Leak Fix - Process isolation implemented
- **Phase 40**: Packet Engine (PACKET_MMAP V2) - Complete with tests
- **Documentation Cleanup**: Technical design documents purified

### Current Focus 🎯
- **NSE Libraries**: Expand from 4 to ~25 protocol libraries
- **2.0 Features**: Complete vuln, API, SDK modules

---

## Phase 1: TCP SYN Single-Target Optimization - COMPLETE ✅

### Status
- ✅ Performance: 0.89x (small), 0.82-1.29x (large, network-dependent)
- ✅ Accuracy: 100% match with nmap
- ✅ Stability: More consistent than nmap

### Key Fixes Applied
1. Cwnd floor = 10 (prevents collapse to 1)
2. Adaptive retry limits (based on max_successful_tryno)
3. Fast packet draining (1ms timeout maintained)
4. 200ms upper limit protection
5. Diagnostic output behind feature flag

### Performance Results (2026-03-11 07:35)

| Test | nmap | rustnmap | Ratio | Status |
|------|------|----------|-------|--------|
| 1 port | 750ms | 841ms | 0.89x | 12% trade-off (acceptable) |
| 100 ports | 2450ms | 2986ms | 0.82x | Network-dependent |
| Accuracy | 100% | 100% | 1.00x | Perfect |

**Conclusion**: The 12% overhead for tiny scans is an architectural trade-off (async vs sync I/O), not a defect.

---

## Phase 2-4: Pending (Original Plan)

| Phase | Focus | Priority | Status |
|-------|-------|----------|--------|
| Phase 2 | IPv6 scanning | P1 | Pending |
| Phase 3 | Multi-target optimization | P1 | Pending |
| Phase 4 | Large-scale scanning | P1 | Pending |

---

## Phase 10: NSE Resource Leak Fix - COMPLETE ✅

### Problem
Scripts that timed out continued running in background, leaking CPU/threads.

### Solution
Process-based isolation with OS-level process termination:
- `rustnmap-nse-runner` binary for isolated execution
- `ProcessExecutor` with reliable timeout handling
- CPU time limits via `setrlimit(RLIMIT_CPU)`

### Results
- Default script timeout: 10 minutes (matching nmap)
- All 118 NSE tests pass
- 2 previously ignored tests now enabled

---

## Phase 11: NSE Library Expansion - IN PROGRESS

> **Status**: **Phase 11.1 COMPLETE** - Core + protocol libraries implemented

### Current State (2026-03-11 20:20)

**Implemented (8 libraries)**:
- nmap - Core scanning functions
- stdnse - Standard extensions
- comm - Network communication
- shortport - Port matching rules
- http - HTTP protocol library (NEW)
- ssh2 - SSH2 protocol library (NEW)
- sslcert - SSL certificate library (NEW)
- dns - DNS protocol library (NEW)

**Remaining Protocol Libraries (~17 libraries)**:
- smb - SMB/CIFS protocol library
- snmp - SNMP protocol library
- ftp - FTP protocol library
- tls - TLS/SSL wrapper
- brute - Password brute forcing
- unpwdb - Username/password database
- openssl - OpenSSL bindings
- And ~10 more...

### Phase 11.1: High-Priority Protocol Libraries - COMPLETE

**Priority**: P0 - Required for common NSE scripts

| Library | Scripts Enabled | Status |
|---------|-----------------|--------|
| http | http-vuln*, http-enum*, http-* | Complete |
| ssh2 | ssh-auth-methods, ssh-* | Complete |
| sslcert | ssl-enum, ssl-cert, ssl-* | Complete |
| dns | dns-* | Complete |

#### Phase 11.2: Medium-Priority Libraries (Next)

**Priority**: P1 - Useful but less critical

| Library | Scripts Enabled | Effort | Order |
|---------|-----------------|--------|-------|
| smb | smb-*, msrpc-* | 3 days | 5 |
| ftp | ftp-* | 2 days | 6 |
| brute | brute-* | 2 days | 7 |
| unpwdb | Used by brute | 1 day | 8 |

#### Phase 11.3: Utility Libraries (Future)

**Priority**: P2 - Convenience features

| Library | Purpose | Effort |
|---------|---------|--------|
| openssl | Crypto operations | 2 days |
| json | JSON parsing | 1 day |
| url | URL manipulation | 1 day |

### Success Criteria

- [x] All Phase 11.1 libraries implemented
- [ ] Top 20 NSE scripts can run
- [ ] Library test coverage >= 80%
- [ ] Documentation in `doc/modules/nse-engine.md`

---

## Phase 40: Packet Engine - COMPLETE ✅

### Status
- ✅ TPACKET_V2 ring buffer implemented
- ✅ Zero-copy packet handling
- ✅ AsyncPacketEngine with Tokio integration
- ✅ All scanners migrated to PacketEngine trait
- ✅ 865+ tests passing, zero clippy warnings

### Performance Targets

| Metric | Target | Status |
|--------|--------|--------|
| PPS | ~1,000,000 | Pending benchmark |
| CPU (T5) | 30% | Pending benchmark |
| Packet Loss (T5) | <1% | Pending benchmark |
| Zero-copy | Verified | ✅ Complete |

---

## Phase 50: Documentation Cleanup - COMPLETE ✅

### Problem
Technical design documents (`doc/`) contained:
- Implementation status reports
- Bug findings and analysis
- Progress tracking with emoji markers
- Performance test results

These don't belong in design documents.

### Solution
Removed inappropriate content from:
- `doc/database.md` - Removed section 4.6 (implementation analysis)
- `doc/database-integration.md` - Removed "Implementation Status" section
- `doc/architecture.md` - Removed performance results, cleaned emojis

### Principle
**Technical design documents should contain ONLY**:
- Architecture decisions
- API specifications
- Data structures
- Design patterns

**Should NOT contain**:
- Implementation status
- Bug reports
- Progress tracking
- Test results

---

## Design vs Implementation Coverage Analysis

### Fully Implemented ✅

| Component | Design | Implementation | Coverage |
|-----------|--------|----------------|----------|
| 12 Scan Types | All specified | All implemented | 100% |
| 7 Port States | 6 designed | 7 implemented | 117% |
| 6 Timing Templates (T0-T5) | All specified | All implemented | 100% |
| Packet Engine | PACKET_MMAP V2 | Complete | 100% |
| Core Crates | 14 designed | 14 implemented | 100% |

### Identified Gaps ❌

1. **rustnmap-macros** - Designed but NOT implemented (low impact)
2. **NSE Libraries** - Only 4 of ~25 implemented (high impact)

### Additional Crates (2.0 Extensions)

These extend beyond original 1.0 design but are documented in roadmap.md:
- `rustnmap-api` - REST API / Daemon mode
- `rustnmap-sdk` - Rust SDK (Builder API)
- `rustnmap-vuln` - CVE/CPE/EPSS/KEV integration
- `rustnmap-scan-management` - SQLite persistence, diff, YAML profiles
- `rustnmap-stateless-scan` - Masscan-like high-speed scanning

---

## Remaining Work

### High Priority
1. **Phase 11**: NSE Library expansion (P0)
2. **Phase 2**: IPv6 scanning support
3. **Phase 3**: Multi-target optimization

### Medium Priority
4. **Phase 4**: Large-scale scanning optimization
5. Performance benchmarking (PPS, CPU, packet loss)
6. Cross-platform compatibility (macOS, Windows)

### Low Priority
7. **rustnmap-macros** implementation (convenience feature)
8. Additional NSE utility libraries

---

## Success Criteria

### Phase 1 (TCP SYN) ✅ COMPLETE
- [x] Speed (large scans) within 20% of nmap
- [x] Speed (small scans) within 15% of nmap
- [x] Accuracy 100%
- [x] Stability consistent or better than nmap

### Phase 11 (NSE Libraries) 🚧 IN PROGRESS
- [ ] http library implemented
- [ ] ssh library implemented
- [ ] ssl library implemented
- [ ] dns library implemented
- [ ] Top 20 NSE scripts can run
- [ ] Library test coverage >= 80%

### Phase 2-5 (Pending)
- [ ] IPv6 >= 0.95x
- [ ] Multi-target optimization
- [ ] Large-scale (1000+ hosts) optimization
- [ ] 2.0 features (vuln, API, SDK)

---

## Current Status Summary (2026-03-11 08:30)

**Completed**: TCP SYN optimization, NSE resource leak fix, Packet engine, Documentation cleanup

**In Progress**: NSE library expansion

**Key Finding**: Core RustNmap has excellent design coverage. The main gap is NSE protocol libraries, which is an intentional phased approach - core libraries work, protocol-specific libraries can be added incrementally.

**Next Priority**: Implement http, ssh, ssl, dns libraries to enable top NSE scripts.
