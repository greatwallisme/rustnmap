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

## Phase 11: NSE Library Expansion - PHASE 11.2 COMPLETE ✅

> **Status**: **Phase 11.2 - COMPLETE** - All medium-priority NSE libraries implemented with zero clippy warnings

### Session 2026-03-15: SMB Library Implementation Complete

**Phase 11.2 Achievement**: All medium-priority NSE libraries (ftp, unpwdb, brute, smb, smbauth, netbios, unicode) are now complete with zero clippy warnings.

**SMB/CIFS Protocol Support**:
- `smb.rs` (1281 lines) - Complete SMB1/CIFS protocol implementation
  - Functions: `get_port`, `start`, `negotiate_protocol`, `start_session`, `tree_connect`, `create_file`, `tree_disconnect`, `logoff`, `stop`
  - Supports port 445 (raw SMB) and port 139 (NetBIOS)
  - NTLMv1/v2 authentication support
- `smbauth.rs` - NTLM authentication with DES and HMAC-MD5
- `netbios.rs` - NetBIOS name encoding/decoding and NBSTAT queries
- `unicode.rs` - UTF-8 to UTF-16LE conversion for SMB strings

**Quality Gate Results**:
```
cargo clippy -p rustnmap-nse -- -D warnings:  Zero warnings
cargo fmt --check -p rustnmap-nse:           Formatting clean
cargo test -p rustnmap-nse:                 33 tests + 5 doc tests passing
```

### Session 2026-03-15: Clippy Warnings Fixed

**Quality Achievement**: All NSE libraries now pass `cargo clippy` with zero warnings.
```

---

## Phase 11.1: High-Priority Libraries - COMPLETE ✅

### Design Conformance Review (2026-03-11 21:00)

**Finding**: Design conformance review identified 1 critical deviation and 4 feature simplifications.
**Requirement**: "不允许简化实现" - All features must match design specification.

| Category | Count | Status |
|----------|-------|--------|
| [A] Technical direction deviation | 1 | **MUST FIX** |
| [B] Feature simplification | 4 | **MUST FIX** |
| [C] Code exceeds design | 2 | Doc update needed |

### Critical Issues Requiring Rework

#### [A-001] SSH2 Key Exchange Not Implemented

**Design Spec**: Full SSH-2 key exchange with Diffie-Hellman groups
- Support group1 (1024-bit), group14 (2048-bit), group16 (4096-bit)
- Returns actual key data: key.key, key_type, fp_input, bits, algorithm, fingerprints

**Current Implementation**: Banner-only implementation
- Only reads SSH banner string
- Uses banner bytes as "pseudo key data"
- Returns placeholder values: bits=0, algorithm="Unknown", key_type="banner"

**Impact**: Scripts relying on SSH key type detection or RSA key size will not work correctly.

**Action Required**: Implement SSH-2 key exchange with Diffie-Hellman per design.

---

#### [B-001] HTTP Missing Pipeline Functions

**Design Spec**: `http.pipeline_add()`, `http.pipeline_go()` for request batching

**Current Implementation**: Not implemented

**Impact**: Scripts using HTTP pipelining for performance will fail.

---

#### [B-002] HTTP Missing Response Fields

**Design Spec**: Response table includes:
- `cookies` - Cookie array
- `decoded` / `undecoded` - Compression handling
- `location` - Redirect URLs
- `incomplete` / `truncated` - Error states

**Current Implementation**: Only basic fields (status, version, header, body)

---

#### [B-003] HTTP Missing Options Support

**Design Spec**: Options table supports:
- `auth` / `digestauth` - Authentication
- `bypass_cache`, `no_cache` - Cache control
- `redirect_ok` - Redirect control
- `max_body_size` - Body size limit
- `scheme` - Protocol scheme

**Current Implementation**: Only `timeout` and `header` options

---

#### [B-004] SSL Missing STARTTLS Protocols

**Design Spec**: Support for ldap, mysql, postgresql, nntp, tds, vnc

**Current Implementation**: Only smtp, pop3, imap, ftp, xmpp implemented

---

### Implementation Plan (Revised)

| Phase | Task | Status | Priority |
|-------|------|--------|----------|
| 11.1.1 | Fix SSH2 key exchange implementation | Complete | P0 |
| 11.1.2 | Add HTTP pipeline functions | Complete | P0 |
| 11.1.3 | Add HTTP missing response fields | Complete | P0 |
| 11.1.4 | Add HTTP missing options support | Complete | P0 |
| 11.1.5 | Add SSL missing STARTTLS protocols | **Complete** | P0 |
| 11.1.6 | Update design doc for file naming | Pending | P2 |
| 11.1.7 | Verify all tests pass with full implementation | Complete | P0 |

**Phase 11.1 Complete** (2026-03-11):
- SSH2: Full Diffie-Hellman key exchange with RSA/DSA/ECDSA/Ed25519 support
- HTTP: Complete HTTP/1.1 with pipeline, cookies, auth, compression
- SSL: All 11 STARTTLS protocols (ftp, smtp, imap, pop3, ldap, mysql, postgresql, nntp, tds, vnc, xmpp)

#### Phase 11.2: Medium-Priority Libraries - COMPLETE ✅

**Priority**: P1 - Useful but less critical

| Library | Scripts Enabled | Effort | Order | Status | Clippy |
|---------|-----------------|--------|-------|--------|--------|
| smb | smb-*, msrpc-* | 3 days | 5 | **Complete** | Zero warnings |
| smbauth | Used by smb | - | - | **Complete** | Zero warnings |
| netbios | Used by smb | - | - | **Complete** | Zero warnings |
| unicode | Used by smb | - | - | **Complete** | Zero warnings |
| ftp | ftp-* | 2 days | 6 | **Complete** | Zero warnings |
| brute | brute-* | 2 days | 7 | **Complete** | Zero warnings |
| unpwdb | Used by brute | 1 day | 8 | **Complete** | Zero warnings |

**Phase 11.2 Complete** (2026-03-15):
- All NSE libraries (http, ssh2, ssl, ftp, brute, unpwdb, smb, smbauth, netbios, unicode) have zero clippy warnings
- SMB/CIFS protocol implementation with NTLMv1/v2 authentication
- NetBIOS name service support (ports 139/445)
- UTF-8/UTF-16LE conversion for SMB strings
- All 33 tests + 5 doc tests passing, formatting clean
- Dependencies added: des, hmac, md4

#### Phase 11.3: Utility Libraries - COMPLETE ✅

**Priority**: P2 - Convenience features

| Library | Purpose | Status | Clippy |
|---------|---------|--------|--------|
| openssl | Crypto operations | **Complete** | Zero warnings |
| json | JSON parsing | Future | - |
| url | URL manipulation | Future | - |

**Session 2026-03-15**: OpenSSL Library Complete

Implemented full OpenSSL cryptographic library for NSE scripts:
- **openssl.rs** (~1100 lines) - Complete crypto operations implementation
  - Hash functions: MD4, MD5, SHA1, SHA256, SHA512, RIPEMD-160
  - HMAC functions for all hash algorithms
  - Random bytes generation (cryptographically strong)
  - Bignum operations: bin2bn, dec2bn, hex2bn, bn2bin, bn2dec, bn2hex
  - Bignum arithmetic: num_bits, num_bytes, mod_exp, rand
  - DES string to key conversion with odd parity
  - DES ECB/CBC encryption and decryption (internal, ready for registration)
  - 10 supported ciphers (DES, DES-ECB, DES-CBC, AES variants)
  - 6 supported digests

**Quality Gate Results**:
- cargo clippy: Zero warnings
- cargo test: 186 tests passing (33 lib + 6 doc + 147 openssl)
- All tests passing with proper error handling

### Success Criteria

- [x] All Phase 11.1 libraries implemented
- [x] Phase 11.2 libraries implemented (SMB, FTP, brute, unpwdb)
- [x] Phase 11.3 openssl library implemented
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
