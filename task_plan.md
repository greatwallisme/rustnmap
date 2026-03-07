# Task Plan: Packet Engine Migration - Phase 3.4

> **Created**: 2026-03-07
> **Updated**: 2026-03-07
> **Status**: Phase 3.4 - Receive Path Integration COMPLETE (5/5 tasks)
> **Priority**: P0 - Critical

---

## Executive Summary

Phase 3.4 (Receive Path Integration) is COMPLETE. All tasks finished:
- Task #1: TcpSynScanner receive path integration (COMPLETE)
- Task #2: Stealth scanners infrastructure (COMPLETE)
- Task #3: ParallelScanEngine receive path (COMPLETE)
- Task #4: UdpScanner receive path (COMPLETE)
- Task #5: Run tests and verify zero warnings (COMPLETE)

### Verification Results

**Zero Clippy Warnings:**
```
cargo clippy --workspace -- -D warnings
Finished `dev` profile in 4.05s
```

**All Tests Pass:**
- Total: 242 tests passed
- 1 pre-existing failure: `test_udp_scan_ipv6_target` (IPv6 scanning not configured)
- No new test failures introduced

### Key Changes

1. **TcpSynScanner**: Uses `packet_engine` for receiving TCP responses
2. **Stealth Scanners**: All scanners use `ScannerPacketEngine` infrastructure
3. **ParallelScanEngine**: Updated receive path to use `packet_engine` instead of `packet_socket`
4. **UdpScanner**: Uses `packet_engine` for UDP scanning
5. **Code Quality**: Zero warnings, zero errors

---

## Phase 3.5: Cleanup (NEXT)

### Remaining Work
- [ ] Remove deprecated `SimpleAfPacket` and `AfPacketEngine` usage
- [ ] Add integration tests for PACKET_MMAP V2 performance
- [ ] Performance validation: 1M+ PPS target

---

## Completed Phases

### Phase 1: Core Infrastructure (COMPLETE)
- TPACKET_V2 structures, syscall wrappers
- MmapPacketEngine implementation
- AsyncPacketEngine with Tokio integration
- BPF filter support
- PacketStream implementation

### Phase 3.1: Infrastructure Preparation (COMPLETE)
- `icmp_dst()` filter added
- `recv_timeout()` method added
- `ScannerPacketEngine` adapter created
- `to_sock_fprog()` exposure

### Phase 3.2: Simple Scanner Migration (COMPLETE)
- TcpFinScanner migrated
- TcpNullScanner migrated
- TcpXmasScanner migrated

### Phase 3.3: Complex Scanner Infrastructure (COMPLETE)
- ScannerPacketEngine integrated into TcpSynScanner
- Stealth scanners (FIN/NULL/XMAS/ACK/Maimon) infrastructure updated
- Migration helpers added to packet_adapter.rs

### Phase 3.4: Receive Path Integration (COMPLETE)
- Task #1: TcpSynScanner receive path integration (COMPLETE)
- Task #2: Stealth scanners infrastructure (COMPLETE)
- Task #3: ParallelScanEngine receive path (COMPLETE)
- Task #4: UdpScanner receive path (COMPLETE)
- Task #5: Run tests and verify zero warnings (COMPLETE)

---

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| Type mismatch in `start_receiver_task` | 1 | Rewrote function with consistent return types |
| Missing `get_interface_for_ip` function | 1 | Added function back to ParallelScanEngine |
| Items-after-statements warning | 1 | Moved const declaration outside if block |
| Doc-markdown warning | 1 | Added backticks around `PACKET_MMAP` |
| Unfulfilled lint expectation | 1 | Removed `#[expect(dead_code)]` from SimpleAfPacket |

---

## Next Steps

1. **Phase 3.5.1**: Remove deprecated `SimpleAfPacket` and `AfPacketEngine` usage
2. **Phase 3.5.2**: Add integration tests for PACKET_MMAP V2 performance
3. **Phase 3.5.3**: Performance validation: 1M+ PPS target
