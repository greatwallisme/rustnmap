# Progress Log: Phase 5 - Performance Validation (BLOCKED)

> **Created**: 2026-03-07
> **Updated**: 2026-03-07
> **Status**: **BLOCKED** - MmapPacketEngine cannot create RX ring (errno=22)

---

## CURRENT STATUS: CRITICAL BLOCKER

**MmapPacketEngine::new() fails with `errno=22 (EINVAL)` when setting up PACKET_RX_RING**

### Error Details

```
Engine creation failed: failed to setup RX ring: Invalid argument (os error 22)
```

### What Fails

The `setsockopt(fd, SOL_PACKET, PACKET_RX_RING, ...)` call returns -1 with errno=22 (EINVAL).

### Test Results

All three configuration sizes fail:
- Small config (block_size=4096, block_nr=64) - FAILED
- Default config (block_size=65536, block_nr=256) - FAILED
- Minimal config (block_size=4096, block_nr=1) - FAILED

### Environment

```
Kernel: 6.1.0-27-amd64 (Linux 6.1.115)
Interface: ens33 (UP, BROADCAST, MULTICAST)
User: root (uid=0, full capabilities)
```

---

## What IS Working

| Component | Status | Evidence |
|-----------|--------|----------|
| Socket creation | ✅ Works | `socket(AF_PACKET, SOCK_RAW, 0)` succeeds |
| PACKET_VERSION set | ✅ Works | `setsockopt(fd, PACKET_VERSION, TPACKET_V2)` succeeds |
| PACKET_RESERVE set | ✅ Works | `setsockopt(fd, PACKET_RESERVE, 4)` succeeds |
| PACKET_AUXDATA set | ✅ Works | `setsockopt(fd, PACKET_AUXDATA, 1)` succeeds |
| First bind (protocol=0) | ✅ Works | `bind()` with protocol=0 succeeds |
| Interface index lookup | ✅ Works | `ioctl(SIOCGIFINDEX)` succeeds |
| MAC address lookup | ✅ Works | `ioctl(SIOCGIFHWADDR)` succeeds |

### What FAILS

| Operation | Status | Error |
|-----------|--------|-------|
| `setsockopt(PACKET_RX_RING)` | ❌ **FAILS** | errno=22 (EINVAL) |

---

## Code Location

File: `crates/rustnmap-packet/src/mmap.rs`
Function: `setup_ring_buffer()` at line 453
Failed call: lines 478-488

```rust
// This call returns -1 with errno=22
let result = unsafe {
    libc::setsockopt(
        fd.as_raw_fd(),
        libc::SOL_PACKET,
        PACKET_RX_RING,
        std::ptr::from_ref::<TpacketReq>(&req).cast::<c_void>(),
        u32::try_from(mem::size_of::<TpacketReq>()).map_err(|e| {
            PacketError::RingBufferSetup(io::Error::new(io::ErrorKind::InvalidInput, e))
        })?,
    )
};
```

---

## Known Facts (NO SPECULATION)

1. **Two-stage bind pattern is implemented** (lines 217, 228):
   - First bind: `bind_to_interface(&fd, if_index)` with protocol=0
   - Then PACKET_RX_RING setup
   - Second bind: `bind_to_interface_with_protocol(&fd, if_index, ETH_P_ALL.to_be())`

2. **The call order matches nmap's libpcap**:
   ```c
   // pcap-linux.c sequence:
   1. socket()
   2. setsockopt(PACKET_VERSION)
   3. bind() with protocol=0
   4. setsockopt(PACKET_RX_RING)  <-- FAILS HERE
   5. bind() with ETH_P_ALL
   ```

3. **TpacketReq structure layout** matches kernel definition:
   ```rust
   pub struct TpacketReq {
       pub tp_block_size: u32,
       pub tp_block_nr: u32,
       pub tp_frame_size: u32,
       pub tp_frame_nr: u32,
   }
   ```

4. **Kernel headers confirm** the struct is correct:
   ```c
   // /usr/include/linux/if_packet.h
   struct tpacket_req {
       unsigned int tp_block_size;
       unsigned int tp_block_nr;
       unsigned int tp_frame_size;
       unsigned int tp_frame_nr;
   };
   ```

---

## What We DON'T Know (Root Cause UNKNOWN)

- **Why** PACKET_RX_RING fails with errno=22
- **Which** parameter the kernel rejects
- **If** it's a kernel version issue (6.1 should support TPACKET_V2)
- **If** there's a missing socket option
- **If** the struct alignment is wrong

---

## Attempted Debugging

| Attempt | Action | Result |
|---------|--------|--------|
| 1 | Vary block size (4096 to 65536) | All fail with errno=22 |
| 2 | Vary block_nr (1 to 256) | All fail with errno=22 |
| 3 | Check kernel version | 6.1.115 (should support V2) |
| 4 | Verify TpacketReq layout | Matches kernel headers |

---

## Impact

- ❌ Cannot run PACKET_MMAP V2 benchmarks
- ❌ Cannot validate zero-copy performance
- ❌ Cannot verify 1M PPS target
- ❌ Phase 5.2 (Performance Validation) is BLOCKED

---

## What IS Complete

| Phase | Task | Status |
|-------|------|--------|
| 1 | PACKET_MMAP V2 infrastructure | Code exists, doesn't work |
| 2 | Network volatility components | ✅ Complete (62 tests) |
| 3 | Scanner integration | ✅ Complete |
| 4 | Documentation updates | ✅ Complete |
| 5.1 | Benchmark code written | ✅ Complete (compiles) |
| 5.2 | **Performance validation** | ❌ **BLOCKED** |

---

## Next Steps (NEED INVESTIGATION)

1. **Use strace** to see exact parameters passed to kernel
2. **Compare with nmap** running strace on both
3. **Check dmesg** for kernel error messages
4. **Try TPACKET_V3** to see if V2 is the issue
5. **Test with raw socket** without PACKET_MMAP

---

## Git Status

```
M crates/rustnmap-benchmarks/benches/mmap_pps.rs
?? crates/rustnmap-packet/examples/
```

No commits pending - changes are unstaged.

---

## Session History

This session attempted to:
1. Run PACKET_MMAP V2 benchmarks
2. Debug why MmapPacketEngine creation fails
3. Identify root cause of errno=22

**Result**: Root cause NOT identified. Need deeper investigation.

---

## Previous Session (2026-03-07)

Committed benchmark file: `c2237ea feat(bench): Add PACKET_MMAP V2 PPS performance benchmarks`

Documentation was updated claiming implementation was complete. **This was incorrect** - the code compiles but doesn't work.
