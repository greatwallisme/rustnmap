# Task Plan: Idle Scan (-sI) Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Status**: In Progress
> **Created**: 2026-02-14
> **Goal**: Implement Idle Scan (-sI) for completely blind port scanning via zombie hosts

---

## Goal

Implement Idle Scan (-sI), an advanced stealth scanning technique that uses a zombie host to scan target ports. No packets are sent from the scanner's IP to the target, making this the stealthiest scan type.

## Background

### Idle Scan Principles

1. **IP ID Sequence Exploitation**: Uses predictable IP ID incrementation on the zombie host
2. **Spoofing**: Sends SYN packets with zombie's IP as source address
3. **Side-Channel Detection**: Determines port state by observing zombie's IP ID changes

### Port State Detection

| IP ID Change | Port State |
|--------------|------------|
| +2 | Open (target SYN-ACK caused zombie to send RST) |
| +1 | Closed (target RST, zombie did nothing) |
| 0/erratic | Filtered or unreliable zombie |

### Reference Documentation

- Design doc: `doc/modules/port-scanning.md`
- Nmap reference: `reference/nmap/idle_scan.cc`

---

## Current Phase

COMPLETE

---

## Phases

### Phase 1: Requirements & Discovery

- [x] Read design document for Idle Scan requirements
- [x] Study Nmap's idle_scan.cc implementation
- [x] Understand IP ID extraction from packets
- [x] Document findings in findings.md
- **Status:** complete

---

### Phase 2: Planning & Structure

- [x] Define `IdleScanner` structure
- [x] Design zombie probing mechanism
- [x] Design packet spoofing approach
- [x] Plan IP ID extraction from RST responses
- [x] Design port state determination logic
- **Status:** complete

---

### Phase 3: Implementation

- [x] Create `idle_scan.rs` module
- [x] Implement zombie IP ID probing (SYN-ACK probe)
- [x] Implement IP ID extraction from IP header
- [x] Implement spoofed SYN packet sending
- [x] Implement port state determination logic
- [x] Implement `PortScanner` trait for `IdleScanner`
- [x] Add module export to `lib.rs`
- **Status:** complete

---

### Phase 4: Testing & Verification

- [x] Add unit tests for `IdleScanner`
- [x] Add tests for IP ID extraction
- [x] Add tests for port state determination
- [x] Run `cargo build` - must pass
- [x] Run `cargo clippy -- -D warnings` - zero warnings
- [x] Run `cargo test` - all tests pass (76 tests, +13 new)
- **Status:** complete

---

### Phase 5: Documentation & Delivery

- [x] Update module documentation
- [x] Add examples to doc comments
- [x] Review implementation against design doc
- [x] Final verification
- **Status:** complete

---

## Key Questions

1. How to extract IP ID from raw IP packets?
2. What's the best way to handle zombie host validation?
3. How to handle IP ID wraparound (16-bit field)?
4. What timeout is appropriate for zombie probing?

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Follow `TcpSynScanner` pattern | Idle scan requires raw sockets for spoofing |
| Use SYN-ACK probes to zombie | Standard way to elicit RST with IP ID |
| Probe zombie port 80 by default | Most hosts have predictable IP ID on port 80 |
| Implement `PortScanner` trait | Consistent with all other scanner implementations |

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| | 1 | |

---

## Notes

- Idle Scan requires root privileges (raw socket for spoofing)
- Zombie host must have predictable IP ID sequence
- Zombie should be idle (low traffic) for accurate results
- Reference: Nmap's `idle_scan.cc` implementation
