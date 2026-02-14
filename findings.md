# Findings: Idle Scan (-sI) Implementation

> **Project**: RustNmap - Rust Network Mapper
> **Created**: 2026-02-14
> **Purpose**: Research findings for Idle Scan (-sI) implementation

---

## Overview

Idle Scan is an advanced, stealthy port scanning technique that uses a third-party "zombie" host to perform the scan. The scan is completely blind - no packets are sent from the scanner's IP address to the target.

## Idle Scan Principles

### How It Works

1. **Probe Zombie for IP ID**: Send a SYN/ACK packet to the zombie and record the IP ID from its RST response
2. **Spoof SYN to Target**: Send a SYN packet to the target with the zombie's IP as the source address
3. **Probe Zombie Again**: Send another SYN/ACK to the zombie and record the new IP ID

### Port State Determination

| Condition | IP ID Change | Interpretation |
|-----------|--------------|----------------|
| Zombie IP ID increased by 2 | +2 | Target port is **Open** (SYN-ACK to zombie, zombie sent RST back) |
| Zombie IP ID increased by 1 | +1 | Target port is **Closed** (RST to zombie, no response needed) |
| No change or erratic | 0 or random | **Filtered** or zombie not suitable |

### Why It Works

- **Open Port**: Target responds with SYN-ACK to zombie. Zombie, not expecting this, sends RST (IP ID +1). The scanner's probe gets RST (IP ID +1). Total: +2.
- **Closed Port**: Target responds with RST to zombie. Zombie does nothing. Scanner's probe gets RST (IP ID +1). Total: +1.

## Technical Requirements

### Zombie Host Requirements

1. **Predictable IP ID Sequence**: The zombie must increment its IP ID sequentially (not random)
2. **Low Traffic**: Minimal traffic from the zombie during scan to avoid IP ID interference
3. **RST on Unexpected SYN-ACK**: Standard TCP stack behavior

### Implementation Components

1. **Zombie Probing**: Send SYN-ACK packets to zombie to get IP ID
2. **Packet Spoofing**: Send SYN packets with zombie's IP as source
3. **IP ID Extraction**: Parse IP header to extract ID field from RST responses
4. **State Determination**: Compare before/after IP IDs to determine port state

## Architecture Design

### IdleScanner Structure

```rust
pub struct IdleScanner {
    /// Local IP address for probes to zombie
    local_addr: Ipv4Addr,
    /// Zombie host IP address (the "idle" host)
    zombie_addr: Ipv4Addr,
    /// Zombie probe port (port on zombie to probe)
    zombie_port: Port,
    /// Raw socket for packet transmission
    socket: RawSocket,
    /// Scanner configuration
    config: ScanConfig,
}
```

### Key Methods

1. `probe_zombie_ip_id() -> ScanResult<u16>`: Get current IP ID from zombie
2. `send_spoofed_syn(target_addr, target_port)`: Send SYN with zombie as source
3. `determine_port_state(ipid_before, ipid_after) -> PortState`: Interpret results

## Reference

- Nmap source: `reference/nmap/idle_scan.cc`
- Design doc: `doc/modules/port-scanning.md`
- RFC 793: TCP protocol behavior

---

## Visual/Browser Findings

-

---

*Update this file after every 2 view/browser/search operations*
*This prevents visual information from being lost*
