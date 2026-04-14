# Localhost Scanning Technical Analysis

> **Created**: 2026-03-08
> **Status**: Design Decision Document
> **Priority**: P0 - Architecture Limitation

---

## Problem Overview

When RustNmap scans `127.0.0.1` (localhost), all ports show `filtered` state, while nmap correctly identifies `open`/`closed` states.

**Test Commands**:
```bash
nmap -sS -p 22 127.0.0.1
# Result: 22/tcp open ssh

rustnmap --scan-syn -p 22 127.0.0.1
# Result: 22/tcp filtered ssh  (incorrect)
```

---

## Root Cause Analysis

### Problem Flow

```
1. User runs: rustnmap --scan-syn -p 22 127.0.0.1
2. TcpSynScanner creates RawSocket (bound to system default address 192.168.15.237)
3. TcpSynScanner creates PacketEngine (bound to ens33 interface)
4. Sends SYN probe: src=192.168.15.237, dst=127.0.0.1
5. Target responds with SYN-ACK: src=127.0.0.1, dst=192.168.15.237
6. **Key Issue**: Response destination address is 192.168.15.237 (external IP)
7. **Routing Decision**: Response to 192.168.15.237 is routed via ens33 interface
8. **Capture Failure**: PacketEngine bound to lo never sees this response
9. **Result**: Timeout -> filtered state
```

### tcpdump Evidence

```
# Actually captured packets
192.168.15.237.60554 > 127.0.0.1.22: Flags [S]     # Our SYN probe
127.0.0.1.22 > 192.168.15.237.60554: Flags [S.]   # SYN-ACK response
192.168.15.237.60554 > 127.0.0.1.22: Flags [R]     # Kernel TCP stack RST
```

**Key Finding**: The SYN-ACK **destination is the external IP**, not 127.0.0.1!

### Technical Cause

#### 1. Raw Socket Source Address Binding

How `RawSocket` is created in `TcpSynScanner`:

```rust
// crates/rustnmap-scan/src/syn_scan.rs:71
let socket = RawSocket::with_protocol(6)?;
```

**Problem**: The RawSocket is not bound to a specific source address. When sending packets, the kernel selects the source address based on these rules:
1. The local address bound to the socket (if already bound)
2. The outgoing interface address determined by the routing table
3. For packets to 127.0.0.1, the kernel uses the primary interface address (192.168.15.237)

#### 2. PACKET_MMAP Interface Binding

Our `localhost_engine` is bound to the `lo` interface:

```rust
// Code correctly detects the loopback interface
[DEBUG] Found loopback interface: lo
[DEBUG] Using loopback interface: lo
```

**However**: The response destination address is 192.168.15.237, so the response is routed via ens33, not lo.

#### 3. Kernel Routing Behavior

Linux kernel decisions for local communication:
- Source address: 192.168.15.237 (primary interface address)
- Destination address: 127.0.0.1 (loopback)
- **Routing decision**: Packets to 127.0.0.1 are sent via lo
- **Response routing**: Packets to 192.168.15.237 are received via the primary interface (ens33)

This is the core issue!

---

## How nmap Handles This

### nmap Source Code Analysis

**File**: `reference/nmap/libnetutil/netutil.cc:1916-1946`

```c
int islocalhost(const struct sockaddr_storage *ss) {
  // Check if address is 127.x.x.x
  if ((sin->sin_addr.s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
    return 1;

  // Check if address matches a local interface address
  if (ipaddr2devname(dev, ss) != -1)
    return 1;

  return 0;
}
```

### Windows Platform Handling

**File**: `reference/nmap/scan_engine.cc:2735-2739`

```c
#ifdef WIN32
  if (!o.have_pcap && scantype != CONNECT_SCAN &&
      Targets[0]->ifType() == devt_loopback) {
    log_write(LOG_STDOUT, "Skipping %s against %s because Windows does not support scanning your own machine (localhost) this way.\n",
             scantype2str(scantype), Targets[0]->NameIP());
    return;
  }
#endif
```

**Key Finding**: nmap **explicitly skips** raw socket scans against localhost on Windows because it is unsupported on certain platforms.

---

## Solutions

### Solution A: Raw Socket Bound to Loopback (Correct Approach)

Modify `TcpSynScanner` to create a dedicated RawSocket for localhost targets, bound to 127.0.0.1.

#### Implementation Structure

```rust
pub struct TcpSynScanner {
    // Existing fields
    local_addr: Ipv4Addr,
    socket: RawSocket,

    // New fields
    localhost_socket: Option<RawSocket>,  // Dedicated for localhost scanning
    is_local_addr_loopback: bool,          // Whether local_addr is loopback
}
```

#### Modified Send Logic

```rust
fn send_syn_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
    // Check if target is localhost
    let is_localhost_target = dst_addr.is_loopback();

    // Select the correct socket
    let socket = if is_localhost_target {
        self.localhost_socket.as_ref().unwrap_or(&self.socket)
    } else {
        &self.socket
    };

    // Send packet
    socket.send_packet(&packet, &dst_sockaddr)?;
    // ...
}
```

#### Constructor Modification

```rust
pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
    // Create primary RawSocket
    let socket = RawSocket::with_protocol(6)?;

    // If local_addr is already loopback, use it directly
    // Otherwise create a dedicated localhost socket
    let localhost_socket = if !local_addr.is_loopback() {
        // Create socket bound to 127.0.0.1
        let lo_socket = RawSocket::with_protocol(6)?;
        lo_socket.bind(Some(Ipv4Addr::new(127, 0, 0, 1)))?;
        Some(lo_socket)
    } else {
        None
    };

    Ok(Self {
        local_addr,
        socket,
        localhost_socket,
        // ...
    })
}
```

**Advantages**:
- Fully resolves the root cause
- Preserves all SYN scan functionality
- Aligns with nmap design philosophy

**Disadvantages**:
- Requires maintaining two RawSockets
- Increased architectural complexity

### Solution B: Use Connect Scan (Fallback Approach)

When localhost targets are detected, fall back to `TcpConnectScanner` instead of `TcpSynScanner`.

#### Implementation Location

In the scanner selection logic within `crates/rustnmap-core/src/orchestrator.rs`:

```rust
// Detect localhost targets
let has_localhost = targets.iter().any(|t| {
    matches!(t.ip, IpAddr::V4(addr) if addr.is_loopback())
});

// If there are localhost targets and SYN scan is selected, warn and use Connect scan
if has_localhost && scantype == ScanType::Syn {
    log_warning("SYN scan against localhost not supported, using Connect scan instead");
    return TcpConnectScanner::new(config)?.scan_targets(targets);
}
```

**Advantages**:
- Simple implementation
- Avoids PACKET_MMAP limitations
- Consistent with nmap behavior on certain platforms

**Disadvantages**:
- Loses SYN scan stealth
- Feature downgrade

---

## Design Decision

### Decision: Implement Solution A (Raw Socket Binding)

**Rationale**:
1. **Feature completeness**: SYN scan should work for all targets, including localhost
2. **nmap parity**: nmap supports SYN scan against localhost on Linux
3. **Technical correctness**: The proper solution is to fix the root cause, not work around it

### Implementation Plan

#### Phase 1: Modify RawSocket

**File**: `crates/rustnmap-net/src/lib.rs`

Add a `bind()` method to `RawSocket`:

```rust
impl RawSocket {
    /// Binds the raw socket to a specific source address.
    ///
    /// # Arguments
    ///
    /// * `src_addr` - Optional source address to bind to
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Socket is already bound
    /// - Invalid address
    /// - Permission denied
    pub fn bind(&self, src_addr: Option<Ipv4Addr>) -> io::Result<()> {
        // Implement bind logic
    }
}
```

#### Phase 2: Modify TcpSynScanner

**File**: `crates/rustnmap-scan/src/syn_scan.rs`

1. Add `localhost_socket` field
2. Modify constructor to create localhost socket
3. Modify `send_syn_probe()` to use the correct socket

#### Phase 3: Test Verification

1. Single-port localhost test
2. Multi-port localhost test
3. Mixed target test (localhost + remote)
4. Comparison with nmap results

---

## Technical Constraints

### PACKET_MMAP Limitations

Known limitations of PACKET_MMAP V2 on Linux:

| Scenario | PACKET_MMAP Behavior | Reason |
|----------|----------------------|--------|
| Scanning remote IP | Works correctly | Symmetric routing, send and receive on the same interface |
| Scanning 127.0.0.1 | Fails | Response routed to external interface, not on lo |
| Bound to lo interface | Can only see lo traffic | Packets from other interfaces do not appear on lo |

### Kernel Routing Table

```
# View routing table
ip route get 127.0.0.1
# 127.0.0.1 dev lo scope link

ip route get 192.168.15.237
# 192.168.15.237 dev ens33 scope link
```

This explains why packets destined for 192.168.15.237 go via ens33 instead of lo.

---

## Test Cases

### Test 1: Single-Port Localhost

```bash
# Should show open
rustnmap --scan-syn -p 22 127.0.0.1
# Expected: 22/tcp open ssh
```

### Test 2: Multi-Port Localhost

```bash
# Should show mixed states
rustnmap --scan-syn -p 22,80,443 127.0.0.1
# Expected: 22/tcp open, 80/tcp closed, 443/tcp closed
```

### Test 3: Mixed Targets

```bash
# Scan localhost and remote target simultaneously
rustnmap --scan-syn -p 22 127.0.0.1 45.33.32.156
# Expected: Both targets scanned correctly
```

---

## References

### Kernel Documentation

- `man 7 packet` - PACKET socket usage
- `man 7 raw` - Raw socket usage
- `man ip-route` - Routing table operations

### nmap References

- `reference/nmap/libnetutil/netutil.cc` - Interface detection
- `reference/nmap/scan_engine.cc` - Scan engine
- `reference/nmap/libpcap/pcap-linux.c` - PACKET_MMAP implementation

---

## Update History

| Date | Change | Author |
|------|--------|--------|
| 2026-03-08 | Created document with complete technical analysis of localhost scanning | Claude |
