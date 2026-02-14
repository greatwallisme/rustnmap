# Findings: FTP Bounce Scan Research

> **Project**: RustNmap - Rust Network Mapper
> **Created**: 2026-02-14
> **Purpose**: Research findings for FTP Bounce Scan implementation

---

## Requirements

From the user request and design documents:
- Implement FTP Bounce Scan (-b) as specified in `doc/modules/port-scanning.md`
- Support scanning through FTP proxy/bounce servers
- Detect port states (Open, Closed, Filtered) via FTP response codes
- No root privileges required (uses standard TCP connections)

---

## Research Findings

### Scanner Architecture Pattern

From studying existing implementations:

1. **PortScanner Trait** (`scanner.rs`):
   ```rust
   pub trait PortScanner {
       fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState>;
       fn requires_root(&self) -> bool;
   }
   ```

2. **Non-Root Pattern** (from `connect_scan.rs`):
   - Uses standard `std::net::TcpStream::connect_timeout()` instead of raw sockets
   - `requires_root()` returns `false`
   - Simple timeout-based connection logic

3. **Module Export Pattern** (from `lib.rs`):
   - Add `pub mod ftp_bounce_scan;`
   - Add `pub use ftp_bounce_scan::FtpBounceScanner;`

### FTP Bounce Scan Requirements (from design doc)

From `doc/modules/port-scanning.md` line 19:
| FTP Bounce | `-b` | User | ★★☆☆☆ | ★★★☆☆ | `FtpBounceScanner` |

Key characteristics:
- **User privilege** (no root required)
- Low stealth (FTP server logs activity)
- Medium accuracy

### FTP PORT Command Format

The FTP PORT command uses the following format:
```
PORT a,b,c,d,e,f
```

Where:
- `a,b,c,d` = 4 octets of target IP address
- `e,f` = 2 octets of target port (port = e*256 + f)

Example for 192.168.1.1:80:
```
PORT 192,168,1,1,0,80
```

### FTP Response Codes for Port State Detection

| Response | Code | Meaning | Port State |
|----------|------|---------|------------|
| 150 | Opening data connection | Transfer starting | Open |
| 200 | Command okay | PORT accepted | (intermediate) |
| 226 | Transfer complete | Connection succeeded | Open |
| 425 | Can't open data connection | Connection refused | Closed |
| 426 | Connection closed | Transfer aborted | Closed/Filtered |
| 500/501 | Syntax error | Invalid PORT command | Error |
| 530 | Not logged in | Auth required | Error |

---

## Technical Decisions

| Decision | Rationale |
|----------|-----------|
| Use standard TcpStream | FTP bounce uses normal TCP, no raw sockets needed |
| Implement FTP command builder | Clean abstraction for PORT command construction |
| Parse FTP responses line by line | Standard FTP protocol handling |
| Store FTP server address in scanner | Scanner needs to know which FTP server to bounce through |
| Use Option<String> for username/password | Support both anonymous and authenticated FTP |

## FtpBounceScanner Structure Design

Based on `TcpConnectScanner` pattern:

```rust
pub struct FtpBounceScanner {
    /// FTP server address (the bounce proxy)
    ftp_server: SocketAddr,
    /// Connection timeout for FTP operations
    connect_timeout: Duration,
    /// Optional username for FTP authentication
    username: Option<String>,
    /// Optional password for FTP authentication
    password: Option<String>,
}
```

## FTP Command Sequence for Bounce Scan

1. **Connect** to FTP server
2. **USER** (optional - for authenticated FTP)
3. **PASS** (optional - for authenticated FTP)
4. **PORT a,b,c,d,e,f** - Tell FTP server to connect to target IP:port
5. **LIST** - Trigger data connection attempt
6. **Parse response** - Determine port state from FTP response code

## Port State Mapping from FTP Responses

| FTP Response | Meaning | Port State |
|--------------|---------|------------|
| 150 (Opening data connection) | FTP server successfully connected to target | Open |
| 226 (Transfer complete) | Data connection established and closed | Open |
| 425 (Can't open data connection) | Connection refused by target | Closed |
| 426 (Connection closed) | Connection aborted | Closed/Filtered |
| Timeout/No response | FTP server couldn't connect | Filtered |

---

## Issues Encountered

| Issue | Resolution |
|-------|------------|
|       |            |

---

## Resources

- Design doc: `doc/modules/port-scanning.md`
- Nmap source: `reference/nmap/bouncescan.cc`
- FTP RFC: RFC 959

---

## Visual/Browser Findings

-

---

*Update this file after every 2 view/browser/search operations*
*This prevents visual information from being lost*
