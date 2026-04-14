# Nmap Constants Reference

This document lists the core constant definitions in the Nmap source code, providing precise references for the Rust implementation.

## Table of Contents

1. [Scan Engine Constants](#1-scan-engine-constants)
2. [Port State Constants](#2-port-state-constants)
3. [OS Detection Constants](#3-os-detection-constants)
4. [NSE Engine Constants](#4-nse-engine-constants)
5. [Output Constants](#5-output-constants)
6. [Timing Constants](#6-timing-constants)
7. [Protocol Constants](#7-protocol-constants)

---

## 1. Scan Engine Constants

### scan_engine.cc

```cpp
// Rate limit detection extra wait time
#define RLD_TIME_MS 1000

// Duration to retain completed hosts (TCP MSL - 2 minutes)
#define COMPL_HOST_LIFETIME_MS 120000
```

```rust
// RustNmap corresponding constants
pub const RLD_TIME_MS: u64 = 1000;
pub const COMPL_HOST_LIFETIME_MS: u64 = 120_000; // 2 minutes
```

### probespec.h

```cpp
// TCP AND UDP AND SCTP protocol maximum (used for special protocol selection)
#define TCPANDUDPANDSCTP IPPROTO_MAX

// UDP AND SCTP
#define UDPANDSCTP (IPPROTO_MAX + 1)
```

```rust
// RustNmap corresponding constants
pub const TCP_AND_UDP_AND_SCTP: u8 = IPPROTO_MAX;
pub const UDP_AND_SCTP: u8 = IPPROTO_MAX + 1;
```

### timing.h

```cpp
// Default current rate history (seconds)
#define DEFAULT_CURRENT_RATE_HISTORY 5.0
```

```rust
// RustNmap corresponding constants
pub const DEFAULT_CURRENT_RATE_HISTORY: f64 = 5.0;
```

---

## 2. Port State Constants

### portlist.h

```cpp
// Port state constants
#define PORT_UNKNOWN 0
#define PORT_CLOSED 1
#define PORT_OPEN 2
#define PORT_FILTERED 3
#define PORT_TESTING 4
#define PORT_FRESH 5
#define PORT_UNFILTERED 6
#define PORT_OPENFILTERED 7
#define PORT_CLOSEDFILTERED 8
#define PORT_HIGHEST_STATE 9  // ***IMPORTANT - increment this value when adding states***
```

```rust
// RustNmap corresponding constants
#[repr(u8)]
pub enum PortState {
    Unknown = 0,
    Closed = 1,
    Open = 2,
    Filtered = 3,
    Testing = 4,
    Fresh = 5,
    Unfiltered = 6,
    OpenFiltered = 7,
    ClosedFiltered = 8,
}

impl PortState {
    pub const HIGHEST_STATE: u8 = 9;
}
```

### service_scan.h

```cpp
// Default service wait time (milliseconds)
#define DEFAULT_SERVICEWAITMS 5000

// Default TCP wrapped timeout (milliseconds)
#define DEFAULT_TCPWRAPPEDMS 2000

// Default connection timeout (milliseconds)
#define DEFAULT_CONNECT_TIMEOUT 5000

// Default SSL connection timeout (milliseconds)
#define DEFAULT_CONNECT_SSL_TIMEOUT 8000

// Maximum number of fallbacks allowed in the service probe file
#define MAXFALLBACKS 20
```

```rust
// RustNmap corresponding constants
pub const DEFAULT_SERVICE_WAIT_MS: u64 = 5000;
pub const DEFAULT_TCP_WRAPPED_MS: u64 = 2000;
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 5000;
pub const DEFAULT_CONNECT_SSL_TIMEOUT: u64 = 8000;
pub const MAX_FALLBACKS: usize = 20;
```

### service_scan.h (ServiceProbeState)

```cpp
// Service probe state enum
enum serviceprobestate {
  PROBESTATE_INITIAL=1,      // Probing not yet started
  PROBESTATE_NULLPROBE,       // NULL probe in progress
  PROBESTATE_MATCHINGPROBES,  // Matching probes in progress
  PROBESTATE_FINISHED_HARDMATCHED,  // Finished - hard match
  PROBESTATE_FINISHED_SOFTMATCHED, // Finished - soft match
  PROBESTATE_FINISHED_NOMATCH,   // Finished - no match
  PROBESTATE_FINISHED_TCPWRAPPED, // Finished - TCP wrapped
  PROBESTATE_EXCLUDED,          // Port excluded
  PROBESTATE_INCOMPLETE          // Failed to complete (error/timeout)
};
```

```rust
// RustNmap corresponding constants
#[repr(u8)]
pub enum ServiceProbeState {
    Initial = 1,
    NullProbe = 2,
    MatchingProbes = 3,
    FinishedHardMatched = 4,
    FinishedSoftMatched = 5,
    FinishedNoMatch = 6,
    FinishedTcpWrapped = 7,
    Excluded = 8,
    Incomplete = 9,
}
```

---

## 3. OS Detection Constants

### FPEngine.h

```cpp
// IPv6 OS detection probe counts
#define NUM_FP_PROBES_IPv6_TCP    13
#define NUM_FP_PROBES_IPv6_ICMPv6 4
#define NUM_FP_PROBES_IPv6_UDP    1

// Total IPv6 OS detection probes
#define NUM_FP_PROBES_IPv6 (NUM_FP_PROBES_IPv6_TCP + \
                              NUM_FP_PROBES_IPv6_ICMPv6 + \
                              NUM_FP_PROBES_IPv6_UDP)

// Timed probe count (probes that require specific timing)
#define NUM_FP_TIMEDPROBES_IPv6 6

// OS scan initial congestion window
#define OSSCAN_INITIAL_CWND (NUM_FP_TIMEDPROBES_IPv6)

// OS scan initial slow start threshold
#define OSSCAN_INITIAL_SSTHRESH (4 * OSSCAN_INITIAL_CWND)

// OS scan host group size
#define OSSCAN_GROUP_SIZE 10

// OS scan initial retransmission timeout (3 seconds, in microseconds)
#define OSSCAN_INITIAL_RTO (3*1000000)

// Novelty threshold (match score difference threshold)
#define FP_NOVELTY_THRESHOLD 15.0

// IPv6 OS detection flow label
#define OSDETECT_FLOW_LABEL 0x12345
```

```rust
// RustNmap corresponding constants
pub const NUM_FP_PROBES_IPV6_TCP: usize = 13;
pub const NUM_FP_PROBES_IPV6_ICMPV6: usize = 4;
pub const NUM_FP_PROBES_IPV6_UDP: usize = 1;
pub const NUM_FP_PROBES_IPV6: usize =
    NUM_FP_PROBES_IPV6_TCP +
    NUM_FP_PROBES_IPV6_ICMPV6 +
    NUM_FP_PROBES_IPV6_UDP;

pub const NUM_FP_TIMED_PROBES_IPV6: usize = 6;
pub const OSSCAN_INITIAL_CWND: usize = NUM_FP_TIMED_PROBES_IPV6;
pub const OSSCAN_INITIAL_SSTHRESH: usize = 4 * OSSCAN_INITIAL_CWND;
pub const OSSCAN_GROUP_SIZE: usize = 10;
pub const OSSCAN_INITIAL_RTO: u64 = 3_000_000; // 3 seconds (microseconds)
pub const FP_NOVELTY_THRESHOLD: f64 = 15.0;
pub const OS_DETECT_FLOW_LABEL: u32 = 0x12345;
```

---

## 4. NSE Engine Constants

### nse_main.h

```cpp
// Script engine name
#define SCRIPT_ENGINE "NSE"

#ifdef WIN32
#  define SCRIPT_ENGINE_LUA_DIR "scripts\\"
#  define SCRIPT_ENGINE_LIB_DIR "nselib\\"
#else
#  define SCRIPT_ENGINE_LUA_DIR "scripts/"
#  define SCRIPT_ENGINE_LIB_DIR "nselib/"
#endif

// Script database path
#define SCRIPT_ENGINE_DATABASE SCRIPT_ENGINE_LUA_DIR "script.db"

// Script file extension
#define SCRIPT_ENGINE_EXTENSION ".nse"
```

```rust
// RustNmap corresponding constants
pub const SCRIPT_ENGINE: &str = "NSE";

#[cfg(windows)]
pub const SCRIPT_ENGINE_LUA_DIR: &str = "scripts\\";
#[cfg(windows)]
pub const SCRIPT_ENGINE_LIB_DIR: &str = "nselib\\";

#[cfg(unix)]
pub const SCRIPT_ENGINE_LUA_DIR: &str = "scripts/";
#[cfg(unix)]
pub const SCRIPT_ENGINE_LIB_DIR: &str = "nselib/";

pub const SCRIPT_ENGINE_DATABASE: &str =
    concat!(SCRIPT_ENGINE_LUA_DIR, "script.db");
pub const SCRIPT_ENGINE_EXTENSION: &str = ".nse";
```

### nse_nmaplib.cc

```cpp
// Number of fields in the version table
#define NSE_NUM_VERSION_FIELDS 12

// NSE protocol options
static const char *NSE_PROTOCOL_OP[] = {"tcp", "udp", "sctp"};
static const int NSE_PROTOCOL[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP};
```

```rust
// RustNmap corresponding constants
pub const NSE_NUM_VERSION_FIELDS: usize = 12;

pub const NSE_PROTOCOL_OP: [&str] = &["tcp", "udp", "sctp"];
pub const NSE_PROTOCOL: [i32] = &[IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP];
```

### nse_lua.h

```cpp
// Lua registry index
#define LUA_REGISTRYINDEX -10000

// Lua invalid reference
#define LUA_NOREF -10001

// Lua status codes
#define LUA_OK 0
#define LUA_YIELD 1
#define LUA_ERRRUN 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5
#define LUA_ERRFILE 6
```

```rust
// RustNmap corresponding constants
pub const LUA_REGISTRY_INDEX: i32 = -10000;
pub const LUA_NOREF: i32 = -10001;

pub enum LuaStatusCode {
    Ok = 0,
    Yield = 1,
    ErrorRun = 2,
    ErrorSyntax = 3,
    ErrorMem = 4,
    ErrorErr = 5,
    ErrorFile = 6,
}
```

---

## 5. Output Constants

### output.h

```cpp
// Number of log files (must be the leading value)
#define LOG_NUM_FILES 4

// Log file mask (mask used for file arrays)
#define LOG_FILE_MASK 15

// Log types
#define LOG_NORMAL 1
#define LOG_MACHINE 2
#define LOG_SKID 4
#define LOG_XML 8
#define LOG_STDOUT 1024
#define LOG_STDERR 2048
#define LOG_SKID_NOXLT 4096

// Maximum log value
#define LOG_MAX LOG_SKID_NOXLT

// Plain log mask
#define LOG_PLAIN (LOG_NORMAL | LOG_SKID | LOG_STDOUT)

// Log names array
#define LOG_NAMES {"normal", "machine", "$Cr!pT |<!dd!3", "XML"}
```

```rust
// RustNmap corresponding constants
pub const LOG_NUM_FILES: u32 = 4;
pub const LOG_FILE_MASK: u32 = 15;

pub enum LogType {
    Normal = 1,      // LOG_NORMAL
    Machine = 2,      // LOG_MACHINE
    Skid = 4,         // LOG_SKID
    Xml = 8,          // LOG_XML
    Stdout = 1024,     // LOG_STDOUT
    Stderr = 2048,     // LOG_STDERR
    SkidNoXlt = 4096, // LOG_SKID_NOXLT
}

impl LogType {
    pub const MAX: LogType = LogType::SkidNoXlt;

    pub const PLAIN: u32 =
        LogType::Normal as u32 |
        LogType::Skid as u32 |
        LogType::Stdout as u32;
}

pub const LOG_NAMES: &[&str] = &["normal", "machine", "$Cr!pT |<!dd!3", "XML"];
```

---

## 6. Timing Constants

### timing.h

```cpp
// Initial retransmission timeout (3 seconds, in microseconds)
// Based on RFC 2988
#define INITIAL_RTT_TIMEOUT 3000000

// Minimum retransmission timeout (100 milliseconds)
#define MIN_RTT_TIMEOUT 100000

// Maximum retransmission timeout (60 seconds)
#define MAX_RTT_TIMEOUT 60000000

// RTT initial value (uncalibrated)
#define RTT_INITIAL_TIMEOUT 6000000

// RTT variance (limits rapid changes)
#define RTT_VAR_MAX 3000000000

// Maximum timeout multiplier
#define MAX_TIMEOUT_MULT 10
```

```rust
// RustNmap corresponding constants
pub const INITIAL_RTT_TIMEOUT: u64 = 3_000_000; // 3 seconds (microseconds)
pub const MIN_RTT_TIMEOUT: u64 = 100_000;     // 100 milliseconds
pub const MAX_RTT_TIMEOUT: u64 = 60_000_000;   // 60 seconds (microseconds)
pub const RTT_INITIAL_TIMEOUT: u64 = 6_000_000;  // 6 seconds (microseconds)
pub const RTT_VAR_MAX: u64 = 3_000_000_000;   // Limits rapid changes
pub const MAX_TIMEOUT_MULT: u32 = 10;
```

---

## 7. Protocol Constants

### protocols.h / nbase.h

```cpp
// Common IP protocols
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_SCTP 132
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58
#define IPPROTO_IP 0

// Ethernet types
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

// TCP flag bits
#define TH_SYN 0x02
#define TH_ACK 0x10
#define TH_FIN 0x01
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
```

```rust
// RustNmap corresponding constants
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_SCTP: u8 = 132;
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_ICMPV6: u8 = 58;
pub const IP_PROTO_IP: u8 = 0;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PUSH: u8 = 0x08;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;
```

---

## Constant Usage Examples

### Port State Checking

```rust
use port::PortState;

fn is_open_port(state: PortState) -> bool {
    matches!(state, PortState::Open | PortState::OpenFiltered)
}

fn is_filtered_port(state: PortState) -> bool {
    matches!(state, PortState::Filtered)
}

fn is_closed_port(state: PortState) -> bool {
    matches!(state, PortState::Closed)
}

fn needs_retry(state: PortState) -> bool {
    matches!(state,
        PortState::Filtered |
        PortState::OpenFiltered |
        PortState::Testing)
}
```

### Log Type Combinations

```rust
use output::LogType;

// Create normal log mask
fn normal_log_mask() -> u32 {
    LogType::Normal as u32
}

// Create full log mask (normal + script kiddie + XML)
fn full_log_mask() -> u32 {
    LogType::Normal as u32 |
    LogType::Skid as u32 |
    LogType::Xml as u32
}

// Output to terminal only (do not write to file)
fn stdout_only() -> u32 {
    LogType::Stdout as u32
}

// All output types
fn all_outputs() -> u32 {
    LogType::Normal as u32 |
    LogType::Machine as u32 |
    LogType::Skid as u32 |
    LogType::Xml as u32 |
    LogType::Stdout as u32 |
    LogType::Stderr as u32
}
```

### Timeout Calculation

```rust
use timing::*;

// Calculate default timeout
fn default_timeout() -> Duration {
    Duration::from_micros(INITIAL_RTT_TIMEOUT)
}

// Calculate minimum timeout
fn min_timeout() -> Duration {
    Duration::from_micros(MIN_RTT_TIMEOUT)
}

// Calculate maximum timeout
fn max_timeout() -> Duration {
    Duration::from_micros(MAX_RTT_TIMEOUT)
}

// Calculate adaptive timeout (based on RTT)
fn adaptive_timeout(srtt: i32, rttvar: i32) -> Duration {
    let timeout = srtt + 4 * rttvar;
    let timeout = timeout.clamp(MIN_RTT_TIMEOUT as i32,
                             MAX_RTT_TIMEOUT as i32);
    Duration::from_micros(timeout as u64)
}
```

### NSE Related

```rust
use nse::*;

// Get script directory
fn script_dir() -> &'static str {
    SCRIPT_ENGINE_LUA_DIR
}

// Get script database path
fn script_db_path() -> String {
    format!("{}{}", SCRIPT_ENGINE_LUA_DIR, SCRIPT_ENGINE_DATABASE)
}

// Get script file extension
fn script_extension() -> &'static str {
    SCRIPT_ENGINE_EXTENSION
}

// Get Lua registry index
fn lua_registry_index() -> i32 {
    LUA_REGISTRY_INDEX
}

// Lua invalid reference constant
fn lua_noref() -> i32 {
    LUA_NOREF
}
```
