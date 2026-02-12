# Findings: Design Document Granularity Analysis

**Created:** 2026-02-12
**Last Updated:** 2026-02-12

## Documentation Structure Analysis

### Current State

The `doc/` directory contains 17 markdown files organized into three categories:

1. **Project Level** (5 files) - Architecture, structure, roadmap
2. **Module Level** (10 files) - Core feature implementations
3. **Appendix** (3 files) - References and deployment

### Key Observations

1. **NSE Module is Largest**
   - `modules/nse-engine.md` is 62.5KB (significantly larger than others)
   - Contains extensive library API documentation
   - Good candidate for further subdivision

2. **Port Scanning is Well-Structured**
   - Has scanner type comparison table
   - Includes state machine diagram
   - Missing: Implementation details from `scan_engine.cc`

3. **Output Module is Medium-Sized**
   - 18KB - covers multiple formats
   - Missing: XML schema details, formatting algorithms

## Nmap Reference Code Findings

### Critical Source Files by Category

#### Scan Engine (scan_engine.cc/h)
**Key Functions:**
- `ultra_scan()` - 3rd generation scanning, handles most scan types
- `determineScanGroupSize()` - Calculates parallel host count
- `get_ping_pcap_result()` - Ping response processing

**Key Classes:**
- `UltraScanInfo` - Main scan state
- `UltraProbe` - Probe representation
- `HostScanStats` - Per-host scan statistics

**Important Constants:**
- tryno_t - Try number with ping/seqnum fields
- Port states: PORT_OPEN, PORT_CLOSED, PORT_FILTERED, etc.

#### Port List Management (portlist.h/cc)
**Key Classes:**
- `Port` - Single port with state, service, script results
- `PortList` - Collection of ports with iteration

**Key Structures:**
- `serviceDeductions` - Service detection results
  - name, confidence, product, version, extrainfo
  - dtype (table vs probed)
  - service_fp (fingerprint for submission)

**Enums:**
- serviceprobestate - PROBESTATE_INITIAL, PROBESTATE_FINISHED_HARDMATCHED, etc.
- service_detection_type - TABLE vs PROBED
- service_tunnel_type - NONE vs SSL

#### OS Detection (FPEngine.h/cc, osscan2.cc)
**Key Classes:**
- `FPEngine` - Generic fingerprinting engine base
- `FPEngine6` - IPv6 fingerprinting
- `FPNetworkControl` - Network access manager with congestion control
- `FPHost` / `FPHost6` - Per-target fingerprinting state
- `FPProbe` - OS detection probe (extends FPPacket)
- `FPResponse` - Received packet data

**Congestion Control:**
- cc_cwnd, cc_ssthresh
- OSSCAN_INITIAL_CWND, OSSCAN_INITIAL_SSTHRESH
- OSSCAN_INITIAL_RTO = 3 seconds
- OSSCAN_GROUP_SIZE = 10 hosts

**Probe Counts:**
- NUM_FP_PROBES_IPv6_TCP = 13
- NUM_FP_PROBES_IPv6_ICMPv6 = 4
- NUM_FP_PROBES_IPv6_UDP = 1

#### NSE (nse_main.cc/h, various nse_*.cc)
**Key Classes:**
- `ScriptResult` - Stores script output with id and output_ref
- `ScriptResults` - std::multiset<ScriptResult*>

**Key Functions:**
- `script_scan()` - Main entry point
- `nse_yield()` - Coroutine yield
- `nse_restore()` - Restore from yield
- `nse_base()` - Base library setup
- `nse_selectedbyname()` - Script selection

**Constants:**
- SCRIPT_ENGINE = "NSE"
- SCRIPT_ENGINE_LUA_DIR = "scripts/"
- SCRIPT_ENGINE_LIB_DIR = "nselib/"
- SCRIPT_ENGINE_DATABASE = "scripts/script.db"
- SCRIPT_ENGINE_EXTENSION = ".nse"

**Library Files:**
- nse_nmaplib.cc - Core nmap library
- nse_nsock.cc - Network socket bindings
- nse_openssl.cc - SSL/TLS support
- nse_ssl_cert.cc - Certificate parsing
- nse_dnet.cc - dnet (network) library
- nse_fs.cc - File system operations
- nse_db.cc - Database operations
- nse_libssh2.cc - SSH protocol
- nse_zlib.cc - Compression
- nse_lpeg.cc - LPeg pattern matching

#### Output (output.cc/h, xml.cc)
**Log Type Constants:**
- LOG_NORMAL = 1
- LOG_MACHINE = 2
- LOG_SKID = 4
- LOG_XML = 8
- LOG_STDOUT = 1024
- LOG_STDERR = 2048

**Key Functions:**
- `log_write(int logt, const char *fmt, ...)` - Main logging
- `printportoutput()` - Tabular port output
- `printmacinfo()` - MAC address display

#### Raw Packet (scan_engine_raw.cc/h)
**Functions:**
- `sendArpScanProbe()` - ARP scanning
- `sendNDScanProbe()` - Neighbor Discovery (IPv6)
- `sendIPScanProbe()` - IP protocol scan
- `get_arp_result()` - ARP response processing
- `get_ns_result()` - ND response processing
- `get_pcap_result()` - pcap response processing

#### Timing (timing.cc/h)
**Key Concepts:**
- Timing templates (T0-T5)
- RTT (Round Trip Time) measurement
- RTO (Retransmission Timeout)
- Congestion control

## Gaps Identified

### High Priority Gaps

1. **Port Scanning Module**
   - Missing: Ultra scan algorithm pseudocode
   - Missing: Probe retry mechanism details
   - Missing: Congestion control integration

2. **OS Detection Module**
   - Missing: FPEngine class hierarchy details
   - Missing: Probe timing requirements
   - Missing: Fingerprint matching algorithm

3. **NSE Module**
   - Missing: C binding architecture
   - Missing: Registry-based output system
   - Missing: Coroutine (yield/restore) mechanism

4. **Output Module**
   - Missing: XML schema
   - Missing: Output formatting algorithms
   - Missing: Log stream multiplexing

### Medium Priority Gaps

5. **Target Parsing Module**
   - Missing: Target class structure
   - Missing: Group expansion algorithm
   - Missing: Expression parsing

6. **Raw Packet Module**
   - Missing: Packet construction details
   - Missing: pcap BPF filter generation

### Low Priority Gaps

7. **Appendix Files**
   - No data structure reference
   - No function reference
   - No constants reference

## Nmap File to Documentation Mapping

| Nmap File | Functionality | Documentation File | Priority |
|------------|--------------|-------------------|------------|
| scan_engine.cc | Ultra scan algorithm, probe handling | modules/port-scanning.md | HIGH |
| scan_engine_raw.cc | Raw packet scanning | modules/port-scanning.md | HIGH |
| scan_engine_connect.cc | TCP connect scanning | modules/port-scanning.md | HIGH |
| portlist.cc/h | Port state management | modules/port-scanning.md | HIGH |
| timing.cc/h | RTT, RTO, congestion control | modules/port-scanning.md | HIGH |
| FPEngine.cc/h | OS fingerprinting engine | modules/os-detection.md | HIGH |
| osscan2.cc | OS detection implementation | modules/os-detection.md | HIGH |
| FPModel.cc/h | Fingerprint model | modules/os-detection.md | MEDIUM |
| service_scan.cc/h | Version detection | modules/service-detection.md | HIGH |
| nse_main.cc/h | Script engine core | modules/nse-engine.md | HIGH |
| nse_nmaplib.cc | Nmap library bindings | modules/nse-engine.md | HIGH |
| nse_nsock.cc | Socket bindings | modules/nse-engine.md | MEDIUM |
| nse_*.cc | Various library bindings | modules/nse-engine.md | MEDIUM |
| output.cc/h | Output system | modules/output.md | HIGH |
| xml.cc | XML output | modules/output.md | MEDIUM |
| traceroute.cc/h | Traceroute | modules/traceroute.md | MEDIUM |
| Target.cc/h | Target management | modules/target-parsing.md | MEDIUM |
| TargetGroup.cc/h | Multi-target handling | modules/target-parsing.md | MEDIUM |
| tcpip.cc/h | Network utilities | modules/raw-packet.md | MEDIUM |

## Detailed Findings by Module

### Port Scanning Module

**Ultra Scan Algorithm (scan_engine.cc):**
- `ultra_scan()` - Main entry point for 3rd generation scanning
- `determineScanGroupSize()` - Calculates optimal parallel host count
- `UltraScanInfo` class - Main scan state container
- `UltraProbe` class - Probe representation
- `HostScanStats` - Per-host scan statistics
- Key constants: RLD_TIME_MS (1000), COMPL_HOST_LIFETIME_MS (120000)

**Timing System (timing.cc/h):**
- Based on RFC2581 TCP congestion control
- `ultra_timing_vals` structure:
  - `cwnd` - Congestion window
  - `ssthresh` - Slow start threshold
  - `num_replies_expected`, `num_replies_received`
- `timeout_info` structure:
  - `srtt` - Smoothed RTT (microseconds)
  - `rttvar` - RTT variance
  - `timeout` - Current timeout threshold
- `RateMeter` class - Rate measurement
- `PacketRateMeter` class - Packet/byte rates
- `ScanProgressMeter` class - Progress tracking

**Port States (portlist.h):**
- PORT_UNKNOWN (0), PORT_CLOSED (1), PORT_OPEN (2)
- PORT_FILTERED (3), PORT_TESTING (4), PORT_FRESH (5)
- PORT_UNFILTERED (6), PORT_OPENFILTERED (7), PORT_CLOSEDFILTERED (8)
- `Port` class with `serviceDeductions` structure

**Probe Types (probespec.h):**
- PS_TCP, PS_UDP, PS_SCTP, PS_PROTO
- PS_ICMP, PS_ARP, PS_ICMPV6, PS_ND, PS_CONNECTTCP

### OS Detection Module

**Fingerprint Engine (FPEngine.h):**
- `FPEngine` - Generic base class
- `FPEngine6` - IPv6 fingerprinting
- `FPNetworkControl` - Network manager with:
  - `cc_cwnd`, `cc_ssthresh` for congestion control
  - `nsock_pool`, `pcap_nsi` for I/O
- `FPHost` / `FPHost6` - Per-target state
- `FPProbe` - OS detection probe (extends FPPacket)
- `FPResponse` - Received packet data

**Constants:**
- NUM_FP_PROBES_IPv6_TCP = 13
- NUM_FP_PROBES_IPv6_ICMPv6 = 4
- NUM_FP_PROBES_IPv6_UDP = 1
- OSSCAN_GROUP_SIZE = 10
- OSSCAN_INITIAL_CWND = NUM_FP_TIMEDPROBES_IPv6 (6)
- OSSCAN_INITIAL_SSTHRESH = 4 * OSSCAN_INITIAL_CWND (24)
- OSSCAN_INITIAL_RTO = 3 seconds (3,000,000 usecs)

### NSE Module

**Core (nse_main.h):**
- `ScriptResult` class - id + output_ref (LUA_REGISTRYINDEX)
- `ScriptResults` - std::multiset<ScriptResult*>
- `script_scan()` - Main entry point
- `nse_yield()`, `nse_restore()` - Coroutine support
- `nse_base()` - Base library setup
- `nse_selectedbyname()` - Script selection

**Library Bindings (nse_nmaplib.cc):**
- `set_version()` - Exposes service version to Lua
- `set_portinfo()` - Exposes port info to Lua
- NSE_NUM_VERSION_FIELDS = 12
- NSE_PROTOCOL_OP[] = {"tcp", "udp", "sctp"}

**Directories:**
- SCRIPT_ENGINE_LUA_DIR = "scripts/"
- SCRIPT_ENGINE_LIB_DIR = "nselib/"
- SCRIPT_ENGINE_DATABASE = "scripts/script.db"
- SCRIPT_ENGINE_EXTENSION = ".nse"

**Other Bindings:**
- nse_nsock.cc - Network socket
- nse_openssl.cc - SSL/TLS
- nse_ssl_cert.cc - Certificate parsing
- nse_dnet.cc - Network (dnet)
- nse_fs.cc - File system
- nse_db.cc - Database
- nse_libssh2.cc - SSH protocol
- nse_zlib.cc - Compression
- nse_lpeg.cc - LPeg pattern matching

### Output Module

**Log Types (output.h):**
- LOG_NORMAL (1), LOG_MACHINE (2), LOG_SKID (4), LOG_XML (8)
- LOG_STDOUT (1024), LOG_STDERR (2048), LOG_SKID_NOXLT (4096)
- LOG_PLAIN = LOG_NORMAL | LOG_SKID | LOG_STDOUT

**Functions:**
- `log_write(int logt, const char *fmt, ...)` - Main logging
- `printportoutput()` - Tabular port output
- `printmacinfo()` - MAC address display

### Service Detection Module

**Service Scan (service_scan.h):**
- `ServiceProbeMatch` class - Probe matching logic
- `MatchDetails` structure - Match results
- `serviceprobestate` enum - Detection states
- PROBESTATE_INITIAL, PROBESTATE_NULLPROBE, PROBESTATE_MATCHINGPROBES
- PROBESTATE_FINISHED_HARDMATCHED, PROBESTATE_FINISHED_SOFTMATCHED
- PROBESTATE_FINISHED_NOMATCH, PROBESTATE_FINISHED_TCPWRAPPED

**Timeouts:**
- DEFAULT_SERVICEWAITMS = 5000
- DEFAULT_TCPWRAPPEDMS = 2000
- DEFAULT_CONNECT_TIMEOUT = 5000
- DEFAULT_CONNECT_SSL_TIMEOUT = 8000
- MAXFALLBACKS = 20

## Recommendations

1. **Add "Implementation Details" sections** to each module doc
2. **Create new appendix files** for data structures and constants
3. **Map Nmap functions to Rust functions** explicitly
4. **Add pseudocode** for key algorithms
5. **Document state machines** with more detail

## Completed Enhancements

### Module Enhancements

1. **Port Scanning Module (modules/port-scanning.md)**
   - Added Section 3.2.5: Implementation Details
   - Ultra Scan algorithm with `ultra_scan()` flow
   - Probe system with `UltraProbe` structure
   - Timing control with `ultra_timing_vals`
   - Port state machine with exact transition conditions
   - Constant mappings from Nmap source

2. **OS Detection Module (modules/os-detection.md)**
   - Added Section 3.4.4: Implementation Details
   - FPHost, FPProbe structures
   - FPNetworkControl for network management
   - IPv6 probe definitions and timing
   - Fingerprint matching algorithm

3. **NSE Module (modules/nse-engine.md)**
   - Added Section 3.5.5: Implementation Details
   - ScriptResult structure and registry
   - Lua coroutine support (yield/restore)
   - Library bindings (nse_nmaplib.cc)
   - Socket bindings (nse_nsock.cc)
   - Constants and directories

### New Appendix Files Created

4. **appendix/nmap-data-structures.md**
   - Complete Nmap C++ structure definitions
   - Corresponding Rust structure definitions
   - Field-by-field mapping for all core types
   - Includes: UltraScanInfo, HostScanStats, Port, Target,
     FPHost, FPProbe, FPNetworkControl, ScriptResult,
     NmapOutputTable, serviceDeductions

5. **appendix/nmap-function-reference.md**
   - Complete Nmap function signatures
   - Corresponding Rust function signatures
   - Organized by module (scan, port, OS, NSE, output)
   - Includes call flow examples

6. **appendix/nmap-constants.md**
   - All #define constants from Nmap source
   - Organized by category (scan, port, OS, NSE, output, timing)
   - Rust const equivalents
   - Usage examples
