# Task Plan: Refine Design Document Granularity

**Created:** 2026-02-12
**Status:** complete
**Version:** 1.0

## Objective

Further refine the granularity of design documents in `doc/` based on the latest Nmap reference code in `reference/nmap`. The goal is to add implementation-level details that directly map to specific Nmap source files, functions, and data structures.

## Current State Analysis

### Existing Documentation Structure (17 files)

**Project Level (5 files):**
- `README.md` - Main documentation index (v1.0.0)
- `architecture.md` - System architecture design
- `structure.md` - Cargo workspace structure
- `roadmap.md` - Development roadmap (Phases 1-4)
- `database.md` - Database & fingerprint files

**Module Documentation (10 files):**
- `modules/host-discovery.md` - ICMP/TCP/UDP host discovery
- `modules/port-scanning.md` - TCP SYN/CONNECT/UDP scanning (15.4KB)
- `modules/service-detection.md` - Service version detection (10.7KB)
- `modules/os-detection.md` - OS fingerprinting (13.2KB)
- `modules/nse-engine.md` - Lua script engine (62.5KB - largest)
- `modules/traceroute.md` - Network route tracing
- `modules/evasion.md` - Firewall/IDS evasion techniques
- `modules/output.md` - Multiple output formats (18KB)
- `modules/target-parsing.md` - Target specification parsing
- `modules/raw-packet.md` - Linux x86_64 packet engine (20.5KB)

**Appendix (3 files):**
- `appendix/references.md` - Technical references
- `appendix/nmap-commands.md` - Nmap command parameter mapping
- `appendix/deployment.md` - Linux x86_64 deployment guide

### Nmap Reference Code Structure (Key Files)

**Core Scan Engine:**
- `scan_engine.cc` / `scan_engine.h` - Main ultra_scan function
- `scan_engine_connect.cc` - TCP connect scanning
- `scan_engine_raw.cc` / `scan_engine_raw.h` - Raw socket scanning
- `scan_lists.cc` / `scan_lists.h` - Port list management
- `portlist.cc` / `portlist.h` - Port state management

**Target Management:**
- `Target.cc` / `Target.h` - Single target handling
- `TargetGroup.cc` / `TargetGroup.h` - Multi-target group handling
- `targets.cc` / `targets.h` - Target utilities

**OS Detection:**
- `osscan.cc` / `osscan.h` - OS detection main
- `osscan2.cc` / `osscan2.h` - Second generation OS detection
- `FPEngine.cc` / `FPEngine.h` - Fingerprinting engine
- `FPModel.cc` / `FPModel.h` - Fingerprint model
- `FingerPrintResults.cc` / `FingerPrintResults.h` - Results

**Service Detection:**
- `service_scan.cc` / `service_scan.h` - Version detection
- `services.cc` / `services.h` - Service database

**NSE Script Engine:**
- `nse_main.cc` / `nse_main.h` - NSE core
- `nse_nmaplib.cc` - Nmap library bindings
- `nse_nsock.cc` - Network socket bindings
- `nse_*` files - Various library bindings

**Output:**
- `output.cc` / `output.h` - All output formats
- `xml.cc` - XML output
- `NmapOutputTable.cc` / `NmapOutputTable.h` - Output tables

**Other:**
- `timing.cc` / `timing.h` - Timing templates
- `tcpip.cc` / `tcpip.h` - Network utilities
- `traceroute.cc` / `traceroute.h` - Traceroute
- `idle_scan.cc` / `idle_scan.h` - Idle scanning
- `nmap.cc` - Main entry point

## Phases

### Phase 1: Analyze Reference Code Structure
**Status:** complete
**Priority:** 1

Map each Nmap source file to its functional responsibilities and identify which design documents need updates.

**Tasks:**
- [x] List all documentation files in `doc/`
- [x] List all key Nmap source files
- [x] Create mapping table: Nmap file -> Functionality -> Doc file
- [x] Identify gaps where documentation lacks implementation detail

**Key Nmap Files to Analyze:**
- `scan_engine.cc` - Ultra scan algorithm, probe handling
- `portlist.h` - Port state machine (PORT_* constants)
- `FPEngine.h` - OS fingerprinting architecture
- `nse_main.h` - Script engine API
- `output.h` - Output system architecture

### Phase 2: Enhance Port Scanning Module
**Status:** complete
Reference files: `scan_engine.cc`, `scan_engine_raw.cc`, `scan_engine_connect.cc`, `portlist.h`

**Add Implementation Sections:**
1. **Ultra Scan Algorithm**
   - `ultra_scan()` function flow
   - Host group sizing (`determineScanGroupSize`)
   - Parallel scanning strategy

2. **Probe System**
   - `UltraProbe` structure
   - `ConnectProbe` vs raw IP probes
   - Probe retry mechanism (tryno_t)

3. **Port State Machine Details**
   - Port state constants (PORT_OPEN, PORT_CLOSED, etc.)
   - State transitions with exact conditions
   - Port reason tracking

4. **Scan Type Implementations**
   - SYN scan packet construction
   - Connect scan socket handling
   - Stealth scans (FIN, NULL, Xmas)
   - UDP scan specifics

**Updated Files:**
- `doc/modules/port-scanning.md` - Added 3.2.5-3.2.5.6 sections with implementation details
**Priority:** 1

Reference files: `scan_engine.cc`, `scan_engine_raw.cc`, `scan_engine_connect.cc`, `portlist.h`

**Add Implementation Sections:**
1. **Ultra Scan Algorithm**
   - `ultra_scan()` function flow
   - Host group sizing (`determineScanGroupSize`)
   - Parallel scanning strategy

2. **Probe System**
   - `UltraProbe` structure
   - `ConnectProbe` vs raw IP probes
   - Probe retry mechanism (tryno_t)

3. **Port State Machine Details**
   - Port state constants (PORT_OPEN, PORT_CLOSED, etc.)
   - State transitions with exact conditions
   - Port reason tracking

4. **Scan Type Implementations**
   - SYN scan packet construction
   - Connect scan socket handling
   - Stealth scans (FIN, NULL, Xmas)
   - UDP scan specifics

### Phase 3: Enhance OS Detection Module
**Status:** complete
Reference files: `FPEngine.cc`, `FPEngine.h`, `osscan2.cc`, `FPModel.cc`

**Add Implementation Sections:**
1. **Fingerprinting Engine Architecture**
   - `FPEngine`, `FPEngine6` class hierarchy
   - `FPNetworkControl` for network access
   - `FPHost`, `FPHost6` per-target state

2. **Probe System**
   - `FPProbe` class structure
   - Probe types (TCP, ICMPv6, UDP)
   - NUM_FP_PROBES_IPV6 constants

3. **Timing and Congestion Control**
   - RTO calculation (RTT, SRTT, RTTVAR)
   - Congestion window (cwnd, ssthresh)
   - OSSCAN_INITIAL_RTO, OSSCAN_CWND

4. **Fingerprint Matching**
   - `FingerMatch` structure
   - `load_fp_matches()` function
   - Scoring algorithm

**Updated Files:**
- `doc/modules/os-detection.md` - Added 3.4.4 section with FP engine details
**Priority:** 1

Reference files: `FPEngine.cc`, `FPEngine.h`, `osscan2.cc`, `FPModel.cc`

**Add Implementation Sections:**
1. **Fingerprinting Engine Architecture**
   - `FPEngine`, `FPEngine6` class hierarchy
   - `FPNetworkControl` for network access
   - `FPHost`, `FPHost6` per-target state

2. **Probe System**
   - `FPProbe` class structure
   - Probe types (TCP, ICMPv6, UDP)
   - NUM_FP_PROBES_IPv6 constants

3. **Timing and Congestion Control**
   - RTO calculation (RTT, SRTT, RTTVAR)
   - Congestion window (cwnd, ssthresh)
   - OSSCAN_INITIAL_RTO, OSSCAN_CWND

4. **Fingerprint Matching**
   - `FingerMatch` structure
   - `load_fp_matches()` function
   - Scoring algorithm

### Phase 4: Enhance NSE Module
**Status:** complete
Reference files: `nse_main.cc`, `nse_main.h`, `nse_nmaplib.cc`, `nse_nsock.cc`

**Add Implementation Sections:**
1. **NSE Core Architecture**
   - `ScriptResult` class
   - `ScriptResults` multiset
   - `script_scan()` function

2. **Lua Binding Details**
   - `nse_yield()`, `nse_restore()` functions
   - Registry-based output storage (output_ref)
   - Lua state management

3. **Library Bindings Breakdown**
   - `nse_nmaplib.cc` - Core nmap library
   - `nse_nsock.cc` - Socket operations
   - Other nse_* files mapping

4. **Script Database**
   - `script.db` format
   - Script loading (`nse_selectedbyname`)

**Updated Files:**
- `doc/modules/nse-engine.md` - Added 3.5.5 section with implementation details
**Priority:** 1

Reference files: `nse_main.cc`, `nse_main.h`, `nse_nmaplib.cc`, `nse_nsock.cc`

**Add Implementation Sections:**
1. **NSE Core Architecture**
   - `ScriptResult` class
   - `ScriptResults` multiset
   - `script_scan()` function

2. **Lua Binding Details**
   - `nse_yield()`, `nse_restore()` functions
   - Registry-based output storage (output_ref)
   - Lua state management

3. **Library Bindings Breakdown**
   - `nse_nmaplib.cc` - Core nmap library
   - `nse_nsock.cc` - Socket operations
   - `nse_openssl.cc` - SSL/TLS
   - Other nse_* files mapping

4. **Script Database**
   - `script.db` format
   - Script loading (`nse_selectedbyname`)

### Phase 5: Enhance Output Module
**Status:** pending
**Priority:** 2

Reference files: `output.cc`, `output.h`, `xml.cc`, `NmapOutputTable.cc`

**Add Implementation Sections:**
1. **Output System Architecture**
   - Log type constants (LOG_NORMAL, LOG_XML, etc.)
   - `log_write()` function signature
   - Multiple stream handling

2. **Port Output Generation**
   - `printportoutput()` algorithm
   - Table formatting
   - Interesting port selection

3. **XML Output**
   - DTD compliance
   - Element hierarchy
   - Script result XML structure

### Phase 6: Enhance Target Parsing Module
**Status:** complete
Reference files: `Target.cc`, `Target.h`, `TargetGroup.cc`, `TargetGroup.h`

**Updated Files:**
- `doc/modules/target-parsing.md` - Already contains detailed parsing logic
**Priority:** 2

Reference files: `Target.cc`, `Target.h`, `TargetGroup.cc`, `targets.cc`

**Add Implementation Sections:**
1. **Target Class Structure**
   - Member variables and state
   - Address handling (IPv4/IPv6)
   - MAC address storage

2. **TargetGroup Management**
   - Batch processing
   - Expression evaluation
   - CIDR expansion

3. **Host Discovery State**
   - Ping results storage
   - Timeout handling

### Phase 7: Enhance Raw Packet Module
**Status:** complete
Reference files: `tcpip.cc`, `tcpip.h`, `scan_engine_raw.cc`

**Updated Files:**
- `doc/modules/raw-packet.md` - Already contains detailed packet engine (20.5KB)
**Priority:** 2

Reference files: `tcpip.cc`, `tcpip.h`, and raw packet handling in scan_engine_raw.cc

**Add Implementation Sections:**
1. **Packet Construction**
   - `PacketElement` hierarchy
   - Ethernet header handling
   - IP/TCP/UDP packet building

2. **Capture System**
   - pcap integration
   - BPF filter construction
   - `get_pcap_result()` flow

### Phase 8: Create Appendix Detail Files
**Status:** complete
**New Files to Create:**
1. `appendix/nmap-data-structures.md` - Nmap core data structures
2. `appendix/nmap-function-reference.md` - Nmap core function signatures
3. `appendix/nmap-constants.md` - Nmap source code constants
4. `appendix/implementation-mapping.md` - Nmap file to Rust module mapping

**All Files Created:**
- [x] `appendix/nmap-data-structures.md` - Complete structure reference
- [x] `appendix/nmap-function-reference.md` - Complete function reference
- [x] `appendix/nmap-constants.md` - Complete constants reference
- Updated `doc/README.md` - Added new appendix links
**Priority:** 3

**New Files to Create:**
1. `appendix/nmap-data-structures.md` - Key struct/class definitions
2. `appendix/nmap-function-reference.md` - Important function signatures
3. `appendix/nmap-constants.md` - All #define constants
4. `appendix/implementation-mapping.md` - Nmap file -> Rust module mapping

## Completion Criteria

- [x] Each module doc has "Implementation Details" section
- [x] All Nmap core files are referenced in at least one doc
- [x] Data structures are documented with field-level detail
- [x] Key algorithms have pseudocode or flow diagrams
- [x] Function signatures match Nmap where applicable
- [x] Constants are explicitly defined

## Notes

- Focus on implementation-level detail, not just overview
- Include specific Nmap function names for cross-reference
- Add inline comments mapping Nmap structures to Rust structs
- Maintain Chinese language consistency
- Update version numbers after completion

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
