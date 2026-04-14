# Nmap Core Data Structures Reference

This document details the core data structures in the Nmap source code, providing precise mapping references for the Rust implementation.

## Table of Contents

1. [Scan Engine Structures](#1-scan-engine-structures)
2. [Port Management Structures](#2-port-management-structures)
3. [OS Detection Structures](#3-os-detection-structures)
4. [NSE Engine Structures](#4-nse-engine-structures)
5. [Target Management Structures](#5-target-management-structures)
6. [Output System Structures](#6-output-system-structures)

---

## 1. Scan Engine Structures

### UltraScanInfo (scan_engine.h)

```cpp
// Nmap C++ definition
class UltraScanInfo {
private:
    // Scan type
    stype scantype;

    // Timeout information
    struct timeout_info *to;

    // Performance configuration
    struct ultra_scan_performance_vars perf;

    // Completed host list
    std::list<HostScanStats *> completedHosts;
    std::list<HostScanStats *> activeHosts;
    std::list<HostScanStats *> incompleteHosts;

    // Probe management
    std::vector<UltraProbe *> probes;
    std::vector<UltraProbe *> freshProbes;

    // Rate metering
    PacketRateMeter send_rate_meter;

    // Timestamp
    struct timeval now;

    // Scan group size
    int group_scan_goal;

    // Whether completed
    bool anyCompleted;
};
```

```rust
// RustNmap corresponding structure
pub struct UltraScanInfo {
    // Scan type
    pub scan_type: ScanType,

    // Timeout information
    pub timeout: TimeoutInfo,

    // Performance configuration
    pub perf: ScanPerformanceVars,

    // Host statistics
    pub completed_hosts: Vec<HostScanStats>,
    pub active_hosts: Vec<HostScanStats>,
    pub incomplete_hosts: Vec<HostScanStats>,

    // Pending probes
    pub pending_probes: Vec<UltraProbe>,
    pub fresh_probes: Vec<UltraProbe>,

    // Rate meter
    pub send_rate_meter: PacketRateMeter,

    // Current time
    pub now: TimeVal,

    // Target group size
    pub group_scan_goal: usize,

    // Whether any host has completed
    pub any_completed: bool,
}
```

### HostScanStats (scan_engine.h)

```cpp
// Nmap C++ definition
class HostScanStats {
public:
    Target *target;

    // Number of probes sent
    int probes_sent;

    // Number of timed-out probes
    int probes_timedout;

    // Different port state counts
    int numopenports;
    int numclosedports;
    int numfilteredports;
    int numuntestableports;

    // Sending rate
    double sending_rate;
};
```

```rust
// RustNmap corresponding structure
pub struct HostScanStats {
    // Target host
    pub target: Target,

    // Number of probes sent
    pub probes_sent: usize,

    // Number of timed-out probes
    pub probes_timedout: usize,

    // Port state counts
    pub num_open_ports: usize,
    pub num_closed_ports: usize,
    pub num_filtered_ports: usize,
    pub num_untestable_ports: usize,

    // Sending rate (probes/second)
    pub sending_rate: f64,
}
```

### UltraProbe (scan_engine.h)

```cpp
// Nmap C++ definition
class UltraProbe {
public:
    // Probe type
    enum ProbeType {
        UP_UNSET,
        UP_IP,
        UP_ARP,
        UP_CONNECT,
        UP_ND,
    } type;

    // Retry number
    tryno_t tryno;

    union {
        struct probespec pspec;  // IP/ARP/ND probe
        ConnectProbe *CP;        // Connect scan
    } mypspec;

    // Send time
    struct timeval sent;
    struct timeval prevSent;

    // Status flags
    bool timedout;
    bool retransmitted;
};
```

```rust
// RustNmap corresponding structure
pub struct UltraProbe {
    // Probe type
    pub probe_type: ProbeType,

    // Retry information
    pub try_no: TryNo,

    // Probe specification
    pub spec: ProbeSpec,

    // Send time
    pub sent: Option<TimeVal>,
    pub prev_sent: Option<TimeVal>,

    // Status flags
    pub timed_out: bool,
    pub retransmitted: bool,
}

// TryNo structure (corresponding to tryno_t)
#[repr(C)]
pub union TryNo {
    raw: u8,
    fields: TryNoFields,
}

#[repr(C)]
pub struct TryNoFields {
    pub is_ping: u8,   // bit 0: whether this is a ping
    pub seq_num: u8,  // bit 1-7: sequence number (0-127)
}
```

---

## 2. Port Management Structures

### Port (portlist.h)

```cpp
// Nmap C++ definition
class Port {
private:
    // Port number
    u16 portno;

    // Protocol
    u8 proto;

    // Port state
    u8 state;

    // Deduction results
    struct serviceDeductions service;

    // State reason
    struct port_reason reason;

    // Script results
    ScriptResults scriptResults;
};
```

```rust
// RustNmap corresponding structure
pub struct Port {
    // Port number
    pub port_no: u16,

    // Protocol (TCP/UDP/SCTP)
    pub protocol: Protocol,

    // Port state
    pub state: PortState,

    // Service deductions
    pub service: Option<ServiceDeductions>,

    // State reason
    pub reason: PortReason,

    // Script execution results
    pub script_results: Vec<ScriptResult>,
}
```

### serviceDeductions (portlist.h)

```cpp
// Nmap C++ definition
struct serviceDeductions {
    const char *name;              // Service name
    int name_confidence;          // Name confidence (0-10)
    char *product;               // Product name
    char *version;               // Version number
    char *extrainfo;            // Extra information
    char *hostname;              // Hostname
    char *ostype;                // OS type
    char *devicetype;           // Device type
    std::vector<char *> cpe;   // CPE identifiers
    enum service_tunnel_type service_tunnel;  // SSL tunnel
    const char *service_fp;       // Service fingerprint (for submission)
    enum service_detection_type dtype;      // Detection type
};
```

```rust
// RustNmap corresponding structure
pub struct ServiceDeductions {
    // Service name
    pub name: Option<String>,

    // Confidence (0-10)
    pub name_confidence: u8,

    // Product information
    pub product: Option<String>,

    // Version information
    pub version: Option<String>,

    // Extra information
    pub extrainfo: Option<String>,

    // Hostname
    pub hostname: Option<String>,

    // OS type
    pub ostype: Option<String>,

    // Device type
    pub devicetype: Option<String>,

    // CPE identifiers
    pub cpe: Vec<String>,

    // SSL tunnel
    pub service_tunnel: ServiceTunnelType,

    // Service fingerprint
    pub service_fp: Option<String>,

    // Detection type
    pub dtype: ServiceDetectionType,
}

pub enum ServiceTunnelType {
    None,
    Ssl,
}

pub enum ServiceDetectionType {
    Table,    // Port table-based
    Probed,    // Active probing
}
```

### port_reason (portreasons.h)

```cpp
// Nmap C++ definition
struct port_reason {
    reason_id_t reason_id;   // Reason ID
    u8 ttl;                    // IP TTL value
    u32 ip_addr;               // Related IP address
    int state;                  // Related state
    const char *hostname;     // Related hostname
};
```

```rust
// RustNmap corresponding structure
pub struct PortReason {
    // Reason ID
    pub reason_id: ReasonId,

    // IP TTL value
    pub ttl: u8,

    // Related IP address
    pub ip_addr: IpAddr,

    // Related state
    pub state: Option<PortState>,

    // Related hostname
    pub hostname: Option<String>,
}

pub enum ReasonId {
    // ICMP unreachable reasons
    IcmpUnreachable,
    IcmpNetUnreachable,
    IcmpHostUnreachable,
    IcmpProtoUnreachable,
    IcmpPortUnreachable,
    IcmpAdminProhibited,

    // TCP response reasons
    SynAck,
    Rst,
    SynRstAck,

    // Other
    TcpWrapper,
    LocalPacket,
    // ...
}
```

---

## 3. OS Detection Structures

### FPHost (FPEngine.h)

```cpp
// Nmap C++ definition
class FPHost {
protected:
    unsigned int total_probes;      // Total probes
    unsigned int timed_probes;      // Timed probes
    unsigned int probes_sent;       // Probes sent
    unsigned int probes_answered;   // Responses received
    unsigned int probes_unanswered; // Unanswered probes
    bool incomplete_fp;             // Whether complete
    bool detection_done;            // Whether detection is complete
    bool timedprobes_sent;          // Whether timed probes have been sent

    Target *target_host;            // Target host
    FPNetworkControl *netctl;       // Network controller
    bool netctl_registered;         // Whether registered

    u32 tcpSeqBase;                 // TCP sequence number base
    int open_port_tcp;              // Open TCP port
    int closed_port_tcp;            // Closed TCP port
    int closed_port_udp;            // Closed UDP port
    int tcp_port_base;              // TCP base port
    int udp_port_base;              // UDP base port
    u16 icmp_seq_counter;           // ICMP sequence counter
    int rto;                        // Retransmission timeout
    int rttvar;                     // RTT variance
    int srtt;                       // Smoothed RTT
};
```

```rust
// RustNmap corresponding structure
pub struct FpHost {
    // Total probes
    pub total_probes: u32,

    // Timed probes
    pub timed_probes: u32,

    // Probes sent
    pub probes_sent: u32,

    // Responses received
    pub probes_answered: u32,

    // Unanswered probes
    pub probes_unanswered: u32,

    // Whether complete
    pub incomplete_fp: bool,

    // Whether detection is complete
    pub detection_done: bool,

    // Whether timed probes have been sent
    pub timed_probes_sent: bool,

    // Target host
    pub target_host: Target,

    // Network controller
    pub netctl: Option<FpNetworkControl>,

    // Whether registered with network controller
    pub netctl_registered: bool,

    // TCP sequence number base
    pub tcp_seq_base: u32,

    // Open TCP port
    pub open_port_tcp: i32,

    // Closed TCP port
    pub closed_port_tcp: i32,

    // Closed UDP port
    pub closed_port_udp: i32,

    // TCP base port
    pub tcp_port_base: i32,

    // UDP base port
    pub udp_port_base: i32,

    // ICMP sequence counter
    pub icmp_seq_counter: u16,

    // Retransmission timeout
    pub rto: i32,

    // RTT variance
    pub rttvar: i32,

    // Smoothed RTT
    pub srtt: i32,
}
```

### FPProbe (FPEngine.h)

```cpp
// Nmap C++ definition
class FPProbe : public FPPacket {
private:
    const char *probe_id;      // Probe ID
    int probe_no;                // Probe number
    int retransmissions;          // Retransmission count
    int times_replied;           // Reply count
    bool failed;                // Whether failed
    bool timed;                 // Whether timed

    FPHost *host;              // Associated host
};
```

```rust
// RustNmap corresponding structure
pub struct FpProbe {
    // Probe ID (e.g. "SEQ", "T1", "IE1", etc.)
    pub probe_id: Cow<'static, str>,

    // Probe number
    pub probe_no: i32,

    // Retransmission count
    pub retransmissions: i32,

    // Number of responses received
    pub times_replied: i32,

    // Whether failed
    pub failed: bool,

    // Whether timed
    pub timed: bool,

    // Associated host
    pub host: *mut FpHost,

    // Packet data (inherited from FPPacket)
    pub packet: PacketData,

    // Send time
    pub sent_time: TimeVal,
}
```

### FPNetworkControl (FPEngine.h)

```cpp
// Nmap C++ definition
class FPNetworkControl {
private:
    nsock_pool nsp;            // Nsock connection pool
    nsock_iod pcap_nsi;        // Pcap descriptor
    nsock_event_id pcap_ev_id; // Last pcap event ID
    bool first_pcap_scheduled;  // Whether first pcap has been scheduled
    bool nsock_init;           // Whether Nsock is initialized
    int rawsd;                 // Raw socket
    std::vector<FPHost *> callers;  // Caller list

    int probes_sent;           // Probes sent
    int responses_recv;        // Responses received
    int probes_timedout;       // Timed-out probes
    float cc_cwnd;             // Congestion window
    float cc_ssthresh;         // Slow start threshold
};
```

```rust
// RustNmap corresponding structure
pub struct FpNetworkControl {
    // Nsock connection pool
    pub nsock_pool: NsockPool,

    // Pcap descriptor
    pub pcap_nsi: NsockIod,

    // Last scheduled pcap event ID
    pub pcap_ev_id: NsockEventId,

    // Whether first pcap has been scheduled
    pub first_pcap_scheduled: bool,

    // Whether Nsock is initialized
    pub nsock_init: bool,

    // Raw socket
    pub raw_sd: i32,

    // Caller list (FPHost list)
    pub callers: Vec<*mut FpHost>,

    // Probes sent
    pub probes_sent: i32,

    // Responses received
    pub responses_recv: i32,

    // Timed-out probes
    pub probes_timedout: i32,

    // Congestion window
    pub cc_cwnd: f32,

    // Slow start threshold
    pub cc_ssthresh: f32,
}
```

---

## 4. NSE Engine Structures

### ScriptResult (nse_main.h)

```cpp
// Nmap C++ definition
class ScriptResult {
private:
    const char *id;              // Script ID
    int output_ref;              // Output table reference (LUA_REGISTRYINDEX)

public:
    ScriptResult();
    ~ScriptResult();
    void clear(void);
    void set_output_tab(lua_State *, int);
    std::string get_output_str(void) const;
    const char *get_id(void) const { return id; }
    void write_xml() const;
    bool operator<(ScriptResult const &b) const {
        return strcmp(this->id, b.id) < 0;
    }
};
```

```rust
// RustNmap corresponding structure
pub struct ScriptResult {
    // Script identifier (filename without .nse)
    pub id: Cow<'static, str>,

    // Output table reference (in LUA_REGISTRYINDEX)
    pub output_ref: i32,

    // Raw output string
    pub output_str: String,
}

impl ScriptResult {
    // Corresponds to get_output_str()
    pub fn get_output_string(&self) -> Cow<'static, str> {
        if self.output_ref != LUA_NOREF {
            // Get output from registry
            get_registry_output(self.output_ref)
        } else {
            Cow::Borrowed(&self.output_str)
        }
    }

    // Corresponds to write_xml()
    pub fn write_xml(&self) {
        // Output script results as XML
        xml::start_element("script");
        xml::attribute("id", self.id);
        xml::attribute("output", self.get_output_string());
        xml::end_element();
    }

    // Corresponds to operator<
    impl Ord for ScriptResult {
        fn cmp(&self, other: &Self) -> Ordering {
            strcmp(self.id, other.id) < 0
        }
    }
}
```

### ScriptResults (nse_main.h)

```cpp
// Nmap C++ definition
typedef std::multiset<ScriptResult *> ScriptResults;

// Get results object
ScriptResults *get_script_scan_results_obj(void);
```

```rust
// RustNmap corresponding structure
pub struct ScriptResults {
    // Use BTreeSet to maintain ordering (equivalent to std::multiset)
    results: BTreeSet<ScriptResult>,
}

impl ScriptResults {
    pub fn new() -> Self {
        Self {
            results: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, result: ScriptResult) {
        self.results.insert(result);
    }

    pub fn iter(&self) -> impl Iterator<Item = &ScriptResult> {
        self.results.iter()
    }
}
```

---

## 5. Target Management Structures

### Target (Target.h)

```cpp
// Nmap C++ core fields
class Target {
private:
    // Address information
    struct sockaddr_storage targetsock;
    struct sockaddr_storage sourcesock;
    char *hostname;
    char *targetname;  // User-specified name

    // MAC address
    u8 MACaddress[6];
    bool MACaddress_set;

    // Status flags
    bool af;                      // Address family
    bool up;                       // Whether online
    bool wping;                    // Whether ping is needed
    bool osscan_done;              // OS scan complete

    // Port list
    PortList ports;

    // OS fingerprint results
    FingerPrintResults OSs;

    // Timestamps
    struct timeval systime;
    struct timeval probe_timeout;
};
```

```rust
// RustNmap corresponding structure
pub struct Target {
    // Address information
    pub target_sock: SocketAddr,
    pub source_sock: Option<SocketAddr>,

    // Hostname
    pub hostname: Option<String>,

    // User-specified target name
    pub target_name: Option<String>,

    // MAC address
    pub mac_address: Option<[u8; 6]>,
    pub mac_address_set: bool,

    // Address family
    pub address_family: AddressFamily,

    // Status flags
    pub is_up: bool,
    pub wants_ping: bool,
    pub os_scan_done: bool,

    // Port list
    pub ports: PortList,

    // OS fingerprint results
    pub os_results: Option<FingerprintResults>,

    // System time
    pub sys_time: Option<TimeVal>,

    // Probe timeout
    pub probe_timeout: Duration,
}
```

### TargetGroup (TargetGroup.h)

```cpp
// Nmap C++ definition
class TargetGroup {
private:
    // Target expressions
    std::vector<std::string> expressions;

    // Current batch
    std::vector<Target *> current_batch;

    // Batch size
    int max_batch_size;

    // Indices
    int current_expr_idx;
    int current_target_idx;
};
```

```rust
// RustNmap corresponding structure
pub struct TargetGroup {
    // Target expressions (e.g. "192.168.1.0/24", "example.com")
    pub expressions: Vec<String>,

    // Current batch
    pub current_batch: Vec<Target>,

    // Batch size
    pub max_batch_size: usize,

    // Indices
    pub current_expr_idx: usize,
    pub current_target_idx: usize,
}

impl TargetGroup {
    // Get next batch of targets
    pub fn next_batch(&mut self) -> Option<Vec<Target>> {
        if self.current_expr_idx >= self.expressions.len() {
            return None;
        }

        let mut batch = Vec::new();
        while batch.len() < self.max_batch_size {
            if let Some(target) = self.next_target() {
                batch.push(target);
            } else {
                break;
            }
        }

        if batch.is_empty() {
            None
        } else {
            Some(batch)
        }
    }
}
```

---

## 6. Output System Structures

### NmapOutputTable (NmapOutputTable.h)

```cpp
// Nmap C++ definition
class NmapOutputTable {
private:
    unsigned int ncolumns;       // Number of columns
    unsigned int nrows;          // Number of rows
    unsigned int maxncolumns;    // Maximum columns
    unsigned int maxnrows;       // Maximum rows

    bool **table;               // Table data
    unsigned short *tableitemvalid;  // Item validity
    bool items_dont_print;      // Whether to print items

public:
    unsigned int size();         // Get table size
    bool isSet();             // Check if set
};
```

```rust
// RustNmap corresponding structure
pub struct NmapOutputTable {
    // Number of columns
    pub num_columns: usize,

    // Number of rows
    pub num_rows: usize,

    // Maximum columns
    pub max_num_columns: usize,

    // Maximum rows
    pub max_num_rows: usize,

    // Table data (2D array)
    pub table: Vec<Vec<Option<String>>>,

    // Item validity
    pub item_valid: Vec<Vec<bool>>,

    // Whether to print items
    pub items_dont_print: bool,
}

impl NmapOutputTable {
    pub fn new(columns: usize, rows: usize) -> Self {
        Self {
            num_columns: columns,
            num_rows: 0,
            max_num_columns: columns,
            max_num_rows: rows,
            table: vec![vec![None; columns]; rows],
            item_valid: vec![vec![false; columns]; rows],
            items_dont_print: false,
        }
    }

    // Add a row
    pub fn add_row(&mut self, row: Vec<Option<String>>) -> Result<()> {
        if self.num_rows >= self.max_num_rows {
            return Err(Error::TableFull);
        }

        if row.len() != self.num_columns {
            return Err(Error::ColumnMismatch);
        }

        self.table.push(row);
        self.num_rows += 1;
        Ok(())
    }
}
```

---

## Constants Mapping Table

| Nmap Constant | Value | Rust Constant Name |
|------------|-----|------------|
| PORT_UNKNOWN | 0 | PortState::Unknown |
| PORT_CLOSED | 1 | PortState::Closed |
| PORT_OPEN | 2 | PortState::Open |
| PORT_FILTERED | 3 | PortState::Filtered |
| PORT_TESTING | 4 | PortState::Testing |
| PORT_FRESH | 5 | PortState::Fresh |
| PORT_UNFILTERED | 6 | PortState::Unfiltered |
| PORT_OPENFILTERED | 7 | PortState::OpenFiltered |
| PORT_CLOSEDFILTERED | 8 | PortState::ClosedFiltered |
| LOG_NORMAL | 1 | LogType::Normal |
| LOG_MACHINE | 2 | LogType::Machine |
| LOG_SKID | 4 | LogType::Skid |
| LOG_XML | 8 | LogType::Xml |
| LOG_STDOUT | 1024 | LogType::Stdout |
| PROBESTATE_INITIAL | 1 | ServiceProbeState::Initial |
| PROBESTATE_NULLPROBE | 2 | ServiceProbeState::NullProbe |
| PROBESTATE_MATCHINGPROBES | 3 | ServiceProbeState::MatchingProbes |
| PROBESTATE_FINISHED_HARDMATCHED | 4 | ServiceProbeState::FinishedHardMatched |
| PROBESTATE_FINISHED_SOFTMATCHED | 5 | ServiceProbeState::FinishedSoftMatched |
| PROBESTATE_FINISHED_NOMATCH | 6 | ServiceProbeState::FinishedNoMatch |
| PROBESTATE_FINISHED_TCPWRAPPED | 7 | ServiceProbeState::FinishedTcpWrapped |
| PROBESTATE_INCOMPLETE | 8 | ServiceProbeState::Incomplete |
