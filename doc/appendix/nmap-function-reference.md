# Nmap Core Function Reference

This document lists key functions in the Nmap source code, providing function signature references for the Rust implementation.

## Table of Contents

1. [Scan Engine Functions](#1-scan-engine-functions)
2. [Port Management Functions](#2-port-management-functions)
3. [OS Detection Functions](#3-os-detection-functions)
4. [NSE Engine Functions](#4-nse-engine-functions)
5. [Target Management Functions](#5-target-management-functions)
6. [Output System Functions](#6-output-system-functions)

---

## 1. Scan Engine Functions

### scan_engine.cc

```cpp
// Third-generation scan main function
void ultra_scan(std::vector<Target *> &Targets,
              const struct scan_lists *ports,
              stype scantype,
              struct timeout_info *to = NULL);
```

```rust
// RustNmap corresponding function signature
pub async fn ultra_scan(
    targets: Vec<Target>,
    scan_lists: &ScanLists,
    scan_type: ScanType,
    timeout_info: Option<&TimeoutInfo>,
) -> Result<Vec<ScanResult>> {
    // implementation...
}
```

```cpp
// Determine scan group size
int determineScanGroupSize(int hosts_scanned_so_far,
                       const struct scan_lists *ports);
```

```rust
pub fn determine_scan_group_size(
    hosts_scanned_so_far: usize,
    scan_lists: &ScanLists,
) -> usize {
    // implementation...
}
```

### scan_engine_raw.cc

```cpp
// Send ARP scan probe
UltraProbe *sendArpScanProbe(UltraScanInfo *USI,
                              HostScanStats *hss,
                              tryno_t tryno);

// Send IPv6 Neighbor Discovery probe
UltraProbe *sendNDScanProbe(UltraScanInfo *USI,
                            HostScanStats *hss,
                            tryno_t tryno);

// Send IP protocol scan probe
UltraProbe *sendIPScanProbe(UltraScanInfo *USI,
                          HostScanStats *hss,
                          const probespec *pspec,
                          tryno_t tryno);

// Get ARP result
bool get_arp_result(UltraScanInfo *USI, struct timeval *stime);

// Get ND result
bool get_ns_result(UltraScanInfo *USI, struct timeval *stime);

// Get pcap result
bool get_pcap_result(UltraScanInfo *USI, struct timeval *stime);
```

```rust
// RustNmap corresponding functions
pub async fn send_arp_scan_probe(
    usi: &mut UltraScanInfo,
    hss: &mut HostScanStats,
    try_no: TryNo,
) -> Result<&mut UltraProbe> {
    // implementation...
}

pub async fn send_nd_scan_probe(
    usi: &mut UltraScanInfo,
    hss: &mut HostScanStats,
    try_no: TryNo,
) -> Result<&mut UltraProbe> {
    // implementation...
}

pub async fn send_ip_scan_probe(
    usi: &mut UltraScanInfo,
    hss: &mut HostScanStats,
    probe_spec: &ProbeSpec,
    try_no: TryNo,
) -> Result<&mut UltraProbe> {
    // implementation...
}

pub async fn get_arp_result(
    usi: &mut UltraScanInfo,
    stime: &TimeVal,
) -> Result<bool> {
    // implementation...
}

pub async fn get_pcap_result(
    usi: &mut UltraScanInfo,
    stime: &TimeVal,
) -> Result<bool> {
    // implementation...
}
```

### scan_engine_connect.cc

```cpp
// TCP Connect scan
int connect_scan(std::vector<Target *> &Targets,
                const struct scan_lists *ports,
                const struct timeout_info *to);
```

```rust
// RustNmap corresponding function
pub async fn connect_scan(
    targets: Vec<Target>,
    ports: &ScanLists,
    timeout: &TimeoutInfo,
) -> Result<Vec<ScanResult>> {
    // implementation...
}
```

---

## 2. Port Management Functions

### portlist.cc

```cpp
// Move commonly used ports to the beginning of the list
void random_port_cheat(u16 *ports, int portcount);

// Port state to string
const char *statenum2str(int state);

// Get Nmap service name
void Port::getNmapServiceName(char *namebuf, int buflen) const;

// Free service information
void Port::freeService(bool del_service);

// Free script results
void Port::freeScriptResults(void);
```

```rust
// RustNmap corresponding functions
pub fn random_port_cheat(ports: &mut [u16], port_count: usize);

pub fn state_enum_to_str(state: PortState) -> &'static str;

impl Port {
    pub fn get_nmap_service_name(&self, name_buf: &mut [u8], buf_len: usize)
        -> Result<usize>;

    pub fn free_service(&mut self, delete_service: bool);

    pub fn free_script_results(&mut self);
}
```

### portreasons.cc

```cpp
// Port reason to string
const char *reason_str(reason_t reason_id, bool shortform);
```

```rust
// RustNmap corresponding function
pub fn reason_str(reason_id: ReasonId, short_form: bool) -> &'static str {
    match reason_id {
        ReasonId::SynAck => "syn-ack",
        ReasonId::Rst => "reset",
        ReasonId::IcmpUnreachable => "icmp-unreach",
        ReasonId::IcmpNetUnreachable => "net-unreach",
        ReasonId::IcmpHostUnreachable => "host-unreach",
        ReasonId::IcmpProtoUnreachable => "proto-unreach",
        ReasonId::IcmpPortUnreachable => "port-unreach",
        ReasonId::IcmpAdminProhibited => "admin-prohibited",
        ReasonId::TcpWrapper => "tcp-wrapper",
        ReasonId::LocalPacket => "local",
        // ...
    }
}
```

---

## 3. OS Detection Functions

### FPEngine.cc

```cpp
// IPv6 OS scan
int FPEngine6::os_scan(std::vector<Target *> &Targets);

// Load fingerprint matches
std::vector<FingerMatch> load_fp_matches();
```

```rust
// RustNmap corresponding functions
impl FingerprintEngineV6 {
    pub async fn os_scan(&mut self, targets: Vec<Target>)
        -> Result<()>;

    pub fn load_finger_matches(db_path: &Path)
        -> Result<Vec<FingerMatch>> {
        // implementation...
    }
}

pub fn load_finger_matches(db_path: &Path)
    -> Result<Vec<FingerMatch>> {
    // implementation...
}
```

### FPModel.cc

```cpp
// Fingerprint matching
std::vector<FingerMatch> FPModel::match(const FingerPrint &FP);
```

```rust
// RustNmap corresponding function
impl FingerprintModel {
    pub fn match_fingerprint(&self, fp: &Fingerprint)
        -> Vec<FingerMatch> {
        // implementation...
    }
}
```

---

## 4. NSE Engine Functions

### nse_main.cc

```cpp
// NSE coroutine yield
int nse_yield(lua_State *, lua_KContext, lua_KFunction);

// NSE coroutine restore
void nse_restore(lua_State *, int);

// NSE destructor
void nse_destructor(lua_State *, char);

// NSE base library initialization
void nse_base(lua_State *);

// Select scripts by name
void nse_selectedbyname(lua_State *);

// Get target
void nse_gettarget(lua_State *, int);

// Open NSE
void open_nse(void);

// Script scan
void script_scan(std::vector<Target *> &targets, stype scantype);

// Close NSE
void close_nse(void);
```

```rust
// RustNmap corresponding functions
pub struct NseCoroutine {
    pub fn yield(&mut self, nresults: i32) -> Result<()>;
    pub fn restore(&mut self, args: &[LuaValue]) -> Result<()>;
}

pub fn nse_destructor(lua: &mut LuaState, code: char);

pub fn nse_base(lua: &mut LuaState);

pub fn nse_selected_by_name(lua: &mut LuaState, patterns: Vec<String>);

pub fn nse_get_target(lua: &mut LuaState, index: i32);

pub async fn open_nse() -> Result<NseEngine>;

pub async fn script_scan(targets: Vec<Target>, scan_type: ScanType)
    -> Result<Vec<NseScriptResult>>;

pub async fn close_nse() -> Result<()>;
```

### nse_nmaplib.cc

```cpp
// Set version information to Lua table
void set_version(lua_State *L, const struct serviceDeductions *sd);

// Set port information to Lua table
void set_portinfo(lua_State *L, const Target *target, const Port *port);

// Push binary IP address
static void push_bin_ip(lua_State *L, const struct sockaddr_storage *ss);

// Set string or nil
static void set_string_or_nil(lua_State *L, const char *fieldname,
                              const char *value);

// Push OS class table
static void push_osclass_table(lua_State *L,
                                const struct OS_Classification *osclass);

// Push OS match table
static void push_osmatch_table(lua_State *L, const FingerMatch *match,
                               const OS_Classification_Results *OSR);
```

```rust
// RustNmap corresponding functions
pub fn set_version(lua: &mut LuaState, sd: &ServiceDeductions);

pub fn set_port_info(lua: &mut LuaState,
                    target: &Target,
                    port: &Port);

pub fn push_bin_ip(lua: &mut LuaState, ss: &SocketAddr);

pub fn set_string_or_nil(lua: &mut LuaState, field: &str, value: Option<&str>);

pub fn push_os_class_table(lua: &mut LuaState, os_class: &OsClassification);

pub fn push_os_match_table(lua: &mut LuaState,
                             match: &FingerMatch,
                             os_results: &OsClassificationResults);
```

### nse_nsock.cc

```cpp
// Nsock binding functions
static const struct luaL_Reg nse_nsock_lib[] = {
    {"connect", nsock_connect},
    {"send", nsock_send},
    {"receive", nsock_receive},
    {"receive_bytes", nsock_receive_bytes},
    {"receive_buf", nsock_receive_buf},
    {"close", nsock_close},
    {"get_info", nsock_get_info},
    {"get_interface_info", nsock_get_interface_info},
    {"setup", nsock_setup},
    {"pcap_open", nsock_pcap_open},
    {"pcap_close", nsock_pcap_close},
    {"pcap_register", nsock_pcap_register},
    {NULL, NULL}
};
```

```rust
// RustNmap corresponding library registration
pub fn register_nsock_library(lua: &mut LuaState) -> Result<()> {
    let methods = [
        ("connect", nsock_connect),
        ("send", nsock_send),
        ("receive", nsock_receive),
        ("receive_bytes", nsock_receive_bytes),
        ("receive_buf", nsock_receive_buf),
        ("close", nsock_close),
        ("get_info", nsock_get_info),
        ("get_interface_info", nsock_get_interface_info),
        ("setup", nsock_setup),
        ("pcap_open", nsock_pcap_open),
        ("pcap_close", nsock_pcap_close),
        ("pcap_register", nsock_pcap_register),
    ];

    for (name, func) in methods {
        lua.register_function(name, func)?;
    }

    Ok(())
}
```

---

## 5. Target Management Functions

### Target.cc

```cpp
// Get target socket address
const struct sockaddr_storage *Target::TargetSockAddr() const;

// Get target name string
const char *Target::TargetName() const;

// Get target name string (with mask)
const char *Target::NameStr() const;

// Set target IP
void Target::setTargetSockAddr(struct sockaddr_storage);

// Generate a random target
Target *Target::get_unused_host(const std::vector<Target *> &hosts);

// Copy target information
Target *Target::clone();
```

```rust
// RustNmap corresponding functions
impl Target {
    pub fn target_sock_addr(&self) -> &SocketAddr;

    pub fn target_name(&self) -> Option<&str>;

    pub fn name_str(&self) -> Cow<str>;

    pub fn set_target_sock_addr(&mut self, addr: SocketAddr);

    pub fn get_unused_host(all: &[Target]) -> Option<&Target>;
}

impl Clone for Target {
    fn clone(&self) -> Self {
        // Deep copy implementation
    }
}
```

### TargetGroup.cc

```cpp
// Get next target
Target *TargetGroup::GetNextHost();

// Get current batch
Target **TargetGroup::GetCurrentBatch();

// End current batch
bool TargetGroup::end_batch();

// Reset target group
void TargetGroup::reset();
```

```rust
// RustNmap corresponding functions
impl TargetGroup {
    pub fn next_host(&mut self) -> Option<&Target>;

    pub fn current_batch(&self) -> &[Target];

    pub fn end_batch(&mut self) -> Result<()>;

    pub fn reset(&mut self);
}
```

---

## 6. Output System Functions

### output.cc

```cpp
// Print port output
void printportoutput(const Target *currenths, const PortList *plist);

// Print MAC address information
void printmacinfo(const Target *currenths);

// Get log filename
char *logfilename(const char *str, struct tm *tm);

// Write log
void log_write(int logt, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

// Log user output
void log_user(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

// Log device output
void log_device(int logt, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

// Log standard output
void log_stdout(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
```

```rust
// RustNmap corresponding functions
pub fn print_port_output(target: &Target, port_list: &PortList);

pub fn print_mac_info(target: &Target);

pub fn log_filename(prefix: &str, tm: &Tm) -> PathBuf;

pub fn log_write(log_type: LogType, fmt: Arguments) -> Result<()>;

pub fn log_write_va(log_type: LogType, fmt: &str, args: VaList)
    -> Result<()>;

pub fn log_user(fmt: Arguments) -> Result<()>;

pub fn log_device(fmt: Arguments) -> Result<()>;

pub fn log_stdout(fmt: Arguments) -> Result<()>;
```

### NmapOutputTable.cc

```cpp
// Add a row
bool NmapOutputTable::addRow(const std::vector<std::string> &row);

// Add a row (variadic arguments)
bool NmapOutputTable::addRowVA(unsigned int ncols, ...);

// Clone table
NmapOutputTable *NmapOutputTable::clone();

// Free table data
void NmapOutputTable::free();

// Check if set
bool NmapOutputTable::isSet();

// Get table size
unsigned int NmapOutputTable::size();

// Get column count
unsigned int NmapOutputTable::numColumns();

// Get row count
unsigned int NmapOutputTable::numRows();

// Format output
void NmapOutputTable::printTable(int logt, bool append);
```

```rust
// RustNmap corresponding functions
impl NmapOutputTable {
    pub fn add_row(&mut self, row: Vec<Option<String>>) -> Result<()>;

    pub fn add_row_va(&mut self, ncols: usize, args: VaList)
        -> Result<()>;

    pub fn clone(&self) -> Self;

    pub fn free(&mut self);

    pub fn is_set(&self) -> bool;

    pub fn size(&self) -> usize;

    pub fn num_columns(&self) -> usize;

    pub fn num_rows(&self) -> usize;

    pub fn print_table(&self, log_type: LogType, append: bool);
}
```

### xml.cc

```cpp
// XML output functions
void xml_start_tag(const char *name, const char *attrname, ...);

void xml_end_tag(void);

void xml_write_escaped(const char *str);

void xml_newline(void);

void xml_attribute_full(const char *name, const char *value,
                         const char *attrname, ...);

int xml_isclosed();
```

```rust
// RustNmap corresponding functions
pub fn xml_start_tag(name: &str, attr_name: Option<&str>, attr_value: Option<&str>);

pub fn xml_end_tag();

pub fn xml_write_escaped(s: &str);

pub fn xml_newline();

pub fn xml_attribute(name: &str, value: &str);

pub fn xml_is_closed() -> bool;
```

---

## Function Call Flow Examples

### Scan Flow

```
main()
  └─> nmap()
       └─> ultra_scan()
              ├─> determineScanGroupSize()
              ├─> UltraScanInfo::new()
              ├─> sendPendingProbes()
              │     ├─> sendArpScanProbe()
              │     ├─> sendIPScanProbe()
              │     └─> sendConnectScanProbe()
              ├─> get_pcap_result()
              ├─> get_arp_result()
              └─> handle_response()
```

### NSE Script Execution Flow

```
script_scan()
  └─> ScriptSelector::select()
       └─> foreach script:
              ├─> ScriptEngine::execute()
              │     ├─> prepare_lua_environment()
              │     │     ├─> create_host_table()
              │     │     ├─> create_port_table()
              │     │     └─> set_registry()
              │     ├─> lua_pcall()
              │     └─> collect_results()
              └─> ScriptResults::insert()
```

### OS Detection Flow

```
os_scan()
  └─> FPEngine6::new()
       ├─> FPHost6::new()
       ├─> choose_osscan_ports()
       ├─> build_probe_list()
       ├─> FPNetworkControl::setup_sniffer()
       └─> loop:
              ├─> FPHost6::schedule()
              ├─> FPNetworkControl::handle_events()
              ├─> FPHost6::callback()
              └─> FPHost6::fill_results()
```
