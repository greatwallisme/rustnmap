# Nmap 核心函数参考

本文档列出 Nmap 源码中的关键函数，为 Rust 实现提供函数签名参考。

## 目录

1. [扫描引擎函数](#1-扫描引擎函数)
2. [端口管理函数](#2-端口管理函数)
3. [OS 检测函数](#3-os-检测函数)
4. [NSE 引擎函数](#4-nse-引擎函数)
5. [目标管理函数](#5-目标管理函数)
6. [输出系统函数](#6-输出系统函数)

---

## 1. 扫描引擎函数

### scan_engine.cc

```cpp
// 第三代扫描主函数
void ultra_scan(std::vector<Target *> &Targets,
              const struct scan_lists *ports,
              stype scantype,
              struct timeout_info *to = NULL);
```

```rust
// RustNmap 对应函数签名
pub async fn ultra_scan(
    targets: Vec<Target>,
    scan_lists: &ScanLists,
    scan_type: ScanType,
    timeout_info: Option<&TimeoutInfo>,
) -> Result<Vec<ScanResult>> {
    // 实现...
}
```

```cpp
// 确定扫描组大小
int determineScanGroupSize(int hosts_scanned_so_far,
                       const struct scan_lists *ports);
```

```rust
pub fn determine_scan_group_size(
    hosts_scanned_so_far: usize,
    scan_lists: &ScanLists,
) -> usize {
    // 实现...
}
```

### scan_engine_raw.cc

```cpp
// 发送 ARP 扫描探测
UltraProbe *sendArpScanProbe(UltraScanInfo *USI,
                              HostScanStats *hss,
                              tryno_t tryno);

// 发送 IPv6 邻居发现探测
UltraProbe *sendNDScanProbe(UltraScanInfo *USI,
                            HostScanStats *hss,
                            tryno_t tryno);

// 发送 IP 协议扫描探测
UltraProbe *sendIPScanProbe(UltraScanInfo *USI,
                          HostScanStats *hss,
                          const probespec *pspec,
                          tryno_t tryno);

// 获取 ARP 结果
bool get_arp_result(UltraScanInfo *USI, struct timeval *stime);

// 获取 ND 结果
bool get_ns_result(UltraScanInfo *USI, struct timeval *stime);

// 获取 pcap 结果
bool get_pcap_result(UltraScanInfo *USI, struct timeval *stime);
```

```rust
// RustNmap 对应函数
pub async fn send_arp_scan_probe(
    usi: &mut UltraScanInfo,
    hss: &mut HostScanStats,
    try_no: TryNo,
) -> Result<&mut UltraProbe> {
    // 实现...
}

pub async fn send_nd_scan_probe(
    usi: &mut UltraScanInfo,
    hss: &mut HostScanStats,
    try_no: TryNo,
) -> Result<&mut UltraProbe> {
    // 实现...
}

pub async fn send_ip_scan_probe(
    usi: &mut UltraScanInfo,
    hss: &mut HostScanStats,
    probe_spec: &ProbeSpec,
    try_no: TryNo,
) -> Result<&mut UltraProbe> {
    // 实现...
}

pub async fn get_arp_result(
    usi: &mut UltraScanInfo,
    stime: &TimeVal,
) -> Result<bool> {
    // 实现...
}

pub async fn get_pcap_result(
    usi: &mut UltraScanInfo,
    stime: &TimeVal,
) -> Result<bool> {
    // 实现...
}
```

### scan_engine_connect.cc

```cpp
// TCP Connect 扫描
int connect_scan(std::vector<Target *> &Targets,
                const struct scan_lists *ports,
                const struct timeout_info *to);
```

```rust
// RustNmap 对应函数
pub async fn connect_scan(
    targets: Vec<Target>,
    ports: &ScanLists,
    timeout: &TimeoutInfo,
) -> Result<Vec<ScanResult>> {
    // 实现...
}
```

---

## 2. 端口管理函数

### portlist.cc

```cpp
// 将常用端口移到列表开头
void random_port_cheat(u16 *ports, int portcount);

// 端口状态转字符串
const char *statenum2str(int state);

// 获取 Nmap 服务名称
void Port::getNmapServiceName(char *namebuf, int buflen) const;

// 释放服务信息
void Port::freeService(bool del_service);

// 释放脚本结果
void Port::freeScriptResults(void);
```

```rust
// RustNmap 对应函数
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
// 端口原因转字符串
const char *reason_str(reason_t reason_id, bool shortform);
```

```rust
// RustNmap 对应函数
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

## 3. OS 检测函数

### FPEngine.cc

```cpp
// IPv6 OS 扫描
int FPEngine6::os_scan(std::vector<Target *> &Targets);

// 加载指纹匹配
std::vector<FingerMatch> load_fp_matches();
```

```rust
// RustNmap 对应函数
impl FingerprintEngineV6 {
    pub async fn os_scan(&mut self, targets: Vec<Target>)
        -> Result<()>;

    pub fn load_finger_matches(db_path: &Path)
        -> Result<Vec<FingerMatch>> {
        // 实现...
    }
}

pub fn load_finger_matches(db_path: &Path)
    -> Result<Vec<FingerMatch>> {
    // 实现...
}
```

### FPModel.cc

```cpp
// 指纹匹配
std::vector<FingerMatch> FPModel::match(const FingerPrint &FP);
```

```rust
// RustNmap 对应函数
impl FingerprintModel {
    pub fn match_fingerprint(&self, fp: &Fingerprint)
        -> Vec<FingerMatch> {
        // 实现...
    }
}
```

---

## 4. NSE 引擎函数

### nse_main.cc

```cpp
// NSE 协程 yield
int nse_yield(lua_State *, lua_KContext, lua_KFunction);

// NSE 协程恢复
void nse_restore(lua_State *, int);

// NSE 析构函数
void nse_destructor(lua_State *, char);

// NSE 基础库初始化
void nse_base(lua_State *);

// 按名称选择脚本
void nse_selectedbyname(lua_State *);

// 获取目标
void nse_gettarget(lua_State *, int);

// 打开 NSE
void open_nse(void);

// 脚本扫描
void script_scan(std::vector<Target *> &targets, stype scantype);

// 关闭 NSE
void close_nse(void);
```

```rust
// RustNmap 对应函数
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
// 设置版本信息到 Lua 表
void set_version(lua_State *L, const struct serviceDeductions *sd);

// 设置端口信息到 Lua 表
void set_portinfo(lua_State *L, const Target *target, const Port *port);

// 推送二进制 IP 地址
static void push_bin_ip(lua_State *L, const struct sockaddr_storage *ss);

// 设置字符串或 nil
static void set_string_or_nil(lua_State *L, const char *fieldname,
                              const char *value);

// 推送 OS 分类表
static void push_osclass_table(lua_State *L,
                                const struct OS_Classification *osclass);

// 推送 OS 匹配表
static void push_osmatch_table(lua_State *L, const FingerMatch *match,
                               const OS_Classification_Results *OSR);
```

```rust
// RustNmap 对应函数
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
// Nsock 绑定函数
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
// RustNmap 对应库注册
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

## 5. 目标管理函数

### Target.cc

```cpp
// 获取目标套接字地址
const struct sockaddr_storage *Target::TargetSockAddr() const;

// 获取目标名称字符串
const char *Target::TargetName() const;

// 获取目标名称字符串 (含掩码)
const char *Target::NameStr() const;

// 设置目标 IP
void Target::setTargetSockAddr(struct sockaddr_storage);

// 生成一个随机目标
Target *Target::get_unused_host(const std::vector<Target *> &hosts);

// 复制目标信息
Target *Target::clone();
```

```rust
// RustNmap 对应函数
impl Target {
    pub fn target_sock_addr(&self) -> &SocketAddr;

    pub fn target_name(&self) -> Option<&str>;

    pub fn name_str(&self) -> Cow<str>;

    pub fn set_target_sock_addr(&mut self, addr: SocketAddr);

    pub fn get_unused_host(all: &[Target]) -> Option<&Target>;
}

impl Clone for Target {
    fn clone(&self) -> Self {
        // 深拷贝实现
    }
}
```

### TargetGroup.cc

```cpp
// 获取下一个目标
Target *TargetGroup::GetNextHost();

// 获取当前批
Target **TargetGroup::GetCurrentBatch();

// 结束当前批
bool TargetGroup::end_batch();

// 重置目标组
void TargetGroup::reset();
```

```rust
// RustNmap 对应函数
impl TargetGroup {
    pub fn next_host(&mut self) -> Option<&Target>;

    pub fn current_batch(&self) -> &[Target];

    pub fn end_batch(&mut self) -> Result<()>;

    pub fn reset(&mut self);
}
```

---

## 6. 输出系统函数

### output.cc

```cpp
// 打印端口输出
void printportoutput(const Target *currenths, const PortList *plist);

// 打印 MAC 地址信息
void printmacinfo(const Target *currenths);

// 获取日志文件名
char *logfilename(const char *str, struct tm *tm);

// 写入日志
void log_write(int logt, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

// 日志用户输出
void log_user(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

// 日志设备输出
void log_device(int logt, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

// 日志标准输出
void log_stdout(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
```

```rust
// RustNmap 对应函数
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
// 添加一行
bool NmapOutputTable::addRow(const std::vector<std::string> &row);

// 添加一行 (可变参数)
bool NmapOutputTable::addRowVA(unsigned int ncols, ...);

// 克隆表
NmapOutputTable *NmapOutputTable::clone();

// 释放表数据
void NmapOutputTable::free();

// 检查是否已设置
bool NmapOutputTable::isSet();

// 获取表大小
unsigned int NmapOutputTable::size();

// 获取列数
unsigned int NmapOutputTable::numColumns();

// 获取行数
unsigned int NmapOutputTable::numRows();

// 格式化输出
void NmapOutputTable::printTable(int logt, bool append);
```

```rust
// RustNmap 对应函数
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
// XML 输出函数
void xml_start_tag(const char *name, const char *attrname, ...);

void xml_end_tag(void);

void xml_write_escaped(const char *str);

void xml_newline(void);

void xml_attribute_full(const char *name, const char *value,
                         const char *attrname, ...);

int xml_isclosed();
```

```rust
// RustNmap 对应函数
pub fn xml_start_tag(name: &str, attr_name: Option<&str>, attr_value: Option<&str>);

pub fn xml_end_tag();

pub fn xml_write_escaped(s: &str);

pub fn xml_newline();

pub fn xml_attribute(name: &str, value: &str);

pub fn xml_is_closed() -> bool;
```

---

## 函数调用流程示例

### 扫描流程

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

### NSE 脚本执行流程

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

### OS 检测流程

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
