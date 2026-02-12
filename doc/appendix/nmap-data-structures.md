# Nmap 核心数据结构参考

本文档详细列出 Nmap 源码中的核心数据结构，为 Rust 实现提供精确映射参考。

## 目录

1. [扫描引擎结构](#1-扫描引擎结构)
2. [端口管理结构](#2-端口管理结构)
3. [OS 检测结构](#3-os-检测结构)
4. [NSE 引擎结构](#4-nse-引擎结构)
5. [目标管理结构](#5-目标管理结构)
6. [输出系统结构](#6-输出系统结构)

---

## 1. 扫描引擎结构

### UltraScanInfo (scan_engine.h)

```cpp
// Nmap C++ 定义
class UltraScanInfo {
private:
    // 扫描类型
    stype scantype;

    // 超时信息
    struct timeout_info *to;

    // 性能配置
    struct ultra_scan_performance_vars perf;

    // 完成主机列表
    std::list<HostScanStats *> completedHosts;
    std::list<HostScanStats *> activeHosts;
    std::list<HostScanStats *> incompleteHosts;

    // 探测管理
    std::vector<UltraProbe *> probes;
    std::vector<UltraProbe *> freshProbes;

    // 速率计量
    PacketRateMeter send_rate_meter;

    // 时间戳
    struct timeval now;

    // 扫描组大小
    int group_scan_goal;

    // 是否完成
    bool anyCompleted;
};
```

```rust
// RustNmap 对应结构
pub struct UltraScanInfo {
    // 扫描类型
    pub scan_type: ScanType,

    // 超时信息
    pub timeout: TimeoutInfo,

    // 性能配置
    pub perf: ScanPerformanceVars,

    // 主机统计
    pub completed_hosts: Vec<HostScanStats>,
    pub active_hosts: Vec<HostScanStats>,
    pub incomplete_hosts: Vec<HostScanStats>,

    // 待发送探测
    pub pending_probes: Vec<UltraProbe>,
    pub fresh_probes: Vec<UltraProbe>,

    // 速率计量器
    pub send_rate_meter: PacketRateMeter,

    // 当前时间
    pub now: TimeVal,

    // 目标组大小
    pub group_scan_goal: usize,

    // 是否有主机完成
    pub any_completed: bool,
}
```

### HostScanStats (scan_engine.h)

```cpp
// Nmap C++ 定义
class HostScanStats {
public:
    Target *target;

    // 已发送探测数
    int probes_sent;

    // 超时探测数
    int probes_timedout;

    // 不同端口状态计数
    int numopenports;
    int numclosedports;
    int numfilteredports;
    int numuntestableports;

    // 发送速率
    double sending_rate;
};
```

```rust
// RustNmap 对应结构
pub struct HostScanStats {
    // 目标主机
    pub target: Target,

    // 已发送探测数
    pub probes_sent: usize,

    // 超时探测数
    pub probes_timedout: usize,

    // 端口状态计数
    pub num_open_ports: usize,
    pub num_closed_ports: usize,
    pub num_filtered_ports: usize,
    pub num_untestable_ports: usize,

    // 发送速率 (探测/秒)
    pub sending_rate: f64,
}
```

### UltraProbe (scan_engine.h)

```cpp
// Nmap C++ 定义
class UltraProbe {
public:
    // 探测类型
    enum ProbeType {
        UP_UNSET,
        UP_IP,
        UP_ARP,
        UP_CONNECT,
        UP_ND,
    } type;

    // 重试号
    tryno_t tryno;

    union {
        struct probespec pspec;  // IP/ARP/ND 探测
        ConnectProbe *CP;        // Connect 扫描
    } mypspec;

    // 发送时间
    struct timeval sent;
    struct timeval prevSent;

    // 状态标志
    bool timedout;
    bool retransmitted;
};
```

```rust
// RustNmap 对应结构
pub struct UltraProbe {
    // 探测类型
    pub probe_type: ProbeType,

    // 重试信息
    pub try_no: TryNo,

    // 探测规格
    pub spec: ProbeSpec,

    // 发送时间
    pub sent: Option<TimeVal>,
    pub prev_sent: Option<TimeVal>,

    // 状态标志
    pub timed_out: bool,
    pub retransmitted: bool,
}

// TryNo 结构 (对应 tryno_t)
#[repr(C)]
pub union TryNo {
    raw: u8,
    fields: TryNoFields,
}

#[repr(C)]
pub struct TryNoFields {
    pub is_ping: u8,   // bit 0: 是否为 ping
    pub seq_num: u8,  // bit 1-7: 序列号 (0-127)
}
```

---

## 2. 端口管理结构

### Port (portlist.h)

```cpp
// Nmap C++ 定义
class Port {
private:
    // 端口号
    u16 portno;

    // 协议
    u8 proto;

    // 端口状态
    u8 state;

    // 推理结果
    struct serviceDeductions service;

    // 状态原因
    struct port_reason reason;

    // 脚本结果
    ScriptResults scriptResults;
};
```

```rust
// RustNmap 对应结构
pub struct Port {
    // 端口号
    pub port_no: u16,

    // 协议 (TCP/UDP/SCTP)
    pub protocol: Protocol,

    // 端口状态
    pub state: PortState,

    // 服务推论
    pub service: Option<ServiceDeductions>,

    // 状态原因
    pub reason: PortReason,

    // 脚本执行结果
    pub script_results: Vec<ScriptResult>,
}
```

### serviceDeductions (portlist.h)

```cpp
// Nmap C++ 定义
struct serviceDeductions {
    const char *name;              // 服务名称
    int name_confidence;          // 名称置信度 (0-10)
    char *product;               // 产品名
    char *version;               // 版本号
    char *extrainfo;            // 额外信息
    char *hostname;              // 主机名
    char *ostype;                // 操作系统类型
    char *devicetype;           // 设备类型
    std::vector<char *> cpe;   // CPE 标识符
    enum service_tunnel_type service_tunnel;  // SSL 隧道
    const char *service_fp;       // 服务指纹 (用于提交)
    enum service_detection_type dtype;      // 检测类型
};
```

```rust
// RustNmap 对应结构
pub struct ServiceDeductions {
    // 服务名称
    pub name: Option<String>,

    // 置信度 (0-10)
    pub name_confidence: u8,

    // 产品信息
    pub product: Option<String>,

    // 版本信息
    pub version: Option<String>,

    // 额外信息
    pub extrainfo: Option<String>,

    // 主机名
    pub hostname: Option<String>,

    // OS 类型
    pub ostype: Option<String>,

    // 设备类型
    pub devicetype: Option<String>,

    // CPE 标识符
    pub cpe: Vec<String>,

    // SSL 隧道
    pub service_tunnel: ServiceTunnelType,

    // 服务指纹
    pub service_fp: Option<String>,

    // 检测类型
    pub dtype: ServiceDetectionType,
}

pub enum ServiceTunnelType {
    None,
    Ssl,
}

pub enum ServiceDetectionType {
    Table,    // 基于端口表
    Probed,    // 主动探测
}
```

### port_reason (portreasons.h)

```cpp
// Nmap C++ 定义
struct port_reason {
    reason_id_t reason_id;   // 原因 ID
    u8 ttl;                    // IP TTL 值
    u32 ip_addr;               // 相关 IP 地址
    int state;                  // 相关状态
    const char *hostname;     // 相关主机名
};
```

```rust
// RustNmap 对应结构
pub struct PortReason {
    // 原因 ID
    pub reason_id: ReasonId,

    // IP TTL 值
    pub ttl: u8,

    // 相关 IP 地址
    pub ip_addr: IpAddr,

    // 相关状态
    pub state: Option<PortState>,

    // 相关主机名
    pub hostname: Option<String>,
}

pub enum ReasonId {
    // ICMP 不可达原因
    IcmpUnreachable,
    IcmpNetUnreachable,
    IcmpHostUnreachable,
    IcmpProtoUnreachable,
    IcmpPortUnreachable,
    IcmpAdminProhibited,

    // TCP 响应原因
    SynAck,
    Rst,
    SynRstAck,

    // 其他
    TcpWrapper,
    LocalPacket,
    // ...
}
```

---

## 3. OS 检测结构

### FPHost (FPEngine.h)

```cpp
// Nmap C++ 定义
class FPHost {
protected:
    unsigned int total_probes;      // 总探测数
    unsigned int timed_probes;      // 定时探测数
    unsigned int probes_sent;       // 已发送探测数
    unsigned int probes_answered;   // 收到响应数
    unsigned int probes_unanswered; // 未响应探测数
    bool incomplete_fp;             // 是否完整
    bool detection_done;            // 是否完成检测
    bool timedprobes_sent;          // 定时探测是否已发送

    Target *target_host;            // 目标主机
    FPNetworkControl *netctl;       // 网络控制器
    bool netctl_registered;         // 是否已注册

    u32 tcpSeqBase;                 // TCP 序列号基数
    int open_port_tcp;              // 开放 TCP 端口
    int closed_port_tcp;            // 关闭 TCP 端口
    int closed_port_udp;            // 关闭 UDP 端口
    int tcp_port_base;              // TCP 基端口
    int udp_port_base;              // UDP 基端口
    u16 icmp_seq_counter;           // ICMP 序列计数器
    int rto;                        // 重传超时
    int rttvar;                     // RTT 方差
    int srtt;                       // 平滑 RTT
};
```

```rust
// RustNmap 对应结构
pub struct FpHost {
    // 总探测数
    pub total_probes: u32,

    // 定时探测数
    pub timed_probes: u32,

    // 已发送探测数
    pub probes_sent: u32,

    // 收到响应数
    pub probes_answered: u32,

    // 未响应探测数
    pub probes_unanswered: u32,

    // 是否完成
    pub incomplete_fp: bool,

    // 检测是否完成
    pub detection_done: bool,

    // 定时探测是否已发送
    pub timed_probes_sent: bool,

    // 目标主机
    pub target_host: Target,

    // 网络控制器
    pub netctl: Option<FpNetworkControl>,

    // 是否已在网络控制器注册
    pub netctl_registered: bool,

    // TCP 序列号基数
    pub tcp_seq_base: u32,

    // 开放 TCP 端口
    pub open_port_tcp: i32,

    // 关闭 TCP 端口
    pub closed_port_tcp: i32,

    // 关闭 UDP 端口
    pub closed_port_udp: i32,

    // TCP 基端口
    pub tcp_port_base: i32,

    // UDP 基端口
    pub udp_port_base: i32,

    // ICMP 序列计数器
    pub icmp_seq_counter: u16,

    // 重传超时
    pub rto: i32,

    // RTT 方差
    pub rttvar: i32,

    // 平滑 RTT
    pub srtt: i32,
}
```

### FPProbe (FPEngine.h)

```cpp
// Nmap C++ 定义
class FPProbe : public FPPacket {
private:
    const char *probe_id;      // 探测 ID
    int probe_no;                // 探测编号
    int retransmissions;          // 重传次数
    int times_replied;           // 响应次数
    bool failed;                // 是否失败
    bool timed;                 // 是否为定时装

    FPHost *host;              // 关联主机
};
```

```rust
// RustNmap 对应结构
pub struct FpProbe {
    // 探测 ID (如 "SEQ", "T1", "IE1", etc.)
    pub probe_id: Cow<'static, str>,

    // 探测编号
    pub probe_no: i32,

    // 重传次数
    pub retransmissions: i32,

    // 收到响应次数
    pub times_replied: i32,

    // 是否失败
    pub failed: bool,

    // 是否为定时装
    pub timed: bool,

    // 关联的主机
    pub host: *mut FpHost,

    // 包数据 (继承自 FPPacket)
    pub packet: PacketData,

    // 发送时间
    pub sent_time: TimeVal,
}
```

### FPNetworkControl (FPEngine.h)

```cpp
// Nmap C++ 定义
class FPNetworkControl {
private:
    nsock_pool nsp;            // Nsock 连接池
    nsock_iod pcap_nsi;        // Pcap 描述符
    nsock_event_id pcap_ev_id; // 上次 pcap 事件 ID
    bool first_pcap_scheduled;  // 是否已调度第一个 pcap
    bool nsock_init;           // Nsock 是否已初始化
    int rawsd;                 // 原始套接字
    std::vector<FPHost *> callers;  // 调用者列表

    int probes_sent;           // 已发送探测数
    int responses_recv;        // 收到响应数
    int probes_timedout;       // 超时探测数
    float cc_cwnd;             // 拥塞窗口
    float cc_ssthresh;         // 慢启动阈值
};
```

```rust
// RustNmap 对应结构
pub struct FpNetworkControl {
    // Nsock 连接池
    pub nsock_pool: NsockPool,

    // Pcap 描述符
    pub pcap_nsi: NsockIod,

    // 上次调度的 pcap 事件 ID
    pub pcap_ev_id: NsockEventId,

    // 是否已调度第一个 pcap
    pub first_pcap_scheduled: bool,

    // Nsock 是否已初始化
    pub nsock_init: bool,

    // 原始套接字
    pub raw_sd: i32,

    // 调用者列表 (FPHost 列表)
    pub callers: Vec<*mut FpHost>,

    // 已发送探测数
    pub probes_sent: i32,

    // 收到响应数
    pub responses_recv: i32,

    // 超时探测数
    pub probes_timedout: i32,

    // 拥塞窗口
    pub cc_cwnd: f32,

    // 慢启动阈值
    pub cc_ssthresh: f32,
}
```

---

## 4. NSE 引擎结构

### ScriptResult (nse_main.h)

```cpp
// Nmap C++ 定义
class ScriptResult {
private:
    const char *id;              // 脚本 ID
    int output_ref;              // 输出表引用 (LUA_REGISTRYINDEX)

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
// RustNmap 对应结构
pub struct ScriptResult {
    // 脚本标识符 (文件名不含 .nse)
    pub id: Cow<'static, str>,

    // 输出表引用 (在 LUA_REGISTRYINDEX 中)
    pub output_ref: i32,

    // 原始输出字符串
    pub output_str: String,
}

impl ScriptResult {
    // 对应 get_output_str()
    pub fn get_output_string(&self) -> Cow<'static, str> {
        if self.output_ref != LUA_NOREF {
            // 从注册表获取输出
            get_registry_output(self.output_ref)
        } else {
            Cow::Borrowed(&self.output_str)
        }
    }

    // 对应 write_xml()
    pub fn write_xml(&self) {
        // 将脚本结果输出为 XML
        xml::start_element("script");
        xml::attribute("id", self.id);
        xml::attribute("output", self.get_output_string());
        xml::end_element();
    }

    // 对应 operator<
    impl Ord for ScriptResult {
        fn cmp(&self, other: &Self) -> Ordering {
            strcmp(self.id, other.id) < 0
        }
    }
}
```

### ScriptResults (nse_main.h)

```cpp
// Nmap C++ 定义
typedef std::multiset<ScriptResult *> ScriptResults;

// 获取结果对象
ScriptResults *get_script_scan_results_obj(void);
```

```rust
// RustNmap 对应结构
pub struct ScriptResults {
    // 使用 BTreeSet 保持排序 (std::multiset 的等价物)
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

## 5. 目标管理结构

### Target (Target.h)

```cpp
// Nmap C++ 核心字段
class Target {
private:
    // 地址信息
    struct sockaddr_storage targetsock;
    struct sockaddr_storage sourcesock;
    char *hostname;
    char *targetname;  // 用户指定的名称

    // MAC 地址
    u8 MACaddress[6];
    bool MACaddress_set;

    // 状态标志
    bool af;                      // 地址族
    bool up;                       // 是否在线
    bool wping;                    // 是否需要 ping
    bool osscan_done;              // OS 扫描完成

    // 端口列表
    PortList ports;

    // OS 指纹结果
    FingerPrintResults OSs;

    // 时间戳
    struct timeval systime;
    struct timeval probe_timeout;
};
```

```rust
// RustNmap 对应结构
pub struct Target {
    // 地址信息
    pub target_sock: SocketAddr,
    pub source_sock: Option<SocketAddr>,

    // 主机名
    pub hostname: Option<String>,

    // 用户指定的目标名称
    pub target_name: Option<String>,

    // MAC 地址
    pub mac_address: Option<[u8; 6]>,
    pub mac_address_set: bool,

    // 地址族
    pub address_family: AddressFamily,

    // 状态标志
    pub is_up: bool,
    pub wants_ping: bool,
    pub os_scan_done: bool,

    // 端口列表
    pub ports: PortList,

    // OS 指纹结果
    pub os_results: Option<FingerprintResults>,

    // 系统时间
    pub sys_time: Option<TimeVal>,

    // 探测超时
    pub probe_timeout: Duration,
}
```

### TargetGroup (TargetGroup.h)

```cpp
// Nmap C++ 定义
class TargetGroup {
private:
    // 目标表达式
    std::vector<std::string> expressions;

    // 当前批处理
    std::vector<Target *> current_batch;

    // 批大小
    int max_batch_size;

    // 索引
    int current_expr_idx;
    int current_target_idx;
};
```

```rust
// RustNmap 对应结构
pub struct TargetGroup {
    // 目标表达式 (如 "192.168.1.0/24", "example.com")
    pub expressions: Vec<String>,

    // 当前批处理
    pub current_batch: Vec<Target>,

    // 批大小
    pub max_batch_size: usize,

    // 索引
    pub current_expr_idx: usize,
    pub current_target_idx: usize,
}

impl TargetGroup {
    // 获取下一批目标
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

## 6. 输出系统结构

### NmapOutputTable (NmapOutputTable.h)

```cpp
// Nmap C++ 定义
class NmapOutputTable {
private:
    unsigned int ncolumns;       // 列数
    unsigned int nrows;          // 行数
    unsigned int maxncolumns;    // 最大列数
    unsigned int maxnrows;       // 最大行数

    bool **table;               // 表数据
    unsigned short *tableitemvalid;  // 项有效性
    bool items_dont_print;      // 是否打印项

public:
    unsigned int size();         // 获取表大小
    bool isSet();             // 检查是否设置
};
```

```rust
// RustNmap 对应结构
pub struct NmapOutputTable {
    // 列数
    pub num_columns: usize,

    // 行数
    pub num_rows: usize,

    // 最大列数
    pub max_num_columns: usize,

    // 最大行数
    pub max_num_rows: usize,

    // 表数据 (二维数组)
    pub table: Vec<Vec<Option<String>>>,

    // 项有效性
    pub item_valid: Vec<Vec<bool>>,

    // 是否打印项
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

    // 添加一行
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

## 常量映射表

| Nmap 常量 | 值 | Rust 常量名 |
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
