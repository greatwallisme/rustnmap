# Nmap 常量参考

本文档列出 Nmap 源码中的核心常量定义，为 Rust 实现提供精确参考。

## 目录

1. [扫描引擎常量](#1-扫描引擎常量)
2. [端口状态常量](#2-端口状态常量)
3. [OS 检测常量](#3-os-检测常量)
4. [NSE 引擎常量](#4-nse-引擎常量)
5. [输出常量](#5-输出常量)
6. [时间常量](#6-时间常量)
7. [协议常量](#7-协议常量)

---

## 1. 扫描引擎常量

### scan_engine.cc

```cpp
// 速率限制检测额外等待时间
#define RLD_TIME_MS 1000

// 保留已完成主机的时长 (TCP MSL - 2 分钟)
#define COMPL_HOST_LIFETIME_MS 120000
```

```rust
// RustNmap 对应常量
pub const RLD_TIME_MS: u64 = 1000;
pub const COMPL_HOST_LIFETIME_MS: u64 = 120_000; // 2 分钟
```

### probespec.h

```cpp
// TCP AND UDP AND SCTP 协议最大值 (用于特殊协议选择)
#define TCPANDUDPANDSCTP IPPROTO_MAX

// UDP AND SCTP
#define UDPANDSCTP (IPPROTO_MAX + 1)
```

```rust
// RustNmap 对应常量
pub const TCP_AND_UDP_AND_SCTP: u8 = IPPROTO_MAX;
pub const UDP_AND_SCTP: u8 = IPPROTO_MAX + 1;
```

### timing.h

```cpp
// 默认当前速率历史 (秒)
#define DEFAULT_CURRENT_RATE_HISTORY 5.0
```

```rust
// RustNmap 对应常量
pub const DEFAULT_CURRENT_RATE_HISTORY: f64 = 5.0;
```

---

## 2. 端口状态常量

### portlist.h

```cpp
// 端口状态常量
#define PORT_UNKNOWN 0
#define PORT_CLOSED 1
#define PORT_OPEN 2
#define PORT_FILTERED 3
#define PORT_TESTING 4
#define PORT_FRESH 5
#define PORT_UNFILTERED 6
#define PORT_OPENFILTERED 7
#define PORT_CLOSEDFILTERED 8
#define PORT_HIGHEST_STATE 9  // ***重要 - 添加状态时需要增加此值***
```

```rust
// RustNmap 对应常量
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
// 默认服务等待时间 (毫秒)
#define DEFAULT_SERVICEWAITMS 5000

// 默认 TCP 包装超时 (毫秒)
#define DEFAULT_TCPWRAPPEDMS 2000

// 默认连接超时 (毫秒)
#define DEFAULT_CONNECT_TIMEOUT 5000

// 默认 SSL 连接超时 (毫秒)
#define DEFAULT_CONNECT_SSL_TIMEOUT 8000

// 服务探测文件中允许的最大回退数
#define MAXFALLBACKS 20
```

```rust
// RustNmap 对应常量
pub const DEFAULT_SERVICE_WAIT_MS: u64 = 5000;
pub const DEFAULT_TCP_WRAPPED_MS: u64 = 2000;
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 5000;
pub const DEFAULT_CONNECT_SSL_TIMEOUT: u64 = 8000;
pub const MAX_FALLBACKS: usize = 20;
```

### service_scan.h (ServiceProbeState)

```cpp
// 服务探测状态枚举
enum serviceprobestate {
  PROBESTATE_INITIAL=1,      // 尚未开始探测
  PROBESTATE_NULLPROBE,       // 正在进行 NULL 探测
  PROBESTATE_MATCHINGPROBES,  // 正在进行匹配探测
  PROBESTATE_FINISHED_HARDMATCHED,  // 完成 - 确匹配
  PROBESTATE_FINISHED_SOFTMATCHED, // 完成 - 软匹配
  PROBESTATE_FINISHED_NOMATCH,   // 完成 - 无匹配
  PROBESTATE_FINISHED_TCPWRAPPED, // 完成 - TCP 包装
  PROBESTATE_EXCLUDED,          // 端口被排除
  PROBESTATE_INCOMPLETE          // 未能完成 (错误/超时)
};
```

```rust
// RustNmap 对应常量
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

## 3. OS 检测常量

### FPEngine.h

```cpp
// IPv6 OS 检测探测数量
#define NUM_FP_PROBES_IPv6_TCP    13
#define NUM_FP_PROBES_IPv6_ICMPv6 4
#define NUM_FP_PROBES_IPv6_UDP    1

// IPv6 OS 检测总探测数
#define NUM_FP_PROBES_IPv6 (NUM_FP_PROBES_IPv6_TCP + \
                              NUM_FP_PROBES_IPv6_ICMPv6 + \
                              NUM_FP_PROBES_IPv6_UDP)

// 定时探测数 (需要特定时序发送的探测数)
#define NUM_FP_TIMEDPROBES_IPv6 6

// OS 扫描初始拥塞窗口
#define OSSCAN_INITIAL_CWND (NUM_FP_TIMEDPROBES_IPv6)

// OS 扫描初始慢启动阈值
#define OSSCAN_INITIAL_SSTHRESH (4 * OSSCAN_INITIAL_CWND)

// OS 扫描主机组大小
#define OSSCAN_GROUP_SIZE 10

// OS 扫描初始重传超时 (3 秒，单位微秒)
#define OSSCAN_INITIAL_RTO (3*1000000)

// 新度阈值 (匹配分数差异阈值)
#define FP_NOVELTY_THRESHOLD 15.0

// IPv6 OS 检测流标签
#define OSDETECT_FLOW_LABEL 0x12345
```

```rust
// RustNmap 对应常量
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
pub const OSSCAN_INITIAL_RTO: u64 = 3_000_000; // 3 秒 (微秒)
pub const FP_NOVELTY_THRESHOLD: f64 = 15.0;
pub const OS_DETECT_FLOW_LABEL: u32 = 0x12345;
```

---

## 4. NSE 引擎常量

### nse_main.h

```cpp
// 脚本引擎名称
#define SCRIPT_ENGINE "NSE"

#ifdef WIN32
#  define SCRIPT_ENGINE_LUA_DIR "scripts\\"
#  define SCRIPT_ENGINE_LIB_DIR "nselib\\"
#else
#  define SCRIPT_ENGINE_LUA_DIR "scripts/"
#  define SCRIPT_ENGINE_LIB_DIR "nselib/"
#endif

// 脚本数据库路径
#define SCRIPT_ENGINE_DATABASE SCRIPT_ENGINE_LUA_DIR "script.db"

// 脚本文件扩展名
#define SCRIPT_ENGINE_EXTENSION ".nse"
```

```rust
// RustNmap 对应常量
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
// version 表中的字段数量
#define NSE_NUM_VERSION_FIELDS 12

// NSE 协议选项
static const char *NSE_PROTOCOL_OP[] = {"tcp", "udp", "sctp"};
static const int NSE_PROTOCOL[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP};
```

```rust
// RustNmap 对应常量
pub const NSE_NUM_VERSION_FIELDS: usize = 12;

pub const NSE_PROTOCOL_OP: [&str] = &["tcp", "udp", "sctp"];
pub const NSE_PROTOCOL: [i32] = &[IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP];
```

### nse_lua.h

```cpp
// Lua 注册表索引
#define LUA_REGISTRYINDEX -10000

// Lua 无效引用
#define LUA_NOREF -10001

// Lua 状态码
#define LUA_OK 0
#define LUA_YIELD 1
#define LUA_ERRRUN 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5
#define LUA_ERRFILE 6
```

```rust
// RustNmap 对应常量
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

## 5. 输出常量

### output.h

```cpp
// 日志文件数量 (必须是开头的值)
#define LOG_NUM_FILES 4

// 日志文件掩码 (用于文件数组的掩码)
#define LOG_FILE_MASK 15

// 日志类型
#define LOG_NORMAL 1
#define LOG_MACHINE 2
#define LOG_SKID 4
#define LOG_XML 8
#define LOG_STDOUT 1024
#define LOG_STDERR 2048
#define LOG_SKID_NOXLT 4096

// 日志最大值
#define LOG_MAX LOG_SKID_NOXLT

// 普通日志掩码
#define LOG_PLAIN (LOG_NORMAL | LOG_SKID | LOG_STDOUT)

// 日志名称数组
#define LOG_NAMES {"normal", "machine", "$Cr!pT |<!dd!3", "XML"}
```

```rust
// RustNmap 对应常量
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

## 6. 时间常量

### timing.h

```cpp
// 初始重传超时 (3 秒，单位微秒)
// 基于 RFC 2988
#define INITIAL_RTT_TIMEOUT 3000000

// 最小重传超时 (100 毫秒)
#define MIN_RTT_TIMEOUT 100000

// 最大重传超时 (60 秒)
#define MAX_RTT_TIMEOUT 60000000

// RTT 初始值 (未校准)
#define RTT_INITIAL_TIMEOUT 6000000

// RTT 变化 (限制快速变化)
#define RTT_VAR_MAX 3000000000

// 最大超时倍数
#define MAX_TIMEOUT_MULT 10
```

```rust
// RustNmap 对应常量
pub const INITIAL_RTT_TIMEOUT: u64 = 3_000_000; // 3 秒 (微秒)
pub const MIN_RTT_TIMEOUT: u64 = 100_000;     // 100 毫秒
pub const MAX_RTT_TIMEOUT: u64 = 60_000_000;   // 60 秒 (微秒)
pub const RTT_INITIAL_TIMEOUT: u64 = 6_000_000;  // 6 秒 (微秒)
pub const RTT_VAR_MAX: u64 = 3_000_000_000;   // 限制快速变化
pub const MAX_TIMEOUT_MULT: u32 = 10;
```

---

## 7. 协议常量

### protocols.h / nbase.h

```cpp
// 常用 IP 协议
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_SCTP 132
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58
#define IPPROTO_IP 0

// 以太网类型
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

// TCP 标志位
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
// RustNmap 对应常量
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

## 常量使用示例

### 端口状态判断

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

### 日志类型组合

```rust
use output::LogType;

// 创建普通日志掩码
fn normal_log_mask() -> u32 {
    LogType::Normal as u32
}

// 创建完整日志掩码 (普通 + 脚本 kiddie + XML)
fn full_log_mask() -> u32 {
    LogType::Normal as u32 |
    LogType::Skid as u32 |
    LogType::Xml as u32
}

// 仅输出到终端 (不写入文件)
fn stdout_only() -> u32 {
    LogType::Stdout as u32
}

// 所有输出类型
fn all_outputs() -> u32 {
    LogType::Normal as u32 |
    LogType::Machine as u32 |
    LogType::Skid as u32 |
    LogType::Xml as u32 |
    LogType::Stdout as u32 |
    LogType::Stderr as u32
}
```

### 超时计算

```rust
use timing::*;

// 计算默认超时
fn default_timeout() -> Duration {
    Duration::from_micros(INITIAL_RTT_TIMEOUT)
}

// 计算最小超时
fn min_timeout() -> Duration {
    Duration::from_micros(MIN_RTT_TIMEOUT)
}

// 计算最大超时
fn max_timeout() -> Duration {
    Duration::from_micros(MAX_RTT_TIMEOUT)
}

// 计算自适应超时 (基于 RTT)
fn adaptive_timeout(srtt: i32, rttvar: i32) -> Duration {
    let timeout = srtt + 4 * rttvar;
    let timeout = timeout.clamp(MIN_RTT_TIMEOUT as i32,
                             MAX_RTT_TIMEOUT as i32);
    Duration::from_micros(timeout as u64)
}
```

### NSE 相关

```rust
use nse::*;

// 获取脚本目录
fn script_dir() -> &'static str {
    SCRIPT_ENGINE_LUA_DIR
}

// 获取脚本数据库路径
fn script_db_path() -> String {
    format!("{}{}", SCRIPT_ENGINE_LUA_DIR, SCRIPT_ENGINE_DATABASE)
}

// 获取脚本文件扩展名
fn script_extension() -> &'static str {
    SCRIPT_ENGINE_EXTENSION
}

// 获取 Lua 注册表索引
fn lua_registry_index() -> i32 {
    LUA_REGISTRY_INDEX
}

// Lua 无效引用常量
fn lua_noref() -> i32 {
    LUA_NOREF
}
```
