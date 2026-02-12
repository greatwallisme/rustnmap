# 4. 数据库与指纹文件设计

## 4.1 数据库文件清单

| 数据库文件               | 功能         | 对应 Nmap 文件            | 更新频率 |
| ------------------- | ---------- | --------------------- | ---- |
| `service-probes`    | 服务探测规则     | `nmap-service-probes` | 高    |
| `os-fingerprints`   | 操作系统指纹     | `nmap-os-db`          | 中    |
| `rpc-procedures`    | RPC 程序号映射  | `nmap-rpc`            | 低    |
| `nmap-mac-prefixes` | MAC 地址厂商前缀 | `nmap-mac-prefixes`   | 中    |
| `payloads`          | UDP/协议载荷   | `nmap-payloads`       | 低    |
| `script-db`         | NSE 脚本索引   | `script.db`           | 中    |

## 4.2 服务探测数据库格式

```
# ==========================
# RustNmap Service Probes Database
# Format: Compatible with Nmap nmap-service-probes
# ==========================

# 排除端口 (通常不探测)
ExcludePorts T:9100-9107,T:111,U:111

# ============ TCP Probes ============

# Null Probe (无数据发送，等待 banner)
Probe TCP NULL q||

# 等待时间
totalwaitms 6000

# 匹配规则
match 1c-server m|^1C:Enterprise\r?\n| p/1C:Enterprise server/
match 4d-server m|^</html><html>\r?\n<head><title>4D WebStar</title>| p/4D WebStar/

# GenericLines Probe (发送 \r\n\r\n)
Probe TCP GenericLines q|\r\n\r\n|
match acap m|^\* ACAP \(IMPLEMENTATION \"([^\)]+)\"\)| p/ACAP server/ i/$1/
match ajetp m|^D \d+\.\d+ AjetP ([\d.]+)\r?\n| p/AjetP print daemon/ v/$1/
match anonymous m|^ ANONYMOUS OK\r?\n| p/Rsync anonymous/

# HTTPOptions Probe
Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.0 200 OK\r\n.*Server: ([^\r\n]+)|s p/HTTP/ i/Server: $1/
softmatch http m|^HTTP/1\.[01] \d\d\d| cpe:/a:vendor:http/

# ============ UDP Probes ============

Probe UDP dnsstatusq q|\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00|
match dns m|^\x00\x00\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00| p/DNS/

# ============ Protocol Details ============
# Each probe has:
# - Probe directive: protocol, name, probe data
# - ports: default target ports
# - sslports: ports to try with SSL
# - totalwaitms: max wait time
# - tcpwrappedms: timeout for tcpwrapped detection
# - rarity: 1-9, probe usage frequency
# - fallback: fallback probe if no match

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
ports 80,8080,443
sslports 443
match http m|^HTTP/1\.1 (\d\d\d) | p/HTTP/ i/status $1/
rarity 1
fallback GenericLines

# 复杂匹配示例 (使用捕获组和 CPE)
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w.+-]+)(?:\s|$)| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/

# 软匹配 - 不确认服务但缩小范围
softmatch ssh m|^SSH-\d\.\d-| 

# Missed service (否定匹配)
match ftp m|^220 Welcome to Pure-FTPd| p/Pure-FTPd/ o/Linux/
match http m|^HTTP/1\.[01] \d\d\d .*\r\nServer: nginx/([\d.]+)|s p/nginx/ v/$1/ cpe:/a:nginx:nginx:$1/
```

## 4.3 OS 指纹数据库格式

```
# ==========================
# RustNmap OS Fingerprints Database
# Format: Compatible with Nmap nmap-os-db
# ==========================

# 指纹条目结构:
# Fingerprint <OS Name>
#   Class <Vendor> <OS Family> <Generation> <Device Type>
#   CPE <CPE String>
#   SEQ, OPS, WIN, ECN, T1-T7, U1, IE 字段

Fingerprint Linux 5.4-5.10
Class Linux | Linux | 5.X | general purpose
CPE cpe:/o:linux:linux_kernel:5

# SEQ (Sequence Analysis)
SEQ(GCD=1-6|ISA=0|IPR=64K|TS=1000-2FFF|SP=0-64|O1=0|O2=0|O3=0|O4=0|O5=0|O6=0)

# OPS (TCP Options)
OPS(O1=M5B4ST11NW7|O2=M5B4ST11NW7|O3=M5B4ST11NW7|O4=M5B4ST11NW7|O5=M5B4ST11NW7|O6=M5B4ST11)

# WIN (TCP Window)
WIN(W1=FFFF|W2=FFFF|W3=FFFF|W4=FFFF|W5=FFFF|W6=FFFF)

# ECN (Explicit Congestion Notification)
ECN(R=Y|DF=Y|T=40|TG=40|CC=N|Q=N)

# T1-T7 (TCP Tests)
T1(R=Y|DF=Y|T=40|S=O|A=S+|F=AS|RD=0|Q=)
T2(R=N)
T3(R=N)
T4(R=Y|DF=Y|T=40|W=FFFF|A=S|O=M5B4ST11NW7|RD=0|Q=)
T5(R=Y|DF=Y|T=40|S=O|A=S+|F=AS|O=M5B4ST11NW7|RD=0|Q=)
T6(R=Y|DF=Y|T=40|W=FFFF|A=S|O=M5B4ST11NW7|RD=0|Q=)
T7(R=N)

# U1 (UDP Test)
U1(R=Y|DF=N|T=40|TOS=0|IPL=164|UN=0|RIPL=G|RID=G|RIPCK=G|RUCK=G|RUL=G|RUD=G)

# IE (ICMP Echo)
IE(R=Y|DFI=N|T=40|TOSI=S|CD=S|SI=S|DL=S)

Fingerprint Microsoft Windows 10 or Server 2016+
Class Microsoft | Windows | 10 | general purpose
CPE cpe:/o:microsoft:windows_10
CPE cpe:/o:microsoft:windows_server_2016

SEQ(GCD=1-6|ISR=106-10A|IPR=64K|TS=100-200|SP=101-106|O1=0|O2=0|O3=0|O4=0|O5=0|O6=0)
OPS(O1=M534ST11NW6|O2=M534ST11|O3=M534ST11NW6|O4=M534ST11NW6|O5=M534ST11NW6|O6=M534ST11)
WIN(W1=2000|W2=2000|W3=2000|W4=2000|W5=2000|W6=2000)
ECN(R=N|DF=Y|T=80|TG=80|CC=N|Q=N)
T1(R=Y|DF=Y|T=80|S=O|A=S+|F=AS|RD=0|Q=)
T2(R=N)
T3(R=N)
T4(R=Y|DF=Y|T=80|W=2000|A=S|O=M534ST11NW6|RD=0|Q=)
T5(R=Y|DF=Y|T=80|S=O|A=S+|F=AS|O=M534ST11NW6|RD=0|Q=)
T6(R=Y|DF=Y|T=80|W=2000|A=S|O=M534ST11NW6|RD=0|Q=)
T7(R=N)
U1(R=Y|DF=N|T=80|TOS=0|IPL=128|UN=0|RIPL=G|RID=G|RIPCK=G|RUCK=G|RUL=G|RUD=G)
IE(R=Y|DFI=N|T=80|TOSI=S|CD=S|SI=S|DL=S)
```

## 4.4 数据库加载器设计

```
// ============================================
// Database Loader Types
// ============================================

use std::collections::HashMap;
use regex::Regex;

/// 数据库管理器
pub struct DatabaseManager {
    pub services: ServiceProbeDatabase,
    pub os: OsFingerprintDatabase,
    pub mac_prefixes: MacPrefixDatabase,
    pub rpc: RpcDatabase,
    pub payloads: PayloadDatabase,
}

/// 服务探测数据库
pub struct ServiceProbeDatabase {
    probes: Vec<ServiceProbe>,
    match_cache: HashMap<String, CompiledMatch>,
}

/// 服务探测定
pub struct ServiceProbe {
    pub name: String,
    pub protocol: Protocol,
    pub probe_data: Vec<u8>,
    pub ports: Vec<u16>,
    pub ssl_ports: Vec<u16>,
    pub total_wait_ms: u64,
    pub rarity: u8,
    pub matches: Vec<MatchRule>,
    pub soft_matches: Vec<MatchRule>,
    pub fallback: Option<String>,
}

/// 匹配规则
pub struct MatchRule {
    pub service: String,
    pub pattern: CompiledRegex,
    pub version_template: Option<String>,
    pub product_template: Option<String>,
    pub info_template: Option<String>,
    pub hostname_template: Option<String>,
    pub os_template: Option<String>,
    pub device_type_template: Option<String>,
    pub cpe_templates: Vec<String>,
    pub is_soft: bool,
}

/// 编译后的正则表达式 (优化性能)
pub struct CompiledRegex {
    regex: Regex,
    capture_count: usize,
}

/// OS 指纹数据库
pub struct OsFingerprintDatabase {
    fingerprints: Vec<OsFingerprint>,
}

pub struct OsFingerprint {
    pub name: String,
    pub classes: Vec<OsClass>,
    pub cpes: Vec<String>,
    pub tcp_seq: TcpSeqFingerprint,
    pub tcp_isn: TcpIsnFingerprint,
    pub ip_id: IpIdFingerprint,
    pub tcp_timestamp: TcpTimestampFingerprint,
    pub tcp_options: HashMap<String, TcpOptionsFingerprint>,
    pub tcp_window: HashMap<String, TcpWindowFingerprint>,
    pub ecn: EcnFingerprint,
    pub tcp_tests: HashMap<String, TcpTestFingerprint>,
    pub udp_test: UdpTestFingerprint,
    pub icmp_test: IcmpTestFingerprint,
}

/// 数据库加载器
impl DatabaseManager {
    pub fn load(data_dir: &Path) -> Result<Self, DatabaseError> {
        Ok(Self {
            services: ServiceProbeLoader::load(&data_dir.join("service-probes"))?,
            os: OsFingerprintLoader::load(&data_dir.join("os-fingerprints"))?,
            mac_prefixes: MacPrefixLoader::load(&data_dir.join("mac-prefixes"))?,
            rpc: RpcLoader::load(&data_dir.join("rpc-procedures"))?,
            payloads: PayloadLoader::load(&data_dir.join("payloads"))?,
        })
    }
    
    /// 更新数据库 (从网络下载)
    pub async fn update(&mut self) -> Result<(), DatabaseError> {
        // 从官方仓库下载最新数据库
        unimplemented!()
    }
}
```

---

