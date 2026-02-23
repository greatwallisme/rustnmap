## 3.8 输出模块设计

对应 Nmap 命令: `-oN`, `-oX`, `-oG`, `-oA`, `-v`, `-d`

### 3.8.1 输出格式架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Output Module Architecture                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    Output Format Layer                             │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   Normal   │ │    XML     │ │   JSON     │ │   Grepable     │ │  │
│  │  │   Format   │ │   Format   │ │   Format   │ │    Format      │ │  │
│  │  │  (.nmap)   │ │   (.xml)   │ │  (.json)   │ │    (.gnmap)    │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐                    │  │
│  │  │   HTML     │ │   CSV      │ │  Markdown  │                    │  │
│  │  │   Report   │ │   Export   │ │   Report   │                    │  │
│  │  └────────────┘ └────────────┘ └────────────┘                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Output Core                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  OutputManager                                              │  │  │
│  │  │  ├── formatters: Vec<Box<dyn OutputFormatter>>              │  │  │
│  │  │  ├── verbosity: VerbosityLevel                              │  │  │
│  │  │  ├── debug_level: u8                                        │  │  │
│  │  │  └── statistics: ScanStatistics                             │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                    │  │
│  │  trait OutputFormatter {                                          │  │
│  │      fn format_scan_result(&self, result: &ScanResult) -> String; │  │
│  │      fn format_host(&self, host: &HostResult) -> String;          │  │
│  │      fn format_port(&self, port: &PortResult) -> String;          │  │
│  │      fn format_script(&self, script: &ScriptResult) -> String;    │  │
│  │      fn file_extension(&self) -> &str;                           │  │
│  │  }                                                                │  │
│  │                                                                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.8.2 输出格式详细设计

```
# RustNmap 1.0.0 scan initiated Wed Feb 11 01:56:58 2026 as:
# rustnmap -sS -sV -O -p- 192.168.1.1

RustNmap scan report for 192.168.1.1
Host is up (0.0023s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Router Manufacturer)
Not shown: 65532 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp   open  http        nginx 1.18.0
443/tcp  open  ssl/http    nginx 1.18.0
| ssl-cert: Subject: commonName=example.com
| Issuer: commonName=Let's Encrypt Authority X3
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
|_Not valid before: 2025-01-01T00:00:00
| http-headers: 
|   Server: nginx/1.18.0
|   Date: Wed, 11 Feb 2026 01:56:58 GMT
|_  Content-Type: text/html

OS CPE: cpe:/o:linux:linux_kernel
OS details: Linux 5.4 - 5.10 (99% confidence)
Network Distance: 1 hop

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   2.3 ms  192.168.1.1

Service detection performed. Please report any incorrect results.
RustNmap done: 1 IP address (1 host up) scanned in 45.23 seconds
```

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="rustnmap" args="rustnmap -sS -sV -O 192.168.1.1" start="1739241418" startstr="Wed Feb 11 01:56:58 2026" version="1.0.0" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
  <verbose level="1"/>
  <debugging level="0"/>
  <taskbegin task="ARP Ping Scan" time="1739241418"/>
  <taskend task="ARP Ping Scan" time="1739241418" extrainfo="1 total hosts"/>
  <taskbegin task="SYN Stealth Scan" time="1739241418"/>
  <taskend task="SYN Stealth Scan" time="1739241445" extrainfo="65535 total ports"/>
  <host starttime="1739241418" endtime="1739241445">
    <status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Router Manufacturer"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="65532">
        <extrareasons reason="conn-refused" count="65532"/>
      </extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.1" ostype="Linux" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx" version="1.18.0" method="probed" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx" version="1.18.0" tunnel="ssl" method="probed" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
        <script id="ssl-cert" output="Subject: commonName=example.com...">
          <table key="cert">
            <elem key="subject">CN=example.com</elem>
            <elem key="issuer">CN=Let's Encrypt Authority X3</elem>
            <elem key="pubkeybits">2048</elem>
            <elem key="pubkeytype">rsa</elem>
          </table>
        </script>
        <script id="http-headers" output="Server: nginx/1.18.0...">
          <table>
            <elem key="Server">nginx/1.18.0</elem>
            <elem key="Date">Wed, 11 Feb 2026 01:56:58 GMT</elem>
            <elem key="Content-Type">text/html</elem>
          </table>
        </script>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4 - 5.10" accuracy="99">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="99">
          <cpe>cpe:/o:linux:linux_kernel:5</cpe>
        </osclass>
      </osmatch>
    </os>
    <trace port="443" proto="tcp">
      <hop ttl="1" rtt="2.3" ipaddr="192.168.1.1"/>
    </trace>
    <times srtt="2300" rttvar="500" to="100000"/>
  </host>
  <runstats>
    <finished time="1739241445" timestr="Wed Feb 11 01:57:25 2026" elapsed="45.23" summary="Nmap done at Wed Feb 11 01:57:25 2026; 1 IP address (1 host up) scanned in 45.23 seconds" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
```

```
{
  "rustnmap": {
    "version": "1.0.0",
    "command": "rustnmap -sS -sV -O 192.168.1.1",
    "start_time": "2026-02-11T01:56:58Z",
    "end_time": "2026-02-11T01:57:25Z",
    "elapsed_seconds": 45.23
  },
  "scan": {
    "type": "syn",
    "protocol": "tcp",
    "total_ports": 65535
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "AA:BB:CC:DD:EE:FF",
      "mac_vendor": "Router Manufacturer",
      "hostname": "router.local",
      "status": "up",
      "reason": "arp-response",
      "latency_ms": 2.3,
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1 Ubuntu 3ubuntu0.1",
            "os_type": "Linux",
            "cpe": ["cpe:/a:openbsd:openssh:8.9p1"],
            "confidence": 10
          }
        },
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "http",
            "product": "nginx",
            "version": "1.18.0",
            "cpe": ["cpe:/a:nginx:nginx:1.18.0"],
            "confidence": 10
          }
        },
        {
          "port": 443,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "http",
            "product": "nginx",
            "version": "1.18.0",
            "tunnel": "ssl",
            "cpe": ["cpe:/a:nginx:nginx:1.18.0"],
            "confidence": 10
          },
          "scripts": {
            "ssl-cert": {
              "subject": "CN=example.com",
              "issuer": "CN=Let's Encrypt Authority X3",
              "public_key_bits": 2048,
              "public_key_type": "rsa"
            },
            "http-headers": {
              "Server": "nginx/1.18.0",
              "Date": "Wed, 11 Feb 2026 01:56:58 GMT",
              "Content-Type": "text/html"
            }
          }
        }
      ],
      "closed_ports": 65532,
      "os_detection": {
        "matches": [
          {
            "name": "Linux 5.4 - 5.10",
            "accuracy": 99,
            "os_family": "Linux",
            "os_generation": "5.X",
            "cpe": ["cpe:/o:linux:linux_kernel:5"]
          }
        ]
      },
      "traceroute": [
        {
          "hop": 1,
          "rtt_ms": 2.3,
          "ip": "192.168.1.1"
        }
      ]
    }
  ],
  "statistics": {
    "total_hosts": 1,
    "hosts_up": 1,
    "hosts_down": 0,
    "total_open_ports": 3,
    "total_closed_ports": 65532,
    "total_filtered_ports": 0
  }
}
```

### 3.8.3 输出模块类型定义

```
// ============================================
// Output Module Types
// ============================================

/// 输出格式化器 Trait
pub trait OutputFormatter: Send + Sync {
    /// 格式化完整扫描结果
    fn format_scan_result(&self, result: &ScanResult) -> Result<String, OutputError>;
    
    /// 格式化单个主机结果
    fn format_host(&self, host: &HostResult) -> Result<String, OutputError>;
    
    /// 格式化端口结果
    fn format_port(&self, port: &PortResult) -> Result<String, OutputError>;
    
    /// 格式化脚本结果
    fn format_script(&self, script: &ScriptResult) -> Result<String, OutputError>;
    
    /// 文件扩展名
    fn file_extension(&self) -> &str;
    
    /// 格式名称
    fn format_name(&self) -> &str;
}

/// 输出管理器
pub struct OutputManager {
    formatters: Vec<Box<dyn OutputFormatter>>,
    writers: Vec<Box<dyn OutputWriter>>,
    verbosity: VerbosityLevel,
    debug_level: u8,
    progress_reporter: Option<ProgressReporter>,
}

/// 输出写入器
pub enum OutputWriter {
    Stdout,
    File { path: PathBuf, file: File },
    Network { address: SocketAddr, stream: TcpStream },
    Memory { buffer: Vec<u8> },
}

/// 详细程度级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbosityLevel {
    Quiet = -1,      // -q: 静默模式
    Normal = 0,      // 默认
    Verbose1 = 1,    // -v
    Verbose2 = 2,    // -vv
    Verbose3 = 3,    // -vvv
    Debug1 = 4,      // -d
    Debug2 = 5,      // -dd
    Debug3 = 6,      // -ddd
    Debug4 = 7,      // -dddd
    Debug5 = 8,      // -ddddd
    Debug6 = 9,      // -dddddd (最高调试级别)
}

/// 进度报告器
pub struct ProgressReporter {
    start_time: Instant,
    total_tasks: usize,
    completed_tasks: usize,
    current_phase: ScanPhase,
}

pub enum ScanPhase {
    Discovery,
    PortScanning,
    ServiceDetection,
    OsDetection,
    ScriptExecution,
    Traceroute,
    Complete,
}

/// 扫描结果总结构
pub struct ScanResult {
    pub metadata: ScanMetadata,
    pub hosts: Vec<HostResult>,
    pub statistics: ScanStatistics,
    pub errors: Vec<ScanError>,
}

pub struct ScanMetadata {
    pub scanner_version: String,
    pub command_line: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub elapsed: Duration,
    pub scan_type: ScanType,
    pub protocol: Protocol,
}

pub struct HostResult {
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub reason: String,
    pub latency: Duration,
    pub ports: Vec<PortResult>,
    pub os_matches: Vec<OsMatch>,
    pub scripts: Vec<ScriptResult>,
    pub traceroute: Option<TracerouteResult>,
    pub times: HostTimes,
}

pub struct PortResult {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub reason: String,
    pub reason_ttl: u8,
    pub service: Option<ServiceInfo>,
    pub scripts: Vec<ScriptResult>,
}

pub struct ServiceInfo {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub hostname: Option<String>,
    pub ostype: Option<String>,
    pub devicetype: Option<String>,
    pub method: DetectionMethod,
    pub confidence: u8,
    pub cpe: Vec<Cpe>,
}

pub struct ScanStatistics {
    pub total_hosts: usize,
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub total_ports_scanned: u64,
    pub open_ports: u64,
    pub closed_ports: u64,
    pub filtered_ports: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

// ============================================
// Formatter Implementations
// ============================================

/// Normal 文本格式化器
pub struct NormalFormatter {
    verbosity: VerbosityLevel,
}

impl OutputFormatter for NormalFormatter {
    fn format_scan_result(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut output = String::new();
        
        // 头部信息
        output.push_str(&format!(
            "# RustNmap {} scan initiated {} as:\n",
            result.metadata.scanner_version,
            result.metadata.start_time.format("%c")
        ));
        output.push_str(&format!("# {}\n\n", result.metadata.command_line));
        
        // 每个主机
        for host in &result.hosts {
            output.push_str(&self.format_host(host)?);
            output.push_str("\n");
        }
        
        // 统计信息
        output.push_str(&format!(
            "Nmap done: {} IP address ({} host up) scanned in {:.2} seconds\n",
            result.statistics.total_hosts,
            result.statistics.hosts_up,
            result.metadata.elapsed.as_secs_f64()
        ));
        
        Ok(output)
    }
    
    fn format_host(&self, host: &HostResult) -> Result<String, OutputError> {
        let mut output = String::new();
        
        // 主机基本信息
        output.push_str(&format!("Nmap scan report for {}\n", host.ip));
        if let Some(ref hostname) = host.hostname {
            output.push_str(&format!("rDNS record for {}: {}\n", host.ip, hostname));
        }
        output.push_str(&format!("Host is {} ({}s latency).\n", 
            match host.status {
                HostStatus::Up => "up",
                HostStatus::Down => "down",
                HostStatus::Unknown => "unknown",
            },
            host.latency.as_secs_f64()
        ));
        
        if let Some(ref mac) = host.mac {
            output.push_str(&format!("MAC Address: {} ({})\n", mac.address, mac.vendor));
        }
        
        // 端口信息
        if !host.ports.is_empty() {
            let closed_count = host.ports.iter().
```


