# 3. 核心功能模块设计

## 3.1 主机发现模块

对应 Nmap 命令: `-sn`, `-PS`, `-PA`, `-PU`, `-PE`, `-PP`, `-PM`, `-PO`

### 3.1.1 功能矩阵

| 扫描类型 | Nmap 参数 | 描述 | RustNmap 实现 |
|----------|-----------|------|---------------|
| ARP Ping | `-PR` | ARP 请求探测 | `ArpDiscovery` |
| ICMP Echo | `-PE` | ICMP Echo Request | `IcmpEchoDiscovery` |
| ICMP Timestamp | `-PP` | ICMP 时间戳请求 | `IcmpTimestampDiscovery` |
| ICMP Address Mask | `-PM` | ICMP 地址掩码请求 | `IcmpMaskDiscovery` |
| TCP SYN Ping | `-PS <port>` | TCP SYN 包探测 | `TcpSynPing` |
| TCP ACK Ping | `-PA <port>` | TCP ACK 包探测 | `TcpAckPing` |
| UDP Ping | `-PU <port>` | UDP 包探测 | `UdpPing` |
| IP Protocol Ping | `-PO <proto>` | IP 协议探测 | `IpProtocolPing` |
| DNS Resolution | `-R/-n` | DNS 正向/反向解析 | `DnsResolver` |

### 3.1.2 主机发现流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    Host Discovery Pipeline                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Target    │───▶│   Target    │───▶│  Parallel Discovery │ │
│  │   Input     │    │   Parser    │    │      Executor       │ │
│  └─────────────┘    └─────────────┘    └──────────┬──────────┘ │
│                                                    │            │
│  ┌─────────────────────────────────────────────────▼──────────┐│
│  │              Discovery Method Selector                       ││
│  │  ┌─────────────────────────────────────────────────────────┐││
│  │  │  Local Network?  ──Yes──▶  ARP Discovery               │││
│  │  │         │                                                 │││
│  │  │        No                                                 │││
│  │  │         ▼                                                 │││
│  │  │  ┌─────────────────────────────────────────────────────┐│││
│  │  │  │  ICMP (Echo/Timestamp/Mask) ──▶  TCP (SYN/ACK)     ││││
│  │  │  │              │                         │            ││││
│  │  │  │              └──────────┬──────────────┘            ││││
│  │  │  │                         ▼                           ││││
│  │  │  │                    UDP Ping                        ││││
│  │  │  └─────────────────────────────────────────────────────┘│││
│  │  └─────────────────────────────────────────────────────────┘││
│  └──────────────────────────────┬──────────────────────────────┘│
│                                 │                               │
│  ┌──────────────────────────────▼──────────────────────────────┐│
│  │                    Result Aggregator                         ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ ││
│  │  │ Host Status │  │ RTT Stats   │  │ DNS Info            │ ││
│  │  │ (Up/Down)   │  │ (min/avg/max)│  │ (hostname/ptr)     │ ││
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 3.1.3 数据结构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                     Host Discovery Types                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  DiscoveryConfig                                                │
│  ├── method: DiscoveryMethod (enum)                            │
│  │   ├── ArpOnly                                               │
│  │   ├── IcmpOnly                                              │
│  │   ├── TcpSyn { ports: Vec<u16> }                           │
│  │   ├── TcpAck { ports: Vec<u16> }                           │
│  │   ├── Udp { ports: Vec<u16> }                              │
│  │   └── Custom { methods: Vec<DiscoveryMethod> }             │
│  ├── timeout: Duration                                         │
│  ├── retry_count: u8                                           │
│  └── parallel_hosts: usize                                     │
│                                                                 │
│  DiscoveredHost                                                 │
│  ├── ip: IpAddr                                                │
│  ├── mac: Option<MacAddr>                                      │
│  ├── hostname: Option<String>                                  │
│  ├── status: HostStatus                                        │
│  │   ├── Up                                                    │
│  │   ├── Down                                                  │
│  │   └── Unknown                                               │
│  ├── rtt: Option<Duration>                                     │
│  ├── discovery_method: DiscoveryMethod                         │
│  └── timestamps: Timestamps                                    │
│      ├── first_seen: Instant                                   │
│      └── last_seen: Instant                                    │
│                                                                 │
│  DiscoveryResult                                                │
│  ├── hosts: Vec<DiscoveredHost>                                │
│  ├── scan_stats: ScanStats                                     │
│  │   ├── total_hosts: usize                                    │
│  │   ├── up_hosts: usize                                       │
│  │   ├── down_hosts: usize                                     │
│  │   └── scan_duration: Duration                               │
│  └── errors: Vec<DiscoveryError>                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

