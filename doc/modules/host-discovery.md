# 3. Core Module Design

## 3.1 Host Discovery Module

Corresponding Nmap commands: `-sn`, `-PS`, `-PA`, `-PU`, `-PE`, `-PP`, `-PM`, `-PO`

### 3.1.1 Feature Matrix

| Scan Type | Nmap Parameter | Description | RustNmap Implementation |
|----------|-----------|------|---------------|
| ARP Ping | `-PR` | ARP request probe | `ArpDiscovery` |
| ICMP Echo | `-PE` | ICMP Echo Request | `IcmpEchoDiscovery` |
| ICMP Timestamp | `-PP` | ICMP Timestamp Request | `IcmpTimestampDiscovery` |
| ICMP Address Mask | `-PM` | ICMP Address Mask Request | `IcmpMaskDiscovery` |
| TCP SYN Ping | `-PS <port>` | TCP SYN packet probe | `TcpSynPing` |
| TCP ACK Ping | `-PA <port>` | TCP ACK packet probe | `TcpAckPing` |
| UDP Ping | `-PU <port>` | UDP packet probe | `UdpPing` |
| IP Protocol Ping | `-PO <proto>` | IP protocol probe | `IpProtocolPing` |
| DNS Resolution | `-R/-n` | DNS forward/reverse resolution | `DnsResolver` |

### 3.1.2 Host Discovery Flow

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

### 3.1.3 Data Structure Design

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
