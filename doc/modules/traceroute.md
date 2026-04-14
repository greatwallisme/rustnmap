## 3.6 Traceroute Module

Corresponding Nmap commands: `--traceroute`, `--traceroute-probe`, `--traceroute-port`

Traceroute Implementation Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Traceroute Module Design                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Supported Methods:                                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Method        │ Protocol │ Default Port │ Description            │  │
│  ├────────────────┼──────────┼──────────────┼────────────────────────┤  │
│  │  UDP           │ UDP      │ 40125        │ Standard UDP traceroute│  │
│  │  TCP SYN       │ TCP      │ 80           │ TCP SYN traceroute     │  │
│  │  ICMP Echo     │ ICMP     │ N/A          │ ICMP Echo Request      │  │
│  │  ICMP DCE      │ ICMP     │ N/A          │ DCE RPC style          │  │
│  │  IP Protocol   │ IP       │ 0            │ Raw IP protocol        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Traceroute Flow:                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                                                                 │   │
│  │   ┌─────────────┐                                              │   │
│  │   │   Target    │                                              │   │
│  │   │   Host      │                                              │   │
│  │   └──────┬──────┘                                              │   │
│  │          │                                                      │   │
│  │          ▼                                                      │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │              TTL Loop (1 to max_hops)                    │  │   │
│  │   │                                                         │  │   │
│  │   │   For TTL = 1 to max_ttl:                               │  │   │
│  │   │     1. Create probe packet with current TTL             │  │   │
│  │   │     2. Send probe packet(s)                             │  │   │
│  │   │     3. Wait for response (ICMP Time Exceeded or         │  │   │
│  │   │        Port Unreachable, or Echo Reply)                 │  │   │
│  │   │     4. Record hop info:                                 │  │   │
│  │   │        - IP address of responding router                │  │   │
│  │   │        - RTT for each probe                             │  │   │
│  │   │        - Hostname (if resolvable)                       │  │   │
│  │   │     5. If reached destination, break                    │  │   │
│  │   │                                                         │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │          │                                                      │   │
│  │          ▼                                                      │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │                 TracerouteResult                         │  │   │
│  │   │                                                         │  │   │
│  │   │   ├── target: TargetInfo                                │  │   │
│  │   │   ├── hops: Vec<HopInfo>                                │  │   │
│  │   │   │   ├── ttl: u8                                       │  │   │
│  │   │   │   ├── ip: Option<IpAddr>                            │  │   │
│  │   │   │   ├── hostname: Option<String>                      │  │   │
│  │   │   │   ├── rtts: Vec<Duration>  // per probe             │  │   │
│  │   │   │   └── loss: f32  // packet loss rate                │  │   │
│  │   │   ├── total_hops: usize                                 │  │   │
│  │   │   ├── completed: bool                                    │  │   │
│  │   │   └── path_mtu: Option<usize>                           │  │   │
│  │   │                                                         │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---
