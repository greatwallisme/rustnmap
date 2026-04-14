## 3.3 Service Version Detection Module

Corresponding Nmap commands: `-sV`, `--version-intensity`, `--version-light`, `--version-all`

### 3.3.1 Service Detection Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Service Version Detection Flow                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐                                                   │
│  │  Open Port  │                                                   │
│  │  Detected   │                                                   │
│  └──────┬──────┘                                                   │
│         │                                                           │
│         ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Service Probe Selection                          │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  1. Match port number with known services               ││   │
│  │  │  2. Select probes based on intensity level              ││   │
│  │  │  3. Order probes by probability                         ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  └──────────────────────────────┬──────────────────────────────┘   │
│                                 │                                   │
│         ┌───────────────────────┼───────────────────────┐          │
│         │                       │                       │          │
│  ┌──────▼──────┐  ┌─────────────▼────────────┐  ┌──────▼──────┐   │
│  │  Null Probe │  │  Service-Specific Probe  │  │ Generic     │   │
│  │  (Banner)   │  │  (e.g., HTTP GET)        │  │ Probes      │   │
│  └──────┬──────┘  └─────────────┬────────────┘  └──────┬──────┘   │
│         │                     │                       │          │
│         └──────────────────────┼──────────────────────┘          │
│                                 │                                   │
│                                 ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Pattern Matching                          │   │
│  │  ┌─────────────────────────────────────────────────────────┐│   │
│  │  │  For each probe response:                               ││   │
│  │  │    1. Apply regex patterns from probe database          ││   │
│  │  │    2. Extract version information                       ││   │
│  │  │    3. Calculate confidence score                        ││   │
│  │  │    4. Return best match                                 ││   │
│  │  └─────────────────────────────────────────────────────────┘│   │
│  └──────────────────────────────┬──────────────────────────────┘   │
│                                 │                                   │
│                                 ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Service Detection Result                   │   │
│  │  ├── service_name: String                                    │   │
│  │  ├── product_name: Option<String>                            │   │
│  │  ├── version: Option<String>                                 │   │
│  │  ├── extrainfo: Option<String>                               │   │
│  │  ├── hostname: Option<String>                                │   │
│  │  ├── ostype: Option<String>                                  │   │
│  │  ├── devicetype: Option<String>                              │   │
│  │  ├── cpe: Vec<Cpe>                                           │   │
│  │  └── confidence: u8 (0-10)                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3.2 Probe Database Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Service Probe Database                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ProbeDefinition                                                    │
│  ├── name: String              (e.g., "GenericLines")              │
│  ├── protocol: Protocol        (TCP/UDP)                           │
│  ├── ports: Vec<u16>           (Target ports)                      │
│  ├── payload: Vec<u8>          (Data to send)                      │
│  ├── rarity: u8                (1-9, probe priority)               │
│  ├── ssl_ports: Vec<u16>       (SSL-wrapped ports)                │
│  └── matches: Vec<MatchRule>   (Response patterns)                 │
│                                                                     │
│  MatchRule                                                          │
│  ├── pattern: Regex            (Match pattern)                     │
│  ├── service: String           (Service name if matched)           │
│  ├── product: Option<String>   (Product name template)             │
│  ├── version: Option<String>   (Version template)                  │
│  ├── info: Option<String>      (Extra info template)               │
│  ├── hostname: Option<String>  (Hostname template)                 │
│  ├── ostype: Option<String>    (OS type template)                  │
│  ├── devicetype: Option<String>(Device type template)              │
│  ├── cpe: Option<String>       (CPE template)                      │
│  └── soft: bool                (Soft match flag)                   │
│                                                                     │
│  ProbeDatabase                                                      │
│  ├── probes: HashMap<String, ProbeDefinition>                      │
│  ├── port_mapping: HashMap<u16, Vec<String>>  // port -> probe names│
│  └── intensity_levels: HashMap<u8, Vec<String>> // rarity -> probes│
│                                                                     │
│  Example Probe Entry:                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Probe TCP GenericLines q|\r\n\r\n|                         │   │
│  │  ports 1-65535                                              │   │
│  │  rarity 1                                                   │   │
│  │                                                             │   │
│  │  match SSH m|^SSH-([\d.]+)-OpenSSH([\w._-]*)\r?\n|          │   │
│  │    p/OpenSSH/ v/$2/ i protocol $1                           │   │
│  │    cpe:/a:openbsd:openssh:$2/                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---
