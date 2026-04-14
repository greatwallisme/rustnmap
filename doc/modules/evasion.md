## 3.7 Firewall/IDS Evasion Module

Corresponding Nmap commands: `-f`, `-D`, `-S`, `--source-port`, `-e`, `--badsum`, `--data-length`

### 3.7.1 Evasion Technique Matrix

|Technique|Nmap Parameter|Description|Implementation Complexity|
|---|---|---|---|
|Fragmentation|`-f`, `--mtu`|IP fragmentation bypass|★★★☆☆|
|Decoy|`-D <decoy1,decoy2,...>`|Decoy IP scanning|★★★★☆|
|Source IP Spoofing|`-S <IP>`|Spoofed source IP|★★☆☆☆|
|Source Port Masquerading|`--source-port <port>`|Specify source port|★☆☆☆☆|
|Interface Selection|`-e <iface>`|Specify network interface|★★☆☆☆|
|MAC Spoofing|`--spoof-mac <addr>`|Spoof MAC address|★★☆☆☆|
|Bad Checksum|`--badsum`|Send incorrect checksums|★☆☆☆☆|
|Data Padding|`--data-length <num>`|Pad with random data|★☆☆☆☆|
|IP Options|`--ip-options <opts>`|Custom IP options|★★★☆☆|
|TTL Setting|`--ttl <value>`|Set TTL value|★☆☆☆☆|
|Random Targets|`--randomize-hosts`|Randomize scan order|★★☆☆☆|
|Timing Templates|`-T0` to `-T5`|Timing control|★★★☆☆|
### 3.7.2 Fragmentation Evasion Implementation

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     IP Fragmentation Evasion                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Fragmentation Modes:                                                   │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  Original TCP SYN Packet (no fragmentation):                      │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │  IP Header (20B) │ TCP Header (20B) │ Payload               │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  Small Fragment Mode (-f, 8 bytes):                               │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │  Fragment 1: IP Header + TCP Flags (8B TCP data)           │  │  │
│  │  │  ┌─────────────────────────────────────────┐               │  │  │
│  │  │  │  IP (20B) │ TCP [first 8B] │ MORE_FRAG │               │  │  │
│  │  │  └─────────────────────────────────────────┘               │  │  │
│  │  │                                                             │  │  │
│  │  │  Fragment 2: Remaining TCP Data                             │  │  │
│  │  │  ┌─────────────────────────────────────────┐               │  │  │
│  │  │  │  IP (20B) │ TCP [remaining 12B+]       │               │  │  │
│  │  │  └─────────────────────────────────────────┘               │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  │  Custom MTU (--mtu <value>):                                      │  │
│  │  ┌────────────────────────────────────────────────────────────┐  │  │
│  │  │  Calculate fragment offset based on MTU value,              │  │  │
│  │  │  ensuring each fragment does not exceed MTU.                │  │  │
│  │  │  Each fragment contains: IP Header + partial data           │  │  │
│  │  └────────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Fragment Configuration Structure:                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  FragmentConfig {                                                 │  │
│  │    enabled: bool,                                                 │  │
│  │    mode: FragmentMode,                                            │  │
│  │    │   ├── Default (8 bytes)                                     │  │
│  │    │   ├── CustomMTU(u16)                                        │  │
│  │    │   └── Random(usize, usize)  // min, max                     │  │
│  │    overlap: bool,           // Allow fragment overlap             │  │
│  │    timeout: Duration,       // Fragment reassembly timeout        │  │
│  │  }                                                               │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.7.3 Decoy Scanning Implementation

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Decoy Scanning Design                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Decoy Scanning Principle:                                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   -D <decoy1,decoy2,...,ME,decoyN>                                │  │
│  │                                                                   │  │
│  │   Probe Packets Sent:                                             │  │
│  │   ┌─────────────────────────────────────────────────────────────┐│  │
│  │   │  Packet 1: Source=decoy1  → Target:Port                    ││  │
│  │   │  Packet 2: Source=decoy2  → Target:Port                    ││  │
│  │   │  Packet 3: Source=ME      → Target:Port  (real scan)       ││  │
│  │   │  Packet 4: Source=decoy3  → Target:Port                    ││  │
│  │   │  Packet 5: Source=decoy4  → Target:Port                    ││  │
│  │   └─────────────────────────────────────────────────────────────┘│  │
│  │                                                                   │  │
│  │   Target's view: Real IP is hidden among decoys, making it       │  │
│  │   difficult to identify the actual attacker.                      │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Decoy Scanning Flow:                                                   │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │  │
│  │   │  Decoy      │───>│  Round      │───>│  Packet            │  │  │
│  │   │  Parser     │    │  Robin      │    │  Injector          │  │  │
│  │   └─────────────┘    │  Scheduler  │    └─────────────────────┘  │  │
│  │                      └─────────────┘                              │  │
│  │                            │                                      │  │
│  │                            ▼                                      │  │
│  │   ┌─────────────────────────────────────────────────────────┐    │  │
│  │   │                   DecoyPacket                            │    │  │
│  │   │                                                         │    │  │
│  │   │   ├── real_source: IpAddr        (real IP)              │    │  │
│  │   │   ├── decoys: Vec<IpAddr>        (decoy list)           │    │  │
│  │   │   ├── position: usize            (ME position in list)  │    │  │
│  │   │   └── random_order: bool         (random send order)    │    │  │
│  │   │                                                         │    │  │
│  │   └─────────────────────────────────────────────────────────┘    │  │
│  │                                                                   │  │
│  │   Special Values:                                                 │  │
│  │   ├── ME      - Real IP                                          │  │
│  │   ├── ME:<n>  - Place real IP at position n                      │  │
│  │   └── RND:n   - Generate n random decoys                         │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.7.4 Evasion Configuration Overview

```
// ============================================
// Evasion Configuration Types
// ============================================

/// Evasion configuration root structure
pub struct EvasionConfig {
    /// Fragmentation configuration
    pub fragmentation: Option<FragmentConfig>,
    
    /// Decoy configuration
    pub decoys: Option<DecoyConfig>,
    
    /// Source address configuration
    pub source: SourceConfig,
    
    /// Packet modification configuration
    pub packet_modification: PacketModConfig,
    
    /// Timing configuration
    pub timing: TimingConfig,
}

/// Fragmentation configuration
pub struct FragmentConfig {
    pub enabled: bool,
    pub mode: FragmentMode,
    pub overlap: bool,
    pub timeout: Duration,
}

pub enum FragmentMode {
    Default,                        // 8-byte fragmentation
    CustomMTU(u16),                 // Custom MTU
    Random { min: usize, max: usize }, // Random fragment size
}

/// Decoy configuration
pub struct DecoyConfig {
    pub decoys: Vec<IpAddr>,
    pub real_ip_position: usize,    // Position of ME
    pub random_order: bool,         // Whether to send in random order
}

/// Source address configuration
pub struct SourceConfig {
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub source_mac: Option<MacAddr>,
    pub interface: Option<String>,
}

/// Packet modification configuration
pub struct PacketModConfig {
    /// Send incorrect checksums
    pub bad_checksum: bool,
    
    /// Additional random data length
    pub data_length: Option<usize>,
    
    /// Custom IP options
    pub ip_options: Option<Vec<IpOption>>,
    
    /// TTL value
    pub ttl: Option<u8>,
    
    /// TOS value
    pub tos: Option<u8>,
    
    /// Do not set any flag bits (used for certain firewall bypasses)
    pub no_flags: bool,
}

/// IP option
pub enum IpOption {
    RecordRoute { max_addresses: u8 },
    Timestamp { flags: u8, max_entries: u8 },
    LooseSourceRoute { addresses: Vec<IpAddr> },
    StrictSourceRoute { addresses: Vec<IpAddr> },
    Custom { type_code: u8, data: Vec<u8> },
}

/// Timing templates
#[derive(Debug, Clone, Copy)]
pub enum TimingTemplate {
    Paranoid,    // T0: Slowest, IDS evasion
    Sneaky,      // T1: Slow, stealthy
    Polite,      // T2: Polite, low bandwidth
    Normal,      // T3: Default
    Aggressive,  // T4: Fast
    Insane,      // T5: Extremely fast
}

impl TimingTemplate {
    pub fn config(&self) -> TimingValues {
        match self {
            TimingTemplate::Paranoid => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(5),
                max_retries: 10,
                scan_delay: Duration::from_millis(300),
                max_parallel: 1,
            },
            TimingTemplate::Sneaky => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(5),
                max_retries: 5,
                scan_delay: Duration::from_millis(100),
                max_parallel: 2,
            },
            TimingTemplate::Polite => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 3,
                scan_delay: Duration::from_millis(10),
                max_parallel: 10,
            },
            TimingTemplate::Normal => TimingValues {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 2,
                scan_delay: Duration::ZERO,
                max_parallel: 100,
            },
            TimingTemplate::Aggressive => TimingValues {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_secs(3),
                initial_rtt_timeout: Duration::from_millis(500),
                max_retries: 1,
                scan_delay: Duration::ZERO,
                max_parallel: 500,
            },
            TimingTemplate::Insane => TimingValues {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_secs(1),
                initial_rtt_timeout: Duration::from_millis(250),
                max_retries: 0,
                scan_delay: Duration::ZERO,
                max_parallel: 1000,
            },
        }
    }
}

pub struct TimingValues {
    pub min_rtt_timeout: Duration,
    pub max_rtt_timeout: Duration,
    pub initial_rtt_timeout: Duration,
    pub max_retries: u8,
    pub scan_delay: Duration,
    pub max_parallel: usize,
}
```

---

