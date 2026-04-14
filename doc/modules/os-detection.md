## 3.4 OS Detection Module

Corresponding Nmap commands: `-O`, `--osscan-limit`, `--osscan-guess`

### 3.4.1 OS Fingerprinting Techniques

| Fingerprint Type | Description | Detection Method | Nmap Reference |
|----------|------|----------|-----------|
| TCP ISN | Initial Sequence Number pattern | Multiple SYN to collect ISN | `SEQ` |
| IP ID | IP Identifier increment pattern | Multiple probes for IP ID | `SEQ` |
| TCP Options | TCP option order and values | SYN packet option analysis | `OPS` |
| TCP Window | Window size characteristics | SYN-ACK window value | `WIN` |
| T1-T7 | TCP response tests | Various TCP packet responses | `T1`-`T7` |
| IE | ICMP response characteristics | ICMP Echo response | `IE` |
| U1 | UDP response characteristics | UDP probe response | `U1` |
| ECN | ECN support | ECN flag bits | `ECN` |

### 3.4.2 OS Detection Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OS Detection Pipeline                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Phase 1: Fingerprint Collection                                    │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                                                               │ │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │ │
│  │   │   TCP SEQ   │    │   TCP OPS   │    │    TCP WIN      │  │ │
│  │   │  Analysis   │    │  Analysis   │    │   Analysis      │  │ │
│  │   │  (6 probes) │    │  (1 probe)  │    │   (1 probe)     │  │ │
│  │   └──────┬──────┘    └──────┬──────┘    └────────┬────────┘  │ │
│  │          │                  │                     │           │ │
│  │   ┌──────▼──────────────────▼─────────────────────▼──────┐   │ │
│  │   │                    TCP Tests (T1-T7)                 │   │ │
│  │   │  T1: Open port response                              │   │ │
│  │   │  T2: Closed port, no flags                           │   │ │
│  │   │  T3: Open port, FIN/PSH/URG                          │   │ │
│  │   │  T4: Closed port, ACK                                │   │ │
│  │   │  T5: Closed port, SYN                                │   │ │
│  │   │  T6: Closed port, ACK                                │   │ │
│  │   │  T7: Closed port, FIN/PSH/URG                        │   │ │
│  │   └──────────────────────────────────────────────────────┘   │ │
│  │                                                               │ │
│  │   ┌─────────────────────────────────────────────────────────┐│ │
│  │   │  ICMP Tests (IE)                                        ││ │
│  │   │  IE1: Echo request with IP options                      ││ │
│  │   │  IE2: Echo request with different IP options            ││ │
│  │   └─────────────────────────────────────────────────────────┘│ │
│  │                                                               │ │
│  │   ┌─────────────────────────────────────────────────────────┐│ │
│  │   │  UDP Test (U1)                                          ││ │
│  │   │  U1: UDP probe to closed port                           ││ │
│  │   └─────────────────────────────────────────────────────────┘│ │
│  │                                                               │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                 │                                   │
│                                 ▼                                   │
│  Phase 2: Fingerprint Generation                                    │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  FingerprintBuilder                                           │ │
│  │  ├── seq: SeqFingerprint                                      │ │
│  │  │   ├── isp: ISPPattern (TCPISTimeStamp, TCPISN)            │ │
│  │  │   ├── ts: TimestampPattern                                │ │
│  │  │   └── gc: GCInterval                                      │ │
│  │  ├── ops: OpsFingerprint (TCP Options per test)              │ │
│  │  ├── win: WinFingerprint (Window sizes per test)             │ │
│  │  ├── ecn: EcnFingerprint                                     │ │
│  │  ├── t1-t7: TcpTestFingerprint                               │ │
│  │  ├── u1: UdpFingerprint                                      │ │
│  │  └── ie: IcmpFingerprint                                     │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                 │                                   │
│                                 ▼                                   │
│  Phase 3: Database Matching                                         │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  FingerprintMatcher                                           │ │
│  │  ├── Load nmap-os-db database                                 │ │
│  │  ├── Calculate match scores for each known fingerprint        │ │
│  │  ├── Apply scoring weights                                    │ │
│  │  └── Return top matches with accuracy percentages            │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4.3 OS Fingerprint Data Structures

```
┌─────────────────────────────────────────────────────────────────────┐
│                      OS Fingerprint Types                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  OsFingerprint                                                      │
│  ├── seq: SeqFingerprint                                            │
│  │   ├── tcp_isn: IsnPattern                                        │
│  │   │   ├── gcd: u32            (GCD of ISN differences)          │
│  │   │   ├── isr: u8             (ISN rate)                        │
│  │   │   └── sp: u8              (Sequence predictability)         │
│  │   ├── ip_id: IpIdPattern                                         │
│  │   │   ├── zi: bool            (Zero IP ID)                      │
│  │   │   ├── inc: bool           (Incremental)                     │
│  │   │   └── ss: u8              (IP ID sequence)                  │
│  │   └── ts: TimestampPattern                                       │
│  │       ├── ts: u8              (Timestamp option)                │
│  │       └── hr: u32             (Hourly rate)                     │
│  │                                                                   │
│  ├── ops: HashMap<String, TcpOpsPattern>  // T1-T7 -> Options      │
│  │   └── TcpOpsPattern                                              │
│  │       ├── mss: Option<u16>    (Max Segment Size)               │
│  │       ├── wscale: Option<u8>  (Window Scale)                   │
│  │       ├── sack: bool          (Selective ACK)                  │
│  │       ├── timestamp: bool     (Timestamp option)               │
│  │       ├── nop: u8             (NOP count)                       │
│  │       └── eol: bool           (End of Options List)            │
│  │                                                                   │
│  ├── win: HashMap<String, u16>       // T1-T7 -> Window Size       │
│  │                                                                   │
│  ├── ecn: EcnPattern                                                │
│  │   ├── r: bool                 (ECE flag response)              │
│  │   ├── df: bool                (Don't Fragment)                 │
│  │   ├── t: u8                   (TOS value)                       │
│  │   └── ad: bool                (CWR set)                         │
│  │                                                                   │
│  └── tests: HashMap<String, TestResult>  // T1-T7, U1, IE          │
│                                                                     │
│  OsMatch                                                            │
│  ├── name: String              (e.g., "Linux 5.4")                 │
│  ├── os_family: OsFamily                                             │
│  │   ├── Linux                                                       │
│  │   ├── Windows                                                     │
│  │   ├── macOS                                                       │
│  │   ├── BSD                                                         │
│  │   ├── Solaris                                                     │
│  │   └── Other(String)                                              │
│  ├── accuracy: u8              (0-100)                              │
│  ├── vendor: Option<String>                                          │
│  ├── os_generation: Option<String>                                   │
│  ├── device_type: Option<String>                                     │
│  └── cpe: Option<Cpe>                                               │
│                                                                     │
│  OsDetectionResult                                                  │
│  ├── matches: Vec<OsMatch>      (Sorted by accuracy)               │
│  ├── fingerprint_used: OsFingerprint                                │
│  └── scan_duration: Duration                                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4.4 OS Detection Implementation Details

Based on the Nmap `FPEngine.cc/h` and `osscan2.cc` implementation.

#### 3.4.4.1 Core Data Structures

**Nmap source code mapping:**

```rust
// Corresponds to the FPEngine base class in Nmap FPEngine.h
pub trait FingerprintEngine {
    fn os_scan(&mut self, targets: Vec<Target>) -> Result<()>;
    fn reset(&mut self);
}

// Corresponds to FPEngine6 - IPv6 fingerprinting
pub struct FingerprintEngineV6 {
    // Target host list
    hosts: Vec<FpHostV6>,

    // Group size (corresponds to OSSCAN_GROUP_SIZE)
    pub group_size: usize,

    // Network controller
    pub network_control: FpNetworkControl,
}

// Corresponds to FPNetworkControl - network access manager
pub struct FpNetworkControl {
    // Nsock connection pool
    pub nsock_pool: nsock_pool,

    // Pcap descriptor
    pub pcap_nsi: nsock_iod,

    // Last scheduled pcap event ID
    pub pcap_ev_id: nsock_event_id,

    // Whether initialized
    pub nsock_init: bool,

    // Raw socket
    pub raw_sd: i32,

    // Registered callers (FPHost list)
    pub callers: Vec<FpHost>,

    // Number of probes sent
    pub probes_sent: i32,

    // Number of responses received
    pub responses_recv: i32,

    // Number of timed-out probes
    pub probes_timedout: i32,

    // Congestion control
    pub cc_cwnd: f32,        // Congestion window
    pub cc_ssthresh: f32,    // Slow start threshold

    // L2 frame support check
    pub fn l2_frames(&self) -> bool {
        self.raw_sd < 0
    }
}

impl FpNetworkControl {
    // Corresponds to cc_init()
    pub fn new() -> Result<Self> {
        Ok(Self {
            nsock_pool: nsock_pool_new()?,
            pcap_nsi: std::ptr::null(),
            pcap_ev_id: 0,
            nsock_init: false,
            raw_sd: -1,
            callers: Vec::new(),
            probes_sent: 0,
            responses_recv: 0,
            probes_timedout: 0,
            // Corresponds to OSSCAN_INITIAL_CWND
            cc_cwnd: NUM_FP_TIMEDPROBES_IPV6 as f32,
            // Corresponds to OSSCAN_INITIAL_SSTHRESH = 4 * CWND
            cc_ssthresh: (4 * NUM_FP_TIMEDPROBES_IPV6) as f32,
        })
    }

    // Corresponds to scheduleProbe()
    pub fn schedule_probe(&mut self,
                            probe: &mut FpProbe,
                            delay_ms: i32)
        -> Result<()> {
        // Check congestion window
        if !self.request_slots(1) {
            return Err(Error::CongestionWindowFull);
        }

        // Schedule send via nsock
        nsock_schedule_timer(
            self.nsock_pool,
            delay_ms,
            Some(probe_transmission_handler),
            probe as *mut c_void,
        )?;

        self.probes_sent += 1;
        Ok(())
    }

    // Corresponds to request_slots()
    pub fn request_slots(&mut self, num_packets: usize) -> bool {
        // Check if there is enough congestion window space
        (self.callers.len() as f32) < self.cc_cwnd
    }

    // Corresponds to cc_update_sent()
    pub fn cc_on_sent(&mut self, pkts: i32) {
        // Update congestion control state
    }

    // Corresponds to cc_update_received()
    pub fn cc_on_received(&mut self) {
        self.responses_recv += 1;

        // Corresponds to cc_report_final_timeout()
        // Adjust window based on response
    }
}
```

#### 3.4.4.2 FPHost Per-Host State

```rust
// Corresponds to FPHost - per-host state for fingerprinting
pub struct FpHost {
    // Total number of probes
    pub total_probes: u32,

    // Number of timed probes (require 100ms interval)
    pub timed_probes: u32,

    // Number of probes sent (excluding retransmissions)
    pub probes_sent: u32,

    // Number of probes that received responses
    pub probes_answered: u32,

    // Number of probes that timed out without response
    pub probes_unanswered: u32,

    // Whether incomplete
    pub incomplete_fp: bool,

    // Whether detection is complete
    pub detection_done: bool,

    // Whether timed probes have been sent
    pub timedprobes_sent: bool,

    // Target host information
    pub target_host: Target,

    // Network controller link
    pub netctl: Option<FpNetworkControl>,

    // Whether registered with network controller
    pub netctl_registered: bool,

    // TCP sequence number base
    pub tcp_seq_base: u32,

    // Open TCP port (for OS probing)
    pub open_port_tcp: i32,

    // Closed TCP port
    pub closed_port_tcp: i32,

    // Closed UDP port
    pub closed_port_udp: i32,

    // TCP probe source port
    pub tcp_port_base: i32,

    // UDP probe port
    pub udp_port_base: i32,

    // ICMPv6 sequence counter
    pub icmp_seq_counter: u16,

    // Retransmission timeout (RTO)
    pub rto: i32,

    // RTT variance
    pub rttvar: i32,

    // Smoothed round-trip time
    pub srtt: i32,
}

impl FpHost {
    // Corresponds to update_RTO()
    pub fn update_rto(&mut self, measured_rtt_us: i32,
                       is_retransmission: bool) {
        if !is_retransmission {
            // First measurement or normal response
            if self.srtt == 0 {
                self.srtt = measured_rtt_us;
                self.rttvar = measured_rtt_us / 2;
            } else {
                // RFC 2988 formula
                let rtt_diff = measured_rtt_us - self.srtt;
                self.rttvar = (3 * self.rttvar / 4 +
                                   rtt_diff.abs() / 2)
                                  .min(i32::MAX);
                self.srtt = (7 * self.srtt / 8 +
                                   measured_rtt_us / 8);
            }
        }

        // Calculate timeout = SRTT + 4 * RTTVAR
        self.rto = self.srtt + 4 * self.rttvar;

        // Corresponds to OSSCAN_INITIAL_RTO = 3 seconds
        self.rto = self.rto.clamp(
            OSSCAN_INITIAL_RTO_MIN,
            OSSCAN_INITIAL_RTO_MAX
        );
    }

    // Corresponds to choose_osscan_ports()
    pub fn choose_osscan_ports(&mut self, ports: &PortList) -> Result<()> {
        // Select one open port and one closed port for OS probing
        self.open_port_tcp = ports.find_open_port()
            .ok_or(Error::NoOpenPort)?;
        self.closed_port_tcp = ports.find_closed_port()
            .ok_or(Error::NoClosedPort)?;

        // For UDP, only need one closed port
        self.closed_port_udp = ports.find_closed_udp_port()
            .ok_or(Error::NoClosedUdpPort)?;

        Ok(())
    }
}
```

#### 3.4.4.3 FPProbe Probe Structure

```rust
// Corresponds to FPProbe - OS fingerprint probe packet
pub struct FpProbe {
    // Probe ID (e.g., "SEQ", "OPS", "T1", etc.)
    pub probe_id: Cow<'static, str>,

    // Probe number
    pub probe_no: i32,

    // Number of retransmissions
    pub retransmissions: i32,

    // Number of responses received
    pub times_replied: i32,

    // Whether failed
    pub failed: bool,

    // Whether this is a timed probe
    pub timed: bool,

    // Associated host
    pub host: *mut FpHost,

    // Packet data (inherited from FPPacket)
    pub packet: PacketData,

    // Send time
    pub sent_time: TimeVal,
}

// Corresponds to FPPacket
pub struct PacketData {
    pub pkt: PacketElement,
    pub link_eth: bool,
    pub eth_hdr: EthHeader,
    pub pkt_time: TimeVal,
}

impl FpProbe {
    // Corresponds to isResponse()
    pub fn is_response(&self, received: &PacketElement) -> bool {
        // Check if the received packet is a response to this probe
        self.matches_probe(received)
    }

    // Corresponds to incrementRetransmissions()
    pub fn increment_retransmissions(&mut self) -> i32 {
        self.retransmissions += 1;
        self.retransmissions
    }

    // Corresponds to setFailed()
    pub fn set_failed(&mut self) {
        self.failed = true;
    }
}
```

#### 3.4.4.4 IPv6 OS Detection Implementation

```rust
// Corresponds to FPHost6
pub struct FpHostV6 {
    // Inherits FPHost
    pub base: FpHost,

    // IPv6-specific probes (13 TCP + 4 ICMPv6 + 1 UDP)
    pub fp_probes: [FpProbe; NUM_FP_PROBES_IPV6],

    // Received responses
    pub fp_responses: [Option<FpResponse>; NUM_FP_PROBES_IPV6],

    // Auxiliary responses for timed probes
    pub aux_resp: [Option<FpResponse>; NUM_FP_TIMEDPROBES_IPV6],
}

impl FpHostV6 {
    // Corresponds to FPEngine6::os_scan()
    pub async fn os_scan(targets: Vec<Target>) -> Result<()> {
        // 1. Create network controller
        let mut netctl = FpNetworkControl::new(&interface)?;

        // 2. Initialize FPHost for each target
        let mut hosts: Vec<FpHostV6> = targets.iter()
            .map(|t| FpHostV6::new(t, &netctl))
            .collect();

        // 3. Select OS scan ports
        for host in &mut hosts {
            host.choose_osscan_ports(&ports)?;
        }

        // 4. Register all hosts with network controller
        for host in &mut hosts {
            netctl.register_caller(host)?;
        }

        // 5. Set up pcap sniffers
        netctl.setup_sniffer(&interface, &bpf_filter)?;

        // 6. Main scan loop
        while !hosts.iter().all(|h| h.done()) {
            // 6.1 Schedule probes
            for host in hosts.iter().filter(|h| !h.done()) {
                host.schedule()?;
            }

            // 6.2 Process events
            netctl.handle_events()?;

            // 6.3 Check timeouts
            for host in hosts.iter_mut() {
                if host.has_timed_out() {
                    host.retry_failed_probes()?;
                }
            }
        }

        // 7. Populate results
        for host in hosts {
            host.fill_results()?;
        }

        Ok(())
    }

    // Corresponds to schedule()
    pub fn schedule(&mut self) -> Result<()> {
        // If all probes have been sent, wait for responses
        if self.probes_sent >= self.total_probes {
            return Ok(());
        }

        // Get next probe to send
        let probe_idx = self.probes_sent as usize;
        let probe = &mut self.fp_probes[probe_idx];

        // Check if this is a timed probe (requires 100ms interval)
        if probe.timed {
            // Ensure timed probes are sent in sequence
            if !self.timedprobes_sent {
                // First timed probe
                self.timedprobes_sent = true;
            } else {
                // Check if 100ms has elapsed since last timed probe
                if !self.check_timed_probe_delay()? {
                    return Ok(());  // Wait longer
                }
            }
        }

        // Send via network controller
        self.host.netctl
            .as_ref()
            .ok_or(Error::NoNetworkControl)?
            .schedule_probe(probe, 0)?;

        self.probes_sent += 1;
        Ok(())
    }

    // Corresponds to callback()
    pub fn callback(&mut self,
                   pkt: &[u8],
                   pkt_len: usize,
                   tv: &TimeVal) -> Result<()> {
        // Parse the received packet
        let response = parse_fingerprint_response(pkt, pkt_len)?;

        // Find the matching probe
        let probe_id = response.matching_probe_id()?;

        // Store response
        self.fp_responses[probe_id] = Some(response);

        // Update RTT and RTO
        let rtt = tv.saturating_sub(&self.fp_probes[probe_id].sent_time);
        self.update_rto(rtt.as_micros() as i32, false)?;

        Ok(())
    }
}
```

#### 3.4.4.5 Probe Type Definitions

```rust
// Corresponds to constants in FPEngine.h
pub const NUM_FP_PROBES_IPV6_TCP: usize = 13;
pub const NUM_FP_PROBES_IPV6_ICMPV6: usize = 4;
pub const NUM_FP_PROBES_IPV6_UDP: usize = 1;
pub const NUM_FP_PROBES_IPV6: usize =
    NUM_FP_PROBES_IPV6_TCP +
    NUM_FP_PROBES_IPV6_ICMPV6 +
    NUM_FP_PROBES_IPV6_UDP;

// Number of timed probes (require specific timing)
pub const NUM_FP_TIMEDPROBES_IPV6: usize = 6;

// Congestion control constants
pub const OSSCAN_GROUP_SIZE: usize = 10;
pub const OSSCAN_INITIAL_CWND: usize = NUM_FP_TIMEDPROBES_IPV6;
pub const OSSCAN_INITIAL_SSTHRESH: usize = 4 * OSSCAN_INITIAL_CWND;
pub const OSSCAN_INITIAL_RTO: i32 = 3_000_000;  // 3 seconds (microseconds)

// TCP flow label (used for OS detection)
pub const OSDETECT_FLOW_LABEL: u32 = 0x12345;

// Novelty threshold (match score difference threshold)
pub const FP_NOVELTY_THRESHOLD: f64 = 15.0;

// IPv6 OS probe types
pub enum V6ProbeType {
    // TCP probes (13)
    SeqTest,
    IcmpEcho,
    TcpT1,  // Open port response
    TcpT2,  // Closed port, no flags
    TcpT3,  // Open port, FIN/PSH/URG
    TcpT4,  // Closed port, ACK
    TcpT5,  // Closed port, SYN
    TcpT6,  // Closed port, ACK
    TcpT7,  // Closed port, FIN/PSH/URG
    // ICMPv6 probes (4)
    IcmpV6Echo,
    // UDP probes (1)
    UdpClosed,
}
```

#### 3.4.4.6 Fingerprint Matching Algorithm

```rust
// Corresponds to FingerMatch and load_fp_matches()
pub struct FingerprintMatcher {
    // All fingerprints in the database
    pub fingerprints: Vec<OsFingerprint>,
}

impl FingerprintMatcher {
    // Corresponds to load_fp_matches()
    pub fn load_from_db(db_path: &Path) -> Result<Self> {
        // Parse nmap-os-db file
        let db_content = fs::read_to_string(db_path)?;
        Ok(Self {
            fingerprints: parse_fingerprints(&db_content)?,
        })
    }

    // Match fingerprint and score
    pub fn match(&self,
               fp: &OsFingerprint) -> Vec<OsMatch> {
        let mut scores: Vec<OsMatch> = Vec::new();

        for known_fp in &self.fingerprints {
            let score = self.calculate_score(fp, known_fp);

            // Only consider it a match if the score is below the threshold
            if score < FP_NOVELTY_THRESHOLD {
                scores.push(OsMatch {
                    name: known_fp.name.clone(),
                    accuracy: ((100.0 - score.max(0.0)) as u8),
                    vendor: known_fp.vendor.clone(),
                    os_family: known_fp.os_family.clone(),
                    // ... other fields
                });
            }
        }

        // Sort by accuracy
        scores.sort_by(|a, b| b.accuracy.cmp(&a.accuracy));
        scores
    }

    // Calculate the difference score between two fingerprints
    fn calculate_score(&self, fp1: &OsFingerprint, fp2: &OsFingerprint)
        -> f64 {
        let mut total_diff = 0.0;

        // SEQ fingerprint comparison
        total_diff += self.compare_seq(&fp1.seq, &fp2.seq);

        // OPS fingerprint comparison (per test)
        for (test, ops1) in &fp1.ops {
            if let Some(ops2) = fp2.ops.get(test) {
                total_diff += self.compare_ops(ops1, ops2);
            }
        }

        // WIN fingerprint comparison
        total_diff += self.compare_win(&fp1.win, &fp2.win);

        // ECN fingerprint comparison
        total_diff += self.compare_ecn(&fp1.ecn, &fp2.ecn);

        // T1-T7 test comparison
        for test in &["T1", "T2", "T3", "T4", "T5", "T6", "T7"] {
            if let Some(t1) = fp1.tests.get(test) {
                if let Some(t2) = fp2.tests.get(test) {
                    total_diff += self.compare_test_result(t1, t2);
                }
            }
        }

        total_diff
    }
}
```

---
