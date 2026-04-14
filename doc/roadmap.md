# 6. Development Roadmap

## Phase 1: Core Infrastructure (MVP)

**Estimated Duration: 4-6 weeks**

| Task | Description | Priority |
|------|-------------|----------|
| CLI Framework | Integrate clap, argument parsing | P0 |
| Target Parsing | IP/hostname/CIDR parsing | P0 |
| Raw Sockets | Linux raw socket support | P0 |
| TCP SYN Scan | Implement core scanning capability | P0 |
| TCP Connect | User-space scan support | P0 |
| Basic Output | Normal format output | P0 |

## Phase 2: Complete Scanning Capabilities

| Task | Description | Priority |
|------|-------------|----------|
| UDP Scan | UDP port probing | P0 |
| Stealth Scan | FIN/NULL/Xmas scan | P1 |
| Host Discovery | ARP/ICMP/TCP Ping | P0 |
| Service Detection | Version detection (basic) | P1 |
| OS Detection | OS fingerprint identification | P1 |
| Traceroute | Route tracing | P2 |

## Phase 3: NSE Script Engine

| Task | Description | Priority |
|------|-------------|----------|
| Lua Integration | mlua/rulua bindings | P0 |
| Base Libraries | nmap, stdnse libraries | P0 |
| Network Libraries | socket, comm libraries | P0 |
| HTTP Library | http protocol support | P1 |
| SSL Library | ssl/tls support | P1 |
| Script Scheduling | Concurrent execution engine | P0 |
| NSE Compatibility | Load Nmap official scripts | P1 |

## Phase 4: Advanced Features and Optimization (Linux x86_64 Focus)

| Task | Description | Priority |
|------|-------------|----------|
| IPv6 Support | Complete IPv6 scanning (Linux kernel 3.0+) | P1 |
| Evasion Techniques | Fragmentation/decoy/spoofing | P2 |
| Performance Optimization | Large-scale scan optimization (PACKET_MMAP, eBPF) | P1 |
| Output Formats | XML/JSON/Grepable | P1 |
| Database Updates | Online fingerprint database updates | P2 |
| Linux-specific Optimization | CPU affinity, huge pages, XDP | P1 |
| systemd Integration | systemd service and socket activation | P2 |

## Phase 40: Packet Engine Architecture Redesign (P0 - Current)

> **Status**: Blocking all performance fixes
> **Reference**: `doc/modules/packet-engineering.md`, `task_plan.md`

**Problem**: `rustnmap-packet` claims PACKET_MMAP V3 but actually uses `recvfrom()` system call

| Task | Description | Priority |
|------|-------------|----------|
| Core Infrastructure | TPACKET_V2 structure definitions, syscall wrappers | P0 |
| Ring Buffer | mmap ring buffer management, frame iterator | P0 |
| Async Integration | AsyncFd wrapper, Channel dispatch, Stream trait | P0 |
| Scanner Migration | Migrate all scanners to PacketEngine trait | P0 |
| Test Verification | Unit tests, integration tests, nmap comparison tests | P0 |
| Documentation | API documentation, performance benchmarks | P1 |

**Architecture Decision**: Use TPACKET_V2 (not V3), referencing nmap's `libpcap/pcap-linux.c`

**Performance Target**: PPS 50K -> 1M (20x), CPU 80% -> 30% (2.7x)

---
# 7. Risks and Challenges (Linux x86_64 Platform)

| Risk Item | Impact | Mitigation |
|-----------|--------|------------|
| **Lua Compatibility** | High | Use mlua crate, maintain strict compatibility with Nmap NSE API; build comprehensive NSE script test suite |
| **Raw Socket Permissions** | Medium | Provide fallback (TCP Connect); prioritize Linux capabilities (CAP_NET_RAW); provide Docker containerized deployment; add permission detection and friendly error messages |
| **Kernel Version Compatibility** | Medium | Support Linux kernel 3.10+ (CentOS 7 baseline); feature detection with graceful degradation; document kernel version requirements for each feature |
| **SELinux/AppArmor Conflicts** | Medium | Provide security policy configuration profiles; document SELinux/AppArmor rule configuration; support auto-detection and configuration suggestions |
| **Fingerprint Database Maintenance** | Medium | Automated update mechanism; community contribution process; synchronization with Nmap official databases |
| **Performance Bottlenecks** | Medium | Async I/O (tokio); zero-copy packet processing (PACKET_MMAP); eBPF filters; CPU affinity binding; performance benchmarks |
| **Legal Compliance** | High | Clear terms of use; add authorization check functionality; emphasize legal use in documentation; add warning messages by default |
| **Docker Network Limitations** | Low | Provide `--privileged` or `--cap-add=NET_RAW` instructions; provide docker-compose examples; support host network mode |

---

# 8. Performance Metrics and Benchmarks (Linux x86_64)

## 8.1 Performance Targets

| Metric | Target Value | Nmap Reference | Description |
|--------|-------------|----------------|-------------|
| **Full Port Scan Speed** | <30s (1000 hosts) | ~60-120s | Scan all 65535 ports on 1000 hosts |
| **SYN Scan Throughput** | >10^6 pps | ~5x10^5 pps | Probes sent per second |
| **Host Discovery Latency** | <5s (/24 network) | ~5-10s | Discover all active hosts in /24 network |
| **Memory Usage** | <500MB (large-scale scan) | ~200-800MB | Peak memory when scanning /16 network |
| **Script Execution Overhead** | <10% | ~5-15% | Additional time from NSE scripts |
| **Startup Time** | <100ms | ~50-200ms | Program startup to scan begin |

## 8.2 Performance Optimization Strategies

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Performance Optimization Strategies                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Async I/O Architecture                                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ┌─────────────────┐      ┌─────────────────────────────────────┐│  │
│  │  │  tokio Runtime  │      │  Async Task per Host Group          ││  │
│  │  │  (Multi-thread) │      │  ├── Port Scan Task                 ││  │
│  │  │                 │      │  ├── Service Detection Task         ││  │
│  │  │  Work Stealing  │      │  └── Script Execution Task          ││  │
│  │  │  Scheduler      │      │                                     ││  │
│  │  └─────────────────┘      └─────────────────────────────────────┘│  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  2. Zero-Copy Packet Processing                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  Traditional (multiple copies):                                   │  │
│  │  Kernel → [Copy] → User Buffer → [Copy] → Parser → [Copy] → App │  │
│  │                                                                   │  │
│  │  Zero-copy:                                                       │  │
│  │  Kernel → mmap → User Buffer (Slice) → Parser (Slice) → App     │  │
│  │                                                                   │  │
│  │  Implementation: pnet + mmap or AF_XDP (Linux)                   │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  3. Batch Operations and Aggregation                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  Send Aggregation:                                                │  │
│  │  ├── sendmmsg() system call (batch send multiple packets)         │  │
│  │  └── Reduce syscall count: N packets → 1 syscall                 │  │
│  │                                                                   │  │
│  │  Receive Aggregation:                                             │  │
│  │  ├── recvmmsg() batch receive                                     │  │
│  │  └── Use PACKET_MMAP V2 (Linux, reference nmap libpcap)           │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  4. Intelligent Timeout Adjustment                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  RTT Sampling:                                                    │  │
│  │  ├── Collect RTT from first N responses                          │  │
│  │  ├── Compute statistics: min, max, mean, stddev                  │  │
│  │  └── Dynamic timeout: timeout = mean + 3 * stddev                │  │
│  │                                                                   │  │
│  │  Adaptive Retry:                                                  │  │
│  │  ├── Initial retry count: 2                                       │  │
│  │  ├── Gradually increase when no response                          │  │
│  │  └── Reduce retries when network conditions are good              │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  5. Lua JIT Optimization (NSE Performance)                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  ├── Use LuaJIT (via mlua)                                        │  │
│  │  ├── Pre-compile common scripts                                   │  │
│  │  ├── Cache Lua state machines (avoid repeated creation)           │  │
│  │  └── Script sandbox isolation (prevent scripts from affecting     │  │
│  │      the main process)                                            │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 8.3 Benchmark Framework

```
// ============================================
// Benchmark Framework Design
// ============================================

use criterion::{Criterion, black_box, BenchmarkId};

/// Performance Benchmark Suite
pub struct BenchmarkSuite {
    targets: Vec<TargetConfig>,
    metrics: MetricsCollector,
}

/// Test Scenarios
pub enum BenchmarkScenario {
    /// Single host full port scan
    SingleHostFullPort {
        target: IpAddr,
    },
    /// Multi-host quick scan
    MultiHostQuickScan {
        network: Ipv4Cidr,
        top_ports: usize,
    },
    /// Large-scale network discovery
    LargeNetworkDiscovery {
        network: Ipv4Cidr,
    },
    /// NSE script performance
    NseScriptExecution {
        scripts: Vec<String>,
        hosts: usize,
    },
    /// OS detection performance
    OsDetection {
        hosts: usize,
    },
}

impl BenchmarkSuite {
    pub fn run(&mut self, c: &mut Criterion) {
        // TCP SYN scan benchmark
        c.bench_function("tcp_syn_scan_1000_ports", |b| {
            b.iter(|| {
                self.bench_tcp_syn_scan(black_box(1000))
            })
        });

        // Host discovery benchmark
        c.bench_function("host_discovery_256", |b| {
            b.iter(|| {
                self.bench_host_discovery(black_box(256))
            })
        });

        // Parameterized benchmark: different concurrency levels
        let mut group = c.benchmark_group("concurrency_levels");
        for concurrency in [10, 50, 100, 500, 1000].iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(concurrency),
                concurrency,
                |b, &concurrency| {
                    b.iter(|| self.bench_concurrent_scan(concurrency))
                },
            );
        }
        group.finish();
    }
}
```

---

# 9. Security Considerations

## 9.1 Security Design Principles

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Security Design Principles                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Principle of Least Privilege                                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Request root/CAP_NET_RAW only when raw sockets are needed    │  │
│  │  ├── Drop privileges as soon as possible after scanning           │  │
│  │  ├── Support unprivileged scan mode (TCP Connect)                 │  │
│  │  └── Use regular user permissions for file operations              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  2. Input Validation                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Strictly validate all user input (targets, ports, params)    │  │
│  │  ├── Prevent command injection attacks                            │  │
│  │  ├── Limit input length and format                                │  │
│  │  └── Verify script source and integrity                           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  3. NSE Sandbox Isolation                                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Lua scripts run in restricted sandbox                        │  │
│  │  ├── Restrict filesystem access                                   │  │
│  │  ├── Restrict network access (scan targets only)                  │  │
│  │  ├── Limit script execution time                                  │  │
│  │  └── Limit script memory usage                                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  4. Memory Safety                                                       │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Rust guarantees memory safety (no buffer overflows)          │  │
│  │  ├── Strict handling of boundary conditions                       │  │
│  │  ├── Use safe FFI bindings                                        │  │
│  │  └── Regular security audits                                      │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  5. Sensitive Data Handling                                             │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Do not log sensitive information (passwords, keys, etc.)     │  │
│  │  ├── Securely clear temporary credentials from memory             │  │
│  │  ├── Encrypt stored configuration files                           │  │
│  │  └── Support output sanitization                                  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 9.2 NSE Sandbox Implementation

```
// ============================================
// NSE Sandbox Implementation
// ============================================

use mlua::{Lua, LuaOptions, StdLib};

/// NSE Sandbox Configuration
pub struct SandboxConfig {
    /// Allowed Lua standard libraries
    pub allowed_std_libs: StdLib,

    /// Whether to allow filesystem access
    pub allow_filesystem: bool,

    /// Whether to allow executing external commands
    pub allow_execute: bool,

    /// Maximum execution time (milliseconds)
    pub max_execution_time_ms: u64,

    /// Maximum memory usage (bytes)
    pub max_memory_bytes: usize,

    /// Allowed network targets
    pub allowed_targets: Vec<IpAddr>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            // Allow only safe standard libraries
            allowed_std_libs: StdLib::BASE
                | StdLib::TABLE
                | StdLib::STRING
                | StdLib::MATH
                | StdLib::UTF8,
            allow_filesystem: false,
            allow_execute: false,
            max_execution_time_ms: 30_000,  // 30 seconds
            max_memory_bytes: 64 * 1024 * 1024,  // 64 MB
            allowed_targets: vec![],
        }
    }
}

/// NSE Sandbox
pub struct NseSandbox {
    lua: Lua,
    config: SandboxConfig,
}

impl NseSandbox {
    /// Create a new sandbox environment
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        // Create restricted Lua state machine
        let lua = Lua::new_with(
            config.allowed_std_libs,
            LuaOptions::default()
                .thread_pool_size(4)
        )?;

        // Register safety-wrapped NSE libraries
        Self::register_safe_libraries(&lua, &config)?;

        Ok(Self { lua, config })
    }

    /// Register safe versions of NSE libraries
    fn register_safe_libraries(lua: &Lua, config: &SandboxConfig) -> Result<(), SandboxError> {
        // Register nmap library (restricted version)
        let nmap = lua.create_table()?;
        nmap.set("log_write", lua.create_function(|_, (level, msg): (u8, String)| {
            // Log output is monitored
            if level > 3 {
                return Err(mlua::Error::RuntimeError("Log level too verbose".into()));
            }
            println!("[NSE LOG {}] {}", level, msg);
            Ok(())
        })?)?;

        // Register restricted socket library
        let socket_lib = Self::create_safe_socket_library(lua, config)?;
        nmap.set("new_socket", socket_lib)?;

        lua.globals().set("nmap", nmap)?;

        // Register stdnse library
        let stdnse = Self::create_stdnse_library(lua)?;
        lua.globals().set("stdnse", stdnse)?;

        Ok(())
    }

    /// Create safe socket library
    fn create_safe_socket_library(lua: &Lua, config: &SandboxConfig) -> Result<mlua::Function, SandboxError> {
        let allowed_targets = config.allowed_targets.clone();

        lua.create_function(move |lua, ()| {
            let socket = lua.create_table()?;

            // Restricted connect method
            let allowed = allowed_targets.clone();
            socket.set("connect", lua.create_function(move |_, (host, port): (String, u16)| {
                // Verify target is in allowed list
                let ip: IpAddr = host.parse()
                    .map_err(|_| mlua::Error::RuntimeError("Invalid IP address".into()))?;

                if !allowed.is_empty() && !allowed.contains(&ip) {
                    return Err(mlua::Error::RuntimeError(
                        format!("Target {} not in allowed list", ip)
                    ));
                }

                // Execute actual connection...
                Ok(())
            })?)?;

            Ok(socket)
        })
        .map_err(SandboxError::from)
    }

    /// Execute script in sandbox
    pub fn execute_script(
        &self,
        script: &str,
        host: &HostInfo,
        port: Option<&PortInfo>,
    ) -> Result<ScriptResult, SandboxError> {
        // Set timeout
        let timeout = Duration::from_millis(self.config.max_execution_time_ms);

        let result = self.lua.load(script)
            .set_name("nse_script")?
            .exec();

        match result {
            Ok(value) => Ok(ScriptResult::from_lua_value(value)),
            Err(e) => Err(SandboxError::ExecutionError(e.to_string())),
        }
    }
}
```

---

# 10. Testing Strategy

## 10.1 Testing Pyramid

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Testing Pyramid                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                          ▲ E2E Tests                                    │
│                         ╱│╲                                             │
│                        ╱ │ ╲        • Real network environment scans     │
│                       ╱  │  ╲       • Cross-platform compatibility       │
│                      ╱   │   ╲      • Performance benchmarks             │
│                     ╱────┼────╲                                          │
│                    ╱ Integration│╲                                       │
│                   ╱  Tests      │ ╲    • Simulated network environment   │
│                  ╱              │  ╲   • Module interaction testing       │
│                 ╱───────────────┼───╲  • Database matching tests         │
│                ╱   Unit Tests   │     ╲                                  │
│               ╱                 │      ╲ • Function-level testing         │
│              ╱                  │       ╲• Packet parsing tests           │
│             ╱───────────────────┼────────╲• Algorithm correctness tests  │
│            ╱    Static Analysis │         ╲                             │
│           ╱                     │          ╲• Clippy lints              │
│          ╱──────────────────────┼───────────╲• rustfmt checks           │
│         ╱                       │            ╲• Security audits          │
│        ╱────────────────────────┼─────────────╲                          │
│       ╱         Fuzzing         │              ╲                         │
│      ╱                          │               ╲• Packet parsing fuzzing│
│     ╱───────────────────────────┼────────────────╲• Input handling fuzz  │
│    ╱                           │                  ╲                      │
│   ──────────────────────────────────────────────────────────────────    │
│                                                                         │
│   Test Coverage Targets:                                                │
│   ├── Unit Tests:       > 80%                                          │
│   ├── Integration:      > 60% (critical paths)                         │
│   └── E2E:              100% critical scenarios                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 10.2 Test Infrastructure

```
// ============================================
// Test Infrastructure Design
// ============================================

use mockall::automock;

/// Mock Network Interface
#[automock]
pub trait NetworkInterface {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetworkError>;
    async fn recv_packet(&self, timeout: Duration) -> Result<Option<RawPacket>, NetworkError>;
    fn set_filter(&mut self, filter: &str) -> Result<(), NetworkError>;
}

/// Test Environment Configuration
pub struct TestEnvironment {
    pub mock_network: MockNetworkInterface,
    pub test_targets: Vec<TestTarget>,
    pub test_database: TestDatabase,
}

/// Test Target (simulated responses)
pub struct TestTarget {
    pub ip: IpAddr,
    pub open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub responses: HashMap<ProbeType, Vec<u8>>,
}

/// Test Database (in-memory database)
pub struct TestDatabase {
    pub service_probes: Vec<ServiceProbe>,
    pub os_fingerprints: Vec<OsFingerprint>,
}

impl TestEnvironment {
    /// Create standard test environment
    pub fn standard() -> Self {
        Self {
            mock_network: MockNetworkInterface::new(),
            test_targets: vec![
                TestTarget {
                    ip: "192.168.1.1".parse().unwrap(),
                    open_ports: vec![22, 80, 443],
                    closed_ports: (1..1000).filter(|p| ![22, 80, 443].contains(p)).collect(),
                    filtered_ports: vec![],
                    responses: Self::standard_responses(),
                },
            ],
            test_database: TestDatabase::minimal(),
        }
    }

    /// Standard response templates
    fn standard_responses() -> HashMap<ProbeType, Vec<u8>> {
        let mut responses = HashMap::new();

        // TCP SYN-ACK response (port 80)
        responses.insert(
            ProbeType::TcpSyn { port: 80 },
            vec![/* TCP SYN-ACK packet bytes */],
        );

        // SSH Banner
        responses.insert(
            ProbeType::Banner { port: 22 },
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec(),
        );

        // HTTP Response
        responses.insert(
            ProbeType::HttpGet { port: 80 },
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n".to_vec(),
        );

        responses
    }
}

/// Unit test examples
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_tcp_syn_packet_builder() {
        let builder = PacketBuilder::new(
            "192.168.1.100".parse().unwrap(),
            MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );

        let packet = builder.build_tcp_syn(
            "192.168.1.1".parse().unwrap(),
            80,
            54321,
            1000,
            TcpOptions::default(),
        ).unwrap();

        // Verify packet length
        assert!(packet.len() >= 40); // IP header + TCP header

        // Verify SYN flag
        let tcp = TcpPacket::new(&packet[20..]).unwrap();
        assert!(tcp.get_flags() & TcpFlags::SYN != 0);
    }

    #[test]
    fn test_target_spec_parser() {
        let parser = TargetSpecParser::new(None);

        // Test CIDR parsing
        let result = parser.parse("192.168.1.0/30").unwrap();
        assert_eq!(result.total_count, 4); // 4 addresses

        // Test range parsing
        let result = parser.parse("192.168.1.1-10").unwrap();
        assert_eq!(result.total_count, 10);

        // Test mixed input
        let result = parser.parse("192.168.1.1,192.168.2.0/30").unwrap();
        assert_eq!(result.total_count, 5);
    }

    #[test]
    fn test_service_matcher() {
        let db = TestDatabase::minimal();
        let matcher = ServiceMatcher::new(db.service_probes);

        let response = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let result = matcher.match_response("GenericLines", response).unwrap();

        assert_eq!(result.service_name, "ssh");
        assert_eq!(result.product, Some("OpenSSH".to_string()));
        assert_eq!(result.version, Some("8.9p1 Ubuntu-3ubuntu0.1".to_string()));
    }
}

/// Integration test examples
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_full_scan_workflow() {
        let env = TestEnvironment::standard();
        let mut scanner = Scanner::with_network(Box::new(env.mock_network));

        // Execute full scan
        let result = scanner
            .target("192.168.1.1")
            .ports(PortSelection::Top(1000))
            .scan_type(ScanType::TcpSyn)
            .run()
            .await
            .unwrap();

        // Verify results
        assert_eq!(result.hosts.len(), 1);
        let host = &result.hosts[0];
        assert_eq!(host.ip, "192.168.1.1".parse().unwrap());
        assert_eq!(host.open_ports().len(), 3);
    }

    #[tokio::test]
    async fn test_nse_script_execution() {
        let env = TestEnvironment::standard();
        let sandbox = NseSandbox::new(SandboxConfig::default()).unwrap();

        let script = r#"
            action = function(host, port)
                return "Test output: " .. host.ip
            end
        "#;

        let host_info = HostInfo {
            ip: "192.168.1.1".parse().unwrap(),
            ..Default::default()
        };

        let result = sandbox.execute_script(script, &host_info, None).unwrap();
        assert!(result.output.contains("192.168.1.1"));
    }
}
```

## 10.3 Continuous Integration Configuration

```
# .github/workflows/ci.yml

name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

  test:
    runs-on: ${{ matrix.os }}
    needs: lint
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, beta]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      - name: Run tests
        run: cargo test --workspace --all-features
      - name: Run tests with coverage
        if: matrix.os == 'ubuntu-latest' && matrix.rust == 'stable'
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --workspace --out Xml
      - name: Upload coverage
        if: matrix.os == 'ubuntu-latest' && matrix.rust == 'stable'
        uses: codecov/codecov-action@v3
        with:
          files: cobertura.xml

  security-audit:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install cargo-audit
        run: cargo install cargo-audit
      - name: Security audit
        run: cargo audit

  benchmark:
    runs-on: ubuntu-latest
    needs: test
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Run benchmarks
        run: cargo bench --no-run
      - name: Store benchmark result
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'cargo'
          output-file-path: bench-results.json
          github-token: ${{ secrets.GITHUB_TOKEN }}
          auto-push: true
```

---

# 11. Documentation and User Support

## 11.1 Documentation Structure

```
docs/
├── README.md                    # Project introduction and quick start
├── INSTALLATION.md              # Installation guide
├── QUICKSTART.md                # Quick start guide
├── USER_GUIDE.md                # User manual
├── CLI_REFERENCE.md             # CLI command reference
├── NSE_GUIDE.md                 # NSE script development guide
│
├── api/                         # API documentation
│   ├── rustdoc/                 # Rust API documentation
│   └── lua/                     # Lua API documentation
│
├── tutorials/                   # Tutorials
│   ├── basic_scan.md
│   ├── service_detection.md
│   ├── os_fingerprinting.md
│   ├── nse_scripts.md
│   └── advanced_techniques.md
│
├── architecture/                # Architecture documentation
│   ├── overview.md
│   ├── packet_engine.md
│   ├── nse_engine.md
│   └── performance.md
│
├── examples/                    # Examples
│   ├── basic/
│   ├── advanced/
│   └── scripts/
│
└── changelog/                   # Change log
    ├── v1.0.0.md
    └── ...
```

## 11.2 Inline Help System

```
// ============================================
// Inline Help System
// ============================================

/// Command-line Help Generator
pub struct HelpGenerator {
    man_pages: HashMap<String, ManPage>,
}

/// Manual Page
pub struct ManPage {
    pub name: String,
    pub synopsis: String,
    pub description: String,
    pub options: Vec<HelpOption>,
    pub examples: Vec<Example>,
    pub see_also: Vec<String>,
}

impl HelpGenerator {
    /// Generate full help text
    pub fn generate(&self, topic: &str) -> String {
        let page = self.man_pages.get(topic).unwrap_or(&self.default_page());

        let mut help = String::new();

        help.push_str(&format!("NAME\n    {} - {}\n\n", page.name, page.synopsis));
        help.push_str(&format!("SYNOPSIS\n    {}\n\n", page.synopsis));
        help.push_str(&format!("DESCRIPTION\n{}\n\n", page.description));

        if !page.options.is_empty() {
            help.push_str("OPTIONS\n");
            for opt in &page.options {
                help.push_str(&format!("    {:<20} {}\n",
                    opt.short.as_ref().map(|s| format!("-{}", s)).unwrap_or_default()
                        + &opt.long.as_ref().map(|l| format!("--{}", l)).unwrap_or_default(),
                    opt.description
                ));
            }
            help.push_str("\n");
        }

        if !page.examples.is_empty() {
            help.push_str("EXAMPLES\n");
            for ex in &page.examples {
                help.push_str(&format!("    # {}\n    {}\n\n", ex.description, ex.command));
            }
        }

        help
    }

    /// Generate Markdown format documentation
    pub fn generate_markdown(&self, topic: &str) -> String {
        // Convert to Markdown format
        unimplemented!()
    }
}
```

---


# 12. Summary

## 12.1 Key Technology Stack Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Technology Stack Summary                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Language & Runtime                                             │   │
│  │  ├── Rust 1.75+ (Edition 2021)                                  │   │
│  │  ├── Lua 5.4 / LuaJIT (NSE scripts)                            │   │
│  │  └── tokio (Async Runtime)                                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Key Dependencies                                               │   │
│  │  ├── mlua (Lua FFI)                    ├── pnet (Packet I/O)    │   │
│  │  ├── clap (CLI Parsing)                ├── pcap (Capture)       │   │
│  │  ├── serde (Serialization)             ├── regex (Matching)     │   │
│  │  ├── trust-dns (DNS Resolution)        ├── rustls (TLS/SSL)     │   │
│  │  └── socket2 (Socket Control)          └── chrono (Time)        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Development Tools                                              │   │
│  │  ├── cargo (Build System)              ├── criterion (Bench)    │   │
│  │  ├── clippy (Linter)                   ├── tarpaulin (Coverage) │   │
│  │  ├── rustfmt (Formatter)               └── nextest (Test Runner)│   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Infrastructure                                                 │   │
│  │  ├── GitHub Actions (CI/CD)            ├── Docker Hub           │   │
│  │  ├── crates.io (Distribution)          ├── GitHub Pages (Docs)  │   │
│  │  └── Codecov (Coverage)                └── Security Audit       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 12.2 Milestone Timeline

```
═══════════════════════════════════════════════════════════════════════════
                           Project Timeline
═══════════════════════════════════════════════════════════════════════════

  2026 Q1          2026 Q2          2026 Q3          2026 Q4
    │                │                │                │
    ▼                ▼                ▼                ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│  Phase 1  │  │  Phase 2  │  │  Phase 3  │  │  Phase 4  │
│   MVP     │  │  Full Scan│  │ NSE Engine│  │  Advanced │
│           │  │           │  │           │  │           │
│ • CLI     │  │ • UDP Scan│  │ • Lua     │  │ • IPv6    │
│ • Target  │  │ • Stealth │  │ • Base Lib│  │ • Evasion │
│ • TCP SYN │  │ • Host    │  │ • HTTP Lib│  │ • Perf Opt│
│ • Output  │  │ • Service │  │ • Sched   │  │ • Platform│
│           │  │ • OS Det  │  │ • NSE Cmp │  │ • Release │
└───────────┘  └───────────┘  └───────────┘  └───────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
   Alpha         Beta 1         Beta 2         v1.0.0
  Release       Release       Release        Release

═══════════════════════════════════════════════════════════════════════════
```

---
