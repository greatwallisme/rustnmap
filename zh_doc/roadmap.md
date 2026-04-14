# 6. 开发路线图

## Phase 1: 基础架构 (MVP)

**预计周期: 4-6 周**

|任务|描述|优先级|
|---|---|---|
|CLI 框架|集成 clap，参数解析|P0|
|目标解析|IP/主机名/CIDR 解析|P0|
|原始套接字|Linux raw socket 支持|P0|
|TCP SYN 扫描|实现核心扫描能力|P0|
|TCP Connect|用户态扫描支持|P0|
|基础输出|Normal 格式输出|P0|

## Phase 2: 完整扫描功能

|任务|描述|优先级|
|---|---|---|
|UDP 扫描|UDP 端口探测|P0|
|隐蔽扫描|FIN/NULL/Xmas 扫描|P1|
|主机发现|ARP/ICMP/TCP Ping|P0|
|服务探测|版本检测 (基础)|P1|
|OS 检测|操作系统指纹识别|P1|
|Traceroute|路由追踪|P2|

## Phase 3: NSE 脚本引擎

|任务|描述|优先级|
|---|---|---|
|Lua 集成|mlua/rulua 绑定|P0|
|基础库|nmap, stdnse 库|P0|
|网络库|socket, comm 库|P0|
|HTTP 库|http 协议支持|P1|
|SSL 库|ssl/tls 支持|P1|
|脚本调度|并发执行引擎|P0|
|NSE 兼容|加载 Nmap 官方脚本|P1|

## Phase 4: 高级功能与优化 (Linux x86_64 专注)

|任务|描述|优先级|
|---|---|---|
|IPv6 支持|完整 IPv6 扫描 (Linux 内核 3.0+)|P1|
|规避技术|分片/诱饵/欺骗|P2|
|性能优化|大规模扫描优化 (PACKET_MMAP, eBPF)|P1|
|输出格式|XML/JSON/Grepable|P1|
|数据库更新|在线更新指纹库|P2|
|Linux 特性优化|CPU 亲和性、大页内存、XDP|P1|
|systemd 集成|systemd service 和 socket 激活|P2|

## Phase 40: 数据包引擎架构重设计 (P0 - 当前)

> **Status**: 阻塞所有性能修复
> **Reference**: `doc/modules/packet-engineering.md`, `task_plan.md`

**问题**: `rustnmap-packet` 声称 PACKET_MMAP V3 但实际使用 `recvfrom()` 系统调用

| 任务 | 描述 | 优先级 |
|------|------|--------|
| 核心基础设施 | TPACKET_V2 结构定义、syscall 包装 | P0 |
| Ring Buffer | mmap 环形缓冲区管理、帧迭代器 | P0 |
| Async 集成 | AsyncFd 包装、Channel 分发、Stream trait | P0 |
| Scanner 迁移 | 将所有扫描器迁移到 PacketEngine trait | P0 |
| 测试验证 | 单元测试、集成测试、nmap 对比测试 | P0 |
| 文档完善 | API 文档、性能基准 | P1 |

**架构决策**: 使用 TPACKET_V2 (非 V3)，参考 nmap 的 `libpcap/pcap-linux.c`

**性能目标**: PPS 50K → 1M (20x), CPU 80% → 30% (2.7x)

---
# 7. 风险与挑战 (Linux x86_64 平台)

|风险项|影响程度|缓解措施|
|---|---|---|
|**Lua 兼容性**|高|使用 mlua crate，保持与 Nmap NSE API 的严格兼容；建立完整的 NSE 脚本测试套件|
|**原始套接字权限**|中|提供降级方案（TCP Connect）；优先使用 Linux capabilities (CAP_NET_RAW)；提供 Docker 容器化部署；添加权限检测和友好的错误提示|
|**内核版本兼容性**|中|支持 Linux 内核 3.10+ (CentOS 7 基线)；特性检测机制，优雅降级；在文档中明确标注各特性所需内核版本|
|**SELinux/AppArmor 冲突**|中|提供安全策略配置文件；文档说明如何配置 SELinux/AppArmor 规则；支持自动检测和配置建议|
|**指纹库维护**|中|自动化更新机制；社区贡献流程；与 Nmap 官方数据库同步|
|**性能瓶颈**|中|异步 I/O (tokio)；零拷贝数据包处理 (PACKET_MMAP)；eBPF 过滤器；CPU 亲和性绑定；性能基准测试|
|**法律合规**|高|明确使用条款；添加授权检查功能；文档中强调合法使用；默认添加警告提示|
|**Docker 网络限制**|低|提供 `--privileged` 或 `--cap-add=NET_RAW` 说明；提供 docker-compose 示例；支持 host 网络模式|

---

# 8. 性能指标与基准 (Linux x86_64)

## 8.1 性能目标

|指标|目标值|Nmap 参考值|说明|
|---|---|---|---|
|**全端口扫描速度**|<30s (1000 hosts)|∼60−120s|单机扫描 1000 主机的 65535 端口|
|**SYN 扫描吞吐**|>106 pps|∼5×105 pps|每秒发送的探测包数|
|**主机发现延迟**|<5s (/24 网络)|∼5−10s|发现 /24 网络所有活跃主机|
|**内存占用**|<500MB (大规模扫描)|∼200−800MB|扫描 /16 网络时的峰值内存|
|**脚本执行开销**|<10%|∼5−15%|NSE 脚本带来的额外时间|
|**启动时间**|<100ms|∼50−200ms|程序启动到开始扫描|

## 8.2 性能优化策略

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Performance Optimization Strategies                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 异步 I/O 架构                                                       │
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
│  2. 零拷贝数据包处理                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  传统方式 (多次拷贝):                                             │  │
│  │  Kernel → [Copy] → User Buffer → [Copy] → Parser → [Copy] → App  │  │
│  │                                                                   │  │
│  │  零拷贝方式:                                                      │  │
│  │  Kernel → mmap → User Buffer (Slice) → Parser (Slice) → App      │  │
│  │                                                                   │  │
│  │  实现: 使用 pnet + mmap 或 AF_XDP (Linux)                        │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  3. 批量操作与聚合                                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  发送聚合:                                                        │  │
│  │  ├── sendmmsg() 系统调用 (批量发送多个数据包)                     │  │
│  │  └── 减少 syscall 次数: N 个包 → 1 次 syscall                    │  │
│  │                                                                   │  │
│  │  接收聚合:                                                        │  │
│  │  ├── recvmmsg() 批量接收                                         │  │
│  │  └── 使用 PACKET_MMAP V2 (Linux, 参考 nmap libpcap)              │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  4. 智能超时调整                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  RTT 采样:                                                        │  │
│  │  ├── 收集前 N 个响应的 RTT                                        │  │
│  │  ├── 计算统计: min, max, mean, stddev                            │  │
│  │  └── 动态调整超时: timeout = mean + 3 * stddev                   │  │
│  │                                                                   │  │
│  │  自适应重试:                                                      │  │
│  │  ├── 初始重试次数: 2                                              │  │
│  │  ├── 无响应时逐步增加                                             │  │
│  │  └── 网络良好时减少重试                                           │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  5. Lua JIT 优化 (NSE 性能)                                             │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │  ├── 使用 LuaJIT (通过 mlua)                                      │  │
│  │  ├── 预编译常用脚本                                               │  │
│  │  ├── 缓存 Lua 状态机 (避免重复创建)                               │  │
│  │  └── 脚本沙箱隔离 (防止脚本影响主进程)                            │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 8.3 基准测试框架

```
// ============================================
// Benchmark Framework Design
// ============================================

use criterion::{Criterion, black_box, BenchmarkId};

/// 性能基准测试套件
pub struct BenchmarkSuite {
    targets: Vec<TargetConfig>,
    metrics: MetricsCollector,
}

/// 测试场景
pub enum BenchmarkScenario {
    /// 单机全端口扫描
    SingleHostFullPort {
        target: IpAddr,
    },
    /// 多主机快速扫描
    MultiHostQuickScan {
        network: Ipv4Cidr,
        top_ports: usize,
    },
    /// 大规模网络发现
    LargeNetworkDiscovery {
        network: Ipv4Cidr,
    },
    /// NSE 脚本性能
    NseScriptExecution {
        scripts: Vec<String>,
        hosts: usize,
    },
    /// OS 检测性能
    OsDetection {
        hosts: usize,
    },
}

impl BenchmarkSuite {
    pub fn run(&mut self, c: &mut Criterion) {
        // TCP SYN 扫描基准
        c.bench_function("tcp_syn_scan_1000_ports", |b| {
            b.iter(|| {
                self.bench_tcp_syn_scan(black_box(1000))
            })
        });
        
        // 主机发现基准
        c.bench_function("host_discovery_256", |b| {
            b.iter(|| {
                self.bench_host_discovery(black_box(256))
            })
        });
        
        // 参数化基准: 不同并发级别
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

# 9. 安全考量

## 9.1 安全设计原则

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Security Design Principles                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 最小权限原则                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── 仅在需要原始套接字时请求 root/CAP_NET_RAW                    │  │
│  │  ├── 扫描完成后尽可能丢弃特权                                     │  │
│  │  ├── 支持非特权扫描模式                    │  │
│  │  └── 文件操作使用普通用户权限                                     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  2. 输入验证                                                            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── 严格验证所有用户输入 (目标、端口、参数等)                    │  │
│  │  ├── 防止命令注入攻击                                             │  │
│  │  ├── 限制输入长度和格式                                           │  │
│  │  └── 验证脚本来源和完整性                                         │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  3. NSE 沙箱隔离                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Lua 脚本运行在受限沙箱中                                     │  │
│  │  ├── 限制文件系统访问                                             │  │
│  │  ├── 限制网络访问 (仅允许扫描目标)                                │  │
│  │  ├── 限制脚本执行时间                                             │  │
│  │  └── 限制脚本内存使用                                             │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  4. 内存安全                                                            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── Rust 保证内存安全 (无缓冲区溢出)                             │  │
│  │  ├── 严格处理边界条件                                             │  │
│  │  ├── 使用安全的 FFI 绑定                                          │  │
│  │  └── 定期安全审计                                                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  5. 敏感数据处理                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ├── 不在日志中记录敏感信息 (密码、密钥等)                        │  │
│  │  ├── 安全清理内存中的临时凭证                                     │  │
│  │  ├── 加密存储的配置文件                                           │  │
│  │  └── 支持输出脱敏                                                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 9.2 NSE 沙箱实现

```
// ============================================
// NSE Sandbox Implementation
// ============================================

use mlua::{Lua, LuaOptions, StdLib};

/// NSE 沙箱配置
pub struct SandboxConfig {
    /// 允许的 Lua 标准库
    pub allowed_std_libs: StdLib,
    
    /// 是否允许文件系统访问
    pub allow_filesystem: bool,
    
    /// 是否允许执行外部命令
    pub allow_execute: bool,
    
    /// 最大执行时间 (毫秒)
    pub max_execution_time_ms: u64,
    
    /// 最大内存使用 (字节)
    pub max_memory_bytes: usize,
    
    /// 允许的网络目标
    pub allowed_targets: Vec<IpAddr>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            // 仅允许安全的标准库
            allowed_std_libs: StdLib::BASE 
                | StdLib::TABLE 
                | StdLib::STRING 
                | StdLib::MATH
                | StdLib::UTF8,
            allow_filesystem: false,
            allow_execute: false,
            max_execution_time_ms: 30_000,  // 30 秒
            max_memory_bytes: 64 * 1024 * 1024,  // 64 MB
            allowed_targets: vec![],
        }
    }
}

/// NSE 沙箱
pub struct NseSandbox {
    lua: Lua,
    config: SandboxConfig,
}

impl NseSandbox {
    /// 创建新的沙箱环境
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        // 创建受限的 Lua 状态机
        let lua = Lua::new_with(
            config.allowed_std_libs,
            LuaOptions::default()
                .thread_pool_size(4)
        )?;
        
        // 注册安全封装的 NSE 库
        Self::register_safe_libraries(&lua, &config)?;
        
        Ok(Self { lua, config })
    }
    
    /// 注册安全版本的 NSE 库
    fn register_safe_libraries(lua: &Lua, config: &SandboxConfig) -> Result<(), SandboxError> {
        // 注册 nmap 库 (受限版本)
        let nmap = lua.create_table()?;
        nmap.set("log_write", lua.create_function(|_, (level, msg): (u8, String)| {
            // 日志输出受监控
            if level > 3 {
                return Err(mlua::Error::RuntimeError("Log level too verbose".into()));
            }
            println!("[NSE LOG {}] {}", level, msg);
            Ok(())
        })?)?;
        
        // 注册受限的 socket 库
        let socket_lib = Self::create_safe_socket_library(lua, config)?;
        nmap.set("new_socket", socket_lib)?;
        
        lua.globals().set("nmap", nmap)?;
        
        // 注册 stdnse 库
        let stdnse = Self::create_stdnse_library(lua)?;
        lua.globals().set("stdnse", stdnse)?;
        
        Ok(())
    }
    
    /// 创建安全的 socket 库
    fn create_safe_socket_library(lua: &Lua, config: &SandboxConfig) -> Result<mlua::Function, SandboxError> {
        let allowed_targets = config.allowed_targets.clone();
        
        lua.create_function(move |lua, ()| {
            let socket = lua.create_table()?;
            
            // 受限的 connect 方法
            let allowed = allowed_targets.clone();
            socket.set("connect", lua.create_function(move |_, (host, port): (String, u16)| {
                // 验证目标是否在允许列表中
                let ip: IpAddr = host.parse()
                    .map_err(|_| mlua::Error::RuntimeError("Invalid IP address".into()))?;
                
                if !allowed.is_empty() && !allowed.contains(&ip) {
                    return Err(mlua::Error::RuntimeError(
                        format!("Target {} not in allowed list", ip)
                    ));
                }
                
                // 执行实际的连接...
                Ok(())
            })?)?;
            
            Ok(socket)
        })
        .map_err(SandboxError::from)
    }
    
    /// 在沙箱中执行脚本
    pub fn execute_script(
        &self, 
        script: &str, 
        host: &HostInfo,
        port: Option<&PortInfo>,
    ) -> Result<ScriptResult, SandboxError> {
        // 设置超时
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

# 10. 测试策略

## 10.1 测试金字塔

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Testing Pyramid                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                          ▲ E2E Tests                                    │
│                         ╱│╲                                             │
│                        ╱ │ ╲        • 真实网络环境扫描                   │
│                       ╱  │  ╲       • 跨平台兼容性测试                   │
│                      ╱   │   ╲      • 性能基准测试                       │
│                     ╱────┼────╲                                          │
│                    ╱ Integration│╲                                       │
│                   ╱  Tests      │ ╲    • 模拟网络环境                    │
│                  ╱              │  ╲   • 模块间交互测试                  │
│                 ╱───────────────┼───╲  • 数据库匹配测试                  │
│                ╱   Unit Tests   │     ╲                                  │
│               ╱                 │      ╲ • 函数级别测试                  │
│              ╱                  │       ╲• 数据包解析测试                │
│             ╱───────────────────┼────────╲• 算法正确性测试               │
│            ╱    Static Analysis │         ╲                             │
│           ╱                     │          ╲• Clippy lints              │
│          ╱──────────────────────┼───────────╲• rustfmt 检查             │
│         ╱                       │            ╲• 安全审计                 │
│        ╱────────────────────────┼─────────────╲                          │
│       ╱         Fuzzing         │              ╲                         │
│      ╱                          │               ╲• 数据包解析模糊测试    │
│     ╱───────────────────────────┼────────────────╲• 输入处理模糊测试     │
│    ╱                           │                  ╲                      │
│   ──────────────────────────────────────────────────────────────────    │
│                                                                         │
│   测试覆盖率目标:                                                       │
│   ├── Unit Tests:       > 80%                                          │
│   ├── Integration:      > 60% (关键路径)                               │
│   └── E2E:              关键场景 100%                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 10.2 测试基础设施

```
// ============================================
// Test Infrastructure Design
// ============================================

use mockall::automock;

/// 模拟网络接口
#[automock]
pub trait NetworkInterface {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), NetworkError>;
    async fn recv_packet(&self, timeout: Duration) -> Result<Option<RawPacket>, NetworkError>;
    fn set_filter(&mut self, filter: &str) -> Result<(), NetworkError>;
}

/// 测试环境配置
pub struct TestEnvironment {
    pub mock_network: MockNetworkInterface,
    pub test_targets: Vec<TestTarget>,
    pub test_database: TestDatabase,
}

/// 测试目标 (模拟响应)
pub struct TestTarget {
    pub ip: IpAddr,
    pub open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub responses: HashMap<ProbeType, Vec<u8>>,
}

/// 测试数据库 (内存数据库)
pub struct TestDatabase {
    pub service_probes: Vec<ServiceProbe>,
    pub os_fingerprints: Vec<OsFingerprint>,
}

impl TestEnvironment {
    /// 创建标准测试环境
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
    
    /// 标准响应模板
    fn standard_responses() -> HashMap<ProbeType, Vec<u8>> {
        let mut responses = HashMap::new();
        
        // TCP SYN-ACK 响应 (端口 80)
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

/// 单元测试示例
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
        
        // 验证包长度
        assert!(packet.len() >= 40); // IP header + TCP header
        
        // 验证 SYN 标志
        let tcp = TcpPacket::new(&packet[20..]).unwrap();
        assert!(tcp.get_flags() & TcpFlags::SYN != 0);
    }
    
    #[test]
    fn test_target_spec_parser() {
        let parser = TargetSpecParser::new(None);
        
        // 测试 CIDR 解析
        let result = parser.parse("192.168.1.0/30").unwrap();
        assert_eq!(result.total_count, 4); // 4 个地址
        
        // 测试范围解析
        let result = parser.parse("192.168.1.1-10").unwrap();
        assert_eq!(result.total_count, 10);
        
        // 测试混合输入
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

/// 集成测试示例
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_full_scan_workflow() {
        let env = TestEnvironment::standard();
        let mut scanner = Scanner::with_network(Box::new(env.mock_network));
        
        // 执行完整扫描
        let result = scanner
            .target("192.168.1.1")
            .ports(PortSelection::Top(1000))
            .scan_type(ScanType::TcpSyn)
            .run()
            .await
            .unwrap();
        
        // 验证结果
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

## 10.3 持续集成配置

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

# 11. 文档与用户支持

## 11.1 文档结构

```
docs/
├── README.md                    # 项目介绍与快速开始
├── INSTALLATION.md              # 安装指南
├── QUICKSTART.md                # 快速入门
├── USER_GUIDE.md                # 用户手册
├── CLI_REFERENCE.md             # CLI 命令参考
├── NSE_GUIDE.md                 # NSE 脚本开发指南
│
├── api/                         # API 文档
│   ├── rustdoc/                 # Rust API 文档
│   └── lua/                     # Lua API 文档
│
├── tutorials/                   # 教程
│   ├── basic_scan.md
│   ├── service_detection.md
│   ├── os_fingerprinting.md
│   ├── nse_scripts.md
│   └── advanced_techniques.md
│
├── architecture/                # 架构文档
│   ├── overview.md
│   ├── packet_engine.md
│   ├── nse_engine.md
│   └── performance.md
│
├── examples/                    # 示例
│   ├── basic/
│   ├── advanced/
│   └── scripts/
│
└── changelog/                   # 变更日志
    ├── v1.0.0.md
    └── ...
```

## 11.2 在线帮助系统

```
// ============================================
// Inline Help System
// ============================================

/// 命令行帮助生成器
pub struct HelpGenerator {
    man_pages: HashMap<String, ManPage>,
}

/// 手册页
pub struct ManPage {
    pub name: String,
    pub synopsis: String,
    pub description: String,
    pub options: Vec<HelpOption>,
    pub examples: Vec<Example>,
    pub see_also: Vec<String>,
}

impl HelpGenerator {
    /// 生成完整帮助文本
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
    
    /// 生成 Markdown 格式文档
    pub fn generate_markdown(&self, topic: &str) -> String {
        // 转换为 Markdown 格式
        unimplemented!()
    }
}
```

---


# 12. 总结

## 12.1 关键技术栈总结

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Technology Stack Summary                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Language & Runtime                                             │   │
│  │  ├── Rust 1.75+ (Edition 2021)                                  │   │
│  │  ├── Lua 5.4 / LuaJIT (NSE 脚本)                               │   │
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

## 12.2 里程碑时间线

```
═══════════════════════════════════════════════════════════════════════════
                           Project Timeline
═══════════════════════════════════════════════════════════════════════════

  2026 Q1          2026 Q2          2026 Q3          2026 Q4
    │                │                │                │
    ▼                ▼                ▼                ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│  Phase 1  │  │  Phase 2  │  │  Phase 3  │  │  Phase 4  │
│   MVP     │  │  完整扫描  │  │ NSE 引擎  │  │ 高级功能  │
│           │  │           │  │           │  │           │
│ • CLI框架 │  │ • UDP扫描 │  │ • Lua集成 │  │ • IPv6    │
│ • 目标解析│  │ • 隐蔽扫描│  │ • 基础库  │  │ • 规避技术│
│ • TCP SYN │  │ • 主机发现│  │ • HTTP库  │  │ • 性能优化│
│ • 基础输出│  │ • 服务探测│  │ • 脚本调度│  │ • 跨平台  │
│           │  │ • OS检测  │  │ • NSE兼容 │  │ • 正式发布│
└───────────┘  └───────────┘  └───────────┘  └───────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
   Alpha         Beta 1         Beta 2         v1.0.0
  Release       Release       Release        Release

═══════════════════════════════════════════════════════════════════════════
```

---

