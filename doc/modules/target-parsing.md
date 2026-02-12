## 3.9 目标规格与解析模块

对应 Nmap 命令: 目标 IP/主机名、`-iL`、`-iR`、`--exclude`、`--excludefile`

### 3.9.1 目标解析流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Target Specification Parser                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  输入格式支持:                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  格式类型          │ 示例                         │ 解析方法      │  │
│  ├────────────────────┼──────────────────────────────┼───────────────┤  │
│  │  单个 IP           │ 192.168.1.1                  │ parse_ipv4    │  │
│  │  IPv6 地址         │ 2001:db8::1                  │ parse_ipv6    │  │
│  │  主机名            │ example.com                  │ dns_resolve   │  │
│  │  CIDR 块           │ 192.168.1.0/24               │ expand_cidr   │  │
│  │  IP 范围           │ 192.168.1.1-10               │ expand_range  │  │
│  │  IP 掩码           │ 192.168.1.0/255.255.255.0    │ expand_mask   │  │
│  │  八位组通配        │ 192.168.1.*                   │ expand_wild   │  │
│  │  多目标            │ 192.168.1.1,192.168.2.1      │ split_parse   │  │
│  │  端口指定          │ example.com:80,443           │ parse_target  │  │
│  │  从文件读取        │ -iL targets.txt              │ read_file     │  │
│  │  随机目标          │ -iR 100                      │ random_ips    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  解析流程:                                                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │  │
│  │   │  Raw Input  │───▶│  Tokenizer  │───▶│  Target Expander   │  │  │
│  │   │  (String)   │    │             │    │                     │  │  │
│  │   └─────────────┘    └─────────────┘    └──────────┬──────────┘  │  │
│  │                                                    │              │  │
│  │   ┌────────────────────────────────────────────────▼──────────┐  │  │
│  │   │                   DNS Resolver (Optional)                 │  │  │
│  │   │                                                           │  │  │
│  │   │  -n:   Skip DNS resolution                                │  │  │
│  │   │  -R:   Always resolve (including PTR for all IPs)         │  │  │
│  │   │  --dns-servers: Custom DNS servers                        │  │  │
│  │   │                                                           │  │  │
│  │   └──────────────────────────────────┬───────────────────────┘  │  │
│  │                                      │                          │  │
│  │   ┌──────────────────────────────────▼───────────────────────┐  │  │
│  │   │                   Target Filter                           │  │  │
│  │   │                                                           │  │  │
│  │   │  Apply --exclude and --excludefile rules                  │  │  │
│  │   │  Remove duplicates                                        │  │  │
│  │   │  Prune local addresses (if scanning remote only)          │  │  │
│  │   │                                                           │  │  │
│  │   └──────────────────────────────────┬───────────────────────┘  │  │
│  │                                      │                          │  │
│  │   ┌──────────────────────────────────▼───────────────────────┐  │  │
│  │   │                   TargetGroup                             │  │  │
│  │   │                                                           │  │  │
│  │   │  Vec<Target> { ip, hostname, ports_to_scan, ... }        │  │  │
│  │   │                                                           │  │  │
│  │   └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.9.2 目标规格类型定义

```
// ============================================
// Target Specification Types
// ============================================

/// 目标规格解析器
pub struct TargetSpecParser {
    dns_resolver: Option<DnsResolver>,
    exclude_list: Vec<TargetSpec>,
}

/// 单个目标
pub struct Target {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ports: Option<Vec<u16>>,  // 如果指定，覆盖全局端口
    pub ipv6_scope: Option<u8>,    // IPv6 zone ID
}

/// 目标规格 (解析前)
pub enum TargetSpec {
    SingleIpv4(Ipv4Addr),
    SingleIpv6(Ipv6Addr),
    Hostname(String),
    Ipv4Cidr { base: Ipv4Addr, prefix: u8 },
    Ipv6Cidr { base: Ipv6Addr, prefix: u8 },
    Ipv4Range { start: Ipv4Addr, end: Ipv4Addr },
    Ipv4Mask { base: Ipv4Addr, mask: Ipv4Addr },
    Ipv4OctetRange { 
        octets: [Option<OctetSpec>; 4] 
    },
    WithPort(Box<TargetSpec>, Vec<u16>),
    Multiple(Vec<TargetSpec>),
}

/// 八位组规格 (用于 192.168.1-10.* 类型的解析)
pub enum OctetSpec {
    Single(u8),
    Range(u8, u8),
    All,
}

/// 目标组 (扫描器的输入)
pub struct TargetGroup {
    pub targets: Vec<Target>,
    pub total_count: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub statistics: TargetStats,
}

impl TargetSpecParser {
    /// 解析输入字符串
    pub fn parse(&self, input: &str) -> Result<TargetGroup, ParseError> {
        let mut targets = Vec::new();
        
        // 1. 标准化输入 (处理换行、逗号等)
        let tokens = self.tokenize(input)?;
        
        // 2. 解析每个 token
        for token in tokens {
            let spec = self.parse_token(&token)?;
            
            // 3. 展开为具体 IP 列表
            let expanded = self.expand_spec(&spec)?;
            
            // 4. DNS 解析 (如果需要)
            for mut target in expanded {
                if let Some(ref resolver) = self.dns_resolver {
                    if target.hostname.is_none() {
                        target.hostname = resolver.reverse_lookup(target.ip)?;
                    }
                }
                targets.push(target);
            }
        }
        
        // 5. 应用排除规则
        targets.retain(|t| !self.is_excluded(t));
        
        // 6. 去重
        targets.sort_by(|a, b| a.ip.cmp(&b.ip));
        targets.dedup_by(|a, b| a.ip == b.ip);
        
        Ok(TargetGroup {
            ipv4_count: targets.iter().filter(|t| t.ip.is_ipv4()).count(),
            ipv6_count: targets.iter().filter(|t| t.ip.is_ipv6()).count(),
            total_count: targets.len(),
            targets,
            statistics: TargetStats::default(),
        })
    }
    
    /// 展开目标规格
    fn expand_spec(&self, spec: &TargetSpec) -> Result<Vec<Target>, ParseError> {
        match spec {
            TargetSpec::SingleIpv4(ip) => Ok(vec![Target::from(*ip)]),
            TargetSpec::SingleIpv6(ip) => Ok(vec![Target::from(*ip)]),
            TargetSpec::Hostname(name) => self.resolve_hostname(name),
            TargetSpec::Ipv4Cidr { base, prefix } => self.expand_cidr_v4(base, prefix),
            TargetSpec::Ipv4Range { start, end } => self.expand_range_v4(start, end),
            TargetSpec::Ipv4OctetRange { octets } => self.expand_octets(octets),
            // ... 其他展开逻辑
            _ => unimplemented!(),
        }
    }
    
    /// 展开八位组范围 (如 192.168.1-10.*)
    fn expand_octets(&self, octets: &[Option<OctetSpec>; 4]) -> Result<Vec<Target>, ParseError> {
        let mut results = Vec::new();
        let mut current = [0u8; 4];
        
        self.expand_octet_recursive(octets, &mut current, 0, &mut results);
        
        Ok(results.into_iter().map(|o| Target::from(Ipv4Addr::from(o))).collect())
    }
    
    fn expand_octet_recursive(
        &self,
        octets: &[Option<OctetSpec>; 4],
        current: &mut [u8; 4],
        depth: usize,
        results: &mut Vec<[u8; 4]>,
    ) {
        if depth == 4 {
            results.push(*current);
            return;
        }
        
        if let Some(ref spec) = octets[depth] {
            match spec {
                OctetSpec::Single(v) => {
                    current[depth] = *v;
                    self.expand_octet_recursive(octets, current, depth + 1, results);
                }
                OctetSpec::Range(s, e) => {
                    for v in *s..=*e {
                        current[depth] = v;
                        self.expand_octet_recursive(octets, current, depth + 1, results);
                    }
                }
                OctetSpec::All => {
                    for v in 0..=255 {
                        current[depth] = v;
                        self.expand_octet_recursive(octets, current, depth + 1, results);
                    }
                }
            }
        }
    }
}
```

---

