## 3.9 Target Specification and Parsing Module

Corresponding Nmap commands: target IP/hostname, `-iL`, `-iR`, `--exclude`, `--excludefile`

### 3.9.1 Target Parsing Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Target Specification Parser                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Supported input formats:                                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Format Type       │ Example                      │ Parser Method │  │
│  ├────────────────────┼──────────────────────────────┼───────────────┤  │
│  │  Single IP         │ 192.168.1.1                  │ parse_ipv4    │  │
│  │  IPv6 address      │ 2001:db8::1                  │ parse_ipv6    │  │
│  │  Hostname          │ example.com                  │ dns_resolve   │  │
│  │  CIDR block        │ 192.168.1.0/24               │ expand_cidr   │  │
│  │  IP range          │ 192.168.1.1-10               │ expand_range  │  │
│  │  IP mask           │ 192.168.1.0/255.255.255.0    │ expand_mask   │  │
│  │  Octet wildcard    │ 192.168.1.*                   │ expand_wild   │  │
│  │  Multiple targets  │ 192.168.1.1,192.168.2.1      │ split_parse   │  │
│  │  Port specification│ example.com:80,443           │ parse_target  │  │
│  │  Read from file    │ -iL targets.txt              │ read_file     │  │
│  │  Random targets    │ -iR 100                      │ random_ips    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Parsing flow:                                                          │
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

### 3.9.2 Target Specification Type Definitions

```
// ============================================
// Target Specification Types
// ============================================

/// Target specification parser
pub struct TargetSpecParser {
    dns_resolver: Option<DnsResolver>,
    exclude_list: Vec<TargetSpec>,
}

/// Single target
pub struct Target {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ports: Option<Vec<u16>>,  // If specified, overrides global ports
    pub ipv6_scope: Option<u8>,    // IPv6 zone ID
}

/// Target specification (before parsing)
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

/// Octet specification (for parsing patterns like 192.168.1-10.*)
pub enum OctetSpec {
    Single(u8),
    Range(u8, u8),
    All,
}

/// Target group (input for the scanner)
pub struct TargetGroup {
    pub targets: Vec<Target>,
    pub total_count: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub statistics: TargetStats,
}

impl TargetSpecParser {
    /// Parse input string
    pub fn parse(&self, input: &str) -> Result<TargetGroup, ParseError> {
        let mut targets = Vec::new();
        
        // 1. Normalize input (handle newlines, commas, etc.)
        let tokens = self.tokenize(input)?;
        
        // 2. Parse each token
        for token in tokens {
            let spec = self.parse_token(&token)?;
            
            // 3. Expand into concrete IP list
            let expanded = self.expand_spec(&spec)?;
            
            // 4. DNS resolution (if needed)
            for mut target in expanded {
                if let Some(ref resolver) = self.dns_resolver {
                    if target.hostname.is_none() {
                        target.hostname = resolver.reverse_lookup(target.ip)?;
                    }
                }
                targets.push(target);
            }
        }
        
        // 5. Apply exclusion rules
        targets.retain(|t| !self.is_excluded(t));
        
        // 6. Deduplicate
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
    
    /// Expand target specification
    fn expand_spec(&self, spec: &TargetSpec) -> Result<Vec<Target>, ParseError> {
        match spec {
            TargetSpec::SingleIpv4(ip) => Ok(vec![Target::from(*ip)]),
            TargetSpec::SingleIpv6(ip) => Ok(vec![Target::from(*ip)]),
            TargetSpec::Hostname(name) => self.resolve_hostname(name),
            TargetSpec::Ipv4Cidr { base, prefix } => self.expand_cidr_v4(base, prefix),
            TargetSpec::Ipv4Range { start, end } => self.expand_range_v4(start, end),
            TargetSpec::Ipv4OctetRange { octets } => self.expand_octets(octets),
            // ... other expansion logic
            _ => unimplemented!(),
        }
    }
    
    /// Expand octet ranges (e.g., 192.168.1-10.*)
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

