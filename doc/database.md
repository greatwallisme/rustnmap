# 4. Database and Fingerprint File Design

## 4.1 Database File List

| Database File | Function | Nmap Equivalent | Update Frequency |
|---------------|----------|-----------------|------------------|
| `service-probes` | Service detection rules | `nmap-service-probes` | High |
| `os-fingerprints` | OS fingerprints | `nmap-os-db` | Medium |
| `rpc-procedures` | RPC program number mapping | `nmap-rpc` | Low |
| `nmap-mac-prefixes` | MAC address vendor prefixes | `nmap-mac-prefixes` | Medium |
| `payloads` | UDP/protocol payloads | `nmap-payloads` | Low |
| `script-db` | NSE script index | `script.db` | Medium |

**Important**: The `nmap-mac-prefixes` file supports **three** IEEE OUI formats:
- **MA-S (9 characters)**: 36-bit extended OUI - `001BC5000 Converging Systems`
- **MA-M (7 characters)**: 28-bit medium OUI - `0055DA0 Shinko Technos`
- **MA-L (6 characters)**: 24-bit standard OUI - `0055DA Ieee Registration Authority`

Lookup follows **longest prefix first** principle (9 first, then 7, then 6).

## 4.2 Service Detection Database Format

```
# ==========================
# RustNmap Service Probes Database
# Format: Compatible with Nmap nmap-service-probes
# ==========================

# Excluded ports (typically not probed)
ExcludePorts T:9100-9107,T:111,U:111

# ============ TCP Probes ============

# Null Probe (no data sent, wait for banner)
Probe TCP NULL q||

# Wait time
totalwaitms 6000

# Match rules
match 1c-server m|^1C:Enterprise\r?\n| p/1C:Enterprise server/
match 4d-server m|^</html><html>\r?\n<head><title>4D WebStar</title>| p/4D WebStar/

# GenericLines Probe (send \r\n\r\n)
Probe TCP GenericLines q|\r\n\r\n|
match acap m|^\* ACAP \(IMPLEMENTATION \"([^\)]+)\"\)| p/ACAP server/ i/$1/
match ajetp m|^D \d+\.\d+ AjetP ([\d.]+)\r?\n| p/AjetP print daemon/ v/$1/
match anonymous m|^ ANONYMOUS OK\r?\n| p/Rsync anonymous/

# HTTPOptions Probe
Probe TCP HTTPOptions q|OPTIONS / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.0 200 OK\r\n.*Server: ([^\r\n]+)|s p/HTTP/ i/Server: $1/
softmatch http m|^HTTP/1\.[01] \d\d\d| cpe:/a:vendor:http/

# ============ UDP Probes ============

Probe UDP dnsstatusq q|\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00|
match dns m|^\x00\x00\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00| p/DNS/

# ============ Protocol Details ============
# Each probe has:
# - Probe directive: protocol, name, probe data
# - ports: default target ports
# - sslports: ports to try with SSL
# - totalwaitms: max wait time
# - tcpwrappedms: timeout for tcpwrapped detection
# - rarity: 1-9, probe usage frequency
# - fallback: fallback probe if no match

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
ports 80,8080,443
sslports 443
match http m|^HTTP/1\.1 (\d\d\d) | p/HTTP/ i/status $1/
rarity 1
fallback GenericLines

# Complex match example (using capture groups and CPE)
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w.+-]+)(?:\s|$)| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/

# Soft match - does not confirm service but narrows scope
softmatch ssh m|^SSH-\d\.\d-|

# Missed service (negative match)
match ftp m|^220 Welcome to Pure-FTPd| p/Pure-FTPd/ o/Linux/
match http m|^HTTP/1\.[01] \d\d\d .*\r\nServer: nginx/([\d.]+)|s p/nginx/ v/$1/ cpe:/a:nginx:nginx:$1/
```

## 4.3 OS Fingerprint Database Format

```
# ==========================
# RustNmap OS Fingerprints Database
# Format: Compatible with Nmap nmap-os-db
# ==========================

# Fingerprint entry structure:
# Fingerprint <OS Name>
#   Class <Vendor> <OS Family> <Generation> <Device Type>
#   CPE <CPE String>
#   SEQ, OPS, WIN, ECN, T1-T7, U1, IE fields

Fingerprint Linux 5.4-5.10
Class Linux | Linux | 5.X | general purpose
CPE cpe:/o:linux:linux_kernel:5

# SEQ (Sequence Analysis)
SEQ(GCD=1-6|ISA=0|IPR=64K|TS=1000-2FFF|SP=0-64|O1=0|O2=0|O3=0|O4=0|O5=0|O6=0)

# OPS (TCP Options)
OPS(O1=M5B4ST11NW7|O2=M5B4ST11NW7|O3=M5B4ST11NW7|O4=M5B4ST11NW7|O5=M5B4ST11NW7|O6=M5B4ST11)

# WIN (TCP Window)
WIN(W1=FFFF|W2=FFFF|W3=FFFF|W4=FFFF|W5=FFFF|W6=FFFF)

# ECN (Explicit Congestion Notification)
ECN(R=Y|DF=Y|T=40|TG=40|CC=N|Q=N)

# T1-T7 (TCP Tests)
T1(R=Y|DF=Y|T=40|S=O|A=S+|F=AS|RD=0|Q=)
T2(R=N)
T3(R=N)
T4(R=Y|DF=Y|T=40|W=FFFF|A=S|O=M5B4ST11NW7|RD=0|Q=)
T5(R=Y|DF=Y|T=40|S=O|A=S+|F=AS|O=M5B4ST11NW7|RD=0|Q=)
T6(R=Y|DF=Y|T=40|W=FFFF|A=S|O=M5B4ST11NW7|RD=0|Q=)
T7(R=N)

# U1 (UDP Test)
U1(R=Y|DF=N|T=40|TOS=0|IPL=164|UN=0|RIPL=G|RID=G|RIPCK=G|RUCK=G|RUL=G|RUD=G)

# IE (ICMP Echo)
IE(R=Y|DFI=N|T=40|TOSI=S|CD=S|SI=S|DL=S)

Fingerprint Microsoft Windows 10 or Server 2016+
Class Microsoft | Windows | 10 | general purpose
CPE cpe:/o:microsoft:windows_10
CPE cpe:/o:microsoft:windows_server_2016

SEQ(GCD=1-6|ISR=106-10A|IPR=64K|TS=100-200|SP=101-106|O1=0|O2=0|O3=0|O4=0|O5=0|O6=0)
OPS(O1=M534ST11NW6|O2=M534ST11|O3=M534ST11NW6|O4=M534ST11NW6|O5=M534ST11NW6|O6=M534ST11)
WIN(W1=2000|W2=2000|W3=2000|W4=2000|W5=2000|W6=2000)
ECN(R=N|DF=Y|T=80|TG=80|CC=N|Q=N)
T1(R=Y|DF=Y|T=80|S=O|A=S+|F=AS|RD=0|Q=)
T2(R=N)
T3(R=N)
T4(R=Y|DF=Y|T=80|W=2000|A=S|O=M534ST11NW6|RD=0|Q=)
T5(R=Y|DF=Y|T=80|S=O|A=S+|F=AS|O=M534ST11NW6|RD=0|Q=)
T6(R=Y|DF=Y|T=80|W=2000|A=S|O=M534ST11NW6|RD=0|Q=)
T7(R=N)
U1(R=Y|DF=N|T=80|TOS=0|IPL=128|UN=0|RIPL=G|RID=G|RIPCK=G|RUCK=G|RUL=G|RUD=G)
IE(R=Y|DFI=N|T=80|TOSI=S|CD=S|SI=S|DL=S)
```

## 4.4 Database Loader Design

```
// ============================================
// Database Loader Types
// ============================================

use std::collections::HashMap;
use regex::Regex;

/// Database Manager
pub struct DatabaseManager {
    pub services: ServiceProbeDatabase,
    pub os: OsFingerprintDatabase,
    pub mac_prefixes: MacPrefixDatabase,
    pub rpc: RpcDatabase,
    pub payloads: PayloadDatabase,
}

/// Service Probe Database
pub struct ServiceProbeDatabase {
    probes: Vec<ServiceProbe>,
    match_cache: HashMap<String, CompiledMatch>,
}

/// Service Probe Definition
pub struct ServiceProbe {
    pub name: String,
    pub protocol: Protocol,
    pub probe_data: Vec<u8>,
    pub ports: Vec<u16>,
    pub ssl_ports: Vec<u16>,
    pub total_wait_ms: u64,
    pub rarity: u8,
    pub matches: Vec<MatchRule>,
    pub soft_matches: Vec<MatchRule>,
    pub fallback: Option<String>,
}

/// Match Rule
pub struct MatchRule {
    pub service: String,
    pub pattern: CompiledRegex,
    pub version_template: Option<String>,
    pub product_template: Option<String>,
    pub info_template: Option<String>,
    pub hostname_template: Option<String>,
    pub os_template: Option<String>,
    pub device_type_template: Option<String>,
    pub cpe_templates: Vec<String>,
    pub is_soft: bool,
}

/// Compiled Regular Expression (performance optimized)
pub struct CompiledRegex {
    regex: Regex,
    capture_count: usize,
}

/// OS Fingerprint Database
pub struct OsFingerprintDatabase {
    fingerprints: Vec<OsFingerprint>,
}

pub struct OsFingerprint {
    pub name: String,
    pub classes: Vec<OsClass>,
    pub cpes: Vec<String>,
    pub tcp_seq: TcpSeqFingerprint,
    pub tcp_isn: TcpIsnFingerprint,
    pub ip_id: IpIdFingerprint,
    pub tcp_timestamp: TcpTimestampFingerprint,
    pub tcp_options: HashMap<String, TcpOptionsFingerprint>,
    pub tcp_window: HashMap<String, TcpWindowFingerprint>,
    pub ecn: EcnFingerprint,
    pub tcp_tests: HashMap<String, TcpTestFingerprint>,
    pub udp_test: UdpTestFingerprint,
    pub icmp_test: IcmpTestFingerprint,
}

/// Database Loader
impl DatabaseManager {
    pub fn load(data_dir: &Path) -> Result<Self, DatabaseError> {
        Ok(Self {
            services: ServiceProbeLoader::load(&data_dir.join("service-probes"))?,
            os: OsFingerprintLoader::load(&data_dir.join("os-fingerprints"))?,
            mac_prefixes: MacPrefixLoader::load(&data_dir.join("mac-prefixes"))?,
            rpc: RpcLoader::load(&data_dir.join("rpc-procedures"))?,
            payloads: PayloadLoader::load(&data_dir.join("payloads"))?,
        })
    }

    /// Update databases (download from network)
    pub async fn update(&mut self) -> Result<(), DatabaseError> {
        // Download latest databases from official repository
        unimplemented!()
    }
}
```

## 4.5 MAC Prefix Database Format

The `nmap-mac-prefixes` file stores mappings from MAC address OUI (Organizationally Unique Identifier) to vendor names.

### 4.5.1 File Format

```
# $Id$
#
# MAC/Vendor database file for Nmap
#
# Format: OUI<whitespace>Vendor Name
#
# OUI formats (IEEE MAC Address Block types):
#   - 6 hex digits (24-bit) MA-L (MAC Address Block - Large)
#   - 7 hex digits (28-bit) MA-M (MAC Address Block - Medium)
#   - 9 hex digits (36-bit) MA-S (MAC Address Block - Small)
#
# Examples:
000000    Private
0050C2   Cisco Systems             # MA-L (24-bit)
0055DA Ieee Registration Authority # MA-L (24-bit)
0055DA0 Shinko Technos            # MA-M (28-bit)
0055DA1 KoolPOS                    # MA-M (28-bit)
001BC5000 Converging Systems      # MA-S (36-bit)
001BC5001 OpenRB.com               # MA-S (36-bit)
```

### 4.5.2 OUI Format Description

Reference: `reference/nmap/MACLookup.cc:119-147`

**MA-L (6 characters, 24-bit) - MAC Address Block Large**
- Standard IEEE OUI allocation
- First 24 bits identify vendor
- Example: `0050C2 Cisco Systems`

**MA-M (7 characters, 28-bit) - MAC Address Block Medium**
- IEEE extended format
- First 28 bits identify specific sub-vendor/product line
- Example: `0055DA0 Shinko Technos`

**MA-S (9 characters, 36-bit) - MAC Address Block Small**
- IEEE small block allocation
- First 36 bits provide finer-grained identification
- Example: `001BC5000 Converging Systems`

**Statistics** (2026-03-09 current database):
- Total entries: ~49,000
- 6 characters (MA-L): ~37,000 (75%)
- 7 characters (MA-M): ~5,700 (12%)
- 9 characters (MA-S): ~6,400 (13%)

### 4.5.3 Lookup Logic (Longest Prefix First)

Actual implementation in `crates/rustnmap-fingerprint/src/database/mac.rs`:

```rust
pub fn lookup(&self, mac: &str) -> Option<&str> {
    let normalized = Self::normalize_mac(mac)?;

    // Try longest match first (12 chars down to 6 chars)
    // This ensures more specific prefixes match before general ones
    for len in (6..=normalized.len().min(12)).rev() {
        let oui = &normalized[..len];
        if let Some(vendor) = self.prefixes.get(oui) {
            return Some(vendor);
        }
    }

    None
}
```

Supports OUI lengths from 6 to 12 characters, automatically matching the longest prefix.

### 4.5.4 Parser Implementation

Actual implementation in `crates/rustnmap-fingerprint/src/database/mac.rs`:

```rust
pub struct MacPrefixDatabase {
    prefixes: HashMap<String, String>,
}

impl MacPrefixDatabase {
    pub fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            let line_num = line_num + 1;
            if line.is_empty() || line.starts_with('#') { continue; }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 { continue; }

            let oui = parts[0].to_uppercase();
            let vendor = parts[1..].join(" ");

            // Validate OUI format (6-12 hex digits for extended prefixes)
            if !(6..=12).contains(&oui.len()) || !oui.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(FingerprintError::ParseError {
                    line: line_num,
                    content: format!("Invalid OUI format: {oui}"),
                });
            }

            db.prefixes.insert(oui, vendor);
        }
        Ok(db)
    }
}
```
```

---
