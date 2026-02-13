// rustnmap-output
// Copyright (C) 2026  greatwallisme
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Output formatter implementations for different output formats.

use crate::error::{OutputError, Result};
use crate::models::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::writer::Writer;
use std::fmt::Write;
use std::io::Write as IoWrite;

/// Verbosity level for output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerbosityLevel {
    /// Quiet mode (-q)
    Quiet = -1,
    /// Normal output (default)
    #[default]
    Normal = 0,
    /// Verbose level 1 (-v)
    Verbose1 = 1,
    /// Verbose level 2 (-vv)
    Verbose2 = 2,
    /// Verbose level 3 (-vvv)
    Verbose3 = 3,
    /// Debug level 1 (-d)
    Debug1 = 4,
    /// Debug level 2 (-dd)
    Debug2 = 5,
    /// Debug level 3 (-ddd)
    Debug3 = 6,
    /// Debug level 4 (-dddd)
    Debug4 = 7,
    /// Debug level 5 (-ddddd)
    Debug5 = 8,
    /// Debug level 6 (-dddddd)
    Debug6 = 9,
}

/// Trait for output formatters.
pub trait OutputFormatter: Send + Sync {
    /// Format complete scan result.
    fn format_scan_result(&self, result: &ScanResult) -> Result<String>;

    /// Format single host result.
    fn format_host(&self, host: &HostResult) -> Result<String>;

    /// Format port result.
    fn format_port(&self, port: &PortResult) -> Result<String>;

    /// Format script result.
    fn format_script(&self, script: &ScriptResult) -> Result<String>;

    /// Get file extension for this format.
    fn file_extension(&self) -> &str;

    /// Get format name.
    fn format_name(&self) -> &str;
}

/// Normal text formatter (Nmap-compatible human-readable output).
#[derive(Debug, Clone, Default)]
pub struct NormalFormatter {
    /// Verbosity level
    pub verbosity: VerbosityLevel,
}

impl NormalFormatter {
    /// Create new normal formatter with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create normal formatter with specified verbosity.
    pub fn with_verbosity(verbosity: VerbosityLevel) -> Self {
        Self { verbosity }
    }
}

impl OutputFormatter for NormalFormatter {
    fn format_scan_result(&self, result: &ScanResult) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "# RustNmap {} scan initiated {} as:\n",
            result.metadata.scanner_version,
            result.metadata.start_time.format("%a %b %d %H:%M:%S %Y")
        ));
        output.push_str(&format!("# {}\n\n", result.metadata.command_line));

        // Hosts
        for host in &result.hosts {
            output.push_str(&self.format_host(host)?);
            output.push('\n');
        }

        // Statistics
        let up_count = result.statistics.hosts_up;
        let total = result.statistics.total_hosts;
        output.push_str(&format!(
            "Nmap done: {} IP address ({} host up) scanned in {:.2} seconds\n",
            total,
            up_count,
            result.metadata.elapsed.as_secs_f64()
        ));

        Ok(output)
    }

    fn format_host(&self, host: &HostResult) -> Result<String> {
        let mut output = String::new();

        // Host line
        output.push_str(&format!("Nmap scan report for {}\n", host.ip));

        if let Some(ref hostname) = host.hostname {
            output.push_str(&format!("rDNS record for {}: {}\n", host.ip, hostname));
        }

        // Status
        let status_str = match host.status {
            HostStatus::Up => "up",
            HostStatus::Down => "down",
            HostStatus::Unknown => "unknown",
        };
        output.push_str(&format!(
            "Host is {} ({}s latency).\n",
            status_str,
            host.latency.as_secs_f64()
        ));

        // MAC address
        if let Some(ref mac) = host.mac {
            let vendor = mac.vendor.as_deref().unwrap_or("unknown");
            output.push_str(&format!("MAC Address: {} ({})\n", mac.address, vendor));
        }

        // Ports
        if !host.ports.is_empty() {
            let open_ports: Vec<_> = host
                .ports
                .iter()
                .filter(|p| matches!(p.state, PortState::Open))
                .collect();

            let closed_count = host
                .ports
                .iter()
                .filter(|p| matches!(p.state, PortState::Closed))
                .count();

            if closed_count > 0 {
                writeln!(output, "Not shown: {closed_count} closed ports").unwrap();
            }

            output.push_str("PORT     STATE SERVICE\n");

            for port in &host.ports {
                output.push_str(&self.format_port(port)?);
            }

            // Scripts
            for port in &open_ports {
                for script in &port.scripts {
                    output.push_str(&self.format_script(script)?);
                }
            }
        }

        // OS detection
        if !host.os_matches.is_empty() {
            output.push_str("OS detection:\n");
            for os_match in &host.os_matches {
                output.push_str(&format!("{} ({}%)\n", os_match.name, os_match.accuracy));
            }
        }

        // Traceroute
        if let Some(ref trace) = host.traceroute {
            output.push_str(&format!(
                "TRACEROUTE (using port {}/{} )\n",
                trace.port,
                match trace.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Sctp => "sctp",
                }
            ));
            output.push_str("HOP RTT     ADDRESS\n");
            for hop in &trace.hops {
                let rtt = hop
                    .rtt
                    .map(|d| format!("{:.2} ms", d.as_secs_f64() * 1000.0))
                    .unwrap_or_else(|| "--".to_string());
                output.push_str(&format!("{}   {}  {}\n", hop.ttl, rtt, hop.ip));
            }
        }

        Ok(output)
    }

    fn format_port(&self, port: &PortResult) -> Result<String> {
        let proto = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        let state = match port.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::Unfiltered => "unfiltered",
            PortState::OpenOrFiltered => "open|filtered",
            PortState::ClosedOrFiltered => "closed|filtered",
            PortState::OpenOrClosed => "open|closed",
            PortState::FilteredOrClosed => "filtered|closed",
            PortState::Unknown => "unknown",
        };

        let service = port
            .service
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(format!(
            "{}/{}  {:7} {}\n",
            port.number, proto, state, service
        ))
    }

    fn format_script(&self, script: &ScriptResult) -> Result<String> {
        let mut output = String::new();
        writeln!(output, "| {}", script.id).unwrap();

        // Format multi-line output with pipe prefix
        for line in script.output.lines() {
            writeln!(output, "|_ {line}").unwrap();
        }

        Ok(output)
    }

    fn file_extension(&self) -> &str {
        "nmap"
    }

    fn format_name(&self) -> &str {
        "Normal"
    }
}

/// XML formatter following Nmap's XML output format.
#[derive(Debug, Clone, Default)]
pub struct XmlFormatter;

impl XmlFormatter {
    /// Create new XML formatter.
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for XmlFormatter {
    fn format_scan_result(&self, result: &ScanResult) -> Result<String> {
        let mut buffer = Vec::new();
        let mut writer = Writer::new_with_indent(&mut buffer, b' ', 2);

        // Root element
        let mut start = BytesStart::new("nmaprun");
        start.push_attribute(("scanner", "rustnmap"));
        start.push_attribute(("args", result.metadata.command_line.as_str()));
        start.push_attribute((
            "start",
            result.metadata.start_time.timestamp().to_string().as_str(),
        ));
        start.push_attribute((
            "startstr",
            result
                .metadata
                .start_time
                .format("%a %b %d %H:%M:%S %Y")
                .to_string()
                .as_str(),
        ));
        start.push_attribute(("version", result.metadata.scanner_version.as_str()));
        start.push_attribute(("xmloutputversion", "1.05"));

        writer.write_event(Event::Start(start))?;

        // Scan info
        let scan_type = match result.metadata.scan_type {
            ScanType::TcpSyn => "syn",
            ScanType::TcpConnect => "connect",
            ScanType::TcpFin => "fin",
            ScanType::TcpNull => "null",
            ScanType::TcpXmas => "xmas",
            ScanType::TcpMaimon => "maimon",
            ScanType::Udp => "udp",
            ScanType::SctpInit => "sctpinit",
            ScanType::SctpCookie => "sctpcookie",
            ScanType::IpProtocol => "ipproto",
            ScanType::Ping => "ping",
            ScanType::TcpAck => "ack",
            ScanType::TcpWindow => "window",
        };

        let proto = match result.metadata.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        let mut scaninfo = BytesStart::new("scaninfo");
        scaninfo.push_attribute(("type", scan_type));
        scaninfo.push_attribute(("protocol", proto));
        scaninfo.push_attribute((
            "numservices",
            result.statistics.total_ports.to_string().as_str(),
        ));
        scaninfo.push_attribute(("services", "1-65535"));

        writer.write_event(Event::Empty(scaninfo))?;

        // Verbose/Debug
        let mut verbose = BytesStart::new("verbose");
        verbose.push_attribute(("level", self.get_verbosity_level().to_string().as_str()));
        writer.write_event(Event::Empty(verbose)).unwrap();

        let mut debugging = BytesStart::new("debugging");
        debugging.push_attribute(("level", self.get_debug_level().to_string().as_str()));
        writer.write_event(Event::Empty(debugging)).unwrap();

        // Hosts
        for host in &result.hosts {
            self.write_host(&mut writer, host)?;
        }

        // Runstats
        writer.write_event(Event::Start(BytesStart::new("runstats")))?;

        writer.write_event(Event::End(BytesEnd::new("runstats")))?;

        // End root
        writer.write_event(Event::End(BytesEnd::new("nmaprun")))?;

        String::from_utf8(buffer).map_err(OutputError::from)
    }

    fn format_host(&self, _host: &HostResult) -> Result<String> {
        // XML doesn't format hosts individually, handled in format_scan_result
        Ok(String::new())
    }

    fn format_port(&self, _port: &PortResult) -> Result<String> {
        // XML doesn't format ports individually, handled in format_scan_result
        Ok(String::new())
    }

    fn format_script(&self, _script: &ScriptResult) -> Result<String> {
        // XML doesn't format scripts individually, handled in format_scan_result
        Ok(String::new())
    }

    fn file_extension(&self) -> &str {
        "xml"
    }

    fn format_name(&self) -> &str {
        "XML"
    }
}

impl XmlFormatter {
    fn get_verbosity_level(&self) -> i8 {
        0
    }

    fn get_debug_level(&self) -> u8 {
        0
    }

    fn write_host<W: IoWrite>(&self, writer: &mut Writer<W>, host: &HostResult) -> Result<()> {
        let mut host_start = BytesStart::new("host");
        match host.ip {
            std::net::IpAddr::V4(_addr) => {
                host_start.push_attribute((
                    "starttime",
                    host.times.srtt.unwrap_or(0).to_string().as_str(),
                ));
                host_start.push_attribute((
                    "endtime",
                    host.times.timeout.unwrap_or(0).to_string().as_str(),
                ));
            }
            std::net::IpAddr::V6(_addr) => {
                // IPv6 addresses use different timestamp handling
            }
        }
        writer.write_event(Event::Start(host_start))?;

        // Status
        let state = match host.status {
            HostStatus::Up => "up",
            HostStatus::Down => "down",
            HostStatus::Unknown => "unknown",
        };
        let mut status_elem = BytesStart::new("status");
        status_elem.push_attribute(("state", state));
        status_elem.push_attribute(("reason", host.status_reason.as_str()));
        writer
            .write_event(Event::Empty(status_elem))
            .map_err(OutputError::from)?;

        // Address
        let mut address = BytesStart::new("address");
        address.push_attribute(("addr", host.ip.to_string().as_str()));
        address.push_attribute(("addrtype", "ipv4"));
        writer
            .write_event(Event::Empty(address))
            .map_err(OutputError::from)?;

        // MAC
        if let Some(ref mac) = host.mac {
            let mut mac_elem = BytesStart::new("address");
            mac_elem.push_attribute(("addr", mac.address.as_str()));
            mac_elem.push_attribute(("addrtype", "mac"));
            if let Some(ref vendor) = mac.vendor {
                mac_elem.push_attribute(("vendor", vendor.as_str()));
            }
            writer
                .write_event(Event::Empty(mac_elem))
                .map_err(OutputError::from)?;
        }

        // Hostnames
        if let Some(ref hostname) = host.hostname {
            writer.write_event(Event::Start(BytesStart::new("hostnames")))?;
            let mut hostname_elem = BytesStart::new("hostname");
            hostname_elem.push_attribute(("name", hostname.as_str()));
            hostname_elem.push_attribute(("type", "PTR"));
            writer
                .write_event(Event::Empty(hostname_elem))
                .map_err(OutputError::from)?;
            writer.write_event(Event::End(BytesEnd::new("hostnames")))?;
        }

        // Ports
        if !host.ports.is_empty() {
            writer.write_event(Event::Start(BytesStart::new("ports")))?;
            for port in &host.ports {
                self.write_port(writer, port)?;
            }
            writer.write_event(Event::End(BytesEnd::new("ports")))?;
        }

        // OS
        if !host.os_matches.is_empty() {
            writer.write_event(Event::Start(BytesStart::new("os")))?;
            for os_match in &host.os_matches {
                self.write_os_match(writer, os_match)?;
            }
            writer.write_event(Event::End(BytesEnd::new("os")))?;
        }

        writer.write_event(Event::End(BytesEnd::new("host")))?;
        Ok(())
    }

    fn write_port<W: IoWrite>(&self, writer: &mut Writer<W>, port: &PortResult) -> Result<()> {
        let proto = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        let state = match port.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::Unfiltered => "unfiltered",
            PortState::OpenOrFiltered => "open|filtered",
            PortState::ClosedOrFiltered => "closed|filtered",
            PortState::OpenOrClosed => "open|closed",
            PortState::FilteredOrClosed => "filtered|closed",
            PortState::Unknown => "unknown",
        };

        let mut port_start = BytesStart::new("port");
        port_start.push_attribute(("protocol", proto));
        port_start.push_attribute(("portid", port.number.to_string().as_str()));

        writer.write_event(Event::Start(port_start))?;

        let mut state_elem = BytesStart::new("state");
        state_elem.push_attribute(("state", state));
        state_elem.push_attribute(("reason", port.state_reason.as_str()));
        state_elem.push_attribute((
            "reason_ttl",
            port.state_ttl.unwrap_or(0).to_string().as_str(),
        ));

        writer
            .write_event(Event::Empty(state_elem))
            .map_err(OutputError::from)?;

        if let Some(ref service) = port.service {
            self.write_service(writer, service)?;
        }

        for script in &port.scripts {
            self.write_script(writer, script)?;
        }

        writer.write_event(Event::End(BytesEnd::new("port")))?;
        Ok(())
    }

    fn write_service<W: IoWrite>(
        &self,
        writer: &mut Writer<W>,
        service: &ServiceInfo,
    ) -> Result<()> {
        let mut service_start = BytesStart::new("service");
        service_start.push_attribute(("name", service.name.as_str()));
        service_start.push_attribute(("method", service.method.as_str()));
        service_start.push_attribute(("conf", service.confidence.to_string().as_str()));

        if let Some(ref product) = service.product {
            service_start.push_attribute(("product", product.as_str()));
        }
        if let Some(ref version) = service.version {
            service_start.push_attribute(("version", version.as_str()));
        }
        if let Some(ref ostype) = service.ostype {
            service_start.push_attribute(("ostype", ostype.as_str()));
        }
        if let Some(ref extrainfo) = service.extrainfo {
            service_start.push_attribute(("extrainfo", extrainfo.as_str()));
        }

        writer
            .write_event(Event::Empty(service_start))
            .map_err(OutputError::from)?;

        Ok(())
    }

    fn write_script<W: IoWrite>(
        &self,
        writer: &mut Writer<W>,
        script: &ScriptResult,
    ) -> Result<()> {
        let mut script_start = BytesStart::new("script");
        script_start.push_attribute(("id", script.id.as_str()));

        if !script.output.is_empty() {
            script_start.push_attribute(("output", script.output.as_str()));
        }

        writer.write_event(Event::Start(script_start))?;

        // Write structured elements
        for element in &script.elements {
            self.write_script_element(writer, element)?;
        }

        writer.write_event(Event::End(BytesEnd::new("script")))?;
        Ok(())
    }

    fn write_script_element<W: IoWrite>(
        &self,
        writer: &mut Writer<W>,
        element: &ScriptElement,
    ) -> Result<()> {
        let mut elem_start = BytesStart::new("table");
        elem_start.push_attribute(("key", element.key.as_str()));

        writer.write_event(Event::Start(elem_start))?;
        writer
            .write_event(Event::Text(BytesText::new(
                element.value.to_string().as_str(),
            )))
            .map_err(OutputError::from)?;
        writer.write_event(Event::End(BytesEnd::new("table")))?;
        Ok(())
    }

    fn write_os_match<W: IoWrite>(&self, writer: &mut Writer<W>, os_match: &OsMatch) -> Result<()> {
        let mut os_start = BytesStart::new("osmatch");
        os_start.push_attribute(("name", os_match.name.as_str()));
        os_start.push_attribute(("accuracy", os_match.accuracy.to_string().as_str()));

        writer.write_event(Event::Start(os_start))?;

        if let Some(ref os_family) = os_match.os_family {
            let mut osclass = BytesStart::new("osclass");
            osclass.push_attribute(("type", "general purpose"));
            osclass.push_attribute(("vendor", ""));
            osclass.push_attribute(("osfamily", os_family.as_str()));
            osclass.push_attribute(("vendor", ""));
            osclass.push_attribute(("osfamily", os_family.as_str()));
            let osgen = os_match
                .os_generation
                .as_deref()
                .map(|s| s.to_string())
                .unwrap_or("".to_string());
            osclass.push_attribute(("osgen", osgen.as_str()));

            writer
                .write_event(Event::Empty(osclass))
                .map_err(OutputError::from)?;
        }

        writer.write_event(Event::End(BytesEnd::new("osmatch")))?;
        Ok(())
    }
}

/// JSON formatter for structured output.
#[derive(Debug, Clone)]
pub struct JsonFormatter {
    /// Pretty print output
    pub pretty: bool,
}

impl JsonFormatter {
    /// Create new JSON formatter with pretty printing enabled.
    pub fn new() -> Self {
        Self { pretty: true }
    }

    /// Create JSON formatter with specified pretty print setting.
    pub fn with_pretty(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self { pretty: true }
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_scan_result(&self, result: &ScanResult) -> Result<String> {
        if self.pretty {
            serde_json::to_string_pretty(result).map_err(OutputError::from)
        } else {
            serde_json::to_string(result).map_err(OutputError::from)
        }
    }

    fn format_host(&self, _host: &HostResult) -> Result<String> {
        // JSON doesn't format hosts individually
        Ok(String::new())
    }

    fn format_port(&self, _port: &PortResult) -> Result<String> {
        // JSON doesn't format ports individually
        Ok(String::new())
    }

    fn format_script(&self, _script: &ScriptResult) -> Result<String> {
        // JSON doesn't format scripts individually
        Ok(String::new())
    }

    fn file_extension(&self) -> &str {
        "json"
    }

    fn format_name(&self) -> &str {
        "JSON"
    }
}

/// Grepable formatter for simple line-based output.
#[derive(Debug, Clone, Default)]
pub struct GrepableFormatter;

impl GrepableFormatter {
    /// Create new grepable formatter.
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for GrepableFormatter {
    fn format_scan_result(&self, result: &ScanResult) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "# rustnmap {} scan initiated {} as: {}\n",
            result.metadata.scanner_version,
            result.metadata.start_time.format("%a %b %d %H:%M:%S %Y"),
            result.metadata.command_line
        ));

        // Hosts
        for host in &result.hosts {
            for port in &host.ports {
                output.push_str(&self.format_port(port)?);
            }
        }

        // Statistics
        output.push_str(&format!(
            "# Nmap done at {} -- {} IP address ({} host up) scanned in {:.2} seconds\n",
            result.metadata.end_time.format("%a %b %d %H:%M:%S %Y"),
            result.statistics.total_hosts,
            result.statistics.hosts_up,
            result.metadata.elapsed.as_secs_f64()
        ));

        Ok(output)
    }

    fn format_host(&self, _host: &HostResult) -> Result<String> {
        // Grepable doesn't format hosts separately
        Ok(String::new())
    }

    fn format_port(&self, port: &PortResult) -> Result<String> {
        let proto = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        let state = match port.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            _ => "unknown",
        };

        let service = port
            .service
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let version = port
            .service
            .as_ref()
            .and_then(|s| s.version.as_ref())
            .map(|v| v.to_owned())
            .unwrap_or_default();

        Ok(format!(
            "Ports: {}//{}/{}/{}/{}\n",
            port.number, proto, state, service, version
        ))
    }

    fn format_script(&self, _script: &ScriptResult) -> Result<String> {
        // Scripts not shown in grepable format
        Ok(String::new())
    }

    fn file_extension(&self) -> &str {
        "gnmap"
    }

    fn format_name(&self) -> &str {
        "Grepable"
    }
}

/// Script Kiddie formatter (| separators).
#[derive(Debug, Clone, Default)]
pub struct ScriptKiddieFormatter;

impl ScriptKiddieFormatter {
    /// Create new script kiddie formatter.
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for ScriptKiddieFormatter {
    fn format_scan_result(&self, result: &ScanResult) -> Result<String> {
        let mut output = String::new();

        // Hosts
        for host in &result.hosts {
            output.push_str(&self.format_host(host)?);
        }

        Ok(output)
    }

    fn format_host(&self, host: &HostResult) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&format!("{} ({})", host.ip, host.ip));
        if let Some(ref hostname) = host.hostname {
            use std::fmt::Write;
            write!(output, " [{hostname}]").unwrap();
        }
        output.push('\n');

        // Ports
        for port in &host.ports {
            output.push_str(&self.format_port(port)?);
        }

        Ok(output)
    }

    fn format_port(&self, port: &PortResult) -> Result<String> {
        let state = match port.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            _ => "unknown",
        };

        let service = port
            .service
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "?".to_string());

        Ok(format!("  | {} | {} | {}\n", port.number, state, service))
    }

    fn format_script(&self, script: &ScriptResult) -> Result<String> {
        Ok(format!("  | |_ {}\n", script.output))
    }

    fn file_extension(&self) -> &str {
        "txt"
    }

    fn format_name(&self) -> &str {
        "Script Kiddie"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn create_test_host() -> HostResult {
        HostResult {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            mac: Some(MacAddress {
                address: "00:11:22:33:44:55".to_string(),
                vendor: Some("TestVendor".to_string()),
            }),
            hostname: Some("test.local".to_string()),
            status: HostStatus::Up,
            status_reason: "syn-ack".to_string(),
            latency: Duration::from_millis(2),
            ports: vec![PortResult {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                state_reason: "syn-ack".to_string(),
                state_ttl: Some(64),
                service: Some(ServiceInfo {
                    name: "http".to_string(),
                    product: Some("nginx".to_string()),
                    version: Some("1.18.0".to_string()),
                    extrainfo: None,
                    hostname: None,
                    ostype: None,
                    devicetype: None,
                    method: "probed".to_string(),
                    confidence: 10,
                    cpe: vec!["cpe:/a:nginx:nginx:1.18.0".to_string()],
                }),
                scripts: vec![],
            }],
            os_matches: vec![],
            scripts: vec![],
            traceroute: None,
            times: HostTimes {
                srtt: Some(2300),
                rttvar: Some(500),
                timeout: Some(100000),
            },
        }
    }

    #[test]
    fn test_normal_formatter_host() {
        let formatter = NormalFormatter::new();
        let host = create_test_host();
        let result = formatter.format_host(&host).unwrap();

        assert!(result.contains("192.168.1.1"));
        assert!(result.contains("80/tcp"));
        assert!(result.contains("open"));
    }

    #[test]
    fn test_json_formatter_serialization() {
        let formatter = JsonFormatter::new();
        let mut scan_result = ScanResult::default();
        scan_result.hosts.push(create_test_host());

        let result = formatter.format_scan_result(&scan_result).unwrap();
        assert!(result.contains("192.168.1.1"));
        assert!(result.contains("nginx"));
    }

    #[test]
    fn test_xml_formatter_creates_valid_xml() {
        let formatter = XmlFormatter::new();
        let mut scan_result = ScanResult::default();
        scan_result.hosts.push(create_test_host());

        let result = formatter.format_scan_result(&scan_result).unwrap();
        assert!(result.contains("<nmaprun"));
        assert!(result.contains("</nmaprun>"));
    }

    #[test]
    fn test_grepable_formatter() {
        let formatter = GrepableFormatter::new();
        let port = PortResult {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            state_reason: "syn-ack".to_string(),
            state_ttl: Some(64),
            service: None,
            scripts: vec![],
        };

        let result = formatter.format_port(&port).unwrap();
        // Grepable format is "Ports: 80//tcp/open/unknown/"
        assert!(result.contains("80//tcp"));
        assert!(result.contains("open"));
    }

    #[test]
    fn test_script_kiddie_formatter() {
        let formatter = ScriptKiddieFormatter::new();
        let port = PortResult {
            number: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            state_reason: "syn-ack".to_string(),
            state_ttl: Some(64),
            service: Some(ServiceInfo {
                name: "ssh".to_string(),
                product: None,
                version: None,
                extrainfo: None,
                hostname: None,
                ostype: None,
                devicetype: None,
                method: "table".to_string(),
                confidence: 3,
                cpe: vec![],
            }),
            scripts: vec![],
        };

        let result = formatter.format_port(&port).unwrap();
        assert!(result.contains("| 22 |"));
        assert!(result.contains("open"));
        assert!(result.contains("ssh"));
    }

    #[test]
    fn test_verbosity_level_values() {
        assert_eq!(VerbosityLevel::Quiet as i8, -1);
        assert_eq!(VerbosityLevel::Normal as i8, 0);
        assert_eq!(VerbosityLevel::Verbose1 as i8, 1);
        assert_eq!(VerbosityLevel::Debug6 as i8, 9);
    }

    #[test]
    fn test_file_extensions() {
        let normal = NormalFormatter::new();
        assert_eq!(normal.file_extension(), "nmap");

        let xml = XmlFormatter::new();
        assert_eq!(xml.file_extension(), "xml");

        let json = JsonFormatter::new();
        assert_eq!(json.file_extension(), "json");

        let grep = GrepableFormatter::new();
        assert_eq!(grep.file_extension(), "gnmap");

        let kiddie = ScriptKiddieFormatter::new();
        assert_eq!(kiddie.file_extension(), "txt");
    }
}
