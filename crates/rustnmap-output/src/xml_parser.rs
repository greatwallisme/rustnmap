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

//! XML parser for Nmap XML output format.
//!
//! This module provides functionality to parse Nmap XML scan results
//! and convert them to RustNmap's `ScanResult` structure for diff
//! comparison and other operations.

use chrono::{TimeZone, Utc};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

use crate::error::{OutputError, Result};
use crate::models::{
    HostResult, HostStatus, HostTimes, MacAddress, OsMatch, PortResult, PortState, Protocol,
    ScanMetadata, ScanResult, ScanStatistics, ScanType, ScriptElement, ScriptResult, ServiceInfo,
};

/// Root element of Nmap XML output.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "nmaprun")]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct NmapXmlRun {
    /// Scanner name (should be "nmap" or "rustnmap")
    #[serde(rename = "@scanner")]
    scanner: String,

    /// Command line arguments
    #[serde(rename = "@args")]
    args: String,

    /// Scan start timestamp (Unix epoch)
    #[serde(rename = "@start", default)]
    start: i64,

    /// Scan start time string
    #[serde(rename = "@startstr", default)]
    startstr: String,

    /// Scanner version
    #[serde(rename = "@version", default)]
    version: String,

    /// XML output version
    #[serde(rename = "@xmloutputversion", default)]
    xmloutputversion: String,

    /// Scan information
    #[serde(default)]
    scaninfo: Vec<XmlScanInfo>,

    /// Verbose level
    #[serde(default)]
    verbose: XmlVerbose,

    /// Debugging level
    #[serde(default)]
    debugging: XmlDebugging,

    /// Host results
    #[serde(rename = "host", default)]
    hosts: Vec<XmlHost>,

    /// Run statistics
    #[serde(default)]
    runstats: XmlRunStats,
}

/// Scan information element.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlScanInfo {
    /// Scan type (syn, connect, udp, etc.)
    #[serde(rename = "@type", default)]
    scan_type: String,

    /// Protocol (tcp, udp, sctp)
    #[serde(rename = "@protocol", default)]
    protocol: String,

    /// Number of services scanned
    #[serde(rename = "@numservices", default)]
    num_services: u64,

    /// Service range
    #[serde(rename = "@services", default)]
    services: String,
}

/// Verbose level element.
#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlVerbose {
    /// Verbose level
    #[serde(rename = "@level", default)]
    level: i8,
}

/// Debugging level element.
#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlDebugging {
    /// Debugging level
    #[serde(rename = "@level", default)]
    level: u8,
}

/// Host element.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlHost {
    /// Start time (Unix timestamp)
    #[serde(rename = "@starttime", default)]
    starttime: i64,

    /// End time (Unix timestamp)
    #[serde(rename = "@endtime", default)]
    endtime: i64,

    /// Host status
    #[serde(default)]
    status: XmlStatus,

    /// Addresses (IP and MAC)
    #[serde(rename = "address", default)]
    addresses: Vec<XmlAddress>,

    /// Hostnames
    #[serde(default)]
    hostnames: XmlHostnames,

    /// Port results
    #[serde(default)]
    ports: XmlPorts,

    /// OS detection results
    #[serde(default)]
    os: XmlOs,

    /// Timing information
    #[serde(default)]
    times: XmlTimes,
}

/// Host status element.
#[derive(Debug, Clone, Deserialize)]
struct XmlStatus {
    /// State (up, down, unknown)
    #[serde(rename = "@state", default)]
    state: String,

    /// Reason for status
    #[serde(rename = "@reason", default)]
    reason: String,
}

impl Default for XmlStatus {
    fn default() -> Self {
        Self {
            state: "unknown".to_string(),
            reason: String::new(),
        }
    }
}

/// Address element.
#[derive(Debug, Clone, Deserialize)]
struct XmlAddress {
    /// Address value
    #[serde(rename = "@addr")]
    addr: String,

    /// Address type (ipv4, ipv6, mac)
    #[serde(rename = "@addrtype", default)]
    addrtype: String,

    /// Vendor (for MAC addresses)
    #[serde(rename = "@vendor", default)]
    vendor: Option<String>,
}

/// Hostnames container.
#[derive(Debug, Clone, Deserialize, Default)]
struct XmlHostnames {
    /// Hostname entries
    #[serde(rename = "hostname", default)]
    hostnames: Vec<XmlHostname>,
}

/// Hostname element.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlHostname {
    /// Hostname name
    #[serde(rename = "@name")]
    name: String,

    /// Hostname type (PTR, user)
    #[serde(rename = "@type", default)]
    hostname_type: String,
}

/// Ports container.
#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlPorts {
    /// Port entries
    #[serde(rename = "port", default)]
    ports: Vec<XmlPort>,

    /// Extraports information (filtered ports summary)
    #[serde(rename = "extraports", default)]
    extraports: Vec<XmlExtraPorts>,
}

/// Extra ports element (filtered/closed summary).
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlExtraPorts {
    /// State of extra ports
    #[serde(rename = "@state")]
    state: String,

    /// Count of extra ports
    #[serde(rename = "@count")]
    count: u64,
}

/// Port element.
#[derive(Debug, Clone, Deserialize)]
struct XmlPort {
    /// Protocol (tcp, udp, sctp)
    #[serde(rename = "@protocol")]
    protocol: String,

    /// Port number
    #[serde(rename = "@portid")]
    portid: u16,

    /// Port state
    #[serde(default)]
    state: XmlPortState,

    /// Service information
    #[serde(default)]
    service: XmlService,

    /// Script results
    #[serde(rename = "script", default)]
    scripts: Vec<XmlScript>,
}

/// Port state element.
#[derive(Debug, Clone, Deserialize)]
struct XmlPortState {
    /// State (open, closed, filtered, etc.)
    #[serde(rename = "@state", default)]
    state: String,

    /// Reason for state
    #[serde(rename = "@reason", default)]
    reason: String,

    /// TTL from response
    #[serde(rename = "@reason_ttl", default)]
    reason_ttl: Option<u8>,
}

impl Default for XmlPortState {
    fn default() -> Self {
        Self {
            state: "unknown".to_string(),
            reason: String::new(),
            reason_ttl: None,
        }
    }
}

/// Service element.
#[derive(Debug, Clone, Deserialize)]
struct XmlService {
    /// Service name
    #[serde(rename = "@name", default)]
    name: String,

    /// Product name
    #[serde(rename = "@product", default)]
    product: Option<String>,

    /// Version string
    #[serde(rename = "@version", default)]
    version: Option<String>,

    /// Extra information
    #[serde(rename = "@extrainfo", default)]
    extrainfo: Option<String>,

    /// Hostname from service
    #[serde(rename = "@hostname", default)]
    hostname: Option<String>,

    /// OS type
    #[serde(rename = "@ostype", default)]
    ostype: Option<String>,

    /// Device type
    #[serde(rename = "@devicetype", default)]
    devicetype: Option<String>,

    /// Detection method
    #[serde(rename = "@method", default)]
    method: String,

    /// Confidence level (1-10)
    #[serde(rename = "@conf", default = "default_confidence")]
    confidence: u8,

    /// CPE identifiers
    #[serde(rename = "cpe", default)]
    cpe: Vec<XmlCpe>,
}

impl Default for XmlService {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            product: None,
            version: None,
            extrainfo: None,
            hostname: None,
            ostype: None,
            devicetype: None,
            method: "table".to_string(),
            confidence: default_confidence(),
            cpe: Vec::new(),
        }
    }
}

fn default_confidence() -> u8 {
    3
}

/// CPE element.
#[derive(Debug, Clone, Deserialize)]
struct XmlCpe {
    /// CPE string (text content)
    #[serde(rename = "$text", default)]
    text: String,
}

/// Script element.
#[derive(Debug, Clone, Deserialize)]
struct XmlScript {
    /// Script ID
    #[serde(rename = "@id")]
    id: String,

    /// Script output
    #[serde(rename = "@output", default)]
    output: String,

    /// Script elements (tables)
    #[serde(default)]
    elem: Vec<XmlScriptElem>,

    /// Script tables
    #[serde(default)]
    table: Vec<XmlScriptTable>,
}

/// Script element.
#[derive(Debug, Clone, Deserialize)]
struct XmlScriptElem {
    /// Element key
    #[serde(rename = "@key", default)]
    key: String,

    /// Element value
    #[serde(rename = "$text", default)]
    text: String,
}

/// Script table element.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlScriptTable {
    /// Table key
    #[serde(rename = "@key", default)]
    key: String,

    /// Nested elements
    #[serde(default)]
    elem: Vec<XmlScriptElem>,

    /// Nested tables
    #[serde(default)]
    table: Vec<XmlScriptTable>,
}

/// OS detection container.
#[derive(Debug, Clone, Deserialize, Default)]
struct XmlOs {
    /// OS matches
    #[serde(rename = "osmatch", default)]
    osmatches: Vec<XmlOsMatch>,
}

/// OS match element.
#[derive(Debug, Clone, Deserialize)]
struct XmlOsMatch {
    /// OS name
    #[serde(rename = "@name")]
    name: String,

    /// Match accuracy (0-100)
    #[serde(rename = "@accuracy")]
    accuracy: u8,

    /// OS class information
    #[serde(rename = "osclass", default)]
    osclass: Vec<XmlOsClass>,
}

/// OS class element.
#[derive(Debug, Clone, Deserialize)]
struct XmlOsClass {
    /// Vendor
    #[serde(rename = "@vendor", default)]
    vendor: Option<String>,

    /// OS family
    #[serde(rename = "@osfamily", default)]
    osfamily: Option<String>,

    /// OS generation
    #[serde(rename = "@osgen", default)]
    osgen: Option<String>,

    /// Device type
    #[serde(rename = "@type", default)]
    device_type: Option<String>,

    /// CPE identifiers
    #[serde(rename = "cpe", default)]
    cpe: Vec<XmlCpe>,
}

/// Timing information element.
#[derive(Debug, Clone, Deserialize, Default)]
struct XmlTimes {
    /// Smoothed RTT (microseconds)
    #[serde(rename = "@srtt", default)]
    srtt: Option<u64>,

    /// RTT variance (microseconds)
    #[serde(rename = "@rttvar", default)]
    rttvar: Option<u64>,

    /// Timeout (microseconds)
    #[serde(rename = "@to", default)]
    timeout: Option<u64>,
}

/// Run statistics container.
#[derive(Debug, Clone, Deserialize, Default)]
struct XmlRunStats {
    /// Finished information
    #[serde(default)]
    finished: XmlFinished,

    /// Hosts statistics
    #[serde(default)]
    hosts: XmlHostStats,
}

/// Finished element.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code, reason = "Fields needed for XML deserialization")]
struct XmlFinished {
    /// Finish time (Unix timestamp)
    #[serde(rename = "@time", default)]
    time: i64,

    /// Finish time string
    #[serde(rename = "@timestr", default)]
    timestr: String,

    /// Elapsed time (seconds)
    #[serde(rename = "@elapsed", default)]
    elapsed: f64,
}

impl Default for XmlFinished {
    fn default() -> Self {
        Self {
            time: 0,
            timestr: String::new(),
            elapsed: 0.0,
        }
    }
}

/// Hosts statistics element.
#[derive(Debug, Clone, Deserialize, Default)]
struct XmlHostStats {
    /// Hosts up
    #[serde(rename = "@up", default)]
    up: usize,

    /// Hosts down
    #[serde(rename = "@down", default)]
    down: usize,

    /// Total hosts
    #[serde(rename = "@total", default)]
    total: usize,
}

/// Parse Nmap XML output and convert to `ScanResult`.
///
/// This function parses XML output from either Nmap or RustNmap
/// and converts it to the internal `ScanResult` format for
/// diff comparison and other operations.
///
/// # Arguments
///
/// * `xml` - XML string to parse
///
/// # Returns
///
/// Parsed `ScanResult` on success.
///
/// # Errors
///
/// Returns `OutputError::InvalidData` if XML parsing fails or
/// if required fields are missing.
///
/// # Example
///
/// ```no_run
/// use rustnmap_output::parse_nmap_xml;
///
/// let xml = r#"<nmaprun scanner="nmap" args="nmap localhost">
///     <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/></host>
/// </nmaprun>"#;
///
/// let result = parse_nmap_xml(xml).unwrap();
/// assert_eq!(result.hosts.len(), 1);
/// ```
pub fn parse_nmap_xml(xml: &str) -> Result<ScanResult> {
    // Parse XML into intermediate structure
    let nmap_run: NmapXmlRun = quick_xml::de::from_str(xml)
        .map_err(|e| OutputError::InvalidData(format!("Failed to parse XML: {e}")))?;

    // Convert to ScanResult
    convert_to_scan_result(nmap_run)
}

/// Convert XML structure to `ScanResult`.
fn convert_to_scan_result(xml: NmapXmlRun) -> Result<ScanResult> {
    // Parse start time
    let start_time = Utc
        .timestamp_opt(xml.start, 0)
        .single()
        .unwrap_or_else(Utc::now);

    // Parse end time from runstats
    let end_time = Utc
        .timestamp_opt(xml.runstats.finished.time, 0)
        .single()
        .unwrap_or_else(Utc::now);

    // Calculate elapsed time
    let elapsed = Duration::from_secs_f64(xml.runstats.finished.elapsed);

    // Determine scan type from scaninfo
    let scan_type = xml
        .scaninfo
        .first()
        .map_or(ScanType::TcpSyn, |info| parse_scan_type(&info.scan_type));

    // Determine protocol from scaninfo
    let protocol = xml
        .scaninfo
        .first()
        .map_or(Protocol::Tcp, |info| parse_protocol(&info.protocol));

    // Convert hosts
    let hosts: Vec<HostResult> = xml
        .hosts
        .into_iter()
        .map(convert_host)
        .collect::<Result<Vec<_>>>()?;

    // Build statistics
    let statistics = ScanStatistics {
        total_hosts: xml.runstats.hosts.total,
        hosts_up: xml.runstats.hosts.up,
        hosts_down: xml.runstats.hosts.down,
        total_ports: hosts.iter().map(|h| h.ports.len() as u64).sum(),
        open_ports: hosts
            .iter()
            .flat_map(|h| &h.ports)
            .filter(|p| matches!(p.state, PortState::Open))
            .count() as u64,
        closed_ports: hosts
            .iter()
            .flat_map(|h| &h.ports)
            .filter(|p| matches!(p.state, PortState::Closed))
            .count() as u64,
        filtered_ports: hosts
            .iter()
            .flat_map(|h| &h.ports)
            .filter(|p| matches!(p.state, PortState::Filtered))
            .count() as u64,
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
    };

    Ok(ScanResult {
        metadata: ScanMetadata {
            scanner_version: xml.version,
            command_line: xml.args,
            start_time,
            end_time,
            elapsed,
            scan_type,
            protocol,
        },
        hosts,
        statistics,
        errors: Vec::new(),
    })
}

/// Convert XML host to `HostResult`.
fn convert_host(xml_host: XmlHost) -> Result<HostResult> {
    // Find IP address
    let ip = xml_host
        .addresses
        .iter()
        .find(|a| a.addrtype == "ipv4" || a.addrtype == "ipv6")
        .and_then(|a| a.addr.parse::<IpAddr>().ok())
        .ok_or_else(|| OutputError::InvalidData("No valid IP address found in host".to_string()))?;

    // Find MAC address
    let mac = xml_host
        .addresses
        .iter()
        .find(|a| a.addrtype == "mac")
        .map(|a| MacAddress {
            address: a.addr.clone(),
            vendor: a.vendor.clone(),
        });

    // Get hostname
    let hostname = xml_host.hostnames.hostnames.first().map(|h| h.name.clone());

    // Parse status
    let status = match xml_host.status.state.as_str() {
        "up" => HostStatus::Up,
        "down" => HostStatus::Down,
        _ => HostStatus::Unknown,
    };

    // Convert ports
    let ports: Vec<PortResult> = xml_host
        .ports
        .ports
        .into_iter()
        .map(convert_port)
        .collect::<Result<Vec<_>>>()?;

    // Convert OS matches
    let os_matches: Vec<OsMatch> = xml_host
        .os
        .osmatches
        .into_iter()
        .map(convert_os_match)
        .collect();

    // Convert timing
    let times = HostTimes {
        srtt: xml_host.times.srtt,
        rttvar: xml_host.times.rttvar,
        timeout: xml_host.times.timeout,
    };

    Ok(HostResult {
        ip,
        mac,
        hostname,
        status,
        status_reason: xml_host.status.reason,
        latency: Duration::ZERO,
        ports,
        os_matches,
        scripts: Vec::new(),
        traceroute: None,
        times,
    })
}

/// Convert XML port to `PortResult`.
fn convert_port(xml_port: XmlPort) -> Result<PortResult> {
    let protocol = parse_protocol(&xml_port.protocol);

    let state = parse_port_state(&xml_port.state.state);

    let service = if xml_port.service.name != "unknown" || xml_port.service.method != "table" {
        Some(ServiceInfo {
            name: xml_port.service.name,
            product: xml_port.service.product,
            version: xml_port.service.version,
            extrainfo: xml_port.service.extrainfo,
            hostname: xml_port.service.hostname,
            ostype: xml_port.service.ostype,
            devicetype: xml_port.service.devicetype,
            method: xml_port.service.method,
            confidence: xml_port.service.confidence,
            cpe: xml_port.service.cpe.into_iter().map(|c| c.text).collect(),
        })
    } else {
        None
    };

    let scripts: Vec<ScriptResult> = xml_port.scripts.into_iter().map(convert_script).collect();

    Ok(PortResult {
        number: xml_port.portid,
        protocol,
        state,
        state_reason: xml_port.state.reason,
        state_ttl: xml_port.state.reason_ttl,
        service,
        scripts,
    })
}

/// Convert XML script to `ScriptResult`.
fn convert_script(xml_script: XmlScript) -> ScriptResult {
    let elements: Vec<ScriptElement> = xml_script
        .elem
        .into_iter()
        .map(|e| ScriptElement {
            key: e.key,
            value: serde_json::Value::String(e.text),
        })
        .chain(xml_script.table.into_iter().flat_map(|t| {
            t.elem.into_iter().map(|e| ScriptElement {
                key: e.key,
                value: serde_json::Value::String(e.text),
            })
        }))
        .collect();

    ScriptResult {
        id: xml_script.id,
        output: xml_script.output,
        elements,
    }
}

/// Convert XML OS match to `OsMatch`.
fn convert_os_match(xml_match: XmlOsMatch) -> OsMatch {
    let first_class = xml_match.osclass.first();

    OsMatch {
        name: xml_match.name,
        accuracy: xml_match.accuracy,
        os_family: first_class.as_ref().and_then(|c| c.osfamily.clone()),
        os_generation: first_class.as_ref().and_then(|c| c.osgen.clone()),
        vendor: first_class.as_ref().and_then(|c| c.vendor.clone()),
        device_type: first_class.as_ref().and_then(|c| c.device_type.clone()),
        cpe: first_class
            .map(|c| c.cpe.iter().map(|cpe| cpe.text.clone()).collect())
            .unwrap_or_default(),
    }
}

/// Parse scan type string to `ScanType`.
fn parse_scan_type(s: &str) -> ScanType {
    match s {
        "syn" => ScanType::TcpSyn,
        "connect" => ScanType::TcpConnect,
        "fin" => ScanType::TcpFin,
        "null" => ScanType::TcpNull,
        "xmas" => ScanType::TcpXmas,
        "maimon" => ScanType::TcpMaimon,
        "udp" => ScanType::Udp,
        "sctpinit" => ScanType::SctpInit,
        "sctpcookie" => ScanType::SctpCookie,
        "ipproto" => ScanType::IpProtocol,
        "ping" => ScanType::Ping,
        "ack" => ScanType::TcpAck,
        "window" => ScanType::TcpWindow,
        _ => ScanType::TcpSyn,
    }
}

/// Parse protocol string to `Protocol`.
fn parse_protocol(s: &str) -> Protocol {
    match s {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "sctp" => Protocol::Sctp,
        _ => Protocol::Tcp,
    }
}

/// Parse port state string to `PortState`.
fn parse_port_state(s: &str) -> PortState {
    match s {
        "open" => PortState::Open,
        "closed" => PortState::Closed,
        "filtered" => PortState::Filtered,
        "unfiltered" => PortState::Unfiltered,
        "open|filtered" => PortState::OpenOrFiltered,
        "closed|filtered" => PortState::ClosedOrFiltered,
        "open|closed" => PortState::OpenOrClosed,
        "filtered|closed" => PortState::FilteredOrClosed,
        _ => PortState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_xml() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX simple.xml -p 22,113 scanme.nmap.org" start="1247268210" startstr="Fri Jul 10 17:23:30 2009" version="4.90RC2" xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" numservices="2" services="22,113"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1247268210" endtime="1247268210">
<status state="up" reason="echo-reply"/>
<address addr="64.13.134.52" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="52"/>
<service name="ssh" method="table" conf="3"/>
</port>
<port protocol="tcp" portid="113">
<state state="closed" reason="reset" reason_ttl="52"/>
<service name="auth" method="table" conf="3"/>
</port>
</ports>
<times srtt="91167" rttvar="51529" to="297283"/>
</host>
<runstats>
<finished time="1247268210" timestr="Fri Jul 10 17:23:30 2009" elapsed="0.56"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"#;

        let result = parse_nmap_xml(xml).unwrap();

        assert_eq!(result.metadata.scanner_version, "4.90RC2");
        assert_eq!(
            result.metadata.command_line,
            "nmap -oX simple.xml -p 22,113 scanme.nmap.org"
        );
        assert_eq!(result.hosts.len(), 1);

        let host = &result.hosts[0];
        assert_eq!(host.ip.to_string(), "64.13.134.52");
        assert_eq!(host.status, HostStatus::Up);
        assert_eq!(host.hostname, Some("scanme.nmap.org".to_string()));
        assert_eq!(host.ports.len(), 2);

        let port22 = &host.ports[0];
        assert_eq!(port22.number, 22);
        assert_eq!(port22.state, PortState::Open);
        assert_eq!(port22.service.as_ref().unwrap().name, "ssh");

        let port113 = &host.ports[1];
        assert_eq!(port113.number, 113);
        assert_eq!(port113.state, PortState::Closed);
    }

    #[test]
    fn test_parse_scan_type() {
        assert_eq!(parse_scan_type("syn"), ScanType::TcpSyn);
        assert_eq!(parse_scan_type("connect"), ScanType::TcpConnect);
        assert_eq!(parse_scan_type("udp"), ScanType::Udp);
        assert_eq!(parse_scan_type("fin"), ScanType::TcpFin);
        assert_eq!(parse_scan_type("unknown"), ScanType::TcpSyn);
    }

    #[test]
    fn test_parse_protocol() {
        assert_eq!(parse_protocol("tcp"), Protocol::Tcp);
        assert_eq!(parse_protocol("udp"), Protocol::Udp);
        assert_eq!(parse_protocol("sctp"), Protocol::Sctp);
        assert_eq!(parse_protocol("unknown"), Protocol::Tcp);
    }

    #[test]
    fn test_parse_port_state() {
        assert_eq!(parse_port_state("open"), PortState::Open);
        assert_eq!(parse_port_state("closed"), PortState::Closed);
        assert_eq!(parse_port_state("filtered"), PortState::Filtered);
        assert_eq!(parse_port_state("open|filtered"), PortState::OpenOrFiltered);
        assert_eq!(parse_port_state("unknown"), PortState::Unknown);
    }

    #[test]
    fn test_parse_xml_with_mac_address() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap localhost">
<host>
<status state="up" reason="arp-response"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="TestVendor"/>
</host>
<runstats>
<finished time="0" elapsed="1.0"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"#;

        let result = parse_nmap_xml(xml).unwrap();
        let host = &result.hosts[0];

        assert!(host.mac.is_some());
        let mac = host.mac.as_ref().unwrap();
        assert_eq!(mac.address, "00:11:22:33:44:55");
        assert_eq!(mac.vendor, Some("TestVendor".to_string()));
    }

    #[test]
    fn test_parse_xml_with_os_detection() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O localhost">
<host>
<status state="up" reason="echo-reply"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<os>
<osmatch name="Linux 5.4" accuracy="95">
<osclass vendor="Linux" osfamily="Linux" osgen="5.X" type="general purpose">
<cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
</osclass>
</osmatch>
</os>
</host>
<runstats>
<finished time="0" elapsed="5.0"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"#;

        let result = parse_nmap_xml(xml).unwrap();
        let host = &result.hosts[0];

        assert_eq!(host.os_matches.len(), 1);
        let os = &host.os_matches[0];
        assert_eq!(os.name, "Linux 5.4");
        assert_eq!(os.accuracy, 95);
        assert_eq!(os.os_family, Some("Linux".to_string()));
        assert_eq!(os.os_generation, Some("5.X".to_string()));
    }
}
