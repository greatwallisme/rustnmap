// Integration tests for output formatters.
//
// These tests verify that all output formatters (Normal, XML, JSON, Grepable, Script Kiddie)
// correctly format scan results in a Nmap-compatible manner.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rustnmap_output::formatter::{
    GrepableFormatter, JsonFormatter, NormalFormatter, OutputFormatter, ScriptKiddieFormatter,
    VerbosityLevel, XmlFormatter,
};
use rustnmap_output::models::{
    HostResult, HostStatus, HostTimes, MacAddress, OsMatch, PortResult, PortState, Protocol,
    ScanResult, ScanStatistics, ScanType, ScriptElement, ScriptResult, ServiceInfo, TracerouteHop,
    TracerouteResult,
};

/// Create a test host with basic information.
fn create_basic_host() -> HostResult {
    HostResult {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        mac: None,
        hostname: None,
        status: HostStatus::Up,
        status_reason: "echo-reply".to_string(),
        latency: Duration::from_millis(5),
        ports: vec![],
        os_matches: vec![],
        scripts: vec![],
        traceroute: None,
        times: HostTimes {
            srtt: Some(5000),
            rttvar: Some(1000),
            timeout: Some(2000000),
        },
    }
}

/// Create a test host with multiple ports and services.
fn create_host_with_ports() -> HostResult {
    HostResult {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        mac: Some(MacAddress {
            address: "00:11:22:33:44:55".to_string(),
            vendor: Some("TestVendor".to_string()),
        }),
        hostname: Some("testhost.local".to_string()),
        status: HostStatus::Up,
        status_reason: "syn-ack".to_string(),
        latency: Duration::from_millis(2),
        ports: vec![
            PortResult {
                number: 22,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                state_reason: "syn-ack".to_string(),
                state_ttl: Some(64),
                service: Some(ServiceInfo {
                    name: "ssh".to_string(),
                    product: Some("OpenSSH".to_string()),
                    version: Some("8.9p1".to_string()),
                    extrainfo: Some("Ubuntu Linux".to_string()),
                    hostname: None,
                    ostype: Some("Linux".to_string()),
                    devicetype: None,
                    method: "probed".to_string(),
                    confidence: 10,
                    cpe: vec!["cpe:/a:openbsd:openssh:8.9p1".to_string()],
                }),
                scripts: vec![],
            },
            PortResult {
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
            },
            PortResult {
                number: 443,
                protocol: Protocol::Tcp,
                state: PortState::Filtered,
                state_reason: "no-response".to_string(),
                state_ttl: None,
                service: Some(ServiceInfo {
                    name: "https".to_string(),
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
            },
            PortResult {
                number: 21,
                protocol: Protocol::Tcp,
                state: PortState::Closed,
                state_reason: "reset".to_string(),
                state_ttl: Some(64),
                service: Some(ServiceInfo {
                    name: "ftp".to_string(),
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
            },
        ],
        os_matches: vec![
            OsMatch {
                name: "Linux 5.4".to_string(),
                accuracy: 95,
                os_family: Some("Linux".to_string()),
                os_generation: Some("5.X".to_string()),
                vendor: Some("Linux".to_string()),
                device_type: Some("general purpose".to_string()),
                cpe: vec!["cpe:/o:linux:linux_kernel:5.4".to_string()],
            },
            OsMatch {
                name: "Linux 5.15".to_string(),
                accuracy: 88,
                os_family: Some("Linux".to_string()),
                os_generation: Some("5.X".to_string()),
                vendor: Some("Linux".to_string()),
                device_type: Some("general purpose".to_string()),
                cpe: vec!["cpe:/o:linux:linux_kernel:5.15".to_string()],
            },
        ],
        scripts: vec![ScriptResult {
            id: "http-title".to_string(),
            output: "Welcome to Test Server".to_string(),
            elements: vec![ScriptElement {
                key: "title".to_string(),
                value: serde_json::json!("Welcome to Test Server"),
            }],
        }],
        traceroute: Some(TracerouteResult {
            protocol: Protocol::Tcp,
            port: 80,
            hops: vec![
                TracerouteHop {
                    ttl: 1,
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    hostname: Some("gateway.local".to_string()),
                    rtt: Some(Duration::from_millis(1)),
                },
                TracerouteHop {
                    ttl: 2,
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    hostname: None,
                    rtt: Some(Duration::from_millis(5)),
                },
                TracerouteHop {
                    ttl: 3,
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    hostname: Some("target.local".to_string()),
                    rtt: Some(Duration::from_millis(10)),
                },
            ],
        }),
        times: HostTimes {
            srtt: Some(2300),
            rttvar: Some(500),
            timeout: Some(1000000),
        },
    }
}

/// Create a test scan result with multiple hosts.
fn create_full_scan_result() -> ScanResult {
    let mut result = ScanResult::default();
    result.metadata.scanner_version = "1.0.0".to_string();
    result.metadata.command_line = "rustnmap -sS -A 192.168.1.0/24".to_string();
    result.metadata.scan_type = ScanType::TcpSyn;
    result.metadata.protocol = Protocol::Tcp;
    result.metadata.elapsed = Duration::from_secs(120);

    result.hosts = vec![
        create_host_with_ports(),
        HostResult {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            mac: None,
            hostname: Some("secondhost.local".to_string()),
            status: HostStatus::Down,
            status_reason: "no-response".to_string(),
            latency: Duration::from_secs(0),
            ports: vec![],
            os_matches: vec![],
            scripts: vec![],
            traceroute: None,
            times: HostTimes {
                srtt: None,
                rttvar: None,
                timeout: None,
            },
        },
    ];

    result.statistics = ScanStatistics {
        total_hosts: 2,
        hosts_up: 1,
        hosts_down: 1,
        total_ports: 1000,
        open_ports: 2,
        closed_ports: 1,
        filtered_ports: 1,
        bytes_sent: 50000,
        bytes_received: 30000,
        packets_sent: 1000,
        packets_received: 800,
    };

    result
}

/// Test normal formatter with empty scan result.
#[test]
fn test_normal_formatter_empty_scan() {
    let formatter = NormalFormatter::new();
    let result = ScanResult::default();

    let output = formatter.format_scan_result(&result).unwrap();

    assert!(output.contains("RustNmap"));
    assert!(output.contains("Nmap done:"));
    assert!(output.contains("0 IP address"));
}

/// Test normal formatter with single host.
#[test]
fn test_normal_formatter_single_host() {
    let formatter = NormalFormatter::new();
    let mut result = ScanResult::default();
    result.hosts.push(create_basic_host());
    result.statistics.total_hosts = 1;
    result.statistics.hosts_up = 1;

    let output = formatter.format_scan_result(&result).unwrap();

    assert!(output.contains("192.168.1.1"));
    assert!(output.contains("Host is up"));
    assert!(output.contains("1 IP address (1 host up)"));
}

/// Test normal formatter with ports and services.
#[test]
fn test_normal_formatter_with_services() {
    let formatter = NormalFormatter::new();
    let mut result = ScanResult::default();
    result.hosts.push(create_host_with_ports());
    result.statistics.total_hosts = 1;
    result.statistics.hosts_up = 1;

    let output = formatter.format_scan_result(&result).unwrap();

    // Check host information
    assert!(output.contains("192.168.1.100"));
    assert!(output.contains("testhost.local"));
    assert!(output.contains("MAC Address: 00:11:22:33:44:55"));
    assert!(output.contains("TestVendor"));

    // Check port information
    assert!(output.contains("22/tcp"));
    assert!(output.contains("80/tcp"));
    assert!(output.contains("open"));
    assert!(output.contains("ssh"));
    assert!(output.contains("http"));
    // Note: Normal formatter shows service name only, not product version

    // Check OS detection
    assert!(output.contains("Linux 5.4"));
    assert!(output.contains("95%"));

    // Check traceroute (uses IP addresses, not hostnames)
    assert!(output.contains("TRACEROUTE"));
    assert!(output.contains("192.168.1.1")); // First hop IP
}

/// Test normal formatter with verbosity levels.
#[test]
fn test_normal_formatter_verbosity() {
    let formatter_quiet = NormalFormatter::with_verbosity(VerbosityLevel::Quiet);
    let formatter_normal = NormalFormatter::with_verbosity(VerbosityLevel::Normal);
    let formatter_verbose = NormalFormatter::with_verbosity(VerbosityLevel::Verbose1);

    let mut result = ScanResult::default();
    result.hosts.push(create_basic_host());

    // All should produce valid output
    let _ = formatter_quiet.format_scan_result(&result).unwrap();
    let _ = formatter_normal.format_scan_result(&result).unwrap();
    let _ = formatter_verbose.format_scan_result(&result).unwrap();
}

/// Test XML formatter with empty result.
#[test]
fn test_xml_formatter_empty_scan() {
    let formatter = XmlFormatter::new();
    let result = ScanResult::default();

    let output = formatter.format_scan_result(&result).unwrap();

    // XML formatter produces nmaprun element
    assert!(output.contains("<nmaprun"));
    assert!(output.contains("</nmaprun>"));
    assert!(output.contains("scanner=\"rustnmap\""));
    assert!(output.contains("xmloutputversion=\"1.05\""));
}

/// Test XML formatter with full scan result.
#[test]
fn test_xml_formatter_full_scan() {
    let formatter = XmlFormatter::new();
    let result = create_full_scan_result();

    let output = formatter.format_scan_result(&result).unwrap();

    // Check structure
    assert!(output.contains("<nmaprun"));
    assert!(output.contains("</nmaprun>"));

    // Check scan info
    assert!(output.contains("<scaninfo"));
    assert!(output.contains("type=\"syn\""));
    assert!(output.contains("protocol=\"tcp\""));

    // Check host information
    assert!(output.contains("<host"));
    assert!(output.contains("<status state=\"up\""));
    assert!(output.contains("<status state=\"down\""));
    assert!(output.contains("addr=\"192.168.1.100\""));
    assert!(output.contains("addr=\"192.168.1.2\""));

    // Check ports
    assert!(output.contains("<ports>"));
    assert!(output.contains("port protocol=\"tcp\""));
    assert!(output.contains("portid=\"22\""));
    assert!(output.contains("portid=\"80\""));
    assert!(output.contains("state=\"open\""));
    assert!(output.contains("state=\"filtered\""));

    // Check services
    assert!(output.contains("<service"));
    assert!(output.contains("name=\"ssh\""));
    assert!(output.contains("name=\"http\""));
    assert!(output.contains("product=\"nginx\""));

    // Check OS detection
    assert!(output.contains("<os>"));
    assert!(output.contains("<osmatch"));
    assert!(output.contains("name=\"Linux 5.4\""));
    assert!(output.contains("accuracy=\"95\""));
}

/// Test XML formatter produces valid XML structure.
#[test]
fn test_xml_formatter_valid_structure() {
    let formatter = XmlFormatter::new();
    let result = create_full_scan_result();

    let output = formatter.format_scan_result(&result).unwrap();

    // Verify balanced tags - <nmaprun> appears as opening tag and closing tag
    let open_nmaprun = output.matches("<nmaprun").count();
    let close_nmaprun = output.matches("</nmaprun>").count();
    assert_eq!(
        open_nmaprun, 1,
        "Should have exactly one nmaprun opening tag"
    );
    assert_eq!(
        close_nmaprun, 1,
        "Should have exactly one nmaprun closing tag"
    );

    // Count host elements - each host has one opening tag with attributes
    // Use "<host " to avoid matching "<hostnames" or "<hostname"
    let host_count = result.hosts.len();
    let open_host = output.matches("<host ").count();
    let close_host = output.matches("</host>").count();
    assert_eq!(
        open_host, host_count,
        "Should have {} host opening tags",
        host_count
    );
    assert_eq!(
        close_host, host_count,
        "Should have {} host closing tags",
        host_count
    );

    // Verify ports tags are balanced
    let open_ports = output.matches("<ports>").count();
    let close_ports = output.matches("</ports>").count();
    assert_eq!(open_ports, close_ports, "Unbalanced ports tags");
}

/// Test JSON formatter with empty result.
#[test]
fn test_json_formatter_empty_scan() {
    let formatter = JsonFormatter::new();
    let result = ScanResult::default();

    let output = formatter.format_scan_result(&result).unwrap();

    // Should be valid JSON starting with opening brace
    assert!(output.starts_with('{'));
    assert!(output.contains("\"metadata\""));
    assert!(output.contains("\"hosts\""));
    assert!(output.contains("\"statistics\""));

    // Verify it's parseable
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed["hosts"].is_array());
    assert_eq!(parsed["hosts"].as_array().unwrap().len(), 0);
}

/// Test JSON formatter with full scan result.
#[test]
fn test_json_formatter_full_scan() {
    let formatter = JsonFormatter::new();
    let result = create_full_scan_result();

    let output = formatter.format_scan_result(&result).unwrap();

    // Parse and verify structure
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Check metadata
    assert_eq!(parsed["metadata"]["scanner_version"], "1.0.0");
    assert_eq!(
        parsed["metadata"]["command_line"],
        "rustnmap -sS -A 192.168.1.0/24"
    );
    assert_eq!(parsed["metadata"]["scan_type"], "tcpsyn");

    // Check hosts
    let hosts = parsed["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);

    // Check first host
    assert_eq!(hosts[0]["ip"], "192.168.1.100");
    assert_eq!(hosts[0]["hostname"], "testhost.local");
    assert_eq!(hosts[0]["status"], "up");

    // Check ports
    let ports = hosts[0]["ports"].as_array().unwrap();
    assert!(!ports.is_empty());
    assert_eq!(ports[0]["number"], 22);
    assert_eq!(ports[0]["state"], "open");

    // Check services
    assert_eq!(ports[0]["service"]["name"], "ssh");
    assert_eq!(ports[0]["service"]["product"], "OpenSSH");

    // Check OS matches
    let os_matches = hosts[0]["os_matches"].as_array().unwrap();
    assert!(!os_matches.is_empty());
    assert_eq!(os_matches[0]["name"], "Linux 5.4");
    assert_eq!(os_matches[0]["accuracy"], 95);

    // Check statistics
    assert_eq!(parsed["statistics"]["total_hosts"], 2);
    assert_eq!(parsed["statistics"]["hosts_up"], 1);
    assert_eq!(parsed["statistics"]["open_ports"], 2);
}

/// Test JSON formatter compact output.
#[test]
fn test_json_formatter_compact() {
    let formatter = JsonFormatter::with_pretty(false);
    let result = create_full_scan_result();

    let output = formatter.format_scan_result(&result).unwrap();

    // Compact output should not have newlines except at end
    let line_count = output.lines().count();
    assert_eq!(line_count, 1, "Compact JSON should be single line");

    // But should still be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed["hosts"].is_array());
}

/// Test JSON formatter pretty output.
#[test]
fn test_json_formatter_pretty() {
    let formatter = JsonFormatter::with_pretty(true);
    let result = create_full_scan_result();

    let output = formatter.format_scan_result(&result).unwrap();

    // Pretty output should have multiple lines with indentation
    let line_count = output.lines().count();
    assert!(line_count > 10, "Pretty JSON should have multiple lines");

    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed["hosts"].is_array());
}

/// Test grepable formatter with empty result.
#[test]
fn test_grepable_formatter_empty_scan() {
    let formatter = GrepableFormatter::new();
    let result = ScanResult::default();

    let output = formatter.format_scan_result(&result).unwrap();

    assert!(output.contains("# rustnmap"));
    assert!(output.contains("Nmap done at"));
    assert!(output.contains("0 IP address"));
}

/// Test grepable formatter with ports.
#[test]
fn test_grepable_formatter_with_ports() {
    let formatter = GrepableFormatter::new();
    let mut result = ScanResult::default();
    result.hosts.push(create_host_with_ports());
    result.statistics.total_hosts = 1;
    result.statistics.hosts_up = 1;

    let output = formatter.format_scan_result(&result).unwrap();

    // Check header format
    assert!(output.contains("# rustnmap"));
    assert!(output.contains("scan initiated"));

    // Check port lines - format is "Ports: <port>//<proto>/<state>/<service>/<version>"
    // Note: Grepable format includes service name and version (not product)
    assert!(output.contains("Ports: 22//tcp/open/ssh/8.9p1"));
    assert!(output.contains("Ports: 80//tcp/open/http/1.18.0"));
    assert!(output.contains("Ports: 443//tcp/filtered/https/"));

    // Check footer
    assert!(output.contains("Nmap done at"));
    assert!(output.contains("1 IP address"));
}

/// Test grepable formatter port format.
#[test]
fn test_grepable_formatter_port_format() {
    let formatter = GrepableFormatter::new();

    let port = PortResult {
        number: 8080,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        state_reason: "syn-ack".to_string(),
        state_ttl: Some(64),
        service: Some(ServiceInfo {
            name: "http-proxy".to_string(),
            product: None,
            version: None,
            extrainfo: None,
            hostname: None,
            ostype: None,
            devicetype: None,
            method: "probed".to_string(),
            confidence: 10,
            cpe: vec![],
        }),
        scripts: vec![],
    };

    let output = formatter.format_port(&port).unwrap();
    assert_eq!(output, "Ports: 8080//tcp/open/http-proxy/\n");
}

/// Test script kiddie formatter with empty result.
#[test]
fn test_script_kiddie_formatter_empty_scan() {
    let formatter = ScriptKiddieFormatter::new();
    let result = ScanResult::default();

    let output = formatter.format_scan_result(&result).unwrap();

    // Empty scan should produce empty output
    assert!(output.is_empty());
}

/// Test script kiddie formatter with hosts.
#[test]
fn test_script_kiddie_formatter_with_hosts() {
    let formatter = ScriptKiddieFormatter::new();
    let mut result = ScanResult::default();
    result.hosts.push(create_host_with_ports());

    let output = formatter.format_scan_result(&result).unwrap();

    // Check host line format: "IP (IP) [hostname]"
    assert!(output.contains("192.168.1.100 (192.168.1.100) [testhost.local]"));

    // Check port format: "  | <port> | <state> | <service>"
    assert!(output.contains("| 22 | open | ssh"));
    assert!(output.contains("| 80 | open | http"));
    assert!(output.contains("| 443 | filtered | https"));
}

/// Test script kiddie formatter with scripts.
#[test]
fn test_script_kiddie_formatter_with_scripts() {
    let formatter = ScriptKiddieFormatter::new();

    let script = ScriptResult {
        id: "test-script".to_string(),
        output: "Test output line 1\nTest output line 2".to_string(),
        elements: vec![],
    };

    let output = formatter.format_script(&script).unwrap();
    assert!(output.contains("| |_ Test output line 1"));
}

/// Test all formatters with all port states.
#[test]
fn test_all_formatters_port_states() {
    let states = vec![
        PortState::Open,
        PortState::Closed,
        PortState::Filtered,
        PortState::Unfiltered,
        PortState::OpenOrFiltered,
        PortState::ClosedOrFiltered,
        PortState::OpenOrClosed,
        PortState::FilteredOrClosed,
        PortState::Unknown,
    ];

    for state in states {
        let mut result = ScanResult::default();
        let mut host = create_basic_host();
        host.ports.push(PortResult {
            number: 80,
            protocol: Protocol::Tcp,
            state,
            state_reason: "test".to_string(),
            state_ttl: None,
            service: None,
            scripts: vec![],
        });
        result.hosts.push(host);

        // All formatters should handle all states
        let normal = NormalFormatter::new();
        let xml = XmlFormatter::new();
        let json = JsonFormatter::new();
        let grepable = GrepableFormatter::new();
        let kiddie = ScriptKiddieFormatter::new();

        let _ = normal.format_scan_result(&result).unwrap();
        let _ = xml.format_scan_result(&result).unwrap();
        let _ = json.format_scan_result(&result).unwrap();
        let _ = grepable.format_scan_result(&result).unwrap();
        let _ = kiddie.format_scan_result(&result).unwrap();
    }
}

/// Test all formatters with all protocols.
#[test]
fn test_all_formatters_protocols() {
    let protocols = vec![Protocol::Tcp, Protocol::Udp, Protocol::Sctp];

    for protocol in protocols {
        let mut result = ScanResult::default();
        let mut host = create_basic_host();
        host.ports.push(PortResult {
            number: 53,
            protocol,
            state: PortState::Open,
            state_reason: "test".to_string(),
            state_ttl: None,
            service: Some(ServiceInfo {
                name: "dns".to_string(),
                product: None,
                version: None,
                extrainfo: None,
                hostname: None,
                ostype: None,
                devicetype: None,
                method: "probed".to_string(),
                confidence: 10,
                cpe: vec![],
            }),
            scripts: vec![],
        });
        result.hosts.push(host);

        let normal = NormalFormatter::new();
        let xml = XmlFormatter::new();
        let json = JsonFormatter::new();
        let grepable = GrepableFormatter::new();

        let normal_out = normal.format_scan_result(&result).unwrap();
        let xml_out = xml.format_scan_result(&result).unwrap();
        let json_out = json.format_scan_result(&result).unwrap();
        let grep_out = grepable.format_scan_result(&result).unwrap();

        // Verify protocol appears in output
        let proto_str = match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        assert!(
            normal_out.to_lowercase().contains(proto_str),
            "Normal formatter should contain {}",
            proto_str
        );
        assert!(
            xml_out.to_lowercase().contains(proto_str),
            "XML formatter should contain {}",
            proto_str
        );
        assert!(
            json_out.to_lowercase().contains(proto_str),
            "JSON formatter should contain {}",
            proto_str
        );
        assert!(
            grep_out.to_lowercase().contains(proto_str),
            "Grepable formatter should contain {}",
            proto_str
        );
    }
}

/// Test all formatters with all host statuses.
#[test]
fn test_all_formatters_host_statuses() {
    let statuses = vec![
        (HostStatus::Up, "up"),
        (HostStatus::Down, "down"),
        (HostStatus::Unknown, "unknown"),
    ];

    for (status, expected_str) in statuses {
        let mut result = ScanResult::default();
        let mut host = create_basic_host();
        host.status = status;
        result.hosts.push(host);

        let normal = NormalFormatter::new();
        let xml = XmlFormatter::new();
        let json = JsonFormatter::new();

        let normal_out = normal.format_scan_result(&result).unwrap();
        let xml_out = xml.format_scan_result(&result).unwrap();
        let json_out = json.format_scan_result(&result).unwrap();

        assert!(
            normal_out.to_lowercase().contains(expected_str),
            "Normal formatter should contain '{}' for {:?}",
            expected_str,
            status
        );
        assert!(
            xml_out.to_lowercase().contains(expected_str),
            "XML formatter should contain '{}' for {:?}",
            expected_str,
            status
        );
        assert!(
            json_out.to_lowercase().contains(expected_str),
            "JSON formatter should contain '{}' for {:?}",
            expected_str,
            status
        );
    }
}

/// Test formatter file extensions.
#[test]
fn test_formatter_file_extensions() {
    assert_eq!(NormalFormatter::new().file_extension(), "nmap");
    assert_eq!(XmlFormatter::new().file_extension(), "xml");
    assert_eq!(JsonFormatter::new().file_extension(), "json");
    assert_eq!(GrepableFormatter::new().file_extension(), "gnmap");
    assert_eq!(ScriptKiddieFormatter::new().file_extension(), "txt");
}

/// Test formatter format names.
#[test]
fn test_formatter_format_names() {
    assert_eq!(NormalFormatter::new().format_name(), "Normal");
    assert_eq!(XmlFormatter::new().format_name(), "XML");
    assert_eq!(JsonFormatter::new().format_name(), "JSON");
    assert_eq!(GrepableFormatter::new().format_name(), "Grepable");
    assert_eq!(ScriptKiddieFormatter::new().format_name(), "Script Kiddie");
}

/// Test normal formatter host formatting directly.
#[test]
fn test_normal_formatter_format_host() {
    let formatter = NormalFormatter::new();
    let host = create_host_with_ports();

    let output = formatter.format_host(&host).unwrap();

    assert!(output.contains("Nmap scan report for 192.168.1.100"));
    assert!(output.contains("Host is up"));
    assert!(output.contains("rDNS record"));
    assert!(output.contains("testhost.local"));
}

/// Test normal formatter port formatting directly.
#[test]
fn test_normal_formatter_format_port() {
    let formatter = NormalFormatter::new();

    let port = PortResult {
        number: 443,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        state_reason: "syn-ack".to_string(),
        state_ttl: Some(64),
        service: Some(ServiceInfo {
            name: "https".to_string(),
            product: Some("Apache".to_string()),
            version: Some("2.4.41".to_string()),
            extrainfo: None,
            hostname: None,
            ostype: None,
            devicetype: None,
            method: "probed".to_string(),
            confidence: 10,
            cpe: vec![],
        }),
        scripts: vec![],
    };

    let output = formatter.format_port(&port).unwrap();

    assert!(output.contains("443/tcp"));
    assert!(output.contains("open"));
    assert!(output.contains("https"));
}

/// Test normal formatter script formatting.
#[test]
fn test_normal_formatter_format_script() {
    let formatter = NormalFormatter::new();

    let script = ScriptResult {
        id: "http-title".to_string(),
        output: "Welcome Page\nVersion 1.0".to_string(),
        elements: vec![],
    };

    let output = formatter.format_script(&script).unwrap();

    assert!(output.contains("| http-title"));
    assert!(output.contains("|_ Welcome Page"));
    assert!(output.contains("|_ Version 1.0"));
}

/// Test scan result with script elements on ports.
#[test]
fn test_formatters_with_port_scripts() {
    let formatter = NormalFormatter::new();

    let mut host = create_basic_host();
    host.ports.push(PortResult {
        number: 80,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        state_reason: "syn-ack".to_string(),
        state_ttl: Some(64),
        service: Some(ServiceInfo {
            name: "http".to_string(),
            product: None,
            version: None,
            extrainfo: None,
            hostname: None,
            ostype: None,
            devicetype: None,
            method: "probed".to_string(),
            confidence: 10,
            cpe: vec![],
        }),
        scripts: vec![
            ScriptResult {
                id: "http-title".to_string(),
                output: "Test Title".to_string(),
                elements: vec![ScriptElement {
                    key: "title".to_string(),
                    value: serde_json::json!("Test Title"),
                }],
            },
            ScriptResult {
                id: "http-server-header".to_string(),
                output: "nginx/1.18.0".to_string(),
                elements: vec![ScriptElement {
                    key: "server".to_string(),
                    value: serde_json::json!("nginx/1.18.0"),
                }],
            },
        ],
    });

    let output = formatter.format_host(&host).unwrap();

    assert!(output.contains("http-title"));
    assert!(output.contains("Test Title"));
    assert!(output.contains("http-server-header"));
    assert!(output.contains("nginx/1.18.0"));
}

/// Test scan result with errors.
#[test]
fn test_json_formatter_with_errors() {
    let formatter = JsonFormatter::new();
    let mut result = create_full_scan_result();

    result.errors.push(rustnmap_output::models::ScanError {
        message: "Permission denied".to_string(),
        target: Some("192.168.1.1".to_string()),
        timestamp: chrono::Utc::now(),
    });

    let output = formatter.format_scan_result(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert!(parsed["errors"].is_array());
    let errors = parsed["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["message"], "Permission denied");
    assert_eq!(errors[0]["target"], "192.168.1.1");
}

/// Test multiple hosts in scan result.
#[test]
fn test_formatters_multiple_hosts() {
    let mut result = ScanResult::default();

    // Add 5 hosts
    for i in 1..=5 {
        let mut host = create_basic_host();
        host.ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
        host.status = if i % 2 == 0 {
            HostStatus::Up
        } else {
            HostStatus::Down
        };
        result.hosts.push(host);
    }

    result.statistics.total_hosts = 5;
    result.statistics.hosts_up = 2;
    result.statistics.hosts_down = 3;

    let normal = NormalFormatter::new();
    let xml = XmlFormatter::new();
    let json = JsonFormatter::new();

    let normal_out = normal.format_scan_result(&result).unwrap();
    let xml_out = xml.format_scan_result(&result).unwrap();
    let json_out = json.format_scan_result(&result).unwrap();

    // Count host occurrences in output
    let host_count_normal = normal_out.matches("Nmap scan report for").count();
    let host_count_xml = xml_out.matches("<host").count();

    assert_eq!(
        host_count_normal, 5,
        "Normal formatter should show all 5 hosts"
    );
    assert_eq!(host_count_xml, 5, "XML formatter should show all 5 hosts");

    let parsed: serde_json::Value = serde_json::from_str(&json_out).unwrap();
    assert_eq!(parsed["hosts"].as_array().unwrap().len(), 5);
}
