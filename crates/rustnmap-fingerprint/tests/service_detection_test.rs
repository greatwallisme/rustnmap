// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Integration tests for service detection functionality.
//!
//! These tests verify the service detection engine can:
//! - Parse probe databases from strings
//! - Match responses against probe patterns
//! - Extract version information from templates
//! - Perform banner grabbing

use rustnmap_fingerprint::service::{ProbeDatabase, ServiceDetector};

/// Test probe database parsing and probe selection.
#[test]
fn test_probe_database_parsing() {
    let content = r"
# Test service probe database
Probe TCP GenericLines q|\r\n\r\n|
rarity 1
Ports 1-65535
Match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)\r?\n| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
Match ssh m|^SSH-([\d.]+)-([\w._-]+)\r?\n| p/$2/ v/$2/ i/protocol $1/

Probe TCP HTTP q|GET / HTTP/1.0\r\n\r\n|
rarity 3
Ports 80,8080,8443
Match http m|^HTTP/1\.[01] (\d{3})| p/HTTP/ i/status $1/
Match apache m|^Server: Apache/([\d.]+)| p/Apache httpd/ v/$1/ cpe:/a:apache:httpd:$1/

Probe UDP DNS q|\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03|
rarity 2
Ports 53
Match dns m|^\x00\x00\x81\x80| p/BIND DNS/
";

    let db = ProbeDatabase::parse(content).expect("Failed to parse probe database");

    assert_eq!(db.probe_count(), 3, "Expected 3 probes");
    assert!(db.get_probe("GenericLines").is_some());
    assert!(db.get_probe("HTTP").is_some());
    assert!(db.get_probe("DNS").is_some());

    // Check probe selection by port
    let port_80_probes = db.probes_for_port(80);
    assert!(!port_80_probes.is_empty(), "Expected probes for port 80");

    // GenericLines applies to all ports
    let port_22_probes = db.probes_for_port(22);
    assert!(!port_22_probes.is_empty(), "Expected probes for port 22");
}

/// Test match rule parsing with all version info fields.
#[test]
fn test_match_rule_parsing() {
    let content = r"
Probe TCP Test q|test|
Match test m|^Test (\d+) (\w+)| p/Product/ v/$1/ i/$2/ h/$1.test.com/ o/Linux/ d/router/ cpe:/a:vendor:product:$1/
";

    let db = ProbeDatabase::parse(content).expect("Failed to parse database");
    let probe = db.get_probe("Test").expect("Test probe not found");

    assert_eq!(probe.matches.len(), 1);

    let match_rule = &probe.matches[0];
    assert_eq!(match_rule.service, "test");
    assert!(match_rule.product_template.is_some());
    assert_eq!(
        match_rule.product_template.as_ref().unwrap().value,
        "Product"
    );
    assert!(match_rule.version_template.is_some());
    assert_eq!(match_rule.version_template.as_ref().unwrap().value, "$1");
    assert!(match_rule.info_template.is_some());
    assert_eq!(match_rule.info_template.as_ref().unwrap().value, "$2");
    assert!(match_rule.hostname_template.is_some());
    assert_eq!(
        match_rule.hostname_template.as_ref().unwrap().value,
        "$1.test.com"
    );
    assert!(match_rule.os_type_template.is_some());
    assert_eq!(match_rule.os_type_template.as_ref().unwrap().value, "Linux");
    assert!(match_rule.device_type_template.is_some());
    assert_eq!(
        match_rule.device_type_template.as_ref().unwrap().value,
        "router"
    );
    assert!(match_rule.cpe_template.is_some());
    assert_eq!(
        match_rule.cpe_template.as_ref().unwrap().value,
        "a:vendor:product:$1"
    );
}

/// Test softmatch directive parsing.
#[test]
fn test_softmatch_parsing() {
    let content = r"
Probe TCP Test q|test|
softmatch fingerprint m|^Fingerprint|
";

    let db = ProbeDatabase::parse(content).expect("Failed to parse database");
    let probe = db.get_probe("Test").expect("Test probe not found");

    assert_eq!(probe.matches.len(), 1);
    assert!(probe.matches[0].soft);
    assert_eq!(probe.matches[0].service, "fingerprint");
}

/// Test service detection with mock responses.
#[test]
fn test_service_detection_with_mock_response() {
    use rustnmap_fingerprint::service::probe::{MatchRule, MatchTemplate, ProbeDefinition};
    use std::collections::HashMap;

    // Create a match rule for SSH
    let rule = MatchRule {
        pattern: r"^SSH-([\d.]+)-OpenSSH_([\w._-]+)".to_string(),
        service: "ssh".to_string(),
        product_template: Some(MatchTemplate {
            value: "OpenSSH".to_string(),
        }),
        version_template: Some(MatchTemplate {
            value: "$2".to_string(),
        }),
        info_template: Some(MatchTemplate {
            value: "protocol $1".to_string(),
        }),
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: Some(MatchTemplate {
            value: "a:openbsd:openssh:$2".to_string(),
        }),
        soft: false,
    };

    // Create a probe with this rule
    let mut probe = ProbeDefinition::new_tcp("SSHProbe".to_string(), Vec::new());
    probe.add_match(rule);

    // Test response matching with pcre2 (bytes API)
    let response = b"SSH-2.0-OpenSSH_8.4p1\r\n";

    let regex = probe.matches[0]
        .compile_regex()
        .expect("Failed to compile regex");
    let captures_result = regex.captures(response);

    assert!(
        captures_result.is_ok(),
        "Expected regex to compile and match"
    );

    let captures_opt = captures_result.unwrap();
    assert!(captures_opt.is_some(), "Expected regex to match");

    let captures = captures_opt.unwrap();
    let mut capture_map = HashMap::new();

    // Get capture groups by index (group 0 is full match, we start from 1)
    let mut i = 1;
    while let Some(cap) = captures.get(i) {
        capture_map.insert(i, cap.as_bytes().to_vec());
        i += 1;
    }

    let result = probe.matches[0].apply(&capture_map);

    assert_eq!(result.service, "ssh");
    assert_eq!(result.product, Some("OpenSSH".to_string()));
    assert_eq!(result.version, Some("8.4p1".to_string()));
    assert_eq!(result.info, Some("protocol 2.0".to_string()));
    assert_eq!(result.cpe, Some("a:openbsd:openssh:8.4p1".to_string()));
    assert_eq!(result.confidence, 8); // Non-soft match
}

/// Test version template extraction with multiple capture groups.
#[test]
fn test_version_template_extraction() {
    use rustnmap_fingerprint::service::probe::{MatchRule, MatchTemplate};
    use std::collections::HashMap;

    let rule = MatchRule {
        pattern: r"^Server: (\w+)/(\d+\.\d+) \((\w+)\)".to_string(),
        service: "http".to_string(),
        product_template: Some(MatchTemplate {
            value: "$1".to_string(),
        }),
        version_template: Some(MatchTemplate {
            value: "$2".to_string(),
        }),
        info_template: Some(MatchTemplate {
            value: "OS: $3".to_string(),
        }),
        hostname_template: None,
        os_type_template: Some(MatchTemplate {
            value: "$3".to_string(),
        }),
        device_type_template: None,
        cpe_template: Some(MatchTemplate {
            value: "a:$1:$1:$2".to_string(),
        }),
        soft: false,
    };

    let mut captures = HashMap::new();
    captures.insert(1, b"Apache".to_vec());
    captures.insert(2, b"2.4.41".to_vec());
    captures.insert(3, b"Ubuntu".to_vec());

    let result = rule.apply(&captures);

    assert_eq!(result.product, Some("Apache".to_string()));
    assert_eq!(result.version, Some("2.4.41".to_string()));
    assert_eq!(result.info, Some("OS: Ubuntu".to_string()));
    assert_eq!(result.os_type, Some("Ubuntu".to_string()));
    assert_eq!(result.cpe, Some("a:Apache:Apache:2.4.41".to_string()));
}

/// Test service detector configuration.
#[test]
fn test_service_detector_configuration() {
    let db = ProbeDatabase::empty();

    // Just verify the detector can be constructed with configuration
    let _detector = ServiceDetector::new(db)
        .with_timeout(std::time::Duration::from_secs(10))
        .with_intensity(5);

    // Configuration is applied internally
}

/// Test regex pattern with flags (case-insensitive).
#[test]
fn test_regex_pattern_with_flags() {
    use rustnmap_fingerprint::service::probe::MatchRule;

    // Pattern with case-insensitive flag
    let rule = MatchRule {
        pattern: r"(?i)^ssh-".to_string(),
        service: "ssh".to_string(),
        product_template: None,
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    let regex = rule.compile_regex().expect("Failed to compile regex");

    assert!(regex.is_match(b"SSH-2.0-OpenSSH").unwrap());
    assert!(regex.is_match(b"ssh-2.0-OpenSSH").unwrap());
    assert!(regex.is_match(b"Ssh-2.0-OpenSSH").unwrap());
}

/// Test empty capture group handling.
#[test]
fn test_empty_capture_group() {
    use rustnmap_fingerprint::service::probe::{MatchRule, MatchTemplate};
    use std::collections::HashMap;

    let rule = MatchRule {
        pattern: r"^Test (\w+)?".to_string(),
        service: "test".to_string(),
        product_template: Some(MatchTemplate {
            value: "Product: $1".to_string(),
        }),
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    // Test with empty capture (optional group didn't match)
    let empty_captures = HashMap::new();
    let result = rule.apply(&empty_captures);

    // Empty capture should result in empty string substitution
    assert_eq!(result.product, Some("Product: ".to_string()));
}

/// Test database loading from file path (mock).
#[tokio::test]
async fn test_database_load_from_file() {
    // Create a temporary file with probe definitions
    let temp_dir = std::env::temp_dir();
    let probe_file = temp_dir.join("test-service-probes.txt");

    let content = r"
Probe TCP Test q|test|
Match test m|^Test|
";

    tokio::fs::write(&probe_file, content)
        .await
        .expect("Failed to write test file");

    // Load the database
    let db = ProbeDatabase::load_from_nmap_db(&probe_file)
        .await
        .expect("Failed to load database");

    assert_eq!(db.probe_count(), 1);
    assert!(db.get_probe("Test").is_some());

    // Clean up
    let _ = tokio::fs::remove_file(&probe_file).await;
}

/// Test error handling for invalid database.
#[tokio::test]
async fn test_database_load_error() {
    let result = ProbeDatabase::load_from_nmap_db("/nonexistent/path/probes.txt").await;
    assert!(result.is_err());
}

/// Test port range parsing in probe definitions.
#[test]
fn test_port_range_parsing() {
    let content = r"
Probe TCP Single q|single|
Ports 22
Match single m|^Single|

Probe TCP Range q|range|
Ports 80-82
Match range m|^Range|

Probe TCP Mixed q|mixed|
Ports 443,8080-8082,9000
Match mixed m|^Mixed|
";

    let db = ProbeDatabase::parse(content).expect("Failed to parse database");

    let single_probes = db.probes_for_port(22);
    assert_eq!(single_probes.len(), 1);

    let range_probes = db.probes_for_port(81);
    assert_eq!(range_probes.len(), 1);

    let mixed_probes_443 = db.probes_for_port(443);
    assert_eq!(mixed_probes_443.len(), 1);

    let mixed_probes_8081 = db.probes_for_port(8081);
    assert_eq!(mixed_probes_8081.len(), 1);
}

/// Test service info creation and manipulation.
#[test]
fn test_service_info_creation() {
    use rustnmap_fingerprint::service::detector::ServiceInfo;

    let info = ServiceInfo::new("ssh").with_confidence(8);

    assert_eq!(info.name, "ssh");
    assert_eq!(info.confidence, 8);
    assert!(info.product.is_none());
    assert!(info.version.is_none());

    // Test confidence clamping
    let info_high = ServiceInfo::new("http").with_confidence(15);
    assert_eq!(info_high.confidence, 10); // Max is 10

    let info_low = ServiceInfo::new("ftp").with_confidence(0);
    assert_eq!(info_low.confidence, 0); // Min is 0
}

/// Test loading real nmap-service-probes database and checking Apache patterns.
#[test]
fn test_real_database_apache_patterns() {
    use std::fs;
    use std::path::Path;

    // Try to load the user's nmap-service-probes database
    let db_path = Path::new("/home/greatwallimse/.rustnmap/db/nmap-service-probes");
    if !db_path.exists() {
        println!("Skipping test - database file not found at {:?}", db_path);
        return;
    }

    let content = fs::read_to_string(db_path).expect("Failed to read database file");
    let db = ProbeDatabase::parse(&content).expect("Failed to parse database");
    println!("Total probes loaded: {}", db.probe_count());

    // Get GetRequest probe
    let get_request = db.get_probe("GetRequest");
    assert!(get_request.is_some(), "GetRequest probe should exist");

    let get_request = get_request.unwrap();
    println!(
        "GetRequest probe has {} match rules",
        get_request.matches.len()
    );

    // Find Apache patterns that match the scanme.nmap.org response
    let scanme_response = b"HTTP/1.1 200 OK\r\nDate: Sun, 22 Feb 2026 02:31:04 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\n";

    let mut apache_match_count = 0;
    let mut total_apache_rules = 0;

    // Print all "Server: Apache[/ ]" patterns to see what they look like
    for (i, rule) in get_request.matches.iter().enumerate() {
        if rule.pattern.contains("Apache[/ ]") {
            total_apache_rules += 1;
            let pattern_end = &rule.pattern[rule.pattern.len().saturating_sub(100)..];
            println!("Rule {} with Apache[/ ]: ...{}", i + 1, pattern_end);

            // Check if pattern ends with a capture group for non-CRLF characters
            // The pattern should end with something like ([^\r\n]+) or ([^\r\n]*)
            if rule.pattern.ends_with("+)") || rule.pattern.contains("([^\r\n]+)") {
                apache_match_count += 1;
                println!("  -> Contains capture group for non-CRLF chars!");

                // Try to match
                if let Ok(regex) = rule.compile_regex() {
                    if let Ok(Some(_)) = regex.captures(scanme_response) {
                        println!("  -> MATCHED the scanme.nmap.org response!");
                        if let Some(ref product) = rule.product_template {
                            println!("  -> Product: {}", product.value);
                        }
                    }
                }
            }
        }
    }

    println!("Total Apache rules: {}", total_apache_rules);
    println!(
        "Total Apache patterns with capture groups: {}",
        apache_match_count
    );

    println!("Total Apache rules: {}", total_apache_rules);
    println!(
        "Total Apache patterns with capture groups: {}",
        apache_match_count
    );

    assert!(
        apache_match_count > 0,
        "Should have at least one Apache pattern with capture groups"
    );
}
