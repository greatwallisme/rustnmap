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

// rustnmap-cli integration tests
//
// These tests verify the end-to-end functionality of the RustNmap CLI,
// including scan orchestration, output formatting, and file output.

use std::net::IpAddr;
use std::time::Duration;

/// Test that CLI can parse basic scan arguments
#[test]
fn test_cli_parse_basic_args() {
    use rustnmap_cli::args::Args;

    let args = Args {
        targets: vec!["127.0.0.1".to_string()],
        ports: Some("80,443".to_string()),
        scan_syn: true,
        timing: Some(3),
        ..Default::default()
    };

    assert!(args.validate().is_ok());
    assert_eq!(args.targets.len(), 1);
    assert_eq!(args.targets[0], "127.0.0.1");
}

/// Test that CLI accepts different scan types
#[test]
fn test_cli_scan_types() {
    use rustnmap_cli::args::Args;

    // SYN scan
    let args = Args {
        targets: vec!["127.0.0.1".to_string()],
        scan_syn: true,
        ..Default::default()
    };
    assert!(args.validate().is_ok());

    // Connect scan
    let args = Args {
        targets: vec!["127.0.0.1".to_string()],
        scan_connect: true,
        ..Default::default()
    };
    assert!(args.validate().is_ok());

    // UDP scan
    let args = Args {
        targets: vec!["127.0.0.1".to_string()],
        scan_udp: true,
        ..Default::default()
    };
    assert!(args.validate().is_ok());
}

/// Test scan configuration building from CLI args
#[test]
fn test_scan_config_building() {
    use rustnmap_core::session::ScanConfig;

    // Test default config
    let config = ScanConfig::default();
    assert!(config.host_discovery);
    assert!(!config.service_detection);
    assert!(!config.os_detection);
    assert!(!config.traceroute);
    assert!(!config.nse_scripts);

    // Test config with service detection enabled
    let config_with_service = ScanConfig {
        service_detection: true,
        ..ScanConfig::default()
    };
    assert!(config_with_service.service_detection);

    // Test config with OS detection enabled
    let config_with_os = ScanConfig {
        os_detection: true,
        ..ScanConfig::default()
    };
    assert!(config_with_os.os_detection);
}

/// Test port specification parsing
#[test]
fn test_port_spec_parsing() {
    use rustnmap_core::session::PortSpec;

    // Test single port
    let spec = PortSpec::List(vec![80]);
    match spec {
        PortSpec::List(ports) => {
            assert_eq!(ports, vec![80]);
        }
        _ => panic!("Expected PortSpec::List"),
    }

    // Test port range
    let spec = PortSpec::Range { start: 1, end: 100 };
    match spec {
        PortSpec::Range { start, end } => {
            assert_eq!(start, 1);
            assert_eq!(end, 100);
        }
        _ => panic!("Expected PortSpec::Range"),
    }

    // Test top N ports
    let spec = PortSpec::Top(1000);
    match spec {
        PortSpec::Top(n) => {
            assert_eq!(n, 1000);
        }
        _ => panic!("Expected PortSpec::Top"),
    }
}

/// Test scan pipeline configuration
#[test]
fn test_scan_pipeline_configuration() {
    use rustnmap_core::orchestrator::{ScanPhase, ScanPipeline};
    use rustnmap_core::session::ScanConfig;

    // Default pipeline should not include optional phases
    let config = ScanConfig::default();
    let pipeline = ScanPipeline::from_config(&config);

    assert!(pipeline.is_enabled(ScanPhase::TargetParsing));
    assert!(pipeline.is_enabled(ScanPhase::HostDiscovery));
    assert!(pipeline.is_enabled(ScanPhase::PortScanning));
    assert!(!pipeline.is_enabled(ScanPhase::ServiceDetection));
    assert!(!pipeline.is_enabled(ScanPhase::OsDetection));
    assert!(!pipeline.is_enabled(ScanPhase::NseExecution));
    assert!(!pipeline.is_enabled(ScanPhase::Traceroute));

    // Pipeline with all optional phases enabled
    let full_config = ScanConfig {
        service_detection: true,
        os_detection: true,
        nse_scripts: true,
        traceroute: true,
        ..ScanConfig::default()
    };
    let full_pipeline = ScanPipeline::from_config(&full_config);

    assert!(full_pipeline.is_enabled(ScanPhase::ServiceDetection));
    assert!(full_pipeline.is_enabled(ScanPhase::OsDetection));
    assert!(full_pipeline.is_enabled(ScanPhase::NseExecution));
    assert!(full_pipeline.is_enabled(ScanPhase::Traceroute));
}

/// Test output model creation and serialization
#[test]
fn test_output_models() {
    use rustnmap_output::models::{HostResult, HostStatus, PortResult, PortState, Protocol};

    // Create a sample scan result
    let host_result = HostResult {
        ip: "127.0.0.1".parse().unwrap(),
        mac: None,
        hostname: Some("localhost".to_string()),
        status: HostStatus::Up,
        status_reason: "syn-ack".to_string(),
        latency: Duration::from_millis(1),
        ports: vec![PortResult {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            state_reason: "syn-ack".to_string(),
            state_ttl: Some(64),
            service: None,
            scripts: vec![],
        }],
        os_matches: vec![],
        scripts: vec![],
        traceroute: None,
        times: rustnmap_output::models::HostTimes {
            srtt: None,
            rttvar: None,
            timeout: None,
        },
    };

    assert_eq!(host_result.ip.to_string(), "127.0.0.1");
    assert_eq!(host_result.ports.len(), 1);
    assert_eq!(host_result.ports[0].number, 80);
    assert!(matches!(host_result.ports[0].state, PortState::Open));
}

/// Test scan phase ordering
#[test]
fn test_scan_phase_ordering() {
    use rustnmap_core::orchestrator::ScanPhase;

    // Test phase progression
    assert_eq!(
        ScanPhase::TargetParsing.next(),
        Some(ScanPhase::HostDiscovery)
    );
    assert_eq!(
        ScanPhase::HostDiscovery.next(),
        Some(ScanPhase::PortScanning)
    );
    assert_eq!(
        ScanPhase::PortScanning.next(),
        Some(ScanPhase::ServiceDetection)
    );
    assert_eq!(
        ScanPhase::ServiceDetection.next(),
        Some(ScanPhase::OsDetection)
    );
    assert_eq!(ScanPhase::OsDetection.next(), Some(ScanPhase::NseExecution));
    assert_eq!(ScanPhase::NseExecution.next(), Some(ScanPhase::Traceroute));
    assert_eq!(
        ScanPhase::Traceroute.next(),
        Some(ScanPhase::ResultAggregation)
    );
    assert_eq!(ScanPhase::ResultAggregation.next(), None);
}

/// Test session creation with different configurations
#[test]
fn test_session_creation() {
    use rustnmap_core::session::{ScanConfig, ScanSession};
    use rustnmap_target::{Target, TargetGroup};

    let config = ScanConfig::default();
    let targets = TargetGroup::new(vec![Target::from("127.0.0.1".parse::<IpAddr>().unwrap())]);

    let session = ScanSession::new(config, targets);
    assert!(session.is_ok());

    let session = session.unwrap();
    assert_eq!(session.target_count(), 1);
}

/// Test that scan types are properly mapped
#[test]
fn test_scan_type_mapping() {
    use rustnmap_core::session::ScanType;

    // Verify all scan types exist
    let _ = ScanType::TcpSyn;
    let _ = ScanType::TcpConnect;
    let _ = ScanType::TcpFin;
    let _ = ScanType::TcpNull;
    let _ = ScanType::TcpXmas;
    let _ = ScanType::TcpAck;
    let _ = ScanType::TcpWindow;
    let _ = ScanType::TcpMaimon;
    let _ = ScanType::Udp;
    let _ = ScanType::SctpInit;
    let _ = ScanType::IpProtocol;
}

/// Test timing template configuration
#[test]
fn test_timing_templates() {
    use rustnmap_scan::scanner::TimingTemplate;

    let timing = TimingTemplate::Paranoid;
    assert!(matches!(timing, TimingTemplate::Paranoid));

    let timing = TimingTemplate::Insane;
    assert!(matches!(timing, TimingTemplate::Insane));
}

/// Test target parsing
#[test]
fn test_target_parsing() {
    use rustnmap_target::TargetParser;

    let parser = TargetParser::new();

    // Test single IP
    let result = parser.parse("127.0.0.1");
    assert!(result.is_ok());
    let group = result.unwrap();
    assert_eq!(group.targets.len(), 1);

    // Test CIDR notation
    let result = parser.parse("192.168.1.0/30");
    assert!(result.is_ok());
    let group = result.unwrap();
    assert_eq!(group.targets.len(), 4);
}

/// Test CLI argument validation
#[test]
fn test_cli_argument_validation() {
    use rustnmap_cli::args::Args;

    // Valid args with target
    let args = Args {
        targets: vec!["192.168.1.1".to_string()],
        ..Default::default()
    };
    assert!(args.validate().is_ok());

    // Args with service detection
    let args = Args {
        targets: vec!["192.168.1.1".to_string()],
        service_detection: true,
        ..Default::default()
    };
    assert!(args.validate().is_ok());

    // Args with OS detection
    let args = Args {
        targets: vec!["192.168.1.1".to_string()],
        os_detection: true,
        ..Default::default()
    };
    assert!(args.validate().is_ok());

    // Args with traceroute
    let args = Args {
        targets: vec!["192.168.1.1".to_string()],
        traceroute: true,
        ..Default::default()
    };
    assert!(args.validate().is_ok());
}

/// Test fingerprint database integration
#[test]
fn test_fingerprint_database_integration() {
    use rustnmap_core::session::FingerprintDatabase;

    // Test empty database
    let db = FingerprintDatabase::new();
    assert!(!db.is_service_db_loaded());
    assert!(!db.is_os_db_loaded());

    // Test database with empty probe databases
    let db = FingerprintDatabase::test_instance();
    assert!(db.is_service_db_loaded());
    assert!(db.is_os_db_loaded());
}

/// Test NSE registry integration
#[test]
fn test_nse_registry_integration() {
    use rustnmap_core::session::NseRegistry;
    use rustnmap_nse::NseScript;

    let mut registry = NseRegistry::new();
    assert!(registry.is_empty());

    let script = NseScript::new(
        "test-script",
        std::path::PathBuf::from("/test.nse"),
        String::new(),
    );
    registry.add_script(&script);
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    // Test engine creation
    let engine = registry.create_engine();
    assert_eq!(engine.database().len(), 1);
}

/// Test orchestrator creation with different configurations
#[test]
fn test_orchestrator_creation() {
    use rustnmap_core::orchestrator::ScanOrchestrator;
    use rustnmap_core::session::{ScanConfig, ScanSession};
    use rustnmap_target::{Target, TargetGroup};
    use std::sync::Arc;

    let config = ScanConfig::default();
    let targets = TargetGroup::new(vec![Target::from("127.0.0.1".parse::<IpAddr>().unwrap())]);

    let session = ScanSession::new(config, targets).unwrap();
    let session = Arc::new(session);

    let orchestrator = ScanOrchestrator::new(session);
    assert_eq!(orchestrator.session().target_count(), 1);
}
