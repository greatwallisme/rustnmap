// Rust guideline compliant 2026-02-15

//! Unit tests for scan orchestrator module.
//!
//! These tests focus on the orchestrator state management, pipeline
//! configuration, and scan phase logic without requiring network operations.

use std::net::IpAddr;
use std::sync::Arc;

use rustnmap_common::Ipv4Addr;
use rustnmap_core::orchestrator::{ScanOrchestrator, ScanPhase, ScanPipeline, ScanState};
use rustnmap_core::session::{ScanConfig, ScanSession};
use rustnmap_core::state::{HostState, PortScanState, ScanProgress};
use rustnmap_target::{Target, TargetGroup};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_test_session() -> Arc<ScanSession> {
    let config = ScanConfig::default();
    let targets = TargetGroup::new(vec![
        Target::from(Ipv4Addr::new(192, 168, 1, 1)),
        Target::from(Ipv4Addr::new(192, 168, 1, 2)),
    ]);

    let target_set = Arc::new(rustnmap_core::session::TargetSet::from_group(targets));
    let packet_engine: Arc<dyn rustnmap_core::session::PacketEngine> =
        Arc::new(rustnmap_core::session::DefaultPacketEngine::new().unwrap());
    let output_sink: Arc<dyn rustnmap_core::session::OutputSink> =
        Arc::new(rustnmap_core::session::DefaultOutputSink::new());
    let fingerprint_db = Arc::new(rustnmap_core::session::FingerprintDatabase::new());
    let nse_registry = Arc::new(rustnmap_core::session::NseRegistry::new());

    Arc::new(ScanSession::with_dependencies(
        config,
        target_set,
        packet_engine,
        output_sink,
        fingerprint_db,
        nse_registry,
    ))
}

// =============================================================================
// ScanPhase Tests
// =============================================================================

#[test]
fn test_scan_phase_next_complete_sequence() {
    // Test the complete phase sequence
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

#[test]
fn test_scan_phase_is_default() {
    // Default phases
    assert!(ScanPhase::TargetParsing.is_default());
    assert!(ScanPhase::HostDiscovery.is_default());
    assert!(ScanPhase::PortScanning.is_default());
    assert!(ScanPhase::ResultAggregation.is_default());

    // Non-default phases
    assert!(!ScanPhase::ServiceDetection.is_default());
    assert!(!ScanPhase::OsDetection.is_default());
    assert!(!ScanPhase::NseExecution.is_default());
    assert!(!ScanPhase::Traceroute.is_default());
}

#[test]
fn test_scan_phase_name() {
    assert_eq!(ScanPhase::TargetParsing.name(), "Target Parsing");
    assert_eq!(ScanPhase::HostDiscovery.name(), "Host Discovery");
    assert_eq!(ScanPhase::PortScanning.name(), "Port Scanning");
    assert_eq!(ScanPhase::ServiceDetection.name(), "Service Detection");
    assert_eq!(ScanPhase::OsDetection.name(), "OS Detection");
    assert_eq!(ScanPhase::NseExecution.name(), "NSE Script Execution");
    assert_eq!(ScanPhase::Traceroute.name(), "Traceroute");
    assert_eq!(ScanPhase::ResultAggregation.name(), "Result Aggregation");
}

#[test]
fn test_scan_phase_display() {
    let phase = ScanPhase::PortScanning;
    assert_eq!(format!("{phase}"), "Port Scanning");

    let phase = ScanPhase::ServiceDetection;
    assert_eq!(format!("{phase}"), "Service Detection");
}

#[test]
fn test_scan_phase_debug() {
    let phase = ScanPhase::HostDiscovery;
    let debug_str = format!("{phase:?}");
    assert!(debug_str.contains("HostDiscovery"));
}

#[test]
fn test_scan_phase_clone() {
    let phase = ScanPhase::PortScanning;
    let cloned = phase;
    assert_eq!(phase, cloned);
}

#[test]
fn test_scan_phase_copy() {
    let phase = ScanPhase::PortScanning;
    let copied = phase;
    assert_eq!(phase, copied);
}

#[test]
fn test_scan_phase_equality() {
    assert_eq!(ScanPhase::PortScanning, ScanPhase::PortScanning);
    assert_ne!(ScanPhase::PortScanning, ScanPhase::HostDiscovery);
}

#[test]
fn test_scan_phase_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(ScanPhase::PortScanning);
    set.insert(ScanPhase::HostDiscovery);
    set.insert(ScanPhase::PortScanning); // Duplicate

    assert_eq!(set.len(), 2);
}

// =============================================================================
// ScanPipeline Tests
// =============================================================================

#[test]
fn test_scan_pipeline_default() {
    let pipeline = ScanPipeline::default();

    // Check default phases are enabled
    assert!(pipeline.is_enabled(ScanPhase::TargetParsing));
    assert!(pipeline.is_enabled(ScanPhase::HostDiscovery));
    assert!(pipeline.is_enabled(ScanPhase::PortScanning));
    assert!(pipeline.is_enabled(ScanPhase::ResultAggregation));

    // Check optional phases are not enabled
    assert!(!pipeline.is_enabled(ScanPhase::ServiceDetection));
    assert!(!pipeline.is_enabled(ScanPhase::OsDetection));
    assert!(!pipeline.is_enabled(ScanPhase::NseExecution));
    assert!(!pipeline.is_enabled(ScanPhase::Traceroute));
}

#[test]
fn test_scan_pipeline_phases_order() {
    let pipeline = ScanPipeline::default();
    let phases = pipeline.phases();

    assert_eq!(phases[0], ScanPhase::TargetParsing);
    assert_eq!(phases[1], ScanPhase::HostDiscovery);
    assert_eq!(phases[2], ScanPhase::PortScanning);
    assert_eq!(phases[3], ScanPhase::ResultAggregation);
}

#[test]
fn test_scan_pipeline_from_config_default() {
    let config = ScanConfig::default();
    let pipeline = ScanPipeline::from_config(&config);

    // Default config should only have default phases
    assert!(pipeline.is_enabled(ScanPhase::TargetParsing));
    assert!(pipeline.is_enabled(ScanPhase::HostDiscovery));
    assert!(pipeline.is_enabled(ScanPhase::PortScanning));
    assert!(!pipeline.is_enabled(ScanPhase::ServiceDetection));
    assert!(!pipeline.is_enabled(ScanPhase::OsDetection));
}

#[test]
fn test_scan_pipeline_from_config_with_service_detection() {
    let config = ScanConfig {
        service_detection: true,
        ..ScanConfig::default()
    };
    let pipeline = ScanPipeline::from_config(&config);

    assert!(pipeline.is_enabled(ScanPhase::ServiceDetection));
}

#[test]
fn test_scan_pipeline_from_config_with_os_detection() {
    let config = ScanConfig {
        os_detection: true,
        ..ScanConfig::default()
    };
    let pipeline = ScanPipeline::from_config(&config);

    assert!(pipeline.is_enabled(ScanPhase::OsDetection));
}

#[test]
fn test_scan_pipeline_from_config_with_nse_scripts() {
    let config = ScanConfig {
        nse_scripts: true,
        ..ScanConfig::default()
    };
    let pipeline = ScanPipeline::from_config(&config);

    assert!(pipeline.is_enabled(ScanPhase::NseExecution));
}

#[test]
fn test_scan_pipeline_from_config_with_traceroute() {
    let config = ScanConfig {
        traceroute: true,
        ..ScanConfig::default()
    };
    let pipeline = ScanPipeline::from_config(&config);

    assert!(pipeline.is_enabled(ScanPhase::Traceroute));
}

#[test]
fn test_scan_pipeline_from_config_all_options() {
    let config = ScanConfig {
        service_detection: true,
        os_detection: true,
        nse_scripts: true,
        traceroute: true,
        ..ScanConfig::default()
    };
    let pipeline = ScanPipeline::from_config(&config);

    assert!(pipeline.is_enabled(ScanPhase::ServiceDetection));
    assert!(pipeline.is_enabled(ScanPhase::OsDetection));
    assert!(pipeline.is_enabled(ScanPhase::NseExecution));
    assert!(pipeline.is_enabled(ScanPhase::Traceroute));
}

#[test]
fn test_scan_pipeline_add_phase() {
    let mut pipeline = ScanPipeline::default();

    assert!(!pipeline.is_enabled(ScanPhase::ServiceDetection));
    pipeline.add_phase(ScanPhase::ServiceDetection);
    assert!(pipeline.is_enabled(ScanPhase::ServiceDetection));
}

#[test]
fn test_scan_pipeline_add_duplicate_phase() {
    let mut pipeline = ScanPipeline::default();

    pipeline.add_phase(ScanPhase::ServiceDetection);
    pipeline.add_phase(ScanPhase::ServiceDetection);

    // Should only appear once in phases list
    let count = pipeline
        .phases()
        .iter()
        .filter(|&&p| p == ScanPhase::ServiceDetection)
        .count();
    assert_eq!(count, 1);
}

#[test]
fn test_scan_pipeline_dependencies() {
    let pipeline = ScanPipeline::default();

    // Check dependencies exist for some phases
    let host_discovery_deps = pipeline.dependencies(ScanPhase::HostDiscovery);
    assert!(host_discovery_deps.is_some());
    assert!(host_discovery_deps
        .unwrap()
        .contains(&ScanPhase::TargetParsing));

    let port_scanning_deps = pipeline.dependencies(ScanPhase::PortScanning);
    assert!(port_scanning_deps.is_some());
    assert!(port_scanning_deps
        .unwrap()
        .contains(&ScanPhase::HostDiscovery));

    let service_detection_deps = pipeline.dependencies(ScanPhase::ServiceDetection);
    assert!(service_detection_deps.is_some());
    assert!(service_detection_deps
        .unwrap()
        .contains(&ScanPhase::PortScanning));
}

#[test]
fn test_scan_pipeline_dependencies_none_for_default() {
    let pipeline = ScanPipeline::default();

    // Target parsing has no dependencies
    let target_parsing_deps = pipeline.dependencies(ScanPhase::TargetParsing);
    assert!(target_parsing_deps.is_none() || target_parsing_deps.unwrap().is_empty());
}

#[test]
fn test_scan_pipeline_add_phase_with_dependency() {
    let mut pipeline = ScanPipeline::default();

    // Add service detection (depends on port scanning)
    pipeline.add_phase(ScanPhase::ServiceDetection);

    // Service detection should be added after port scanning
    let phases = pipeline.phases();
    let port_scan_idx = phases.iter().position(|&p| p == ScanPhase::PortScanning);
    let service_idx = phases
        .iter()
        .position(|&p| p == ScanPhase::ServiceDetection);

    assert!(port_scan_idx.is_some());
    assert!(service_idx.is_some());
    assert!(service_idx.unwrap() > port_scan_idx.unwrap());
}

#[test]
fn test_scan_pipeline_debug() {
    let pipeline = ScanPipeline::default();
    let debug_str = format!("{pipeline:?}");
    assert!(debug_str.contains("ScanPipeline"));
}

#[test]
fn test_scan_pipeline_clone() {
    let pipeline = ScanPipeline::default();
    let cloned = pipeline.clone();

    assert_eq!(pipeline.phases().len(), cloned.phases().len());
    for phase in pipeline.phases() {
        assert!(cloned.is_enabled(*phase));
    }
}

// =============================================================================
// ScanState Tests
// =============================================================================

#[test]
fn test_scan_state_new() {
    let state = ScanState::new();
    assert_eq!(state.host_count(), 0);
    assert_eq!(state.port_count(), 0);
}

#[test]
fn test_scan_state_default() {
    let state = ScanState::default();
    assert_eq!(state.host_count(), 0);
    assert_eq!(state.port_count(), 0);
}

#[test]
fn test_scan_state_host_state_creation() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    let host_state = state.host_state(ip);
    assert_eq!(
        host_state.status,
        rustnmap_output::models::HostStatus::Unknown
    );
    assert_eq!(state.host_count(), 1);
}

#[test]
fn test_scan_state_host_state_multiple() {
    let mut state = ScanState::new();

    let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2));

    state.host_state(ip1);
    state.host_state(ip2);

    assert_eq!(state.host_count(), 2);
}

#[test]
fn test_scan_state_host_state_same_ip() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    state.host_state(ip);
    state.host_state(ip);

    // Should still be 1 since it's the same IP
    assert_eq!(state.host_count(), 1);
}

#[test]
fn test_scan_state_port_state_creation() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    let port_state = state.port_state(ip, 80);
    assert_eq!(*port_state, PortScanState::default());
    assert_eq!(state.port_count(), 1);
}

#[test]
fn test_scan_state_port_state_multiple_ports() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    state.port_state(ip, 80);
    state.port_state(ip, 443);
    state.port_state(ip, 22);

    assert_eq!(state.port_count(), 3);
}

#[test]
fn test_scan_state_port_state_multiple_hosts() {
    let mut state = ScanState::new();
    let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2));

    state.port_state(ip1, 80);
    state.port_state(ip2, 80);

    assert_eq!(state.port_count(), 2);
}

#[test]
fn test_scan_state_port_state_same_port() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    state.port_state(ip, 80);
    state.port_state(ip, 80);

    // Should still be 1 since it's the same host:port
    assert_eq!(state.port_count(), 1);
}

#[test]
fn test_scan_state_progress() {
    let mut state = ScanState::new();

    let progress = ScanProgress::new(100);
    state.set_progress(progress);

    let retrieved = state.progress();
    assert_eq!(retrieved.total_targets, 100);
    assert_eq!(retrieved.pending_targets, 100);
    assert_eq!(retrieved.current_phase, "initializing");
}

#[test]
fn test_scan_state_progress_default() {
    let state = ScanState::new();

    let progress = state.progress();
    assert_eq!(progress.total_targets, 0);
    assert_eq!(progress.completed_targets, 0);
    assert_eq!(progress.active_targets, 0);
    assert_eq!(progress.pending_targets, 0);
    assert_eq!(progress.current_phase, "initializing");
}

#[test]
fn test_scan_state_debug() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    state.host_state(ip);

    let debug_str = format!("{state:?}");
    assert!(debug_str.contains("ScanState"));
    assert!(debug_str.contains("hosts"));
    assert!(debug_str.contains("progress"));
}

// =============================================================================
// ScanOrchestrator Tests
// =============================================================================

#[test]
fn test_orchestrator_creation() {
    let session = create_test_session();
    let orchestrator = ScanOrchestrator::new(session);

    assert_eq!(orchestrator.session().target_count(), 2);
}

#[test]
fn test_orchestrator_with_pipeline() {
    let session = create_test_session();
    let custom_pipeline = ScanPipeline::default();
    let orchestrator = ScanOrchestrator::with_pipeline(session, custom_pipeline);

    assert_eq!(orchestrator.session().target_count(), 2);
}

#[test]
fn test_orchestrator_session() {
    let session = create_test_session();
    let orchestrator = ScanOrchestrator::new(session);

    assert_eq!(orchestrator.session().target_count(), 2);
}

#[test]
fn test_orchestrator_pipeline() {
    let session = create_test_session();
    let orchestrator = ScanOrchestrator::new(session);

    let pipeline = orchestrator.pipeline();
    assert!(pipeline.is_enabled(ScanPhase::TargetParsing));
}

#[test]
fn test_orchestrator_debug() {
    let session = create_test_session();
    let orchestrator = ScanOrchestrator::new(session);

    let debug_str = format!("{orchestrator:?}");
    assert!(debug_str.contains("ScanOrchestrator"));
    assert!(debug_str.contains("pipeline"));
}

// =============================================================================
// HostState Tests (from state module)
// =============================================================================

#[test]
fn test_host_state_default() {
    let state = HostState::default();
    assert_eq!(state.status, rustnmap_output::models::HostStatus::Unknown);
    assert!(state.discovery_method.is_none());
}

#[test]
fn test_host_state_new() {
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    let state = HostState::new(ip);
    assert_eq!(state.status, rustnmap_output::models::HostStatus::Unknown);
}

#[test]
fn test_host_state_debug() {
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    let state = HostState::new(ip);
    let debug_str = format!("{state:?}");
    assert!(debug_str.contains("HostState"));
}

// =============================================================================
// PortScanState Tests
// =============================================================================

#[test]
fn test_port_scan_state_default() {
    let state = PortScanState::default();
    assert_eq!(state.probe_count, 0);
    assert!(!state.service_detected);
}

#[test]
fn test_port_scan_state_debug() {
    let state = PortScanState::default();
    let debug_str = format!("{state:?}");
    assert!(debug_str.contains("PortScanState"));
}

// =============================================================================
// ScanProgress Tests
// =============================================================================

#[test]
fn test_scan_progress_default() {
    let progress = ScanProgress::default();
    assert_eq!(progress.total_targets, 0);
    assert_eq!(progress.completed_targets, 0);
    assert_eq!(progress.active_targets, 0);
    assert_eq!(progress.pending_targets, 0);
    assert_eq!(progress.current_phase, "initializing");
    assert!(progress.start_time.is_none());
    assert!(progress.eta.is_none());
}

#[test]
fn test_scan_progress_new() {
    let progress = ScanProgress::new(100);
    assert_eq!(progress.total_targets, 100);
    assert_eq!(progress.pending_targets, 100);
    assert_eq!(progress.active_targets, 0);
    assert_eq!(progress.completed_targets, 0);
    assert!(progress.start_time.is_some());
}

#[test]
fn test_scan_progress_target_started() {
    let mut progress = ScanProgress::new(10);
    progress.target_started();
    assert_eq!(progress.active_targets, 1);
    assert_eq!(progress.pending_targets, 9);
}

#[test]
fn test_scan_progress_target_completed() {
    let mut progress = ScanProgress::new(10);
    progress.target_started();
    progress.target_completed();
    assert_eq!(progress.active_targets, 0);
    assert_eq!(progress.completed_targets, 1);
}

#[test]
fn test_scan_progress_completion_percentage() {
    let mut progress = ScanProgress::new(100);
    assert_eq!(progress.completion_percentage(), 0);

    progress.completed_targets = 25;
    assert_eq!(progress.completion_percentage(), 25);

    progress.completed_targets = 50;
    assert_eq!(progress.completion_percentage(), 50);

    progress.completed_targets = 100;
    assert_eq!(progress.completion_percentage(), 100);
    assert!(progress.is_complete());
}

#[test]
fn test_scan_progress_is_complete() {
    let mut progress = ScanProgress::new(5);
    assert!(!progress.is_complete());

    progress.completed_targets = 5;
    assert!(progress.is_complete());
}

#[test]
fn test_scan_progress_set_phase() {
    let mut progress = ScanProgress::new(10);
    progress.set_phase("port_scanning");
    assert_eq!(progress.current_phase, "port_scanning");
}

#[test]
fn test_scan_progress_clone() {
    let mut progress = ScanProgress::new(50);
    progress.completed_targets = 10;
    progress.set_phase("test_phase");

    let cloned = progress.clone();
    assert_eq!(cloned.total_targets, 50);
    assert_eq!(cloned.completed_targets, 10);
    assert_eq!(cloned.current_phase, "test_phase");
}

#[test]
fn test_scan_progress_debug() {
    let progress = ScanProgress::default();
    let debug_str = format!("{progress:?}");
    assert!(debug_str.contains("ScanProgress"));
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_scan_pipeline_empty_phases() {
    let pipeline = ScanPipeline::default();
    let phases = pipeline.phases();

    // Should have at least the default phases
    assert!(!phases.is_empty());
}

#[test]
fn test_scan_phase_is_default_all_variants() {
    let all_phases = [
        ScanPhase::TargetParsing,
        ScanPhase::HostDiscovery,
        ScanPhase::PortScanning,
        ScanPhase::ServiceDetection,
        ScanPhase::OsDetection,
        ScanPhase::NseExecution,
        ScanPhase::Traceroute,
        ScanPhase::ResultAggregation,
    ];

    // Ensure all phases have a defined is_default value
    for phase in all_phases {
        let _ = phase.is_default();
    }
}

#[test]
fn test_scan_phase_name_all_variants() {
    let all_phases = [
        ScanPhase::TargetParsing,
        ScanPhase::HostDiscovery,
        ScanPhase::PortScanning,
        ScanPhase::ServiceDetection,
        ScanPhase::OsDetection,
        ScanPhase::NseExecution,
        ScanPhase::Traceroute,
        ScanPhase::ResultAggregation,
    ];

    // Ensure all phases have a defined name
    for phase in all_phases {
        let name = phase.name();
        assert!(!name.is_empty());
    }
}

#[test]
fn test_scan_state_host_count_with_ipv6() {
    let mut state = ScanState::new();

    let ip4 = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    let ip6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    state.host_state(ip4);
    state.host_state(ip6);

    assert_eq!(state.host_count(), 2);
}

#[test]
fn test_scan_state_port_count_same_ip_different_ports() {
    let mut state = ScanState::new();
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    state.port_state(ip, 80);
    state.port_state(ip, 443);
    state.port_state(ip, 22);

    assert_eq!(state.port_count(), 3);
}

#[test]
fn test_scan_pipeline_dependencies_all_phases() {
    let pipeline = ScanPipeline::default();

    // Check that all phases that should have dependencies do
    let phases_with_deps = [
        ScanPhase::HostDiscovery,
        ScanPhase::PortScanning,
        ScanPhase::ServiceDetection,
        ScanPhase::OsDetection,
        ScanPhase::NseExecution,
        ScanPhase::Traceroute,
        ScanPhase::ResultAggregation,
    ];

    for phase in phases_with_deps {
        let deps = pipeline.dependencies(phase);
        assert!(deps.is_some(), "Phase {phase:?} should have dependencies");
    }
}

#[test]
fn test_scan_progress_with_zero_targets() {
    let progress = ScanProgress::new(0);
    assert_eq!(progress.total_targets, 0);
    assert_eq!(progress.completion_percentage(), 0);
    assert!(progress.is_complete());
}

#[test]
fn test_scan_progress_saturating_sub() {
    let mut progress = ScanProgress::new(1);
    progress.target_started();
    progress.target_started(); // Try to start more than available

    // Should saturate at 0
    assert_eq!(progress.pending_targets, 0);
}
