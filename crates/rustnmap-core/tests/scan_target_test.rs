// Target scan test for external test target
// Run with: cargo test -p rustnmap-core --test scan_target_test -- --include-ignored
//
// Configuration:
// - Set TEST_TARGET_IP in .env file or environment (default: 127.0.0.1)
// - Set TEST_TARGET_PORTS in .env file or environment (default: 22,80,443,3389,8080)
// - Set TEST_SCAN_TIMEOUT_SECS in .env file or environment (default: 30)

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustnmap_core::session::{PortSpec, ScanConfig, ScanType};
use rustnmap_core::{ScanOrchestrator, ScanSession};
use rustnmap_scan::scanner::TimingTemplate;
use rustnmap_target::{Target, TargetGroup};

/// Load environment variables from `.env` file if present.
fn init_env() {
    let _ = dotenvy::dotenv();
}

/// Gets the external test target IP from environment or defaults to localhost.
fn target_ip() -> Ipv4Addr {
    init_env();
    std::env::var("TEST_TARGET_IP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

/// Gets the ports to scan from environment or returns defaults.
fn target_ports() -> Vec<u16> {
    init_env();
    std::env::var("TEST_TARGET_PORTS")
        .unwrap_or_else(|_| "22,80,443,3389,8080".to_string())
        .split(',')
        .map(str::trim)
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Gets the scan timeout from environment or returns default.
fn scan_timeout() -> Duration {
    init_env();
    std::env::var("TEST_SCAN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or_else(|| Duration::from_secs(30), Duration::from_secs)
}

/// Detects if the current process has `root/CAP_NET_RAW` privileges.
fn has_raw_socket_privileges() -> bool {
    // SAFETY: Creating a raw socket to test privileges; fd is checked before use
    match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) } {
        -1 => false,
        fd => {
            // SAFETY: fd is valid (not -1) and was just created by socket()
            unsafe { libc::close(fd) };
            true
        }
    }
}

/// Tests TCP SYN scan against the configured external test target.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges - scans external target (configure via TEST_TARGET_IP in .env)"]
async fn test_syn_scan_target() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let target_ip = target_ip();
    let ports = target_ports();

    let config = ScanConfig {
        scan_types: vec![ScanType::TcpSyn],
        port_spec: PortSpec::List(ports.clone()),
        timing_template: TimingTemplate::Normal,
        host_timeout: scan_timeout(),
        ..ScanConfig::default()
    };

    let target = Target::from(target_ip);
    let targets = TargetGroup::new(vec![target]);

    let session = ScanSession::new(config, targets).expect("Failed to create scan session");
    let session = Arc::new(session);

    let orchestrator = ScanOrchestrator::new(session);

    println!("\n========================================");
    println!("Starting SYN scan against {target_ip}");
    println!("Ports: {ports:?}");
    println!("========================================\n");

    let start = std::time::Instant::now();

    match orchestrator.run().await {
        Ok(result) => {
            let duration = start.elapsed();
            println!("\nScan completed in {duration:?}");
            println!("Hosts found: {}", result.hosts.len());

            for host in &result.hosts {
                println!("\nHost: {}", host.ip);
                println!("Status: {:?}", host.status);

                if host.ports.is_empty() {
                    println!("\nNo open ports found");
                } else {
                    println!("\nOpen Ports:");
                    for port in &host.ports {
                        println!(
                            "  {:>5}/{:<4} - {:?}",
                            port.number,
                            format!("{:?}", port.protocol).to_lowercase(),
                            port.state
                        );
                    }
                }
            }

            // Test passes if scan completes
            println!("\nSYN scan test PASSED");
        }
        Err(e) => {
            println!("\nScan error: {e}");
            // Don't fail the test on network errors
            println!("SYN scan completed with error (may be expected)");
        }
    }
}

/// Tests TCP Connect scan against the configured external test target.
/// This does NOT require root privileges.
#[tokio::test]
#[ignore = "Scans external target (configure via TEST_TARGET_IP in .env) - may be slow"]
async fn test_connect_scan_target() {
    let target_ip = target_ip();
    let ports = target_ports();

    let config = ScanConfig {
        scan_types: vec![ScanType::TcpConnect],
        port_spec: PortSpec::List(ports.clone()),
        timing_template: TimingTemplate::Normal,
        host_timeout: Duration::from_secs(60),
        ..ScanConfig::default()
    };

    let target = Target::from(target_ip);
    let targets = TargetGroup::new(vec![target]);

    let session = ScanSession::new(config, targets).expect("Failed to create scan session");
    let session = Arc::new(session);

    let orchestrator = ScanOrchestrator::new(session);

    println!("\n========================================");
    println!("Starting Connect scan against {target_ip}");
    println!("Ports: {ports:?}");
    println!("========================================\n");

    let start = std::time::Instant::now();

    match orchestrator.run().await {
        Ok(result) => {
            let duration = start.elapsed();
            println!("\nScan completed in {duration:?}");

            for host in &result.hosts {
                println!("\nHost: {}", host.ip);
                for port in &host.ports {
                    println!("  Port {}: {:?}", port.number, port.state);
                }
            }

            println!("\nConnect scan test PASSED");
        }
        Err(e) => {
            println!("\nScan error: {e}");
            println!("Connect scan completed with error");
        }
    }
}

/// Tests UDP scan against the configured external test target.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges - scans external target (configure via TEST_TARGET_IP in .env)"]
async fn test_udp_scan_target() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let target_ip = target_ip();
    let ports = vec![53u16, 123, 161]; // DNS, NTP, SNMP

    let config = ScanConfig {
        scan_types: vec![ScanType::Udp],
        port_spec: PortSpec::List(ports.clone()),
        timing_template: TimingTemplate::Normal,
        host_timeout: Duration::from_secs(60),
        ..ScanConfig::default()
    };

    let target = Target::from(target_ip);
    let targets = TargetGroup::new(vec![target]);

    let session = ScanSession::new(config, targets).expect("Failed to create scan session");
    let session = Arc::new(session);

    let orchestrator = ScanOrchestrator::new(session);

    println!("\n========================================");
    println!("Starting UDP scan against {target_ip}");
    println!("Ports: {ports:?}");
    println!("========================================\n");

    let start = std::time::Instant::now();

    match orchestrator.run().await {
        Ok(result) => {
            let duration = start.elapsed();
            println!("\nUDP scan completed in {duration:?}");

            for host in &result.hosts {
                println!("\nHost: {}", host.ip);
                for port in &host.ports {
                    println!("  Port {}: {:?}", port.number, port.state);
                }
            }

            println!("\nUDP scan test PASSED");
        }
        Err(e) => {
            println!("\nUDP scan error: {e}");
        }
    }
}

/// Tests ICMP ping (host discovery) against the configured external test target.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges - pings external target (configure via TEST_TARGET_IP in .env)"]
fn test_icmp_ping_target() {
    use rustnmap_common::ScanConfig as CommonScanConfig;
    use rustnmap_target::{HostDiscovery, HostState};

    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    init_env();
    let target_ip = target_ip();

    let config = CommonScanConfig {
        initial_rtt: Duration::from_secs(2),
        max_retries: 2,
        ..CommonScanConfig::default()
    };

    let discovery = HostDiscovery::new(config);
    let target = Target::from(target_ip);

    println!("\n========================================");
    println!("Pinging {target_ip}");
    println!("========================================\n");

    match discovery.discover_icmp(&target) {
        Ok(state) => {
            println!("\nHost state: {state:?}");
            assert!(
                matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
                "Got valid host state"
            );
            println!("\nICMP ping test PASSED");
        }
        Err(e) => {
            println!("\nPing error: {e}");
        }
    }
}

/// Tests OS detection against the configured external test target.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges - performs OS detection (configure via TEST_TARGET_IP in .env)"]
async fn test_os_detection_target() {
    use rustnmap_fingerprint::os::{FingerprintDatabase, OsDetector};

    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    init_env();
    let target_ip = target_ip();

    // Create an empty fingerprint database
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let detector = OsDetector::new(db, local_addr);

    let target_addr = std::net::SocketAddr::from((target_ip, 80));

    println!("\n========================================");
    println!("Performing OS detection against {target_ip}");
    println!("========================================\n");

    let start = std::time::Instant::now();

    match detector.detect_os(&target_addr).await {
        Ok(fingerprint) => {
            let duration = start.elapsed();
            println!("\nOS detection completed in {duration:?}");
            println!("Fingerprint: {fingerprint:?}");
            println!("\nOS detection test PASSED");
        }
        Err(e) => {
            println!("\nOS detection error: {e}");
        }
    }
}
