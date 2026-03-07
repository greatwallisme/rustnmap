//! RecvfromPacketEngine PPS (Packets Per Second) performance benchmarks.
//!
//! This module benchmarks the actual packet reception throughput of `RecvfromPacketEngine`
//! to measure real-world PPS achieved with the recvfrom() fallback.
//!
//! # Environment Requirements
//!
//! - Root privileges (`CAP_NET_RAW` capability)
//! - Actual network interface (not loopback)
//! - Network traffic (either from background traffic or packet generator)
//!
//! # Running the benchmarks
//!
//! ```bash
//! # Run with default settings (requires network traffic)
//! sudo cargo bench -p rustnmap-benchmarks -- recvfrom_pps
//!
//! # Run with specific interface
//! TEST_INTERFACE=ens33 sudo cargo bench -p rustnmap-benchmarks -- recvfrom_pps
//! ```
//!
//! # Expected Results
//!
//! Since PACKET_MMAP is not available on this kernel, we expect:
//! - recvfrom PPS: ~50,000 PPS (baseline)
//! - CPU usage: ~80% under load (T5 timing)
//! - This will serve as the baseline for future PACKET_MMAP implementation

// Rust guideline compliant 2026-03-07

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rustnmap_packet::{PacketEngine, RecvfromPacketEngine};
use std::env;
use std::hint::black_box;
use std::time::Duration;

/// Get the test interface name from environment or use default.
fn get_test_interface() -> String {
    env::var("TEST_INTERFACE").unwrap_or_else(|_| String::from("ens33"))
}

/// Benchmark packet reception throughput.
///
/// This measures how many packets per second the `RecvfromPacketEngine`
/// can receive and process from the network.
fn bench_recvfrom_packet_reception(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Try to create the engine - skip if not available
    let mut engine = match RecvfromPacketEngine::new(&if_name) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Skipping recvfrom PPS benchmark: cannot create engine on {if_name}: {e}");
            eprintln!("This benchmark requires root privileges and a valid network interface.");
            return;
        }
    };

    // Start the engine
    if let Err(e) = engine.start() {
        eprintln!("Skipping recvfrom PPS benchmark: failed to start engine: {e}");
        return;
    }

    let mut group = c.benchmark_group("recvfrom_pps");
    group
        .measurement_time(Duration::from_secs(10))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(2));

    // Benchmark packet reception in a loop
    group.bench_function("recv_packets", |b| {
        b.iter(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let packet_count = runtime.block_on(async {
                let mut count = 0u64;
                let timeout = Duration::from_millis(100); // Measure for 100ms

                let start_time = std::time::Instant::now();
                while start_time.elapsed() < timeout {
                    match engine.recv().await {
                        Ok(Some(_packet)) => {
                            count += 1;
                        }
                        Ok(None) => {
                            // Timeout or no packet, continue
                        }
                        Err(_e) => {
                            // Error receiving, continue
                        }
                    }
                }
                count
            });
            black_box(packet_count)
        });
    });

    group.finish();
}

/// Benchmark packet transmission throughput.
///
/// This measures how many packets per second the `RecvfromPacketEngine`
/// can transmit to the network.
fn bench_recvfrom_packet_transmission(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Try to create the engine - skip if not available
    let engine = match RecvfromPacketEngine::new(&if_name) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Skipping recvfrom PPS benchmark: cannot create engine on {if_name}: {e}");
            return;
        }
    };

    // Create a test packet (Ethernet frame)
    let test_packet = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: broadcast
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Source: arbitrary
        0x08, 0x00, // EtherType: IPv4
        // Minimal IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // IP header
        0xc0, 0xa8, 0x01, 0x01, // Source IP
        0xc0, 0xa8, 0x01, 0xff, // Dest IP
        // UDP header (8 bytes)
        0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00, // UDP header
        // Payload (4 bytes)
        0x00, 0x00, 0x00, 0x00,
    ];

    let mut group = c.benchmark_group("recvfrom_send_pps");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    group.throughput(Throughput::Bytes(test_packet.len() as u64));

    group.bench_function("send_packets", |b| {
        b.iter(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let packet_count = runtime.block_on(async {
                let mut count = 0u64;
                let timeout = Duration::from_millis(100); // Measure for 100ms
                let test_packet_ref = &test_packet;

                let start_time = std::time::Instant::now();
                while start_time.elapsed() < timeout {
                    // Send packet and count
                    match engine.send(black_box(test_packet_ref)).await {
                        Ok(_bytes_sent) => {
                            count += 1;
                        }
                        Err(_e) => {
                            // Error sending, continue
                        }
                    }
                }
                count
            });
            black_box(packet_count)
        });
    });

    group.finish();
}

/// Benchmark round-trip packet operations (send + receive).
///
/// This measures the combined throughput of sending and receiving packets,
/// which is more representative of actual scanning workloads.
fn bench_recvfrom_round_trip(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Try to create the engine - skip if not available
    let mut engine = match RecvfromPacketEngine::new(&if_name) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Skipping recvfrom PPS benchmark: cannot create engine on {if_name}: {e}");
            return;
        }
    };

    // Start the engine
    if let Err(e) = engine.start() {
        eprintln!("Skipping recvfrom PPS benchmark: failed to start engine: {e}");
        return;
    }

    // Create a test packet
    let test_packet = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: broadcast
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Source: arbitrary
        0x08, 0x00, // EtherType: IPv4
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // IP header
        0xc0, 0xa8, 0x01, 0x01, // Source IP
        0xc0, 0xa8, 0x01, 0xff, // Dest IP
        0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00, // UDP header
        0x00, 0x00, 0x00, 0x00, // Payload
    ];

    let mut group = c.benchmark_group("recvfrom_round_trip");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    group.bench_function("send_and_recv", |b| {
        b.iter(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let ops_count = runtime.block_on(async {
                let mut count = 0u64;
                let timeout = Duration::from_millis(100);

                let start_time = std::time::Instant::now();
                while start_time.elapsed() < timeout {
                    // Send packet
                    let _ = engine.send(black_box(&test_packet)).await;

                    // Try to receive (may timeout, that's ok)
                    let _ = engine.recv().await;

                    count += 1;
                }
                count
            });
            black_box(ops_count)
        });
    });

    group.finish();
}

criterion_group!(
    name = recvfrom_pps;
    config = Criterion::default().sample_size(10);
    targets = bench_recvfrom_packet_reception, bench_recvfrom_packet_transmission,
    bench_recvfrom_round_trip
);

criterion_main!(recvfrom_pps);
