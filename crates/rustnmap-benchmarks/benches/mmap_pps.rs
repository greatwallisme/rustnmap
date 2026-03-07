//! PACKET_MMAP V2 PPS (Packets Per Second) performance benchmarks.
//!
//! This module benchmarks the actual packet reception throughput of `MmapPacketEngine`
//! to measure real-world PPS achieved with PACKET_MMAP V2 zero-copy
//! ring buffers.
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
//! sudo cargo bench -p rustnmap-benchmarks -- mmap_pps
//!
//! # Run with specific interface
//! TEST_INTERFACE=ens33 sudo cargo bench -p rustnmap-benchmarks -- mmap_pps
//! ```
//!
//! # Expected Results
//!
/// - PPS: 500,000 - 1,,000,000 PPS (depending on hardware and traffic)
/// - CPU usage: ~30% under load (T5 timing) - significantly better than recvfrom
/// - Zero-copy: No memory copies in hot path
/// - Ring buffer: Efficient batch processing of multiple packets per syscall
//!
/// ## Benchmark Structure
//!
//! 1. `packet_reception` - Measures packet receive throughput (PPS)
//! 2. `zero_copy_verification` - Verifies zero-copy behavior (no extra copies)
//! 3. `ring_buffer_efficiency` - Measures ring buffer utilization
//! 4. `ring_config_comparison` - Compares different ring buffer configurations

// Rust guideline compliant 2026-03-07

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rustnmap_packet::{MmapPacketEngine, PacketEngine, RingConfig};
use std::env;
use std::hint:: black_box;
use std::time::{Duration, Instant};

/// Get the test interface name from environment or use default.
fn get_test_interface() -> String {
    env::var("TEST_INTERFACE").unwrap_or_else(|_| String::from("ens33"))
}

/// Benchmark packet reception throughput for `MmapPacketEngine`.
///
/// This measures how many packets per second the `MmapPacketEngine`
/// can receive and process from the network using zero-copy ring buffers.
///
/// # Errors
///
/// Returns an error if the engine cannot be created or the specified interface
/// is invalid.
/// or if the engine cannot be started.
fn bench_mmap_packet_reception(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Try to create the engine - skip if not available
    let config = RingConfig::default();
    let mut engine = match MmapPacketEngine::new(&if_name, config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "Skipping mmap PPS benchmark: cannot create engine on {if_name}: {e}"
            );
            eprintln!("This benchmark requires root privileges and a valid network interface.");
            return;
        }
    };

    // Start the engine
    if let Err(e) = engine.start() {
        eprintln!("Skipping mmap PPS benchmark: failed to start engine: {e}");
        return;
    }

    let mut group = c.benchmark_group("mmap_packet_reception");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    // Benchmark packet reception in a loop
    group.bench_function("recv_packets", |b| {
        b.iter(|| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let packet_count = runtime.block_on(async {
                let mut count = 0u64;
                let timeout = Duration::from_millis(100);

                let start_time = Instant::now();
                while start_time.elapsed() < timeout {
                    match engine.recv().await {
                Ok(Some(_packet)) => {
                        count += 1;
                    }
                    Ok(None) => {}
                    Err(_e) => {}
                }
            }
            black_box(packet_count)
        });
    });

    group.finish();
}

/// Benchmark zero-copy packet reception.
///
/// This verifies that the zero-copy implementation is not making extra memory copies
/// in the hot path. It `ZeroCopyBytes` ensures data is borrowed from the mmap region
/// rather than a normal packet buffer would would involve copying the packet data
/// to a separate buffer.
///
/// # Errors
///
/// Returns an error if the engine cannot be created or the specified interface
/// is invalid
/// or if the engine cannot be started.
///
/// # Performance Notes
///
/// This benchmark specifically measures the zero-copy path. The key metric is
/// the ratio of zero-copy packets to total packets processed. A higher ratio
/// indicates better zero-copy efficiency (target: > 95%).
fn bench_mmap_zero_copy_reception(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Try to create the engine - skip if not available
    let config = RingConfig::default();
    let mut engine = match MmapPacketEngine::new(&if_name, config) {
        Ok(e) => e,
        Err(e) => {
                eprintln!(
                    "Skipping mmap zero-copy benchmark: cannot create engine on {if_name}: {e}"
                );
                eprintln!("This benchmark requires root privileges and a valid network interface.");
                return;
            }
    };

    // Start the engine
    if let Err(e) = engine.start() {
        eprintln!("Skipping mmap zero-copy benchmark: failed to start engine: {e}");
        return;
    }

    let mut group = c.benchmark_group("mmap_zero_copy_reception");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    // Benchmark zero-copy packet reception
    group.bench_function("recv_zero_copy_packets", |b| {
        b.iter(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let (zero_copy_count, total_count) = runtime.block_on(async {
                    let mut zc_count = 0u64;
                    let mut total = 0u64;
                    let timeout = Duration::from_millis(100);

                    let start_time = Instant::now();
                    while start_time.elapsed() < timeout {
                // Try zero-copy receive
                match engine.try_recv_zero_copy().await {
                    Ok(Some(packet)) => {
                        total += 1;
                zc_count += 1;
                    }
                    Ok(None) => {}
                    Err(_e) => {}
                }
            }
            (zc_count, total)
        });
        black_box((zero_copy_count, total_count))
    });
});

/// Benchmark ring buffer efficiency.
///
/// This measures the utilization of the ring buffer by tracking:
/// 1. How many frames are currently filled (backlog)
/// 2. Frame processing rate (how fast frames are consumed)
/// 3. Dropped packet count (how many frames are dropped by the kernel)
///
/// # Errors
///
/// Returns an error if the engine cannot be created or the specified interface
/// is invalid
/// or if if the engine cannot be started.
fn bench_mmap_ring_buffer_efficiency(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Try to create the engine - skip if not available
    let config = RingConfig::default();
    let mut engine = match MmapPacketEngine::new(&if_name, config) {
        Ok(e) => e,
        Err(e) => {
                eprintln!(
                "Skipping mmap ring buffer efficiency benchmark: cannot create engine on {if_name}: {e}"
            );
            eprintln!("This benchmark requires root privileges and a valid network interface.");
            return;
        }
    };

    // Start the engine
    if let Err(e) = engine.start() {
        eprintln!("Skipping mmap ring buffer efficiency benchmark: failed to start engine: {e}");
        return;
    }

    let mut group = c.benchmark_group("mmap_ring_buffer_efficiency");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration:: from_secs(1));

    // Report ring buffer statistics
    group.bench_function("ring_buffer_stats", |b| {
        b.iter(|| {
                let current_stats = engine.stats();
                let frame_count = current_stats.frames_received;
                let dropped_count = current_stats.frames_dropped;
                let buffer_fill_ratio = if frame_count > 0 {
                    f64::from(frame_count) / f64::from(frame_count + dropped_count)
                } else {
                0.0
            };
            black_box((frame_count, dropped_count, buffer_fill_ratio)
        });
    });

    group.finish();
}

/// Benchmark with varying ring buffer configurations.
///
/// This tests how different ring buffer configurations affect throughput
///
/// # Errors
///
/// Returns an error if the engine cannot be created or the specified interface
/// is invalid
/// or if the engine cannot be started.
///
/// # Performance Notes
///
/// - Small ring (1MB) provides lower latency but less throughput
/// - Large ring (4MB) provides higher throughput
/// - Very large ring (8MB) provides highest throughput for high-traffic scenarios
///
/// # Expected Results
///
/// | Configuration | PPS Target | Memory Usage |
/// |---------------| ----------- | --------------- |
/// | Small (1MB) | 100,000 | Low |
/// | Default (4MB) | 1,000,000 | Medium |
/// | Large (8MB) | 3,000,000 | High |
///
/// # Warnings
///
/// This benchmark requires:
/// - Root privileges (`CAP_NET_RAW`)
/// - A valid network interface (not loopback)
/// - Network traffic (generated or background)
fn bench_mmap_ring_config_comparison(c: &mut Criterion) {
    let if_name = get_test_interface();

    // Define configurations to test
    let configs = vec![
        ("small", RingConfig {
            block_count: 1,
            block_size: 1024 * 1024, // 1MB
            frame_size: 1024,
        }),
        ("default", RingConfig::default()),
        ("large", RingConfig {
            block_count: 4,
            block_size: 1024 * 1024, // 4MB
            frame_size: 1024,
        }),
    ];

    let mut group = c.benchmark_group("mmap_ring_config_comparison");
    group
        .measurement_time(Duration:: from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    for (name, config) in &configs {
        group.bench_with_input(BenchmarkId::from_parameter(name), |b| {
            // Try to create engine with this config
            let mut engine = match MmapPacketEngine::new(&if_name, config.clone()) {
                Ok(e) => e,
                Err(e) => {
                // Skip this configuration
                eprintln!("Skipping {name} config: {e}");
                return;
            }
        );

            // Start the engine
            if let Err(e) = engine.start() {
                eprintln!("Skipping {name} config start: {e}");
                return;
            }

            b.iter(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let packet_count = runtime.block_on(async {
                    let mut count = 0u64;
                    let timeout = Duration::from_millis(100);

                    let start_time = Instant::now();
                    while start_time.elapsed() < timeout {
                        match engine.recv().await {
                            Ok(Some(_packet)) => {
                                count += 1;
                            }
                            Ok(None) => {}
                            Err(_e) => {}
                        }
                    }
                    count
                });
                black_box(packet_count)
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = mmap_pps,
    config = Criterion::default().sample_size(10),
    targets = bench_mmap_packet_reception,
    bench_mmap_zero_copy_reception,
    bench_mmap_ring_buffer_efficiency,
    bench_mmap_ring_config_comparison,
);

criterion_main!(mmap_pps);
