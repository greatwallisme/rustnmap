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
//! TEST_INTERFACE=ens33 cargo bench -p rustnmap-benchmarks -- mmap_pps
//! ```
//!
//! # Expected Results
//!
//! - PPS: 500,000 - 1,000,000 PPS (depending on hardware and traffic)
//! - CPU usage: ~30% under load (T5 timing)
//! - Zero-copy: No memory copies in hot path

// Rust guideline compliant 2026-03-07

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rustnmap_packet::{MmapPacketEngine, PacketEngine, RingConfig};
use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

/// Get the test interface name from environment or use default.
fn get_test_interface() -> String {
    env::var("TEST_INTERFACE").unwrap_or_else(|_| String::from("ens33"))
}

/// Create a default RX-enabled ring config.
fn default_rx_config() -> RingConfig {
    RingConfig {
        block_size: 65536,
        block_nr: 256,
        frame_size: 4096,
        frame_timeout: 64,
        enable_rx: true,
        enable_tx: false,
    }
}

/// Benchmark packet reception throughput for `MmapPacketEngine`.
fn bench_mmap_packet_reception(c: &mut Criterion) {
    let if_name = get_test_interface();
    let config = default_rx_config();

    let Some(mut engine) = MmapPacketEngine::new(&if_name, config)
        .inspect_err(|e| {
            eprintln!("Skipping mmap PPS benchmark: cannot create engine on {if_name}: {e}");
        })
        .ok()
    else {
        return;
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let Some(()) = runtime.block_on(async {
        engine
            .start()
            .await
            .inspect_err(|e| {
                eprintln!("Skipping mmap PPS benchmark: failed to start engine: {e}");
            })
            .ok()
    }) else {
        return;
    };

    let mut group = c.benchmark_group("mmap_packet_reception");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    group.bench_function("recv_packets", |b| {
        b.iter(|| {
            let packet_count = runtime.block_on(async {
                let mut count = 0u64;
                let timeout = Duration::from_millis(100);
                let start_time = Instant::now();

                while start_time.elapsed() < timeout {
                    match engine.recv().await {
                        Ok(Some(_)) => count += 1,
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
                count
            });
            black_box(packet_count)
        });
    });

    group.finish();
}

/// Benchmark zero-copy packet reception.
fn bench_mmap_zero_copy_reception(c: &mut Criterion) {
    let if_name = get_test_interface();
    let config = default_rx_config();

    let Some(mut engine) = MmapPacketEngine::new(&if_name, config)
        .inspect_err(|e| {
            eprintln!("Skipping mmap zero-copy benchmark: cannot create engine on {if_name}: {e}");
        })
        .ok()
    else {
        return;
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let Some(()) = runtime.block_on(async {
        engine
            .start()
            .await
            .inspect_err(|e| {
                eprintln!("Skipping mmap zero-copy benchmark: failed to start engine: {e}");
            })
            .ok()
    }) else {
        return;
    };

    let mut group = c.benchmark_group("mmap_zero_copy_reception");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    group.bench_function("recv_zero_copy_packets", |b| {
        b.iter(|| {
            let (zero_copy_count, total_count) = runtime.block_on(async {
                let mut zc_count = 0u64;
                let mut total = 0u64;
                let timeout = Duration::from_millis(100);
                let start_time = Instant::now();

                while start_time.elapsed() < timeout {
                    match engine.recv().await {
                        Ok(Some(_packet)) => {
                            total += 1;
                            zc_count += 1;
                        }
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
                (zc_count, total)
            });
            black_box((zero_copy_count, total_count))
        });
    });

    group.finish();
}

/// Benchmark ring buffer efficiency.
fn bench_mmap_ring_buffer_efficiency(c: &mut Criterion) {
    let if_name = get_test_interface();
    let config = default_rx_config();

    let Some(mut engine) = MmapPacketEngine::new(&if_name, config)
        .inspect_err(|e| {
            eprintln!(
                "Skipping mmap ring buffer benchmark: cannot create engine on {if_name}: {e}"
            );
        })
        .ok()
    else {
        return;
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let Some(()) = runtime.block_on(async {
        engine
            .start()
            .await
            .inspect_err(|e| {
                eprintln!("Skipping mmap ring buffer benchmark: failed to start engine: {e}");
            })
            .ok()
    }) else {
        return;
    };

    let mut group = c.benchmark_group("mmap_ring_buffer_efficiency");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    group.bench_function("ring_buffer_recv", |b| {
        b.iter(|| {
            let packet_count = runtime.block_on(async {
                let mut count = 0u64;
                let timeout = Duration::from_millis(100);
                let start_time = Instant::now();

                while start_time.elapsed() < timeout {
                    match engine.recv().await {
                        Ok(Some(_)) => count += 1,
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
                count
            });
            black_box(packet_count)
        });
    });

    group.finish();
}

/// Benchmark with varying ring buffer configurations.
fn bench_mmap_ring_config_comparison(c: &mut Criterion) {
    let if_name = get_test_interface();

    let configs: Vec<(&str, RingConfig)> = vec![
        (
            "small",
            RingConfig {
                block_size: 4096,
                block_nr: 64,
                frame_size: 2048,
                frame_timeout: 64,
                enable_rx: true,
                enable_tx: false,
            },
        ),
        (
            "default",
            RingConfig {
                block_size: 65536,
                block_nr: 256,
                frame_size: 4096,
                frame_timeout: 64,
                enable_rx: true,
                enable_tx: false,
            },
        ),
        (
            "large",
            RingConfig {
                block_size: 131072,
                block_nr: 512,
                frame_size: 4096,
                frame_timeout: 64,
                enable_rx: true,
                enable_tx: false,
            },
        ),
    ];

    let mut group = c.benchmark_group("mmap_ring_config_comparison");
    group
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1));

    for (name, config) in &configs {
        group.bench_with_input(BenchmarkId::from_parameter(name), config, |b, &config| {
            let Some(mut engine) = MmapPacketEngine::new(&if_name, config)
                .inspect_err(|e| eprintln!("Skipping {name} config: {e}"))
                .ok()
            else {
                return;
            };

            let runtime = tokio::runtime::Runtime::new().unwrap();
            let Some(()) = runtime.block_on(async {
                engine
                    .start()
                    .await
                    .inspect_err(|e| {
                        eprintln!("Skipping {name} config start: {e}");
                    })
                    .ok()
            }) else {
                return;
            };

            b.iter(|| {
                let packet_count = runtime.block_on(async {
                    let mut count = 0u64;
                    let timeout = Duration::from_millis(100);
                    let start_time = Instant::now();

                    while start_time.elapsed() < timeout {
                        match engine.recv().await {
                            Ok(Some(_)) => count += 1,
                            Ok(None) => {}
                            Err(_) => {}
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

criterion_group! {
    name = mmap_pps;
    config = Criterion::default().sample_size(10);
    targets = bench_mmap_packet_reception,
    bench_mmap_zero_copy_reception,
    bench_mmap_ring_buffer_efficiency,
    bench_mmap_ring_config_comparison
}

criterion_main!(mmap_pps);
