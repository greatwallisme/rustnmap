//! Scanning performance benchmarks for `RustNmap`.
//!
//! This module benchmarks the performance of various scanning techniques
//! including TCP SYN scan, TCP Connect scan, UDP scan, and parallel scan throughput.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rustnmap_common::{Ipv4Addr, Port, PortRange, PortState, Protocol, ScanConfig, TimingTemplate};
use rustnmap_net::raw_socket::{TcpPacketBuilder, UdpPacketBuilder};
use rustnmap_scan::scanner::PortScanner;
use rustnmap_scan::TcpConnectScanner;
use rustnmap_target::{Target, TargetParser};
use std::hint::black_box;

/// Creates a test target for benchmarking.
fn create_test_target(ip: &str) -> Target {
    Target {
        ip: rustnmap_common::IpAddr::V4(ip.parse().unwrap()),
        hostname: None,
        ports: None,
        ipv6_scope: None,
    }
}

/// Benchmark TCP SYN packet construction.
///
/// This measures the overhead of building raw TCP SYN packets,
/// which is the hot path for SYN scanning.
fn bench_tcp_syn_packet_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_syn_packet_construction");

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
    let src_port: Port = 60000;
    let dst_port: Port = 80;

    group.throughput(Throughput::Elements(1));
    group.bench_function("build_syn_packet", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .seq(12345)
                .syn()
                .window(65535)
                .build();
            black_box(packet);
        });
    });

    group.bench_function("build_syn_packet_with_options", |b| {
        let options = [0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02];
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .seq(12345)
                .syn()
                .window(65535)
                .options(&options)
                .build();
            black_box(packet);
        });
    });

    group.finish();
}

/// Benchmark TCP Connect scan performance (simulated).
///
/// Since actual network operations are non-deterministic for benchmarking,
/// we benchmark the scanner setup and configuration overhead.
fn bench_tcp_connect_scan_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_connect_scan");

    let config = ScanConfig::default();

    group.bench_function("scanner_creation", |b| {
        b.iter(|| {
            let scanner = TcpConnectScanner::new(None, config.clone());
            black_box(scanner);
        });
    });

    group.bench_function("scan_port_filtered_protocol", |b| {
        let scanner = TcpConnectScanner::new(None, config.clone());
        let target = create_test_target("192.168.1.1");

        b.iter(|| {
            // UDP protocol should be filtered by TCP scanner
            let result = scanner.scan_port(&target, 80, Protocol::Udp);
            let _ = black_box(result);
        });
    });

    group.finish();
}

/// Benchmark UDP packet construction.
fn bench_udp_packet_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_packet_construction");

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
    let src_port: Port = 60000;
    let dst_port: Port = 53;

    group.throughput(Throughput::Elements(1));
    group.bench_function("build_udp_packet_empty", |b| {
        b.iter(|| {
            let packet = UdpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port).build();
            black_box(packet);
        });
    });

    group.bench_function("build_udp_packet_with_payload", |b| {
        let payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        b.iter(|| {
            let packet = UdpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .payload(payload)
                .build();
            black_box(packet);
        });
    });

    group.finish();
}

/// Benchmark port range iteration.
fn bench_port_range_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_range_iteration");

    group.throughput(Throughput::Elements(1000));
    group.bench_function("iterate_1000_ports", |b| {
        let range = PortRange::new(1, 1000).unwrap();
        b.iter(|| {
            let count = range.iter().count();
            black_box(count);
        });
    });

    group.throughput(Throughput::Elements(65535));
    group.bench_function("iterate_all_ports", |b| {
        let range = PortRange::new(1, 65535).unwrap();
        b.iter(|| {
            let count = range.iter().count();
            black_box(count);
        });
    });

    group.throughput(Throughput::Elements(100));
    group.bench_function("port_list_from_slice", |b| {
        let ports: Vec<Port> = (1..=100).collect();
        b.iter(|| {
            let list = rustnmap_common::PortList::from_slice(&ports);
            black_box(list);
        });
    });

    group.finish();
}

/// Benchmark target parsing and expansion.
fn bench_target_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_parsing");

    let parser = TargetParser::new();

    group.bench_function("parse_single_ip", |b| {
        b.iter(|| {
            let target = parser.parse("192.168.1.1").unwrap();
            black_box(target);
        });
    });

    group.bench_function("parse_cidr_24", |b| {
        b.iter(|| {
            let target = parser.parse("192.168.1.0/24").unwrap();
            black_box(target);
        });
    });

    group.bench_function("parse_range", |b| {
        b.iter(|| {
            let target = parser.parse("192.168.1.1-100").unwrap();
            black_box(target);
        });
    });

    group.bench_function("expand_cidr_24", |b| {
        b.iter(|| {
            let addrs =
                rustnmap_target::expand_target_spec(&rustnmap_target::TargetSpec::Ipv4Cidr {
                    base: Ipv4Addr::new(192, 168, 1, 0),
                    prefix: 24,
                })
                .unwrap();
            black_box(addrs);
        });
    });

    group.finish();
}

/// Benchmark timing template operations.
fn bench_timing_templates(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_templates");

    group.bench_function("template_t0_paranoia", |b| {
        b.iter(|| {
            let template = TimingTemplate::Paranoid;
            let config = template.scan_config();
            black_box(config);
        });
    });

    group.bench_function("template_t5_insane", |b| {
        b.iter(|| {
            let template = TimingTemplate::Insane;
            let config = template.scan_config();
            black_box(config);
        });
    });

    group.bench_function("template_all_variants", |b| {
        b.iter(|| {
            let templates = [
                TimingTemplate::Paranoid,
                TimingTemplate::Sneaky,
                TimingTemplate::Polite,
                TimingTemplate::Normal,
                TimingTemplate::Aggressive,
                TimingTemplate::Insane,
            ];
            let results: Vec<_> = templates
                .iter()
                .map(rustnmap_common::TimingTemplate::scan_config)
                .collect();
            black_box(results);
        });
    });

    group.finish();
}

/// Benchmark parallel scan throughput simulation.
///
/// Measures the theoretical maximum throughput of the scanning engine
/// by simulating port state processing without actual network I/O.
fn bench_parallel_scan_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_scan_throughput");

    // Simulate processing port states
    group.throughput(Throughput::Elements(1000));
    group.bench_function("process_1000_port_states", |b| {
        let states = [
            PortState::Open,
            PortState::Closed,
            PortState::Filtered,
            PortState::OpenOrFiltered,
        ];
        b.iter(|| {
            for i in 0..1000 {
                let state = states[i % states.len()];
                let is_open = state.is_open();
                let is_closed = state.is_closed();
                let is_filtered = state.is_filtered();
                black_box((is_open, is_closed, is_filtered));
            }
        });
    });

    // Simulate scan result aggregation
    group.throughput(Throughput::Elements(100));
    group.bench_function("aggregate_100_results", |b| {
        b.iter(|| {
            let mut open_count = 0u32;
            let mut closed_count = 0u32;
            let mut filtered_count = 0u32;

            for i in 0..100 {
                let state = match i % 4 {
                    0 => PortState::Open,
                    1 => PortState::Closed,
                    2 => PortState::Filtered,
                    _ => PortState::OpenOrFiltered,
                };

                match state {
                    PortState::Open => open_count += 1,
                    PortState::Closed => closed_count += 1,
                    PortState::Filtered
                    | PortState::OpenOrFiltered
                    | PortState::ClosedOrFiltered => {
                        filtered_count += 1;
                    }
                    _ => {}
                }
            }

            black_box((open_count, closed_count, filtered_count));
        });
    });

    group.finish();
}

/// Benchmark scan configuration operations.
fn bench_scan_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_config");

    group.bench_function("default_config", |b| {
        b.iter(|| {
            let config = ScanConfig::default();
            black_box(config);
        });
    });

    group.bench_function("config_with_timing", |b| {
        b.iter(|| {
            let config = TimingTemplate::Aggressive.scan_config();
            black_box(config);
        });
    });

    group.finish();
}

/// Benchmark stealth scan packet construction.
fn bench_stealth_scan_packets(c: &mut Criterion) {
    let mut group = c.benchmark_group("stealth_scan_packets");

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
    let src_port: Port = 60000;
    let dst_port: Port = 80;

    group.throughput(Throughput::Elements(1));

    group.bench_function("build_fin_packet", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .seq(12345)
                .fin()
                .window(65535)
                .build();
            black_box(packet);
        });
    });

    group.bench_function("build_null_packet", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .seq(12345)
                .window(65535)
                .build();
            black_box(packet);
        });
    });

    group.bench_function("build_xmas_packet", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .seq(12345)
                .fin()
                .psh()
                .urg()
                .window(65535)
                .build();
            black_box(packet);
        });
    });

    group.bench_function("build_ack_packet", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, src_port, dst_port)
                .seq(12345)
                .ack_flag()
                .window(65535)
                .build();
            black_box(packet);
        });
    });

    group.finish();
}

criterion_group!(
    scan_benches,
    bench_tcp_syn_packet_construction,
    bench_tcp_connect_scan_overhead,
    bench_udp_packet_construction,
    bench_port_range_iteration,
    bench_target_parsing,
    bench_timing_templates,
    bench_parallel_scan_throughput,
    bench_scan_config,
    bench_stealth_scan_packets
);

criterion_main!(scan_benches);
