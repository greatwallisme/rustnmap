//! Packet I/O performance benchmarks for RustNmap.
//!
//! This module benchmarks raw socket operations, PACKET_MMAP throughput,
//! and packet parsing overhead.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rustnmap_common::{Ipv4Addr, MacAddr};
use rustnmap_net::raw_socket::{
    parse_arp_reply, parse_icmp_echo_reply, parse_icmp_response, parse_tcp_options,
    parse_tcp_response, parse_tcp_response_full, parse_udp_response, ArpPacketBuilder,
    IcmpPacketBuilder, TcpPacketBuilder, UdpPacketBuilder,
};
use rustnmap_packet::{PacketBuffer, DEFAULT_BLOCK_SIZE, DEFAULT_FRAME_SIZE};
use std::hint::black_box;

/// Benchmark TCP packet parsing performance.
///
/// This measures the overhead of parsing TCP response packets,
/// which is critical for high-throughput scanning.
fn bench_tcp_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_packet_parsing");

    // Create a sample TCP SYN-ACK packet
    let src_ip = Ipv4Addr::new(192, 168, 1, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 100);
    let packet = TcpPacketBuilder::new(src_ip, dst_ip, 80, 60000)
        .seq(12345)
        .ack(54321)
        .syn()
        .ack_flag()
        .window(65535)
        .build();

    group.throughput(Throughput::Bytes(packet.len() as u64));

    group.bench_function("parse_tcp_response_basic", |b| {
        b.iter(|| {
            let result = parse_tcp_response(&black_box(&packet));
            black_box(result);
        });
    });

    group.bench_function("parse_tcp_response_full", |b| {
        b.iter(|| {
            let result = parse_tcp_response_full(&black_box(&packet));
            black_box(result);
        });
    });

    // Parse with options
    let packet_with_options = TcpPacketBuilder::new(src_ip, dst_ip, 80, 60000)
        .seq(12345)
        .ack(54321)
        .syn()
        .ack_flag()
        .window(65535)
        .options(&[0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02])
        .build();

    group.bench_function("parse_tcp_response_with_options", |b| {
        b.iter(|| {
            let result = parse_tcp_response_full(&black_box(&packet_with_options));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark TCP options parsing.
fn bench_tcp_options_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_options_parsing");

    // Sample TCP packet with various options
    let src_ip = Ipv4Addr::new(192, 168, 1, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 100);
    let packet = TcpPacketBuilder::new(src_ip, dst_ip, 80, 60000)
        .seq(12345)
        .syn()
        .window(65535)
        .options(&[
            0x02, 0x04, 0x05, 0xb4, // MSS = 1460
            0x01, 0x01, // NOP, NOP
            0x04, 0x02, // SACK permitted
            0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
            0x03, 0x03, 0x07, // Window scale = 7
        ])
        .build();

    group.throughput(Throughput::Elements(1));

    group.bench_function("parse_tcp_options_full", |b| {
        b.iter(|| {
            // TCP header starts at byte 20 (IP header)
            let result = parse_tcp_options(&black_box(&packet), 20);
            black_box(result);
        });
    });

    // Empty options
    let packet_no_options = TcpPacketBuilder::new(src_ip, dst_ip, 80, 60000)
        .seq(12345)
        .syn()
        .window(65535)
        .build();

    group.bench_function("parse_tcp_options_empty", |b| {
        b.iter(|| {
            let result = parse_tcp_options(&black_box(&packet_no_options), 20);
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark UDP packet parsing.
fn bench_udp_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_packet_parsing");

    let src_ip = Ipv4Addr::new(192, 168, 1, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 100);
    let payload = b"Hello, World!";
    let packet = UdpPacketBuilder::new(src_ip, dst_ip, 53, 60000)
        .payload(payload)
        .build();

    group.throughput(Throughput::Bytes(packet.len() as u64));

    group.bench_function("parse_udp_response", |b| {
        b.iter(|| {
            let result = parse_udp_response(&black_box(&packet));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark ICMP packet parsing.
fn bench_icmp_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("icmp_packet_parsing");

    let src_ip = Ipv4Addr::new(192, 168, 1, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

    // ICMP Echo Request
    let echo_packet = IcmpPacketBuilder::new(src_ip, dst_ip)
        .identifier(1234)
        .sequence(1)
        .build();

    group.throughput(Throughput::Bytes(echo_packet.len() as u64));

    group.bench_function("parse_icmp_echo_reply", |b| {
        b.iter(|| {
            let result = parse_icmp_echo_reply(&black_box(&echo_packet));
            black_box(result);
        });
    });

    group.bench_function("parse_icmp_response", |b| {
        b.iter(|| {
            let result = parse_icmp_response(&black_box(&echo_packet));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark ARP packet parsing.
fn bench_arp_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("arp_packet_parsing");

    let src_mac = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let target_ip = Ipv4Addr::new(192, 168, 1, 1);

    let arp_request = ArpPacketBuilder::new(src_mac, src_ip, target_ip).build();

    group.throughput(Throughput::Bytes(arp_request.len() as u64));

    group.bench_function("parse_arp_reply", |b| {
        b.iter(|| {
            let result = parse_arp_reply(&black_box(&arp_request));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark packet buffer operations.
fn bench_packet_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_buffer");

    group.bench_function("packet_buffer_empty", |b| {
        b.iter(|| {
            let buf = PacketBuffer::empty();
            black_box(buf);
        });
    });

    group.bench_function("packet_buffer_default", |b| {
        b.iter(|| {
            let buf: PacketBuffer = Default::default();
            black_box(buf);
        });
    });

    group.bench_function("packet_buffer_is_empty", |b| {
        let buf = PacketBuffer::empty();
        b.iter(|| {
            let result = buf.is_empty();
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark packet construction throughput.
fn bench_packet_construction_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_construction_throughput");

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

    // TCP SYN packets - common in scanning
    group.throughput(Throughput::Elements(1000));
    group.bench_function("construct_1000_tcp_syn", |b| {
        b.iter(|| {
            for i in 0..1000 {
                let dst_port = 1 + (i % 65535) as u16;
                let packet = TcpPacketBuilder::new(src_ip, dst_ip, 60000, dst_port)
                    .seq(i as u32)
                    .syn()
                    .window(65535)
                    .build();
                black_box(packet);
            }
        });
    });

    // UDP packets
    group.throughput(Throughput::Elements(1000));
    group.bench_function("construct_1000_udp", |b| {
        b.iter(|| {
            for i in 0..1000 {
                let dst_port = 1 + (i % 65535) as u16;
                let packet = UdpPacketBuilder::new(src_ip, dst_ip, 60000, dst_port).build();
                black_box(packet);
            }
        });
    });

    // ICMP packets
    group.throughput(Throughput::Elements(1000));
    group.bench_function("construct_1000_icmp", |b| {
        b.iter(|| {
            for i in 0..1000 {
                let packet = IcmpPacketBuilder::new(src_ip, dst_ip)
                    .identifier(i as u16)
                    .sequence(i as u16)
                    .build();
                black_box(packet);
            }
        });
    });

    group.finish();
}

/// Benchmark PACKET_MMAP constants and configuration.
fn bench_packet_mmap_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_mmap_config");

    group.bench_function("read_constants", |b| {
        b.iter(|| {
            let block_size = DEFAULT_BLOCK_SIZE;
            let frame_size = DEFAULT_FRAME_SIZE;
            black_box((block_size, frame_size));
        });
    });

    group.bench_function("calculate_frame_nr", |b| {
        b.iter(|| {
            let block_nr = 256usize;
            let frame_nr = (DEFAULT_BLOCK_SIZE / DEFAULT_FRAME_SIZE) * block_nr;
            black_box(frame_nr);
        });
    });

    group.finish();
}

/// Benchmark checksum calculations.
fn bench_checksum_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum_calculation");

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

    group.bench_function("tcp_packet_with_checksum", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, 60000, 80)
                .seq(12345)
                .syn()
                .window(65535)
                .build();
            black_box(packet);
        });
    });

    group.bench_function("udp_packet_with_checksum", |b| {
        let payload = b"Test payload for checksum calculation";
        b.iter(|| {
            let packet = UdpPacketBuilder::new(src_ip, dst_ip, 60000, 53)
                .payload(payload)
                .build();
            black_box(packet);
        });
    });

    group.bench_function("icmp_packet_with_checksum", |b| {
        b.iter(|| {
            let packet = IcmpPacketBuilder::new(src_ip, dst_ip)
                .identifier(1234)
                .sequence(1)
                .build();
            black_box(packet);
        });
    });

    group.finish();
}

/// Benchmark packet batch processing simulation.
fn bench_packet_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_batch_processing");

    // Simulate processing a batch of received packets
    let src_ip = Ipv4Addr::new(192, 168, 1, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

    // Create sample packets
    let packets: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            TcpPacketBuilder::new(src_ip, dst_ip, 80 + (i % 10) as u16, 60000)
                .seq(i as u32)
                .syn()
                .ack_flag()
                .window(65535)
                .build()
        })
        .collect();

    group.throughput(Throughput::Elements(100));
    group.bench_function("process_batch_100_packets", |b| {
        b.iter(|| {
            let mut open_count = 0;
            let mut closed_count = 0;
            let mut filtered_count = 0;

            for packet in &packets {
                if let Some((flags, _seq, _ack, _src_port)) = parse_tcp_response(packet) {
                    let syn_received = (flags & 0x02) != 0;
                    let ack_received = (flags & 0x10) != 0;
                    let rst_received = (flags & 0x04) != 0;

                    if syn_received && ack_received {
                        open_count += 1;
                    } else if rst_received {
                        closed_count += 1;
                    } else {
                        filtered_count += 1;
                    }
                }
            }

            black_box((open_count, closed_count, filtered_count));
        });
    });

    group.finish();
}

criterion_group!(
    packet_benches,
    bench_tcp_packet_parsing,
    bench_tcp_options_parsing,
    bench_udp_packet_parsing,
    bench_icmp_packet_parsing,
    bench_arp_packet_parsing,
    bench_packet_buffer,
    bench_packet_construction_throughput,
    bench_packet_mmap_config,
    bench_checksum_calculation,
    bench_packet_batch_processing
);

criterion_main!(packet_benches);
