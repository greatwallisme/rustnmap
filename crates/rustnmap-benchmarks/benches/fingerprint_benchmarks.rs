//! Fingerprinting performance benchmarks for `RustNmap`.
//!
//! This module benchmarks OS detection probe generation, service detection
//! matching speed, and database loading performance.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rustnmap_common::Ipv4Addr;
use rustnmap_fingerprint::os::{
    database::OsFamily, EcnFingerprint, FingerprintDatabase, IpIdSeqClass, IsnClass,
    OpsFingerprint, OsFingerprint, OsMatch, SeqFingerprint,
};
use rustnmap_fingerprint::service::ProbeDatabase;
use rustnmap_net::raw_socket::TcpPacketBuilder;
use std::hint::black_box;

/// Benchmark OS detection probe generation.
///
/// OS detection requires sending specially crafted TCP probes
/// to analyze the target's TCP/IP stack behavior.
fn bench_os_probe_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("os_probe_generation");

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

    // T1-T7 probes are the standard Nmap OS detection probes
    group.throughput(Throughput::Elements(7));
    group.bench_function("generate_t1_t7_probes", |b| {
        #[allow(clippy::vec_init_then_push)]
        b.iter(|| {
            let mut packets = Vec::with_capacity(7);

            // T1: Standard SYN packet
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 80)
                    .seq(0)
                    .syn()
                    .window(65535)
                    .options(&[0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x00])
                    .build(),
            );

            // T2: NULL packet with same options
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 80)
                    .seq(0)
                    .window(65535)
                    .options(&[0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x00])
                    .build(),
            );

            // T3: SYN-FIN-URG-PSH
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 80)
                    .seq(0)
                    .syn()
                    .fin()
                    .psh()
                    .urg()
                    .window(65535)
                    .options(&[0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x00])
                    .build(),
            );

            // T4: ACK with window 1024
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 80)
                    .seq(0)
                    .ack_flag()
                    .window(1024)
                    .build(),
            );

            // T5: SYN to closed port
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 81)
                    .seq(0)
                    .syn()
                    .window(65535)
                    .build(),
            );

            // T6: ACK to closed port
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 81)
                    .seq(0)
                    .ack_flag()
                    .window(65535)
                    .build(),
            );

            // T7: FIN-PSH-URG to closed port
            packets.push(
                TcpPacketBuilder::new(src_ip, dst_ip, 60000, 81)
                    .seq(0)
                    .fin()
                    .psh()
                    .urg()
                    .window(65535)
                    .build(),
            );

            black_box(packets);
        });
    });

    // Individual probe generation
    group.throughput(Throughput::Elements(1));
    group.bench_function("generate_single_probe", |b| {
        b.iter(|| {
            let packet = TcpPacketBuilder::new(src_ip, dst_ip, 60000, 80)
                .seq(0)
                .syn()
                .window(65535)
                .options(&[0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x00])
                .build();
            black_box(packet);
        });
    });

    group.finish();
}

/// Benchmark OS fingerprint construction.
fn bench_os_fingerprint_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("os_fingerprint_construction");

    group.bench_function("create_empty_fingerprint", |b| {
        b.iter(|| {
            let fp = OsFingerprint::new();
            black_box(fp);
        });
    });

    group.bench_function("create_fingerprint_with_seq", |b| {
        b.iter(|| {
            let mut fp = OsFingerprint::new();
            fp.seq = Some(SeqFingerprint {
                class: IsnClass::Random,
                timestamp: true,
                ts_val: 0xA,
                ts_val: 0xA,
                gcd: 1,
                isr: 0,
                sp: 0,
                ti: IpIdSeqClass::Random,
                ci: IpIdSeqClass::Random,
                ii: IpIdSeqClass::Random,
                ss: 0,
                timestamps: vec![1, 2, 3, 4, 5, 6],
            });
            black_box(fp);
        });
    });

    group.bench_function("create_fingerprint_with_ops", |b| {
        b.iter(|| {
            let mut fp = OsFingerprint::new();
            fp.ops.insert(
                "T1".to_string(),
                OpsFingerprint {
                    mss: Some(1460),
                    wscale: Some(7),
                    sack: true,
                    timestamp: true,
                    nop_count: 2,
                    eol: false,
                },
            );
            black_box(fp);
        });
    });

    group.finish();
}

/// Benchmark OS fingerprint database operations.
fn bench_os_fingerprint_database(c: &mut Criterion) {
    let mut group = c.benchmark_group("os_fingerprint_database");

    group.bench_function("create_empty_database", |b| {
        b.iter(|| {
            let db = FingerprintDatabase::empty();
            black_box(db);
        });
    });

    // Create a database with some test fingerprints
    let db = create_test_os_database();

    group.bench_function("find_matches_empty_fingerprint", |b| {
        let fp = OsFingerprint::new();
        b.iter(|| {
            let matches = db.find_matches(&fp);
            black_box(matches);
        });
    });

    group.bench_function("find_matches_with_seq", |b| {
        let mut fp = OsFingerprint::new();
        fp.seq = Some(SeqFingerprint {
            class: IsnClass::Random,
            timestamp: true,
            ts_val: 0xA,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Random,
            ci: IpIdSeqClass::Random,
            ii: IpIdSeqClass::Random,
            ss: 0,
            timestamps: vec![1, 2, 3, 4, 5, 6],
        });
        b.iter(|| {
            let matches = db.find_matches(&fp);
            black_box(matches);
        });
    });

    group.finish();
}

/// Benchmark service probe database parsing.
fn bench_service_probe_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("service_probe_parsing");

    group.bench_function("create_empty_probe_database", |b| {
        b.iter(|| {
            let db = ProbeDatabase::empty();
            black_box(db);
        });
    });

    // Sample service probe database content
    let sample_db = r"
# Test service probe database
Probe TCP GenericLines q|\r\n\r\n|
rarity 1
Ports 1-65535
Match ssh m|^SSH-([\d.]+)| p/OpenSSH/ v/$1/

Probe TCP HTTP q|GET / HTTP/1.0\r\n\r\n|
rarity 3
Ports 80,8080
Match http m|^Server: ([\w/]+)| p/$1/

Probe TCP FTP q|QUIT\r\n|
rarity 1
Ports 21
Match ftp m|^220 ([\w\s]+)| p/$1/
";

    group.bench_function("parse_small_database", |b| {
        b.iter(|| {
            let db = ProbeDatabase::parse(black_box(sample_db)).unwrap();
            black_box(db);
        });
    });

    group.finish();
}

/// Benchmark service detection matching.
fn bench_service_detection_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("service_detection_matching");

    // Create a probe database with match rules
    let db_content = r"
Probe TCP GenericLines q|\r\n\r\n|
rarity 1
Ports 1-65535
Match ssh m|^SSH-([\d.]+)-OpenSSH_([\w.]+)| p/OpenSSH/ v/$2/
Match ssh m|^SSH-([\d.]+)| p/SSH/
Match http m|^HTTP/1\.[01] \d{3}| p/HTTP/
Match ftp m|^220 .*FTP| p/FTP/
Match smtp m|^220 .*SMTP| p/SMTP/
";

    let db = ProbeDatabase::parse(db_content).unwrap();

    group.bench_function("match_ssh_response", |b| {
        let response = b"SSH-2.0-OpenSSH_8.9p1\r\n";
        b.iter(|| {
            let probes = db.probes_for_port(22);
            for probe in probes {
                for match_rule in &probe.matches {
                    if match_rule.pattern.contains("SSH") {
                        black_box(match_rule);
                    }
                }
            }
            black_box(response);
        });
    });

    group.bench_function("match_http_response", |b| {
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
        b.iter(|| {
            let probes = db.probes_for_port(80);
            for probe in probes {
                for match_rule in &probe.matches {
                    if match_rule.pattern.contains("HTTP") {
                        black_box(match_rule);
                    }
                }
            }
            black_box(response);
        });
    });

    group.bench_function("probe_lookup_by_port", |b| {
        b.iter(|| {
            for port in [22, 80, 443, 21, 25] {
                let probes = db.probes_for_port(port);
                black_box(probes);
            }
        });
    });

    group.finish();
}

/// Benchmark fingerprint comparison operations.
fn bench_fingerprint_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("fingerprint_comparison");

    group.bench_function("compare_seq_fingerprints_same", |b| {
        let seq1 = SeqFingerprint {
            class: IsnClass::Random,
            timestamp: true,
            ts_val: 0xA,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Random,
            ci: IpIdSeqClass::Random,
            ii: IpIdSeqClass::Random,
            ss: 0,
            timestamps: vec![1, 2, 3, 4, 5, 6],
        };
        let seq2 = seq1.clone();

        b.iter(|| {
            let same = seq1.class == seq2.class;
            black_box(same);
        });
    });

    group.bench_function("compare_seq_fingerprints_different", |b| {
        let seq1 = SeqFingerprint {
            class: IsnClass::Random,
            timestamp: true,
            ts_val: 0xA,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Random,
            ci: IpIdSeqClass::Random,
            ii: IpIdSeqClass::Random,
            ss: 0,
            timestamps: vec![1, 2, 3, 4, 5, 6],
        };
        let seq2 = SeqFingerprint {
            class: IsnClass::Incremental { increment: 1 },
            timestamp: false,
            ts_val: 0,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Incremental,
            ci: IpIdSeqClass::Incremental,
            ii: IpIdSeqClass::Incremental,
            ss: 0,
            timestamps: vec![],
        };

        b.iter(|| {
            let same = seq1.class == seq2.class;
            black_box(same);
        });
    });

    group.bench_function("compare_ops_fingerprints", |b| {
        let ops1 = OpsFingerprint {
            mss: Some(1460),
            wscale: Some(7),
            sack: true,
            timestamp: true,
            nop_count: 2,
            eol: false,
        };
        let ops2 = ops1.clone();

        b.iter(|| {
            let mss_same = ops1.mss == ops2.mss;
            let wscale_same = ops1.wscale == ops2.wscale;
            let sack_same = ops1.sack == ops2.sack;
            black_box((mss_same, wscale_same, sack_same));
        });
    });

    group.finish();
}

/// Benchmark ECN fingerprint operations.
fn bench_ecn_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecn_fingerprint");

    group.bench_function("create_ecn_fingerprint", |b| {
        b.iter(|| {
            let ecn = EcnFingerprint {
                ece: true,
                cwr: true,
                df: true,
                tos: 0x02,
            };
            black_box(ecn);
        });
    });

    group.bench_function("compare_ecn_fingerprints", |b| {
        let ecn1 = EcnFingerprint {
            ece: true,
            cwr: true,
            df: true,
            tos: 0x02,
        };
        let ecn2 = EcnFingerprint {
            ece: false,
            cwr: true,
            df: true,
            tos: 0x00,
        };

        b.iter(|| {
            let ece_diff = ecn1.ece != ecn2.ece;
            let cwr_diff = ecn1.cwr != ecn2.cwr;
            let df_diff = ecn1.df != ecn2.df;
            black_box((ece_diff, cwr_diff, df_diff));
        });
    });

    group.finish();
}

/// Benchmark OS match result creation.
fn bench_os_match_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("os_match_creation");

    group.bench_function("create_os_match", |b| {
        b.iter(|| {
            let os_match = OsMatch {
                name: "Linux 5.4".to_string(),
                family: OsFamily::Linux,
                vendor: Some("Linux".to_string()),
                generation: Some("5.4".to_string()),
                device_type: Some("general purpose".to_string()),
                cpe: Some("cpe:/o:linux:linux_kernel:5.4".to_string()),
                accuracy: 98,
            };
            black_box(os_match);
        });
    });

    group.finish();
}

/// Helper function to create a test OS fingerprint database.
fn create_test_os_database() -> FingerprintDatabase {
    // For benchmarking, we create an empty database
    // In real usage, this would be loaded from nmap-os-db
    FingerprintDatabase::empty()
}

criterion_group!(
    fingerprint_benches,
    bench_os_probe_generation,
    bench_os_fingerprint_construction,
    bench_os_fingerprint_database,
    bench_service_probe_parsing,
    bench_service_detection_matching,
    bench_fingerprint_comparison,
    bench_ecn_fingerprint,
    bench_os_match_creation
);

criterion_main!(fingerprint_benches);
