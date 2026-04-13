# rustnmap-benchmarks

Performance benchmarks for RustNmap.

## Purpose

Criterion-based benchmarks for hot paths: packet processing, scan operations, fingerprint matching, and NSE script execution.

## Benchmarks

| Benchmark | File | Focus |
|-----------|------|-------|
| Scan | `scan_benchmarks.rs` | TCP/UDP packet construction, port iteration |
| Packet | `packet_benchmarks.rs` | Packet processing, ring buffer operations |
| Fingerprint | `fingerprint_benchmarks.rs` | OS/service fingerprint matching |
| NSE | `nse_benchmarks.rs` | Lua script execution performance |

## Running Benchmarks

```bash
# All benchmarks
cargo bench -p rustnmap-benchmarks

# Specific benchmark
cargo bench -p rustnmap-benchmarks -- scan

# Save baseline
cargo bench -- --save-baseline before

# Compare with baseline
cargo bench -- --baseline before
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| criterion | Benchmark framework |
| rustnmap-common | Common types |
| rustnmap-net | Network primitives |
| rustnmap-packet | Packet engine |
| rustnmap-scan | Scan implementations |
| rustnmap-target | Target parsing |
| rustnmap-fingerprint | Fingerprinting |
| rustnmap-nse | Script engine |

## Benchmark Structure

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_function(c: &mut Criterion) {
    c.bench_function("name", |b| {
        b.iter(|| {
            // Code to benchmark
            black_box(operation())
        })
    });
}

criterion_group!(benches, benchmark_function);
criterion_main!(benches);
```

## Profile-Guided Optimization

```bash
# Generate profile data
cargo bench -- --profile-time 60

# Use for PGO build
llvm-profdata merge -o default.profdata *.profraw
```

## Performance Targets

| Operation | Target |
|-----------|--------|
| Packet build | < 1μs |
| Port iteration | > 10M ports/sec |
| Fingerprint match | < 100μs |
| NSE script load | < 10ms per script |
