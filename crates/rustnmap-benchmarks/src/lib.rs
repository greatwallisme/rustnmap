//! RustNmap Performance Benchmarks
//!
//! This crate contains comprehensive performance benchmarks for the RustNmap
//! project, measuring scanning performance, packet I/O, fingerprinting, and
//! NSE script execution.
//!
//! ## Running Benchmarks
//!
//! ```bash
//! # Run all benchmarks
//! cargo bench
//!
//! # Run specific benchmark suite
//! cargo bench --bench scan_benchmarks
//! cargo bench --bench packet_benchmarks
//! cargo bench --bench fingerprint_benchmarks
//! cargo bench --bench nse_benchmarks
//!
//! # Run with quick mode (fewer iterations)
//! cargo bench -- --quick
//! ```

// This is a benchmark crate, no public library code needed
