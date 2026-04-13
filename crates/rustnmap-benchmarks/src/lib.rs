// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! `RustNmap` Performance Benchmarks
//!
//! This crate contains comprehensive performance benchmarks for the `RustNmap`
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
