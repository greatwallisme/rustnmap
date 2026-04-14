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

//! Command-line interface for `RustNmap` network scanner.
//!
//! This crate provides the main `rustnmap` binary that integrates
//! all scanning modules into a unified Nmap-compatible CLI.

pub mod args;
pub mod cli;
pub mod embedded;
pub mod help;

// Re-export main types
pub use args::{Args, ScanType};
