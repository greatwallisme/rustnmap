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

//! Linux system call wrappers for PACKET_MMAP V2
//!
//! This module provides low-level system call wrappers and TPACKET_V2 structures
//! for the zero-copy packet capture.

// Rust guideline compliant 2026-03-05

mod if_packet;
mod tpacket;

pub use if_packet::*;
pub use tpacket::*;
