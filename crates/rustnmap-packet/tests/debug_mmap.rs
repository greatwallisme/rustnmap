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

// Debug test for PACKET_MMAP
use rustnmap_packet::{MmapPacketEngine, RingConfig};

#[test]
fn debug_mmap_creation() {
    let if_name = "ens33";
    let config = RingConfig::new(4096, 1, 512);

    println!("Testing MmapPacketEngine::new() with minimal config...");
    println!("Interface: {if_name}");
    println!(
        "Config: block_size={}, block_nr={}, frame_size={}",
        config.block_size, config.block_nr, config.frame_size
    );

    match MmapPacketEngine::new(if_name, config) {
        Ok(_engine) => {
            println!("✓ MmapPacketEngine created successfully!");
        }
        Err(e) => {
            println!("✗ MmapPacketEngine::new() failed:");
            println!("  Error: {e:?}");
            println!("  Display: {e}");

            // Check for specific errors
            let err_str = format!("{e:?}");
            if err_str.contains("22")
                || err_str.contains("EINVAL")
                || err_str.contains("InvalidInput")
            {
                println!("  Contains errno=22 (EINVAL) indication");
            }
            if err_str.contains("RxRing") {
                println!("  Error from PACKET_RX_RING setup");
            }
        }
    }
}
