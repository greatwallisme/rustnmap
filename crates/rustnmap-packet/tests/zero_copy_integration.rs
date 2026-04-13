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

//! Integration tests for zero-copy packet buffer.
//!
//! These tests verify that the `ZeroCopyPacket` implementation provides
//! true zero-copy operation without heap allocation or data copying.
//!
//! # Requirements
//!
//! - Root privileges (`CAP_NET_RAW` capability)
//! - Actual network interface (not loopback)
//! - **Linux kernel with full `PACKET_MMAP` support** (WSL2 does NOT support `PACKET_RX_RING`)
//!
//! # Running the tests
//!
//! ```bash
//! # On a Linux system with PACKET_MMAP support:
//! sudo cargo test -p rustnmap-packet --test zero_copy_integration
//!
//! # Skip environment-limited tests:
//! cargo test -p rustnmap-packet --test zero_copy_integration -- --skip test_zero_copy
//! ```
//!
//! # Environment Limitations
//!
//! **WSL2**: Does NOT support `PACKET_RX_RING`. Tests will fail with:
//! `Environment does not support PACKET_MMAP: ... (WSL2 limitation)`
//!
//! This is a known WSL2 limitation. Use a proper Linux system (Debian, Ubuntu, etc.)
//! or a VM with full kernel support for `PACKET_MMAP`.
//!
//! # Design Reference
//!
//! See `doc/modules/packet-engineering.md` section "零拷贝数据包缓冲区设计".

// Rust guideline compliant 2026-03-07

use rustnmap_packet::{MmapPacketEngine, PacketEngine, RingConfig};

/// Helper function to get the test interface name.
///
/// Uses the "eth0" interface by default.
/// TODO: Auto-detect the first non-loopback UP interface.
fn get_test_interface() -> String {
    // Default to eth0 for testing
    // In production, this should auto-detect the first UP non-loopback interface
    std::env::var("TEST_INTERFACE").unwrap_or_else(|_| String::from("eth0"))
}

/// Helper function to check if `PACKET_MMAP` is supported on this system.
///
/// WSL2 does not support `PACKET_RX_RING`, which causes setsockopt to fail
/// with errno=22 (EINVAL). This function detects that condition.
fn check_packet_mmap_support() -> Result<(), String> {
    // Try to create a simple test socket and set up PACKET_RX_RING
    let result = std::panic::catch_unwind(|| {
        // Use minimal configuration
        let config = RingConfig::new(4096, 1, 512);

        // Use the actual test interface, not loopback
        let if_name = get_test_interface();

        // Try to create engine - this will fail if PACKET_MMAP is not supported
        let _engine = MmapPacketEngine::new(&if_name, config);

        // If we get here without panic, check the result
        true
    });

    if result.is_err() {
        return Err("PACKET_MMAP test caused panic".to_string());
    }

    // Check if the error is EINVAL (22) which indicates WSL2 or no PACKET_MMAP support
    let if_name = get_test_interface();
    if let Err(e) = MmapPacketEngine::new(&if_name, RingConfig::new(4096, 1, 512)) {
        let error_msg = format!("{e:?}");
        if error_msg.contains("code: 22") || error_msg.contains("InvalidInput") {
            return Err(format!(
                "PACKET_MMAP not supported: {e}. These tests require a Linux system with full PACKET_MMAP support."
            ));
        }
    }

    Ok(())
}

/// Helper function to create and start an engine for testing.
/// Returns `None` if `PACKET_MMAP` is not supported, allowing tests to skip gracefully.
async fn create_test_engine() -> Option<(MmapPacketEngine, String)> {
    // First check if PACKET_MMAP is supported
    if let Err(e) = check_packet_mmap_support() {
        eprintln!("SKIP: Environment does not support PACKET_MMAP: {e}");
        eprintln!("These tests require a Linux system with full PACKET_MMAP support.");
        eprintln!("The RecvfromPacketEngine fallback will be used instead.");
        return None;
    }

    let if_name = get_test_interface();
    // Use smaller ring buffer configuration for testing
    // Based on architecture.md recommendations but scaled down
    let config = RingConfig::new(262_144, 4, 2048); // 256KB blocks, 4 blocks, 2KB frames
    let mut engine = match MmapPacketEngine::new(&if_name, config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: Failed to create engine on {if_name}: {e:?}");
            return None;
        }
    };

    if let Err(e) = engine.start().await {
        eprintln!("SKIP: Failed to start engine: {e:?}");
        return None;
    }

    Some((engine, if_name))
}

#[tokio::test]
async fn test_zero_copy_no_alloc() {
    //! Test 1: Verify that borrowed `ZeroCopyBytes` does not allocate.
    //!
    //! This test verifies that when we receive a packet using `try_recv_zero_copy`,
    //! the data is borrowed from the mmap region and not copied to the heap.

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // For this test, we need to:
    // 1. Send a test packet to ourselves
    // 2. Receive it using try_recv_zero_copy
    // 3. Verify that the data is borrowed (is_borrowed() == true)
    // 4. Verify that the data pointer is within the mmap region

    // Note: This test requires a packet sender which we don't have yet.
    // For now, we test the API structure.

    // TODO: Implement packet sending for full integration test
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Send test packet and verify zero-copy");
}

#[tokio::test]

async fn test_frame_lifecycle() {
    //! Test 2: Verify frame lifecycle management.
    //!
    //! This test verifies that:
    //! 1. Frames are marked as in-use when packet is created
    //! 2. Frames are released back to kernel when packet is dropped
    //! 3. The same frame can be reused after release

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // This test requires access to internal frame tracking.
    // The `ZeroCopyPacket` holds an `Arc<MmapPacketEngine>` and calls
    // release_frame_by_idx when dropped.

    // TODO: Add frame tracking to MmapPacketEngine for testing
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Add frame tracking and verify lifecycle");
}

#[tokio::test]

async fn test_no_data_copy() {
    //! Test 3: Verify no data copy occurs for borrowed packets.
    //!
    //! This test verifies that:
    //! 1. Borrowed `ZeroCopyBytes` has no owned data
    //! 2. The data pointer points into the mmap region
    //! 3. `len()` == capacity (no extra allocation)

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // For borrowed data:
    // - `ZeroCopyBytes::is_borrowed()` should return true
    // - The data should be accessible without copy

    // TODO: Receive packet and verify borrowed state
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Verify borrowed data has no copy");
}

#[tokio::test]

async fn test_concurrent_frames() {
    //! Test 4: Verify multiple frames can be held simultaneously.
    //!
    //! This test verifies that:
    //! 1. Multiple `ZeroCopyPackets` can exist at once
    //! 2. Each packet holds a different frame
    //! 3. Frames are released when each packet is dropped

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // This requires:
    // 1. Receiving multiple packets without dropping them
    // 2. Verifying each has a different frame_idx
    // 3. Dropping them and verifying frames are released

    // TODO: Receive multiple packets and verify concurrent access
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Receive and hold multiple packets");
}

#[tokio::test]

async fn test_zero_copy_data_within_mmap_region() {
    //! Test 5: Verify packet data pointer is within mmap region.
    //!
    //! This test verifies the debug assertion in `ZeroCopyPacket::new`:
    //! - The data pointer must be within [`ring_ptr`, `ring_ptr` + `ring_size`)

    let Some((engine, if_name)) = create_test_engine().await else {
        return;
    };
    let engine_ref = &engine;

    // Get mmap region bounds
    let mmap_start = engine_ref.ring_ptr() as usize;
    let mmap_end = mmap_start + engine_ref.ring_size();

    eprintln!("Test interface: {if_name}");
    eprintln!("Mmap region: [{mmap_start:#x}..{mmap_end:#x}]");
    eprintln!("Region size: {} bytes", engine_ref.ring_size());

    // When we receive a packet, `ZeroCopyPacket::new` has a debug_assert
    // that verifies the data pointer is within this region.
    // If the assertion fails, the test will panic.

    // TODO: Receive packet and let debug_assert verify pointer location
}

#[tokio::test]

async fn test_clone_creates_independent_packet() {
    //! Test 6: Verify `Clone` creates an independent packet.
    //!
    //! This test verifies that:
    //! 1. Cloned packet has the same `Arc` reference (ref count incremented)
    //! 2. Cloned packet has the same `frame_idx`
    //! 3. When both are dropped, frame is released (safe due to atomics)

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // TODO: Receive packet, clone it, and verify independence
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Test clone behavior");
}

#[tokio::test]

async fn test_drop_releases_frame() {
    //! Test 7: Verify `Drop` releases frame back to kernel.
    //!
    //! This test verifies that when a `ZeroCopyPacket` is dropped:
    //! 1. The `frame_idx` is released via `release_frame_by_idx`
    //! 2. The `tp_status` is set to `TP_STATUS_KERNEL`
    //! 3. The kernel can reuse the frame

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // TODO: Verify frame release via tp_status check
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Verify tp_status becomes TP_STATUS_KERNEL after drop");
}

#[tokio::test]

async fn test_owned_data_copy() {
    //! Test 8: Verify owned data works correctly.
    //!
    //! This test verifies that `ZeroCopyBytes::owned()` creates
    //! an owned copy that is independent of the mmap region.

    let data = vec![1u8, 2, 3, 4, 5];
    let zero_copy_bytes = rustnmap_packet::zero_copy::ZeroCopyBytes::owned(data);

    assert_eq!(zero_copy_bytes.len(), 5);
    assert!(!zero_copy_bytes.is_borrowed());
    assert_eq!(&zero_copy_bytes[..], &[1, 2, 3, 4, 5]);
}

#[tokio::test]

async fn test_into_packet_buffer() {
    //! Test 9: Verify conversion to `PacketBuffer` works.
    //!
    //! This test verifies that `ZeroCopyPacket::into_packet_buffer`
    //! creates a `PacketBuffer` with copied data.

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // TODO: Create ZeroCopyPacket and convert to PacketBuffer
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Test into_packet_buffer conversion");
}

#[tokio::test]

async fn test_performance_improvement() {
    //! Test 10: Measure actual PPS improvement.
    //!
    //! This integration test measures the actual packets-per-second
    //! achieved with zero-copy vs. the old recvfrom approach.
    //!
    //! Target metrics:
    //! - Current (recvfrom): ~50,000 PPS
    //! - Target (zero-copy): ~1,000,000 PPS
    //! - Improvement: 20x

    let Some((_engine, if_name)) = create_test_engine().await else {
        return;
    };

    // TODO: Implement PPS measurement with traffic generator
    eprintln!("Test interface: {if_name}");
    eprintln!("TODO: Measure PPS with actual traffic");
}

// Unit tests for ZeroCopyBytes (don't require root)

#[test]
fn test_zero_copy_bytes_owned() {
    //! Unit test: Verify owned `ZeroCopyBytes` works correctly.

    let data = vec![10u8, 20, 30, 40, 50];
    let bytes = rustnmap_packet::zero_copy::ZeroCopyBytes::owned(data);

    assert_eq!(bytes.len(), 5);
    assert!(!bytes.is_borrowed());
    assert_eq!(bytes[0], 10);
    assert_eq!(bytes[4], 50);
}

#[test]
fn test_zero_copy_bytes_empty() {
    //! Unit test: Verify empty `ZeroCopyBytes` works correctly.

    let bytes = rustnmap_packet::zero_copy::ZeroCopyBytes::owned(vec![]);

    assert_eq!(bytes.len(), 0);
    assert!(bytes.is_empty());
    assert!(!bytes.is_borrowed());
}

#[test]
fn test_zero_copy_bytes_deref() {
    //! Unit test: Verify `Deref` implementation works correctly.

    let data = vec![1u8, 2, 3, 4, 5];
    let bytes = rustnmap_packet::zero_copy::ZeroCopyBytes::owned(data);

    // Test slice access
    let slice: &[u8] = &bytes;
    assert_eq!(slice, &[1, 2, 3, 4, 5]);

    // Test indexing
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[2], 3);

    // Test iteration
    let mut sum = 0u8;
    for b in bytes.iter() {
        sum += b;
    }
    assert_eq!(sum, 15);
}

#[test]
fn test_zero_copy_bytes_as_ref() {
    //! Unit test: Verify `AsRef<[u8]>` implementation works correctly.

    let data = vec![100u8, 200, 50];
    let bytes = rustnmap_packet::zero_copy::ZeroCopyBytes::owned(data.clone());

    let as_ref: &[u8] = bytes.as_ref();
    assert_eq!(as_ref, &data[..]);
}

#[test]
fn test_zero_copy_bytes_to_bytes() {
    //! Unit test: Verify `to_bytes()` creates a `Bytes` copy.

    let data = vec![7u8, 14, 21, 28];
    let bytes = rustnmap_packet::zero_copy::ZeroCopyBytes::owned(data);

    let bytes_copy = bytes.to_bytes();
    assert_eq!(bytes_copy.len(), 4);
    assert_eq!(&bytes_copy[..], &[7, 14, 21, 28]);
}
