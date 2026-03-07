//! Zero-copy packet engine using `PACKET_MMAP` V2 for `RustNmap`.
//!
//! This crate provides high-performance packet I/O using Linux `PACKET_MMAP`
//! interface for zero-copy packet access, with a `recvfrom`-based fallback.
//!
//! # Architecture
//!
//! The primary engine uses Linux's `PACKET_MMAP` V2 interface for zero-copy packet
//! capture and transmission. This provides significant performance benefits
//! over traditional socket-based approaches:
//!
//! - **Zero-copy receive**: Packets are accessed directly from kernel memory
//! - **Zero-copy send**: Packets are written directly to kernel ring buffers
//! - **Batch processing**: Multiple packets can be sent/received in a single syscall
//! - **BPF filtering**: Kernel-space filtering reduces overhead
//!
//! V2 is chosen over V3 for stability (V3 has bugs in kernels < 3.19).
//!
//! # Fallback Engine
//!
//! When `PACKET_MMAP` V2 is unavailable, `RecvfromPacketEngine` provides a
//! fallback using the traditional `recvfrom()` system call. This engine:
//!
//! - Works on all systems without special requirements
//! - Has higher CPU usage and lower throughput
//! - Uses a simpler synchronous API
//!
//! # Requirements
//!
//! - Linux kernel 3.2+ (for `TPACKET_V2` support)
//! - Root privileges or `CAP_NET_RAW` capability
//! - `x86_64` architecture
//!
//! # Example
//!
//! ```rust,ignore
//! use rustnmap_packet::{PacketEngine, RingConfig, PacketBuffer};
//!
//! async fn capture_packets<E: PacketEngine>(engine: &mut E) -> Result<(), rustnmap_packet::PacketError> {
//!     engine.start().await?;
//!
//!     while let Some(packet) = engine.recv().await? {
//!         // Process packet: packet.len() bytes available
//!         let _len = packet.len();
//!     }
//!
//!     engine.stop().await
//! }
//! ```

#![warn(missing_docs)]

use libc::{c_int, c_ushort};

// ============================================================================
// Module declarations
// ============================================================================

/// Linux system call wrappers and TPACKET_V2 structures.
pub mod sys;

/// Error types for packet engine operations.
mod error;

/// Packet engine trait and core types.
mod engine;

/// PACKET_MMAP V2 ring buffer implementation.
mod mmap;

/// Async packet engine with Tokio integration.
mod async_engine;

/// Packet stream implementation.
mod stream;

/// recvfrom-based fallback packet engine.
mod recvfrom;

/// BPF (Berkeley Packet Filter) utilities.
pub mod bpf;

/// Zero-copy packet buffer implementation.
pub mod zero_copy;

// ============================================================================
// Public re-exports
// ============================================================================

#[doc(inline)]
pub use crate::async_engine::AsyncPacketEngine;
#[doc(inline)]
pub use crate::bpf::{BpfFilter, BpfInstruction};
#[doc(inline)]
pub use crate::engine::{EngineStats, PacketBuffer, PacketEngine, RingConfig};
#[doc(inline)]
pub use crate::error::{PacketError, Result};
#[doc(inline)]
pub use crate::mmap::MmapPacketEngine;
#[doc(inline)]
pub use crate::recvfrom::RecvfromPacketEngine;
#[doc(inline)]
pub use crate::stream::PacketStream;
#[doc(inline)]
pub use crate::zero_copy::ZeroCopyPacket;

// ============================================================================
// Constants
// ============================================================================

/// Buffer size for `PACKET_MMAP` ring buffer (in bytes).
///
/// This value is set to 4MiB, which is a reasonable default for
/// high-throughput scanning without excessive memory usage.
pub const DEFAULT_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Block size for `PACKET_MMAP` (in bytes).
///
/// Must be a power of two and aligned to system page size.
pub const DEFAULT_BLOCK_SIZE: usize = 65536;

/// Frame size for `PACKET_MMAP` (in bytes).
///
/// Set to accommodate maximum jumbo frames plus headers.
pub const DEFAULT_FRAME_SIZE: usize = 4096;

/// Number of blocks in the ring buffer.
pub const DEFAULT_BLOCK_NR: usize = 256;

/// Number of frames per block.
pub const DEFAULT_FRAME_NR: usize = DEFAULT_BLOCK_SIZE / DEFAULT_FRAME_SIZE * DEFAULT_BLOCK_NR;

/// Ethernet protocol for all traffic.
pub const ETH_P_ALL: c_ushort = 0x0003;

/// Packet socket version V3.
pub const TPACKET_V3: c_int = 3;

/// `TPACKET_STATUS_KERNEL`: Kernel owns the buffer.
pub const TP_STATUS_KERNEL: u32 = 0;

/// `TPACKET_STATUS_USER`: Userspace owns the buffer.
pub const TP_STATUS_USER: u32 = 1 << 0;

/// `TPACKET_STATUS_COPY`: Kernel is currently copying data to the buffer.
pub const TP_STATUS_COPY: u32 = 1 << 1;
/// `TPACKET_STATUS_LOSING`: Packets are being dropped because the buffer is full.
pub const TP_STATUS_LOSING: u32 = 1 << 2;
/// `TPACKET_STATUS_CSUMNOTREADY`: Checksum is not yet calculated.
pub const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;
/// `TPACKET_STATUS_VLAN_VALID`: VLAN information is valid.
pub const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
/// `TPACKET_STATUS_VLAN_TPID_VALID`: VLAN TPID is valid.
pub const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 4 * 1024 * 1024);
        assert_eq!(DEFAULT_BLOCK_SIZE, 65536);
        assert_eq!(DEFAULT_FRAME_SIZE, 4096);
        assert_eq!(DEFAULT_BLOCK_NR, 256);
    }
}
