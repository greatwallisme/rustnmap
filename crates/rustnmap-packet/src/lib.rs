//! Zero-copy packet engine using `PACKET_MMAP` V3 for `RustNmap`.
//!
//! This crate provides high-performance packet I/O using Linux's `PACKET_MMAP`
//! interface for zero-copy packet access.

#![warn(missing_docs)]

/// Buffer size for `PACKET_MMAP` ring buffer (in bytes).
///
/// This value is set to 4MiB, which is a reasonable default for
/// high-throughput scanning without excessive memory usage.
pub const DEFAULT_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Block size for `PACKET_MMAP` (in bytes).
///
/// Must be a power of two and aligned to system page size.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Frame size for `PACKET_MMAP` (in bytes).
///
/// Set to accommodate maximum jumbo frames plus headers.
pub const DEFAULT_FRAME_SIZE: usize = 16384;

/// Number of blocks in the ring buffer.
pub const DEFAULT_BLOCK_NR: usize = 256;

/// Number of frames per block.
pub const DEFAULT_FRAME_NR: usize = DEFAULT_BLOCK_SIZE / DEFAULT_FRAME_SIZE * DEFAULT_BLOCK_NR;

/// Packet buffer for zero-copy I/O.
#[derive(Debug)]
pub struct PacketBuffer {
    /// Length of valid data.
    length: usize,
}

impl PacketBuffer {
    /// Creates a new empty packet buffer.
    #[must_use]
    pub const fn empty() -> Self {
        Self { length: 0 }
    }

    /// Returns true if this buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the length of this buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_buffer_empty() {
        let buf = PacketBuffer::empty();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_packet_buffer_default() {
        let buf = PacketBuffer::default();
        assert!(buf.is_empty());
    }
}
