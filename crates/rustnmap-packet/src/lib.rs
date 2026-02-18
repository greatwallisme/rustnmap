//! Zero-copy packet engine using `PACKET_MMAP` V3 for `RustNmap`.
//!
//! This crate provides high-performance packet I/O using Linux `PACKET_MMAP`
//! interface for zero-copy packet access.

#![warn(missing_docs)]

use bytes::Bytes;

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
///
/// Uses `bytes::Bytes` for zero-copy reference counting, allowing
/// efficient sharing of packet data across threads without copying.
#[derive(Debug, Clone)]
pub struct PacketBuffer {
    /// Zero-copy packet data.
    data: Bytes,
}

impl PacketBuffer {
    /// Creates a new empty packet buffer.
    #[must_use]
    pub const fn empty() -> Self {
        Self { data: Bytes::new() }
    }

    /// Creates a new packet buffer from existing data.
    ///
    /// # Arguments
    ///
    /// * `data` - Packet data to wrap
    #[must_use]
    pub fn from_data(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }

    /// Creates a new packet buffer with allocated space.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity in bytes
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Bytes::from(vec![0u8; capacity]),
        }
    }

    /// Returns true if this buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the length of this buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns the packet data as a byte slice.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the packet data as Bytes (zero-copy).
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.data.clone()
    }

    /// Returns the packet data as a mutable vector (consumes self).
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.data = Bytes::new();
    }

    /// Resizes the buffer to hold `new_len` bytes.
    ///
    /// # Arguments
    ///
    /// * `new_len` - New length in bytes
    pub fn resize(&mut self, new_len: usize) {
        let mut vec = self.data.to_vec();
        vec.resize(new_len, 0);
        self.data = Bytes::from(vec);
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<u8>> for PacketBuffer {
    fn from(vec: Vec<u8>) -> Self {
        Self::from_data(vec)
    }
}

impl From<&[u8]> for PacketBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::from_data(slice.to_vec())
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

    #[test]
    fn test_packet_buffer_from_data() {
        let data = vec![1u8, 2, 3, 4, 5];
        let buf = PacketBuffer::from_data(data.clone());
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.data(), &data);
    }

    #[test]
    fn test_packet_buffer_with_capacity() {
        let buf = PacketBuffer::with_capacity(1024);
        assert_eq!(buf.len(), 1024);
        assert!(buf.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_packet_buffer_clear() {
        let mut buf = PacketBuffer::with_capacity(100);
        assert_eq!(buf.len(), 100);
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_packet_buffer_resize() {
        let mut buf = PacketBuffer::empty();
        buf.resize(50);
        assert_eq!(buf.len(), 50);
        buf.resize(100);
        assert_eq!(buf.len(), 100);
        buf.resize(25);
        assert_eq!(buf.len(), 25);
    }

    #[test]
    fn test_packet_buffer_to_bytes() {
        let data = vec![1u8, 2, 3];
        let buf = PacketBuffer::from_data(data.clone());
        let bytes = buf.to_bytes();
        assert_eq!(&bytes[..], &data);
    }

    #[test]
    fn test_packet_buffer_into_vec() {
        let data = vec![1u8, 2, 3];
        let buf = PacketBuffer::from_data(data.clone());
        let vec = buf.into_vec();
        assert_eq!(&vec, &data);
    }
}
