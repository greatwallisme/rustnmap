//! Core packet engine trait and related types.
//!
//! This module defines the `PacketEngine` trait, which is the primary abstraction
//! for packet capture and transmission. Implementations include:
//! - `MmapPacketEngine`: `TPACKET_V2` ring buffer (zero-copy)
//! - `AsyncPacketEngine`: Tokio async wrapper

// Rust guideline compliant 2026-03-05

use crate::error::PacketError;
use crate::zero_copy::ZeroCopyPacket;
use async_trait::async_trait;
use bytes::Bytes;
use std::time::Instant;

/// Result type for packet engine operations.
pub type Result<T> = std::result::Result<T, PacketError>;

/// Ring buffer configuration for `TPACKET_V2`.
///
/// This struct defines the parameters for the `PACKET_MMAP` ring buffer.
/// The configuration must be validated before use.
///
/// # Example
///
/// ```rust
/// use rustnmap_packet::RingConfig;
///
/// let config = RingConfig::new(65536, 256, 4096)
///     .with_rx(true)
///     .with_frame_timeout(64);
/// config.validate().unwrap();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RingConfig {
    /// Block size in bytes (must be power of two, >= page size).
    pub block_size: u32,

    /// Number of blocks in the ring buffer.
    pub block_nr: u32,

    /// Frame size in bytes (must be >= `TPACKET_ALIGNMENT`).
    pub frame_size: u32,

    /// Frame timeout in milliseconds (for `TPACKET_V2`).
    pub frame_timeout: u32,

    /// Enable receive ring.
    pub enable_rx: bool,

    /// Enable transmit ring.
    pub enable_tx: bool,
}

impl Default for RingConfig {
    fn default() -> Self {
        // Default configuration optimized for high-throughput scanning
        // Based on nmap's defaults
        Self {
            block_size: 65536, // 64 KiB
            block_nr: 256,     // 256 blocks = 16 MiB total
            frame_size: 4096,  // 4 KiB (jumbo frame + headers)
            frame_timeout: 64, // 64ms (nmap default)
            enable_rx: true,
            enable_tx: false,
        }
    }
}

impl RingConfig {
    /// Creates a new ring configuration.
    ///
    /// # Arguments
    ///
    /// * `block_size` - Block size in bytes (must be power of two, >= page size)
    /// * `block_nr` - Number of blocks (must be > 0)
    /// * `frame_size` - Frame size in bytes (must be >= `TPACKET_ALIGNMENT`)
    ///
    /// # Example
    ///
    /// ```
    /// use rustnmap_packet::RingConfig;
    ///
    /// let config = RingConfig::new(131072, 128, 2048);
    /// ```
    #[must_use]
    pub const fn new(block_size: u32, block_nr: u32, frame_size: u32) -> Self {
        Self {
            block_size,
            block_nr,
            frame_size,
            frame_timeout: 64,
            enable_rx: true,
            enable_tx: false,
        }
    }

    /// Sets the frame timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Frame timeout in milliseconds
    #[must_use]
    pub const fn with_frame_timeout(mut self, timeout: u32) -> Self {
        self.frame_timeout = timeout;
        self
    }

    /// Enables or disables receive ring.
    #[must_use]
    pub const fn with_rx(mut self, enable: bool) -> Self {
        self.enable_rx = enable;
        self
    }

    /// Enables or disables transmit ring.
    #[must_use]
    pub const fn with_tx(mut self, enable: bool) -> Self {
        self.enable_tx = enable;
        self
    }

    /// Validates the ring configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `block_size` is not a power of two
    /// - `block_size` is less than page size
    /// - `block_nr` is zero
    /// - `frame_size` is less than `TPACKET_ALIGNMENT`
    /// - `frame_size` is greater than `block_size`
    ///
    /// # Example
    ///
    /// ```
    /// use rustnmap_packet::RingConfig;
    ///
    /// let config = RingConfig::default();
    /// config.validate().unwrap();
    /// ```
    pub fn validate(&self) -> std::result::Result<(), crate::error::PacketError> {
        // block_size must be power of two
        if !self.block_size.is_power_of_two() {
            return Err(PacketError::InvalidConfig(format!(
                "block_size ({}) must be a power of two",
                self.block_size
            )));
        }

        // block_size must be >= page size
        // SAFETY: sysconf returns the system page size, which is always positive
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "page size fits in u32 on all supported platforms"
        )]
        let page_size = page_size as u32;
        if self.block_size < page_size {
            return Err(PacketError::InvalidConfig(format!(
                "block_size ({}) must be >= page size ({})",
                self.block_size, page_size
            )));
        }

        // block_nr must be > 0
        if self.block_nr == 0 {
            return Err(PacketError::InvalidConfig(
                "block_nr must be > 0".to_string(),
            ));
        }

        // frame_size must be >= TPACKET_ALIGNMENT
        #[expect(
            clippy::cast_possible_truncation,
            reason = "TPACKET_ALIGNMENT is a small constant"
        )]
        if self.frame_size < crate::sys::TPACKET_ALIGNMENT as u32 {
            return Err(PacketError::InvalidConfig(format!(
                "frame_size ({}) must be >= TPACKET_ALIGNMENT ({})",
                self.frame_size,
                crate::sys::TPACKET_ALIGNMENT
            )));
        }

        // frame_size must be <= block_size
        if self.frame_size > self.block_size {
            return Err(PacketError::InvalidConfig(format!(
                "frame_size ({}) must be <= block_size ({})",
                self.frame_size, self.block_size
            )));
        }

        Ok(())
    }

    /// Returns the total ring buffer size in bytes.
    #[must_use]
    pub const fn total_size(&self) -> usize {
        self.block_size as usize * self.block_nr as usize
    }

    /// Returns the number of frames per block.
    #[must_use]
    pub const fn frames_per_block(&self) -> usize {
        self.block_size as usize / self.frame_size as usize
    }
}

/// Engine statistics.
///
/// This struct tracks various statistics about packet engine operation.
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    /// Number of packets received.
    pub packets_received: u64,

    /// Number of packets sent.
    pub packets_sent: u64,

    /// Number of packets dropped.
    pub packets_dropped: u64,

    /// Number of bytes received.
    pub bytes_received: u64,

    /// Number of bytes sent.
    pub bytes_sent: u64,

    /// Number of receive errors.
    pub receive_errors: u64,

    /// Number of send errors.
    pub send_errors: u64,
}

impl EngineStats {
    /// Creates a new `EngineStats` with all fields set to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packets_received: 0,
            packets_sent: 0,
            packets_dropped: 0,
            bytes_received: 0,
            bytes_sent: 0,
            receive_errors: 0,
            send_errors: 0,
        }
    }
}

/// Packet buffer for zero-copy I/O.
///
/// Uses `Bytes` for zero-copy reference counting, allowing efficient sharing
/// of packet data across threads without copying.
///
/// # Example
///
/// ```
/// use rustnmap_packet::PacketBuffer;
///
/// // Create from data
/// let data = vec![1u8, 2, 3, 4, 5];
/// let buffer = PacketBuffer::from_data(data);
///
/// // Access packet data
/// assert_eq!(buffer.len(), 5);
/// assert_eq!(buffer.data().as_ref(), &[1, 2, 3, 4, 5]);
/// ```
#[derive(Debug, Clone)]
pub struct PacketBuffer {
    /// Zero-copy packet data.
    data: Bytes,

    /// Timestamp when packet was received.
    timestamp: Instant,

    /// Captured length (may be less than original if truncated).
    captured_len: usize,

    /// Original packet length.
    original_len: usize,

    /// VLAN TCI (if present).
    vlan_tci: Option<u16>,

    /// VLAN TPID (if present).
    vlan_tpid: Option<u16>,
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::empty()
    }
}

impl PacketBuffer {
    /// Creates an empty packet buffer.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            data: Bytes::new(),
            timestamp: Instant::now(),
            captured_len: 0,
            original_len: 0,
            vlan_tci: None,
            vlan_tpid: None,
        }
    }

    /// Creates a packet buffer from raw data.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes
    #[must_use]
    pub fn from_data(data: impl Into<Bytes>) -> Self {
        let bytes = data.into();
        let len = bytes.len();
        Self {
            data: bytes,
            timestamp: Instant::now(),
            captured_len: len,
            original_len: len,
            vlan_tci: None,
            vlan_tpid: None,
        }
    }

    /// Creates a packet buffer with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Buffer capacity in bytes
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Bytes::from(vec![0u8; capacity]),
            timestamp: Instant::now(),
            captured_len: capacity,
            original_len: capacity,
            vlan_tci: None,
            vlan_tpid: None,
        }
    }

    /// Returns the packet data.
    #[must_use]
    pub const fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns the packet length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the captured length.
    #[must_use]
    pub const fn captured_len(&self) -> usize {
        self.captured_len
    }

    /// Returns the original packet length.
    #[must_use]
    pub const fn original_len(&self) -> usize {
        self.original_len
    }

    /// Returns the VLAN TCI if present.
    #[must_use]
    pub const fn vlan_tci(&self) -> Option<u16> {
        self.vlan_tci
    }

    /// Returns the VLAN TPID if present.
    #[must_use]
    pub const fn vlan_tpid(&self) -> Option<u16> {
        self.vlan_tpid
    }

    /// Returns the packet timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> Instant {
        self.timestamp
    }

    /// Converts the buffer to `Bytes`.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        self.data.clone()
    }

    /// Converts the buffer into a `Vec<u8>`.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.data = Bytes::new();
        self.captured_len = 0;
        self.original_len = 0;
        self.vlan_tci = None;
        self.vlan_tpid = None;
    }

    /// Resizes the buffer.
    ///
    /// # Arguments
    ///
    /// * `new_len` - New buffer length
    pub fn resize(&mut self, new_len: usize) {
        if new_len == 0 {
            self.clear();
        } else {
            let mut data = vec![0u8; new_len];
            let copy_len = std::cmp::min(new_len, self.data.len());
            data[..copy_len].copy_from_slice(&self.data[..copy_len]);
            self.data = Bytes::from(data);
            self.captured_len = new_len;
            self.original_len = new_len;
        }
    }

    /// Sets VLAN information.
    ///
    /// # Arguments
    ///
    /// * `tci` - VLAN TCI value
    /// * `tpid` - VLAN TPID value
    pub fn set_vlan(&mut self, tci: u16, tpid: u16) {
        self.vlan_tci = Some(tci);
        self.vlan_tpid = Some(tpid);
    }
}

impl From<Vec<u8>> for PacketBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }
}

impl From<&[u8]> for PacketBuffer {
    fn from(data: &[u8]) -> Self {
        Self::from_data(Bytes::copy_from_slice(data))
    }
}

/// Core packet engine trait.
///
/// This trait defines the interface for packet capture and transmission engines.
/// Implementations can use different strategies (e.g., `PACKET_MMAP`, `recvfrom`).
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_packet::{PacketEngine, RingConfig, AsyncPacketEngine};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let config = RingConfig::default();
///     let mut engine = AsyncPacketEngine::new("eth0", config).await?;
///
///     engine.start().await?;
///
///     while let Some(packet) = engine.recv().await? {
///         let _len = packet.len();
///     }
///
///     engine.stop().await?;
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait PacketEngine: Send + Sync {
    /// Starts the packet engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine cannot be started.
    async fn start(&mut self) -> Result<()>;

    /// Receives a packet (zero-copy).
    ///
    /// Returns a `ZeroCopyPacket` that holds a reference to the engine's
    /// memory-mapped region without copying data. The frame is automatically
    /// released back to the kernel when the packet is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if packet reception fails.
    async fn recv(&mut self) -> Result<Option<ZeroCopyPacket>>;

    /// Sends a packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet data to send
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails.
    async fn send(&self, packet: &[u8]) -> Result<usize>;

    /// Stops the packet engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine cannot be stopped.
    async fn stop(&mut self) -> Result<()>;

    /// Returns engine statistics.
    #[must_use]
    fn stats(&self) -> EngineStats;

    /// Flushes any buffered packets.
    ///
    /// # Errors
    ///
    /// Returns an error if flushing fails.
    fn flush(&self) -> Result<()>;

    /// Sets a BPF filter.
    ///
    /// # Arguments
    ///
    /// * `filter` - BPF filter program
    ///
    /// # Errors
    ///
    /// Returns an error if the filter cannot be set.
    fn set_filter(&self, filter: &libc::sock_fprog) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_config_default() {
        let config = RingConfig::default();
        assert_eq!(config.block_size, 65536);
        assert_eq!(config.block_nr, 256);
        assert_eq!(config.frame_size, 4096);
        assert_eq!(config.frame_timeout, 64);
        assert!(config.enable_rx);
        assert!(!config.enable_tx);
    }

    #[test]
    fn test_ring_config_builder() {
        let config = RingConfig::new(8192, 128, 2048)
            .with_frame_timeout(128)
            .with_rx(true)
            .with_tx(true);
        assert_eq!(config.block_size, 8192);
        assert_eq!(config.block_nr, 128);
        assert_eq!(config.frame_size, 2048);
        assert_eq!(config.frame_timeout, 128);
        assert!(config.enable_rx);
        assert!(config.enable_tx);
    }

    #[test]
    fn test_ring_config_validate() {
        let config = RingConfig::default();
        config.validate().unwrap();

        // Invalid: block_size not power of two
        let config = RingConfig {
            block_size: 65535,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Invalid: block_nr zero
        let config = RingConfig {
            block_nr: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ring_config_total_size() {
        let config = RingConfig::default();
        assert_eq!(config.total_size(), 65536 * 256);
    }

    #[test]
    fn test_ring_config_frames_per_block() {
        let config = RingConfig::default();
        assert_eq!(config.frames_per_block(), 65536 / 4096);
    }

    #[test]
    fn test_engine_stats_default() {
        let stats = EngineStats::default();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_sent, 0);
    }

    #[test]
    fn test_engine_stats_new() {
        let stats = EngineStats::new();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_sent, 0);
    }

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
        assert_eq!(buf.data(), &data[..]);
        assert_eq!(buf.captured_len(), 5);
        assert_eq!(buf.original_len(), 5);
    }

    #[test]
    fn test_packet_buffer_from_vec() {
        let data = vec![1u8, 2, 3, 4, 5];
        let buf = PacketBuffer::from(data.clone());
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.data(), &data[..]);
    }

    #[test]
    fn test_packet_buffer_from_slice() {
        let data = vec![1u8, 2, 3, 4, 5];
        let buf = PacketBuffer::from(data.as_slice());
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.data(), &data[..]);
    }

    #[test]
    fn test_packet_buffer_with_capacity() {
        let buf = PacketBuffer::with_capacity(1024);
        assert_eq!(buf.len(), 1024);
        assert!(buf.data().iter().all(|&b| b == 0));
        assert_eq!(buf.captured_len(), 1024);
        assert_eq!(buf.original_len(), 1024);
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
        assert_eq!(&bytes[..], &data[..]);
    }

    #[test]
    fn test_packet_buffer_into_vec() {
        let data = vec![1u8, 2, 3];
        let buf = PacketBuffer::from(data.clone());
        let vec = buf.into_vec();
        assert_eq!(&vec[..], &data[..]);
    }

    #[test]
    fn test_packet_buffer_vlan() {
        let mut buf = PacketBuffer::empty();
        buf.set_vlan(1, 0x8100);
        assert_eq!(buf.vlan_tci(), Some(1));
        assert_eq!(buf.vlan_tpid(), Some(0x8100));
    }
}
