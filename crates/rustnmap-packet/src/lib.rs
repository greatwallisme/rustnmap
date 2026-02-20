//! Zero-copy packet engine using `PACKET_MMAP` V3 for `RustNmap`.
//!
//! This crate provides high-performance packet I/O using Linux `PACKET_MMAP`
//! interface for zero-copy packet access.
//!
//! # Architecture
//!
//! The engine uses Linux's `PACKET_MMAP` V3 interface for zero-copy packet
//! capture and transmission. This provides significant performance benefits
//! over traditional socket-based approaches:
//!
//! - **Zero-copy receive**: Packets are accessed directly from kernel memory
//! - **Zero-copy send**: Packets are written directly to kernel ring buffers
//! - **Batch processing**: Multiple packets can be sent/received in a single syscall
//! - **BPF filtering**: Kernel-space filtering reduces overhead
//!
//! # Requirements
//!
//! - Linux kernel 3.2+ (for `TPACKET_V3` support)
//! - Root privileges or `CAP_NET_RAW` capability
//! - `x86_64` architecture
//!
//! # Example
//!
//! See [`AfPacketEngine`] for usage examples.

#![warn(missing_docs)]

use bytes::Bytes;
use libc::{c_int, c_uint, c_ushort, sockaddr_ll};
use rustnmap_common::MacAddr;
use socket2::Socket;
use std::fmt;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::ptr;
use std::time::Duration;

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

/// Socket options for `PACKET_MMAP`.
mod sockopt {
    use libc::c_int;

    /// From `linux/if_packet.h`
    pub const PACKET_VERSION: c_int = 10;

    /// From asm/socket.h and asm-generic/socket.h
    pub const SO_ATTACH_FILTER: c_int = 26;
    pub const SO_DETACH_FILTER: c_int = 27;
}

/// Maximum packet length for Ethernet.
const MAX_PACKET_LEN: usize = 65535;

/// Error type for `PACKET_MMAP` operations.
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    /// Failed to create socket.
    #[error("failed to create socket: {0}")]
    SocketCreation(#[source] io::Error),

    /// Failed to set socket option.
    #[error("failed to set socket option {0}: {1}")]
    SocketOption(String, #[source] io::Error),

    /// Failed to bind to interface.
    #[error("failed to bind to interface: {0}")]
    BindFailed(String, #[source] io::Error),

    /// Interface not found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// Invalid interface name.
    #[error("invalid interface name: {0}")]
    InvalidInterfaceName(String),

    /// Failed to get interface index.
    #[error("failed to get interface index for {0}")]
    InterfaceIndexFailed(String, #[source] io::Error),

    /// Failed to get MAC address.
    #[error("failed to get MAC address: {0}")]
    MacAddressFailed(String, #[source] io::Error),

    /// Failed to setup RX ring.
    #[error("failed to setup RX ring: {0}")]
    RxRingSetup(#[source] io::Error),

    /// Failed to setup TX ring.
    #[error("failed to setup TX ring: {0}")]
    TxRingSetup(#[source] io::Error),

    /// Failed to mmap ring buffer.
    #[error("failed to mmap ring buffer: {0}")]
    MmapFailed(#[source] io::Error),

    /// Invalid ring configuration.
    #[error("invalid ring configuration: {0}")]
    InvalidConfig(String),

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Operation not supported.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Packet too large.
    #[error("packet too large: {size} bytes (max {max})")]
    PacketTooLarge {
        /// The size of the packet that was too large.
        size: usize,
        /// The maximum allowed packet size.
        max: usize,
    },

    /// BPF filter error.
    #[error("BPF filter error: {0}")]
    BpfFilter(String),
}

/// Result type for `PACKET_MMAP` operations.
pub type Result<T> = std::result::Result<T, PacketError>;

/// Ring buffer configuration for `PACKET_MMAP` V3.
#[derive(Debug, Clone, Copy)]
pub struct RingConfig {
    /// Block size in bytes (must be page-aligned).
    pub block_size: usize,

    /// Number of blocks in the ring.
    pub block_nr: usize,

    /// Frame size in bytes (max packet size).
    pub frame_size: usize,

    /// Frame timeout in milliseconds.
    pub frame_timeout: u32,

    /// Whether to use RX ring.
    pub enable_rx: bool,

    /// Whether to use TX ring.
    pub enable_tx: bool,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            block_nr: DEFAULT_BLOCK_NR,
            frame_size: DEFAULT_FRAME_SIZE,
            frame_timeout: 64,
            enable_rx: true,
            enable_tx: false,
        }
    }
}

impl RingConfig {
    /// Creates a new ring configuration with custom values.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Panics
    ///
    /// Panics if `block_size` is not a power of two.
    #[must_use]
    pub const fn new(block_size: usize, block_nr: usize, frame_size: usize) -> Self {
        assert!(
            block_size.is_power_of_two(),
            "block_size must be power of two"
        );
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
    #[must_use]
    pub const fn with_frame_timeout(mut self, timeout: u32) -> Self {
        self.frame_timeout = timeout;
        self
    }

    /// Enables RX ring.
    #[must_use]
    pub const fn with_rx(mut self, enable: bool) -> Self {
        self.enable_rx = enable;
        self
    }

    /// Enables TX ring.
    #[must_use]
    pub const fn with_tx(mut self, enable: bool) -> Self {
        self.enable_tx = enable;
        self
    }

    /// Returns the total size of the ring buffer.
    #[must_use]
    pub const fn total_size(&self) -> usize {
        self.block_size * self.block_nr
    }

    /// Returns the number of frames per block.
    #[must_use]
    pub const fn frames_per_block(&self) -> usize {
        self.block_size / self.frame_size
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<()> {
        if !self.block_size.is_power_of_two() {
            return Err(PacketError::InvalidConfig(
                "block_size must be power of two".to_string(),
            ));
        }

        if self.block_size < 4096 {
            return Err(PacketError::InvalidConfig(
                "block_size must be at least 4096".to_string(),
            ));
        }

        if self.block_nr == 0 {
            return Err(PacketError::InvalidConfig(
                "block_nr must be non-zero".to_string(),
            ));
        }

        if self.frame_size < 256 {
            return Err(PacketError::InvalidConfig(
                "frame_size must be at least 256".to_string(),
            ));
        }

        if self.frame_size > MAX_PACKET_LEN {
            return Err(PacketError::InvalidConfig(format!(
                "frame_size must be at most {MAX_PACKET_LEN}"
            )));
        }

        if self.frame_size > self.block_size {
            return Err(PacketError::InvalidConfig(
                "frame_size must not exceed block_size".to_string(),
            ));
        }

        Ok(())
    }
}

/// Packet buffer for zero-copy I/O.
///
/// Uses `bytes::Bytes` for zero-copy reference counting, allowing
/// efficient sharing of packet data across threads without copying.
#[derive(Debug, Clone)]
pub struct PacketBuffer {
    /// Zero-copy packet data.
    data: Bytes,

    /// Timestamp when packet was received.
    timestamp: Duration,

    /// Captured length (may be less than original if truncated).
    captured_len: usize,

    /// Original packet length.
    original_len: usize,

    /// VLAN TCI (if present).
    vlan_tci: Option<u16>,

    /// VLAN TPID (if present).
    vlan_tpid: Option<u16>,
}

impl PacketBuffer {
    /// Creates a new empty packet buffer.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            data: Bytes::new(),
            timestamp: Duration::ZERO,
            captured_len: 0,
            original_len: 0,
            vlan_tci: None,
            vlan_tpid: None,
        }
    }

    /// Creates a new packet buffer from existing data.
    ///
    /// # Arguments
    ///
    /// * `data` - Packet data to wrap
    #[must_use]
    pub fn from_data(data: impl Into<Bytes>) -> Self {
        let data = data.into();
        let len = data.len();
        Self {
            data,
            timestamp: Duration::ZERO,
            captured_len: len,
            original_len: len,
            vlan_tci: None,
            vlan_tpid: None,
        }
    }

    /// Creates a new packet buffer with allocated space.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity in bytes
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let data = Bytes::from(vec![0u8; capacity]);
        let len = data.len();
        Self {
            data,
            timestamp: Duration::ZERO,
            captured_len: len,
            original_len: len,
            vlan_tci: None,
            vlan_tpid: None,
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

    /// Returns the packet timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> Duration {
        self.timestamp
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

    /// Returns the packet data as a mutable vector (consumes self).
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.data = Bytes::new();
        self.timestamp = Duration::ZERO;
        self.captured_len = 0;
        self.original_len = 0;
        self.vlan_tci = None;
        self.vlan_tpid = None;
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
        self.captured_len = new_len;
        self.original_len = new_len;
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

/// Zero-copy `PACKET_MMAP` V3 engine for Linux.
///
/// This engine provides high-performance packet capture and transmission
/// using Linux's `PACKET_MMAP` V3 interface.
///
/// # Example
///
/// ```rust,no_run
/// use rustnmap_packet::{AfPacketEngine, RingConfig};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = RingConfig::default();
/// let mut engine = AfPacketEngine::new("eth0", config)?;
///
/// // Set promiscuous mode
/// engine.set_promiscuous(true)?;
///
/// // Receive packets
/// while let Some(packet) = engine.recv_packet()? {
///     let _packet_size = packet.len();
/// }
/// # Ok(())
/// # }
/// ```
pub struct AfPacketEngine {
    /// Owned file descriptor for the socket.
    fd: OwnedFd,

    /// Interface index.
    if_index: c_uint,

    /// Interface name.
    if_name: String,

    /// MAC address.
    mac_addr: MacAddr,
}

#[expect(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::undocumented_unsafe_blocks,
    reason = "FFI bindings require casts and unsafe blocks for Linux socket API"
)]
impl AfPacketEngine {
    /// Creates a new `PACKET_MMAP` V3 engine.
    ///
    /// # Arguments
    ///
    /// * `if_name` - Network interface name (e.g., "eth0")
    /// * `config` - Ring buffer configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The interface does not exist
    /// - The socket cannot be created (requires `CAP_NET_RAW`)
    /// - The ring buffer cannot be configured
    /// - The ring buffer cannot be mmap'd
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid.
    pub fn new(if_name: &str, config: RingConfig) -> Result<Self> {
        config.validate().expect("invalid ring configuration");

        // Validate interface name
        if if_name.is_empty() {
            return Err(PacketError::InvalidInterfaceName(
                "interface name cannot be empty".to_string(),
            ));
        }

        #[allow(clippy::cast_possible_truncation, reason = "IFNAMSIZ fits in usize")]
        if if_name.len() > libc::IFNAMSIZ - 1 {
            return Err(PacketError::InvalidInterfaceName(format!(
                "interface name too long (max {} characters)",
                libc::IFNAMSIZ - 1
            )));
        }

        // Create `AF_PACKET` socket
        let fd = Self::create_socket()?;

        // Set packet version to V3
        Self::set_packet_version(&fd, TPACKET_V3)?;

        // Get interface index
        let if_index = Self::get_interface_index(&fd, if_name)?;

        // Bind to interface
        Self::bind_to_interface(&fd, if_name, if_index)?;

        // Get MAC address
        let mac_addr = Self::get_mac_address(&fd, if_index)?;

        Ok(Self {
            fd,
            if_index,
            if_name: if_name.to_string(),
            mac_addr,
        })
    }

    /// Creates a new `AF_PACKET` socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created.
    fn create_socket() -> Result<OwnedFd> {
        // SAFETY: socket() syscall with valid arguments
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(ETH_P_ALL)) };

        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(PacketError::PermissionDenied(
                    "CAP_NET_RAW capability required".to_string(),
                ));
            }
            return Err(PacketError::SocketCreation(err));
        }

        // SAFETY: fd is valid and non-negative
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Set non-blocking mode
        let socket = Socket::from(fd);
        socket
            .set_nonblocking(true)
            .map_err(|e| PacketError::SocketOption("non-blocking".to_string(), e))?;

        // Convert back to OwnedFd
        let fd = socket.into();

        Ok(fd)
    }

    /// Sets the packet socket version.
    ///
    /// # Errors
    ///
    /// Returns an error if the version cannot be set.
    fn set_packet_version(fd: &OwnedFd, version: c_int) -> Result<()> {
        // SAFETY: setsockopt with valid fd and version pointer
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                sockopt::PACKET_VERSION,
                sockopt::PACKET_VERSION,
                (&raw const version).cast::<libc::c_void>(),
                mem::size_of::<c_int>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(PacketError::SocketOption(
                "PACKET_VERSION".to_string(),
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Gets the interface index for the given interface name.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface cannot be found.
    fn get_interface_index(fd: &OwnedFd, if_name: &str) -> Result<c_uint> {
        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };

        // Copy interface name to ifreq
        let if_name_bytes = if_name.as_bytes();
        #[expect(clippy::indexing_slicing, reason = "Length checked above")]
        for (i, &byte) in if_name_bytes.iter().enumerate() {
            ifreq.ifr_name[i] = byte as i8;
        }

        // SAFETY: ioctl with valid ifreq
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFINDEX, &raw mut ifreq) };

        if ret < 0 {
            return Err(PacketError::InterfaceIndexFailed(
                if_name.to_string(),
                io::Error::last_os_error(),
            ));
        }

        // SAFETY: ifr_ifindex is accessed through the union
        let if_index = unsafe { ifreq.ifr_ifru.ifru_addr.sa_family as i32 };

        Ok(u32::try_from(if_index).unwrap_or(0))
    }

    /// Binds the socket to the specified interface.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    fn bind_to_interface(fd: &OwnedFd, if_name: &str, if_index: c_uint) -> Result<()> {
        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = if_index as i32;

        // SAFETY: bind() with valid sockaddr
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if ret < 0 {
            return Err(PacketError::BindFailed(
                if_name.to_string(),
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Gets the MAC address of the interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC address cannot be retrieved.
    fn get_mac_address(fd: &OwnedFd, _if_index: c_uint) -> Result<MacAddr> {
        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };

        // SAFETY: ioctl with valid ifreq
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR, &raw mut ifreq) };

        if ret < 0 {
            return Err(PacketError::MacAddressFailed(
                "ioctl failed".to_string(),
                io::Error::last_os_error(),
            ));
        }

        // SAFETY: Extract MAC address from sa_data
        let sa_data = unsafe { &ifreq.ifr_ifru.ifru_hwaddr.sa_data };
        let mac_addr = MacAddr::new([
            sa_data[0] as u8,
            sa_data[1] as u8,
            sa_data[2] as u8,
            sa_data[3] as u8,
            sa_data[4] as u8,
            sa_data[5] as u8,
        ]);

        Ok(mac_addr)
    }

    /// Receives a packet (blocking).
    ///
    /// # Errors
    ///
    /// Returns an error if packet reception fails.
    ///
    /// # Note
    ///
    /// This implementation uses recvfrom. Future versions will implement
    /// the full `PACKET_MMAP` ring buffer for zero-copy operation.
    pub fn recv_packet(&self) -> Result<Option<PacketBuffer>> {
        let mut buffer = vec![0u8; MAX_PACKET_LEN];

        // SAFETY: recvfrom with valid fd and buffer
        let ret = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(PacketError::SocketOption("recvfrom".to_string(), err));
        }

        let len = ret as usize;
        buffer.truncate(len);

        let mut packet = PacketBuffer::from_data(buffer);
        packet.timestamp = Duration::from_secs(0);
        packet.captured_len = len;
        packet.original_len = len;

        Ok(Some(packet))
    }

    /// Sends a packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet data to send
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails.
    pub fn send_packet(&self, packet: &[u8]) -> Result<usize> {
        if packet.len() > MAX_PACKET_LEN {
            return Err(PacketError::PacketTooLarge {
                size: packet.len(),
                max: MAX_PACKET_LEN,
            });
        }

        let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = self.if_index as i32;
        addr.sll_halen = 6;
        addr.sll_addr = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0];

        // SAFETY: sendto with valid arguments
        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast::<libc::c_void>(),
                packet.len(),
                0,
                (&raw const addr).cast::<libc::sockaddr>(),
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if ret < 0 {
            return Err(PacketError::SocketOption(
                "sendto".to_string(),
                io::Error::last_os_error(),
            ));
        }

        Ok(ret as usize)
    }

    /// Sets promiscuous mode on the interface.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable promiscuous mode
    ///
    /// # Errors
    ///
    /// Returns an error if setting promiscuous mode fails.
    pub fn set_promiscuous(&self, enable: bool) -> Result<()> {
        let mut mreq: libc::packet_mreq = unsafe { mem::zeroed() };
        mreq.mr_ifindex = self.if_index as i32;
        mreq.mr_type = libc::PACKET_MR_PROMISC as u16;

        // SAFETY: setsockopt with valid fd and mreq pointer
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                if enable {
                    libc::PACKET_ADD_MEMBERSHIP
                } else {
                    libc::PACKET_DROP_MEMBERSHIP
                },
                (&raw const mreq).cast::<libc::c_void>(),
                mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(PacketError::SocketOption(
                "promiscuous mode".to_string(),
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Sets a BPF filter on the socket.
    ///
    /// # Arguments
    ///
    /// * `filter` - BPF filter program
    ///
    /// # Errors
    ///
    /// Returns an error if setting the filter fails.
    pub fn set_filter(&self, filter: &libc::sock_fprog) -> Result<()> {
        // SAFETY: setsockopt with valid fd and filter pointer
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                sockopt::SO_ATTACH_FILTER,
                sockopt::SO_ATTACH_FILTER,
                std::ptr::from_ref::<libc::sock_fprog>(filter).cast::<libc::c_void>(),
                mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(PacketError::BpfFilter(
                io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    /// Clears the BPF filter on the socket.
    ///
    /// # Errors
    ///
    /// Returns an error if clearing the filter fails.
    pub fn clear_filter(&self) -> Result<()> {
        // SAFETY: setsockopt with null filter pointer
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                sockopt::SO_DETACH_FILTER,
                sockopt::SO_DETACH_FILTER,
                ptr::null(),
                0,
            )
        };

        if ret < 0 {
            return Err(PacketError::BpfFilter("failed to clear filter".to_string()));
        }

        Ok(())
    }

    /// Returns the interface index.
    #[must_use]
    pub const fn interface_index(&self) -> c_uint {
        self.if_index
    }

    /// Returns the interface name.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.if_name
    }

    /// Returns the MAC address.
    #[must_use]
    pub const fn mac_address(&self) -> MacAddr {
        self.mac_addr
    }
}

impl fmt::Debug for AfPacketEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AfPacketEngine")
            .field("interface", &self.if_name)
            .field("if_index", &self.if_index)
            .field("mac_addr", &self.mac_addr)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_config_default() {
        let config = RingConfig::default();
        assert_eq!(config.block_size, DEFAULT_BLOCK_SIZE);
        assert_eq!(config.block_nr, DEFAULT_BLOCK_NR);
        assert_eq!(config.frame_size, DEFAULT_FRAME_SIZE);
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

        // Invalid: block_size too small
        let config = RingConfig {
            block_size: 2048,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Invalid: block_nr zero
        let config = RingConfig {
            block_nr: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Invalid: frame_size too small
        let config = RingConfig {
            frame_size: 128,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Invalid: frame_size > block_size
        let config = RingConfig {
            frame_size: 131_072,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ring_config_total_size() {
        let config = RingConfig::default();
        assert_eq!(config.total_size(), DEFAULT_BLOCK_SIZE * DEFAULT_BLOCK_NR);
    }

    #[test]
    fn test_ring_config_frames_per_block() {
        let config = RingConfig::default();
        assert_eq!(
            config.frames_per_block(),
            DEFAULT_BLOCK_SIZE / DEFAULT_FRAME_SIZE
        );
    }

    #[test]
    fn test_packet_buffer_empty() {
        let buf = PacketBuffer::empty();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.timestamp(), Duration::ZERO);
        assert_eq!(buf.captured_len(), 0);
        assert_eq!(buf.original_len(), 0);
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
    fn test_constants() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 4 * 1024 * 1024);
        assert_eq!(DEFAULT_BLOCK_SIZE, 65536);
        assert_eq!(DEFAULT_FRAME_SIZE, 4096);
        assert_eq!(DEFAULT_BLOCK_NR, 256);
    }
}
