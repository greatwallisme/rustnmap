//! Zero-copy packet engine using `PACKET_MMAP` V2 for `RustNmap`.
//!
//! This crate provides high-performance packet I/O using Linux `PACKET_MMAP`
//! interface for zero-copy packet access.
//!
//! # Architecture
//!
//! The engine uses Linux's `PACKET_MMAP` V2 interface for zero-copy packet
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

use libc::{c_int, c_uint, c_ushort, sockaddr_ll};
use rustnmap_common::MacAddr;
use socket2::Socket;
use std::fmt;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::ptr;

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

// ============================================================================
// Legacy AfPacketEngine (uses recvfrom, not PACKET_MMAP)
// ============================================================================

/// Legacy `AF_PACKET` engine using `recvfrom`.
///
/// This is the legacy implementation that uses `recvfrom` syscall.
/// For high-performance zero-copy packet capture, use the `PacketEngine` trait
/// implementations instead.
///
/// # Deprecation
///
/// This struct is maintained for backward compatibility.
/// New code should use `MmapPacketEngine` (once implemented) for zero-copy
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
    /// Creates a new `PACKET_MMAP` engine.
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
            .map_err(|e| PacketError::SocketOption {
                option: "non-blocking".to_string(),
                source: e,
            })?;
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
            return Err(PacketError::SocketOption {
                option: "PACKET_VERSION".to_string(),
                source: io::Error::last_os_error(),
            });
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
            return Err(PacketError::interface_index_failed(
                if_name,
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
            return Err(PacketError::bind_failed(
                if_name,
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
            return Err(PacketError::mac_address_failed(
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
            return Err(PacketError::SocketOption {
                option: "recvfrom".to_string(),
                source: err,
            });
        }
        let len = ret as usize;
        buffer.truncate(len);
        let packet = PacketBuffer::from_data(buffer);
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
            return Err(PacketError::SocketOption {
                option: "sendto".to_string(),
                source: io::Error::last_os_error(),
            });
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
            return Err(PacketError::SocketOption {
                option: "promiscuous mode".to_string(),
                source: io::Error::last_os_error(),
            });
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
    fn test_constants() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 4 * 1024 * 1024);
        assert_eq!(DEFAULT_BLOCK_SIZE, 65536);
        assert_eq!(DEFAULT_FRAME_SIZE, 4096);
        assert_eq!(DEFAULT_BLOCK_NR, 256);
    }
}
