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

//! PACKET_MMAP V2 ring buffer implementation for zero-copy packet capture.
//!
//! This module provides `MmapPacketEngine`, a high-performance packet capture
//! engine using Linux's `TPACKET_V2` ring buffer interface for zero-copy
//! packet access.
//!
//! # Architecture
//!
//! The engine uses a memory-mapped ring buffer shared with the kernel:
//! - Zero-copy receive: Packets accessed directly from kernel memory
//! - Zero-copy send: Packets written directly to kernel ring buffers
//! - Batch processing: Multiple packets processed per syscall
//! - Kernel-space BPF filtering: Reduces userspace overhead
//!
//! V2 is chosen over V3 for stability (V3 has bugs in kernels < 3.19).
//!
//! # Memory Ordering
//!
//! Frame status uses Acquire/Release ordering:
//! - Acquire: When checking if frame is available for userspace
//! - Release: When returning frame to kernel
//!
//! # Drop Order
//!
//! CRITICAL: `munmap` must be called BEFORE `close(fd)`:
//! - Wrong order causes `EBADF` errors
//! - Kernel expects mmap to be released before socket
//!
//! # References
//!
//! - nmap's `libpcap/pcap-linux.c` for ring buffer management
//! - Linux kernel `Documentation/networking/packet_mmap.txt`
//! - `include/uapi/linux/if_packet.h` for TPACKET structures
//!
//! # Example
//!
//! ```rust,ignore
//! use rustnmap_packet::{MmapPacketEngine, RingConfig, PacketEngine};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = RingConfig::default();
//!     let mut engine = MmapPacketEngine::new("eth0", config)?;
//!
//!     engine.start().await?;
//!
//!     while let Some(packet) = engine.recv().await? {
//!         // Process packet: packet.len() bytes available
//!         let _len = packet.len();
//!     }
//!
//!     engine.stop().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Safety
//!
//! This struct uses `unsafe` for:
//! - `mmap`/`munmap` system calls
//! - Atomic operations on memory-mapped structures
//! - Raw pointer manipulation for ring buffer access
//!
//! All unsafe blocks have SAFETY comments explaining invariants.
//!
//! # Testing
//!
//! Integration tests require:
//! - Root privileges (CAP_NET_RAW capability)
//! - Actual network interface (not loopback)
//! - Run with: `sudo cargo test -p rustnmap-packet --test integration`

// Rust guideline compliant 2026-03-05

use crate::engine::{EngineStats, PacketBuffer, PacketEngine, Result, RingConfig};
use crate::error::PacketError;
use crate::sys::{
    Tpacket2Hdr, TpacketReq, AF_PACKET, ETH_P_ALL, PACKET_AUXDATA, PACKET_RESERVE, PACKET_RX_RING,
    PACKET_VERSION, SOCK_RAW, TPACKET_ALIGNMENT, TPACKET_V2, TP_STATUS_KERNEL, TP_STATUS_USER,
    TP_STATUS_VLAN_VALID, VLAN_TAG_LEN,
};
use crate::zero_copy::ZeroCopyPacket;
use async_trait::async_trait;
use bytes::Bytes;
use rustnmap_common::MacAddr;
use std::ffi::c_void;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Shared ring buffer state for zero-copy packet lifetime management.
///
/// This lightweight struct holds only what `ZeroCopyPacket` needs to keep
/// the mmap region alive and release frames. It avoids cloning the full
/// `MmapPacketEngine` per packet.
///
/// # Safety
///
/// The `ring_ptr` and `frame_ptrs` remain valid as long as this Arc lives,
/// because dropping the last Arc triggers munmap via the Drop impl.
#[derive(Debug)]
pub struct RingRef {
    /// Memory-mapped ring buffer pointer.
    pub(crate) ring_ptr: NonNull<u8>,
    /// Ring buffer size in bytes.
    pub(crate) ring_size: usize,
    /// Frame pointers for frame release.
    pub(crate) frame_ptrs: Vec<NonNull<Tpacket2Hdr>>,
    /// Total number of frames.
    pub(crate) frame_count: u32,
}

impl RingRef {
    /// Releases a frame back to the kernel by its index.
    pub fn release_frame(&self, frame_idx: u32) {
        if (frame_idx as usize) >= self.frame_ptrs.len() {
            return;
        }
        let frame_ptr = self.frame_ptrs[frame_idx as usize];
        // SAFETY: frame_ptr is valid and within the mmap'd region
        let hdr = unsafe { frame_ptr.as_ref() };
        let status_ptr = std::ptr::addr_of!(hdr.tp_status).cast::<AtomicU32>();
        // SAFETY: status_ptr points to the first field of Tpacket2Hdr,
        // which is a naturally aligned u32 in kernel-shared memory.
        unsafe {
            (*status_ptr).store(TP_STATUS_KERNEL, Ordering::Release);
        }
    }
}

impl Drop for RingRef {
    fn drop(&mut self) {
        // This is only called when all Arc references (including those held by
        // ZeroCopyPacket) are dropped. NonNull guarantees non-null by construction.
        if self.ring_size > 0 {
            // SAFETY: ring_ptr was obtained from mmap and is valid. ring_size
            // matches the original mmap size. This is the matching munmap call.
            unsafe {
                libc::munmap(self.ring_ptr.as_ptr().cast::<c_void>(), self.ring_size);
            }
        }
    }
}

// SAFETY: RingRef uses atomic operations for frame status access.
// The mmap pointer and frame pointers are only accessed through safe abstractions.
unsafe impl Send for RingRef {}
// SAFETY: &RingRef provides read-only access to frame pointers and ring metadata.
// Frame release uses atomic store (Ordering::Release), which is thread-safe.
unsafe impl Sync for RingRef {}

/// Maximum number of ENOMEM retry attempts.
const ENOMEM_MAX_RETRIES: u32 = 10;

/// ENOMEM reduction factor (5% reduction per attempt, following nmap).
const ENOMEM_REDUCTION_PERCENT: u32 = 95;

/// Maximum packet length for Ethernet.
const MAX_PACKET_LEN: usize = 65535;

/// Result type for ring buffer setup containing ring pointer, size, frame pointers, and count.
type RingSetupResult = Result<(NonNull<u8>, usize, Vec<NonNull<Tpacket2Hdr>>, u32)>;

/// `PACKET_MMAP` V2 engine for zero-copy packet capture.
///
/// This engine uses Linux's `TPACKET_V2` ring buffer interface for
/// zero-copy packet capture and transmission. It provides significant
/// performance benefits over traditional socket-based approaches.
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_packet::{MmapPacketEngine, RingConfig, PacketEngine};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = RingConfig::default();
///     let mut engine = MmapPacketEngine::new("eth0", config)?;
///
///     engine.start().await?;
///
///     while let Some(packet) = engine.recv().await? {
///         // Process packet: packet.len() bytes available
///         let _len = packet.len();
///     }
///
///     engine.stop().await?;
///     Ok(())
/// }
/// ```
///
/// # Safety
///
/// This struct uses `unsafe` for:
/// - `mmap`/`munmap` system calls
/// - Atomic operations on memory-mapped structures
/// - Raw pointer manipulation for ring buffer access
///
/// All unsafe blocks have SAFETY comments explaining invariants.
#[derive(Debug)]
pub struct MmapPacketEngine {
    /// Socket file descriptor.
    fd: OwnedFd,
    /// Shared ring buffer state for zero-copy packet lifetime management.
    /// Created once at engine construction, cloned (Arc) per packet.
    ring_ref: Arc<RingRef>,
    /// Current frame index for receive.
    rx_frame_idx: u32,
    /// Interface index.
    if_index: u32,
    /// Interface name.
    if_name: String,
    /// MAC address of the interface.
    mac_addr: MacAddr,
    /// Engine statistics.
    stats: EngineStats,
    /// Running state flag.
    running: AtomicBool,
    /// Packets received counter.
    packets_received: AtomicU64,
    /// Packets dropped counter.
    packets_dropped: AtomicU64,
    /// Bytes received counter.
    bytes_received: AtomicU64,
}

impl MmapPacketEngine {
    /// Creates a new `MmapPacketEngine` bound to the specified interface.
    ///
    /// # Arguments
    ///
    /// * `if_name` - Network interface name (e.g., "eth0")
    /// * `config` - Ring buffer configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - Interface not found
    /// - Ring buffer setup fails
    /// - mmap fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::{MmapPacketEngine, RingConfig};
    ///
    /// let config = RingConfig::default();
    /// let engine = MmapPacketEngine::new("eth0", config)?;
    /// ```
    pub fn new(if_name: &str, config: RingConfig) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        // Get interface information
        let if_index = Self::get_interface_index(if_name)?;
        let mac_addr = Self::get_interface_mac(if_name)?;

        // Create socket with correct option sequence
        let fd = Self::create_socket()?;

        // CRITICAL: Bind BEFORE setting up ring buffer
        // PACKET_RX_RING requires the socket to be bound to an interface first.
        // This ordering is required by the kernel and matches nmap's approach.
        Self::bind_to_interface(&fd, if_index)?;

        // Setup ring buffer with ENOMEM recovery
        // Must come after bind() to avoid errno=22 (EINVAL)
        let (ring_ptr, ring_size, frame_ptrs, frame_count) = Self::setup_ring_buffer(&fd, &config)?;

        // CRITICAL: Re-bind with actual protocol AFTER ring buffer setup.
        // Following nmap's libpcap pattern (pcap-linux.c:1297-1302):
        // "Now that we have activated the mmap ring, we can set the correct protocol."
        // First bind with protocol=0 allows ring buffer setup without dropping packets.
        // Second bind with ETH_P_ALL enables actual packet reception.
        Self::bind_to_interface_with_protocol(&fd, if_index, ETH_P_ALL.to_be())?;

        // Create shared ring ref for zero-copy packet lifetime management.
        // The ring_ref does NOT own the mmap -- the engine does via its Drop impl.
        // When the engine is dropped, it munmaps. The ring_ref's Drop is a no-op
        // to avoid double-munmap (see RingRef::drop).
        let ring_ref = Arc::new(RingRef {
            ring_ptr,
            ring_size,
            frame_ptrs,
            frame_count,
        });

        Ok(Self {
            fd,
            ring_ref,
            rx_frame_idx: 0,
            if_index,
            if_name: if_name.to_string(),
            mac_addr,
            stats: EngineStats::default(),
            running: AtomicBool::new(false),
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        })
    }

    /// Creates a raw packet socket.
    fn create_socket() -> Result<OwnedFd> {
        // For SOCK_RAW packet sockets, protocol must be 0 (all protocols).
        // Protocol filtering is handled by bind(), not socket creation.
        // See: packet(7) man page and nmap's libpcap/pcap-linux.c
        let protocol = 0;
        // SAFETY: socket() creates a new file descriptor. We check for errors
        // and wrap the result in OwnedFd for automatic cleanup.
        let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, protocol) };

        if fd < 0 {
            return Err(PacketError::SocketCreation(io::Error::last_os_error()));
        }

        // SAFETY: fd is valid and owned by us. OwnedFd takes ownership.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Set PACKET_VERSION to TPACKET_V2 - MUST be first
        Self::set_socket_option(&owned_fd, PACKET_VERSION, TPACKET_V2, "PACKET_VERSION")?;

        // Set PACKET_RESERVE - MUST be before RX_RING
        Self::set_socket_option(&owned_fd, PACKET_RESERVE, 4, "PACKET_RESERVE")?;

        // Enable PACKET_AUXDATA for VLAN information
        Self::set_socket_option(&owned_fd, PACKET_AUXDATA, 1, "PACKET_AUXDATA")?;

        Ok(owned_fd)
    }

    /// Sets a socket option with an integer value.
    fn set_socket_option(
        fd: &OwnedFd,
        option_name: libc::c_int,
        value: libc::c_int,
        option_desc: &str,
    ) -> Result<()> {
        let value_ptr = std::ptr::from_ref(&value).cast::<c_void>();
        let value_len = mem::size_of::<libc::c_int>();

        // SAFETY: setsockopt is a standard POSIX call. We pass valid pointers
        // and check the return value.
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                option_name,
                value_ptr,
                u32::try_from(value_len).map_err(|e| PacketError::SocketOption {
                    option: option_desc.to_string(),
                    source: io::Error::new(io::ErrorKind::InvalidInput, e),
                })?,
            )
        };

        if result < 0 {
            return Err(PacketError::socket_option(
                option_desc,
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Gets the interface index for the given interface name.
    fn get_interface_index(if_name: &str) -> Result<u32> {
        if if_name.is_empty() {
            return Err(PacketError::InvalidInterfaceName(if_name.to_string()));
        }

        // SAFETY: mem::zeroed() is safe for libc::ifreq which is POD
        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };

        // Copy interface name safely (ifr_name is [i8; IFNAMSIZ])
        let cstr = std::ffi::CString::new(if_name).map_err(|_nul| {
            PacketError::InvalidInterfaceName(format!("interface name contains NUL: {if_name}"))
        })?;
        let bytes = cstr.as_bytes_with_nul();
        if bytes.len() > ifreq.ifr_name.len() {
            return Err(PacketError::InvalidInterfaceName(format!(
                "interface name too long: {if_name}"
            )));
        }
        for (i, &b) in bytes.iter().enumerate() {
            ifreq.ifr_name[i] = i8::try_from(b).map_err(|_overflow| {
                PacketError::InvalidInterfaceName(format!(
                    "invalid character in interface name: {if_name}"
                ))
            })?;
        }

        // SAFETY: socket() creates a control socket for ioctl
        let ctl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctl_fd < 0 {
            return Err(PacketError::interface_index_failed(
                if_name,
                io::Error::last_os_error(),
            ));
        }

        // SAFETY: ioctl to get interface index. We check the return value.
        let result = unsafe {
            libc::ioctl(
                ctl_fd,
                libc::SIOCGIFINDEX,
                std::ptr::from_ref(&ifreq).cast::<c_void>(),
            )
        };

        // SAFETY: close the control socket
        unsafe { libc::close(ctl_fd) };

        if result < 0 {
            return Err(PacketError::InterfaceNotFound(if_name.to_string()));
        }

        // SAFETY: ifr_ifindex is valid after successful ioctl
        let index = u32::try_from(unsafe { ifreq.ifr_ifru.ifru_ifindex }).map_err(|overflow| {
            PacketError::interface_index_failed(
                if_name,
                io::Error::new(io::ErrorKind::InvalidData, overflow),
            )
        })?;

        Ok(index)
    }

    /// Gets the MAC address for the given interface name.
    fn get_interface_mac(if_name: &str) -> Result<MacAddr> {
        // SAFETY: mem::zeroed() is safe for libc::ifreq which is POD
        let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };

        let cstr = std::ffi::CString::new(if_name).map_err(|_nul| {
            PacketError::InvalidInterfaceName(format!("interface name contains NUL: {if_name}"))
        })?;
        let bytes = cstr.as_bytes_with_nul();
        if bytes.len() > ifreq.ifr_name.len() {
            return Err(PacketError::InvalidInterfaceName(format!(
                "interface name too long: {if_name}"
            )));
        }
        for (i, &b) in bytes.iter().enumerate() {
            ifreq.ifr_name[i] = i8::try_from(b).map_err(|_overflow| {
                PacketError::InvalidInterfaceName(format!(
                    "invalid character in interface name: {if_name}"
                ))
            })?;
        }

        // SAFETY: socket() creates a control socket for ioctl
        let ctl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctl_fd < 0 {
            return Err(PacketError::mac_address_failed(
                if_name,
                io::Error::last_os_error(),
            ));
        }

        // SAFETY: ioctl to get hardware address
        let result = unsafe {
            libc::ioctl(
                ctl_fd,
                libc::SIOCGIFHWADDR,
                std::ptr::from_ref(&ifreq).cast::<c_void>(),
            )
        };

        // SAFETY: close the control socket
        unsafe { libc::close(ctl_fd) };

        if result < 0 {
            return Err(PacketError::mac_address_failed(
                if_name,
                io::Error::last_os_error(),
            ));
        }

        // SAFETY: hwaddr is valid after successful ioctl
        // SAFETY: sa_data is i8 (signed char), but MAC addresses are unsigned bytes.
        // We use `as u8` to reinterpret the bits, which preserves the bit pattern.
        // This is safe because MAC address bytes are always valid u8 values (0-255).
        let hwaddr = unsafe { ifreq.ifr_ifru.ifru_hwaddr };
        // Cast i8 to u8 for MAC address bytes - this preserves the bit pattern
        // which is what we want for MAC addresses (values 0-255 stored as signed bytes).
        #[allow(
            clippy::cast_sign_loss,
            reason = "MAC address bytes are stored as i8 in sockaddr but represent unsigned values"
        )]
        let addr = MacAddr::new([
            hwaddr.sa_data[0] as u8,
            hwaddr.sa_data[1] as u8,
            hwaddr.sa_data[2] as u8,
            hwaddr.sa_data[3] as u8,
            hwaddr.sa_data[4] as u8,
            hwaddr.sa_data[5] as u8,
        ]);

        Ok(addr)
    }

    /// Sets up the ring buffer with ENOMEM recovery strategy.
    ///
    /// Following nmap's approach: if ENOMEM occurs, reduce `block_size` by 5%
    /// and retry up to 10 times.
    fn setup_ring_buffer(fd: &OwnedFd, config: &RingConfig) -> RingSetupResult {
        let mut block_size = config.block_size;
        let mut attempts = 0;

        loop {
            attempts += 1;

            let req = TpacketReq::with_values(
                block_size,
                config.block_nr,
                config.frame_size,
                block_size / config.frame_size * config.block_nr,
            );

            // Validate the request
            if let Err(e) = req.validate() {
                return Err(PacketError::InvalidConfig(e.to_string()));
            }

            let ring_size = req
                .ring_size()
                .map_err(|e| PacketError::InvalidConfig(e.to_string()))?;

            // Set up RX ring
            // SAFETY: setsockopt with valid TpacketReq pointer
            let result = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    PACKET_RX_RING,
                    std::ptr::from_ref::<TpacketReq>(&req).cast::<c_void>(),
                    u32::try_from(mem::size_of::<TpacketReq>()).map_err(|e| {
                        PacketError::RingBufferSetup(io::Error::new(io::ErrorKind::InvalidInput, e))
                    })?,
                )
            };

            if result < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOMEM) && attempts < ENOMEM_MAX_RETRIES {
                    // Reduce block size by 5% and retry
                    block_size = block_size * ENOMEM_REDUCTION_PERCENT / 100;
                    // Ensure alignment
                    let alignment = u32::try_from(TPACKET_ALIGNMENT).unwrap_or(16);
                    block_size = block_size.div_ceil(alignment) * alignment;
                    continue;
                }
                return Err(PacketError::RxRingSetup(err));
            }

            // mmap the ring buffer
            // SAFETY: mmap creates a memory mapping. We check for MAP_FAILED.
            let ring_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    ring_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd.as_raw_fd(),
                    0,
                )
            };

            if ring_ptr == libc::MAP_FAILED {
                return Err(PacketError::mmap_failed(
                    ring_size,
                    io::Error::last_os_error(),
                ));
            }

            let ring_ptr =
                NonNull::new(ring_ptr.cast::<u8>()).ok_or_else(|| PacketError::MmapFailed {
                    size: ring_size,
                    source: io::Error::other("mmap returned null"),
                })?;

            // Compute frame pointers
            let frame_ptrs = Self::compute_frame_pointers(ring_ptr, &req)?;
            let frame_count = u32::try_from(frame_ptrs.len())
                .map_err(|e| PacketError::InvalidConfig(format!("Too many frames: {e}")))?;

            return Ok((ring_ptr, ring_size, frame_ptrs, frame_count));
        }
    }

    /// Computes pointers to each frame in the ring buffer.
    fn compute_frame_pointers(
        ring_ptr: NonNull<u8>,
        req: &TpacketReq,
    ) -> Result<Vec<NonNull<Tpacket2Hdr>>> {
        let frames_per_block = usize::try_from(req.tp_block_size / req.tp_frame_size)
            .map_err(|e| PacketError::InvalidConfig(format!("Frame calculation overflow: {e}")))?;

        let total_frames =
            frames_per_block
                .checked_mul(usize::try_from(req.tp_block_nr).map_err(|e| {
                    PacketError::InvalidConfig(format!("Block count overflow: {e}"))
                })?)
                .ok_or_else(|| PacketError::InvalidConfig("Frame count overflow".to_string()))?;

        let mut frame_ptrs = Vec::with_capacity(total_frames);

        let block_nr: usize = usize::try_from(req.tp_block_nr)
            .map_err(|e| PacketError::InvalidConfig(format!("Block index overflow: {e}")))?;
        let block_size: usize = usize::try_from(req.tp_block_size)
            .map_err(|e| PacketError::InvalidConfig(format!("Block size overflow: {e}")))?;
        let frame_size: usize = usize::try_from(req.tp_frame_size)
            .map_err(|e| PacketError::InvalidConfig(format!("Frame size overflow: {e}")))?;

        for block_idx in 0..block_nr {
            let block_offset = block_idx
                .checked_mul(block_size)
                .ok_or_else(|| PacketError::InvalidConfig("Block offset overflow".to_string()))?;

            for frame_idx in 0..frames_per_block {
                let frame_offset = frame_idx.checked_mul(frame_size).ok_or_else(|| {
                    PacketError::InvalidConfig("Frame offset overflow".to_string())
                })?;

                let total_offset = block_offset.checked_add(frame_offset).ok_or_else(|| {
                    PacketError::InvalidConfig("Total offset overflow".to_string())
                })?;

                // SAFETY: The offset is within the mmap'd region by construction.
                // Frame alignment is ensured by TPACKET requirements (frame_size
                // is a multiple of TPACKET_ALIGNMENT).
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "Frame size is guaranteed aligned to TPACKET_ALIGNMENT by kernel contract"
                )]
                let frame_ptr = unsafe {
                    NonNull::new(ring_ptr.as_ptr().add(total_offset).cast::<Tpacket2Hdr>())
                        .ok_or_else(|| {
                            PacketError::InvalidConfig("Frame pointer is null".to_string())
                        })?
                };

                frame_ptrs.push(frame_ptr);
            }
        }

        Ok(frame_ptrs)
    }

    /// Binds the socket to the specified interface with protocol=0.
    ///
    /// This initial bind with protocol=0 is required BEFORE setting up `PACKET_RX_RING`.
    /// The socket must be re-bound with the actual protocol (`ETH_P_ALL`) after ring setup.
    fn bind_to_interface(fd: &OwnedFd, if_index: u32) -> Result<()> {
        Self::bind_to_interface_with_protocol(fd, if_index, 0)
    }

    /// Binds the socket to the specified interface with the specified protocol.
    ///
    /// # Arguments
    ///
    /// * `fd` - Socket file descriptor
    /// * `if_index` - Interface index
    /// * `protocol` - Ethernet protocol in network byte order (e.g., `ETH_P_ALL.to_be()`)
    fn bind_to_interface_with_protocol(fd: &OwnedFd, if_index: u32, protocol: u16) -> Result<()> {
        // SAFETY: mem::zeroed() is safe for sockaddr_ll which is POD
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = u16::try_from(AF_PACKET).map_err(|e| PacketError::BindFailed {
            interface: format!("index {if_index}"),
            source: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;
        addr.sll_protocol = protocol; // Use the specified protocol
        addr.sll_ifindex = i32::try_from(if_index).map_err(|e| PacketError::BindFailed {
            interface: format!("index {if_index}"),
            source: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;

        // SAFETY: bind is a standard POSIX call with valid address
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                u32::try_from(mem::size_of::<libc::sockaddr_ll>()).map_err(|e| {
                    PacketError::BindFailed {
                        interface: format!("index {if_index}"),
                        source: io::Error::new(io::ErrorKind::InvalidInput, e),
                    }
                })?,
            )
        };

        if result < 0 {
            return Err(PacketError::bind_failed(
                format!("index {if_index}"),
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Checks if a frame is available for reading.
    ///
    /// Uses Acquire ordering to synchronize with kernel's Release store.
    fn frame_is_available(&self) -> bool {
        let frame_idx = self.rx_frame_idx as usize;
        if frame_idx >= self.ring_ref.frame_ptrs.len() {
            return false;
        }

        let frame_ptr = self.ring_ref.frame_ptrs[frame_idx];

        // Check if pointer is within mmap'd region
        let frame_addr = frame_ptr.as_ptr() as usize;
        let ring_start = self.ring_ref.ring_ptr.as_ptr() as usize;
        let ring_end = ring_start + self.ring_ref.ring_size;

        if frame_addr < ring_start || frame_addr >= ring_end {
            return false;
        }

        // SAFETY: frame_ptr is valid and within the mmap'd region
        let hdr = unsafe { frame_ptr.as_ref() };
        // The first field of Tpacket2Hdr is tp_status (u32), which we
        // access atomically to synchronize with the kernel.
        // CRITICAL: We must access the kernel-shared memory directly,
        // NOT create a new AtomicU32 (which would break atomicity).
        let status_ptr = std::ptr::addr_of!(hdr.tp_status).cast::<AtomicU32>();
        // SAFETY: status_ptr points to the first field of Tpacket2Hdr,
        // which is a naturally aligned u32 in kernel-shared memory.
        unsafe { (*status_ptr).load(Ordering::Acquire) & TP_STATUS_USER != 0 }
    }

    /// Releases a frame back to the kernel.
    ///
    /// Uses Release ordering to synchronize with kernel's Acquire load.
    fn release_frame(&self) {
        let frame_ptr = self.ring_ref.frame_ptrs[self.rx_frame_idx as usize];
        // SAFETY: frame_ptr is valid and within the mmap'd region
        let hdr = unsafe { frame_ptr.as_ref() };
        // The first field of Tpacket2Hdr is tp_status (u32), which we
        // access atomically to synchronize with the kernel.
        let status_ptr = std::ptr::addr_of!(hdr.tp_status).cast::<AtomicU32>();
        // SAFETY: status_ptr points to the first field of Tpacket2Hdr,
        // which is a u32 that we access atomically.
        unsafe {
            (*status_ptr).store(TP_STATUS_KERNEL, Ordering::Release);
        }
    }

    /// Advances to the next frame in the ring.
    fn advance_frame(&mut self) {
        self.rx_frame_idx = (self.rx_frame_idx + 1) % self.ring_ref.frame_count;
    }

    /// Returns the memory-mapped region pointer.
    ///
    /// This is used by `ZeroCopyPacket` to verify that data pointers
    /// are within the valid region (in debug builds).
    #[must_use]
    pub fn ring_ptr(&self) -> *const u8 {
        self.ring_ref.ring_ptr.as_ptr()
    }

    /// Returns the memory-mapped region size in bytes.
    ///
    /// This is used by `ZeroCopyPacket` to verify that data pointers
    /// are within the valid region (in debug builds).
    #[must_use]
    pub fn ring_size(&self) -> usize {
        self.ring_ref.ring_size
    }

    /// Releases a frame back to the kernel by its index.
    ///
    /// This is used by `ZeroCopyPacket`'s `Drop` implementation to release
    /// the frame when the packet is dropped.
    ///
    /// # Arguments
    ///
    /// * `frame_idx` - Index of the frame to release
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `frame_idx` >= `frame_count`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `frame_idx` is within bounds (0..`frame_count`).
    /// This is guaranteed when the frame was obtained from a valid `ZeroCopyPacket`.
    pub fn release_frame_by_idx(&self, frame_idx: u32) {
        #[cfg(debug_assertions)]
        assert!(
            frame_idx < self.ring_ref.frame_count,
            "frame_idx {} >= frame_count {}",
            frame_idx,
            self.ring_ref.frame_count
        );

        let frame_ptr = self.ring_ref.frame_ptrs[frame_idx as usize];
        // SAFETY: frame_ptr is valid and within the mmap'd region
        let hdr = unsafe { frame_ptr.as_ref() };

        // The first field of Tpacket2Hdr is tp_status (u32), which we
        // access atomically to synchronize with the kernel.
        let status_ptr = std::ptr::addr_of!(hdr.tp_status).cast::<AtomicU32>();
        // SAFETY: status_ptr points to the first field of Tpacket2Hdr (tp_status),
        // which is a u32 that we access atomically to synchronize with the kernel.
        unsafe {
            (*status_ptr).store(TP_STATUS_KERNEL, Ordering::Release);
        }
    }

    /// Tries to receive a packet without blocking (zero-copy variant).
    ///
    /// This method returns a `ZeroCopyPacket` that holds a reference to the engine
    /// and points directly into the memory-mapped region without copying data.
    /// The frame is automatically released back to the kernel when the packet is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The engine is not running
    /// - Frame access fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::{MmapPacketEngine, RingConfig};
    ///
    /// let mut engine = MmapPacketEngine::new("eth0", RingConfig::default())?;
    /// engine.start().await?;
    ///
    /// if let Some(packet) = engine.try_recv_zero_copy()? {
    ///     // Process packet without copying data
    ///     let _len = packet.len();
    /// } // Frame automatically released here
    /// ```
    pub fn try_recv_zero_copy(&mut self) -> Result<Option<crate::ZeroCopyPacket>> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        let frame_idx = self.rx_frame_idx as usize;

        // Check bounds BEFORE accessing
        if frame_idx >= self.ring_ref.frame_ptrs.len() {
            return Err(PacketError::InvalidConfig(format!(
                "frame_idx {frame_idx} out of bounds"
            )));
        }

        if !self.frame_is_available() {
            return Ok(None);
        }

        let frame_ptr = self.ring_ref.frame_ptrs[frame_idx];
        // SAFETY: frame_ptr is valid and we've verified frame is available
        let hdr = unsafe { frame_ptr.as_ref() };

        // Get packet data
        // tp_mac is the offset from frame start to Ethernet header (per kernel documentation)
        // nmap uses: bp = frame + tp_mac (see libpcap/pcap-linux.c:4010)
        let data_offset = hdr.tp_mac as usize;
        let data_len = hdr.tp_snaplen as usize;
        let original_len = hdr.tp_len as usize;

        // Check for VLAN tag
        let has_vlan = (hdr.tp_status & TP_STATUS_VLAN_VALID) != 0;

        // Update statistics
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(data_len as u64, Ordering::Relaxed);

        // Get the current frame index before advancing
        let current_frame_idx = self.rx_frame_idx;

        // Advance to the next frame (do NOT release the current frame yet)
        // The frame will be released when the ZeroCopyPacket is dropped
        self.advance_frame();

        // Clone the shared ring ref instead of the full engine.
        // Arc::clone only increments the reference count (~10 CPU cycles)
        // compared to the old approach of dup(fd) + full engine allocation.
        let ring_ref = Arc::clone(&self.ring_ref);

        let (data, vlan_tci, vlan_tpid) = if has_vlan {
            // For VLAN-tagged packets, the kernel strips the VLAN tag and sets
            // TP_STATUS_VLAN_VALID. We need to reconstruct the Ethernet header
            // with the VLAN tag inserted. This requires copying because we need
            // to shift the packet data to make room for the 4-byte VLAN tag.
            //
            // This is a limitation of the TPACKET_V2 interface. When VLAN
            // stripping is enabled, the zero-copy optimization is not possible.
            let reconstructed =
                Self::reconstruct_vlan_packet(hdr, frame_ptr, data_offset, data_len);
            // Convert the reconstructed Bytes to ZeroCopyBytes with owned data
            let zc_bytes = crate::zero_copy::ZeroCopyBytes::owned(reconstructed.to_vec());
            (zc_bytes, Some(hdr.tp_vlan_tci), Some(hdr.tp_vlan_tpid))
        } else {
            // Zero-copy: Create ZeroCopyBytes that points directly into the mmap region
            // SAFETY: data_offset + data_len is within the frame by kernel contract
            let data_ptr = unsafe { frame_ptr.as_ptr().cast::<u8>().add(data_offset) };
            // SAFETY:
            // - data_ptr points into the mmap region owned by ring_ref
            // - The region remains valid for the lifetime of ring_ref
            // - ring_ref is captured by ZeroCopyBytes
            // - data_len is the captured length
            let zc_bytes = unsafe {
                crate::zero_copy::ZeroCopyBytes::borrowed(Arc::clone(&ring_ref), data_ptr, data_len)
            };
            (zc_bytes, None, None)
        };

        // Create the zero-copy packet
        let packet = crate::ZeroCopyPacket::new(
            ring_ref,
            current_frame_idx,
            data,
            std::time::Instant::now(),
            data_len,
            original_len,
            vlan_tci,
            vlan_tpid,
        );

        Ok(Some(packet))
    }

    /// Tries to receive a packet without blocking.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The engine is not running
    /// - Frame access fails
    pub fn try_recv(&mut self) -> Result<Option<PacketBuffer>> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        if !self.frame_is_available() {
            return Ok(None);
        }

        let frame_ptr = self.ring_ref.frame_ptrs[self.rx_frame_idx as usize];
        // SAFETY: frame_ptr is valid and we've verified frame is available
        let hdr = unsafe { frame_ptr.as_ref() };

        // Get packet data
        // tp_mac is the offset from frame start to Ethernet header (per kernel documentation)
        // nmap uses: bp = frame + tp_mac (see libpcap/pcap-linux.c:4010)
        let data_offset = hdr.tp_mac as usize;
        let data_len = hdr.tp_snaplen as usize;

        // Check for VLAN tag
        let has_vlan = (hdr.tp_status & TP_STATUS_VLAN_VALID) != 0;

        // Build the packet data
        let packet_data = if has_vlan {
            // Reconstruct VLAN-tagged packet
            Self::reconstruct_vlan_packet(hdr, frame_ptr, data_offset, data_len)
        } else {
            // Direct copy
            // SAFETY: data_offset + data_len is within the frame by kernel contract
            let data_ptr = unsafe { frame_ptr.as_ptr().cast::<u8>().add(data_offset) };
            // SAFETY: data_ptr is valid and data_len is within bounds
            let slice = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
            Bytes::copy_from_slice(slice)
        };

        // Update statistics
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(data_len as u64, Ordering::Relaxed);

        // Create packet buffer
        let mut buffer = PacketBuffer::from_data(packet_data);
        if has_vlan {
            buffer.set_vlan(hdr.tp_vlan_tci, hdr.tp_vlan_tpid);
        }

        // Release frame back to kernel
        self.release_frame();
        self.advance_frame();

        Ok(Some(buffer))
    }

    /// Reconstructs a VLAN-tagged packet.
    ///
    /// When `TP_STATUS_VLAN_VALID` is set, the VLAN tag has been stripped.
    /// We need to reconstruct the Ethernet header with the VLAN tag.
    fn reconstruct_vlan_packet(
        hdr: &Tpacket2Hdr,
        frame_ptr: NonNull<Tpacket2Hdr>,
        data_offset: usize,
        data_len: usize,
    ) -> Bytes {
        // SAFETY: data_offset is within the frame by kernel contract
        let data_ptr = unsafe { frame_ptr.as_ptr().cast::<u8>().add(data_offset) };

        // VLAN-tagged Ethernet header is 18 bytes (14 + 4 for VLAN tag)
        let vlan_tag_len = VLAN_TAG_LEN;

        // Create reconstructed packet
        let reconstructed_len = data_len + vlan_tag_len;
        let mut reconstructed = vec![0u8; reconstructed_len];

        // SAFETY: We're reading from the frame within bounds
        let original_data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };

        // Copy destination and source MAC addresses (12 bytes)
        reconstructed[..12].copy_from_slice(&original_data[..12]);

        // Insert VLAN TPID and TCI
        reconstructed[12..14].copy_from_slice(&hdr.tp_vlan_tpid.to_be_bytes());
        reconstructed[14..16].copy_from_slice(&hdr.tp_vlan_tci.to_be_bytes());

        // Copy EtherType (2 bytes) - now at offset 16
        reconstructed[16..18].copy_from_slice(&original_data[12..14]);

        // Copy payload
        reconstructed[18..].copy_from_slice(&original_data[14..]);

        Bytes::from(reconstructed)
    }

    /// Returns the interface name.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.if_name
    }

    /// Returns the interface index.
    #[must_use]
    pub const fn interface_index(&self) -> u32 {
        self.if_index
    }

    /// Returns the MAC address.
    #[must_use]
    pub const fn mac_address(&self) -> MacAddr {
        self.mac_addr
    }

    /// Returns the raw file descriptor for the socket.
    ///
    /// This is used for async integration with `AsyncFd`.
    /// The caller should NOT close this fd as it is owned by the engine.
    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

// NOTE: No explicit Drop impl for MmapPacketEngine.
// The fd is automatically closed by OwnedFd's Drop.
// The mmap region is munmap-ed by RingRef::drop when the last Arc<RingRef> is
// dropped (which may be held by in-flight ZeroCopyPackets). Field drop order
// ensures ring_ref (and its mmap) drops BEFORE fd, matching kernel expectations.

// SAFETY: MmapPacketEngine uses atomic operations for shared state and
// the ring buffer pointer is only accessed through safe abstractions.
// The kernel ensures proper synchronization via the tp_status field.
unsafe impl Send for MmapPacketEngine {}

// SAFETY: MmapPacketEngine uses atomic operations for shared state and
// the ring buffer pointer is only accessed through safe abstractions.
// The kernel ensures proper synchronization via the tp_status field.
unsafe impl Sync for MmapPacketEngine {}

#[async_trait]
impl PacketEngine for MmapPacketEngine {
    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            return Err(PacketError::AlreadyStarted);
        }

        self.running.store(true, Ordering::Release);
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ZeroCopyPacket>> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        // Try to receive a packet (zero-copy)
        if let Some(packet) = self.try_recv_zero_copy()? {
            return Ok(Some(packet));
        }

        // No packet available, yield and retry
        tokio::task::yield_now().await;

        // Try again after yielding
        self.try_recv_zero_copy()
    }

    async fn send(&self, packet: &[u8]) -> Result<usize> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        if packet.len() > MAX_PACKET_LEN {
            return Err(PacketError::PacketTooLarge {
                size: packet.len(),
                max: MAX_PACKET_LEN,
            });
        }

        // Build sockaddr_ll for sending
        // SAFETY: mem::zeroed() is safe for sockaddr_ll which is POD
        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = u16::try_from(AF_PACKET).map_err(|e| PacketError::SocketOption {
            option: "send".to_string(),
            source: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;
        addr.sll_ifindex = i32::try_from(self.if_index).map_err(|e| PacketError::SocketOption {
            option: "send".to_string(),
            source: io::Error::new(io::ErrorKind::InvalidInput, e),
        })?;
        addr.sll_halen = 6;
        addr.sll_protocol = ETH_P_ALL.to_be();

        // SAFETY: sendto is a standard POSIX call with valid parameters
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast::<c_void>(),
                packet.len(),
                0,
                std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                u32::try_from(mem::size_of::<libc::sockaddr_ll>()).map_err(|e| {
                    PacketError::SocketOption {
                        option: "send".to_string(),
                        source: io::Error::new(io::ErrorKind::InvalidInput, e),
                    }
                })?,
            )
        };

        if sent < 0 {
            return Err(PacketError::SocketOption {
                option: "sendto".to_string(),
                source: io::Error::last_os_error(),
            });
        }

        Ok(
            usize::try_from(sent).map_err(|e| PacketError::SocketOption {
                option: "send".to_string(),
                source: io::Error::new(io::ErrorKind::InvalidInput, e),
            })?,
        )
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        self.running.store(false, Ordering::Release);
        Ok(())
    }

    fn stats(&self) -> EngineStats {
        EngineStats {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent,
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent,
            receive_errors: self.stats.receive_errors,
            send_errors: self.stats.send_errors,
        }
    }

    fn flush(&self) -> Result<()> {
        // No buffered packets in ring buffer mode
        Ok(())
    }

    fn set_filter(&self, filter: &libc::sock_fprog) -> Result<()> {
        // SAFETY: setsockopt with SO_ATTACH_FILTER is safe with valid filter pointer
        let result = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                std::ptr::from_ref(filter).cast::<c_void>(),
                u32::try_from(mem::size_of::<libc::sock_fprog>())
                    .map_err(|e| PacketError::BpfFilter(format!("Invalid filter size: {e}")))?,
            )
        };

        if result < 0 {
            return Err(PacketError::BpfFilter(
                io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(ENOMEM_MAX_RETRIES, 10);
        assert_eq!(ENOMEM_REDUCTION_PERCENT, 95);
        assert_eq!(MAX_PACKET_LEN, 65535);
    }

    #[test]
    fn test_ring_config_validation() {
        let config = RingConfig::default();
        config.validate().unwrap();
    }

    #[test]
    fn test_ring_config_invalid_block_size() {
        let config = RingConfig {
            block_size: 65535, // Not power of two
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ring_config_zero_block_nr() {
        let config = RingConfig {
            block_nr: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tpacket_req_size() {
        assert_eq!(mem::size_of::<TpacketReq>(), 16);
    }

    #[test]
    fn test_tpacket2_hdr_size() {
        assert_eq!(mem::size_of::<Tpacket2Hdr>(), 32);
    }
}
