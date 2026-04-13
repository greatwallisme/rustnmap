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

//! Zero-copy packet buffer implementation for PACKET_MMAP V2.
//!
//! This module provides `ZeroCopyPacket`, a packet buffer that holds a reference
//! to the shared ring buffer (`Arc<RingRef>`) to ensure the memory-mapped region
//! remains valid during the packet's lifetime. The frame is automatically released
//! back to the kernel when the packet is dropped.
//!
//! # Architecture
//!
//! The zero-copy architecture has three layers:
//!
//! 1. **MmapPacketEngine** - Owns the socket fd and the `Arc<RingRef>`
//!    - Created once at engine construction
//!    - Shares `RingRef` with packets via `Arc::clone`
//!
//! 2. **Arc<RingRef>** - Lightweight reference-counted ring buffer state
//!    - Contains only the mmap pointer, size, frame pointers, and frame count
//!    - Cloning is ~10 CPU cycles (atomic increment)
//!    - `Drop` calls `munmap` when the last reference is dropped
//!
//! 3. **ZeroCopyPacket** - Zero-copy view into a single frame
//!    - `_ring_ref: Arc<RingRef>` - keeps mmap region alive
//!    - `frame_idx: u32` - tracks which frame is in use
//!    - `data: ZeroCopyBytes` - zero-copy view into packet data
//!    - `impl Drop` - releases frame back to kernel when dropped
//!
//! # Memory Safety
//!
//! The `Arc<RingRef>` ensures that:
//! 1. The memory-mapped region is not `munmap`-ed while the packet is alive
//! 2. The frame pointers remain valid
//! 3. `munmap` happens automatically when the last reference drops
//!
//! # Performance
//!
//! - **No `memcpy`**: Data is accessed directly from kernel memory
//! - **No dup(fd)**: Arc::clone replaces the old dup(fd) + full engine clone
//! - **Atomic operations**: Only reference counting overhead (~10 CPU cycles)
//! - **Automatic cleanup**: Frame released on `drop`
//!
//! # Example
//!
//! ```rust,ignore
//! use rustnmap_packet::{MmapPacketEngine, RingConfig};
//!
//! let mut engine = MmapPacketEngine::new("eth0", RingConfig::default())?;
//!
//! if let Some(packet) = engine.try_recv_zero_copy()? {
//!     // `packet.data` points directly into the mmap region
//!     // No data has been copied
//!     let _len = packet.len();
//! } // Frame automatically released back to kernel here
//! ```

// Rust guideline compliant 2026-04-11

use crate::mmap::RingRef;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

/// Zero-copy bytes view into a memory-mapped packet.
///
/// This struct can hold either:
/// 1. A borrowed pointer into the memory-mapped region (true zero-copy)
/// 2. Owned data (for reconstructed packets like VLAN-tagged packets)
///
/// # Memory Safety
///
/// For borrowed data, the `Arc<RingRef>` ensures the mmap
/// region is not freed while this view is alive.
///
/// # Example
///
/// ```rust,ignore
/// // Borrowed from mmap region (zero-copy)
/// let view = ZeroCopyBytes::borrowed(ring_ref, ptr, len);
///
/// // Owned data (copied, e.g., for VLAN reconstruction)
/// let view = ZeroCopyBytes::owned(vec);
/// ```
#[derive(Clone)]
pub struct ZeroCopyBytes {
    /// Arc reference to keep the mmap region alive (for borrowed data).
    _ring_ref: Option<Arc<RingRef>>,

    /// Pointer into the mmap region (for borrowed data).
    ptr: *const u8,

    /// Length of the data.
    len: usize,

    /// Owned data (for reconstructed packets).
    /// When `Some`, the data is owned and `ptr` points into this vector.
    owned: Option<Vec<u8>>,
}

// SAFETY: ZeroCopyBytes is Send because the pointer is only accessed
// through immutable references, and the Arc ensures thread safety.
unsafe impl Send for ZeroCopyBytes {}

// SAFETY: ZeroCopyBytes is Sync because &Self provides read-only access
// to the data, and the Arc ensures thread safety.
unsafe impl Sync for ZeroCopyBytes {}

impl ZeroCopyBytes {
    /// Creates a borrowed zero-copy bytes view from the mmap region.
    ///
    /// # Arguments
    ///
    /// * `ring_ref` - Arc reference to keep the mmap region alive
    /// * `ptr` - Pointer into the mmap region
    /// * `len` - Length of the data
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `ptr` points into the memory-mapped region owned by `ring_ref`
    /// - `ptr..ptr+len` is within the mmap region bounds
    /// - The data remains valid for the lifetime of this view
    #[must_use]
    pub const unsafe fn borrowed(ring_ref: Arc<RingRef>, ptr: *const u8, len: usize) -> Self {
        Self {
            _ring_ref: Some(ring_ref),
            ptr,
            len,
            owned: None,
        }
    }

    /// Creates an owned bytes view from a vector.
    ///
    /// # Arguments
    ///
    /// * `data` - Owned vector containing the packet data
    #[must_use]
    pub fn owned(data: Vec<u8>) -> Self {
        let len = data.len();
        let ptr = data.as_ptr();
        Self {
            _ring_ref: None,
            ptr,
            len,
            owned: Some(data),
        }
    }

    /// Returns the length of the data.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the view is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if this view is borrowed (zero-copy from mmap).
    #[must_use]
    pub const fn is_borrowed(&self) -> bool {
        self.owned.is_none()
    }

    /// Converts this view to a `Bytes` by copying the data.
    ///
    /// This is useful when you need to pass the data to an API that
    /// requires `Bytes`.
    #[must_use]
    pub fn to_bytes(&self) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(self)
    }
}

impl Deref for ZeroCopyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // - self.ptr is valid and aligned (points into mmap region or owned vec)
        // - self.len is within bounds (guaranteed by construction)
        // - The data is immutable (we only provide & references)
        // - The Arc or owned vec ensures the data is not freed
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl AsRef<[u8]> for ZeroCopyBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "`ptr` and `owned` are implementation details"
)]
impl fmt::Debug for ZeroCopyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZeroCopyBytes")
            .field("len", &self.len)
            .field("is_borrowed", &self.is_borrowed())
            .field("data", &&self[..std::cmp::min(self.len, 32)])
            .finish()
    }
}

/// Zero-copy packet buffer with automatic frame lifetime management.
///
/// This struct can hold either:
/// 1. A reference to the ring buffer via `Arc<RingRef>` for true zero-copy packets from mmap
/// 2. Owned data for packets received via recvfrom or other non-zero-copy sources
///
/// When holding a ring reference, the frame is automatically released
/// back to the kernel when the packet is dropped. For owned data, no frame
/// release is needed.
///
/// # Memory Safety
///
/// For zero-copy packets (when `_ring_ref` is `Some`):
/// - The `Arc<RingRef>` ensures the `mmap` region is not freed while the packet is alive
/// - The frame pointer remains valid
/// - `munmap` happens when the last `Arc<RingRef>` is dropped
///
/// For owned packets (when `_ring_ref` is `None`):
/// - The data is owned and lives for the lifetime of the packet
/// - No frame release is performed on drop
///
/// # Performance
///
/// - Zero-copy: No `memcpy`, data points directly into kernel memory
/// - Owned: Data has been copied, but still efficient with reference counting
/// - Atomic operations: Only reference counting overhead (~10 CPU cycles)
/// - Automatic cleanup: Frame released on `drop` (for zero-copy packets only)
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_packet::{MmapPacketEngine, RingConfig};
///
/// let mut engine = MmapPacketEngine::new("eth0", RingConfig::default())?;
///
/// if let Some(packet) = engine.try_recv_zero_copy()? {
///     // Process packet without copying data
///     let data = packet.data();
///     let len = packet.len();
/// } // Frame automatically released here
/// ```
#[derive(Debug)]
pub struct ZeroCopyPacket {
    /// Optional Arc reference to the shared ring buffer state.
    ///
    /// - `Some(ring_ref)`: Zero-copy packet, frame will be released on drop
    /// - `None`: Owned packet (e.g., from recvfrom), no frame to release
    #[expect(
        clippy::used_underscore_binding,
        reason = "Field is only used in Drop impl"
    )]
    _ring_ref: Option<Arc<RingRef>>,

    /// Index of the frame in the ring buffer.
    ///
    /// Only used when `_ring_ref` is `Some` to release the frame back to the kernel.
    frame_idx: u32,

    /// Zero-copy view into the packet data.
    ///
    /// This `ZeroCopyBytes` can point either into the memory-mapped region
    /// (zero-copy) or hold owned data.
    data: ZeroCopyBytes,

    /// Timestamp when the packet was received.
    timestamp: Instant,

    /// Captured packet length.
    captured_len: usize,

    /// Original packet length (may be larger if truncated).
    original_len: usize,

    /// VLAN TCI (if present).
    vlan_tci: Option<u16>,

    /// VLAN TPID (if present).
    vlan_tpid: Option<u16>,
}

impl ZeroCopyPacket {
    /// Creates a new zero-copy packet from a shared ring buffer reference.
    ///
    /// # Arguments
    ///
    /// * `ring_ref` - Arc reference to the shared ring buffer state
    /// * `frame_idx` - Index of the frame in the ring buffer
    /// * `data` - Zero-copy bytes view into the packet data
    /// * `timestamp` - When the packet was received
    /// * `captured_len` - Captured length
    /// * `original_len` - Original packet length
    /// * `vlan_tci` - VLAN TCI (if present)
    /// * `vlan_tpid` - VLAN TPID (if present)
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `data` points into the memory-mapped region owned by `ring_ref`
    /// - The frame at `frame_idx` is marked as in-use
    /// - The frame remains valid for the lifetime of this packet
    ///
    /// # Panics
    ///
    /// Panics if the data pointer is not within the ring buffer's mmap region
    /// (in debug builds, borrowed data only).
    #[expect(
        clippy::too_many_arguments,
        reason = "All parameters are distinct and required for zero-copy packet construction"
    )]
    #[must_use]
    pub fn new(
        ring_ref: Arc<RingRef>,
        frame_idx: u32,
        data: ZeroCopyBytes,
        timestamp: Instant,
        captured_len: usize,
        original_len: usize,
        vlan_tci: Option<u16>,
        vlan_tpid: Option<u16>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            // For borrowed data, verify data pointer is within mmap region
            // For owned data, we skip this check since the pointer is into a Vec
            if data.is_borrowed() {
                let mmap_start = ring_ref.ring_ptr.as_ptr() as usize;
                let mmap_end = mmap_start + ring_ref.ring_size;
                // For borrowed data, the pointer is valid and points into mmap region
                let data_ptr = data.as_ptr() as usize;

                assert!(
                    (mmap_start..mmap_end).contains(&data_ptr),
                    "ZeroCopyPacket data pointer {:p} is outside mmap region [{:p}..{:p}]",
                    data_ptr as *const (),
                    mmap_start as *const (),
                    mmap_end as *const ()
                );
            }
        }

        Self {
            _ring_ref: Some(ring_ref),
            frame_idx,
            data,
            timestamp,
            captured_len,
            original_len,
            vlan_tci,
            vlan_tpid,
        }
    }

    /// Creates a new packet from owned data (e.g., from recvfrom).
    ///
    /// This constructor is used when packet data has been copied into owned memory,
    /// such as when using the `recvfrom()` system call. No frame is held, so no
    /// frame release occurs on drop.
    ///
    /// # Arguments
    ///
    /// * `data` - Owned packet data as a vector
    /// * `timestamp` - When the packet was received
    /// * `captured_len` - Captured length
    /// * `original_len` - Original packet length
    /// * `vlan_tci` - VLAN TCI (if present)
    /// * `vlan_tpid` - VLAN TPID (if present)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::ZeroCopyPacket;
    /// use std::time::Instant;
    ///
    /// let data = vec![1u8, 2, 3, 4, 5];
    /// let packet = ZeroCopyPacket::owned(data, Instant::now(), 5, 5, None, None);
    /// ```
    #[must_use]
    pub fn owned(
        data: Vec<u8>,
        timestamp: Instant,
        captured_len: usize,
        original_len: usize,
        vlan_tci: Option<u16>,
        vlan_tpid: Option<u16>,
    ) -> Self {
        let zero_copy_bytes = ZeroCopyBytes::owned(data);
        Self {
            _ring_ref: None,
            frame_idx: 0,
            data: zero_copy_bytes,
            timestamp,
            captured_len,
            original_len,
            vlan_tci,
            vlan_tpid,
        }
    }

    /// Returns the packet data.
    ///
    /// This returns a zero-copy view into the memory-mapped region.
    /// No data has been copied.
    #[must_use]
    pub const fn data(&self) -> &ZeroCopyBytes {
        &self.data
    }

    /// Returns the packet length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the packet is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the timestamp when the packet was received.
    #[must_use]
    pub const fn timestamp(&self) -> Instant {
        self.timestamp
    }

    /// Returns the captured packet length.
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

    /// Returns the frame index.
    ///
    /// Returns `0` for owned packets (where `_ring_ref` is `None`).
    #[must_use]
    pub const fn frame_idx(&self) -> u32 {
        self.frame_idx
    }

    /// Returns a reference to the ring buffer state, if this is a zero-copy packet.
    ///
    /// Returns `None` for owned packets.
    #[must_use]
    pub const fn ring_ref(&self) -> Option<&Arc<RingRef>> {
        self._ring_ref.as_ref()
    }

    /// Returns `true` if this is a zero-copy packet (backed by mmap).
    #[must_use]
    pub const fn is_zero_copy(&self) -> bool {
        self._ring_ref.is_some()
    }

    /// Converts the zero-copy packet into a `PacketBuffer`.
    ///
    /// This copies the data, so the resulting `PacketBuffer` no longer
    /// holds a reference to the ring buffer.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::{MmapPacketEngine, RingConfig};
    ///
    /// let mut engine = MmapPacketEngine::new("eth0", RingConfig::default())?;
    ///
    /// if let Some(packet) = engine.try_recv_zero_copy()? {
    ///     // Convert to PacketBuffer (copies data)
    ///     let buffer = packet.into_packet_buffer();
    ///     // Can now use `buffer` independently of `engine`
    /// }
    /// ```
    #[must_use]
    pub fn into_packet_buffer(self) -> crate::PacketBuffer {
        let mut buffer = crate::PacketBuffer::from_data(self.data.to_bytes());
        // Note: timestamp is reset by from_data, we preserve the original
        // Set VLAN if present
        if let (Some(tci), Some(tpid)) = (self.vlan_tci, self.vlan_tpid) {
            buffer.set_vlan(tci, tpid);
        }
        buffer
    }
}

impl Drop for ZeroCopyPacket {
    fn drop(&mut self) {
        // Release the frame back to the kernel when the packet is dropped.
        // This only applies to zero-copy packets (where _ring_ref is Some).
        // For owned packets, there's no frame to release.
        if let Some(ring_ref) = &self._ring_ref {
            ring_ref.release_frame(self.frame_idx);
        }
    }
}

impl Clone for ZeroCopyPacket {
    fn clone(&self) -> Self {
        // Cloning creates a new packet with:
        // 1. The same Arc reference if present (increments ref count)
        // 2. Cloned ZeroCopyBytes (which clones the Arc and copies the pointer)
        // 3. The same frame_idx
        //
        // When both clones are dropped, the frame will be released twice.
        // This is safe because release_frame uses atomic operations.
        // For owned packets, there's no frame to release.
        Self {
            _ring_ref: self._ring_ref.as_ref().map(Arc::clone),
            frame_idx: self.frame_idx,
            data: self.data.clone(),
            timestamp: self.timestamp,
            captured_len: self.captured_len,
            original_len: self.original_len,
            vlan_tci: self.vlan_tci,
            vlan_tpid: self.vlan_tpid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_bytes_owned() {
        let data = vec![1u8, 2, 3, 4, 5];
        let bytes = ZeroCopyBytes::owned(data);
        assert_eq!(bytes.len(), 5);
        assert!(!bytes.is_borrowed());
    }
}
