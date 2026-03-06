//! `TPACKET_V2` structures and constants for zero-copy packet capture.
//!
//! This module provides `TPACKET_V2` ring buffer structures and constants
//! for zero-copy packet capture on Linux.

// Rust guideline compliant 2026-03-05

use super::TPACKET_ALIGNMENT;

/// `tpacket2_hdr` structure (32 bytes)
///
/// Reference: Linux kernel `include/uapi/linux/if_packet.h:146-157`
///
/// # Layout
///
/// | Offset | Size | Field            |
/// |--------|------|------------------|
/// | 0      | 4    | `tp_status`      |
/// | 4      | 4    | `tp_len`         |
/// | 8      | 4    | `tp_snaplen`     |
/// | 12     | 2    | `tp_mac`         |
/// | 14     | 2    | `tp_net`         |
/// | 16     | 4    | `tp_sec`         |
/// | 20     | 4    | `tp_nsec`        |
/// | 24     | 2    | `tp_vlan_tci`    |
/// | 26     | 2    | `tp_vlan_tpid`   |
/// | 28     | 4    | `tp_padding`     |
///
/// # Notes
///
/// - V2 uses `tp_nsec` (nanoseconds), NOT `tp_usec` (microseconds)
/// - `tp_padding` is `[u8; 4]`, NOT `[u8; 8]`
/// - Total size is 32 bytes, NOT 48 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tpacket2Hdr {
    /// Frame status (`TP_STATUS_*`)
    pub tp_status: u32,
    /// Packet length
    pub tp_len: u32,
    /// Captured length
    pub tp_snaplen: u32,
    /// MAC header offset
    pub tp_mac: u16,
    /// Network header offset
    pub tp_net: u16,
    /// Timestamp seconds
    pub tp_sec: u32,
    /// Timestamp nanoseconds (NOT `tp_usec`!)
    pub tp_nsec: u32,
    /// VLAN TCI
    pub tp_vlan_tci: u16,
    /// VLAN TPID
    pub tp_vlan_tpid: u16,
    /// Padding (4 bytes, NOT 8!)
    pub tp_padding: [u8; 4],
}

impl Tpacket2Hdr {
    /// Returns a frame data pointer (after header).
    #[must_use]
    pub const fn data_ptr(&self) -> *const u8 {
        std::ptr::from_ref(self).cast()
    }

    /// Returns a frame data length.
    #[must_use]
    pub const fn data_len(&self) -> usize {
        self.tp_snaplen as usize
    }

    /// Returns the frame status.
    #[must_use]
    pub const fn status(&self) -> u32 {
        self.tp_status
    }
}

/// `tpacket_req` structure for V2 ring buffer configuration
///
/// Reference: Linux kernel `include/uapi/linux/if_packet.h`
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TpacketReq {
    /// Block size in bytes
    pub tp_block_size: u32,
    /// Number of blocks
    pub tp_block_nr: u32,
    /// Frame size in bytes
    pub tp_frame_size: u32,
    /// Number of frames
    pub tp_frame_nr: u32,
}

impl TpacketReq {
    /// Creates a new `TpacketReq` with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tp_block_size: 0,
            tp_block_nr: 0,
            tp_frame_size: 0,
            tp_frame_nr: 0,
        }
    }

    /// Creates a new `TpacketReq` with the specified values.
    #[must_use]
    pub const fn with_values(
        block_size: u32,
        block_nr: u32,
        frame_size: u32,
        frame_nr: u32,
    ) -> Self {
        Self {
            tp_block_size: block_size,
            tp_block_nr: block_nr,
            tp_frame_size: frame_size,
            tp_frame_nr: frame_nr,
        }
    }
}

impl Default for TpacketReq {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for `TpacketReq` validation
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum TpacketReqError {
    /// Page size could not be determined
    #[error("Page size could not be determined")]
    PageSizeUnknown,

    /// Block size is not aligned to page size
    #[error("Block size is not a multiple of page size {page_size}")]
    BlockSizeNotPageAligned {
        /// Page size in bytes (for error messages)
        page_size: u32,
    },

    /// Frame size is not aligned to `TPACKET_ALIGNMENT`
    #[error("Frame size is not a multiple of TPACKET_ALIGNMENT ({tpacket_alignment})")]
    FrameSizeNotAligned {
        /// `TPACKET_ALIGNMENT` in bytes (for error messages)
        tpacket_alignment: u32,
    },

    /// Block count is zero
    #[error("Block count must not be zero")]
    BlockCountZero,

    /// Frame count is zero
    #[error("Frame count must not be zero")]
    FrameCountZero,

    /// Ring size calculation overflow
    #[error("Ring size calculation overflow")]
    RingSizeOverflow,
}

impl TpacketReq {
    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `block_size` is not a multiple of page size
    /// - `frame_size` is not a multiple of `TPACKET_ALIGNMENT`
    /// - `block_nr` is 0
    /// - `frame_nr` is 0
    pub fn validate(&self) -> Result<(), TpacketReqError> {
        // SAFETY: `sysconf(_SC_PAGESIZE)` is a read-only system call that returns
        // the system page size. It does not modify any state and is thread-safe.
        let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

        if page_size_raw <= 0 {
            return Err(TpacketReqError::PageSizeUnknown);
        }

        let page_size =
            u32::try_from(page_size_raw).map_err(|_overflow| TpacketReqError::PageSizeUnknown)?;

        // Block size must be a multiple of page size
        if !self.tp_block_size.is_multiple_of(page_size) {
            return Err(TpacketReqError::BlockSizeNotPageAligned { page_size });
        }

        // Frame size must be aligned to TPACKET_ALIGNMENT
        let alignment = u32::try_from(TPACKET_ALIGNMENT)
            .map_err(|_overflow| TpacketReqError::PageSizeUnknown)?;
        if !self.tp_frame_size.is_multiple_of(alignment) {
            return Err(TpacketReqError::FrameSizeNotAligned {
                tpacket_alignment: alignment,
            });
        }

        if self.tp_block_nr == 0 {
            return Err(TpacketReqError::BlockCountZero);
        }

        if self.tp_frame_nr == 0 {
            return Err(TpacketReqError::FrameCountZero);
        }

        Ok(())
    }

    /// Returns the total ring buffer size in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the calculation overflows.
    pub fn ring_size(&self) -> Result<usize, TpacketReqError> {
        let block_size = usize::try_from(self.tp_block_size)
            .map_err(|_overflow| TpacketReqError::RingSizeOverflow)?;
        let block_nr = usize::try_from(self.tp_block_nr)
            .map_err(|_overflow| TpacketReqError::RingSizeOverflow)?;

        block_size
            .checked_mul(block_nr)
            .ok_or(TpacketReqError::RingSizeOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpacket2_hdr_size() {
        assert_eq!(std::mem::size_of::<Tpacket2Hdr>(), 32);
    }

    #[test]
    fn test_tpacket_req_size() {
        assert_eq!(std::mem::size_of::<TpacketReq>(), 16);
    }

    #[test]
    fn test_tpacket_req_validate() {
        let req = TpacketReq::new();
        assert!(req.validate().is_err());

        let req = TpacketReq::with_values(4096, 2, 2048, 2048);
        req.validate().unwrap();

        // Invalid: block size not page aligned
        let req = TpacketReq::with_values(4095, 2, 2048, 2048);
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_tpacket2_hdr_fields() {
        let hdr = Tpacket2Hdr {
            tp_status: 1,
            tp_len: 2,
            tp_snaplen: 3,
            tp_mac: 4,
            tp_net: 5,
            tp_sec: 6,
            tp_nsec: 7,
            tp_vlan_tci: 8,
            tp_vlan_tpid: 9,
            tp_padding: [0, 1, 2, 3],
        };

        assert_eq!(hdr.tp_status, 1);
        assert_eq!(hdr.tp_len, 2);
        assert_eq!(hdr.tp_snaplen, 3);
        assert_eq!(hdr.tp_mac, 4);
        assert_eq!(hdr.tp_net, 5);
        assert_eq!(hdr.tp_sec, 6);
        assert_eq!(hdr.tp_nsec, 7);
        assert_eq!(hdr.tp_vlan_tci, 8);
        assert_eq!(hdr.tp_vlan_tpid, 9);
        assert_eq!(hdr.tp_padding, [0, 1, 2, 3]);
    }

    #[test]
    fn test_tpacket2_hdr_data_ptr() {
        let hdr = Tpacket2Hdr {
            tp_status: 1,
            tp_len: 2,
            tp_snaplen: 100,
            tp_mac: 0,
            tp_net: 14,
            tp_sec: 0,
            tp_nsec: 0,
            tp_vlan_tci: 0,
            tp_vlan_tpid: 0,
            tp_padding: [0; 4],
        };

        let data_ptr = hdr.data_ptr();
        assert_eq!(data_ptr, std::ptr::from_ref(&hdr).cast::<u8>());
    }

    #[test]
    fn test_tpacket2_hdr_data_len() {
        let hdr = Tpacket2Hdr {
            tp_status: 1,
            tp_len: 2,
            tp_snaplen: 100,
            tp_mac: 0,
            tp_net: 14,
            tp_sec: 0,
            tp_nsec: 0,
            tp_vlan_tci: 0,
            tp_vlan_tpid: 0,
            tp_padding: [0; 4],
        };
        assert_eq!(hdr.data_len(), 100);
    }
}
