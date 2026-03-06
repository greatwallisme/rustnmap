//! Error types for `PACKET_MMAP` operations.
//!
//! This module defines all error types used throughout the packet engine.

// Rust guideline compliant 2026-03-05

use std::io;

/// Error type for `PACKET_MMAP` operations.
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    /// Failed to create socket.
    #[error("failed to create socket: {0}")]
    SocketCreation(#[source] io::Error),

    /// Failed to set socket option.
    #[error("failed to set socket option {option}: {source}")]
    SocketOption {
        /// The name of the socket option.
        option: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Failed to bind to interface.
    #[error("failed to bind to interface '{interface}': {source}")]
    BindFailed {
        /// The interface name.
        interface: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Interface not found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// Invalid interface name.
    #[error("invalid interface name: {0}")]
    InvalidInterfaceName(String),

    /// Failed to get interface index.
    #[error("failed to get interface index for '{interface}': {source}")]
    InterfaceIndexFailed {
        /// The interface name.
        interface: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Failed to get MAC address.
    #[error("failed to get MAC address for '{interface}': {source}")]
    MacAddressFailed {
        /// The interface name.
        interface: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Failed to setup RX ring.
    #[error("failed to setup RX ring: {0}")]
    RxRingSetup(#[source] io::Error),

    /// Failed to setup TX ring.
    #[error("failed to setup TX ring: {0}")]
    TxRingSetup(#[source] io::Error),

    /// Failed to mmap ring buffer.
    #[error("failed to mmap ring buffer (size={size}): {source}")]
    MmapFailed {
        /// The requested ring buffer size.
        size: usize,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Failed to munmap ring buffer.
    #[error("failed to munmap ring buffer: {0}")]
    MunmapFailed(#[source] io::Error),

    /// Invalid ring configuration.
    #[error("invalid ring configuration: {0}")]
    InvalidConfig(String),

    /// Insufficient memory for ring buffer.
    #[error("insufficient memory for ring buffer (reduced to minimum)")]
    InsufficientMemory,

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

    /// Engine not started.
    #[error("engine not started")]
    NotStarted,

    /// Engine already started.
    #[error("engine already started")]
    AlreadyStarted,

    /// Engine stopped.
    #[error("engine stopped")]
    Stopped,

    /// Ring buffer setup failed.
    #[error("ring buffer setup failed after {attempts} attempts")]
    RingBufferSetupFailed {
        /// Number of attempts made.
        attempts: u32,
    },

    /// Ring buffer setup failed with I/O error.
    #[error("ring buffer setup failed: {0}")]
    RingBufferSetup(#[source] io::Error),

    /// No frame available.
    #[error("no frame available")]
    NoFrameAvailable,

    /// Invalid frame status.
    #[error("invalid frame status: {0}")]
    InvalidFrameStatus(u32),

    /// Channel send error.
    #[error("channel send error")]
    ChannelSend,

    /// Channel receive error.
    #[error("channel receive error")]
    ChannelReceive,

    /// Failed to duplicate file descriptor.
    #[error("failed to duplicate file descriptor: {0}")]
    FdDupFailed(#[source] io::Error),

    /// Failed to create `AsyncFd`.
    #[error("failed to create AsyncFd: {0}")]
    AsyncFdCreate(#[source] io::Error),

    /// Receiver stream ended.
    #[error("receiver stream ended")]
    StreamEnded,
}

impl PacketError {
    /// Creates a new socket option error.
    #[must_use]
    pub fn socket_option(option: impl Into<String>, source: io::Error) -> Self {
        Self::SocketOption {
            option: option.into(),
            source,
        }
    }

    /// Creates a new bind failed error.
    #[must_use]
    pub fn bind_failed(interface: impl Into<String>, source: io::Error) -> Self {
        Self::BindFailed {
            interface: interface.into(),
            source,
        }
    }

    /// Creates a new interface index failed error.
    #[must_use]
    pub fn interface_index_failed(interface: impl Into<String>, source: io::Error) -> Self {
        Self::InterfaceIndexFailed {
            interface: interface.into(),
            source,
        }
    }

    /// Creates a new MAC address failed error.
    #[must_use]
    pub fn mac_address_failed(interface: impl Into<String>, source: io::Error) -> Self {
        Self::MacAddressFailed {
            interface: interface.into(),
            source,
        }
    }

    /// Creates a new mmap failed error.
    #[must_use]
    pub fn mmap_failed(size: usize, source: io::Error) -> Self {
        Self::MmapFailed { size, source }
    }

    /// Returns `true` if this error indicates the engine is not started.
    #[must_use]
    pub const fn is_not_started(&self) -> bool {
        matches!(self, Self::NotStarted)
    }

    /// Returns `true` if this error indicates the engine is stopped.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Returns `true` if this error is recoverable by retrying.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NoFrameAvailable | Self::RingBufferSetupFailed { .. }
        )
    }
}

/// Result type for `PACKET_MMAP` operations.
pub type Result<T> = std::result::Result<T, PacketError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_error_display() {
        let err = PacketError::InterfaceNotFound("eth0".to_string());
        assert_eq!(err.to_string(), "interface not found: eth0");

        let err = PacketError::InvalidConfig("test".to_string());
        assert_eq!(err.to_string(), "invalid ring configuration: test");
    }

    #[test]
    fn test_packet_error_helpers() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test");
        let err = PacketError::socket_option("TEST", io_err);
        assert!(matches!(err, PacketError::SocketOption { .. }));

        let io_err = io::Error::new(io::ErrorKind::Other, "test");
        let err = PacketError::bind_failed("eth0", io_err);
        assert!(matches!(err, PacketError::BindFailed { .. }));
    }

    #[test]
    fn test_packet_error_predicates() {
        assert!(PacketError::NotStarted.is_not_started());
        assert!(!PacketError::Stopped.is_not_started());

        assert!(PacketError::Stopped.is_stopped());
        assert!(!PacketError::NotStarted.is_stopped());

        assert!(PacketError::NoFrameAvailable.is_retryable());
        assert!(!PacketError::NotStarted.is_retryable());
    }
}
