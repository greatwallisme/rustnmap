//! Network primitives and socket abstractions for `RustNmap`.
//!
//! This crate provides low-level network access including raw socket creation,
//! packet I/O, and network interface management.

#![warn(missing_docs)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "Dependency version conflict in transitive deps"
)]

use rustnmap_common::Result;

/// Creates a raw socket for packet capture and injection.
///
/// # Errors
///
/// Returns an error if the socket cannot be created due to insufficient permissions
/// or system limitations.
pub fn create_raw_socket() -> Result<raw_socket::RawSocket> {
    raw_socket::RawSocket::new()
}

/// Raw socket module for Linux packet I/O.
pub mod raw_socket {
    use std::os::fd::OwnedFd;

    /// Raw socket handle for packet I/O.
    #[derive(Debug)]
    pub struct RawSocket {
        /// The owned file descriptor for the socket.
        #[expect(
            dead_code,
            reason = "File descriptor will be used when implementing send/recv"
        )]
        fd: OwnedFd,
    }

    impl RawSocket {
        /// Creates a new raw socket.
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - The process lacks `CAP_NET_RAW` capability
        /// - The system runs out of file descriptors
        /// - The socket protocol is not supported
        pub fn new() -> super::Result<Self> {
            use rustnmap_common::error::NetworkError;
            use rustnmap_common::Error;
            use socket2::{Domain, Protocol, Type};

            // Use IP protocol 0 for raw IP packet capture
            let socket = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0)))
                .map_err(|e| Error::Network(NetworkError::RawSocketCreation { source: e }))?;

            Ok(Self { fd: socket.into() })
        }
    }
}
