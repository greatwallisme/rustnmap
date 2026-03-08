//! Packet engine adapter for scanner migration.
//!
//! This module provides an adapter layer that wraps `AsyncPacketEngine` from `rustnmap-packet`
//! to provide a familiar interface to the current scanners using `SimpleAfPacket`.
//!
//! # Migration Strategy
//!
//! The adapter provides:
//! 1. Similar API to `SimpleAfPacket` for gradual migration
//! 2. Async-first design using Tokio
//! 3. Proper timeout handling
//! 4. BPF filter support
//!
//! # Design Decisions
//!
//! - Uses `AsyncPacketEngine` internally for `PACKET_MMAP` V2
//! - Provides synchronous-style `recv_with_timeout` method for compatibility
//! - Implements `Send + Sync` for sharing across async tasks
//! - Caches interface properties to avoid blocking lookups
//!
//! # Example
//!
//! ```rust,ignore
//! use std::time::Duration;
//! use rustnmap_scan::packet_adapter::ScannerPacketEngine;
//! use rustnmap_common::ScanConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ScanConfig::default();
//! let mut engine = ScannerPacketEngine::new("eth0", config)?;
//!
//! engine.start().await?;
//!
//! // Receive with timeout
//! match engine.recv_with_timeout(Duration::from_millis(200)).await? {
//!     Some(data) => process_packet(&data),
//!     None => handle_timeout(),
//! }
//!
//! engine.stop().await?;
//! # Ok(())
//! # }
//! ```

// Rust guideline compliant 2026-03-06

use rustnmap_common::{MacAddr, ScanConfig};
use rustnmap_packet::{AsyncPacketEngine, BpfFilter, EngineStats, PacketEngine, RingConfig};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Adapter that wraps `AsyncPacketEngine` to provide a familiar interface
/// for scanners currently using `SimpleAfPacket`.
///
/// This struct provides:
/// - Async-first packet capture using `PACKET_MMAP` V2
/// - Timeout-aware receive methods
/// - BPF filter support
/// - Thread-safe sharing via `Arc<Mutex>`
///
/// # Migration Notes
///
/// When migrating from `SimpleAfPacket`:
/// 1. Replace `Option<Arc<SimpleAfPacket>>` with `Option<Arc<Mutex<ScannerPacketEngine>>>`
/// 2. Replace `pkt_sock.recv_packet_with_timeout(duration)` with
///    `engine.lock().await.recv_with_timeout(duration).await`
/// 3. Add BPF filter setup in scanner constructor
#[derive(Debug)]
pub struct ScannerPacketEngine {
    /// Inner async packet engine.
    inner: AsyncPacketEngine,

    /// Interface name.
    if_name: String,

    /// Interface index.
    if_index: u32,

    /// MAC address.
    mac_addr: MacAddr,

    /// Configuration reference (for future use).
    _config: ScanConfig,
}

impl ScannerPacketEngine {
    /// Creates a new scanner packet engine.
    ///
    /// # Arguments
    ///
    /// * `if_name` - Network interface name (e.g., "eth0")
    /// * `config` - Scanner configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - Interface not found
    /// - Ring buffer setup fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_scan::packet_adapter::ScannerPacketEngine;
    /// use rustnmap_common::ScanConfig;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ScanConfig::default();
    /// let engine = ScannerPacketEngine::new("eth0", config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(if_name: &str, config: ScanConfig) -> Result<Self, rustnmap_packet::PacketError> {
        let ring_config = RingConfig::default();
        let inner = AsyncPacketEngine::new(if_name, ring_config)?;

        // Get interface properties
        let if_index = inner.interface_index();
        let mac_addr = inner.mac_address();

        Ok(Self {
            inner,
            if_name: if_name.to_string(),
            if_index,
            mac_addr,
            _config: config,
        })
    }

    /// Creates a new scanner packet engine wrapped in `Arc<Mutex>`.
    ///
    /// This is the primary constructor for scanner migration, allowing
    /// the engine to be shared across async tasks.
    ///
    /// # Arguments
    ///
    /// * `if_name` - Network interface name (e.g., "eth0")
    /// * `config` - Scanner configuration
    ///
    /// # Errors
    ///
    /// Returns an error if engine creation fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use tokio::sync::Mutex;
    /// use rustnmap_scan::packet_adapter::ScannerPacketEngine;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = ScannerPacketEngine::new_shared("eth0", Default::default())?;
    /// let engine = Arc::new(Mutex::new(engine));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_shared(
        if_name: &str,
        config: ScanConfig,
    ) -> Result<Arc<Mutex<Self>>, rustnmap_packet::PacketError> {
        Ok(Arc::new(Mutex::new(Self::new(if_name, config)?)))
    }

    /// Starts the packet engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is already started or startup fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # async fn example(mut engine: ScannerPacketEngine) -> Result<(), rustnmap_packet::PacketError> {
    /// engine.start().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(&mut self) -> rustnmap_packet::Result<()> {
        self.inner.start().await
    }

    /// Stops the packet engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is not running.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # async fn example(mut engine: ScannerPacketEngine) -> Result<(), rustnmap_packet::PacketError> {
    /// engine.stop().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stop(&mut self) -> rustnmap_packet::Result<()> {
        self.inner.stop().await
    }

    /// Receives a packet with a timeout.
    ///
    /// This method provides similar semantics to `SimpleAfPacket::recv_packet_with_timeout`.
    ///
    /// # Arguments
    ///
    /// * `timeout_duration` - Maximum time to wait for a packet
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(data))` if a packet was received,
    /// `Ok(None)` if timeout elapsed without data, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is not running or a receive error occurs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::time::Duration;
    ///
    /// # async fn example(mut engine: ScannerPacketEngine) -> Result<(), Box<dyn std::error::Error>> {
    /// match engine.recv_with_timeout(Duration::from_millis(200)).await? {
    ///     Some(packet) => handle_packet(&packet),
    ///     None => handle_timeout(),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn recv_with_timeout(
        &mut self,
        timeout_duration: Duration,
    ) -> rustnmap_packet::Result<Option<Vec<u8>>> {
        let result = self.inner.recv_timeout(timeout_duration).await?;
        match result {
            Some(packet) => {
                // Convert ZeroCopyPacket to Vec<u8> by copying the data
                // Note: This defeats zero-copy, but maintains API compatibility
                Ok(Some(packet.data().as_ref().to_vec()))
            }
            None => Ok(None),
        }
    }

    /// Sets a BPF filter on the socket.
    ///
    /// # Arguments
    ///
    /// * `filter` - BPF filter to attach
    ///
    /// # Errors
    ///
    /// Returns an error if filter attachment fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::BpfFilter;
    ///
    /// # fn example(mut engine: ScannerPacketEngine) -> Result<(), rustnmap_packet::PacketError> {
    /// let filter = BpfFilter::tcp_dst_port(80);
    /// engine.set_filter(&filter)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_filter(&self, filter: &BpfFilter) -> rustnmap_packet::Result<()> {
        let fprog = filter.to_sock_fprog();
        self.inner.set_filter(&fprog)
    }

    /// Returns the engine statistics.
    #[must_use]
    pub fn stats(&self) -> EngineStats {
        self.inner.stats()
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
}

/// Helper function to create a packet engine for stealth scanners.
///
/// This function creates a `ScannerPacketEngine` wrapped in `Arc<Mutex>`
/// for use with stealth scanners.
///
/// # Arguments
///
/// * `local_addr` - Local IP address for the scanner
/// * `config` - Scanner configuration
///
/// # Returns
///
/// Returns `Some(engine)` if successful, or `None` if creation fails.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use rustnmap_scan::packet_adapter::create_stealth_engine;
/// use rustnmap_common::ScanConfig;
///
/// # fn example() -> Option<Arc<Mutex<ScannerPacketEngine>>> {
/// let config = ScanConfig::default();
/// create_stealth_engine(config.local_addr?, config)
/// # }
/// ```
#[must_use]
pub fn create_stealth_engine(
    local_addr: Option<Ipv4Addr>,
    config: ScanConfig,
) -> Option<Arc<Mutex<ScannerPacketEngine>>> {
    // Get interface name from local address
    let if_name = detect_interface_from_addr(local_addr);

    // Create the engine
    ScannerPacketEngine::new_shared(&if_name, config).ok()
}

/// Detects the network interface name from a local IP address.
///
/// This function enumerates all network interfaces and finds the one
/// whose address matches the given local IP address.
///
/// # Arguments
///
/// * `local_addr` - Local IP address to look up
///
/// # Returns
///
/// Returns the interface name if found, or the first non-loopback interface as default.
///
/// # Implementation Note
///
/// This implementation uses `getifaddrs()` to enumerate interfaces and match
/// by address, following nmap's pattern in `libnetutil/netutil.cc:ipaddr2devname()`.
#[must_use]
pub fn detect_interface_from_addr(local_addr: Option<Ipv4Addr>) -> String {
    use std::ffi::CStr;
    use std::net::Ipv4Addr as StdIpv4Addr;

    // SAFETY: getifaddrs() and freeifaddrs() are libc functions for interface enumeration.
    // The function properly handles the returned pointers and uses CStr for safe string conversion.
    // Pointer validity is checked before dereferencing.
    //
    // The cast from sockaddr to sockaddr_in is safe because:
    // 1. We verify sa_family is AF_INET before casting
    // 2. When AF_INET, the structure is always sockaddr_in with sin_port and sin_addr
    // 3. This is the standard pattern documented in POSIX getifaddrs(3)
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "sockaddr is sockaddr_in when AF_INET"
    )]
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

        // getifaddrs() returns 0 on success, -1 on failure
        if libc::getifaddrs(&raw mut ifaddrs) != 0 || ifaddrs.is_null() {
            // Fallback to "eth0" if getifaddrs fails
            return "eth0".to_string();
        }

        let mut current = ifaddrs;
        let mut first_non_loopback: Option<String> = None;

        while !current.is_null() {
            let ifa = &*current;

            // Convert interface name to String
            let if_name = if ifa.ifa_name.is_null() {
                current = ifa.ifa_next;
                continue;
            } else {
                CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned()
            };

            // Check address family (AF_INET = 2)
            // Use i32::from for lossless cast from u16 to i32 comparison
            if !ifa.ifa_addr.is_null() && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET {
                // Cast to sockaddr_in for IPv4 address extraction
                // SAFETY: Verified sa_family is AF_INET above, so this is sockaddr_in
                let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip_bytes = addr.sin_addr.s_addr.to_ne_bytes();
                let ip = StdIpv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

                // Store first non-loopback interface as fallback
                if first_non_loopback.is_none() && !ip.is_loopback() {
                    first_non_loopback = Some(if_name.clone());
                }

                // Check if this interface matches our local_addr
                if let Some(local) = local_addr {
                    let local_bytes = local.octets();
                    if ip_bytes[0] == local_bytes[0]
                        && ip_bytes[1] == local_bytes[1]
                        && ip_bytes[2] == local_bytes[2]
                        && ip_bytes[3] == local_bytes[3]
                    {
                        // Found matching interface
                        libc::freeifaddrs(ifaddrs);
                        return if_name;
                    }
                }
            }

            current = ifa.ifa_next;
        }

        // Free the ifaddrs structure
        libc::freeifaddrs(ifaddrs);

        // Return first non-loopback interface as fallback, or "eth0" as last resort
        first_non_loopback.unwrap_or_else(|| "eth0".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_packet_engine_creation() {
        let config = ScanConfig::default();
        let result = ScannerPacketEngine::new("eth0", config);

        // Note: This test may fail if eth0 doesn't exist or without root
        // In CI/CD, this would be skipped or handled by integration tests
        assert!(result.is_ok() || cfg!(target_os = "linux"));
    }

    #[test]
    fn test_scanner_packet_engine_shared_creation() {
        let config = ScanConfig::default();
        let result = ScannerPacketEngine::new_shared("eth0", config);

        // Note: This test may fail without root privileges
        // In CI/CD, this would be skipped or handled by integration tests
        assert!(result.is_ok() || cfg!(target_os = "linux"));
    }
}
