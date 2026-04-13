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

//! Async packet engine using Tokio AsyncFd.
//!
//! This module provides `AsyncPacketEngine`, a Tokio-compatible async wrapper
//! around `MmapPacketEngine` for non-blocking packet capture.
//!
//! # Architecture
//!
//! The async engine uses:
//! - `AsyncFd<OwnedFd>` for non-blocking socket notifications
//! - `mpsc` channels for packet distribution
//! - Background task for ring buffer polling
//!
//! # Key Design Decisions
//!
//! 1. **AsyncFd is not Clone**: We use `Arc<AsyncFd<OwnedFd>>` for sharing
//! 2. **fd ownership**: We use `libc::dup()` to duplicate the fd for AsyncFd
//!    to avoid double-close issues
//! 3. **Engine sharing**: We use `Arc<Mutex<>>` for the engine in background tasks
//!    (not raw pointers)
//!
//! # Example
//!
//! ```rust,ignore
//! use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), rustnmap_packet::PacketError> {
//!     let config = RingConfig::default();
//!     let mut engine = AsyncPacketEngine::new("eth0", config)?;
//!
//!     engine.start().await?;
//!
//!     while let Some(packet) = engine.recv().await? {
//!         // Process packet
//!         let _len = packet.len();
//!     }
//!
//!     engine.stop().await?;
//!     Ok(())
//! }
//! ```

// Rust guideline compliant 2026-03-06

use crate::engine::{EngineStats, PacketEngine, Result, RingConfig};
use crate::error::PacketError;
use crate::mmap::MmapPacketEngine;
use crate::zero_copy::ZeroCopyPacket;
use async_trait::async_trait;
use rustnmap_common::MacAddr;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::io::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Ready;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

/// Channel size for packet distribution.
///
/// This value provides a reasonable buffer for async packet processing
/// without excessive memory usage.
const CHANNEL_SIZE: usize = 1024;

/// Async packet engine with Tokio integration.
///
/// This struct wraps `MmapPacketEngine` with Tokio's `AsyncFd` for
/// non-blocking packet capture. Packets are received via channels.
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustnmap_packet::PacketError> {
///     let config = RingConfig::default();
///     let mut engine = AsyncPacketEngine::new("eth0", config)?;
///
///     engine.start().await?;
///
///     while let Some(packet) = engine.recv().await? {
///         // Process packet
///         let _len = packet.len();
///     }
///
///     engine.stop().await?;
///     Ok(())
/// }
/// ```
///
/// # Design Notes
///
/// - Uses `Arc<AsyncFd<OwnedFd>>` because `AsyncFd` is not `Clone`
/// - Uses `libc::dup()` to duplicate fd for `AsyncFd` ownership
/// - Uses `Arc<Mutex<>>` for engine in background tasks (not raw pointers)
/// - Uses channels for packet distribution (avoiding busy-spin)
/// - Caches interface properties to avoid blocking in async context
#[derive(Debug)]
pub struct AsyncPacketEngine {
    /// Inner mmap engine wrapped in Arc<Mutex> for sharing across tasks.
    engine: Arc<Mutex<MmapPacketEngine>>,

    /// `AsyncFd` for non-blocking socket notifications.
    /// Wrapped in Arc because `AsyncFd` is not Clone.
    async_fd: Arc<AsyncFd<OwnedFd>>,

    /// Packet sender channel.
    packet_tx: Sender<Result<ZeroCopyPacket>>,

    /// Packet receiver channel.
    packet_rx: Receiver<Result<ZeroCopyPacket>>,

    /// Running state flag.
    running: Arc<AtomicBool>,

    /// Engine statistics (cached from inner engine).
    stats: Arc<Mutex<EngineStats>>,

    /// Cached interface name (to avoid blocking in async context).
    if_name: String,

    /// Cached interface index.
    if_index: u32,

    /// Cached MAC address.
    mac_addr: MacAddr,
}

impl AsyncPacketEngine {
    /// Creates a new async packet engine.
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
    /// - fd duplication fails
    /// - `AsyncFd` creation fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::{AsyncPacketEngine, RingConfig};
    ///
    /// # fn example() -> Result<(), rustnmap_packet::PacketError> {
    /// let config = RingConfig::default();
    /// let engine = AsyncPacketEngine::new("eth0", config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(if_name: &str, config: RingConfig) -> Result<Self> {
        // Create the mmap engine
        let engine = MmapPacketEngine::new(if_name, config)?;

        // Cache interface properties before wrapping in Arc<Mutex>
        let if_index = engine.interface_index();
        let mac_addr = engine.mac_address();
        let if_name_owned = engine.interface_name().to_string();

        // CRITICAL: Duplicate the fd for AsyncFd ownership.
        // We cannot use the fd directly because MmapPacketEngine owns it.
        // Using the same fd would cause double-close issues.
        // SAFETY: dup() duplicates the file descriptor.
        let dup_fd = unsafe { libc::dup(engine.as_raw_fd()) };
        if dup_fd < 0 {
            return Err(PacketError::FdDupFailed(io::Error::last_os_error()));
        }

        // SAFETY: dup_fd is valid and owned by us. OwnedFd takes ownership.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };

        // Create AsyncFd for non-blocking notifications
        let async_fd = AsyncFd::new(owned_fd).map_err(PacketError::AsyncFdCreate)?;

        // Create channels for packet distribution
        let (packet_tx, packet_rx) = channel(CHANNEL_SIZE);

        Ok(Self {
            engine: Arc::new(Mutex::new(engine)),
            async_fd: Arc::new(async_fd),
            packet_tx,
            packet_rx,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(EngineStats::default())),
            if_name: if_name_owned,
            if_index,
            mac_addr,
        })
    }

    /// Starts the engine without spawning the background receiver task.
    ///
    /// This is for callers that want to read packets directly from the ring
    /// buffer using `try_recv_direct()` instead of receiving through the
    /// bounded channel. The background task would compete for the same ring
    /// buffer frames, so it must not be spawned when direct reads are used.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is already started or startup fails.
    pub async fn start_no_background(&mut self) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            return Err(PacketError::AlreadyStarted);
        }

        // Start the inner engine
        let mut engine = self.engine.lock().await;
        engine.start().await?;

        self.running.store(true, Ordering::Release);
        Ok(())
    }

    /// Returns a reference to the packet receiver for stream conversion.
    ///
    /// This method is used internally by `into_stream()` and can be used
    /// to get the receiver without consuming the engine.
    #[must_use]
    pub fn receiver(&self) -> &Receiver<Result<ZeroCopyPacket>> {
        &self.packet_rx
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

    /// Receives a packet with a timeout.
    ///
    /// This method is similar to `recv()` but returns `Ok(None)` if no
    /// packet is received within the specified timeout duration.
    ///
    /// # Arguments
    ///
    /// * `timeout_duration` - Maximum time to wait for a packet
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The engine is not running
    /// - A packet receive error occurs
    /// - The timeout elapses (returns `Ok(None)`)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::time::Duration;
    /// use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};
    ///
    /// # async fn example(mut engine: AsyncPacketEngine) -> Result<(), rustnmap_packet::PacketError> {
    /// engine.start().await?;
    ///
    /// match engine.recv_timeout(Duration::from_millis(200)).await? {
    ///     Some(packet) => process(packet),
    ///     None => handle_timeout(),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn recv_timeout(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<Option<ZeroCopyPacket>> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        // Use tokio::time::timeout to wrap the channel receive
        match timeout(timeout_duration, self.packet_rx.recv()).await {
            Ok(Some(result)) => result.map(Some),
            Ok(None) | Err(_) => Ok(None), // Channel closed or timeout elapsed
        }
    }

    /// Reads a packet directly from the `PACKET_MMAP` ring buffer.
    ///
    /// This bypasses the bounded channel and background task entirely,
    /// providing the lowest possible latency for time-critical operations
    /// like port scanning where probe timeout accuracy is essential.
    ///
    /// The background task may also be reading from the ring buffer concurrently,
    /// so this method uses the same mutex to serialize access.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is not started or a receive error occurs.
    pub async fn try_recv_direct(&self) -> Result<Option<ZeroCopyPacket>> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        let mut engine = self.engine.lock().await;
        engine.try_recv_zero_copy()
    }

    /// Converts the engine into a packet stream.
    ///
    /// This method consumes the receiver and returns a `PacketStream`
    /// for ergonomic async iteration.
    ///
    /// # Note
    ///
    /// The engine must be started before converting to a stream.
    /// The stream will end when the engine is stopped or an error occurs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};
    /// use tokio_stream::StreamExt;
    ///
    /// # async fn example() -> Result<(), rustnmap_packet::PacketError> {
    /// let config = RingConfig::default();
    /// let mut engine = AsyncPacketEngine::new("eth0", config)?;
    /// engine.start().await?;
    ///
    /// let mut stream = engine.into_stream();
    ///
    /// while let Some(result) = stream.next().await {
    ///     let packet = result?;
    ///     // Process packet
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn into_stream(self) -> crate::stream::PacketStream {
        crate::stream::PacketStream::new(self.packet_rx)
    }
}

#[async_trait]
impl PacketEngine for AsyncPacketEngine {
    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            return Err(PacketError::AlreadyStarted);
        }

        // Start the inner engine
        let mut engine = self.engine.lock().await;
        engine.start().await?;

        self.running.store(true, Ordering::Release);

        // Clone handles for the background task
        let engine = Arc::clone(&self.engine);
        let async_fd = Arc::clone(&self.async_fd);
        let packet_tx = self.packet_tx.clone();
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);

        // Spawn background receiver task
        tokio::spawn(async move {
            while running.load(Ordering::Acquire) {
                // Wait for socket to be readable
                match async_fd.readable().await {
                    Ok(mut ready_guard) => {
                        // Try to receive packets while socket is readable
                        let mut received_any = false;

                        loop {
                            // Try to receive a packet without blocking (zero-copy)
                            let result = {
                                let mut engine_guard = engine.lock().await;
                                engine_guard.try_recv_zero_copy()
                            };

                            match result {
                                Ok(Some(packet)) => {
                                    received_any = true;

                                    // Update stats
                                    let mut stats_guard = stats.lock().await;
                                    stats_guard.packets_received += 1;
                                    stats_guard.bytes_received += packet.len() as u64;

                                    // Send packet through channel
                                    if packet_tx.send(Ok(packet)).await.is_err() {
                                        // Channel closed, stop receiving
                                        running.store(false, Ordering::Release);
                                        return;
                                    }
                                }
                                Ok(None) => {
                                    // No more packets available
                                    break;
                                }
                                Err(e) => {
                                    // Send error through channel
                                    if packet_tx.send(Err(e)).await.is_err() {
                                        running.store(false, Ordering::Release);
                                        return;
                                    }
                                    break;
                                }
                            }
                        }

                        // Clear the readiness if we received something
                        if received_any {
                            ready_guard.clear_ready_matching(Ready::READABLE);
                        }
                    }
                    Err(e) => {
                        // AsyncFd error, send through channel
                        let _ = packet_tx
                            .send(Err(PacketError::SocketOption {
                                option: "async_fd.readable".to_string(),
                                source: e,
                            }))
                            .await;
                        running.store(false, Ordering::Release);
                        return;
                    }
                }
            }
        });

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<ZeroCopyPacket>> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        // Receive from channel
        match self.packet_rx.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    async fn send(&self, packet: &[u8]) -> Result<usize> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        // Forward to inner engine
        let engine = self.engine.lock().await;
        engine.send(packet).await
    }

    async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(PacketError::NotStarted);
        }

        self.running.store(false, Ordering::Release);

        // Stop the inner engine
        let mut engine = self.engine.lock().await;
        engine.stop().await
    }

    fn stats(&self) -> EngineStats {
        // Try to get stats without blocking (best effort)
        // If we can't get the lock immediately, return cached stats
        match self.stats.try_lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                // Return a copy from the inner engine as fallback
                futures::executor::block_on(async { self.engine.lock().await.stats() })
            }
        }
    }

    fn flush(&self) -> Result<()> {
        // Forward to inner engine (blocking)
        let engine = futures::executor::block_on(self.engine.lock());
        engine.flush()
    }

    fn set_filter(&self, filter: &libc::sock_fprog) -> Result<()> {
        // Forward to inner engine (blocking)
        let engine = futures::executor::block_on(self.engine.lock());
        engine.set_filter(filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_size() {
        assert_eq!(CHANNEL_SIZE, 1024);
    }
}
