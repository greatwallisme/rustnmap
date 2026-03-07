//! Packet stream implementation using `ReceiverStream`.
//!
//! This module provides `PacketStream`, a `Stream` implementation
//! that wraps a channel receiver for non-blocking packet delivery.
//!
//! # Design Rationale
//!
//! We use `ReceiverStream` from `tokio-stream` instead of implementing
//! `Stream` directly to avoid busy-spin patterns. The `ReceiverStream`
//! properly yields when the channel is empty, allowing the async runtime
//! to schedule other tasks.
//!
//! # Example
//!
//! ```rust,ignore
//! use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};
//! use tokio_stream::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), rustnmap_packet::PacketError> {
//!     let config = RingConfig::default();
//!     let mut engine = AsyncPacketEngine::new("eth0", config)?;
//!
//!     engine.start().await?;
//!
//!     // Convert to stream
//!     let mut stream = engine.into_stream();
//!
//!     while let Some(result) = stream.next().await {
//!         let packet = result?;
//!         // Process packet
//!     }
//!
//!     Ok(())
//! }
//! ```

// Rust guideline compliant 2026-03-06

use crate::engine::Result;
use crate::zero_copy::ZeroCopyPacket;
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::wrappers::ReceiverStream;

/// Packet stream wrapping a channel receiver.
///
/// This struct implements `Stream` for ergonomic packet processing.
/// It uses `ReceiverStream` internally to avoid busy-spin patterns.
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_packet::{AsyncPacketEngine, RingConfig, PacketEngine};
/// use tokio_stream::StreamExt;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustnmap_packet::PacketError> {
///     let config = RingConfig::default();
///     let mut engine = AsyncPacketEngine::new("eth0", config)?;
///
///     engine.start().await?;
///
///     // Convert to stream
///     let mut stream = engine.into_stream();
///
///     while let Some(result) = stream.next().await {
///         let packet = result?;
///         // Process packet
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct PacketStream {
    /// Inner receiver stream.
    inner: ReceiverStream<Result<ZeroCopyPacket>>,
}

impl PacketStream {
    /// Creates a new packet stream from a receiver.
    #[must_use]
    pub fn new(receiver: tokio::sync::mpsc::Receiver<Result<ZeroCopyPacket>>) -> Self {
        Self {
            inner: ReceiverStream::new(receiver),
        }
    }

    /// Returns the inner receiver for manual control.
    #[must_use]
    pub fn into_inner(self) -> tokio::sync::mpsc::Receiver<Result<ZeroCopyPacket>> {
        self.inner.into_inner()
    }
}

impl Stream for PacketStream {
    type Item = Result<ZeroCopyPacket>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Delegate to ReceiverStream, which has correct readiness semantics
        // This avoids busy-spin by properly yielding when channel is empty
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_stream_new() {
        let (_, rx) = tokio::sync::mpsc::channel::<Result<ZeroCopyPacket>>(1);
        let stream = PacketStream::new(rx);
        drop(stream); // Just verify it can be created
    }
}
