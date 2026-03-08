//! Minimal test for recv() to reproduce SIGSEGV

use rustnmap_packet::{MmapPacketEngine, PacketEngine, RingConfig};
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("Testing recv() call...");

    // Test with larger frame_size to avoid potential alignment issues
    let config = RingConfig {
        block_size: 4096,
        block_nr: 1,
        frame_size: 4096, // Larger frame size
        frame_timeout: 64,
        enable_rx: true,
        enable_tx: false,
    };

    println!("Creating engine on ens33...");
    let mut engine = match MmapPacketEngine::new("ens33", config) {
        Ok(e) => e,
        Err(e) => {
            println!("Failed to create engine: {e}");
            return;
        }
    };

    println!("Starting engine...");
    if let Err(e) = engine.start().await {
        println!("Failed to start engine: {e}");
        return;
    }

    println!("Engine started. Calling recv()...");

    // Try to receive multiple packets to reproduce SIGSEGV
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    let mut packet_count = 0u64;

    loop {
        println!("DEBUG: Calling recv(), packet_count = {}", packet_count);
        // Print engine state before recv
        // Note: We can't access private fields directly, so we'll infer from behavior
        match engine.recv().await {
            Ok(Some(packet)) => {
                println!(
                    "Received packet {}: {} bytes",
                    packet_count + 1,
                    packet.len()
                );
                packet_count += 1;
                // Continue to next recv() call immediately
                if packet_count >= 5 {
                    println!("Received 5 packets, stopping");
                    break;
                }
            }
            Ok(None) => {
                println!("No packet available (this is expected if no traffic)");
            }
            Err(e) => {
                println!("recv() error: {e}");
                break;
            }
        }

        if start.elapsed() > timeout {
            println!("Timeout after 5 seconds");
            break;
        }

        // Small delay to avoid busy waiting
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!(
        "Test completed successfully! Total packets: {}",
        packet_count
    );
}
