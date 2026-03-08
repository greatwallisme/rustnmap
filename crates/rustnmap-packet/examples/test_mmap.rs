// Diagnostic example - expects undocumented unsafe blocks
// These are temporary test tools, not production code.
#![expect(clippy::undocumented_unsafe_blocks)]

use rustnmap_packet::{MmapPacketEngine, PacketEngine, RingConfig};

fn print_config(config: &RingConfig) {
    println!("  block_size: {}", config.block_size);
    println!("  block_nr: {}", config.block_nr);
    println!("  frame_size: {}", config.frame_size);
    println!("  frame_timeout: {}", config.frame_timeout);
    println!("  enable_rx: {}", config.enable_rx);
    println!("  enable_tx: {}", config.enable_tx);
}

fn main() {
    println!("Testing MmapPacketEngine creation with various configs...\n");

    // Test 1: Small config
    println!("Test 1: Small config");
    let config = RingConfig {
        block_size: 4096,
        block_nr: 64,
        frame_size: 2048,
        frame_timeout: 64,
        enable_rx: true,
        enable_tx: false,
    };
    print_config(&config);
    match MmapPacketEngine::new("ens33", config) {
        Ok(_) => println!("  SUCCESS!"),
        Err(e) => println!("  FAILED: {e}\n"),
    }

    // Test 2: Default config
    println!("\nTest 2: Default config");
    let config = RingConfig::default();
    print_config(&config);
    match MmapPacketEngine::new("ens33", config) {
        Ok(mut engine) => {
            println!("  SUCCESS! Starting engine...");
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                match engine.start().await {
                    Ok(_) => println!("  Engine started successfully!"),
                    Err(e) => println!("  Engine start failed: {e}"),
                }
            });
        }
        Err(e) => println!("  FAILED: {e}\n"),
    }

    // Test 3: Minimal config
    println!("\nTest 3: Minimal config (page-aligned)");
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
    let config = RingConfig {
        block_size: page_size,
        block_nr: 1,
        frame_size: 2048,
        frame_timeout: 64,
        enable_rx: true,
        enable_tx: false,
    };
    print_config(&config);
    match MmapPacketEngine::new("ens33", config) {
        Ok(_) => println!("  SUCCESS!"),
        Err(e) => println!("  FAILED: {e}\n"),
    }
}
