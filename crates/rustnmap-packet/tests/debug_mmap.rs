// Debug test for PACKET_MMAP
use rustnmap_packet::{MmapPacketEngine, RingConfig};

#[test]
fn debug_mmap_creation() {
    let if_name = "ens33";
    let config = RingConfig::new(4096, 1, 512);
    
    println!("Testing MmapPacketEngine::new() with minimal config...");
    println!("Interface: {}", if_name);
    println!("Config: block_size={}, block_nr={}, frame_size={}", 
        config.block_size, config.block_nr, config.frame_size);
    
    match MmapPacketEngine::new(if_name, config) {
        Ok(_engine) => {
            println!("✓ MmapPacketEngine created successfully!");
        }
        Err(e) => {
            println!("✗ MmapPacketEngine::new() failed:");
            println!("  Error: {:?}", e);
            println!("  Display: {}", e);
            
            // Check for specific errors
            let err_str = format!("{:?}", e);
            if err_str.contains("22") || err_str.contains("EINVAL") || err_str.contains("InvalidInput") {
                println!("  Contains errno=22 (EINVAL) indication");
            }
            if err_str.contains("RxRing") {
                println!("  Error from PACKET_RX_RING setup");
            }
        }
    }
}
