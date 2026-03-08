//! Print exact constant values

fn main() {
    println!("Constant values in Rust:");
    println!("  AF_PACKET = {}", libc::AF_PACKET);
    println!("  SOCK_RAW = {}", libc::SOCK_RAW);
    println!("  SOL_PACKET = {}", libc::SOL_PACKET);
    println!("  PACKET_VERSION (10) = {}", 10);
    println!("  PACKET_RESERVE (12) = {}", 12);
    println!("  PACKET_AUXDATA (8) = {}", 8);
    println!("  PACKET_RX_RING (5) = {}", 5);
    println!("  TPACKET_V2 = {}", 2);
    println!("  ETH_P_ALL = {}", 0x0003u16);

    // Compare with our constants
    use rustnmap_packet::sys::*;
    println!("\nOur constants:");
    println!("  AF_PACKET = {}", AF_PACKET);
    println!("  SOCK_RAW = {}", SOCK_RAW);
    println!("  PACKET_VERSION = {}", PACKET_VERSION);
    println!("  PACKET_RESERVE = {}", PACKET_RESERVE);
    println!("  PACKET_AUXDATA = {}", PACKET_AUXDATA);
    println!("  PACKET_RX_RING = {}", PACKET_RX_RING);
    println!("  TPACKET_V2 = {}", TPACKET_V2);
    println!("  ETH_P_ALL = {:x}", ETH_P_ALL);
}
