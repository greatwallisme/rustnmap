//! Print exact bytes of TpacketReq

// Diagnostic example - expects undocumented unsafe blocks
// These are temporary test tools, not production code.
#![expect(clippy::undocumented_unsafe_blocks)]

use rustnmap_packet::sys::TpacketReq;
use std::mem;

fn main() {
    let req = TpacketReq::with_values(4096, 1, 2048, 2);

    println!("TpacketReq {{");
    println!(
        "  tp_block_size = {} (0x{:x})",
        req.tp_block_size, req.tp_block_size
    );
    println!(
        "  tp_block_nr  = {} (0x{:x})",
        req.tp_block_nr, req.tp_block_nr
    );
    println!(
        "  tp_frame_size = {} (0x{:x})",
        req.tp_frame_size, req.tp_frame_size
    );
    println!(
        "  tp_frame_nr  = {} (0x{:x})",
        req.tp_frame_nr, req.tp_frame_nr
    );
    println!("}}");
    println!("sizeof(TpacketReq) = {}", mem::size_of::<TpacketReq>());

    // Print raw bytes
    let p = &req as *const TpacketReq as *const u8;
    let bytes = unsafe { std::slice::from_raw_parts(p, mem::size_of::<TpacketReq>()) };
    print!("Raw bytes (little-endian): ");
    for b in bytes {
        print!("{:02x} ", b);
    }
    println!();
}
