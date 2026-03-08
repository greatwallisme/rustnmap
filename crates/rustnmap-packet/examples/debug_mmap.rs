//! Debug test to see exact values passed to PACKET_RX_RING

// Diagnostic example - expects undocumented unsafe blocks
// These are temporary test tools, not production code.
#![expect(clippy::undocumented_unsafe_blocks)]

use rustnmap_packet::sys::TpacketReq;
use std::ffi::c_void;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::io::OwnedFd;

fn main() {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
    println!("Page size: {}", page_size);

    // Test 1: Minimal valid config following nmap's calculation
    println!("\n=== Test 1: nmap-style calculation ===");
    let frame_size = 2048u32;
    let buffer_size = 2 * 1024 * 1024u32; // 2MB default

    // nmap calculates tp_frame_nr first
    let tp_frame_nr = (buffer_size + frame_size - 1) / frame_size;
    println!("tp_frame_nr (calculated from buffer_size): {}", tp_frame_nr);

    // Then calculates tp_block_size
    let mut tp_block_size = page_size;
    while tp_block_size < frame_size {
        tp_block_size <<= 1;
    }
    println!("tp_block_size: {}", tp_block_size);

    // Then frames_per_block
    let frames_per_block = tp_block_size / frame_size;
    println!("frames_per_block: {}", frames_per_block);

    // Then tp_block_nr
    let tp_block_nr = tp_frame_nr / frames_per_block;
    println!("tp_block_nr (calculated): {}", tp_block_nr);

    // Then RECALCULATES tp_frame_nr for consistency
    let tp_frame_nr = tp_block_nr * frames_per_block;
    println!("tp_frame_nr (recalculated): {}", tp_frame_nr);

    let req = TpacketReq::with_values(tp_block_size, tp_block_nr, frame_size, tp_frame_nr);
    print_req(&req);

    match test_setsockopt(&req) {
        Ok(_) => println!("SUCCESS!"),
        Err(e) => println!("FAILED: {}", e),
    }

    // Test 2: Our original calculation
    println!("\n=== Test 2: Original calculation ===");
    let block_size = 4096u32;
    let block_nr = 64u32;
    let frame_size = 2048u32;
    let frame_nr = block_size / frame_size * block_nr;
    println!(
        "block_size: {}, block_nr: {}, frame_size: {}, frame_nr: {}",
        block_size, block_nr, frame_size, frame_nr
    );

    let req = TpacketReq::with_values(block_size, block_nr, frame_size, frame_nr);
    print_req(&req);

    match test_setsockopt(&req) {
        Ok(_) => println!("SUCCESS!"),
        Err(e) => println!("FAILED: {}", e),
    }

    // Test 3: Simple page-aligned config
    println!("\n=== Test 3: Simple page-aligned ===");
    let block_size = page_size;
    let block_nr = 1u32;
    let frame_size = 2048u32;
    let frames_per_block = block_size / frame_size;
    let frame_nr = frames_per_block * block_nr;
    println!(
        "block_size: {}, block_nr: {}, frame_size: {}, frame_nr: {}",
        block_size, block_nr, frame_size, frame_nr
    );

    let req = TpacketReq::with_values(block_size, block_nr, frame_size, frame_nr);
    print_req(&req);

    match test_setsockopt(&req) {
        Ok(_) => println!("SUCCESS!"),
        Err(e) => println!("FAILED: {}", e),
    }
}

fn print_req(req: &TpacketReq) {
    println!("TpacketReq:");
    println!("  tp_block_size: {}", req.tp_block_size);
    println!("  tp_block_nr: {}", req.tp_block_nr);
    println!("  tp_frame_size: {}", req.tp_frame_size);
    println!("  tp_frame_nr: {}", req.tp_frame_nr);
    println!("  sizeof(TpacketReq): {}", mem::size_of::<TpacketReq>());
    println!(
        "  ring_size: {} bytes",
        req.tp_block_size as usize * req.tp_block_nr as usize
    );
}

fn test_setsockopt(req: &TpacketReq) -> Result<(), io::Error> {
    use rustnmap_packet::sys::{AF_PACKET, PACKET_RX_RING, PACKET_VERSION, SOCK_RAW, TPACKET_V2};

    // Create socket
    let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Set PACKET_VERSION (MUST be first)
    let version = TPACKET_V2;
    let result = unsafe {
        libc::setsockopt(
            owned_fd.as_raw_fd(),
            libc::SOL_PACKET,
            PACKET_VERSION,
            std::ptr::from_ref(&version).cast::<c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // CRITICAL: Bind to interface with protocol=0 BEFORE PACKET_RX_RING
    // This is required by the kernel (following nmap's libpcap pattern)
    let if_name = std::ffi::CString::new("ens33").unwrap();
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    let bytes = if_name.as_bytes_with_nul();
    for (i, &b) in bytes.iter().enumerate() {
        ifreq.ifr_name[i] = i8::try_from(b).unwrap();
    }

    // Get interface index
    let ctl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if ctl_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let ioctl_result = unsafe { libc::ioctl(ctl_fd, libc::SIOCGIFINDEX, &ifreq) };
    unsafe { libc::close(ctl_fd) };
    if ioctl_result < 0 {
        return Err(io::Error::last_os_error());
    }
    let if_index = unsafe { ifreq.ifr_ifru.ifru_ifindex } as u32;

    // Bind with protocol=0
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = 0; // CRITICAL: protocol=0 for initial bind
    addr.sll_ifindex = if_index as i32;

    let bind_result = unsafe {
        libc::bind(
            owned_fd.as_raw_fd(),
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_result < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("bind failed: {}", io::Error::last_os_error()),
        ));
    }

    // Now try PACKET_RX_RING
    let result = unsafe {
        libc::setsockopt(
            owned_fd.as_raw_fd(),
            libc::SOL_PACKET,
            PACKET_RX_RING,
            std::ptr::from_ref::<TpacketReq>(req).cast::<c_void>(),
            mem::size_of::<TpacketReq>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let err = io::Error::last_os_error();
        Err(err)
    } else {
        Ok(())
    }
}
