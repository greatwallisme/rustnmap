//! Debug test using libc constants directly

// Diagnostic example - expects undocumented unsafe blocks
// These are temporary test tools, not production code.
#![expect(clippy::undocumented_unsafe_blocks, reason = "debug example code")]

use std::ffi::c_void;
use std::io;
use std::mem;

fn main() {
    println!("Using libc constants directly...");

    println!("Step 1: Creating socket...");
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        println!("  FAILED: {}", io::Error::last_os_error());
        return;
    }
    println!("  OK (fd={})", fd);

    println!("Step 2: Setting PACKET_VERSION = 1 (TPACKET_V2)...");
    let version = 1i32;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            10, // PACKET_VERSION
            std::ptr::from_ref(&version).cast::<c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        println!("  FAILED: {}", io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return;
    }
    println!("  OK");

    println!("Step 3: Setting PACKET_RESERVE = 4...");
    let reserve = 4i32;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            12, // PACKET_RESERVE (NOTE: this might be wrong!)
            std::ptr::from_ref(&reserve).cast::<c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        println!("  FAILED: {}", io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return;
    }
    println!("  OK");

    println!("Step 4: Getting interface index for ens33...");
    let if_name = std::ffi::CString::new("ens33").unwrap();
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    let bytes = if_name.as_bytes_with_nul();
    for (i, &b) in bytes.iter().enumerate() {
        ifreq.ifr_name[i] = i8::try_from(b).unwrap();
    }

    let ctl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if ctl_fd < 0 {
        println!(
            "  FAILED to create control socket: {}",
            io::Error::last_os_error()
        );
        unsafe { libc::close(fd) };
        return;
    }
    let ioctl_result = unsafe { libc::ioctl(ctl_fd, libc::SIOCGIFINDEX, &ifreq) };
    unsafe { libc::close(ctl_fd) };
    if ioctl_result < 0 {
        println!("  FAILED: {}", io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return;
    }
    let if_index = unsafe { ifreq.ifr_ifru.ifru_ifindex };
    println!("  if_index = {}", if_index);

    println!("Step 5: Binding to interface with protocol=0...");
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = 0;
    addr.sll_ifindex = if_index;

    let bind_result = unsafe {
        libc::bind(
            fd,
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if bind_result < 0 {
        println!("  FAILED: {}", io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return;
    }
    println!("  OK");

    println!("Step 6: Setting up PACKET_RX_RING...");
    #[repr(C)]
    struct TpacketReq {
        tp_block_size: u32,
        tp_block_nr: u32,
        tp_frame_size: u32,
        tp_frame_nr: u32,
    }

    let req = TpacketReq {
        tp_block_size: 4096,
        tp_block_nr: 1,
        tp_frame_size: 2048,
        tp_frame_nr: 2,
    };
    println!(
        "  block_size={} block_nr={} frame_size={} frame_nr={}",
        req.tp_block_size, req.tp_block_nr, req.tp_frame_size, req.tp_frame_nr
    );

    let optlen = mem::size_of::<TpacketReq>() as libc::socklen_t;
    println!("  sizeof(TpacketReq) = {}", optlen);

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            5, // PACKET_RX_RING
            std::ptr::from_ref::<TpacketReq>(&req).cast::<c_void>(),
            optlen,
        )
    };

    if result < 0 {
        let err = io::Error::last_os_error();
        println!(
            "  FAILED: {} (errno={})",
            err,
            err.raw_os_error().unwrap_or(0)
        );
        unsafe { libc::close(fd) };
        return;
    }

    println!("  SUCCESS!");
    unsafe { libc::close(fd) };
}
