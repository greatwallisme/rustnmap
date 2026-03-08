//! Run C test via std::process

// Diagnostic example - expects undocumented unsafe blocks
// These are temporary test tools, not production code.
#![expect(clippy::undocumented_unsafe_blocks)]

use std::process::Command;

fn main() {
    println!("Running C test via std::process::Command...");

    let output = Command::new("/tmp/test_full").output();

    match output {
        Ok(out) => {
            println!("stdout:\n{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                println!("stderr:\n{}", String::from_utf8_lossy(&out.stderr));
            }
            println!("exit code: {}", out.status.code().unwrap_or(-1));
        }
        Err(e) => {
            println!("Failed to run C test: {}", e);
        }
    }

    println!("\nNow trying Rust again...\n");

    // Now try Rust
    use std::ffi::c_void;
    use std::mem;

    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        println!("socket FAILED: {}", std::io::Error::last_os_error());
        return;
    }

    let version = 2i32;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            10,
            std::ptr::from_ref(&version).cast::<c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    let reserve = 4i32;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            12,
            std::ptr::from_ref(&reserve).cast::<c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    let auxdata = 1i32;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            8,
            std::ptr::from_ref(&auxdata).cast::<c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    let if_name = std::ffi::CString::new("ens33").unwrap();
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    let bytes = if_name.as_bytes_with_nul();
    for (i, &b) in bytes.iter().enumerate() {
        ifreq.ifr_name[i] = i8::try_from(b).unwrap();
    }

    let ctl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let _ = unsafe { libc::ioctl(ctl_fd, libc::SIOCGIFINDEX, &ifreq) };
    unsafe { libc::close(ctl_fd) };
    let if_index = unsafe { ifreq.ifr_ifru.ifru_ifindex };

    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = 0;
    addr.sll_ifindex = if_index;

    let _ = unsafe {
        libc::bind(
            fd,
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };

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

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            5,
            std::ptr::from_ref::<TpacketReq>(&req).cast::<c_void>(),
            mem::size_of::<TpacketReq>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        println!(
            "Rust PACKET_RX_RING FAILED: {} (errno={})",
            err,
            err.raw_os_error().unwrap_or(0)
        );
    } else {
        println!("Rust PACKET_RX_RING SUCCESS!");
    }

    unsafe { libc::close(fd) };
}
