//! `AF_PACKET` socket constants and structures.
//!
//! This module provides `AF_PACKET` socket constants and Linux kernel
//! definitions for raw packet access.

// Rust guideline compliant 2026-03-05

/// Address family for packet sockets.
pub const AF_PACKET: libc::c_int = 17;

/// Raw packet socket type.
pub const SOCK_RAW: libc::c_int = 3;

/// Datagram packet socket type.
pub const SOCK_DGRAM: libc::c_int = 5;

/// Ethernet protocol types (from `if_ether.h`)
pub const ETH_P_ALL: u16 = 0x0003;
/// Internet Protocol packet type.
pub const ETH_P_IP: u16 = 0x0800;
/// IPv6 packet type.
pub const ETH_P_IPV6: u16 = 0x86DD;
/// Address Resolution Protocol packet type.
pub const ETH_P_ARP: u16 = 0x0806;

/// Packet socket options (from `if_packet.h`)
pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
/// Drop multicast group membership.
pub const PACKET_DROP_MEMBERSHIP: libc::c_int = 2;
/// Set up packet ring buffer for receive.
pub const PACKET_RX_RING: libc::c_int = 5;
/// Set up packet ring buffer for transmit.
pub const PACKET_TX_RING: libc::c_int = 7;
/// Set packet ring buffer version.
pub const PACKET_VERSION: libc::c_int = 10;
/// Reserve headroom in packet ring buffer.
pub const PACKET_RESERVE: libc::c_int = 12;
/// Enable auxiliary data in packet ring buffer.
pub const PACKET_AUXDATA: libc::c_int = 8;

/// `TPACKET` version 2 constant.
pub const TPACKET_V2: libc::c_int = 2;

/// Frame status constants (from `if_packet.h`)
/// Frame is owned by kernel.
pub const TP_STATUS_KERNEL: u32 = 0;
/// Frame is owned by userspace.
pub const TP_STATUS_USER: u32 = 1 << 0;
/// Frame was copied (not zero-copy).
pub const TP_STATUS_COPY: u32 = 1 << 1;
/// Packets are being dropped.
pub const TP_STATUS_LOSING: u32 = 1 << 2;
/// VLAN information is valid.
pub const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
/// VLAN TPID is valid.
pub const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 5;

/// `TPACKET` alignment requirement (16 bytes).
pub const TPACKET_ALIGNMENT: usize = 16;

/// `TPACKET2` header length (32 bytes).
pub const TPACKET2_HDRLEN: usize = 32;

/// VLAN tag length in bytes.
pub const VLAN_TAG_LEN: usize = 4;
