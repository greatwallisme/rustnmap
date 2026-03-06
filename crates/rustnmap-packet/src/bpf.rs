//! BPF (Berkeley Packet Filter) utilities for kernel-space packet filtering.
//!
//! This module provides a high-level API for creating and attaching BPF filters
//! to packet sockets. BPF filters run in kernel space, reducing the overhead of
//! packet capture by filtering packets before they reach userspace.
//!
//! # Architecture
//!
//! BPF is a simple virtual machine with a small instruction set:
//! - Load operations: Load values from packet data
//! - Comparison operations: Compare values
//! - Jump operations: Conditional and unconditional jumps
//! - Return operations: Return accept/reject decision
//!
//! # Example
//!
//! ```rust,ignore
//! use rustnmap_packet::BpfFilter;
//!
//! // Create a filter for TCP port 80
//! let filter = BpfFilter::tcp_dst_port(80);
//!
//! // Attach to socket (requires CAP_NET_RAW)
//! filter.attach(fd)?;
//! ```
//!
//! # References
//!
//! - Linux kernel `Documentation/networking/filter.txt`
//! - BSD Packet Filter paper by McCanne and Jacobson
//! - `reference/nmap/libpcap/gencode.c` for nmap's filter generation

// Rust guideline compliant 2026-03-05

use crate::error::{PacketError, Result};
use std::io;
use std::mem;
use std::os::fd::AsRawFd;

/// BPF instruction structure.
///
/// This is the raw BPF instruction format used by the kernel.
/// Each instruction consists of:
/// - `code`: Operation code (load, jump, ret, etc.)
/// - `jt`: Jump target if true (for conditional jumps)
/// - `jf`: Jump target if false (for conditional jumps)
/// - `k`: Generic multiuse field (immediate value, offset, etc.)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfInstruction {
    /// Operation code.
    pub code: u16,
    /// Jump target if condition is true.
    pub jt: u8,
    /// Jump target if condition is false.
    pub jf: u8,
    /// Multiuse field (immediate, offset, constant).
    pub k: u32,
}

impl BpfInstruction {
    /// Creates a new BPF instruction.
    #[must_use]
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Creates a load half-word (16-bit) from packet instruction.
    #[must_use]
    pub const fn load_half(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, offset)
    }

    /// Creates a load word (32-bit) from packet instruction.
    #[must_use]
    pub const fn load_word(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset)
    }

    /// Creates a load immediate instruction.
    #[must_use]
    pub const fn load_imm(value: u32) -> Self {
        Self::new(BPF_LD | BPF_IMM, 0, 0, value)
    }

    /// Creates a jump if equal instruction.
    #[must_use]
    pub const fn jump_eq(value: u32, jt: u8, jf: u8) -> Self {
        Self::new(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, value)
    }

    /// Creates an unconditional jump instruction.
    #[must_use]
    pub const fn jump(offset: u8) -> Self {
        Self::new(BPF_JMP | BPF_JA, 0, 0, offset as u32)
    }

    /// Creates a return instruction with the given value.
    #[must_use]
    pub const fn ret(value: u32) -> Self {
        Self::new(BPF_RET | BPF_K, 0, 0, value)
    }

    /// Creates a return accept instruction (accept entire packet).
    #[must_use]
    pub const fn ret_accept() -> Self {
        Self::ret(u32::MAX)
    }

    /// Creates a return reject instruction (drop packet).
    #[must_use]
    pub const fn ret_reject() -> Self {
        Self::ret(0)
    }
}

// ============================================================================
// BPF Instruction Opcodes
// ============================================================================

/// Load instruction class.
const BPF_LD: u16 = 0x00;

/// Load into accumulator.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_LDX: u16 = 0x01;

/// Store from accumulator.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_ST: u16 = 0x02;

/// Store from X register.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_STX: u16 = 0x03;

/// ALU operations.
const BPF_ALU: u16 = 0x04;

/// Jump operations.
const BPF_JMP: u16 = 0x05;

/// Return instruction.
const BPF_RET: u16 = 0x06;

/// Miscellaneous.
const BPF_MISC: u16 = 0x07;

// Size modifiers
/// Word size (4 bytes).
const BPF_W: u16 = 0x00;
/// Half-word size (2 bytes).
const BPF_H: u16 = 0x08;
/// Byte size.
const BPF_B: u16 = 0x10;

// Mode modifiers
/// Immediate value.
const BPF_IMM: u16 = 0x00;
/// Absolute offset in packet.
const BPF_ABS: u16 = 0x20;
/// Indirect offset (packet[X + k:k+1]).
const BPF_IND: u16 = 0x40;
/// Memory load/store.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_MEM: u16 = 0x60;
/// Length of packet.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_LEN: u16 = 0x80;

// Jump conditions
/// Jump if equal.
const BPF_JEQ: u16 = 0x10;
/// Jump if greater than.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_JGT: u16 = 0x20;
/// Jump if greater than or equal.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_JGE: u16 = 0x30;
/// Jump if set.
const BPF_JSET: u16 = 0x40;

// Source operand
/// Use constant K.
const BPF_K: u16 = 0x00;
/// Use X register.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_X: u16 = 0x08;

// ALU operations
/// Add.
const BPF_ADD: u16 = 0x00;
/// Subtract.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_SUB: u16 = 0x10;
/// Multiply.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_MUL: u16 = 0x20;
/// Divide.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_DIV: u16 = 0x30;
/// Logical OR.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_OR: u16 = 0x40;
/// Logical AND.
const BPF_AND: u16 = 0x50;
/// Logical shift left.
const BPF_LSH: u16 = 0x60;
/// Logical shift right.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_RSH: u16 = 0x70;
/// Negate.
#[expect(
    dead_code,
    reason = "BPF opcode reserved for future filter implementations"
)]
const BPF_NEG: u16 = 0x80;

// Jump modifiers
/// Unconditional jump.
const BPF_JA: u16 = 0x00;

// ============================================================================
// Protocol Offsets
// ============================================================================

/// Ethernet header length (14 bytes: 6 dst + 6 src + 2 type).
const ETH_HLEN: u32 = 14;

/// IP header length field offset (low 4 bits of byte at offset 0).
const IP_HLEN_OFFSET: u32 = 0;

/// IP protocol field offset in IP header.
const IP_PROTO_OFFSET: u32 = 9;

/// IP source address offset in IP header.
const IP_SRC_OFFSET: u32 = 12;

/// IP destination address offset in IP header.
const IP_DST_OFFSET: u32 = 16;

/// TCP source port offset in TCP header (relative to TCP start).
const TCP_SRC_PORT_OFFSET: u32 = 0;

/// TCP destination port offset in TCP header (relative to TCP start).
const TCP_DST_PORT_OFFSET: u32 = 2;

/// UDP source port offset in UDP header (relative to UDP start).
const UDP_SRC_PORT_OFFSET: u32 = 0;

/// UDP destination port offset in UDP header (relative to UDP start).
const UDP_DST_PORT_OFFSET: u32 = 2;

/// ICMP type field offset in ICMP header (relative to ICMP start).
const ICMP_TYPE_OFFSET: u32 = 0;

/// `EtherType` for IPv4.
const ETHERTYPE_IP: u16 = 0x0800;

/// `EtherType` for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// `EtherType` for ARP.
const ETHERTYPE_ARP: u16 = 0x0806;

/// Protocol number for TCP.
const IPPROTO_TCP: u32 = 6;

/// Protocol number for UDP.
const IPPROTO_UDP: u32 = 17;

/// Protocol number for ICMP.
const IPPROTO_ICMP: u32 = 1;

// ============================================================================
// BpfFilter
// ============================================================================

/// BPF filter program for kernel-space packet filtering.
///
/// This struct wraps a BPF filter program and provides methods for
/// creating common filters and attaching them to sockets.
///
/// # Example
///
/// ```rust,ignore
/// use rustnmap_packet::BpfFilter;
///
/// // Create a filter for TCP port 80
/// let filter = BpfFilter::tcp_dst_port(80);
///
/// // Attach to socket (requires CAP_NET_RAW)
/// filter.attach(fd)?;
/// ```
#[derive(Clone, Debug)]
pub struct BpfFilter {
    /// BPF instructions.
    instructions: Vec<BpfInstruction>,
}

impl BpfFilter {
    /// Creates a new BPF filter from raw instructions.
    ///
    /// # Arguments
    ///
    /// * `instructions` - BPF instructions
    #[must_use]
    pub fn new(instructions: Vec<BpfInstruction>) -> Self {
        Self { instructions }
    }

    /// Creates an empty filter that accepts all packets.
    #[must_use]
    pub fn accept_all() -> Self {
        Self::new(vec![BpfInstruction::ret_accept()])
    }

    /// Creates a filter that rejects all packets.
    #[must_use]
    pub fn reject_all() -> Self {
        Self::new(vec![BpfInstruction::ret_reject()])
    }

    /// Creates a filter for TCP destination port.
    ///
    /// This filter matches TCP packets destined for the specified port.
    ///
    /// # Arguments
    ///
    /// * `port` - Destination port number
    #[must_use]
    pub fn tcp_dst_port(port: u16) -> Self {
        Self::new(Self::build_port_filter(
            IPPROTO_TCP,
            TCP_DST_PORT_OFFSET,
            port,
        ))
    }

    /// Creates a filter for TCP source port.
    ///
    /// # Arguments
    ///
    /// * `port` - Source port number
    #[must_use]
    pub fn tcp_src_port(port: u16) -> Self {
        Self::new(Self::build_port_filter(
            IPPROTO_TCP,
            TCP_SRC_PORT_OFFSET,
            port,
        ))
    }

    /// Creates a filter for UDP destination port.
    ///
    /// # Arguments
    ///
    /// * `port` - Destination port number
    #[must_use]
    pub fn udp_dst_port(port: u16) -> Self {
        Self::new(Self::build_port_filter(
            IPPROTO_UDP,
            UDP_DST_PORT_OFFSET,
            port,
        ))
    }

    /// Creates a filter for UDP source port.
    ///
    /// # Arguments
    ///
    /// * `port` - Source port number
    #[must_use]
    pub fn udp_src_port(port: u16) -> Self {
        Self::new(Self::build_port_filter(
            IPPROTO_UDP,
            UDP_SRC_PORT_OFFSET,
            port,
        ))
    }

    /// Creates a filter for ICMP packets.
    #[must_use]
    pub fn icmp() -> Self {
        Self::new(Self::build_icmp_filter())
    }

    /// Creates a filter for ICMP echo request (ping).
    #[must_use]
    pub fn icmp_echo_request() -> Self {
        Self::new(Self::build_icmp_type_filter(8))
    }

    /// Creates a filter for ICMP echo reply.
    #[must_use]
    pub fn icmp_echo_reply() -> Self {
        Self::new(Self::build_icmp_type_filter(0))
    }

    /// Creates a filter for ICMP packets with a specific destination address.
    ///
    /// This filter matches ICMP packets destined for the specified IPv4 address.
    /// It is useful for filtering ICMP responses in scanning applications.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address in network byte order
    #[must_use]
    pub fn icmp_dst(addr: u32) -> Self {
        Self::new(Self::build_icmp_dst_filter(addr))
    }

    /// Creates a filter for TCP SYN packets.
    #[must_use]
    pub fn tcp_syn() -> Self {
        Self::new(Self::build_tcp_syn_filter())
    }

    /// Creates a filter for TCP ACK packets.
    #[must_use]
    pub fn tcp_ack() -> Self {
        Self::new(Self::build_tcp_ack_filter())
    }

    /// Creates a filter for IPv4 packets.
    #[must_use]
    pub fn ipv4() -> Self {
        Self::new(Self::build_ethertype_filter(u32::from(ETHERTYPE_IP)))
    }

    /// Creates a filter for IPv6 packets.
    #[must_use]
    pub fn ipv6() -> Self {
        Self::new(Self::build_ethertype_filter(u32::from(ETHERTYPE_IPV6)))
    }

    /// Creates a filter for ARP packets.
    #[must_use]
    pub fn arp() -> Self {
        Self::new(Self::build_ethertype_filter(u32::from(ETHERTYPE_ARP)))
    }

    /// Creates a filter for IPv4 destination address.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address in network byte order
    #[must_use]
    pub fn ipv4_dst(addr: u32) -> Self {
        Self::new(Self::build_ipv4_addr_filter(IP_DST_OFFSET, addr))
    }

    /// Creates a filter for IPv4 source address.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address in network byte order
    #[must_use]
    pub fn ipv4_src(addr: u32) -> Self {
        Self::new(Self::build_ipv4_addr_filter(IP_SRC_OFFSET, addr))
    }

    /// Creates a combined filter that matches any of the given filters.
    ///
    /// # Arguments
    ///
    /// * `filters` - Filters to combine with OR logic
    #[must_use]
    pub fn any(filters: &[Self]) -> Self {
        if filters.is_empty() {
            return Self::reject_all();
        }

        if filters.len() == 1 {
            return filters[0].clone();
        }

        // Build OR filter: for each filter, if it matches, accept.
        // If none match, reject.
        let mut instructions = Vec::new();

        for (i, filter) in filters.iter().enumerate() {
            // Add this filter's instructions
            let start_idx = instructions.len();
            instructions.extend_from_slice(&filter.instructions);

            // If this is not the last filter, modify the return instructions
            // to jump to the common accept point
            if i < filters.len() - 1 {
                // Calculate where the final accept instruction will be
                let mut estimated_len = 0;
                for f in &filters[i + 1..] {
                    estimated_len += f.instructions.len();
                }

                // Patch any ret_accept to jump to final accept
                for instr in &mut instructions[start_idx..] {
                    if instr.code == (BPF_RET | BPF_K) && instr.k == u32::MAX {
                        // Replace with jump to final accept
                        let jump_offset = u8::try_from(estimated_len).unwrap_or(255);
                        *instr = BpfInstruction::jump(jump_offset);
                    }
                }
            }
        }

        // Add final accept
        instructions.push(BpfInstruction::ret_accept());

        // Add final reject (for when all filters fail)
        instructions.push(BpfInstruction::ret_reject());

        Self::new(instructions)
    }

    /// Builds a port filter for the given protocol and port.
    fn build_port_filter(protocol: u32, port_offset: u32, port: u16) -> Vec<BpfInstruction> {
        // Load EtherType (bytes 12-13)
        // Check if IPv4
        // If not IPv4, reject
        // Load IP protocol (byte 23)
        // Check if matches protocol (TCP=6, UDP=17)
        // If not, reject
        // Load IP header length (low 4 bits of byte 14)
        // Calculate transport header offset = 14 + IP header length * 4
        // Load port at offset
        // If matches, accept
        // Else reject

        vec![
            // Load EtherType (bytes 12-13)
            BpfInstruction::load_half(ETH_HLEN),
            // Jump if IPv4
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 6),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP protocol (byte at offset 23 = 14 + 9)
            BpfInstruction::load_byte(ETH_HLEN + IP_PROTO_OFFSET),
            // Jump if matches protocol
            BpfInstruction::jump_eq(protocol, 0, 3),
            // Not matching protocol, reject
            BpfInstruction::ret_reject(),
            // Load IP header length * 4 (low 4 bits of byte 14, multiplied by 4)
            // First load the byte
            BpfInstruction::load_byte(ETH_HLEN + IP_HLEN_OFFSET),
            // AND with 0x0F to get header length, then multiply by 4
            BpfInstruction::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0F),
            // Multiply by 4 using left shift by 2
            BpfInstruction::new(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 2),
            // Add ETH_HLEN + port_offset to get the port offset
            BpfInstruction::new(BPF_ALU | BPF_ADD | BPF_K, 0, 0, ETH_HLEN + port_offset),
            // Load port using indirect addressing (X + k)
            // First move accumulator to X
            BpfInstruction::new(BPF_MISC | BPF_TAX, 0, 0, 0),
            // Load half-word at packet[X + 0]
            BpfInstruction::new(BPF_LD | BPF_H | BPF_IND, 0, 0, 0),
            // Compare with port (in network byte order)
            BpfInstruction::jump_eq(u32::from(port.to_be()), 0, 1),
            // Not matching, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds an ICMP filter.
    fn build_icmp_filter() -> Vec<BpfInstruction> {
        vec![
            // Load EtherType
            BpfInstruction::load_half(ETH_HLEN),
            // Check if IPv4
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 5),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP protocol
            BpfInstruction::load_byte(ETH_HLEN + IP_PROTO_OFFSET),
            // Check if ICMP (1)
            BpfInstruction::jump_eq(IPPROTO_ICMP, 0, 1),
            // Not ICMP, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds an ICMP type filter.
    fn build_icmp_type_filter(icmp_type: u8) -> Vec<BpfInstruction> {
        vec![
            // Load EtherType
            BpfInstruction::load_half(ETH_HLEN),
            // Check if IPv4
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 7),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP protocol
            BpfInstruction::load_byte(ETH_HLEN + IP_PROTO_OFFSET),
            // Check if ICMP (1)
            BpfInstruction::jump_eq(IPPROTO_ICMP, 0, 4),
            // Not ICMP, reject
            BpfInstruction::ret_reject(),
            // Load IP header length
            BpfInstruction::load_byte(ETH_HLEN + IP_HLEN_OFFSET),
            // AND with 0x0F, multiply by 4
            BpfInstruction::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0F),
            BpfInstruction::new(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 2),
            // Add ETH_HLEN + ICMP_TYPE_OFFSET
            BpfInstruction::new(BPF_ALU | BPF_ADD | BPF_K, 0, 0, ETH_HLEN + ICMP_TYPE_OFFSET),
            // Move to X
            BpfInstruction::new(BPF_MISC | BPF_TAX, 0, 0, 0),
            // Load ICMP type byte
            BpfInstruction::new(BPF_LD | BPF_B | BPF_IND, 0, 0, 0),
            // Compare with desired type
            BpfInstruction::jump_eq(u32::from(icmp_type), 0, 1),
            // Not matching, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds an ICMP filter with destination address.
    ///
    /// This filter matches ICMP packets destined for the specified IPv4 address.
    fn build_icmp_dst_filter(addr: u32) -> Vec<BpfInstruction> {
        vec![
            // Load EtherType (bytes 12-13)
            BpfInstruction::load_half(ETH_HLEN),
            // Check if IPv4 (0x0800) - jump to next if true, else skip 5 to reject
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 5),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP protocol (byte at offset 23 = 14 + 9)
            BpfInstruction::load_byte(ETH_HLEN + IP_PROTO_OFFSET),
            // Check if ICMP (1) - jump to next if true, else skip 3 to reject
            BpfInstruction::jump_eq(IPPROTO_ICMP, 0, 3),
            // Not ICMP, reject
            BpfInstruction::ret_reject(),
            // Load destination IP (offset 30, 4 bytes) - 14 + 16 (IP dst offset)
            BpfInstruction::load_word(ETH_HLEN + IP_DST_OFFSET),
            // Check if matches local IP - jump to accept if true, else reject
            BpfInstruction::jump_eq(addr, 0, 1),
            // Not matching, reject
            BpfInstruction::ret_reject(),
            // Accept packet (return full packet length)
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds a TCP SYN filter.
    fn build_tcp_syn_filter() -> Vec<BpfInstruction> {
        // TCP flags are at offset 13 from TCP header start
        const TCP_FLAGS_OFFSET: u32 = 13;
        const TCP_FLAG_SYN: u32 = 0x02;

        vec![
            // Load EtherType
            BpfInstruction::load_half(ETH_HLEN),
            // Check if IPv4
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 7),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP protocol
            BpfInstruction::load_byte(ETH_HLEN + IP_PROTO_OFFSET),
            // Check if TCP (6)
            BpfInstruction::jump_eq(IPPROTO_TCP, 0, 4),
            // Not TCP, reject
            BpfInstruction::ret_reject(),
            // Load IP header length
            BpfInstruction::load_byte(ETH_HLEN + IP_HLEN_OFFSET),
            // AND with 0x0F, multiply by 4
            BpfInstruction::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0F),
            BpfInstruction::new(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 2),
            // Add ETH_HLEN + TCP_FLAGS_OFFSET
            BpfInstruction::new(BPF_ALU | BPF_ADD | BPF_K, 0, 0, ETH_HLEN + TCP_FLAGS_OFFSET),
            // Move to X
            BpfInstruction::new(BPF_MISC | BPF_TAX, 0, 0, 0),
            // Load TCP flags byte
            BpfInstruction::new(BPF_LD | BPF_B | BPF_IND, 0, 0, 0),
            // Check if SYN flag is set
            BpfInstruction::new(BPF_JMP | BPF_JSET | BPF_K, 0, 1, TCP_FLAG_SYN),
            // SYN not set, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds a TCP ACK filter.
    fn build_tcp_ack_filter() -> Vec<BpfInstruction> {
        const TCP_FLAGS_OFFSET: u32 = 13;
        const TCP_FLAG_ACK: u32 = 0x10;

        vec![
            // Load EtherType
            BpfInstruction::load_half(ETH_HLEN),
            // Check if IPv4
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 7),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP protocol
            BpfInstruction::load_byte(ETH_HLEN + IP_PROTO_OFFSET),
            // Check if TCP (6)
            BpfInstruction::jump_eq(IPPROTO_TCP, 0, 4),
            // Not TCP, reject
            BpfInstruction::ret_reject(),
            // Load IP header length
            BpfInstruction::load_byte(ETH_HLEN + IP_HLEN_OFFSET),
            // AND with 0x0F, multiply by 4
            BpfInstruction::new(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0F),
            BpfInstruction::new(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 2),
            // Add ETH_HLEN + TCP_FLAGS_OFFSET
            BpfInstruction::new(BPF_ALU | BPF_ADD | BPF_K, 0, 0, ETH_HLEN + TCP_FLAGS_OFFSET),
            // Move to X
            BpfInstruction::new(BPF_MISC | BPF_TAX, 0, 0, 0),
            // Load TCP flags byte
            BpfInstruction::new(BPF_LD | BPF_B | BPF_IND, 0, 0, 0),
            // Check if ACK flag is set
            BpfInstruction::new(BPF_JMP | BPF_JSET | BPF_K, 0, 1, TCP_FLAG_ACK),
            // ACK not set, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds an Ethertype filter.
    fn build_ethertype_filter(ethertype: u32) -> Vec<BpfInstruction> {
        vec![
            // Load EtherType (bytes 12-13)
            BpfInstruction::load_half(ETH_HLEN),
            // Check if matches
            BpfInstruction::jump_eq(ethertype, 0, 1),
            // Not matching, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Builds an IPv4 address filter.
    fn build_ipv4_addr_filter(offset: u32, addr: u32) -> Vec<BpfInstruction> {
        vec![
            // Load EtherType
            BpfInstruction::load_half(ETH_HLEN),
            // Check if IPv4
            BpfInstruction::jump_eq(u32::from(ETHERTYPE_IP), 0, 3),
            // Not IPv4, reject
            BpfInstruction::ret_reject(),
            // Load IP address at offset
            BpfInstruction::load_word(ETH_HLEN + offset),
            // Check if matches
            BpfInstruction::jump_eq(addr, 0, 1),
            // Not matching, reject
            BpfInstruction::ret_reject(),
            // Accept
            BpfInstruction::ret_accept(),
        ]
    }

    /// Returns the number of instructions in the filter.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if the filter is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Returns a reference to the instructions.
    #[must_use]
    pub fn instructions(&self) -> &[BpfInstruction] {
        &self.instructions
    }

    /// Converts the filter to a `libc::sock_fprog` for kernel attachment.
    ///
    /// # Safety
    ///
    /// The returned `sock_fprog` contains a pointer to the filter's internal
    /// instructions. The filter must remain valid for the lifetime of the
    /// `sock_fprog`.
    #[must_use]
    pub fn to_sock_fprog(&self) -> libc::sock_fprog {
        libc::sock_fprog {
            len: u16::try_from(self.instructions.len()).unwrap_or(u16::MAX),
            filter: self.instructions.as_ptr() as *mut libc::sock_filter,
        }
    }

    /// Attaches the filter to a socket.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor of the socket
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The filter is empty
    /// - The socket operation fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustnmap_packet::BpfFilter;
    /// use std::os::fd::AsRawFd;
    ///
    /// let filter = BpfFilter::tcp_dst_port(80);
    /// filter.attach(socket.as_raw_fd())?;
    /// ```
    pub fn attach<F: AsRawFd>(&self, fd: &F) -> Result<()> {
        if self.instructions.is_empty() {
            return Err(PacketError::BpfFilter("filter is empty".to_string()));
        }

        let fprog = self.to_sock_fprog();

        // SAFETY: setsockopt with SO_ATTACH_FILTER is safe with valid filter pointer.
        // The fprog contains a valid pointer to our instructions vector.
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                std::ptr::from_ref(&fprog).cast::<std::ffi::c_void>(),
                u32::try_from(mem::size_of::<libc::sock_fprog>())
                    .map_err(|e| PacketError::BpfFilter(format!("Invalid filter size: {e}")))?,
            )
        };

        if result < 0 {
            return Err(PacketError::BpfFilter(
                io::Error::last_os_error().to_string(),
            ));
        }

        Ok(())
    }

    /// Detaches any BPF filter from the socket.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor of the socket
    ///
    /// # Errors
    ///
    /// Returns an error if the socket operation fails.
    pub fn detach<F: AsRawFd>(fd: &F) -> Result<()> {
        // SAFETY: setsockopt with SO_DETACH_FILTER is safe with null pointer
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_DETACH_FILTER,
                std::ptr::null(),
                0,
            )
        };

        if result < 0 {
            // ENOENT means no filter was attached, which is fine
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(PacketError::BpfFilter(format!(
                    "failed to detach filter: {err}"
                )));
            }
        }

        Ok(())
    }
}

/// Creates a load byte instruction.
impl BpfInstruction {
    /// Creates a load byte instruction.
    #[must_use]
    pub const fn load_byte(offset: u32) -> Self {
        Self::new(BPF_LD | BPF_B | BPF_ABS, 0, 0, offset)
    }
}

// TAX instruction opcode
/// Transfer accumulator to X register.
const BPF_TAX: u16 = 0x00;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_instruction_size() {
        assert_eq!(mem::size_of::<BpfInstruction>(), 8);
    }

    #[test]
    fn test_bpf_filter_accept_all() {
        let filter = BpfFilter::accept_all();
        assert_eq!(filter.len(), 1);
        assert_eq!(filter.instructions()[0].code, BPF_RET | BPF_K);
        assert_eq!(filter.instructions()[0].k, u32::MAX);
    }

    #[test]
    fn test_bpf_filter_reject_all() {
        let filter = BpfFilter::reject_all();
        assert_eq!(filter.len(), 1);
        assert_eq!(filter.instructions()[0].code, BPF_RET | BPF_K);
        assert_eq!(filter.instructions()[0].k, 0);
    }

    #[test]
    fn test_bpf_filter_tcp_dst_port() {
        let filter = BpfFilter::tcp_dst_port(80);
        assert!(!filter.is_empty());
        // Should have instructions for: load ethertype, check IPv4, load protocol,
        // check TCP, load IP header len, calculate offset, load port, compare, accept/reject
        assert!(filter.len() > 5);
    }

    #[test]
    fn test_bpf_filter_udp_dst_port() {
        let filter = BpfFilter::udp_dst_port(53);
        assert!(!filter.is_empty());
        assert!(filter.len() > 5);
    }

    #[test]
    fn test_bpf_filter_icmp() {
        let filter = BpfFilter::icmp();
        assert!(!filter.is_empty());
        // Should have: load ethertype, check IPv4, load protocol, check ICMP, accept/reject
        assert!(filter.len() > 3);
    }

    #[test]
    fn test_bpf_filter_ipv4() {
        let filter = BpfFilter::ipv4();
        assert_eq!(filter.len(), 4); // load, compare, reject, accept
        assert_eq!(filter.instructions()[0].code, BPF_LD | BPF_H | BPF_ABS);
        assert_eq!(filter.instructions()[0].k, ETH_HLEN);
    }

    #[test]
    fn test_bpf_filter_ipv6() {
        let filter = BpfFilter::ipv6();
        assert_eq!(filter.len(), 4);
    }

    #[test]
    fn test_bpf_filter_arp() {
        let filter = BpfFilter::arp();
        assert_eq!(filter.len(), 4);
    }

    #[test]
    fn test_bpf_filter_tcp_syn() {
        let filter = BpfFilter::tcp_syn();
        assert!(!filter.is_empty());
        // Should include flag checking
        assert!(filter.len() > 5);
    }

    #[test]
    fn test_bpf_filter_tcp_ack() {
        let filter = BpfFilter::tcp_ack();
        assert!(!filter.is_empty());
        assert!(filter.len() > 5);
    }

    #[test]
    fn test_bpf_filter_icmp_echo_request() {
        let filter = BpfFilter::icmp_echo_request();
        assert!(!filter.is_empty());
        // Should check for ICMP type 8
        assert!(filter.len() > 5);
    }

    #[test]
    fn test_bpf_filter_icmp_echo_reply() {
        let filter = BpfFilter::icmp_echo_reply();
        assert!(!filter.is_empty());
        // Should check for ICMP type 0
        assert!(filter.len() > 5);
    }

    #[test]
    fn test_bpf_filter_icmp_dst() {
        let filter = BpfFilter::icmp_dst(0x01020304);
        assert!(!filter.is_empty());
        // Should check for IPv4, ICMP, and destination IP
        assert!(filter.len() > 7);
    }

    #[test]
    fn test_bpf_instruction_load_half() {
        let instr = BpfInstruction::load_half(12);
        assert_eq!(instr.code, BPF_LD | BPF_H | BPF_ABS);
        assert_eq!(instr.k, 12);
    }

    #[test]
    fn test_bpf_instruction_load_word() {
        let instr = BpfInstruction::load_word(20);
        assert_eq!(instr.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(instr.k, 20);
    }

    #[test]
    fn test_bpf_instruction_jump_eq() {
        let instr = BpfInstruction::jump_eq(6, 1, 2);
        assert_eq!(instr.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(instr.jt, 1);
        assert_eq!(instr.jf, 2);
        assert_eq!(instr.k, 6);
    }

    #[test]
    fn test_bpf_instruction_ret_accept() {
        let instr = BpfInstruction::ret_accept();
        assert_eq!(instr.code, BPF_RET | BPF_K);
        assert_eq!(instr.k, u32::MAX);
    }

    #[test]
    fn test_bpf_instruction_ret_reject() {
        let instr = BpfInstruction::ret_reject();
        assert_eq!(instr.code, BPF_RET | BPF_K);
        assert_eq!(instr.k, 0);
    }

    #[test]
    fn test_bpf_filter_ipv4_dst() {
        let addr: u32 = 0xC0A80001; // 192.168.0.1
        let filter = BpfFilter::ipv4_dst(addr);
        assert!(!filter.is_empty());
        assert!(filter.len() > 3);
    }

    #[test]
    fn test_bpf_filter_ipv4_src() {
        let addr: u32 = 0xC0A80001; // 192.168.0.1
        let filter = BpfFilter::ipv4_src(addr);
        assert!(!filter.is_empty());
        assert!(filter.len() > 3);
    }

    #[test]
    fn test_bpf_filter_any_empty() {
        let filter = BpfFilter::any(&[]);
        assert_eq!(filter.len(), 1);
        assert_eq!(filter.instructions()[0].k, 0); // reject
    }

    #[test]
    fn test_bpf_filter_any_single() {
        let filters = [BpfFilter::tcp_dst_port(80)];
        let combined = BpfFilter::any(&filters);
        // Should be equivalent to the single filter
        assert!(!combined.is_empty());
    }

    #[test]
    fn test_bpf_filter_clone() {
        let filter = BpfFilter::tcp_dst_port(80);
        let cloned = filter.clone();
        assert_eq!(filter.len(), cloned.len());
    }

    #[test]
    fn test_bpf_filter_debug() {
        let filter = BpfFilter::accept_all();
        let debug_str = format!("{filter:?}");
        assert!(debug_str.contains("BpfFilter"));
    }
}
