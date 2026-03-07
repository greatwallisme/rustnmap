//! ICMP error classification for network volatility handling.
//!
//! This module provides classification of ICMP error messages to determine
//! appropriate scanner responses, following nmap's behavior.
//!
//! # Architecture
//!
//! Based on `doc/architecture.md` Section 2.3.4:
//!
//! ```text
//! ErrorRecovery (ICMP 分类)
//! ├─ HOST_UNREACH → Mark Down
//! ├─ NET_UNREACH → Reduce cwnd, Boost delay
//! ├─ PORT_UNREACH (UDP) → Mark Closed
//! ├─ ADMIN_PROHIBITED → Mark Filtered
//! ├─ FRAG_NEEDED → Set DF=0
//! └─ TIMEOUT → Retry with backoff
//! ```
//!
//! # Behavior
//!
//! ICMP errors are classified and mapped to appropriate actions:
//! - **Host unreachable**: Target host is down
//! - **Network unreachable**: Network issues, reduce scan rate
//! - **Port unreachable**: UDP port is closed
//! - **Admin prohibited**: Traffic is filtered by firewall
//! - **Fragmentation needed**: Need to disable DF bit
//! - **Timeout**: Retry with exponential backoff
//!
//! # Examples
//!
//! ```rust
//! use rustnmap_scan::icmp_handler::{IcmpAction, classify_icmp_error};
//! use rustnmap_common::PortState;
//!
//! // Classify HOST_UNREACH error
//! let action = classify_icmp_error(3, 1); // ICMP type 3, code 1
//! assert_eq!(action, IcmpAction::MarkDown);
//! ```
//!
//! # References
//!
//! - `doc/architecture.md` Section 2.3.4
//! - `reference/nmap/scan_engine.cc` - Nmap's ICMP handling
//! - RFC 792 - Internet Control Message Protocol

#![warn(missing_docs)]

use rustnmap_common::PortState;

/// Action to take in response to an ICMP error.
///
/// Based on nmap's handling of ICMP error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpAction {
    /// Mark the target host as down.
    ///
    /// Generated for `HOST_UNREACH` errors.
    MarkDown,

    /// Reduce congestion window and increase scan delay.
    ///
    /// Generated for `NET_UNREACH` errors when network is congested.
    ReduceCwnd,

    /// Mark the port as closed.
    ///
    /// Generated for `PORT_UNREACH` errors (UDP scanning).
    MarkClosed,

    /// Mark the port/service as filtered by firewall.
    ///
    /// Generated for `ADMIN_PROHIBITED` errors.
    MarkFiltered,

    /// Disable DF (Don't Fragment) bit for subsequent probes.
    ///
    /// Generated for `FRAG_NEEDED` errors when packets are too large.
    SetDfZero,

    /// Retry the probe with exponential backoff.
    ///
    /// Generated for timeout or other transient errors.
    RetryWithBackoff,

    /// No specific action required.
    ///
    /// For ICMP errors that don't require special handling.
    None,
}

/// ICMP error types for classification.
///
/// Based on RFC 792 and common ICMP implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    /// Destination Unreachable (Type 3).
    DestinationUnreachable = 3,
    /// Time Exceeded (Type 11).
    TimeExceeded = 11,
    /// Parameter Problem (Type 12).
    ParameterProblem = 12,
    /// Source Quench (Type 4) - deprecated.
    SourceQuench = 4,
}

/// Destination Unreachable codes (Type 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestUnreachableCode {
    /// Network unreachable (Code 0).
    NetworkUnreachable = 0,
    /// Host unreachable (Code 1).
    HostUnreachable = 1,
    /// Protocol unreachable (Code 2).
    ProtocolUnreachable = 2,
    /// Port unreachable (Code 3).
    PortUnreachable = 3,
    /// Fragmentation needed and DF set (Code 4).
    FragmentationNeeded = 4,
    /// Source route failed (Code 5).
    SourceRouteFailed = 5,
    /// Destination network unknown (Code 6).
    NetworkUnknown = 6,
    /// Destination host unknown (Code 7).
    HostUnknown = 7,
    /// Source host isolated (Code 8).
    HostIsolated = 8,
    /// Network administratively prohibited (Code 9).
    NetworkProhibited = 9,
    /// Host administratively prohibited (Code 10).
    HostProhibited = 10,
    /// Network unreachable for TOS (Code 11).
    NetworkUnreachableForTos = 11,
    /// Host unreachable for TOS (Code 12).
    HostUnreachableForTos = 12,
    /// Communication administratively prohibited (Code 13).
    CommunicationProhibited = 13,
    /// Host precedence violation (Code 14).
    HostPrecedenceViolation = 14,
    /// Precedence cutoff in effect (Code 15).
    PrecedenceCutoff = 15,
}

/// Classifies an ICMP error and returns the appropriate action.
///
/// This maps ICMP type/code pairs to scanner actions following nmap's behavior.
///
/// # Arguments
///
/// * `icmp_type` - ICMP message type (e.g., 3 for Destination Unreachable)
/// * `icmp_code` - ICMP message code (e.g., 1 for Host Unreachable)
///
/// # Returns
///
/// The appropriate `IcmpAction` for this error type.
///
/// # Examples
///
/// ```
/// use rustnmap_scan::icmp_handler::{IcmpAction, classify_icmp_error};
///
/// // HOST_UNREACH (Type 3, Code 1 or 2)
/// assert_eq!(classify_icmp_error(3, 1), IcmpAction::MarkDown);
/// assert_eq!(classify_icmp_error(3, 2), IcmpAction::MarkDown);
///
/// // NET_UNREACH (Type 3, Code 0)
/// assert_eq!(classify_icmp_error(3, 0), IcmpAction::ReduceCwnd);
///
/// // PORT_UNREACH (Type 3, Code 3)
/// assert_eq!(classify_icmp_error(3, 3), IcmpAction::MarkClosed);
///
/// // FRAG_NEEDED (Type 3, Code 4)
/// assert_eq!(classify_icmp_error(3, 4), IcmpAction::SetDfZero);
/// ```
#[must_use]
pub const fn classify_icmp_error(icmp_type: u8, icmp_code: u8) -> IcmpAction {
    match (icmp_type, icmp_code) {
        // Network unreachable (Type 3, Code 0) or Source Quench (Type 4)
        (3, 0) | (4, _) => IcmpAction::ReduceCwnd,

        // Other Destination Unreachable codes
        (3, 1 | 2) => IcmpAction::MarkDown, // Host/Protocol unreachable
        (3, 3) => IcmpAction::MarkClosed,   // Port unreachable
        (3, 4) => IcmpAction::SetDfZero,    // Fragmentation needed
        (3, 9 | 10 | 13) => IcmpAction::MarkFiltered, // Administratively prohibited

        // Time Exceeded (Type 11) and Parameter Problem (Type 12)
        // Both trigger retry with backoff
        (11, 0 | 1) | (12, _) => IcmpAction::RetryWithBackoff,

        // Unknown ICMP types
        _ => IcmpAction::None,
    }
}

/// Maps ICMP action to port state for scan results.
///
/// Converts an `IcmpAction` to the corresponding `PortState` for reporting.
///
/// # Arguments
///
/// * `action` - The ICMP action to map
///
/// # Returns
///
/// The corresponding port state, or `None` if no direct mapping exists.
///
/// # Examples
///
/// ```
/// use rustnmap_scan::icmp_handler::{IcmpAction, action_to_port_state};
/// use rustnmap_common::PortState;
///
/// assert_eq!(action_to_port_state(IcmpAction::MarkClosed), Some(PortState::Closed));
/// assert_eq!(action_to_port_state(IcmpAction::MarkFiltered), Some(PortState::Filtered));
/// assert_eq!(action_to_port_state(IcmpAction::ReduceCwnd), None);
/// ```
#[must_use]
pub const fn action_to_port_state(action: IcmpAction) -> Option<PortState> {
    match action {
        IcmpAction::MarkClosed => Some(PortState::Closed),
        // Both MarkFiltered and MarkDown map to Filtered for port purposes
        IcmpAction::MarkFiltered | IcmpAction::MarkDown => Some(PortState::Filtered),
        _ => None, // Other actions don't map directly to port states
    }
}

/// ICMP error message parser.
///
/// Provides helper methods for parsing ICMP error messages from raw packets.
#[derive(Debug, Clone, Copy)]
pub struct IcmpParser;

impl IcmpParser {
    /// Extracts ICMP type and code from a raw packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw packet bytes (must include IP header)
    ///
    /// # Returns
    ///
    /// `Some((type, code))` if ICMP header is found, `None` otherwise.
    ///
    /// # Note
    ///
    /// This is a simplified parser that assumes:
    /// - IPv4 packet (20-byte header)
    /// - ICMP header starts at byte 20
    /// - Type is at byte 20, Code is at byte 21
    #[must_use]
    pub const fn extract_type_code(packet: &[u8]) -> Option<(u8, u8)> {
        if packet.len() < 21 {
            return None;
        }

        // Skip IP header (20 bytes for IPv4)
        // ICMP type is at offset 20, Code at offset 21
        let icmp_type = packet[20];
        let icmp_code = packet[21];

        // Verify it's an ICMP message (protocol = 1)
        // IP protocol field is at byte 9
        if packet[9] != 1 {
            return None;
        }

        Some((icmp_type, icmp_code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_host_unreachable() {
        // Code 1: Host unreachable
        assert_eq!(classify_icmp_error(3, 1), IcmpAction::MarkDown);
        // Code 2: Protocol unreachable (also treated as host unreachable)
        assert_eq!(classify_icmp_error(3, 2), IcmpAction::MarkDown);
    }

    #[test]
    fn test_classify_network_unreachable() {
        assert_eq!(classify_icmp_error(3, 0), IcmpAction::ReduceCwnd);
    }

    #[test]
    fn test_classify_port_unreachable() {
        assert_eq!(classify_icmp_error(3, 3), IcmpAction::MarkClosed);
    }

    #[test]
    fn test_classify_frag_needed() {
        assert_eq!(classify_icmp_error(3, 4), IcmpAction::SetDfZero);
    }

    #[test]
    fn test_classify_admin_prohibited() {
        // Network administratively prohibited
        assert_eq!(classify_icmp_error(3, 9), IcmpAction::MarkFiltered);
        // Host administratively prohibited
        assert_eq!(classify_icmp_error(3, 10), IcmpAction::MarkFiltered);
        // Communication administratively prohibited
        assert_eq!(classify_icmp_error(3, 13), IcmpAction::MarkFiltered);
    }

    #[test]
    fn test_classify_time_exceeded() {
        // TTL expired during transit
        assert_eq!(classify_icmp_error(11, 0), IcmpAction::RetryWithBackoff);
        // Fragment reassembly time exceeded
        assert_eq!(classify_icmp_error(11, 1), IcmpAction::RetryWithBackoff);
    }

    #[test]
    fn test_classify_parameter_problem() {
        assert_eq!(classify_icmp_error(12, 0), IcmpAction::RetryWithBackoff);
    }

    #[test]
    fn test_classify_source_quench() {
        assert_eq!(classify_icmp_error(4, 0), IcmpAction::ReduceCwnd);
    }

    #[test]
    fn test_classify_unknown_icmp() {
        assert_eq!(classify_icmp_error(255, 0), IcmpAction::None);
    }

    #[test]
    fn test_action_to_port_state() {
        assert_eq!(
            action_to_port_state(IcmpAction::MarkClosed),
            Some(PortState::Closed)
        );
        assert_eq!(
            action_to_port_state(IcmpAction::MarkFiltered),
            Some(PortState::Filtered)
        );
        assert_eq!(
            action_to_port_state(IcmpAction::MarkDown),
            Some(PortState::Filtered)
        );
        assert_eq!(action_to_port_state(IcmpAction::ReduceCwnd), None);
        assert_eq!(action_to_port_state(IcmpAction::SetDfZero), None);
        assert_eq!(action_to_port_state(IcmpAction::RetryWithBackoff), None);
        assert_eq!(action_to_port_state(IcmpAction::None), None);
    }

    #[test]
    fn test_icmp_parser_valid_packet() {
        // Construct a minimal IPv4 + ICMP packet
        // IP header (20 bytes) + ICMP header (8 bytes)
        let mut packet = [0u8; 28];

        // Set IP version and IHL
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)

        // Set protocol to ICMP (1)
        packet[9] = 1;

        // Set ICMP type (3) and code (1) - Destination Unreachable, Host Unreachable
        packet[20] = 3;
        packet[21] = 1;

        let result = IcmpParser::extract_type_code(&packet);
        assert_eq!(result, Some((3, 1)));
    }

    #[test]
    fn test_icmp_parser_invalid_protocol() {
        let mut packet = [0u8; 28];

        // Set IP version and IHL
        packet[0] = 0x45;

        // Set protocol to TCP (6) instead of ICMP
        packet[9] = 6;

        let result = IcmpParser::extract_type_code(&packet);
        assert_eq!(result, None);
    }

    #[test]
    fn test_icmp_parser_too_short() {
        let packet = [0u8; 20]; // Only IP header, no ICMP

        let result = IcmpParser::extract_type_code(&packet);
        assert_eq!(result, None);
    }
}
