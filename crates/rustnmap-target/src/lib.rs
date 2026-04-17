// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Target parsing and host discovery for `RustNmap`.
//!
//! This crate provides:
//! - Target specification parsing (CIDR, ranges, wildcards)
//! - Target expansion and validation
//! - Host discovery via ICMP ping
//!
//! # Examples
//!
//! ```
//! use rustnmap_target::TargetParser;
//!
//! let parser = TargetParser::new();
//! let group = parser.parse("192.168.1.0/24").unwrap();
//! assert_eq!(group.len(), 256);
//! ```

#![warn(missing_docs)]

use rustnmap_common::{Error, Ipv4Addr, Ipv6Addr, Result};

pub mod discovery;
pub mod dns;
pub mod parser;
pub mod spec;

// Re-exports
pub use discovery::{
    ArpPing, ArpPingBatch, HostDiscovery, HostDiscoveryMethod, HostState, IcmpPing,
    IcmpTimestampPing, Icmpv6NeighborDiscovery, Icmpv6PacketBuilder, Icmpv6Ping, TcpAckPing,
    TcpSynPing, TcpSynPingV6, Tcpv6PacketBuilder,
};
pub use dns::DnsResolver;
pub use parser::TargetParser;
pub use spec::{Target, TargetGroup, TargetSpec};

/// Creates a new target parser with default configuration.
#[must_use]
pub const fn parser() -> TargetParser {
    TargetParser::new()
}

/// Eight-bit octet specification for IP range expansion.
///
/// Used for patterns like `192.168.1-10.*` where each octet
/// can be a single value, range, or wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OctetSpec {
    /// Single specific value.
    Single(u8),
    /// Inclusive range of values.
    Range(u8, u8),
    /// Wildcard matching all values (0-255).
    All,
}

impl OctetSpec {
    /// Returns true if this spec is a wildcard.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Returns the minimum value in this spec.
    #[must_use]
    pub const fn min(&self) -> u8 {
        match self {
            Self::Single(v) | Self::Range(v, _) => *v,
            Self::All => 0,
        }
    }

    /// Returns the maximum value in this spec.
    #[must_use]
    pub const fn max(&self) -> u8 {
        match self {
            Self::Single(v) | Self::Range(_, v) => *v,
            Self::All => 255,
        }
    }

    /// Returns an iterator over all values in this spec.
    #[must_use]
    pub fn iter(self) -> OctetIter {
        OctetIter {
            spec: self,
            done: false,
            current: self.min(),
        }
    }
}

/// Iterator over octet specification values.
#[derive(Debug, Clone)]
pub struct OctetIter {
    spec: OctetSpec,
    done: bool,
    current: u8,
}

impl Iterator for OctetIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let value = self.current;

        // Check if we've reached the end
        if self.current >= self.spec.max() {
            self.done = true;
        } else {
            self.current = self.current.wrapping_add(1);
        }

        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        let remaining = (self.spec.max() - self.current) as usize + 1;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for OctetIter {
    fn len(&self) -> usize {
        if self.done {
            0
        } else {
            (self.spec.max() - self.current) as usize + 1
        }
    }
}

/// Expands a target specification into a list of IP addresses.
///
/// # Errors
///
/// Returns an error if the specification is invalid or expansion
/// would produce an unreasonably large number of addresses.
pub fn expand_target_spec(spec: &TargetSpec) -> Result<Vec<Ipv4Addr>> {
    match spec {
        TargetSpec::SingleIpv4(addr) => Ok(vec![*addr]),
        TargetSpec::Ipv4Cidr { base, prefix } => expand_cidr_v4(*base, *prefix),
        TargetSpec::Ipv4Range { start, end } => expand_range_v4(*start, *end),
        TargetSpec::Ipv4OctetRange { octets } => expand_octet_range(octets),
        TargetSpec::Multiple(specs) => {
            let mut result = Vec::new();
            for s in specs {
                result.extend(expand_target_spec(s)?);
            }
            Ok(result)
        }
        _ => Ok(Vec::new()), // IPv6 and hostname not expanded in this function
    }
}

/// Expands an IPv4 CIDR block into individual addresses.
///
/// # Errors
///
/// Returns an error if prefix is invalid or expansion is too large.
fn expand_cidr_v4(base: Ipv4Addr, prefix: u8) -> Result<Vec<Ipv4Addr>> {
    if prefix > 32 {
        return Err(Error::Target(
            rustnmap_common::error::TargetError::InvalidCidr {
                cidr: format!("{base}/{prefix}"),
                reason: "prefix length must be <= 32".to_string(),
            },
        ));
    }

    // Limit expansion to prevent memory exhaustion
    let host_bits = 32u32.saturating_sub(u32::from(prefix));
    let count = 1u32.wrapping_shl(host_bits);

    if count > 65536 {
        // Limit CIDR expansion to /64 or smaller
        return Err(Error::Target(
            rustnmap_common::error::TargetError::InvalidCidr {
                cidr: format!("{base}/{prefix}"),
                reason: format!("CIDR expansion too large: {count} addresses"),
            },
        ));
    }

    let base_u32 = u32::from(base);
    let mut result = Vec::with_capacity(count as usize);

    for i in 0..count {
        let addr = Ipv4Addr::from(base_u32 | i);
        result.push(addr);
    }

    Ok(result)
}

/// Expands an IPv6 CIDR block into individual addresses.
///
/// # Errors
///
/// Returns an error if prefix is invalid or expansion is too large.
fn expand_cidr_v6(base: Ipv6Addr, prefix: u8) -> Result<Vec<Ipv6Addr>> {
    if prefix > 128 {
        return Err(Error::Target(
            rustnmap_common::error::TargetError::InvalidCidr {
                cidr: format!("{base}/{prefix}"),
                reason: "IPv6 prefix length must be <= 128".to_string(),
            },
        ));
    }

    // For IPv6, we need to be very careful about memory usage
    // IPv6 CIDR can theoretically have up to 2^64 addresses for /64 prefix
    // We limit expansion to /112 (65536 addresses max), same as IPv4's /16 limit
    let host_bits = 128u32.saturating_sub(u32::from(prefix));
    let count = if host_bits >= 64 {
        // Too large to materialize - return just the network address
        // This is common for standard /64 networks
        return Ok(vec![base]);
    } else {
        1u64.wrapping_shl(host_bits)
    };

    if count > 65536 {
        return Err(Error::Target(
            rustnmap_common::error::TargetError::InvalidCidr {
                cidr: format!("{base}/{prefix}"),
                reason: format!("IPv6 CIDR expansion too large: {count} addresses"),
            },
        ));
    }

    // Convert IPv6 to u128 for arithmetic
    let segments = base.segments();
    let base_u128: u128 = (u128::from(segments[0]) << 112)
        | (u128::from(segments[1]) << 96)
        | (u128::from(segments[2]) << 80)
        | (u128::from(segments[3]) << 64)
        | (u128::from(segments[4]) << 48)
        | (u128::from(segments[5]) << 32)
        | (u128::from(segments[6]) << 16)
        | u128::from(segments[7]);

    // Create host mask (not used directly - included for clarity)
    let _host_mask = if host_bits == 0 {
        0u128
    } else {
        (1u128.wrapping_shl(host_bits)) - 1
    };

    let capacity = usize::try_from(count).unwrap_or(usize::MAX);
    let mut result = Vec::with_capacity(capacity);

    for i in 0..count {
        let addr_u128 = base_u128 | u128::from(i);
        let addr = Ipv6Addr::new(
            ((addr_u128 >> 112) & 0xFFFF) as u16,
            ((addr_u128 >> 96) & 0xFFFF) as u16,
            ((addr_u128 >> 80) & 0xFFFF) as u16,
            ((addr_u128 >> 64) & 0xFFFF) as u16,
            ((addr_u128 >> 48) & 0xFFFF) as u16,
            ((addr_u128 >> 32) & 0xFFFF) as u16,
            ((addr_u128 >> 16) & 0xFFFF) as u16,
            (addr_u128 & 0xFFFF) as u16,
        );
        result.push(addr);
    }

    Ok(result)
}

/// Expands an IPv4 range into individual addresses.
fn expand_range_v4(start: Ipv4Addr, end: Ipv4Addr) -> Result<Vec<Ipv4Addr>> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    if end_u32 < start_u32 {
        return Err(Error::Target(
            rustnmap_common::error::TargetError::InvalidPortRange { start: 0, end: 0 },
        ));
    }

    let count = end_u32.wrapping_sub(start_u32).saturating_add(1);

    if count > 65536 {
        return Err(Error::config(format!(
            "IP range expansion too large: {count} addresses"
        )));
    }

    let mut result = Vec::with_capacity(count as usize);
    let mut current = start_u32;

    while current <= end_u32 {
        result.push(Ipv4Addr::from(current));
        current = current.saturating_add(1);
    }

    Ok(result)
}

/// Expands an octet range pattern like `192.168.1-10.*` into addresses.
fn expand_octet_range(octets: &[Option<OctetSpec>; 4]) -> Result<Vec<Ipv4Addr>> {
    // First calculate total size to avoid overflow
    // Use u64 to avoid overflow during calculation
    let size: u64 = octets
        .iter()
        .map(|o| {
            o.map_or(1u64, |spec| {
                u64::from(spec.max()) - u64::from(spec.min()) + 1
            })
        })
        .product();

    if size > 65536 {
        return Err(Error::config(format!(
            "Octet range expansion too large: {size} addresses"
        )));
    }

    let mut result = Vec::new();
    let current = [0u8; 4];

    // Recursive expansion using explicit stack to avoid recursion depth
    let mut stack = Vec::with_capacity(4);
    stack.push((0, current));

    while let Some((depth, mut addr)) = stack.pop() {
        if depth == 4 {
            result.push(Ipv4Addr::from(addr));
            continue;
        }

        let spec = match &octets[depth] {
            Some(s) => *s,
            None => OctetSpec::Single(0),
        };

        match spec {
            OctetSpec::Single(v) => {
                addr[depth] = v;
                stack.push((depth + 1, addr));
            }
            OctetSpec::Range(s, e) => {
                // Push in reverse order to maintain natural order
                for v in (s..=e).rev() {
                    let mut new_addr = addr;
                    new_addr[depth] = v;
                    stack.push((depth + 1, new_addr));
                }
            }
            OctetSpec::All => {
                for v in (0..=255).rev() {
                    let mut new_addr = addr;
                    new_addr[depth] = v;
                    stack.push((depth + 1, new_addr));
                }
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_octet_spec_single() {
        let spec = OctetSpec::Single(80);
        assert!(!spec.is_wildcard());
        assert_eq!(spec.min(), 80);
        assert_eq!(spec.max(), 80);
    }

    #[test]
    fn test_octet_spec_range() {
        let spec = OctetSpec::Range(80, 100);
        assert!(!spec.is_wildcard());
        assert_eq!(spec.min(), 80);
        assert_eq!(spec.max(), 100);
    }

    #[test]
    fn test_octet_spec_wildcard() {
        let spec = OctetSpec::All;
        assert!(spec.is_wildcard());
        assert_eq!(spec.min(), 0);
        assert_eq!(spec.max(), 255);
    }

    #[test]
    fn test_octet_iter_single() {
        let iter = OctetSpec::Single(42).iter();
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.collect::<Vec<_>>(), vec![42]);
    }

    #[test]
    fn test_octet_iter_range() {
        let iter = OctetSpec::Range(10, 13).iter();
        assert_eq!(iter.len(), 4);
        assert_eq!(iter.collect::<Vec<_>>(), vec![10, 11, 12, 13]);
    }

    #[test]
    fn test_octet_iter_wildcard() {
        let iter = OctetSpec::All.iter();
        assert_eq!(iter.len(), 256);
        let mut iter2 = OctetSpec::All.iter();
        assert_eq!(iter2.next().unwrap(), 0);
        assert_eq!(OctetSpec::All.iter().last().unwrap(), 255);
    }

    #[test]
    fn test_expand_cidr_v4() {
        let base = Ipv4Addr::new(192, 168, 1, 0);
        let result = expand_cidr_v4(base, 24).unwrap();
        assert_eq!(result.len(), 256);
        assert_eq!(result[0], base);
        assert_eq!(result[255], Ipv4Addr::new(192, 168, 1, 255));
    }

    #[test]
    fn test_expand_cidr_v4_too_large() {
        let base = Ipv4Addr::new(10, 0, 0, 0);
        // /8 would expand to 16M addresses - too large
        let result = expand_cidr_v4(base, 8);
        result.unwrap_err();
    }

    #[test]
    fn test_expand_range_v4() {
        let start = Ipv4Addr::new(192, 168, 1, 1);
        let end = Ipv4Addr::new(192, 168, 1, 5);
        let result = expand_range_v4(start, end).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], start);
        assert_eq!(result[4], end);
    }

    #[test]
    fn test_expand_octet_range() {
        let octets = [
            Some(OctetSpec::Single(192)),
            Some(OctetSpec::Single(168)),
            Some(OctetSpec::Single(1)),
            Some(OctetSpec::Range(1, 5)),
        ];
        let result = expand_octet_range(&octets).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(result[4], Ipv4Addr::new(192, 168, 1, 5));
    }

    #[test]
    fn test_expand_octet_range_wildcard() {
        let octets = [
            Some(OctetSpec::Single(10)),
            Some(OctetSpec::Range(0, 1)),
            Some(OctetSpec::Single(0)),
            Some(OctetSpec::All),
        ];
        let result = expand_octet_range(&octets).unwrap();
        assert_eq!(result.len(), 2 * 256);
        assert!(result.contains(&Ipv4Addr::new(10, 0, 0, 0)));
        assert!(result.contains(&Ipv4Addr::new(10, 1, 0, 255)));
    }

    #[test]
    fn test_expand_cidr_v6() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        // /120 gives 256 addresses
        let result = expand_cidr_v6(base, 120).unwrap();
        assert_eq!(result.len(), 256);
        assert_eq!(result[0], base);
        assert_eq!(
            result[255],
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xFF)
        );
    }

    #[test]
    fn test_expand_cidr_v6_single() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        // /128 gives 1 address
        let result = expand_cidr_v6(base, 128).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], base);
    }

    #[test]
    fn test_expand_cidr_v6_large_prefix() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        // /64 returns just the network address (too large to expand)
        let result = expand_cidr_v6(base, 64).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], base);
    }

    #[test]
    fn test_expand_cidr_v6_invalid_prefix() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        // /129 is invalid
        let result = expand_cidr_v6(base, 129);
        result.unwrap_err();
    }
}
