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

//! Target specification types for `RustNmap`.
//!
//! This module defines the types used to represent network targets
//! in various formats: single IPs, CIDR blocks, ranges, wildcards, etc.

use rustnmap_common::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::fmt;

/// A single network target to be scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// IP address of the target.
    pub ip: IpAddr,
    /// Optional hostname.
    pub hostname: Option<String>,
    /// Optional port override for this target.
    pub ports: Option<Vec<u16>>,
    /// IPv6 zone ID for link-local addresses.
    pub ipv6_scope: Option<u32>,
}

impl From<Ipv4Addr> for Target {
    fn from(addr: Ipv4Addr) -> Self {
        Self {
            ip: IpAddr::V4(addr),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        }
    }
}

impl From<Ipv6Addr> for Target {
    fn from(addr: Ipv6Addr) -> Self {
        Self {
            ip: IpAddr::V6(addr),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        }
    }
}

impl From<IpAddr> for Target {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => Self::from(a),
            IpAddr::V6(a) => Self::from(a),
        }
    }
}

/// Target specification before expansion.
///
/// This represents the parsed form of a target string before
/// it is expanded into individual addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    /// Single IPv4 address.
    SingleIpv4(Ipv4Addr),
    /// Single IPv6 address.
    SingleIpv6(Ipv6Addr),
    /// Hostname to be resolved.
    Hostname(String),
    /// IPv4 CIDR block.
    Ipv4Cidr {
        /// Base address of the CIDR block.
        base: Ipv4Addr,
        /// Prefix length (0-32).
        prefix: u8,
    },
    /// IPv6 CIDR block.
    Ipv6Cidr {
        /// Base address of the CIDR block.
        base: Ipv6Addr,
        /// Prefix length (0-128).
        prefix: u8,
    },
    /// IPv4 address range.
    Ipv4Range {
        /// Start address (inclusive).
        start: Ipv4Addr,
        /// End address (inclusive).
        end: Ipv4Addr,
    },
    /// IPv4 octet range pattern (e.g., `192.168.1-10.*`).
    Ipv4OctetRange {
        /// Octet specifications for each of the 4 octets.
        octets: [Option<crate::OctetSpec>; 4],
    },
    /// Target with specific ports.
    WithPort(Box<TargetSpec>, Vec<u16>),
    /// Multiple target specifications.
    Multiple(Vec<TargetSpec>),
}

impl fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleIpv4(addr) => write!(f, "{addr}"),
            Self::SingleIpv6(addr) => write!(f, "{addr}"),
            Self::Hostname(name) => write!(f, "{name}"),
            Self::Ipv4Cidr { base, prefix } => write!(f, "{base}/{prefix}"),
            Self::Ipv6Cidr { base, prefix } => write!(f, "{base}/{prefix}"),
            Self::Ipv4Range { start, end } => write!(f, "{start}-{end}"),
            Self::Ipv4OctetRange { octets } => {
                for (i, opt) in octets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ".")?;
                    }
                    match opt {
                        None | Some(crate::OctetSpec::All) => write!(f, "*")?,
                        Some(crate::OctetSpec::Single(v)) => write!(f, "{v}")?,
                        Some(crate::OctetSpec::Range(s, e)) => write!(f, "{s}-{e}")?,
                    }
                }
                Ok(())
            }
            Self::WithPort(spec, ports) => {
                write!(f, "{spec}:")?;
                for (i, port) in ports.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{port}")?;
                }
                Ok(())
            }
            Self::Multiple(specs) => {
                for (i, spec) in specs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{spec}")?;
                }
                Ok(())
            }
        }
    }
}

/// A group of targets to scan together.
///
/// This is the output of target parsing and expansion.
#[derive(Debug, Clone)]
pub struct TargetGroup {
    /// The targets in this group.
    pub targets: Vec<Target>,
    /// Statistics about the target group.
    pub stats: TargetGroupStats,
}

impl TargetGroup {
    /// Creates a new target group from a list of targets.
    #[must_use]
    pub fn new(targets: Vec<Target>) -> Self {
        let stats = TargetGroupStats::from_targets(&targets);
        Self { targets, stats }
    }

    /// Returns the number of targets in this group.
    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Returns true if this group is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// Statistics about a target group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetGroupStats {
    /// Total number of targets.
    pub total_count: usize,
    /// Number of IPv4 targets.
    pub ipv4_count: usize,
    /// Number of IPv6 targets.
    pub ipv6_count: usize,
}

impl TargetGroupStats {
    /// Creates statistics from a list of targets.
    fn from_targets(targets: &[Target]) -> Self {
        let total_count = targets.len();
        let ipv4_count = targets
            .iter()
            .filter(|t| matches!(t.ip, IpAddr::V4(_)))
            .count();
        let ipv6_count = targets
            .iter()
            .filter(|t| matches!(t.ip, IpAddr::V6(_)))
            .count();

        Self {
            total_count,
            ipv4_count,
            ipv6_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_from_ipv4() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let target = Target::from(addr);
        assert!(matches!(target.ip, IpAddr::V4(_)));
        assert_eq!(target.hostname, None);
    }

    #[test]
    fn test_target_from_ipv6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let target = Target::from(addr);
        assert!(matches!(target.ip, IpAddr::V6(_)));
        assert_eq!(target.hostname, None);
    }

    #[test]
    fn test_target_group_stats() {
        let targets = vec![
            Target::from(Ipv4Addr::new(192, 168, 1, 1)),
            Target::from(Ipv4Addr::new(192, 168, 1, 2)),
            Target::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];
        let group = TargetGroup::new(targets);
        assert_eq!(group.len(), 3);
        assert_eq!(group.stats.ipv4_count, 2);
        assert_eq!(group.stats.ipv6_count, 1);
        assert_eq!(group.stats.total_count, 3);
    }

    #[test]
    fn test_target_spec_display_cidr() {
        let spec = TargetSpec::Ipv4Cidr {
            base: Ipv4Addr::new(192, 168, 1, 0),
            prefix: 24,
        };
        assert_eq!(spec.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_target_spec_display_range() {
        let spec = TargetSpec::Ipv4Range {
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
        };
        assert_eq!(spec.to_string(), "192.168.1.1-192.168.1.100");
    }
}
