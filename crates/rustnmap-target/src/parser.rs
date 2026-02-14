//! Target specification parser for `RustNmap`.
//!
//! This module provides the parser that converts target strings
//! into [`TargetSpec`] enums for expansion.

use crate::{DnsResolver, OctetSpec, Target, TargetGroup, TargetSpec};
use rustnmap_common::{error::TargetError, Error, Ipv4Addr, Ipv6Addr};

/// Result type for async parser operations.
pub type AsyncResult<T> = std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<T>> + Send>>;

/// Target specification parser.
///
/// Parses target strings in various formats:
/// - Single IPs: `192.168.1.1`, `2001:db8::1`
/// - Hostnames: `example.com`
/// - CIDR: `192.168.0.0/24`
/// - Ranges: `192.168.1.1-100`
/// - Octet ranges: `192.168.1-10.*`
/// - Multiple: `192.168.1.1,192.168.2.1`
/// - With ports: `example.com:80,443`
#[derive(Debug, Clone)]
pub struct TargetParser {
    /// DNS resolver for hostname resolution.
    dns_resolver: Option<DnsResolver>,

    /// Exclusion list (not yet implemented).
    #[expect(dead_code, reason = "Will be implemented in future phase")]
    exclude_list: Vec<TargetSpec>,
}

impl TargetParser {
    /// Creates a new target parser without DNS resolution.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dns_resolver: None,
            exclude_list: Vec::new(),
        }
    }

    /// Creates a new target parser with DNS resolution enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the DNS resolver cannot be created.
    pub fn with_dns() -> crate::Result<Self> {
        let resolver = DnsResolver::new()?;

        Ok(Self {
            dns_resolver: Some(resolver),
            exclude_list: Vec::new(),
        })
    }

    /// Sets the DNS resolver for this parser.
    pub fn set_dns_resolver(&mut self, resolver: DnsResolver) {
        self.dns_resolver = Some(resolver);
    }

    /// Parses a target string into a target group.
    ///
    /// # Errors
    ///
    /// Returns an error if the input contains invalid target specifications.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_target::TargetParser;
    ///
    /// let parser = TargetParser::new();
    /// let group = parser.parse("192.168.1.1").unwrap();
    /// assert_eq!(group.len(), 1);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the input produces no valid target specifications.
    #[allow(clippy::missing_panics_doc, reason = "Never panics for valid input")]
    pub fn parse(&self, input: &str) -> crate::Result<TargetGroup> {
        let tokens = Self::tokenize(input)?;
        let mut specs = Vec::new();

        for token in tokens {
            let spec = Self::parse_token(&token)?;
            specs.push(spec);
        }

        // Combine multiple specs into one if needed
        let final_spec = if specs.len() == 1 {
            specs.into_iter().next().unwrap()
        } else {
            TargetSpec::Multiple(specs)
        };

        // Expand the spec into targets
        let targets = Self::expand_spec(self, &final_spec)?;

        Ok(TargetGroup::new(targets))
    }

    /// Tokenizes input string into individual target specifications.
    fn tokenize(input: &str) -> crate::Result<Vec<String>> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut after_colon = false;

        for ch in input.chars() {
            match ch {
                ':' => {
                    current.push(ch);
                    after_colon = true;
                }
                ',' => {
                    if after_colon {
                        // Comma after colon is part of port specification
                        current.push(ch);
                    } else if !current.is_empty() {
                        tokens.push(current.trim().to_string());
                        current = String::new();
                    }
                }
                ' ' | '\t' | '\n' | '\r' => {
                    if !current.is_empty() && !after_colon {
                        tokens.push(current.trim().to_string());
                        current = String::new();
                    } else {
                        current.push(ch);
                    }
                }
                _ => {
                    current.push(ch);
                    if !ch.is_ascii_digit() {
                        after_colon = false;
                    }
                }
            }
        }

        if !current.trim().is_empty() {
            tokens.push(current.trim().to_string());
        }

        if tokens.is_empty() {
            return Err(Error::Target(TargetError::EmptySpecification));
        }

        Ok(tokens)
    }

    /// Parses a single token into a target specification.
    fn parse_token(token: &str) -> crate::Result<TargetSpec> {
        // Check for port specification
        if let Some((addr_part, ports_part)) = token.split_once(':') {
            if ports_part.chars().all(|c| c.is_ascii_digit() || c == ',') {
                let ports = Self::parse_ports(ports_part)?.into_iter().collect();
                let inner_spec = Self::parse_token(addr_part)?;
                return Ok(TargetSpec::WithPort(Box::new(inner_spec), ports));
            }
        }

        // Try IPv6 address first (contains ':')
        if token.contains(':') && !token.contains(',') {
            if let Ok(addr) = token.parse::<Ipv6Addr>() {
                return Ok(TargetSpec::SingleIpv6(addr));
            }
            if let Some((addr, prefix)) = token.split_once('/') {
                if let Ok(addr) = addr.parse::<Ipv6Addr>() {
                    if let Ok(prefix) = prefix.parse::<u8>() {
                        return Ok(TargetSpec::Ipv6Cidr { base: addr, prefix });
                    }
                }
            }
        }

        // Try IPv4 CIDR
        if let Some((addr, prefix)) = token.split_once('/') {
            if let Ok(addr) = addr.parse::<Ipv4Addr>() {
                if let Ok(prefix) = prefix.parse::<u8>() {
                    return Ok(TargetSpec::Ipv4Cidr { base: addr, prefix });
                }
            }
        }

        // Try IPv4 range
        if token.contains('-') && !token.contains(',') {
            let parts: Vec<&str> = token.split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<Ipv4Addr>();
                let end = parts[1].parse::<Ipv4Addr>();
                if let (Ok(start), Ok(end)) = (start, end) {
                    return Ok(TargetSpec::Ipv4Range { start, end });
                }
            }
        }

        // Try octet range (e.g., 192.168.1-10.*)
        if token.contains('.') || token.contains('*') {
            if let Some(spec) = Self::parse_octet_range(token)? {
                return Ok(spec);
            }
        }

        // Try single IPv4
        if let Ok(addr) = token.parse::<Ipv4Addr>() {
            return Ok(TargetSpec::SingleIpv4(addr));
        }

        // Treat as hostname
        Ok(TargetSpec::Hostname(token.to_string()))
    }

    /// Parses an octet range pattern like `192.168.1-10.*`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "Using Result for consistent error handling"
    )]
    fn parse_octet_range(input: &str) -> crate::Result<Option<TargetSpec>> {
        let octets: Vec<&str> = input.split('.').collect();
        if octets.len() != 4 {
            return Ok(None);
        }

        let mut result = [None; 4];
        for (i, octet) in octets.iter().enumerate() {
            result[i] = Some(Self::parse_octet_spec(octet));
        }

        Ok(Some(TargetSpec::Ipv4OctetRange { octets: result }))
    }

    /// Parses a single octet specification.
    fn parse_octet_spec(input: &str) -> OctetSpec {
        if input == "*" {
            OctetSpec::All
        } else if let Some((start, end)) = input.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.parse::<u8>(), end.parse::<u8>()) {
                OctetSpec::Range(start, end)
            } else {
                OctetSpec::Single(0)
            }
        } else {
            OctetSpec::Single(input.parse().unwrap_or(0))
        }
    }

    /// Parses a comma-separated port list.
    fn parse_ports(input: &str) -> crate::Result<Vec<u16>> {
        let mut ports = Vec::new();

        for part in input.split(',') {
            let port = part
                .parse::<u16>()
                .map_err(|_e| Error::Target(TargetError::PortOutOfRange { port: 0 }))?;
            if port == 0 {
                return Err(Error::Target(TargetError::PortOutOfRange { port }));
            }
            ports.push(port);
        }

        Ok(ports)
    }

    /// Expands a target specification into individual targets.
    #[expect(
        clippy::only_used_in_recursion,
        reason = "Required for recursive expansion"
    )]
    fn expand_spec(&self, spec: &TargetSpec) -> crate::Result<Vec<Target>> {
        match spec {
            TargetSpec::SingleIpv4(addr) => Ok(vec![Target::from(*addr)]),
            TargetSpec::SingleIpv6(addr) => Ok(vec![Target::from(*addr)]),
            TargetSpec::Hostname(name) => {
                // When no DNS resolver is configured, return an error
                Err(Error::config(format!(
                    "Hostname '{name}' requires DNS resolution. Use with_dns() or parse_async()"
                )))
            }
            TargetSpec::Ipv4Cidr { base, prefix } => {
                let addrs = crate::expand_cidr_v4(*base, *prefix)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
            TargetSpec::Ipv4Range { start, end } => {
                let addrs = crate::expand_range_v4(*start, *end)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
            TargetSpec::Ipv4OctetRange { octets } => {
                let addrs = crate::expand_octet_range(octets)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
            TargetSpec::WithPort(inner, ports) => {
                let mut targets = Self::expand_spec(self, inner)?;
                for target in &mut targets {
                    target.ports = Some(ports.clone());
                }
                Ok(targets)
            }
            TargetSpec::Multiple(specs) => {
                let mut result = Vec::new();
                for spec in specs {
                    result.extend(Self::expand_spec(self, spec)?);
                }
                Ok(result)
            }
            TargetSpec::Ipv6Cidr { base, prefix } => {
                let addrs = crate::expand_cidr_v6(*base, *prefix)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
        }
    }

    /// Asynchronously parses a target string into a target group with DNS resolution.
    ///
    /// This method enables DNS resolution for hostnames and returns the resolved targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the input contains invalid target specifications or DNS resolution fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use rustnmap_target::TargetParser;
    ///
    /// let parser = TargetParser::with_dns().await.unwrap();
    /// let group = parser.parse_async("example.com").await.unwrap();
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the input produces no valid target specifications.
    pub async fn parse_async(&self, input: &str) -> crate::Result<TargetGroup> {
        let tokens = Self::tokenize(input)?;
        let mut specs = Vec::new();

        for token in tokens {
            let spec = Self::parse_token(&token)?;
            specs.push(spec);
        }

        // Combine multiple specs into one if needed
        let final_spec = if specs.len() == 1 {
            specs.into_iter().next().unwrap()
        } else {
            TargetSpec::Multiple(specs)
        };

        // Expand the spec into targets asynchronously
        let targets = self.expand_spec_async(&final_spec).await?;

        Ok(TargetGroup::new(targets))
    }

    /// Asynchronously expands a target specification into individual targets.
    #[allow(
        clippy::only_used_in_recursion,
        reason = "Required for recursive expansion"
    )]
    async fn expand_spec_async(&self, spec: &TargetSpec) -> crate::Result<Vec<Target>> {
        match spec {
            TargetSpec::SingleIpv4(addr) => Ok(vec![Target::from(*addr)]),
            TargetSpec::SingleIpv6(addr) => Ok(vec![Target::from(*addr)]),
            TargetSpec::Hostname(name) => {
                // Use DNS resolver if available
                if let Some(ref resolver) = self.dns_resolver {
                    let addresses = resolver.resolve(name).await?;
                    let targets = addresses
                        .into_iter()
                        .map(|ip| Target {
                            ip,
                            hostname: Some(name.clone()),
                            ports: None,
                            ipv6_scope: None,
                        })
                        .collect();
                    Ok(targets)
                } else {
                    Err(Error::config(
                        "DNS resolver not configured. Use with_dns() to enable hostname resolution".to_string(),
                    ))
                }
            }
            TargetSpec::Ipv4Cidr { base, prefix } => {
                let addrs = crate::expand_cidr_v4(*base, *prefix)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
            TargetSpec::Ipv4Range { start, end } => {
                let addrs = crate::expand_range_v4(*start, *end)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
            TargetSpec::Ipv4OctetRange { octets } => {
                let addrs = crate::expand_octet_range(octets)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
            TargetSpec::WithPort(inner, ports) => {
                let mut targets = Box::pin(self.expand_spec_async(inner)).await?;
                for target in &mut targets {
                    target.ports = Some(ports.clone());
                }
                Ok(targets)
            }
            TargetSpec::Multiple(specs) => {
                let mut result = Vec::new();
                for spec in specs {
                    result.extend(Box::pin(self.expand_spec_async(spec)).await?);
                }
                Ok(result)
            }
            TargetSpec::Ipv6Cidr { base, prefix } => {
                let addrs = crate::expand_cidr_v6(*base, *prefix)?;
                Ok(addrs.into_iter().map(Target::from).collect())
            }
        }
    }
}

impl Default for TargetParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_common::IpAddr;

    #[test]
    fn test_parse_single_ipv4() {
        let parser = TargetParser::new();
        let group = parser.parse("192.168.1.1").unwrap();
        assert_eq!(group.len(), 1);
        assert_eq!(
            group.targets[0].ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_parse_cidr() {
        let parser = TargetParser::new();
        let group = parser.parse("192.168.1.0/24").unwrap();
        assert_eq!(group.len(), 256);
    }

    #[test]
    fn test_parse_range() {
        let parser = TargetParser::new();
        let group = parser.parse("192.168.1.1-5").unwrap();
        assert_eq!(group.len(), 5);
    }

    #[test]
    fn test_parse_multiple() {
        let parser = TargetParser::new();
        let group = parser.parse("192.168.1.1,192.168.1.10").unwrap();
        assert_eq!(group.len(), 2);
    }

    #[test]
    fn test_parse_hostname_without_dns() {
        // Without DNS resolver, hostname parsing should fail
        let parser = TargetParser::new();
        let result = parser.parse("example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DNS"));
    }

    #[tokio::test]
    async fn test_parse_hostname_with_dns() {
        // With DNS resolver, hostname parsing should work
        let parser = TargetParser::with_dns().unwrap();
        let group = parser.parse_async("localhost").await.unwrap();
        assert!(!group.is_empty());
        // localhost should have at least one target with hostname set
        assert!(group.targets.iter().any(|t| t.hostname == Some("localhost".to_string())));
    }

    #[test]
    fn test_parse_with_ports() {
        let parser = TargetParser::new();
        let group = parser.parse("192.168.1.1:80,443").unwrap();
        assert_eq!(group.len(), 1);
        assert_eq!(group.targets[0].ports, Some(vec![80, 443]));
    }

    #[test]
    fn test_parse_empty() {
        let parser = TargetParser::new();
        let result = parser.parse("");
        assert!(result.is_err());
    }
}
