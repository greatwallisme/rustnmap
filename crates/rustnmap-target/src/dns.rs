//! DNS resolution for target hostnames.
//!
//! This module provides DNS resolution using trust-dns-resolver,
//! supporting A, AAAA, and PTR records.

use rustnmap_common::{Error, IpAddr, Result};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

/// DNS resolver for target hostnames.
///
/// Resolves hostnames to IP addresses and supports reverse DNS lookups.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    /// The underlying resolver instance.
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    /// Creates a new DNS resolver with system configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver cannot be created.
    pub fn new() -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self { resolver })
    }

    /// Resolves a hostname to IP addresses.
    ///
    /// Returns both IPv4 and IPv6 addresses for the hostname.
    ///
    /// # Errors
    ///
    /// Returns an error if the hostname cannot be resolved.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();

        // Try to resolve A/AAAA records
        match self.resolver.lookup_ip(hostname).await {
            Ok(ips) => {
                for ip in ips.iter() {
                    addresses.push(ip);
                }
            }
            Err(e) => {
                return Err(Error::config(format!(
                    "DNS resolution failed for {hostname}: {e}"
                )));
            }
        }

        if addresses.is_empty() {
            return Err(Error::config(format!(
                "No IP addresses found for {hostname}"
            )));
        }

        Ok(addresses)
    }

    /// Performs a reverse DNS lookup (PTR record) for an IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if the reverse lookup fails.
    pub async fn reverse_lookup(&self, ip: IpAddr) -> Result<Option<String>> {
        let name = match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(v6) => {
                // IPv6 reverse lookup format
                let segments = v6.segments();
                let mut reverse_parts = Vec::new();
                for segment in segments.iter().rev() {
                    let bytes = segment.to_be_bytes();
                    reverse_parts.push(format!("{:x}", bytes[1]));
                    reverse_parts.push(format!("{:x}", bytes[0]));
                }
                format!("{}.ip6.arpa", reverse_parts.join("."))
            }
        };

        match self
            .resolver
            .lookup(&name, trust_dns_resolver::proto::rr::RecordType::PTR)
            .await
        {
            Ok(lookup) => {
                for record in lookup.record_iter() {
                    if let Some(ptr) = record.data().and_then(|d| d.as_ptr()) {
                        return Ok(Some(ptr.0.to_string()));
                    }
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_localhost() {
        let resolver = DnsResolver::new().unwrap();
        let addresses = resolver.resolve("localhost").await.unwrap();

        // localhost should resolve to at least 127.0.0.1
        assert!(!addresses.is_empty());
        assert!(addresses
            .iter()
            .any(|ip| matches!(ip, IpAddr::V4(v4) if v4.octets() == [127, 0, 0, 1])));
    }

    #[tokio::test]
    async fn test_resolve_invalid_hostname() {
        let resolver = DnsResolver::new().unwrap();
        let result = resolver.resolve("this-should-not-exist.invalid-tld").await;
        result.unwrap_err();
    }

    #[tokio::test]
    async fn test_reverse_lookup_localhost() {
        let resolver = DnsResolver::new().unwrap();
        let hostname = resolver
            .reverse_lookup(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .await
            .unwrap();

        // Should resolve to localhost or similar
        assert!(hostname.is_some());
    }
}
