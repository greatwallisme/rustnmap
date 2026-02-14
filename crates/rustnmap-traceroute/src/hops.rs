//! Hop information structures for traceroute results.

use rustnmap_common::Ipv4Addr;
use std::time::Duration;

/// Information about a single hop in the network path.
#[derive(Debug, Clone, PartialEq)]
pub struct HopInfo {
    /// TTL value for this hop.
    ttl: u8,

    /// IP address of the responding router.
    ip: Option<Ipv4Addr>,

    /// Resolved hostname (if enabled).
    hostname: Option<String>,

    /// Round-trip times for each probe sent to this hop.
    rtts: Vec<Duration>,

    /// Packet loss rate (0.0 to 1.0).
    loss: f32,
}

/// Path MTU information discovered during traceroute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMtu {
    /// The MTU value in bytes.
    value: u16,

    /// TTL at which MTU was discovered.
    ttl: u8,
}

impl HopInfo {
    /// Creates a new hop info instance.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Time-to-live value for this hop
    /// * `ip` - IP address of responding router (if any)
    /// * `hostname` - Resolved hostname (if available)
    /// * `rtts` - List of round-trip times for probes
    /// * `loss` - Packet loss rate (0.0 = none, 1.0 = all)
    #[must_use]
    pub const fn new(
        ttl: u8,
        ip: Option<Ipv4Addr>,
        hostname: Option<String>,
        rtts: Vec<Duration>,
        loss: f32,
    ) -> Self {
        Self {
            ttl,
            ip,
            hostname,
            rtts,
            loss,
        }
    }

    /// Returns the TTL value for this hop.
    #[must_use]
    pub const fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Returns the IP address of the responding router.
    #[must_use]
    pub const fn ip(&self) -> Option<Ipv4Addr> {
        self.ip
    }

    /// Returns the resolved hostname (if available).
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Returns the list of round-trip times for all probes.
    #[must_use]
    pub fn rtts(&self) -> &[Duration] {
        &self.rtts
    }

    /// Returns the number of probes sent.
    #[must_use]
    pub fn probe_count(&self) -> usize {
        self.rtts.len()
    }

    /// Returns the number of successful probes (received responses).
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.rtts.len()
    }

    /// Returns the packet loss rate (0.0 to 1.0).
    #[must_use]
    pub const fn loss(&self) -> f32 {
        self.loss
    }

    /// Returns the average round-trip time for successful probes.
    ///
    /// Returns `None` if no probes were successful.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "f64 has limited mantissa, precision loss acceptable"
    )]
    pub fn avg_rtt(&self) -> Option<Duration> {
        if self.rtts.is_empty() {
            return None;
        }
        let total: u128 = self.rtts.iter().map(Duration::as_micros).sum();
        Some(Duration::from_micros(
            u64::try_from(total / self.rtts.len() as u128).unwrap_or(u64::MAX),
        ))
    }

    /// Returns the minimum round-trip time.
    #[must_use]
    pub fn min_rtt(&self) -> Option<Duration> {
        self.rtts.iter().min().copied()
    }

    /// Returns the maximum round-trip time.
    #[must_use]
    pub fn max_rtt(&self) -> Option<Duration> {
        self.rtts.iter().max().copied()
    }

    /// Returns the standard deviation of round-trip times.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "f64 sqrt is positive, truncation acceptable"
    )]
    pub fn rtt_stddev(&self) -> Option<Duration> {
        if self.rtts.len() < 2 {
            return None;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "f64 has limited mantissa, precision loss acceptable for RTT calculations"
        )]
        let avg = self.avg_rtt()?.as_micros() as f64;
        #[allow(
            clippy::cast_precision_loss,
            reason = "f64 has limited mantissa, precision loss acceptable for RTT calculations"
        )]
        let variance: f64 = self
            .rtts
            .iter()
            .map(|d| {
                let diff = d.as_micros() as f64 - avg;
                diff * diff
            })
            .sum::<f64>()
            / self.rtts.len() as f64;
        Some(Duration::from_micros(variance.sqrt() as u64))
    }

    /// Returns whether the hop responded to any probe.
    #[must_use]
    pub fn responded(&self) -> bool {
        self.ip.is_some()
    }
}

impl PathMtu {
    /// Creates a new path MTU info instance.
    ///
    /// # Arguments
    ///
    /// * `value` - MTU value in bytes
    /// * `ttl` - TTL at which MTU was discovered
    #[must_use]
    pub const fn new(value: u16, ttl: u8) -> Self {
        Self { value, ttl }
    }

    /// Returns the MTU value in bytes.
    #[must_use]
    pub const fn value(&self) -> u16 {
        self.value
    }

    /// Returns the TTL at which MTU was discovered.
    #[must_use]
    pub const fn ttl(&self) -> u8 {
        self.ttl
    }
}

impl std::fmt::Display for HopInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TTL: {}", self.ttl)?;
        if let Some(ip) = self.ip {
            write!(f, " IP: {ip}")?;
        } else {
            write!(f, " IP: *")?;
        }
        if let Some(hostname) = &self.hostname {
            write!(f, " ({hostname})")?;
        }
        if let Some(avg) = self.avg_rtt() {
            #[allow(
                clippy::cast_precision_loss,
                reason = "f64 has limited mantissa, precision loss acceptable for RTT display"
            )]
            write!(f, " RTT: {:.2}ms", avg.as_micros() as f64 / 1000.0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_info_new() {
        let hop = HopInfo::new(1, None, None, vec![], 0.0);
        assert_eq!(hop.ttl(), 1);
        assert!(hop.ip().is_none());
        assert!(hop.hostname().is_none());
        assert_eq!(hop.probe_count(), 0);
        assert!(!hop.responded());
    }

    #[test]
    fn test_hop_info_with_ip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let hop = HopInfo::new(1, Some(ip), None, vec![], 0.0);
        assert_eq!(hop.ip(), Some(ip));
        assert!(hop.responded());
    }

    #[test]
    fn test_hop_info_with_rtts() {
        let rtts = vec![
            Duration::from_millis(10),
            Duration::from_millis(12),
            Duration::from_millis(11),
        ];
        let hop = HopInfo::new(1, Some(Ipv4Addr::new(192, 168, 1, 1)), None, rtts, 0.0);

        assert_eq!(hop.probe_count(), 3);
        assert!(hop.avg_rtt().is_some());
        assert!(hop.min_rtt().is_some());
        assert!(hop.max_rtt().is_some());

        let avg = hop.avg_rtt().unwrap();
        assert!(avg >= Duration::from_millis(10) && avg <= Duration::from_millis(12));
    }

    #[test]
    fn test_hop_info_avg_rtt_empty() {
        let hop = HopInfo::new(1, None, None, vec![], 0.0);
        assert!(hop.avg_rtt().is_none());
    }

    #[test]
    fn test_hop_info_rtt_stddev() {
        let rtts = vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(15),
        ];
        let hop = HopInfo::new(1, Some(Ipv4Addr::new(192, 168, 1, 1)), None, rtts, 0.0);

        // Should have stddev with multiple samples
        let stddev = hop.rtt_stddev();
        assert!(stddev.is_some());
    }

    #[test]
    fn test_hop_info_rtt_stddev_single() {
        let rtts = vec![Duration::from_millis(10)];
        let hop = HopInfo::new(1, Some(Ipv4Addr::new(192, 168, 1, 1)), None, rtts, 0.0);

        // Should not have stddev with single sample
        let stddev = hop.rtt_stddev();
        assert!(stddev.is_none());
    }

    #[test]
    #[allow(clippy::float_cmp, reason = "comparing exact f32 values set in test")]
    fn test_hop_info_loss() {
        let hop = HopInfo::new(1, Some(Ipv4Addr::new(192, 168, 1, 1)), None, vec![], 0.5);
        assert_eq!(hop.loss(), 0.5);
    }

    #[test]
    fn test_path_mtu_new() {
        let mtu = PathMtu::new(1500, 5);
        assert_eq!(mtu.value(), 1500);
        assert_eq!(mtu.ttl(), 5);
    }

    #[test]
    fn test_hop_display() {
        let hop = HopInfo::new(
            1,
            Some(Ipv4Addr::new(192, 168, 1, 1)),
            Some("router.local".to_string()),
            vec![Duration::from_millis(10)],
            0.0,
        );
        let display = format!("{hop}");
        assert!(display.contains("TTL: 1"));
        assert!(display.contains("192.168.1.1"));
        assert!(display.contains("router.local"));
        assert!(display.contains("10.00ms"));
    }
}
