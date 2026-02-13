// Rust guideline compliant 2026-02-12

//! Evasion configuration types.
//!
//! This module defines the configuration structures for all evasion techniques.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Overall evasion configuration combining all evasion techniques.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// IP fragmentation configuration.
    pub fragmentation: Option<FragmentConfig>,

    /// Decoy scanning configuration.
    pub decoys: Option<DecoyConfig>,

    /// Source address configuration.
    pub source: SourceConfig,

    /// Packet modification configuration.
    pub packet_modification: PacketModConfig,

    /// Timing configuration.
    pub timing: TimingConfig,
}

impl EvasionConfig {
    /// Creates a new builder for `EvasionConfig`.
    #[must_use]
    pub fn builder() -> EvasionConfigBuilder {
        EvasionConfigBuilder::new()
    }

    /// Returns true if any evasion technique is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.fragmentation.is_some()
            || self.decoys.is_some()
            || self.source.source_ip.is_some()
            || self.source.source_port.is_some()
            || self.packet_modification.bad_checksum
            || self.packet_modification.data_length.is_some()
            || self.packet_modification.ip_options.is_some()
            || self.packet_modification.ttl.is_some()
    }
}

/// Builder for constructing `EvasionConfig`.
#[derive(Debug, Clone)]
pub struct EvasionConfigBuilder {
    config: EvasionConfig,
}

impl EvasionConfigBuilder {
    fn new() -> Self {
        Self {
            config: EvasionConfig::default(),
        }
    }

    /// Sets the fragmentation configuration.
    #[must_use]
    pub fn fragmentation(mut self, _fragment_size: u16) -> Self {
        self.config.fragmentation = Some(FragmentConfig {
            enabled: true,
            mode: FragmentMode::Default,
            overlap: false,
            timeout: Duration::from_secs(30),
        });
        self
    }

    /// Sets custom MTU fragmentation.
    #[must_use]
    pub fn fragmentation_mtu(mut self, mtu: u16) -> Self {
        self.config.fragmentation = Some(FragmentConfig {
            enabled: true,
            mode: FragmentMode::CustomMTU(mtu),
            overlap: false,
            timeout: Duration::from_secs(30),
        });
        self
    }

    /// Sets random fragmentation range.
    #[must_use]
    pub fn fragmentation_random(mut self, min: usize, max: usize) -> Self {
        self.config.fragmentation = Some(FragmentConfig {
            enabled: true,
            mode: FragmentMode::Random { min, max },
            overlap: false,
            timeout: Duration::from_secs(30),
        });
        self
    }

    /// Sets the decoy configuration.
    #[must_use]
    pub fn decoys(mut self, decoys: Vec<IpAddr>) -> Self {
        self.config.decoys = Some(DecoyConfig {
            decoys,
            real_ip_position: 0,
            random_order: false,
        });
        self
    }

    /// Sets decoys with custom real IP position.
    #[must_use]
    pub fn decoys_with_position(mut self, decoys: Vec<IpAddr>, real_ip_position: usize) -> Self {
        self.config.decoys = Some(DecoyConfig {
            decoys,
            real_ip_position,
            random_order: false,
        });
        self
    }

    /// Sets the source IP address.
    #[must_use]
    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.config.source.source_ip = Some(ip);
        self
    }

    /// Sets the source port.
    #[must_use]
    pub fn source_port(mut self, port: u16) -> Self {
        self.config.source.source_port = Some(port);
        self
    }

    /// Sets the source MAC address.
    #[must_use]
    pub fn source_mac(mut self, mac: [u8; 6]) -> Self {
        self.config.source.source_mac = Some(mac);
        self
    }

    /// Sets the network interface.
    #[must_use]
    pub fn interface(mut self, iface: String) -> Self {
        self.config.source.interface = Some(iface);
        self
    }

    /// Enables bad checksum (for testing firewall responses).
    #[must_use]
    pub fn bad_checksum(mut self) -> Self {
        self.config.packet_modification.bad_checksum = true;
        self
    }

    /// Sets data padding length.
    #[must_use]
    pub fn data_length(mut self, length: usize) -> Self {
        self.config.packet_modification.data_length = Some(length);
        self
    }

    /// Sets the TTL value.
    #[must_use]
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.config.packet_modification.ttl = Some(ttl);
        self
    }

    /// Sets the timing template.
    #[must_use]
    pub fn timing_template(mut self, template: TimingTemplate) -> Self {
        self.config.timing.template = template;
        self
    }

    /// Builds the final configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The fragment size is invalid (less than 8 or greater than 1500)
    /// - The source port is 0
    /// - The TTL is 0
    /// - The decoy list is empty
    /// - The real IP position exceeds the decoy list length
    pub fn build(self) -> super::Result<EvasionConfig> {
        if let Some(ref frag) = self.config.fragmentation {
            // Validate fragment size
            match &frag.mode {
                FragmentMode::CustomMTU(mtu) => {
                    if *mtu < 8 || *mtu > 1500 {
                        return Err(super::Error::InvalidFragmentSize {
                            size: *mtu as usize,
                        });
                    }
                }
                FragmentMode::Random { min, max } => {
                    if *min < 8 || *max > 1500 || min > max {
                        return Err(super::Error::InvalidFragmentSize { size: *min });
                    }
                }
                FragmentMode::Default => {}
            }
        }

        // Validate source port
        if let Some(port) = self.config.source.source_port {
            if port == 0 {
                return Err(super::Error::InvalidPort { port });
            }
        }

        // Validate TTL
        if let Some(ttl) = self.config.packet_modification.ttl {
            if ttl == 0 {
                return Err(super::Error::InvalidTtl { ttl });
            }
        }

        // Validate decoy configuration
        if let Some(ref decoys) = self.config.decoys {
            if decoys.decoys.is_empty() {
                return Err(super::Error::InvalidDecoyConfig(
                    "decoy list cannot be empty".into(),
                ));
            }
            if decoys.real_ip_position > decoys.decoys.len() {
                return Err(super::Error::InvalidDecoyConfig(
                    "real IP position exceeds decoy list length".into(),
                ));
            }
        }

        Ok(self.config)
    }
}

/// IP fragmentation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentConfig {
    /// Whether fragmentation is enabled.
    pub enabled: bool,

    /// Fragmentation mode.
    pub mode: FragmentMode,

    /// Whether to allow overlapping fragments.
    pub overlap: bool,

    /// Reassembly timeout.
    pub timeout: Duration,
}

/// Fragmentation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FragmentMode {
    /// Default 8-byte fragments.
    Default,
    /// Custom MTU value.
    CustomMTU(u16),
    /// Random fragment sizes between min and max.
    Random { min: usize, max: usize },
}

/// Decoy scanning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    /// List of decoy IP addresses.
    pub decoys: Vec<IpAddr>,

    /// Position of real IP in decoy sequence (0-based).
    /// If equal to `decoys.len()`, real IP is sent after all decoys.
    pub real_ip_position: usize,

    /// Whether to randomize the order of decoy packets.
    pub random_order: bool,
}

/// Source address configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceConfig {
    /// Spoofed source IP address.
    pub source_ip: Option<IpAddr>,

    /// Spoofed source port.
    pub source_port: Option<u16>,

    /// Spoofed source MAC address.
    #[serde(skip)]
    pub source_mac: Option<[u8; 6]>,

    /// Network interface to use.
    pub interface: Option<String>,
}

/// Packet modification configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketModConfig {
    /// Send packets with bad checksums (for testing).
    pub bad_checksum: bool,

    /// Add random data padding of specified length.
    pub data_length: Option<usize>,

    /// Custom IP options to include.
    #[serde(skip)]
    pub ip_options: Option<Vec<IpOption>>,

    /// TTL value for IP packets.
    pub ttl: Option<u8>,

    /// Type of Service (TOS) value.
    pub tos: Option<u8>,

    /// Set no TCP flags (for certain firewalls).
    pub no_flags: bool,
}

/// IP option type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpOption {
    /// Record Route - records the route the packet takes.
    RecordRoute { max_addresses: u8 },

    /// Timestamp - records timing information.
    Timestamp { flags: u8, max_entries: u8 },

    /// Loose Source Routing - packet must visit specified addresses.
    LooseSourceRoute { addresses: Vec<IpAddr> },

    /// Strict Source Routing - packet must only visit specified addresses.
    StrictSourceRoute { addresses: Vec<IpAddr> },

    /// Custom IP option with type code and data.
    Custom { type_code: u8, data: Vec<u8> },
}

/// Timing configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Timing template to use.
    pub template: TimingTemplate,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            template: TimingTemplate::Normal,
        }
    }
}

/// Timing templates corresponding to Nmap's -T0 through -T5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingTemplate {
    /// T0 - Paranoid: Very slow, maximum evasion.
    Paranoid,

    /// T1 - Sneaky: Slow, stealthy scanning.
    Sneaky,

    /// T2 - Polite: Low bandwidth usage.
    Polite,

    /// T3 - Normal: Default timing.
    Normal,

    /// T4 - Aggressive: Fast scanning.
    Aggressive,

    /// T5 - Insane: Maximum speed, may be inaccurate.
    Insane,
}

impl TimingTemplate {
    /// Returns the timing values for this template.
    #[must_use]
    pub const fn config(&self) -> TimingValues {
        match self {
            TimingTemplate::Paranoid => TimingValues {
                min_rtt_timeout_ms: 100,
                max_rtt_timeout_ms: 10000,
                initial_rtt_timeout_ms: 5000,
                max_retries: 10,
                scan_delay_ms: 300,
                max_parallel: 1,
            },
            TimingTemplate::Sneaky => TimingValues {
                min_rtt_timeout_ms: 100,
                max_rtt_timeout_ms: 10000,
                initial_rtt_timeout_ms: 5000,
                max_retries: 5,
                scan_delay_ms: 100,
                max_parallel: 2,
            },
            TimingTemplate::Polite => TimingValues {
                min_rtt_timeout_ms: 100,
                max_rtt_timeout_ms: 10000,
                initial_rtt_timeout_ms: 1000,
                max_retries: 3,
                scan_delay_ms: 10,
                max_parallel: 10,
            },
            TimingTemplate::Normal => TimingValues {
                min_rtt_timeout_ms: 100,
                max_rtt_timeout_ms: 10000,
                initial_rtt_timeout_ms: 1000,
                max_retries: 2,
                scan_delay_ms: 0,
                max_parallel: 100,
            },
            TimingTemplate::Aggressive => TimingValues {
                min_rtt_timeout_ms: 50,
                max_rtt_timeout_ms: 3000,
                initial_rtt_timeout_ms: 500,
                max_retries: 1,
                scan_delay_ms: 0,
                max_parallel: 500,
            },
            TimingTemplate::Insane => TimingValues {
                min_rtt_timeout_ms: 50,
                max_rtt_timeout_ms: 1000,
                initial_rtt_timeout_ms: 250,
                max_retries: 0,
                scan_delay_ms: 0,
                max_parallel: 1000,
            },
        }
    }
}

/// Timing values derived from a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingValues {
    /// Minimum RTT timeout in milliseconds.
    pub min_rtt_timeout_ms: u64,

    /// Maximum RTT timeout in milliseconds.
    pub max_rtt_timeout_ms: u64,

    /// Initial RTT timeout in milliseconds.
    pub initial_rtt_timeout_ms: u64,

    /// Maximum number of retries.
    pub max_retries: u8,

    /// Delay between scans in milliseconds.
    pub scan_delay_ms: u64,

    /// Maximum parallel probes.
    pub max_parallel: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evasion_config_default() {
        let config = EvasionConfig::default();
        assert!(config.fragmentation.is_none());
        assert!(config.decoys.is_none());
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_evasion_config_builder() {
        let config = EvasionConfig::builder()
            .fragmentation(8)
            .source_port(53)
            .ttl(64)
            .build()
            .unwrap();

        assert!(config.fragmentation.is_some());
        assert_eq!(config.source.source_port, Some(53));
        assert_eq!(config.packet_modification.ttl, Some(64));
    }

    #[test]
    fn test_evasion_config_builder_invalid_fragment_size() {
        let result = EvasionConfig::builder().fragmentation_mtu(0).build();

        assert!(result.is_err());
        if let Err(err) = result {
            let is_fragment_error = matches!(err, super::super::Error::InvalidFragmentSize { .. });
            assert!(
                is_fragment_error,
                "expected InvalidFragmentSize error, got: {err}"
            );
        }
    }

    #[test]
    fn test_evasion_config_builder_invalid_port() {
        let result = EvasionConfig::builder().source_port(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_evasion_config_builder_invalid_ttl() {
        let result = EvasionConfig::builder().ttl(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_decoy_config_validation() {
        let result = EvasionConfig::builder()
            .decoys_with_position(vec![], 0)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_fragment_mode() {
        let mode = FragmentMode::Default;
        assert_eq!(mode, FragmentMode::Default);

        let mode = FragmentMode::CustomMTU(1500);
        assert_eq!(mode, FragmentMode::CustomMTU(1500));

        let mode = FragmentMode::Random { min: 8, max: 100 };
        assert_eq!(mode, FragmentMode::Random { min: 8, max: 100 });
    }

    #[test]
    fn test_timing_template_config() {
        let paranoid = TimingTemplate::Paranoid.config();
        assert_eq!(paranoid.max_parallel, 1);
        assert_eq!(paranoid.scan_delay_ms, 300);

        let normal = TimingTemplate::Normal.config();
        assert_eq!(normal.max_parallel, 100);
        assert_eq!(normal.scan_delay_ms, 0);

        let insane = TimingTemplate::Insane.config();
        assert_eq!(insane.max_parallel, 1000);
        assert_eq!(insane.max_retries, 0);
    }

    #[test]
    fn test_source_config_default() {
        let config = SourceConfig::default();
        assert!(config.source_ip.is_none());
        assert!(config.source_port.is_none());
    }

    #[test]
    fn test_packet_mod_config_default() {
        let config = PacketModConfig::default();
        assert!(!config.bad_checksum);
        assert!(config.data_length.is_none());
        assert!(config.ttl.is_none());
    }

    #[test]
    fn test_ip_option_variants() {
        let record = IpOption::RecordRoute { max_addresses: 9 };
        assert!(matches!(record, IpOption::RecordRoute { .. }));

        let timestamp = IpOption::Timestamp {
            flags: 1,
            max_entries: 4,
        };
        assert!(matches!(timestamp, IpOption::Timestamp { .. }));

        let custom = IpOption::Custom {
            type_code: 42,
            data: vec![1, 2, 3],
        };
        assert!(matches!(custom, IpOption::Custom { .. }));
    }

    #[test]
    fn test_evasion_config_is_enabled() {
        let mut config = EvasionConfig::default();
        assert!(!config.is_enabled());

        config.source.source_port = Some(80);
        assert!(config.is_enabled());

        config.source.source_port = None;
        config.packet_modification.bad_checksum = true;
        assert!(config.is_enabled());
    }

    #[test]
    fn test_timing_values_property() {
        let templates = [
            TimingTemplate::Paranoid,
            TimingTemplate::Sneaky,
            TimingTemplate::Polite,
            TimingTemplate::Normal,
            TimingTemplate::Aggressive,
            TimingTemplate::Insane,
        ];

        for template in templates {
            let values = template.config();
            // Parallel should be a reasonable power of 2 or related value
            assert!(values.max_parallel <= 1000);
            // Max retries should be bounded
            assert!(values.max_retries <= 10);
            // Delay should be reasonable
            assert!(values.scan_delay_ms <= 300);
        }
    }
}
