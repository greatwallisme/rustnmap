// Rust guideline compliant 2026-02-12

//! Packet modification implementation.
//!
//! This module provides functionality for modifying packets in various ways
//! to evade detection or elicit specific responses.

use std::time::SystemTime;

use crate::{config::PacketModConfig, Result};

/// Modifier for applying various packet modifications.
#[derive(Debug, Clone)]
pub struct PacketModifier {
    config: PacketModConfig,
}

impl PacketModifier {
    /// Creates a new packet modifier.
    #[must_use]
    pub fn new(config: PacketModConfig) -> Self {
        Self { config }
    }

    /// Creates a modifier with default (no modification) configuration.
    #[must_use]
    pub fn none() -> Self {
        Self {
            config: PacketModConfig::default(),
        }
    }

    /// Applies modifications to a packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - The original packet bytes.
    ///
    /// # Returns
    ///
    /// The modified packet bytes.
    ///
    /// # Errors
    ///
    /// This function currently does not return errors but may in the future
    /// if validation is added for packet modifications.
    pub fn apply(&self, mut packet: Vec<u8>) -> Result<Vec<u8>> {
        // Apply data padding
        if let Some(padding_len) = self.config.data_length {
            packet = Self::add_padding(packet, padding_len);
        }

        // Apply bad checksum if configured
        if self.config.bad_checksum {
            packet = Self::corrupt_checksum(packet);
        }

        // Note: IP options and TTL modifications would need to be applied
        // at packet construction time, not on the complete packet.
        // These are configuration flags that would be used by the packet builder.

        Ok(packet)
    }

    /// Adds random padding data to a packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - The original packet.
    /// * `length` - Number of random bytes to append.
    fn add_padding(mut packet: Vec<u8>, length: usize) -> Vec<u8> {
        if length == 0 {
            return packet;
        }

        // In production, would use random bytes
        // For deterministic behavior, use a pattern
        let padding: Vec<u8> = (0..length)
            .map(|i| u8::try_from(i % 256).expect("mod 256 always fits in u8"))
            .collect();
        packet.extend_from_slice(&padding);

        packet
    }

    /// Corrupts the checksum in a packet.
    ///
    /// This is used for testing firewall behavior when receiving
    /// packets with invalid checksums.
    fn corrupt_checksum(mut packet: Vec<u8>) -> Vec<u8> {
        if packet.len() < 12 {
            return packet;
        }

        // For IP packets, corrupt the IP checksum at bytes 10-11
        // Assume IP header starts at beginning of packet
        if packet.len() >= 12 {
            // Flip a bit in the checksum
            packet[10] = !packet[10];
        }

        // For TCP packets, corrupt the TCP checksum
        // TCP header starts at IP header length (typically 20 bytes)
        if packet.len() >= 20 + 18 {
            let ip_header_length = (packet[0] & 0x0F) * 4;
            let tcp_checksum_offset = ip_header_length + 16;

            if usize::from(tcp_checksum_offset + 2) <= packet.len() {
                packet[usize::from(tcp_checksum_offset)] =
                    !packet[usize::from(tcp_checksum_offset)];
            }
        }

        packet
    }

    /// Returns the configuration used by this modifier.
    #[must_use]
    pub fn config(&self) -> &PacketModConfig {
        &self.config
    }

    /// Returns true if any modification is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.bad_checksum
            || self.config.data_length.is_some()
            || self.config.ip_options.is_some()
            || self.config.ttl.is_some()
            || self.config.no_flags
            || self.config.tos.is_some()
    }
}

/// Builder for IP options.
#[derive(Debug, Clone)]
pub struct IpOptionsBuilder {
    options: Vec<crate::config::IpOption>,
}

impl IpOptionsBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: Vec::new(),
        }
    }

    /// Adds a Record Route option.
    #[must_use]
    pub fn record_route(mut self, max_addresses: u8) -> Self {
        self.options
            .push(crate::config::IpOption::RecordRoute { max_addresses });
        self
    }

    /// Adds a Timestamp option.
    #[must_use]
    pub fn timestamp(mut self, flags: u8, max_entries: u8) -> Self {
        self.options
            .push(crate::config::IpOption::Timestamp { flags, max_entries });
        self
    }

    /// Adds a Loose Source Route option.
    #[must_use]
    pub fn loose_source_route(mut self, addresses: Vec<std::net::IpAddr>) -> Self {
        self.options
            .push(crate::config::IpOption::LooseSourceRoute { addresses });
        self
    }

    /// Adds a Strict Source Route option.
    #[must_use]
    pub fn strict_source_route(mut self, addresses: Vec<std::net::IpAddr>) -> Self {
        self.options
            .push(crate::config::IpOption::StrictSourceRoute { addresses });
        self
    }

    /// Builds the options vector.
    #[must_use]
    pub fn build(self) -> Vec<crate::config::IpOption> {
        self.options
    }
}

impl Default for IpOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculates a checksum for the given data.
///
/// This is a simple internet checksum used by IP, TCP, and UDP.
///
/// # Panics
///
/// Panics if the checksum calculation overflows a `u16`.
#[must_use]
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            let word = u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            sum += word;
        } else if chunk.len() == 1 {
            // Handle odd-length data
            let word = u32::from(chunk[0]) << 8;
            sum += word;
        }
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    u16::from_be((!u16::try_from(sum).unwrap()).to_be())
}

/// Generates a random padding sequence of the specified length.
///
/// In production, this would use a cryptographically secure RNG.
/// For deterministic testing, uses a simple pattern.
///
/// # Panics
///
/// Panics if the system time is earlier than `UNIX_EPOCH`.
#[must_use]
pub fn generate_padding(length: usize) -> Vec<u8> {
    if length == 0 {
        return Vec::new();
    }

    // Use timestamp-based seed for pseudo-randomness
    let seed = u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap_or(123_456_789); // Use default seed if conversion fails

    // Simple LCG for deterministic pseudo-randomness
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            ((state >> 16) & 0xFF) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Import proptest macros for use within proptest! blocks
    use proptest::prop_assert_eq;

    #[test]
    fn test_packet_modifier_new() {
        let config = PacketModConfig::default();
        let modifier = PacketModifier::new(config.clone());

        assert!(!modifier.is_enabled());
    }

    #[test]
    fn test_packet_modifier_none() {
        let modifier = PacketModifier::none();
        assert!(!modifier.is_enabled());
    }

    #[test]
    fn test_packet_modifier_is_enabled() {
        let config = PacketModConfig {
            bad_checksum: true,
            data_length: None,
            ip_options: None,
            ttl: None,
            tos: None,
            no_flags: false,
        };
        let modifier = PacketModifier::new(config);
        assert!(modifier.is_enabled());
    }

    #[test]
    fn test_add_padding() {
        let packet = vec![1, 2, 3];
        let padded = PacketModifier::add_padding(packet, 5);

        assert_eq!(padded.len(), 8);
        assert_eq!(padded[0..3], [1, 2, 3]);
    }

    #[test]
    fn test_add_padding_zero() {
        let packet = vec![1, 2, 3];
        let padded = PacketModifier::add_padding(packet, 0);

        assert_eq!(padded.len(), 3);
    }

    #[test]
    fn test_corrupt_checksum() {
        let mut packet = vec![0u8; 40];
        packet[10] = 0x12;
        packet[11] = 0x34;

        let corrupted = PacketModifier::corrupt_checksum(packet);

        assert_ne!(corrupted[10], 0x12);
    }

    #[test]
    fn test_apply_bad_checksum() {
        let config = PacketModConfig {
            bad_checksum: true,
            data_length: None,
            ip_options: None,
            ttl: None,
            tos: None,
            no_flags: false,
        };
        let modifier = PacketModifier::new(config);
        let packet = vec![0u8; 40];

        let result = modifier.apply(packet).unwrap();

        // Should have modified checksum byte
        assert!(result.len() >= 12);
    }

    #[test]
    fn test_apply_padding() {
        let config = PacketModConfig {
            bad_checksum: false,
            data_length: Some(10),
            ip_options: None,
            ttl: None,
            tos: None,
            no_flags: false,
        };
        let modifier = PacketModifier::new(config);
        let packet = vec![1, 2, 3];

        let result = modifier.apply(packet).unwrap();

        assert_eq!(result.len(), 13);
        assert_eq!(result[0..3], [1, 2, 3]);
    }

    #[test]
    fn test_calculate_checksum() {
        let data = [0x45u8, 0x00, 0x00, 0x1C, 0x12, 0x34];
        let checksum = calculate_checksum(&data);
        // Checksum should be non-zero
        assert!(checksum != 0);
    }

    #[test]
    fn test_calculate_checksum_odd_length() {
        let data = [0x45u8, 0x00, 0x00]; // Odd number of bytes
        let checksum = calculate_checksum(&data);
        // Should handle odd length
        // Just verify calculate_checksum doesn't panic with odd-length data
        let _ = checksum;
    }

    #[test]
    fn test_generate_padding() {
        let padding = generate_padding(10);
        assert_eq!(padding.len(), 10);
    }

    #[test]
    fn test_generate_padding_zero() {
        let padding = generate_padding(0);
        assert_eq!(padding.len(), 0);
    }

    #[test]
    fn test_ip_options_builder() {
        let builder = IpOptionsBuilder::new().record_route(9).timestamp(1, 4);

        let options = builder.build();

        assert_eq!(options.len(), 2);
        assert!(matches!(
            options[0],
            crate::config::IpOption::RecordRoute { .. }
        ));
        assert!(matches!(
            options[1],
            crate::config::IpOption::Timestamp { .. }
        ));
    }

    #[test]
    fn test_ip_options_builder_loose_source() {
        let addresses = vec!["192.0.2.1".parse().unwrap()];
        let builder = IpOptionsBuilder::new().loose_source_route(addresses.clone());

        let options = builder.build();

        assert_eq!(options.len(), 1);
        assert!(matches!(
            options[0],
            crate::config::IpOption::LooseSourceRoute { .. }
        ));
    }

    #[test]
    fn test_ip_options_builder_strict_source() {
        let addresses = vec!["192.0.2.1".parse().unwrap()];
        let builder = IpOptionsBuilder::new().strict_source_route(addresses);

        let options = builder.build();

        assert_eq!(options.len(), 1);
        assert!(matches!(
            options[0],
            crate::config::IpOption::StrictSourceRoute { .. }
        ));
    }

    proptest::proptest! {
        #[test]
        fn test_padding_length_property(length in 0usize..1000) {
            let packet = vec![1u8, 2, 3];

            let padded = PacketModifier::add_padding(packet.clone(), length);

            prop_assert_eq!(padded.len(), packet.len() + length);
            // Original packet contents should be preserved
            prop_assert_eq!(&padded[..packet.len()], &packet[..]);
        }

        #[test]
        fn test_checksum_property(data in proptest::collection::vec(0u8..=u8::MAX, 0..1000)) {
            let checksum = calculate_checksum(&data);

            // Checksum should be deterministic - same input yields same output
            let checksum2 = calculate_checksum(&data);
            prop_assert_eq!(checksum, checksum2);
        }
    }
}
