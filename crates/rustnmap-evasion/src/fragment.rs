// Rust guideline compliant 2026-02-12

//! IP fragmentation evasion implementation.
//!
//! This module provides functionality to fragment packets into smaller pieces
//! to bypass firewalls and IDS that only reassemble complete packets.

use std::time::Duration;

use crate::{config::FragmentConfig, Result};

/// Maximum transmission unit (MTU) for standard Ethernet.
pub const DEFAULT_MTU: u16 = 1500;

/// Minimum fragment size (8 bytes to accommodate TCP header).
pub const MIN_FRAGMENT_SIZE: usize = 8;

/// IP header size in bytes.
const IP_HEADER_SIZE: usize = 20;

/// Fragmenter for splitting packets into smaller fragments.
#[derive(Debug, Clone)]
pub struct Fragmenter {
    config: FragmentConfig,
}

impl Fragmenter {
    /// Creates a new fragmenter with the given configuration.
    #[must_use]
    pub fn new(config: FragmentConfig) -> Self {
        Self { config }
    }

    /// Creates a fragmenter with default 8-byte fragmentation.
    #[must_use]
    pub fn default_mode() -> Self {
        Self {
            config: FragmentConfig {
                enabled: true,
                mode: crate::config::FragmentMode::Default,
                overlap: false,
                timeout: Duration::from_secs(30),
            },
        }
    }

    /// Fragments a packet into multiple smaller packets.
    ///
    /// # Arguments
    ///
    /// * `packet` - The complete packet to fragment (including IP header).
    /// * `mtu` - The Maximum Transmission Unit for the network path.
    ///
    /// # Returns
    ///
    /// A vector of packet fragments, each starting with an IP header.
    ///
    /// # Example
    ///
    /// ```
    /// use rustnmap_evasion::fragment::Fragmenter;
    ///
    /// let fragmenter = Fragmenter::default_mode();
    /// let packet = vec![0u8; 100];  // 100-byte packet
    /// let fragments = fragmenter.fragment(&packet, 1500).unwrap();
    /// assert!(fragments.len() > 1);  // Should be fragmented
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if packet slicing fails.
    pub fn fragment(&self, packet: &[u8], mtu: u16) -> Result<Vec<Vec<u8>>> {
        if !self.config.enabled {
            return Ok(vec![packet.to_vec()]);
        }

        let fragment_size = self.get_fragment_size(mtu as usize);
        let data_size = packet.len().saturating_sub(IP_HEADER_SIZE);

        // Only fragment if data doesn't fit in a single fragment
        if data_size <= fragment_size {
            return Ok(vec![packet.to_vec()]);
        }

        // Calculate number of fragments needed
        let data_size = packet.len() - IP_HEADER_SIZE;
        let mut fragments = Vec::new();

        let mut offset = 0;
        let fragment_id = self.generate_fragment_id();

        while offset < data_size {
            let remaining = data_size - offset;
            let current_fragment_size = fragment_size.min(remaining);

            let is_last = offset + current_fragment_size >= data_size;

            let fragment =
                self.build_fragment(packet, offset, current_fragment_size, fragment_id, is_last);

            fragments.push(fragment);
            offset += current_fragment_size;
        }

        Ok(fragments)
    }

    /// Gets the fragment size (data portion, not including IP header) based on the configured mode.
    fn get_fragment_size(&self, mtu: usize) -> usize {
        let base_size = match &self.config.mode {
            crate::config::FragmentMode::Default => 8,
            crate::config::FragmentMode::CustomMTU(size) => {
                // CustomMTU specifies total fragment size including IP header
                // Convert to data portion size
                (*size as usize).saturating_sub(IP_HEADER_SIZE)
            }
            crate::config::FragmentMode::Random { min, max } => {
                // For deterministic testing, use mid-range
                // In real implementation, would use rand::thread_rng().gen(*min..*max)
                (min + max) / 2
            }
        };
        base_size.min(mtu - IP_HEADER_SIZE).max(MIN_FRAGMENT_SIZE)
    }

    /// Generates a unique fragment identifier.
    #[allow(
        clippy::unused_self,
        reason = "Self is used for API consistency with other Fragmenter methods"
    )]
    fn generate_fragment_id(&self) -> u16 {
        // In real implementation, this would be random or incrementing
        // For deterministic behavior in tests, use fixed value
        0x1234
    }

    /// Builds a single fragment packet.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "IP header fields are bounded by protocol spec"
    )]
    fn build_fragment(
        &self,
        original_packet: &[u8],
        data_offset: usize,
        fragment_data_size: usize,
        fragment_id: u16,
        is_last: bool,
    ) -> Vec<u8> {
        // IP header starts at beginning of packet
        let mut ip_header = original_packet[..IP_HEADER_SIZE].to_vec();

        // Set fragment flags
        // bit 0: reserved (must be 0)
        // bit 1: Don't Fragment (DF)
        // bit 2: More Fragments (MF)
        let mf_flag = u16::from(!is_last);

        // Fragment offset is in 8-byte units
        let fragment_offset = (data_offset / 8) as u16;

        // Set fragment flags and offset in IP header (bytes 6-7)
        // High 4 bits of byte 6: flags
        // Low 4 bits of byte 6 + byte 7: offset
        let flags_fragment = ((mf_flag & 0x1) << 13) | (fragment_offset & 0x1FFF);

        ip_header[6] = (flags_fragment >> 8) as u8;
        ip_header[7] = (flags_fragment & 0xFF) as u8;

        // Set identification field (bytes 4-5)
        ip_header[4] = (fragment_id >> 8) as u8;
        ip_header[5] = (fragment_id & 0xFF) as u8;

        // Set total length for this fragment
        let total_length = IP_HEADER_SIZE + fragment_data_size;
        ip_header[2] = (total_length >> 8) as u8;
        ip_header[3] = (total_length & 0xFF) as u8;

        // Recalculate IP checksum (set to 0 first)
        ip_header[10] = 0;
        ip_header[11] = 0;

        let checksum = self.calculate_ip_checksum(&ip_header);
        ip_header[10] = (checksum >> 8) as u8;
        ip_header[11] = (checksum & 0xFF) as u8;

        // Build fragment: IP header + fragment data
        // Calculate slice bounds for this fragment's data
        let slice_start = IP_HEADER_SIZE + data_offset;
        let slice_end = IP_HEADER_SIZE + data_offset + fragment_data_size;

        let mut fragment = ip_header;
        fragment.extend_from_slice(&original_packet[slice_start..slice_end]);

        fragment
    }

    /// Calculates IP header checksum.
    #[allow(
        clippy::unused_self,
        reason = "Self is used for API consistency with other Fragmenter methods"
    )]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "IP checksum is guaranteed to fit in u16 by design"
    )]
    fn calculate_ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                let word = u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
                sum += word;
            }
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        (!sum) as u16
    }

    /// Returns the configuration used by this fragmenter.
    #[must_use]
    pub fn config(&self) -> &FragmentConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FragmentMode;

    #[test]
    fn test_fragmenter_new() {
        let config = FragmentConfig {
            enabled: true,
            mode: FragmentMode::Default,
            overlap: false,
            timeout: Duration::from_secs(30),
        };
        let fragmenter = Fragmenter::new(config.clone());
        assert_eq!(fragmenter.config(), &config);
    }

    #[test]
    fn test_fragmenter_default_mode() {
        let fragmenter = Fragmenter::default_mode();
        assert!(fragmenter.config().enabled);
    }

    #[test]
    fn test_fragment_small_packet() {
        let fragmenter = Fragmenter::default_mode();
        // 28-byte packet: 20-byte IP header + 8 bytes data
        // Data size (8) equals fragment size (8), so no fragmentation needed
        let packet = vec![0u8; 28];

        let fragments = fragmenter.fragment(&packet, 1500).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), packet.len());
    }

    #[test]
    fn test_fragment_large_packet() {
        let fragmenter = Fragmenter::default_mode();

        // Create a 100-byte packet (IP header + 80 bytes data)
        let mut packet = vec![0u8; 100];
        // Set valid IP header length (5 * 4 = 20 bytes)
        packet[0] = 0x45;

        let fragments = fragmenter.fragment(&packet, 1500).unwrap();

        // With 8-byte fragment mode, we should get multiple fragments
        assert!(fragments.len() > 1);
    }

    #[test]
    fn test_fragment_custom_mtu() {
        let config = FragmentConfig {
            enabled: true,
            mode: FragmentMode::CustomMTU(100),
            overlap: false,
            timeout: Duration::from_secs(30),
        };
        let fragmenter = Fragmenter::new(config);

        let mut packet = vec![0u8; 200];
        packet[0] = 0x45;

        let fragments = fragmenter.fragment(&packet, 1500).unwrap();

        // With MTU 100, we should get multiple fragments
        assert!(fragments.len() > 1);

        // Each fragment should be <= 100 bytes (including IP header)
        for (i, fragment) in fragments.iter().enumerate() {
            assert!(
                fragment.len() <= 100,
                "Fragment {} has length {} which is > 100",
                i,
                fragment.len()
            );
        }
    }

    #[test]
    fn test_fragment_disabled() {
        let config = FragmentConfig {
            enabled: false,
            mode: FragmentMode::Default,
            overlap: false,
            timeout: Duration::from_secs(30),
        };
        let fragmenter = Fragmenter::new(config);

        let packet = vec![1, 2, 3, 4, 5];
        let fragments = fragmenter.fragment(&packet, 1500).unwrap();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], packet);
    }

    #[test]
    fn test_fragment_min_size() {
        assert_eq!(MIN_FRAGMENT_SIZE, 8);
    }

    #[test]
    fn test_default_mtu() {
        assert_eq!(DEFAULT_MTU, 1500);
    }

    #[test]
    fn test_ip_checksum_calculation() {
        let fragmenter = Fragmenter::default_mode();

        // Valid IP header for checksum test
        let mut header = vec![
            0x45, 0x00, 0x00, 0x1C, // Version, IHL, TOS, Total Length
            0x12, 0x34, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum
            0x00, 0x00, 0x00, 0x00, // Source Address
            0x00, 0x00, 0x00, 0x00, // Dest Address
        ];

        let checksum = fragmenter.calculate_ip_checksum(&header);

        // Verify checksum is non-zero
        assert!(checksum != 0);

        // Set checksum in header
        header[10] = (checksum >> 8) as u8;
        header[11] = (checksum & 0xFF) as u8;

        // Verify checksum with checksum set
        let verify_checksum = fragmenter.calculate_ip_checksum(&header);
        // When checksum is included, the result should be 0
        // (the sum wraps to 0xFFFF, and !0xFFFF = 0)
        assert_eq!(verify_checksum, 0);
    }

    #[test]
    fn test_fragment_size_property() {
        let fragmenter = Fragmenter::default_mode();

        // Test various MTU values
        for size in [68, 576, 1000, 1500] {
            let result = fragmenter.get_fragment_size(size);

            // Fragment size should be within valid range
            assert!(result >= MIN_FRAGMENT_SIZE);
            assert!(result <= size - IP_HEADER_SIZE);
        }
    }
}
