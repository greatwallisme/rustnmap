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

//! Cookie generation and verification for stateless scanning.

use blake3::Hasher;
use getrandom::getrandom;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Cookie generation error.
#[derive(Debug, Error)]
pub enum CookieError {
    /// Failed to generate random bytes.
    #[error("Failed to generate random key: {0}")]
    RandomGeneration(#[from] getrandom::Error),
}

/// Verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Cookie is valid.
    Valid,
    /// Cookie is invalid (possibly forged).
    Invalid,
    /// Cookie has expired (possible replay attack).
    Expired,
}

/// Cookie structure for encoding source port and sequence number.
#[derive(Debug, Clone, Copy)]
pub struct Cookie {
    /// Encoded source port (1024-65535).
    pub source_port: u16,
    /// Encoded sequence number.
    pub sequence_num: u32,
    /// Timestamp when cookie was generated.
    pub timestamp: u64,
}

/// Cookie generator for stateless scanning.
///
/// Uses BLAKE3 hash with a random key to generate verifiable cookies
/// that encode source port and sequence number without maintaining state.
pub struct CookieGenerator {
    /// Encryption key (randomly generated).
    #[allow(
        clippy::missing_fields_in_debug,
        reason = "Key is secret and should not be logged"
    )]
    key: [u8; 32],
}

impl Clone for CookieGenerator {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl std::fmt::Debug for CookieGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieGenerator")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl CookieGenerator {
    /// Create a new cookie generator with a random key.
    ///
    /// # Errors
    ///
    /// Returns an error if random key generation fails.
    pub fn new() -> Result<Self, CookieError> {
        let mut key = [0u8; 32];
        getrandom(&mut key)?;
        Ok(Self { key })
    }

    /// Create with a specific key (for testing).
    #[must_use]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Generate a cookie for a target IP.
    ///
    /// Note: Only the low 16 bits of the timestamp are used in the hash
    /// to enable verification from the sequence number alone.
    #[must_use]
    pub fn generate(&self, target: IpAddr, port: u16, timestamp: u64) -> Cookie {
        // Only use low 16 bits of timestamp for hash (for verification compatibility)
        let timestamp_16bit = timestamp & 0xFFFF;

        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        // Handle both IPv4 and IPv6
        match target {
            IpAddr::V4(ip) => {
                hasher.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                hasher.update(&ip.octets());
            }
        }
        hasher.update(&timestamp_16bit.to_le_bytes());
        hasher.update(&port.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Source port: use high 16 bits (exclude privileged ports)
        let source_port = 1024 + (u16::from_le_bytes([hash_bytes[0], hash_bytes[1]]) % 64511);

        // Sequence number: use hash bytes 4-7 combined with timestamp
        let seq_high = u32::from(u16::from_le_bytes([hash_bytes[2], hash_bytes[3]]));
        let seq_low = timestamp_16bit as u32;
        let sequence_num = (seq_high << 16) | seq_low;

        Cookie {
            source_port,
            sequence_num,
            timestamp,
        }
    }

    /// Verify a received response.
    ///
    /// This performs production-grade verification by regenerating the complete
    /// cookie and verifying both the source port and sequence number match.
    /// This prevents response spoofing by ensuring the response matches
    /// the original destination port AND the expected sequence pattern.
    ///
    /// # Arguments
    ///
    /// * `target` - The target IP address
    /// * `dest_port` - The original destination port that was probed
    /// * `source_port` - The source port from the response
    /// * `ack_num` - The acknowledgment number from the response (seq + 1)
    /// * `max_age` - Maximum age for the cookie to be considered valid
    #[must_use]
    pub fn verify(
        &self,
        target: IpAddr,
        dest_port: u16,
        source_port: u16,
        ack_num: u32,
        max_age: Duration,
    ) -> VerifyResult {
        // Reconstruct sequence number (ack_num = seq + 1)
        let sequence_num = ack_num.saturating_sub(1);

        // Extract timestamp from sequence number (low 16 bits)
        let cookie_timestamp_16bit = u64::from(sequence_num & 0xFFFF);

        // Get current timestamp (also as 16-bit for comparison)
        let current_time_16bit = current_timestamp() & 0xFFFF;

        // Check if cookie has expired (handle wraparound at 16-bit boundary)
        // The age is calculated in the 16-bit timestamp space
        let age = if current_time_16bit >= cookie_timestamp_16bit {
            current_time_16bit - cookie_timestamp_16bit
        } else {
            // Wraparound case: cookie timestamp is near 65535, current is near 0
            (65536 - cookie_timestamp_16bit) + current_time_16bit
        };

        if age > max_age.as_secs() {
            return VerifyResult::Expired;
        }

        // Production-grade verification: regenerate the complete expected cookie
        // using the target, destination port, and timestamp
        let expected_cookie = self.generate(target, dest_port, cookie_timestamp_16bit);

        // Verify both the source port AND sequence number match
        // This prevents response spoofing by ensuring the response is for
        // the exact probe we sent (correct target, port, and timing)
        if expected_cookie.source_port == source_port
            && expected_cookie.sequence_num == sequence_num
        {
            VerifyResult::Valid
        } else {
            VerifyResult::Invalid
        }
    }

    /// Verify a received response without knowing the destination port.
    ///
    /// This is a legacy verification method that is less secure because it
    /// doesn't verify the destination port. Use [`verify`](Self::verify) instead
    /// when the destination port is known.
    ///
    /// # Security Note
    ///
    /// This method is vulnerable to certain replay attacks and should only be
    /// used when the destination port cannot be determined.
    ///
    /// # Deprecation Note
    ///
    /// This method cannot properly verify cookies generated with the port-based
    /// hash. It is retained for backward compatibility only.
    #[must_use]
    #[deprecated(
        since = "2.0.0",
        note = "Cannot properly verify port-based cookies. Use `verify` instead."
    )]
    pub fn verify_without_port(
        &self,
        target: IpAddr,
        source_port: u16,
        ack_num: u32,
        max_age: Duration,
    ) -> VerifyResult {
        // Reconstruct sequence number (ack_num = seq + 1)
        let sequence_num = ack_num.saturating_sub(1);

        // Extract timestamp from sequence number (low 16 bits)
        let cookie_timestamp_16bit = u64::from(sequence_num & 0xFFFF);

        // Get current timestamp (also as 16-bit for comparison)
        let current_time_16bit = current_timestamp() & 0xFFFF;

        // Check if cookie has expired (handle wraparound at 16-bit boundary)
        let age = if current_time_16bit >= cookie_timestamp_16bit {
            current_time_16bit - cookie_timestamp_16bit
        } else {
            // Wraparound case
            (65536 - cookie_timestamp_16bit) + current_time_16bit
        };

        if age > max_age.as_secs() {
            return VerifyResult::Expired;
        }

        // Legacy verification: regenerate with port 0 and check if ports match
        // This is fundamentally insecure but retained for backward compatibility
        let expected_cookie = self.generate(target, 0, cookie_timestamp_16bit);

        if expected_cookie.source_port == source_port {
            VerifyResult::Valid
        } else {
            VerifyResult::Invalid
        }
    }

    /// Generate cookie and return packet parameters.
    ///
    /// Returns (`source_port`, `sequence_number`).
    #[must_use]
    pub fn generate_packet_params(&self, target: IpAddr, dest_port: u16) -> (u16, u32) {
        let timestamp = current_timestamp();
        let cookie = self.generate(target, dest_port, timestamp);
        (cookie.source_port, cookie.sequence_num)
    }
}

impl Default for CookieGenerator {
    fn default() -> Self {
        Self::new().expect("Failed to create CookieGenerator")
    }
}

/// Get current Unix timestamp.
#[must_use]
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cookie_generator_creation() {
        CookieGenerator::new().unwrap();
    }

    #[test]
    fn test_cookie_generation() {
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let cookie = generator.generate(target, 80, 1_234_567_890);

        assert!(cookie.source_port >= 1024);
        assert_eq!(cookie.timestamp, 1_234_567_890);
    }

    #[test]
    fn test_cookie_determinism() {
        let key = [42u8; 32];
        let generator = CookieGenerator::with_key(key);
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let cookie1 = generator.generate(target, 80, 1_234_567_890);
        let cookie2 = generator.generate(target, 80, 1_234_567_890);

        assert_eq!(cookie1.source_port, cookie2.source_port);
        assert_eq!(cookie1.sequence_num, cookie2.sequence_num);
    }

    #[test]
    fn test_cookie_different_targets() {
        let generator = CookieGenerator::default();
        let target1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let target2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let cookie1 = generator.generate(target1, 80, 1_234_567_890);
        let cookie2 = generator.generate(target2, 80, 1_234_567_890);

        assert_ne!(cookie1.source_port, cookie2.source_port);
        assert_ne!(cookie1.sequence_num, cookie2.sequence_num);
    }

    #[test]
    fn test_cookie_different_ports() {
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let cookie1 = generator.generate(target, 80, 1_234_567_890);
        let cookie2 = generator.generate(target, 443, 1_234_567_890);

        assert_ne!(cookie1.source_port, cookie2.source_port);
    }

    #[test]
    fn test_packet_params_generation() {
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let (source_port, seq_num) = generator.generate_packet_params(target, 80);

        assert!(source_port >= 1024);
        assert!(seq_num > 0);
    }

    #[test]
    fn test_verify_valid_cookie() {
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dest_port = 80u16;

        // Use current timestamp (will be truncated to 16 bits in sequence number)
        let timestamp = current_timestamp();

        // Generate cookie
        let cookie = generator.generate(target, dest_port, timestamp);

        // Verify with correct parameters (ack_num = seq + 1)
        // Use large max_age to avoid time-based expiration
        let result = generator.verify(
            target,
            dest_port,
            cookie.source_port,
            cookie.sequence_num + 1,
            Duration::from_secs(100_000),
        );

        assert_eq!(result, VerifyResult::Valid);
    }

    #[test]
    fn test_verify_wrong_dest_port() {
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dest_port = 80u16;

        // Use current timestamp
        let timestamp = current_timestamp();

        // Generate cookie for port 80
        let cookie = generator.generate(target, dest_port, timestamp);

        // Verify with wrong destination port (443 instead of 80)
        let result = generator.verify(
            target,
            443, // Wrong port
            cookie.source_port,
            cookie.sequence_num + 1,
            Duration::from_secs(100_000),
        );

        assert_eq!(result, VerifyResult::Invalid);
    }

    #[test]
    fn test_verify_wrong_target() {
        let generator = CookieGenerator::default();
        let target1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let target2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let dest_port = 80u16;

        // Use current timestamp
        let timestamp = current_timestamp();

        // Generate cookie for target1
        let cookie = generator.generate(target1, dest_port, timestamp);

        // Verify with wrong target
        let result = generator.verify(
            target2, // Wrong target
            dest_port,
            cookie.source_port,
            cookie.sequence_num + 1,
            Duration::from_secs(100_000),
        );

        assert_eq!(result, VerifyResult::Invalid);
    }

    #[test]
    fn test_verify_expired_cookie() {
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dest_port = 80u16;

        // Use a timestamp from 120 seconds ago
        let old_timestamp = current_timestamp() - 120;

        // Generate cookie with old timestamp
        let cookie = generator.generate(target, dest_port, old_timestamp);

        // Verify with 60 second max age
        let result = generator.verify(
            target,
            dest_port,
            cookie.source_port,
            cookie.sequence_num + 1,
            Duration::from_secs(60),
        );

        assert_eq!(result, VerifyResult::Expired);
    }

    #[test]
    fn test_verify_without_port_valid() {
        // Note: verify_without_port is deprecated and only works when the
        // cookie was generated with port 0. For proper verification, use
        // the verify() method with the known destination port.
        let generator = CookieGenerator::default();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Use current timestamp
        let timestamp = current_timestamp();

        // Generate cookie with port 0 (required for verify_without_port)
        #[allow(deprecated, reason = "Testing deprecated verify_without_port method")]
        let cookie = generator.generate(target, 0, timestamp);

        // Verify without port (legacy method)
        #[allow(deprecated, reason = "Testing deprecated verify_without_port method")]
        let result = generator.verify_without_port(
            target,
            cookie.source_port,
            cookie.sequence_num + 1,
            Duration::from_secs(100_000),
        );

        assert_eq!(result, VerifyResult::Valid);
    }
}
