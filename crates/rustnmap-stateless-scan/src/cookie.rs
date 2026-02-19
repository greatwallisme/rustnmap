// rustnmap-stateless-scan
// Copyright (C) 2026  greatwallisme

//! Cookie generation and verification for stateless scanning.

use blake3::Hasher;
use getrandom::getrandom;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
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
    #[allow(clippy::missing_fields_in_debug, reason = "Key is secret and should not be logged")]
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
    #[must_use]
    pub fn generate(&self, target: IpAddr, port: u16, timestamp: u64) -> Cookie {
        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        // Handle both IPv4 and IPv6
        match target {
            IpAddr::V4(ip) => { hasher.update(&ip.octets()); }
            IpAddr::V6(ip) => { hasher.update(&ip.octets()); }
        }
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&port.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Source port: use high 16 bits (exclude privileged ports)
        let source_port = 1024 + (u16::from_le_bytes([hash_bytes[0], hash_bytes[1]]) % 64511);

        // Sequence number: use hash bytes 4-7 combined with timestamp
        let seq_high = u32::from(u16::from_le_bytes([hash_bytes[2], hash_bytes[3]]));
        let seq_low = (timestamp & 0xFFFF) as u32;
        let sequence_num = (seq_high << 16) | seq_low;

        Cookie {
            source_port,
            sequence_num,
            timestamp,
        }
    }

    /// Verify a received response.
    #[must_use]
    pub fn verify(&self, target: IpAddr, source_port: u16, ack_num: u32, max_age: Duration) -> VerifyResult {
        // Reconstruct sequence number (ack_num = seq + 1)
        let sequence_num = ack_num.saturating_sub(1);

        // Extract timestamp from sequence number (low 16 bits)
        let cookie_timestamp = u64::from(sequence_num & 0xFFFF);

        // Get current timestamp
        let current_time = current_timestamp();

        // Check if cookie has expired (handle wraparound)
        let age = if current_time >= cookie_timestamp {
            current_time - cookie_timestamp
        } else {
            // Wraparound case
            (u64::MAX - cookie_timestamp) + current_time
        };

        if age > max_age.as_secs() {
            return VerifyResult::Expired;
        }

        // Rebuild cookie and verify
        // We need to find the original port - try to match source_port
        // Verify by recomputing the expected port from the target and timestamp
        //TODO: This is a simplified verification - in production, you'd use a different approach
        let expected_port_hash = self.compute_port_hash(target, cookie_timestamp);
        let actual_port = 1024 + (expected_port_hash % 64511);

        if actual_port == source_port {
            VerifyResult::Valid
        } else {
            VerifyResult::Invalid
        }
    }

    /// Compute port hash for verification.
    fn compute_port_hash(&self, target: IpAddr, timestamp: u64) -> u16 {
        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        // Handle both IPv4 and IPv6
        match target {
            IpAddr::V4(ip) => { hasher.update(&ip.octets()); }
            IpAddr::V6(ip) => { hasher.update(&ip.octets()); }
        }
        hasher.update(&timestamp.to_le_bytes());
        // Port is not included in hash for verification
        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();
        u16::from_le_bytes([hash_bytes[0], hash_bytes[1]])
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
}
