// Rust guideline compliant 2026-02-12

//! Decoy scanning implementation.
//!
//! This module provides functionality for decoy scanning, where packets
//! are sent from multiple source IP addresses to hide the true scanner.

use std::net::IpAddr;

use crate::config::DecoyConfig;

/// Scheduler for managing decoy scanning.
#[derive(Debug, Clone)]
pub struct DecoyScheduler {
    config: DecoyConfig,
    current_index: usize,
    real_ip: IpAddr,
    shuffle_order: Vec<usize>,
}

impl DecoyScheduler {
    /// Creates a new decoy scheduler.
    ///
    /// # Arguments
    ///
    /// * `config` - The decoy configuration.
    /// * `real_ip` - The actual source IP address of the scanner.
    ///
    /// # Returns
    ///
    /// A scheduler ready to generate decoy packet sources.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal conditions. The `unwrap()` call
    /// is safe because `decoy_iter` is guaranteed to have enough elements:
    /// - We iterate through `0..=decoys.len()` positions (`decoys.len()` + 1 positions)
    /// - One position is reserved for `real_ip_position`
    /// - The remaining `decoys.len()` positions are filled from `decoy_iter`
    /// - Therefore, `decoy_iter` will always have a value when `unwrap()` is called
    ///
    /// # Errors
    ///
    /// Returns an error if the decoy list is empty or if the real IP position
    /// exceeds the decoy list length.
    pub fn new(config: DecoyConfig, real_ip: IpAddr) -> std::result::Result<Self, crate::Error> {
        if config.decoys.is_empty() {
            return Err(crate::Error::InvalidDecoyConfig(
                "decoy list cannot be empty".into(),
            ));
        }

        if config.real_ip_position > config.decoys.len() {
            return Err(crate::Error::InvalidDecoyConfig(
                "real IP position exceeds decoy list length".into(),
            ));
        }

        // Build the shuffle order with real_ip_position respected.
        // The sequence should have the real IP at config.real_ip_position,
        // with decoys filling the remaining positions in order.
        let mut shuffle_order = Vec::with_capacity(config.decoys.len() + 1);
        let mut decoy_iter = config.decoys.iter().enumerate().map(|(i, _)| i);

        for pos in 0..=config.decoys.len() {
            if pos == config.real_ip_position {
                // Position for real IP - mark with max value
                shuffle_order.push(config.decoys.len());
            } else {
                // Position for a decoy
                shuffle_order.push(decoy_iter.next().unwrap());
            }
        }

        Ok(Self {
            config,
            current_index: 0,
            real_ip,
            shuffle_order,
        })
    }

    /// Returns the total number of sources (decoys + real IP).
    #[must_use]
    pub fn total_sources(&self) -> usize {
        self.config.decoys.len() + 1
    }

    /// Returns the next source IP to use for a packet.
    ///
    /// # Returns
    ///
    /// `Some(source_ip)` if more packets need to be sent, `None` when all
    /// sources have been used.
    ///
    /// # Example
    ///
    /// ```
    /// use rustnmap_evasion::decoy::DecoyScheduler;
    /// use rustnmap_evasion::config::DecoyConfig;
    /// use std::net::IpAddr;
    ///
    /// let config = DecoyConfig {
    ///     decoys: vec![
    ///         "192.0.2.1".parse().unwrap(),
    ///         "192.0.2.2".parse().unwrap(),
    ///     ],
    ///     real_ip_position: 1,
    ///     random_order: false,
    /// };
    /// let real_ip = "192.0.2.100".parse().unwrap();
    ///
    /// let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();
    ///
    /// // First packet uses first decoy
    /// assert_eq!(scheduler.next_source(), Some("192.0.2.1".parse().unwrap()));
    ///
    /// // Second packet uses real IP
    /// assert_eq!(scheduler.next_source(), Some("192.0.2.100".parse().unwrap()));
    /// ```
    #[must_use]
    pub fn next_source(&mut self) -> Option<IpAddr> {
        if self.current_index >= self.shuffle_order.len() {
            return None;
        }

        let position = self.shuffle_order[self.current_index];
        self.current_index += 1;

        Some(self.source_at_position(position))
    }

    /// Resets the scheduler to start from the first source again.
    pub fn reset(&mut self) {
        self.current_index = 0;
    }

    /// Returns the source IP at a given position.
    ///
    /// Position 0 through (decoys.len()-1) returns decoys.
    /// Position `decoys.len()` returns the real IP.
    fn source_at_position(&self, position: usize) -> IpAddr {
        if position < self.config.decoys.len() {
            self.config.decoys[position]
        } else {
            self.real_ip
        }
    }

    /// Returns true if the given IP is the real scanner IP.
    #[must_use]
    pub fn is_real_ip(&self, ip: &IpAddr) -> bool {
        *ip == self.real_ip
    }

    /// Returns the position of the real IP in the sequence.
    #[must_use]
    pub fn real_ip_position(&self) -> usize {
        self.config.real_ip_position
    }

    /// Returns a reference to the decoy configuration.
    #[must_use]
    pub fn config(&self) -> &DecoyConfig {
        &self.config
    }

    /// Returns the current index in the sequence.
    #[must_use]
    pub fn current_index(&self) -> usize {
        self.current_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prop_assert_eq;

    #[test]
    fn test_decoy_scheduler_new() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap()],
            real_ip_position: 0,
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let scheduler = DecoyScheduler::new(config, real_ip);
        assert!(scheduler.is_ok());
    }

    #[test]
    fn test_decoy_scheduler_empty_decoys() {
        let config = DecoyConfig {
            decoys: vec![],
            real_ip_position: 0,
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let result = DecoyScheduler::new(config, real_ip);
        assert!(result.is_err());
    }

    #[test]
    fn test_decoy_scheduler_invalid_position() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap()],
            real_ip_position: 5, // Invalid: exceeds decoys.len()
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let result = DecoyScheduler::new(config, real_ip);
        assert!(result.is_err());
    }

    #[test]
    fn test_decoy_scheduler_next_source() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            real_ip_position: 1, // Real IP at position 1
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

        // First: decoy[0]
        assert_eq!(scheduler.next_source(), Some("192.0.2.1".parse().unwrap()));

        // Second: real IP (position 1)
        assert_eq!(
            scheduler.next_source(),
            Some("192.0.2.100".parse().unwrap())
        );

        // Third: decoy[1]
        assert_eq!(scheduler.next_source(), Some("192.0.2.2".parse().unwrap()));

        // No more sources
        assert_eq!(scheduler.next_source(), None);
    }

    #[test]
    fn test_decoy_scheduler_total_sources() {
        let config = DecoyConfig {
            decoys: vec![
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "192.0.2.3".parse().unwrap(),
            ],
            real_ip_position: 0,
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let scheduler = DecoyScheduler::new(config, real_ip).unwrap();
        assert_eq!(scheduler.total_sources(), 4); // 3 decoys + 1 real
    }

    #[test]
    fn test_decoy_scheduler_reset() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap()],
            real_ip_position: 0,
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

        // Exhaust sources
        assert_eq!(scheduler.current_index(), 0);
        let _ = scheduler.next_source();
        assert_eq!(scheduler.current_index(), 1);
        let _ = scheduler.next_source();
        assert_eq!(scheduler.current_index(), 2);

        // Reset
        scheduler.reset();
        assert_eq!(scheduler.current_index(), 0);
        assert!(scheduler.next_source().is_some());
    }

    #[test]
    fn test_decoy_scheduler_is_real_ip() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap()],
            real_ip_position: 0,
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let scheduler = DecoyScheduler::new(config, real_ip).unwrap();

        assert!(scheduler.is_real_ip(&real_ip));
        assert!(!scheduler.is_real_ip(&"192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_decoy_scheduler_real_ip_position() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap()],
            real_ip_position: 1,
            random_order: false,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let scheduler = DecoyScheduler::new(config, real_ip).unwrap();
        assert_eq!(scheduler.real_ip_position(), 1);
    }

    #[test]
    fn test_decoy_scheduler_config() {
        let config = DecoyConfig {
            decoys: vec!["192.0.2.1".parse().unwrap()],
            real_ip_position: 0,
            random_order: true,
        };
        let real_ip = "192.0.2.100".parse().unwrap();

        let scheduler = DecoyScheduler::new(config, real_ip).unwrap();
        assert_eq!(scheduler.config().random_order, true);
    }

    proptest::proptest! {
        #[test]
        fn test_decoy_scheduler_multiple_rounds(decoy_count in 1usize..=10) {
            let decoys: Vec<IpAddr> = (0..decoy_count)
                .map(|i| format!("192.0.2.{}", i + 1).parse().unwrap())
                .collect();

            let config = DecoyConfig {
                decoys: decoys.clone(),
                real_ip_position: 0,
                random_order: false,
            };
            let real_ip = "192.0.2.100".parse().unwrap();

            let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

            // Should get exactly decoys.len() + 1 sources
            let mut count = 0;
            while scheduler.next_source().is_some() {
                count += 1;
            }

            prop_assert_eq!(count, decoy_count + 1);
        }
    }
}
