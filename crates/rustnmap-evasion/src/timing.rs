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

// Rust guideline compliant 2026-02-12

//! Timing template configuration.
//!
//! This module provides timing templates that control scan speed and
//! evasion characteristics, corresponding to Nmap's -T0 through -T5.

use crate::{config::TimingTemplate, TimingValues};

/// Default timing template (T3 - Normal).
pub const DEFAULT_TEMPLATE: TimingTemplate = TimingTemplate::Normal;

/// Controller for timing-based scan parameters.
#[derive(Debug, Clone)]
pub struct TimingController {
    template: TimingTemplate,
    values: TimingValues,
}

impl TimingController {
    /// Creates a new timing controller with given template.
    #[must_use]
    pub fn new(template: TimingTemplate) -> Self {
        let values = template.config();
        Self { template, values }
    }

    /// Creates a controller with default (Normal) timing.
    #[must_use]
    pub fn new_default() -> Self {
        Self {
            template: DEFAULT_TEMPLATE,
            values: DEFAULT_TEMPLATE.config(),
        }
    }

    /// Returns the current timing template.
    #[must_use]
    pub fn template(&self) -> TimingTemplate {
        self.template
    }

    /// Returns the timing values for this template.
    #[must_use]
    pub fn values(&self) -> &TimingValues {
        &self.values
    }

    /// Returns the initial RTT timeout in milliseconds.
    #[must_use]
    pub fn initial_rtt_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.values.initial_rtt_timeout_ms)
    }

    /// Returns the minimum RTT timeout in milliseconds.
    #[must_use]
    pub fn min_rtt_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.values.min_rtt_timeout_ms)
    }

    /// Returns the maximum RTT timeout in milliseconds.
    #[must_use]
    pub fn max_rtt_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.values.max_rtt_timeout_ms)
    }

    /// Returns the maximum number of retries.
    #[must_use]
    pub fn max_retries(&self) -> u8 {
        self.values.max_retries
    }

    /// Returns the delay between scans.
    #[must_use]
    pub fn scan_delay(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.values.scan_delay_ms)
    }

    /// Returns the maximum number of parallel probes.
    #[must_use]
    pub fn max_parallel(&self) -> usize {
        self.values.max_parallel
    }

    /// Returns true if this template prioritizes stealth over speed.
    #[must_use]
    pub fn is_stealthy(&self) -> bool {
        matches!(
            self.template,
            TimingTemplate::Paranoid | TimingTemplate::Sneaky | TimingTemplate::Polite
        )
    }

    /// Returns true if this template prioritizes speed over accuracy.
    #[must_use]
    pub fn is_aggressive(&self) -> bool {
        matches!(
            self.template,
            TimingTemplate::Aggressive | TimingTemplate::Insane
        )
    }

    /// Calculates the scan delay based on timing template.
    ///
    /// For stealthy templates, returns a delay. For aggressive templates,
    /// returns zero delay.
    #[must_use]
    pub fn calculate_scan_delay(&self, probe_count: usize) -> std::time::Duration {
        if self.values.scan_delay_ms == 0 {
            return std::time::Duration::ZERO;
        }

        // Scale delay based on number of probes
        let base_delay = self.values.scan_delay_ms;
        let scaled_delay =
            base_delay.saturating_mul(u64::try_from(probe_count).unwrap_or(u64::MAX) / 100);
        std::time::Duration::from_millis(scaled_delay)
    }

    /// Calculates the timeout for a specific probe attempt.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The attempt number (0-based).
    /// * `rtt_estimate` - Estimated RTT in milliseconds.
    ///
    /// # Returns
    ///
    /// The timeout duration for this attempt.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    #[must_use]
    pub fn calculate_probe_timeout(
        &self,
        attempt: u8,
        rtt_estimate: Option<std::time::Duration>,
    ) -> std::time::Duration {
        let base_timeout = self.initial_rtt_timeout();

        // Back off on retries
        let backoff_multiplier = 2u32.saturating_pow(u32::from(attempt));
        let backed_off = base_timeout.saturating_mul(backoff_multiplier);

        // Cap at max timeout
        let max_timeout = self.max_rtt_timeout();

        // If we have an RTT estimate, use it to adjust
        if let Some(rtt) = rtt_estimate {
            let adjusted = rtt.saturating_mul(3);
            std::cmp::min(adjusted, std::cmp::min(backed_off, max_timeout))
        } else {
            std::cmp::min(backed_off, max_timeout)
        }
    }

    /// Returns the template as a string (T0-T5).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self.template {
            TimingTemplate::Paranoid => "T0",
            TimingTemplate::Sneaky => "T1",
            TimingTemplate::Polite => "T2",
            TimingTemplate::Normal => "T3",
            TimingTemplate::Aggressive => "T4",
            TimingTemplate::Insane => "T5",
        }
    }

    /// Parses a timing template string (T0-T5).
    ///
    /// # Arguments
    ///
    /// * `s` - The string to parse.
    ///
    /// # Returns
    ///
    /// `Ok(template)` if valid, `Err` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::InvalidTimingTemplate)` if the string is not a valid template.
    pub fn parse_template(s: &str) -> crate::Result<TimingTemplate> {
        match s.to_uppercase().as_str() {
            "T0" | "PARANOID" => Ok(TimingTemplate::Paranoid),
            "T1" | "SNEAKY" => Ok(TimingTemplate::Sneaky),
            "T2" | "POLITE" => Ok(TimingTemplate::Polite),
            "T3" | "NORMAL" => Ok(TimingTemplate::Normal),
            "T4" | "AGGRESSIVE" => Ok(TimingTemplate::Aggressive),
            "T5" | "INSANE" => Ok(TimingTemplate::Insane),
            _ => Err(crate::Error::InvalidTimingTemplate(s.to_string())),
        }
    }

    /// Sets a new timing template.
    pub fn set_template(&mut self, template: TimingTemplate) {
        self.template = template;
        self.values = template.config();
    }
}

impl Default for TimingController {
    fn default() -> Self {
        Self::new_default()
    }
}

impl From<TimingTemplate> for TimingController {
    fn from(template: TimingTemplate) -> Self {
        Self::new(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_controller_new() {
        let controller = TimingController::new(TimingTemplate::Paranoid);
        assert_eq!(controller.template(), TimingTemplate::Paranoid);
    }

    #[test]
    fn test_timing_controller_default() {
        let controller = TimingController::default();
        assert_eq!(controller.template(), TimingTemplate::Normal);
    }

    #[test]
    fn test_timing_controller_initial_rtt_timeout() {
        let controller = TimingController::new(TimingTemplate::Paranoid);
        assert_eq!(
            controller.initial_rtt_timeout(),
            std::time::Duration::from_millis(5000)
        );
    }

    #[test]
    fn test_timing_controller_min_rtt_timeout() {
        let controller = TimingController::new(TimingTemplate::Insane);
        assert_eq!(
            controller.min_rtt_timeout(),
            std::time::Duration::from_millis(50)
        );
    }

    #[test]
    fn test_timing_controller_max_rtt_timeout() {
        let controller = TimingController::new(TimingTemplate::Sneaky);
        assert_eq!(
            controller.max_rtt_timeout(),
            std::time::Duration::from_millis(10000)
        );
    }

    #[test]
    fn test_timing_controller_max_retries() {
        let controller = TimingController::new(TimingTemplate::Paranoid);
        assert_eq!(controller.max_retries(), 10);
    }

    #[test]
    fn test_timing_controller_scan_delay() {
        let controller = TimingController::new(TimingTemplate::Sneaky);
        assert_eq!(
            controller.scan_delay(),
            std::time::Duration::from_millis(100)
        );
    }

    #[test]
    fn test_timing_controller_max_parallel() {
        let controller = TimingController::new(TimingTemplate::Aggressive);
        assert_eq!(controller.max_parallel(), 500);
    }

    #[test]
    fn test_timing_controller_is_stealthy() {
        assert!(TimingController::new(TimingTemplate::Paranoid).is_stealthy());
        assert!(TimingController::new(TimingTemplate::Sneaky).is_stealthy());
        assert!(TimingController::new(TimingTemplate::Polite).is_stealthy());
        assert!(!TimingController::new(TimingTemplate::Normal).is_stealthy());
        assert!(!TimingController::new(TimingTemplate::Aggressive).is_stealthy());
    }

    #[test]
    fn test_timing_controller_is_aggressive() {
        assert!(TimingController::new(TimingTemplate::Aggressive).is_aggressive());
        assert!(TimingController::new(TimingTemplate::Insane).is_aggressive());
        assert!(!TimingController::new(TimingTemplate::Normal).is_aggressive());
        assert!(!TimingController::new(TimingTemplate::Paranoid).is_aggressive());
    }

    #[test]
    fn test_timing_controller_calculate_scan_delay() {
        let controller = TimingController::new(TimingTemplate::Polite);
        let delay = controller.calculate_scan_delay(100);
        assert_eq!(delay, std::time::Duration::from_millis(10));
    }

    #[test]
    fn test_timing_controller_calculate_probe_timeout() {
        let controller = TimingController::new(TimingTemplate::Normal);

        let timeout = controller.calculate_probe_timeout(0, None);
        assert_eq!(timeout, std::time::Duration::from_millis(1000));

        let timeout = controller.calculate_probe_timeout(1, None);
        assert_eq!(timeout, std::time::Duration::from_millis(2000));
    }

    #[test]
    fn test_timing_controller_calculate_probe_timeout_with_rtt() {
        let controller = TimingController::new(TimingTemplate::Normal);

        let rtt = std::time::Duration::from_millis(100);
        let timeout = controller.calculate_probe_timeout(0, Some(rtt));

        // Should be 3x RTT
        assert_eq!(timeout, std::time::Duration::from_millis(300));
    }

    #[test]
    fn test_timing_controller_as_str() {
        assert_eq!(
            TimingController::new(TimingTemplate::Paranoid).as_str(),
            "T0"
        );
        assert_eq!(TimingController::new(TimingTemplate::Sneaky).as_str(), "T1");
        assert_eq!(TimingController::new(TimingTemplate::Polite).as_str(), "T2");
        assert_eq!(TimingController::new(TimingTemplate::Normal).as_str(), "T3");
        assert_eq!(
            TimingController::new(TimingTemplate::Aggressive).as_str(),
            "T4"
        );
        assert_eq!(TimingController::new(TimingTemplate::Insane).as_str(), "T5");
    }

    #[test]
    fn test_timing_parse_template_valid() {
        assert_eq!(
            TimingController::parse_template("T0").unwrap(),
            TimingTemplate::Paranoid
        );
        assert_eq!(
            TimingController::parse_template("T1").unwrap(),
            TimingTemplate::Sneaky
        );
        assert_eq!(
            TimingController::parse_template("T2").unwrap(),
            TimingTemplate::Polite
        );
        assert_eq!(
            TimingController::parse_template("T3").unwrap(),
            TimingTemplate::Normal
        );
        assert_eq!(
            TimingController::parse_template("T4").unwrap(),
            TimingTemplate::Aggressive
        );
        assert_eq!(
            TimingController::parse_template("T5").unwrap(),
            TimingTemplate::Insane
        );
    }

    #[test]
    fn test_timing_parse_template_valid_names() {
        assert_eq!(
            TimingController::parse_template("PARANOID").unwrap(),
            TimingTemplate::Paranoid
        );
        assert_eq!(
            TimingController::parse_template("SNEAKY").unwrap(),
            TimingTemplate::Sneaky
        );
        assert_eq!(
            TimingController::parse_template("POLITE").unwrap(),
            TimingTemplate::Polite
        );
        assert_eq!(
            TimingController::parse_template("NORMAL").unwrap(),
            TimingTemplate::Normal
        );
        assert_eq!(
            TimingController::parse_template("AGGRESSIVE").unwrap(),
            TimingTemplate::Aggressive
        );
        assert_eq!(
            TimingController::parse_template("INSANE").unwrap(),
            TimingTemplate::Insane
        );
    }

    #[test]
    fn test_timing_parse_template_invalid() {
        TimingController::parse_template("T6").unwrap_err();
        TimingController::parse_template("INVALID").unwrap_err();
        TimingController::parse_template("").unwrap_err();
    }

    #[test]
    fn test_timing_controller_set_template() {
        let mut controller = TimingController::new(TimingTemplate::Normal);
        assert_eq!(controller.max_parallel(), 100);

        controller.set_template(TimingTemplate::Insane);
        assert_eq!(controller.max_parallel(), 1000);
    }

    #[test]
    fn test_timing_values_constant() {
        assert_eq!(DEFAULT_TEMPLATE, TimingTemplate::Normal);
    }

    #[test]
    fn test_timeout_calculation_property() {
        let controller = TimingController::new(TimingTemplate::Normal);

        // Test various attempt numbers
        for attempt in 0u8..5 {
            let timeout = controller.calculate_probe_timeout(attempt, None);

            // Timeout should increase with attempt number (exponential backoff)
            // but should be capped at max
            assert!(timeout <= controller.max_rtt_timeout());
        }
    }

    #[test]
    fn test_parallelism_property() {
        let templates = [
            TimingTemplate::Paranoid,
            TimingTemplate::Sneaky,
            TimingTemplate::Polite,
            TimingTemplate::Normal,
            TimingTemplate::Aggressive,
            TimingTemplate::Insane,
        ];

        for template in templates {
            let controller = TimingController::new(template);

            // All templates should have valid parallelism
            assert!(controller.max_parallel() >= 1);
            assert!(controller.max_parallel() <= 1000);
        }
    }
}
