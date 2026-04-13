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

//! Create scan handler
// Rust guideline compliant 2026-03-10

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

/// Valid scan types per nmap specification.
const VALID_SCAN_TYPES: &[&str] = &[
    "syn",
    "connect",
    "udp",
    "fin",
    "null",
    "xmas",
    "maimon",
    "sctp_init",
    "sctp_cookie",
    "ack",
    "window",
    "idle",
];

/// Valid timing templates (T0-T5).
const VALID_TIMING: &[&str] = &["T0", "T1", "T2", "T3", "T4", "T5"];

/// Validate scan creation request.
///
/// # Errors
///
/// Returns an error if:
/// - No targets specified
/// - Invalid target format
/// - Invalid scan type
/// - Invalid timing template
/// - Invalid port specification
fn validate_request(request: &crate::CreateScanRequest) -> Result<(), ApiError> {
    // Validate targets not empty
    if request.targets.is_empty() {
        return Err(ApiError::InvalidRequest("No targets specified".to_string()));
    }

    // Validate each target format
    for target in &request.targets {
        validate_target_format(target)?;
    }

    // Validate scan_type against allowed values
    let scan_type_str = request.scan_type.as_str();
    if !VALID_SCAN_TYPES.contains(&scan_type_str) {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid scan_type: '{}'. Valid types: {}",
            request.scan_type,
            VALID_SCAN_TYPES.join(", ")
        )));
    }

    // Validate timing template if provided
    if let Some(timing) = &request.options.timing {
        let timing_str = timing.as_str();
        if !VALID_TIMING.contains(&timing_str) {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid timing template: '{}'. Valid templates: {}",
                timing,
                VALID_TIMING.join(", ")
            )));
        }
    }

    // Validate port specification if provided
    if let Some(ports) = &request.options.ports {
        validate_port_spec(ports)?;
    }

    Ok(())
}

/// Validate a target format (IP, CIDR, or hostname).
///
/// # Errors
///
/// Returns an error if the target format is invalid.
fn validate_target_format(target: &str) -> Result<(), ApiError> {
    // Try parsing as CIDR notation first
    if target.contains('/') {
        // Basic CIDR validation: IP/prefix format
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() != 2 {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid CIDR notation: '{target}'. Expected format: IP/prefix (e.g., 192.168.1.0/24)"
            )));
        }

        // Validate IP part
        let ip_part = parts[0];
        if ip_part.parse::<std::net::IpAddr>().is_err() {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid IP address in CIDR: '{ip_part}'"
            )));
        }

        // Validate prefix part
        let prefix_str = parts[1];
        if let Ok(prefix) = prefix_str.parse::<u8>() {
            // Valid prefix range depends on IP version
            let max_prefix = if target.contains(':') { 128 } else { 32 };
            if prefix > max_prefix {
                return Err(ApiError::InvalidRequest(format!(
                    "Invalid CIDR prefix: '/{prefix}'. Must be 0-{max_prefix}"
                )));
            }
        } else {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid CIDR prefix: '{prefix_str}'. Must be a number"
            )));
        }

        return Ok(());
    }

    // Try parsing as IP address
    if let Ok(addr) = target.parse::<std::net::IpAddr>() {
        // Check if address is reserved/special based on type
        // Note: loopback (127.0.0.1, ::1) is ALLOWED for testing purposes (matches nmap behavior)
        let is_special = match addr {
            std::net::IpAddr::V4(v4) => v4.is_multicast() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_multicast(),
        };
        if is_special {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid IP address: '{addr}'. Address is multicast or link-local"
            )));
        }
        return Ok(());
    }

    // Validate as hostname
    validate_hostname(target)
}

/// Validate a port specification string.
///
/// Supports: "22", "1-1000", "22,80,443", "top100", "all".
///
/// # Errors
///
/// Returns an error if the port specification contains invalid port numbers or syntax.
fn validate_port_spec(spec: &str) -> Result<(), ApiError> {
    match spec {
        "1-65535" | "all" | "*" => Ok(()),
        s if s.starts_with("top") => {
            let n = s.trim_start_matches("top").trim();
            if n.parse::<usize>().is_err() {
                return Err(ApiError::InvalidRequest(format!(
                    "Invalid port spec: '{spec}'. 'top' must be followed by a number (e.g., top100)"
                )));
            }
            Ok(())
        }
        s if s.contains(',') => {
            for part in s.split(',') {
                validate_single_port_or_range(part.trim(), spec)?;
            }
            Ok(())
        }
        s => validate_single_port_or_range(s, spec),
    }
}

/// Validate a single port number or port range.
fn validate_single_port_or_range(part: &str, full_spec: &str) -> Result<(), ApiError> {
    if let Some((start, end)) = part.split_once('-') {
        let start: u16 = start.parse().map_err(|_e| {
            ApiError::InvalidRequest(format!(
                "Invalid port in spec '{full_spec}': '{start}' is not a valid port number"
            ))
        })?;
        let end: u16 = end.parse().map_err(|_e| {
            ApiError::InvalidRequest(format!(
                "Invalid port in spec '{full_spec}': '{end}' is not a valid port number"
            ))
        })?;
        if start > end {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid port range in spec '{full_spec}': start ({start}) > end ({end})"
            )));
        }
    } else {
        part.parse::<u16>().map_err(|_e| {
            ApiError::InvalidRequest(format!(
                "Invalid port in spec '{full_spec}': '{part}' is not a valid port number"
            ))
        })?;
    }
    Ok(())
}

/// Validate a hostname format.
///
/// # Errors
///
/// Returns an error if the hostname format is invalid.
fn validate_hostname(hostname: &str) -> Result<(), ApiError> {
    // RFC 952/1123 compliant hostname validation
    // - Max 253 characters total
    // - Each label max 63 characters
    // - Labels: alphanumeric + hyphen (not at start/end)
    // - Underscore allowed (not RFC, but common in practice)

    if hostname.is_empty() || hostname.len() > 253 {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid hostname length: '{hostname}'. Must be 1-253 characters"
        )));
    }

    // Split into labels and validate each
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid hostname label: '{label}'. Each label must be 1-63 characters"
            )));
        }

        // Check characters: alphanumeric, hyphen, underscore
        let chars_valid = label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !chars_valid {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid hostname label: '{label}'. Labels can only contain alphanumeric characters, hyphens, or underscores"
            )));
        }

        // Label cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ApiError::InvalidRequest(format!(
                "Invalid hostname label: '{label}'. Labels cannot start or end with hyphen"
            )));
        }
    }

    Ok(())
}

/// Handler for POST /api/v1/scans
///
/// # Errors
///
/// Returns an error if the request is invalid or the scan cannot be created.
pub async fn create_scan(
    State(state): State<crate::server::ApiState>,
    Json(request): Json<crate::CreateScanRequest>,
) -> ApiResult<(StatusCode, Json<crate::ApiResponse<CreateScanResponse>>)> {
    // Validate request
    validate_request(&request)?;

    // Create scan task
    let scan_id = format!("scan_{}", Uuid::new_v4().as_simple());

    // Submit scan to manager (with concurrency limit check)
    state.scan_manager.create_scan_if_allowed(
        &scan_id,
        request.targets.clone(),
        request.scan_type.clone(),
    )?;

    let response = CreateScanResponse {
        id: scan_id.clone(),
        status: crate::ScanStatus::Queued,
        created_at: chrono::Utc::now(),
        targets: request.targets,
        progress: crate::ScanProgress {
            total_hosts: 0,
            completed_hosts: 0,
            percentage: 0.0,
            current_phase: None,
            pps: None,
            eta_seconds: None,
        },
    };

    Ok((
        StatusCode::CREATED,
        Json(crate::ApiResponse::success(response)),
    ))
}

/// Response for successful scan creation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CreateScanResponse {
    pub id: String,
    pub status: crate::ScanStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub targets: Vec<String>,
    pub progress: crate::ScanProgress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateScanRequest, ScanOptions};

    fn make_request(targets: Vec<&str>) -> CreateScanRequest {
        CreateScanRequest {
            targets: targets.into_iter().map(String::from).collect(),
            scan_type: "syn".to_string(),
            options: ScanOptions::default(),
        }
    }

    // ==================== validate_request tests ====================

    #[test]
    fn test_validate_request_empty_targets() {
        let request = CreateScanRequest {
            targets: vec![],
            scan_type: "syn".to_string(),
            options: ScanOptions::default(),
        };
        let result = validate_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ApiError::InvalidRequest(_)));
    }

    #[test]
    fn test_validate_request_valid_targets() {
        let request = make_request(vec!["192.168.1.1", "scanme.nmap.org"]);
        let result = validate_request(&request);
        result.unwrap();
    }

    #[test]
    fn test_validate_request_invalid_scan_type() {
        let request = CreateScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            scan_type: "invalid_scan".to_string(),
            options: ScanOptions::default(),
        };
        let result = validate_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let ApiError::InvalidRequest(msg) = err {
            assert!(msg.contains("Invalid scan_type"));
        } else {
            panic!("Expected InvalidRequest error");
        }
    }

    #[test]
    fn test_validate_request_valid_timing() {
        let request = CreateScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            scan_type: "syn".to_string(),
            options: ScanOptions {
                timing: Some("T4".to_string()),
                ..Default::default()
            },
        };
        let result = validate_request(&request);
        result.unwrap();
    }

    #[test]
    fn test_validate_request_invalid_timing() {
        let request = CreateScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            scan_type: "syn".to_string(),
            options: ScanOptions {
                timing: Some("T9".to_string()),
                ..Default::default()
            },
        };
        let result = validate_request(&request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let ApiError::InvalidRequest(msg) = err {
            assert!(msg.contains("Invalid timing template"));
        } else {
            panic!("Expected InvalidRequest error");
        }
    }

    // ==================== validate_target_format tests ====================

    #[test]
    fn test_validate_target_ipv4_valid() {
        validate_target_format("192.168.1.1").unwrap();
        validate_target_format("8.8.8.8").unwrap();
        validate_target_format("45.33.32.156").unwrap();
    }

    #[test]
    fn test_validate_target_ipv4_loopback_allowed() {
        // Loopback is allowed for testing purposes (matches nmap behavior)
        validate_target_format("127.0.0.1").unwrap();
    }

    #[test]
    fn test_validate_target_ipv4_multicast_rejected() {
        let result = validate_target_format("224.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_target_ipv4_link_local_rejected() {
        let result = validate_target_format("169.254.1.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_target_ipv6_valid() {
        validate_target_format("2001:4860:4860::8888").unwrap();
        validate_target_format("2607:f8b0:4004:800::200e").unwrap();
    }

    #[test]
    fn test_validate_target_ipv6_loopback_allowed() {
        // Loopback is allowed for testing purposes (matches nmap behavior)
        validate_target_format("::1").unwrap();
    }

    #[test]
    fn test_validate_target_ipv6_multicast_rejected() {
        let result = validate_target_format("ff02::1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_target_cidr_ipv4_valid() {
        validate_target_format("192.168.1.0/24").unwrap();
        validate_target_format("10.0.0.0/8").unwrap();
        validate_target_format("0.0.0.0/0").unwrap();
        validate_target_format("192.168.1.1/32").unwrap();
    }

    #[test]
    fn test_validate_target_cidr_ipv4_invalid_prefix() {
        let result = validate_target_format("192.168.1.0/33");
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let ApiError::InvalidRequest(msg) = err {
            assert!(msg.contains("Invalid CIDR prefix"));
        } else {
            panic!("Expected InvalidRequest error");
        }
    }

    #[test]
    fn test_validate_target_cidr_ipv4_missing_prefix() {
        let result = validate_target_format("192.168.1.0/");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_target_cidr_ipv4_invalid_ip() {
        let result = validate_target_format("256.1.1.0/24");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_target_cidr_ipv6_valid() {
        validate_target_format("2001:db8::/32").unwrap();
        validate_target_format("fe80::/10").unwrap();
    }

    #[test]
    fn test_validate_target_cidr_ipv6_invalid_prefix() {
        let result = validate_target_format("2001:db8::/129");
        assert!(result.is_err());
    }

    // ==================== validate_hostname tests ====================

    #[test]
    fn test_validate_hostname_valid() {
        validate_hostname("localhost").unwrap();
        validate_hostname("scanme.nmap.org").unwrap();
        validate_hostname("example.com").unwrap();
        validate_hostname("sub.domain.example.com").unwrap();
        validate_hostname("my-host").unwrap();
        validate_hostname("my_host").unwrap();
        validate_hostname("a").unwrap(); // Single char
    }

    #[test]
    fn test_validate_hostname_empty() {
        let result = validate_hostname("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_too_long() {
        let long_hostname = "a".repeat(254);
        let result = validate_hostname(&long_hostname);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_label_too_long() {
        let long_label = "a".repeat(64);
        let hostname = format!("{long_label}.com");
        let result = validate_hostname(&hostname);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_starts_with_hyphen() {
        let result = validate_hostname("-invalid.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_ends_with_hyphen() {
        let result = validate_hostname("invalid-.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_invalid_chars() {
        assert!(validate_hostname("invalid!.com").is_err());
        assert!(validate_hostname("invalid@.com").is_err());
        assert!(validate_hostname("invalid .com").is_err());
    }

    #[test]
    fn test_validate_hostname_empty_label() {
        let result = validate_hostname("invalid..com");
        assert!(result.is_err());
    }

    // ==================== scan type validation tests ====================

    #[test]
    fn test_all_scan_types_valid() {
        let scan_types = [
            "syn",
            "connect",
            "udp",
            "fin",
            "null",
            "xmas",
            "maimon",
            "sctp_init",
            "sctp_cookie",
            "ack",
            "window",
            "idle",
        ];
        for scan_type in scan_types {
            let request = CreateScanRequest {
                targets: vec!["192.168.1.1".to_string()],
                scan_type: scan_type.to_string(),
                options: ScanOptions::default(),
            };
            assert!(
                validate_request(&request).is_ok(),
                "Scan type '{scan_type}' should be valid"
            );
        }
    }

    // ==================== timing template validation tests ====================

    #[test]
    fn test_all_timing_templates_valid() {
        let timings = ["T0", "T1", "T2", "T3", "T4", "T5"];
        for timing in timings {
            let request = CreateScanRequest {
                targets: vec!["192.168.1.1".to_string()],
                scan_type: "syn".to_string(),
                options: ScanOptions {
                    timing: Some(timing.to_string()),
                    ..Default::default()
                },
            };
            assert!(
                validate_request(&request).is_ok(),
                "Timing template '{timing}' should be valid"
            );
        }
    }

    // ==================== port validation tests ====================

    #[test]
    fn test_validate_port_spec_single_port() {
        validate_port_spec("80").unwrap();
        validate_port_spec("443").unwrap();
    }

    #[test]
    fn test_validate_port_spec_range() {
        validate_port_spec("1-1000").unwrap();
        validate_port_spec("22-80").unwrap();
    }

    #[test]
    fn test_validate_port_spec_comma_separated() {
        validate_port_spec("22,80,443").unwrap();
        validate_port_spec("80,443").unwrap();
    }

    #[test]
    fn test_validate_port_spec_top() {
        validate_port_spec("top100").unwrap();
        validate_port_spec("top1000").unwrap();
    }

    #[test]
    fn test_validate_port_spec_all() {
        validate_port_spec("all").unwrap();
        validate_port_spec("1-65535").unwrap();
        validate_port_spec("*").unwrap();
    }

    #[test]
    fn test_validate_port_spec_invalid_port() {
        let result = validate_port_spec("99999");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_port_spec_invalid_range() {
        let result = validate_port_spec("80-22");
        assert!(result.is_err());
        if let ApiError::InvalidRequest(msg) = result.unwrap_err() {
            assert!(msg.contains("start") && msg.contains("end"));
        }
    }

    #[test]
    fn test_validate_port_spec_invalid_comma() {
        let result = validate_port_spec("22,abc,443");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_port_spec_invalid_top() {
        let result = validate_port_spec("topabc");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_request_valid_ports() {
        let request = CreateScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            scan_type: "syn".to_string(),
            options: ScanOptions {
                ports: Some("22,80,443".to_string()),
                ..Default::default()
            },
        };
        validate_request(&request).unwrap();
    }
}
