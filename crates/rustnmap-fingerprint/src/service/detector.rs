//! Service detection engine.
//!
//! Executes service probes and matches responses to detect
//! service types and version information.

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use regex::Regex;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tracing::{debug, info, trace};

use super::{
    database::ProbeDatabase,
    probe::{MatchResult, ProbeDefinition, Protocol},
};
use crate::{FingerprintError, Result};

/// Service version information detected from a port.
///
/// Contains all extracted service details with confidence scores.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceInfo {
    /// Service protocol name (e.g., "ssh", "http", "ftp").
    pub name: String,

    /// Product name with version (e.g., "OpenSSH 8.4").
    pub product: Option<String>,

    /// Version string only.
    pub version: Option<String>,

    /// Additional service information.
    pub info: Option<String>,

    /// Hostname reported by service.
    pub hostname: Option<String>,

    /// Operating system reported by service.
    pub os_type: Option<String>,

    /// Device type reported.
    pub device_type: Option<String>,

    /// CPE (Common Platform Enumeration) identifier.
    pub cpe: Option<String>,

    /// Confidence score (0-10, higher is better).
    pub confidence: u8,
}

impl ServiceInfo {
    /// Create basic service info with just a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            product: None,
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: None,
            confidence: 5,
        }
    }

    /// Set confidence score (clamped to 0-10).
    #[must_use]
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(10);
        self
    }

    /// Create service info from a match result.
    #[must_use]
    pub fn from_match(result: MatchResult) -> Self {
        Self {
            name: result.service,
            product: result.product,
            version: result.version,
            info: result.info,
            hostname: result.hostname,
            os_type: result.os_type,
            device_type: result.device_type,
            cpe: result.cpe,
            confidence: result.confidence,
        }
    }
}

/// Service detection engine.
///
/// Manages probe execution and response matching for service
/// version detection.
#[derive(Debug)]
pub struct ServiceDetector {
    /// Probe database.
    db: ProbeDatabase,

    /// Configurable timeout for probe responses.
    default_timeout: Duration,

    /// Version intensity (1-9).
    intensity: u8,
}

impl ServiceDetector {
    /// Create new detector with probe database.
    #[must_use]
    pub fn new(db: ProbeDatabase) -> Self {
        Self {
            db,
            default_timeout: Duration::from_secs(5),
            intensity: 7,
        }
    }

    /// Set default probe response timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Set version detection intensity (1-9).
    #[must_use]
    pub fn with_intensity(mut self, intensity: u8) -> Self {
        self.intensity = intensity.clamp(1, 9);
        self
    }

    /// Detect service on a specific port.
    ///
    /// # Errors
    /// Returns error if network operation fails or fingerprint matching fails.
    pub async fn detect_service(&self, target: &SocketAddr, port: u16) -> Result<Vec<ServiceInfo>> {
        info!("Starting service detection on {}:{}", target.ip(), port);

        // First try banner grabbing (null probe) for services that send banners immediately
        let mut results = Vec::new();

        match self.grab_banner(target, port).await {
            Ok(Some(banner)) => {
                trace!("Got banner: {} bytes", banner.len());

                // Try to match banner against all probe rules (treat as GenericLines response)
                let probes = self.select_probes(port);
                for probe in &probes {
                    let matches = Self::match_response(probe, &banner)?;
                    for match_result in matches {
                        results.push(ServiceInfo::from_match(match_result));
                    }
                }

                // If we got confident results from banner, return early
                if results.iter().any(|r| r.confidence >= 8) {
                    return Ok(results);
                }
            }
            Ok(None) => {
                debug!("No banner received from {}:{}", target.ip(), port);
            }
            Err(e) => {
                debug!("Banner grab failed: {}", e);
            }
        }

        // Get applicable probes for this port at configured intensity
        let probes = self.select_probes(port);

        if probes.is_empty() {
            debug!("No probes available for port {}", port);
            if results.is_empty() {
                return Ok(vec![ServiceInfo::new("unknown")]);
            }
            return Ok(results);
        }

        // Execute probes in order
        for probe in &probes {
            trace!("Sending probe '{}' to port {}", probe.name, port);

            match self.send_probe(target, port, probe).await {
                Ok(Some(response)) => {
                    trace!("Got response: {} bytes", response.len());

                    // Match response against all rules
                    let matches = Self::match_response(probe, &response)?;

                    for match_result in matches {
                        results.push(ServiceInfo::from_match(match_result));
                    }

                    // If we got confident results, we can stop
                    if results.iter().any(|r| r.confidence >= 8) {
                        break;
                    }
                }
                Ok(None) => {
                    debug!("No response from probe '{}' on port {}", probe.name, port);
                }
                Err(e) => {
                    debug!("Probe '{}' failed: {}", probe.name, e);
                }
            }
        }

        Ok(results)
    }

    /// Grab banner from a TCP port without sending any data.
    ///
    /// Some services (SSH, FTP, SMTP) send a banner immediately upon connection.
    /// This method connects and reads the initial response without sending anything.
    ///
    /// # Errors
    /// Returns error if connection times out or network operation fails.
    pub async fn grab_banner(&self, target: &SocketAddr, port: u16) -> Result<Option<Vec<u8>>> {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        trace!("Grabbing banner from {}:{}", target.ip(), port);

        // Connect to target
        let stream = timeout(
            self.default_timeout,
            TcpStream::connect((target.ip(), port)),
        )
        .await
        .map_err(|_| FingerprintError::Timeout {
            address: target.ip().to_string(),
            port,
        })?;

        let mut stream = stream?;

        // Read banner without sending anything
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(self.default_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => 0,
            Err(_) => {
                return Err(FingerprintError::Timeout {
                    address: target.ip().to_string(),
                    port,
                });
            }
        };

        if n > 0 {
            buffer.truncate(n);
            trace!("Banner grabbed: {} bytes", n);
            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// Select probes for a port based on intensity level.
    fn select_probes(&self, port: u16) -> Vec<&ProbeDefinition> {
        let mut probes: Vec<&ProbeDefinition> = self.db.probes_for_port(port);

        // Filter by intensity - only include probes at or below our intensity
        // Intensity 1 = rarity 1-3, Intensity 9 = all probes
        let max_rarity = self.intensity_to_max_rarity();

        probes.retain(|p| p.rarity <= max_rarity);

        // Sort by rarity (lower = try first) and then by name
        probes.sort_by(|a, b| a.rarity.cmp(&b.rarity).then_with(|| a.name.cmp(&b.name)));

        probes
    }

    /// Convert intensity level (1-9) to maximum probe rarity to use.
    fn intensity_to_max_rarity(&self) -> u8 {
        // Intensity mapping:
        // 0 (light) -> rarity 3
        // 1-5 (default) -> rarity 5-7
        // 6-9 (intensive) -> rarity 7-9
        // 10 (all) -> rarity 9
        match self.intensity {
            0 => 3,
            1..=3 => 5,
            4..=6 => 7,
            _ => 9,
        }
    }

    /// Send a single probe and await response.
    async fn send_probe(
        &self,
        target: &SocketAddr,
        port: u16,
        probe: &ProbeDefinition,
    ) -> Result<Option<Vec<u8>>> {
        let payload = &probe.payload;

        match probe.protocol {
            Protocol::Tcp => self.send_tcp_probe(target, port, payload).await,
            Protocol::Udp => self.send_udp_probe(target, port, payload).await,
        }
    }

    /// Send TCP probe to target.
    async fn send_tcp_probe(
        &self,
        target: &SocketAddr,
        port: u16,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        // Connect and send
        let stream = timeout(
            self.default_timeout,
            TcpStream::connect((target.ip(), port)),
        )
        .await
        .map_err(|_| FingerprintError::Timeout {
            address: target.ip().to_string(),
            port,
        })?;

        // Send payload
        let mut stream = stream?;
        stream
            .write_all(payload)
            .await
            .map_err(|e: std::io::Error| FingerprintError::Network {
                operation: "write probe".to_string(),
                reason: e.to_string(),
            })?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(self.default_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => 0,
            Err(_) => {
                return Err(FingerprintError::Timeout {
                    address: target.ip().to_string(),
                    port,
                })
            }
        };

        if n > 0 {
            buffer.truncate(n);
            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// Send UDP probe to target.
    async fn send_udp_probe(
        &self,
        target: &SocketAddr,
        _port: u16,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| FingerprintError::Network {
                operation: "bind UDP socket".to_string(),
                reason: e.to_string(),
            })?;

        // Send probe
        socket
            .send_to(payload, *target)
            .await
            .map_err(|e| FingerprintError::Network {
                operation: "send UDP probe".to_string(),
                reason: e.to_string(),
            })?;

        // Try to receive response
        let mut buffer = vec![0u8; 4096];
        let result = timeout(self.default_timeout, socket.recv_from(&mut buffer)).await;

        match result {
            Ok(Ok((n, _))) if n > 0 => {
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            _ => Ok(None),
        }
    }

    /// Match response against probe rules.
    fn match_response(probe: &ProbeDefinition, response: &[u8]) -> Result<Vec<MatchResult>> {
        let response_str = String::from_utf8_lossy(response);
        let mut results = Vec::new();

        for rule in &probe.matches {
            let regex = rule.compile_regex()?;
            if let Some(captures) = Self::try_match(&regex, &response_str) {
                let match_result = rule.apply(&captures);
                debug!(
                    "Match rule '{}' with confidence {}",
                    rule.service, match_result.confidence
                );
                results.push(match_result);
            }
        }

        Ok(results)
    }

    /// Try to match regex and extract capture groups.
    fn try_match(regex: &Regex, text: &str) -> Option<HashMap<usize, String>> {
        let captures = regex.captures(text)?;
        let mut map = HashMap::new();

        for (i, opt) in captures.iter().enumerate() {
            if let Some(m) = opt {
                map.insert(i, m.as_str().to_string());
            }
        }

        Some(map)
    }
}

#[cfg(test)]
mod tests {
    use super::super::probe::{MatchRule, MatchTemplate};
    use super::*;

    #[test]
    fn test_service_info_new() {
        let info = ServiceInfo::new("ssh");
        assert_eq!(info.name, "ssh");
        assert_eq!(info.confidence, 5);
        assert!(info.product.is_none());
        assert!(info.version.is_none());
    }

    #[test]
    fn test_service_info_with_confidence() {
        let info = ServiceInfo::new("http").with_confidence(15);
        assert_eq!(info.confidence, 10); // Clamped to max

        let info2 = ServiceInfo::new("ftp").with_confidence(3);
        assert_eq!(info2.confidence, 3); // Unchanged

        let info3 = ServiceInfo::new("smtp").with_confidence(0);
        assert_eq!(info3.confidence, 0); // Zero allowed
    }

    #[test]
    fn test_service_info_from_match_full() {
        let match_result = MatchResult {
            service: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.4".to_string()),
            info: Some("protocol 2.0".to_string()),
            hostname: Some("server.example.com".to_string()),
            os_type: Some("Linux".to_string()),
            device_type: Some("general purpose".to_string()),
            cpe: Some("cpe:/a:openbsd:openssh:8.4".to_string()),
            confidence: 9,
        };

        let info = ServiceInfo::from_match(match_result);
        assert_eq!(info.name, "ssh");
        assert_eq!(info.product, Some("OpenSSH".to_string()));
        assert_eq!(info.version, Some("8.4".to_string()));
        assert_eq!(info.info, Some("protocol 2.0".to_string()));
        assert_eq!(info.hostname, Some("server.example.com".to_string()));
        assert_eq!(info.os_type, Some("Linux".to_string()));
        assert_eq!(info.device_type, Some("general purpose".to_string()));
        assert_eq!(info.cpe, Some("cpe:/a:openbsd:openssh:8.4".to_string()));
        assert_eq!(info.confidence, 9);
    }

    #[test]
    fn test_service_info_from_match_minimal() {
        let match_result = MatchResult {
            service: "unknown".to_string(),
            product: None,
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: None,
            confidence: 5,
        };

        let info = ServiceInfo::from_match(match_result);
        assert_eq!(info.name, "unknown");
        assert!(info.product.is_none());
        assert!(info.version.is_none());
        assert_eq!(info.confidence, 5);
    }

    #[test]
    fn test_intensity_to_max_rarity_boundaries() {
        let mut detector = ServiceDetector::new(ProbeDatabase::empty());

        // Test boundary value 0
        detector.intensity = 0;
        assert_eq!(detector.intensity_to_max_rarity(), 3);

        // Test boundary values 1-3 -> rarity 5
        detector.intensity = 1;
        assert_eq!(detector.intensity_to_max_rarity(), 5);
        detector.intensity = 2;
        assert_eq!(detector.intensity_to_max_rarity(), 5);
        detector.intensity = 3;
        assert_eq!(detector.intensity_to_max_rarity(), 5);

        // Test boundary values 4-6 -> rarity 7
        detector.intensity = 4;
        assert_eq!(detector.intensity_to_max_rarity(), 7);
        detector.intensity = 5;
        assert_eq!(detector.intensity_to_max_rarity(), 7);
        detector.intensity = 6;
        assert_eq!(detector.intensity_to_max_rarity(), 7);

        // Test boundary values 7-9 -> rarity 9
        detector.intensity = 7;
        assert_eq!(detector.intensity_to_max_rarity(), 9);
        detector.intensity = 8;
        assert_eq!(detector.intensity_to_max_rarity(), 9);
        detector.intensity = 9;
        assert_eq!(detector.intensity_to_max_rarity(), 9);

        // Test values above 9 (should clamp to 9)
        detector.intensity = 10;
        assert_eq!(detector.intensity_to_max_rarity(), 9);
        detector.intensity = 255;
        assert_eq!(detector.intensity_to_max_rarity(), 9);
    }

    #[test]
    fn test_detector_with_intensity() {
        let detector = ServiceDetector::new(ProbeDatabase::empty()).with_intensity(5);
        assert_eq!(detector.intensity, 5);

        // Test clamping at upper bound
        let detector2 = ServiceDetector::new(ProbeDatabase::empty()).with_intensity(15);
        assert_eq!(detector2.intensity, 9);

        // Test clamping at lower bound
        let detector3 = ServiceDetector::new(ProbeDatabase::empty()).with_intensity(0);
        assert_eq!(detector3.intensity, 1);
    }

    #[test]
    fn test_detector_with_timeout() {
        let detector =
            ServiceDetector::new(ProbeDatabase::empty()).with_timeout(Duration::from_secs(10));
        assert_eq!(detector.default_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_try_match() {
        let detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH-([\d.]+)-(.*)").unwrap();

        let text = "SSH-8.4-p1";
        let captures = ServiceDetector::try_match(&regex, text).unwrap();

        assert_eq!(captures.get(&0), Some(&"SSH-8.4-p1".to_string())); // Full match
        assert_eq!(captures.get(&1), Some(&"8.4".to_string()));
        assert_eq!(captures.get(&2), Some(&"p1".to_string()));
    }

    #[test]
    fn test_try_match_no_match() {
        let detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH-([\d.]+)").unwrap();

        let text = "HTTP/1.1 200 OK";
        let result = ServiceDetector::try_match(&regex, text);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_match_empty_captures() {
        let detector = ServiceDetector::new(ProbeDatabase::empty());
        // Regex with optional group that doesn't match
        let regex = Regex::new(r"SSH(-[\d.]+)?").unwrap();

        let text = "SSH";
        let captures = ServiceDetector::try_match(&regex, text).unwrap();
        assert_eq!(captures.get(&0), Some(&"SSH".to_string()));
        // Group 1 doesn't exist in this match because optional part not present
        assert_eq!(captures.get(&1), None);
    }

    #[test]
    fn test_try_match_with_optional_group_present() {
        let detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH(-[\d.]+)?").unwrap();

        let text = "SSH-2.0";
        let captures = ServiceDetector::try_match(&regex, text).unwrap();
        assert_eq!(captures.get(&0), Some(&"SSH-2.0".to_string()));
        assert_eq!(captures.get(&1), Some(&"-2.0".to_string()));
    }

    #[test]
    fn test_match_response_success() {
        let mut probe = ProbeDefinition::new_tcp("SSHProbe".to_string(), b"".to_vec());
        probe.add_match(MatchRule {
            pattern: r"^SSH-([\d.]+)-OpenSSH_(.*)".to_string(),
            service: "ssh".to_string(),
            product_template: Some(MatchTemplate {
                value: "OpenSSH".to_string(),
            }),
            version_template: Some(MatchTemplate {
                value: "$1".to_string(),
            }),
            info_template: Some(MatchTemplate {
                value: "$2".to_string(),
            }),
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        });

        let response = b"SSH-2.0-OpenSSH_8.4p1";
        let results = ServiceDetector::match_response(&probe, response).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "ssh");
        assert_eq!(results[0].product, Some("OpenSSH".to_string()));
        assert_eq!(results[0].version, Some("2.0".to_string()));
        assert_eq!(results[0].info, Some("8.4p1".to_string()));
        assert_eq!(results[0].confidence, 8); // Hard match
    }

    #[test]
    fn test_match_response_soft_match() {
        let mut probe = ProbeDefinition::new_tcp("GenericProbe".to_string(), b"".to_vec());
        probe.add_match(MatchRule {
            pattern: r"^SSH".to_string(),
            service: "ssh".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: true,
        });

        let response = b"SSH-2.0-OpenSSH_8.4";
        let results = ServiceDetector::match_response(&probe, response).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "ssh");
        assert_eq!(results[0].confidence, 5); // Soft match
    }

    #[test]
    fn test_match_response_no_match() {
        let mut probe = ProbeDefinition::new_tcp("SSHProbe".to_string(), b"".to_vec());
        probe.add_match(MatchRule {
            pattern: r"^SSH-".to_string(),
            service: "ssh".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        });

        let response = b"HTTP/1.1 200 OK";
        let results = ServiceDetector::match_response(&probe, response).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_match_response_multiple_rules() {
        let mut probe = ProbeDefinition::new_tcp("MultiProbe".to_string(), b"".to_vec());
        probe.add_match(MatchRule {
            pattern: r"^SSH-".to_string(),
            service: "ssh".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        });
        probe.add_match(MatchRule {
            pattern: r"^HTTP/".to_string(),
            service: "http".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        });

        // Test SSH match
        let results = ServiceDetector::match_response(&probe, b"SSH-2.0-OpenSSH").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "ssh");

        // Test HTTP match
        let results = ServiceDetector::match_response(&probe, b"HTTP/1.1 200 OK").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "http");
    }

    #[test]
    fn test_match_response_invalid_regex() {
        let mut probe = ProbeDefinition::new_tcp("BadProbe".to_string(), b"".to_vec());
        probe.add_match(MatchRule {
            pattern: r"[invalid(".to_string(), // Invalid regex
            service: "test".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        });

        let response = b"test";
        let result = ServiceDetector::match_response(&probe, response);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FingerprintError::InvalidRegex { .. }
        ));
    }

    #[test]
    fn test_match_response_binary_data() {
        let mut probe = ProbeDefinition::new_tcp("BinaryProbe".to_string(), b"".to_vec());
        probe.add_match(MatchRule {
            pattern: r"\x00\x01\x02".to_string(),
            service: "binary".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        });

        let response = vec![0x00, 0x01, 0x02, 0x03];
        let results = ServiceDetector::match_response(&probe, &response).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "binary");
    }

    #[test]
    fn test_select_probes_with_empty_database() {
        let db = ProbeDatabase::empty();
        let detector = ServiceDetector::new(db);
        let probes = detector.select_probes(80);
        assert!(probes.is_empty());
    }

    #[test]
    fn test_select_probes_filters_by_rarity_via_parse() {
        let content = r"
Probe TCP Common q|probe1|
rarity 1
Ports 80

Probe TCP Uncommon q|probe2|
rarity 5
Ports 80

Probe TCP Rare q|probe3|
rarity 9
Ports 80
";
        let db = ProbeDatabase::parse(content).unwrap();

        // Test with intensity 3 (max rarity 5)
        let detector = ServiceDetector::new(db.clone()).with_intensity(3);
        let probes = detector.select_probes(80);
        assert_eq!(probes.len(), 2); // Common and Uncommon
        assert!(probes.iter().all(|p| p.rarity <= 5));

        // Test with intensity 9 (max rarity 9)
        let detector = ServiceDetector::new(db).with_intensity(9);
        let probes = detector.select_probes(80);
        assert_eq!(probes.len(), 3); // All probes
    }

    #[test]
    fn test_select_probes_sorts_by_rarity_via_parse() {
        let content = r"
Probe TCP Zebra q|probe1|
rarity 5
Ports 80

Probe TCP Alpha q|probe2|
rarity 1
Ports 80

Probe TCP Beta q|probe3|
rarity 3
Ports 80
";
        let db = ProbeDatabase::parse(content).unwrap();

        let detector = ServiceDetector::new(db).with_intensity(9);
        let probes = detector.select_probes(80);

        assert_eq!(probes.len(), 3);
        assert_eq!(probes[0].name, "Alpha"); // rarity 1
        assert_eq!(probes[1].name, "Beta"); // rarity 3
        assert_eq!(probes[2].name, "Zebra"); // rarity 5
    }

    #[test]
    fn test_select_probes_sorts_by_name_for_same_rarity_via_parse() {
        let content = r"
Probe TCP Zebra q|probe1|
rarity 3
Ports 80

Probe TCP Alpha q|probe2|
rarity 3
Ports 80
";
        let db = ProbeDatabase::parse(content).unwrap();

        let detector = ServiceDetector::new(db).with_intensity(9);
        let probes = detector.select_probes(80);

        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].name, "Alpha"); // Same rarity, alphabetical
        assert_eq!(probes[1].name, "Zebra");
    }

    #[test]
    fn test_service_info_default_confidence() {
        let info = ServiceInfo::new("test");
        assert_eq!(info.confidence, 5);
    }

    #[test]
    fn test_service_info_with_confidence_clamping() {
        // Test upper clamp
        let info = ServiceInfo::new("test").with_confidence(255);
        assert_eq!(info.confidence, 10);

        // Test at boundary
        let info = ServiceInfo::new("test").with_confidence(10);
        assert_eq!(info.confidence, 10);

        // Test below boundary
        let info = ServiceInfo::new("test").with_confidence(9);
        assert_eq!(info.confidence, 9);
    }
}
