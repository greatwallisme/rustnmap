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
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(10);
        self
    }

    /// Create service info from a match result.
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
    pub fn new(db: ProbeDatabase) -> Self {
        Self {
            db,
            default_timeout: Duration::from_secs(5),
            intensity: 7,
        }
    }

    /// Set default probe response timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Set version detection intensity (1-9).
    pub fn with_intensity(mut self, intensity: u8) -> Self {
        self.intensity = intensity.clamp(1, 9);
        self
    }

    /// Detect service on a specific port.
    pub async fn detect_service(&self, target: &SocketAddr, port: u16) -> Result<Vec<ServiceInfo>> {
        info!("Starting service detection on {}:{}", target.ip(), port);

        // Get applicable probes for this port at configured intensity
        let probes = self.select_probes(port);

        if probes.is_empty() {
            debug!("No probes available for port {}", port);
            return Ok(vec![ServiceInfo::new("unknown")]);
        }

        let mut results = Vec::new();

        // Execute probes in order
        for probe in &probes {
            trace!("Sending probe '{}' to port {}", probe.name, port);

            match self.send_probe(target, port, probe).await {
                Ok(Some(response)) => {
                    trace!("Got response: {} bytes", response.len());

                    // Match response against all rules
                    let matches = self.match_response(probe, &response)?;

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
            7..=9 => 9,
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
    fn match_response(&self, probe: &ProbeDefinition, response: &[u8]) -> Result<Vec<MatchResult>> {
        let response_str = String::from_utf8_lossy(response);
        let mut results = Vec::new();

        for rule in &probe.matches {
            let regex = rule.compile_regex()?;
            if let Some(captures) = self.try_match(&regex, &response_str) {
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
    fn try_match(&self, regex: &Regex, text: &str) -> Option<HashMap<usize, String>> {
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
    use super::*;

    #[test]
    fn test_service_info_new() {
        let info = ServiceInfo::new("ssh");
        assert_eq!(info.name, "ssh");
        assert_eq!(info.confidence, 5);
    }

    #[test]
    fn test_service_info_with_confidence() {
        let info = ServiceInfo::new("http").with_confidence(15);
        assert_eq!(info.confidence, 10); // Clamped
    }

    #[test]
    fn test_intensity_to_max_rarity() {
        let mut detector = ServiceDetector::new(ProbeDatabase::empty());

        detector.intensity = 0;
        assert_eq!(detector.intensity_to_max_rarity(), 3);

        detector.intensity = 5;
        assert_eq!(detector.intensity_to_max_rarity(), 7);

        detector.intensity = 9;
        assert_eq!(detector.intensity_to_max_rarity(), 9);
    }

    #[test]
    fn test_try_match() {
        let detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH-([\d.]+)-(.*)").unwrap();

        let text = "SSH-8.4-p1";
        let captures = detector.try_match(&regex, text).unwrap();

        assert_eq!(captures.get(&1), Some(&"8.4".to_string()));
        assert_eq!(captures.get(&2), Some(&"p1".to_string()));
    }
}
