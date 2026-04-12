//! Service detection engine.
//!
//! Executes service probes and matches responses to detect
//! service types and version information.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use pcre2::bytes::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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
#[derive(Debug, Clone)]
pub struct ServiceDetector {
    /// Probe database shared across concurrent detection tasks via Arc.
    db: Arc<ProbeDatabase>,

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
            db: Arc::new(db),
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
    /// Implements nmap's total time budget model (DEFAULT_SERVICEWAITMS):
    /// all probes for a single port share one time budget (5 seconds).
    /// Each subsequent probe gets `budget - elapsed`, matching nmap's
    /// `probe_timemsleft()` logic in `service_scan.cc`.
    ///
    /// Connection reuse: the TCP connection from the banner grab (NULL probe)
    /// is reused for the first subsequent probe, matching nmap's optimization
    /// in `service_scan.cc` lines 2095-2105.
    ///
    /// # Arguments
    ///
    /// * `target` - Target socket address
    /// * `port` - Port number to probe
    /// * `protocol` - Protocol string: "tcp" or "udp"
    ///
    /// # Errors
    ///
    /// Returns error if network operation fails or fingerprint matching fails.
    pub async fn detect_service_with_protocol(
        &self,
        target: &SocketAddr,
        port: u16,
        protocol: &str,
    ) -> Result<Vec<ServiceInfo>> {
        info!(
            "Starting service detection on {}:{} ({})",
            target.ip(),
            port,
            protocol
        );
        let is_udp = protocol.eq_ignore_ascii_case("udp");

        // nmap's DEFAULT_SERVICEWAITMS = 5000ms: total time budget for ALL probes.
        // Each probe's timeout = budget - elapsed_so_far.
        let total_budget = self.default_timeout;
        let start = Instant::now();
        let mut results = Vec::new();

        // Track TCP connection for reuse after banner grab (nmap optimization)
        let mut reusable_stream: Option<tokio::net::TcpStream> = None;

        // Banner grabbing only works for TCP (services that send banners on connect).
        // UDP services never send unsolicited data, so skip banner grab entirely.
        // nmap calls this the "NULL probe" and it shares the same time budget.
        if !is_udp {
            let remaining = total_budget.saturating_sub(start.elapsed());
            if !remaining.is_zero() {
                match self.grab_banner_and_keep_stream(target, port, remaining).await {
                    Ok((banner_opt, stream_opt)) => {
                        reusable_stream = stream_opt;

                        if let Some(banner) = banner_opt {
                            trace!("Got banner: {} bytes", banner.len());

                            // Try to match banner against all probe rules
                            let probes = self.select_probes(port, protocol);
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
                    }
                    Err(e) => {
                        debug!("Banner grab failed: {}", e);
                    }
                }
            }
        }

        // Get applicable probes for this port at configured intensity
        let probes = self.select_probes(port, protocol);
        debug!("Selected {} probes for port {}", probes.len(), port);

        if probes.is_empty() {
            debug!("No probes available for port {}", port);
            if results.is_empty() {
                return Ok(vec![ServiceInfo::new("unknown")]);
            }
            return Ok(results);
        }

        // Execute probes in order, sharing the remaining time budget.
        // Reuse TCP connection from banner grab for first probe (nmap optimization).
        for probe in &probes {
            let remaining = total_budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                debug!("Time budget exhausted, stopping probes for port {}", port);
                break;
            }

            debug!(
                "Sending probe '{}' to port {} ({}ms remaining)",
                probe.name,
                port,
                remaining.as_millis()
            );

            // Try to reuse existing connection for first probe, then open new ones
            let response = if let Some(stream) = reusable_stream.take() {
                self.send_probe_on_existing_stream(stream, probe, remaining)
                    .await
            } else {
                self.send_probe_with_timeout(target, port, probe, remaining)
                    .await
            };

            match response {
                Ok(Some(response)) => {
                    debug!(
                        "Got {} bytes from probe '{}' on port {}",
                        response.len(),
                        probe.name,
                        port
                    );

                    let matches = Self::match_response(probe, &response)?;

                    debug!(
                        "Got {} matches from probe '{}' on port {}",
                        matches.len(),
                        probe.name,
                        port
                    );
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

    /// Send a probe with a specific timeout (for total time budget).
    async fn send_probe_with_timeout(
        &self,
        target: &SocketAddr,
        port: u16,
        probe: &ProbeDefinition,
        timeout_duration: Duration,
    ) -> Result<Option<Vec<u8>>> {
        let payload = &probe.payload;

        match probe.protocol {
            Protocol::Tcp => {
                self.send_tcp_probe_with_timeout(target, port, payload, timeout_duration)
                    .await
            }
            Protocol::Udp => {
                self.send_udp_probe_with_timeout(target, port, payload, timeout_duration)
                    .await
            }
        }
    }

    /// Grab banner while keeping the TCP stream for connection reuse.
    ///
    /// Returns (banner_option, stream_option). The stream can be reused
    /// for the next probe, avoiding an extra TCP handshake.
    /// Matches nmap's optimization in service_scan.cc lines 2095-2105.
    async fn grab_banner_and_keep_stream(
        &self,
        target: &SocketAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<(Option<Vec<u8>>, Option<tokio::net::TcpStream>)> {
        trace!(
            "Grabbing banner from {}:{} (timeout: {}ms)",
            target.ip(),
            port,
            timeout_duration.as_millis()
        );

        let stream = timeout(timeout_duration, TcpStream::connect((target.ip(), port)))
            .await
            .map_err(|_| FingerprintError::Timeout {
                address: target.ip().to_string(),
                port,
            })?;

        let mut stream = stream?;

        // Set read timeout to avoid blocking beyond budget
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(timeout_duration, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => {
                // Read error but connection is open -- return stream for reuse
                return Ok((None, Some(stream)));
            }
            Err(_) => {
                // Timeout on read -- connection still usable for sending probes
                return Ok((None, Some(stream)));
            }
        };

        if n > 0 {
            buffer.truncate(n);
            trace!("Banner grabbed: {} bytes", n);
            Ok((Some(buffer), Some(stream)))
        } else {
            // No data but connection open
            Ok((None, Some(stream)))
        }
    }

    /// Send a probe on an existing TCP stream (connection reuse).
    ///
    /// This avoids the TCP handshake overhead (~1 RTT) for the first probe
    /// after the banner grab, matching nmap's connection reuse optimization.
    async fn send_probe_on_existing_stream(
        &self,
        mut stream: tokio::net::TcpStream,
        probe: &ProbeDefinition,
        timeout_duration: Duration,
    ) -> Result<Option<Vec<u8>>> {
        let payload = &probe.payload;

        stream
            .write_all(payload)
            .await
            .map_err(|e: std::io::Error| FingerprintError::Network {
                operation: "write probe on existing stream".to_string(),
                reason: e.to_string(),
            })?;

        let mut buffer = vec![0u8; 4096];
        let n = match timeout(timeout_duration, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => 0,
            Err(_) => {
                return Ok(None);
            }
        };

        if n > 0 {
            buffer.truncate(n);
            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// Send TCP probe with specific timeout.
    async fn send_tcp_probe_with_timeout(
        &self,
        target: &SocketAddr,
        port: u16,
        payload: &[u8],
        timeout_duration: Duration,
    ) -> Result<Option<Vec<u8>>> {
        let stream = timeout(timeout_duration, TcpStream::connect((target.ip(), port)))
            .await
            .map_err(|_| FingerprintError::Timeout {
                address: target.ip().to_string(),
                port,
            })?;

        let mut stream = stream?;
        stream
            .write_all(payload)
            .await
            .map_err(|e: std::io::Error| FingerprintError::Network {
                operation: "write probe".to_string(),
                reason: e.to_string(),
            })?;

        let mut buffer = vec![0u8; 4096];
        let n = match timeout(timeout_duration, stream.read(&mut buffer)).await {
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

    /// Send UDP probe with specific timeout.
    async fn send_udp_probe_with_timeout(
        &self,
        target: &SocketAddr,
        _port: u16,
        payload: &[u8],
        timeout_duration: Duration,
    ) -> Result<Option<Vec<u8>>> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| FingerprintError::Network {
                operation: "bind UDP socket".to_string(),
                reason: e.to_string(),
            })?;

        socket
            .send_to(payload, *target)
            .await
            .map_err(|e| FingerprintError::Network {
                operation: "send UDP probe".to_string(),
                reason: e.to_string(),
            })?;

        let mut buffer = vec![0u8; 4096];
        let result = timeout(timeout_duration, socket.recv_from(&mut buffer)).await;

        match result {
            Ok(Ok((n, _))) if n > 0 => {
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            _ => Ok(None),
        }
    }

    /// Select probes for a port based on intensity level.
    fn select_probes(&self, port: u16, protocol: &str) -> Vec<&ProbeDefinition> {
        let mut probes: Vec<&ProbeDefinition> = self.db.probes_for_port(port);

        // nmap separates TCP and UDP service probes completely.
        // TCP ports only get TCP probes, UDP ports only get UDP probes.
        let target_protocol = if protocol.eq_ignore_ascii_case("udp") {
            Protocol::Udp
        } else {
            Protocol::Tcp
        };
        probes.retain(|p| p.protocol == target_protocol);

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

    /// Match response against probe rules.
    fn match_response(probe: &ProbeDefinition, response: &[u8]) -> Result<Vec<MatchResult>> {
        let response_str = String::from_utf8_lossy(response);
        debug!(
            "Matching probe '{}' against response ({} bytes): {}",
            probe.name,
            response.len(),
            response_str
        );
        debug!(
            "Response bytes (hex): {:?}",
            response
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );

        let mut results = Vec::new();

        for rule in &probe.matches {
            debug!("Trying rule pattern: {}", rule.pattern);
            let regex = rule.compile_regex()?;
            if let Some(captures) = Self::try_match(&regex, response) {
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
    fn try_match(regex: &Regex, text: &[u8]) -> Option<HashMap<usize, Vec<u8>>> {
        // pcre2::bytes::Regex::captures() returns Result<Option<Captures>, Error>
        match regex.captures(text) {
            Ok(Some(captures)) => {
                let mut map = HashMap::new();

                // captures[0] is always the full match (group 0)
                // SAFETY: Group 0 always exists in a successful match
                map.insert(0, captures[0].to_vec());

                // Extract additional capture groups using pcre2 API
                // Call captures_read once to populate all capture locations
                let mut locs = regex.capture_locations();
                if let Ok(Some(_)) = regex.captures_read(&mut locs, text) {
                    // Iterate through first 10 capture groups (most nmap patterns have < 5)
                    for i in 1..=10 {
                        if let Some((start, end)) = locs.get(i) {
                            map.insert(i, text[start..end].to_vec());
                        }
                    }
                }
                Some(map)
            }
            Ok(None) => None,
            Err(e) => {
                debug!("Regex error: {}", e);
                None
            }
        }
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
        let _detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH-([\d.]+)-(.*)").unwrap();

        let text = b"SSH-8.4-p1";
        let captures = ServiceDetector::try_match(&regex, text).unwrap();

        assert_eq!(captures.get(&0), Some(&b"SSH-8.4-p1".to_vec())); // Full match
        assert_eq!(captures.get(&1), Some(&b"8.4".to_vec()));
        assert_eq!(captures.get(&2), Some(&b"p1".to_vec()));
    }

    #[test]
    fn test_try_match_no_match() {
        let _detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH-([\d.]+)").unwrap();

        let text = b"HTTP/1.1 200 OK";
        let result = ServiceDetector::try_match(&regex, text);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_match_empty_captures() {
        let _detector = ServiceDetector::new(ProbeDatabase::empty());
        // Regex with optional group that doesn't match
        let regex = Regex::new(r"SSH(-[\d.]+)?").unwrap();

        let text = b"SSH";
        let captures = ServiceDetector::try_match(&regex, text).unwrap();
        assert_eq!(captures.get(&0), Some(&b"SSH".to_vec()));
        // Group 1 doesn't exist in the map because optional part didn't match
        // This is expected behavior for pcre2
        assert_eq!(captures.get(&1), None);
    }

    #[test]
    fn test_try_match_with_optional_group_present() {
        let _detector = ServiceDetector::new(ProbeDatabase::empty());
        let regex = Regex::new(r"SSH(-[\d.]+)?").unwrap();

        let text = b"SSH-2.0";
        let captures = ServiceDetector::try_match(&regex, text).unwrap();
        assert_eq!(captures.get(&0), Some(&b"SSH-2.0".to_vec()));
        assert_eq!(captures.get(&1), Some(&b"-2.0".to_vec()));
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
        let probes = detector.select_probes(80, "tcp");
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
        let probes = detector.select_probes(80, "tcp");
        assert_eq!(probes.len(), 2); // Common and Uncommon
        assert!(probes.iter().all(|p| p.rarity <= 5));

        // Test with intensity 9 (max rarity 9)
        let detector = ServiceDetector::new(db).with_intensity(9);
        let probes = detector.select_probes(80, "tcp");
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
        let probes = detector.select_probes(80, "tcp");

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
        let probes = detector.select_probes(80, "tcp");

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

    #[test]
    fn test_negative_lookahead_pattern() {
        // This test verifies that pcre2 correctly handles negative lookahead (?!\r\n)
        // which was the root cause of service detection not working with fancy-regex
        let _detector = ServiceDetector::new(ProbeDatabase::empty());

        // Pattern with negative lookahead: match HTTP headers but stop at empty line
        let regex = Regex::new(r"(?s)^HTTP/1\.[01] (?:[^\r\n]*\r\n(?!\r\n))*?Host:").unwrap();

        // Response with Host header before empty line - should match
        let response1 = b"HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n";
        assert!(
            regex.is_match(response1).unwrap(),
            "Should match HTTP response with Host header"
        );

        // Response without Host header, empty line immediately - should not match
        let response2 = b"HTTP/1.1 200 OK\r\n\r\n";
        assert!(
            !regex.is_match(response2).unwrap(),
            "Should not match response without Host header"
        );

        // Response with other headers before empty line - should not match (no Host)
        let response3 = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        assert!(
            !regex.is_match(response3).unwrap(),
            "Should not match response without Host header"
        );
    }
}
