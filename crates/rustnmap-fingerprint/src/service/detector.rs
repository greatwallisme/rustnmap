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
use tokio_rustls::{client::TlsStream, rustls, TlsConnector};
use tracing::{debug, info, trace};

use super::{
    database::ProbeDatabase,
    probe::{MatchResult, ProbeDefinition, Protocol},
};
use crate::{FingerprintError, Result};

/// Maximum time to wait for banner data during NULL probe (banner grab).
///
/// For non-banner services (HTTP, etc.) the server never sends unsolicited data,
/// so the read would block until timeout. Without this cap the banner grab
/// consumes the entire 5-second probe budget, leaving zero time for actual
/// probes like GetRequest -- which is the probe that detects HTTP versions.
///
/// Banner services (SSH, FTP, SMTP) send data within milliseconds of connect,
/// so 2 seconds is more than sufficient even with high-latency links.
const BANNER_READ_TIMEOUT_CAP: Duration = Duration::from_secs(2);

/// Maximum time to wait for a single probe response.
///
/// Without this cap, a probe like X11Probe (which receives no response from HTTP
/// servers) can consume the entire remaining budget, preventing later probes like
/// FourOhFourRequest from ever running.  nmap uses per-probe timeouts (~5s each)
/// rather than a shared budget; capping at 1.5s preserves budget fairness while
/// still allowing ample time for typical service responses.
const PROBE_READ_TIMEOUT_CAP: Duration = Duration::from_millis(1500);

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
        self.detect_service_inner(target, port, protocol, false)
            .await
    }

    /// Core service detection with optional SSL tunnel support.
    ///
    /// Implements nmap's two-pass detection model:
    /// 1. Plain TCP pass: banner grab + probes (excludes sslports-only probes)
    /// 2. If service detected as "ssl" and port matches sslports, establish TLS
    ///    and re-run probes inside the encrypted tunnel
    async fn detect_service_inner(
        &self,
        target: &SocketAddr,
        port: u16,
        protocol: &str,
        in_ssl_tunnel: bool,
    ) -> Result<Vec<ServiceInfo>> {
        info!(
            "Starting service detection on {}:{} ({}) tunnel={}",
            target.ip(),
            port,
            protocol,
            if in_ssl_tunnel { "ssl" } else { "none" }
        );
        let is_udp = protocol.eq_ignore_ascii_case("udp");

        // nmap's DEFAULT_SERVICEWAITMS = 5000ms: total time budget for ALL probes.
        let total_budget = self.default_timeout;
        let start = Instant::now();
        let mut results = Vec::new();

        // Track TCP connection for reuse after banner grab (nmap optimization)
        let mut reusable_stream: Option<tokio::net::TcpStream> = None;

        // --- Phase 1: Banner grab (NULL probe) ---

        // Banner grabbing only works for TCP (services that send banners on connect).
        // UDP services never send unsolicited data, so skip banner grab entirely.
        // For known SSL ports (443, 993, 995, ...), skip banner grab completely.
        // Opening a plain TCP connection on an SSL-only port wastes time AND the
        // server may reject subsequent TLS connections after the plain connection
        // closes (connection reset). nmap also skips the NULL probe on SSL ports.
        let is_known_ssl = !is_udp && !in_ssl_tunnel && self.is_probable_ssl_port(port);

        if !is_udp && !is_known_ssl {
            let remaining = total_budget.saturating_sub(start.elapsed());
            if !remaining.is_zero() {
                match self
                    .grab_banner_and_keep_stream(target, port, remaining)
                    .await
                {
                    Ok((banner_opt, stream_opt, closed_after_ms)) => {
                        reusable_stream = stream_opt;

                        if let Some(banner) = banner_opt {
                            trace!("Got banner: {} bytes", banner.len());

                            // Try to match banner against all probe rules
                            let probes = self.select_probes(port, protocol);
                            for probe in &probes {
                                let matches =
                                    Self::match_response_with_fallback(&self.db, probe, &banner)?;
                                for match_result in matches {
                                    results.push(ServiceInfo::from_match(match_result));
                                }
                            }

                            // If we got confident results from banner, return early
                            if results.iter().any(|r| r.confidence >= 8) {
                                return Ok(results);
                            }
                        } else {
                            // No banner received — check for tcpwrapped.
                            // Nmap: if the connection closes before tcpwrappedms (default 3000ms)
                            // with no data, the service is classified as "tcpwrapped".
                            let tcpwrappedms = self.get_tcpwrappedms();
                            if closed_after_ms < tcpwrappedms {
                                debug!(
                                    "tcpwrapped detected: connection closed after {}ms (threshold {}ms)",
                                    closed_after_ms, tcpwrappedms
                                );
                                let info = ServiceInfo::new("tcpwrapped").with_confidence(8);
                                results.push(info);
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

        // --- Phase 2: Active probes ---

        // For known SSL ports, skip the plain-text probe phase entirely.
        // Rationale: plain probes on SSL-only ports (443, 993, 995) never match
        // HTTP/SMTP/etc. services -- they waste time and open TCP connections that
        // can cause the subsequent TLS handshake to be rejected (connection reset).
        // nmap's behavior is equivalent: on ssl-only ports it goes straight to TLS.
        let skip_plain_probes = is_known_ssl && !in_ssl_tunnel;

        // Select probes for this port, excluding NULL (already handled by banner grab).
        // In SSL tunnel pass, prefer probes that list this port in sslports.
        let probes = if skip_plain_probes {
            debug!(
                "Skipping plain probes for port {} (known SSL port, no banner), going straight to TLS",
                port
            );
            Vec::new()
        } else {
            let mut probes = self.select_probes_for_pass(port, protocol, in_ssl_tunnel);
            probes.retain(|p| p.name != "NULL");
            probes
        };
        debug!(
            "Selected {} probes for port {} (ssl={})",
            probes.len(),
            port,
            in_ssl_tunnel
        );

        if probes.is_empty() && !skip_plain_probes {
            debug!("No probes available for port {}", port);
            if results.is_empty() {
                return Ok(vec![ServiceInfo::new("unknown")]);
            }
            return Ok(results);
        }

        // For probable SSL ports not yet in an SSL tunnel, reserve part of the budget
        // for SSL tunnel detection. Without this reservation, the probe loop consumes
        // the entire budget and the SSL tunnel phase is never reached (needs >500ms).
        // This fixes detection on ports like 443 (https) and 995 (pop3s).
        let needs_ssl_reserve = !is_udp
            && !in_ssl_tunnel
            && self.is_probable_ssl_port(port)
            && !results.iter().any(|r| r.name == "ssl");
        let probe_budget = if needs_ssl_reserve {
            // Reserve 2500ms for SSL tunnel phase (handshake + banner + probes).
            // The TLS handshake alone needs ~2 RTTs; with a 300ms RTT that's 600ms,
            // plus time for banner read and probe responses inside the tunnel.
            let reserve = Duration::from_millis(2500);
            let remaining = total_budget.saturating_sub(start.elapsed());
            let capped = remaining.saturating_sub(reserve);
            debug!(
                "Reserving {}ms for SSL tunnel on port {} (probe budget: {}ms)",
                reserve.as_millis(),
                port,
                capped.as_millis()
            );
            Some(start + capped)
        } else {
            None
        };

        // Execute probes in order, sharing the remaining time budget.
        // Reuse TCP connection from banner grab for first probe (nmap optimization).
        for probe in &probes {
            let probe_deadline = probe_budget.unwrap_or(start + total_budget);
            let remaining = probe_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if probe_budget.is_some() {
                    debug!(
                        "Probe budget exhausted (SSL reserve), stopping probes for port {}",
                        port
                    );
                } else {
                    debug!("Time budget exhausted, stopping probes for port {}", port);
                }
                break;
            }

            debug!(
                "Sending probe '{}' to port {} ({}ms remaining)",
                probe.name,
                port,
                remaining.as_millis()
            );

            // Cap per-probe timeout so one slow probe doesn't starve the rest.
            let probe_timeout = remaining.min(PROBE_READ_TIMEOUT_CAP);

            // Try to reuse existing connection for first probe, then open new ones
            let response = if let Some(stream) = reusable_stream.take() {
                self.send_probe_on_existing_stream(stream, probe, probe_timeout)
                    .await
            } else {
                self.send_probe_with_timeout(target, port, probe, probe_timeout)
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

                    let matches = Self::match_response_with_fallback(&self.db, probe, &response)?;

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

        // --- Phase 3: SSL tunnel pass (nmap two-pass model) ---
        //
        // If the plain TCP pass detected "ssl" (or we got no confident match and
        // this port is a known SSL port), establish TLS and re-run probes inside
        // the encrypted tunnel. This matches nmap's scanThroughTunnel() logic.
        if !is_udp && !in_ssl_tunnel {
            let needs_ssl = results.iter().any(|r| r.name == "ssl")
                || (results.iter().all(|r| r.confidence < 8) && self.is_probable_ssl_port(port));

            if needs_ssl {
                let remaining = total_budget.saturating_sub(start.elapsed());
                if !remaining.is_zero() {
                    debug!("Attempting SSL tunnel detection on port {}", port);
                    match self
                        .detect_through_ssl_tunnel(target, port, remaining)
                        .await
                    {
                        Ok(ssl_results) if !ssl_results.is_empty() => {
                            // Prefix service names with "ssl/" and return
                            let prefixed: Vec<ServiceInfo> = ssl_results
                                .into_iter()
                                .map(|mut r| {
                                    if !r.name.starts_with("ssl/")
                                        && r.name != "ssl"
                                        && r.name != "unknown"
                                    {
                                        r.name = format!("ssl/{}", r.name);
                                    }
                                    r
                                })
                                .collect();
                            if prefixed
                                .iter()
                                .any(|r| r.name != "ssl" && r.name != "unknown")
                            {
                                return Ok(prefixed);
                            }
                        }
                        Ok(_) => {
                            debug!("SSL tunnel detection returned no results");
                        }
                        Err(e) => {
                            debug!("SSL tunnel detection failed: {}", e);
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Detect service through an SSL/TLS tunnel.
    ///
    /// Establishes a TLS connection, then sends probes and matches responses
    /// inside the encrypted tunnel. Matches nmap's scanThroughTunnel() behavior.
    async fn detect_through_ssl_tunnel(
        &self,
        target: &SocketAddr,
        port: u16,
        budget: Duration,
    ) -> Result<Vec<ServiceInfo>> {
        let start = Instant::now();

        // Connect and perform TLS handshake
        let tls_stream = self.establish_tls_connection(target, port, budget).await?;
        let mut stream = match tls_stream {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        debug!(
            "TLS tunnel established to {}:{} ({}ms remaining)",
            target.ip(),
            port,
            budget.saturating_sub(start.elapsed()).as_millis()
        );

        // Try reading a banner through the TLS tunnel (some services send
        // banners immediately after TLS handshake, e.g., SMTPS, POP3S).
        // Use a tight cap (500ms) -- unlike the plain TCP pass where 2s is
        // reasonable, inside a TLS tunnel the budget is already reduced and
        // HTTP servers never send unsolicited data, so every millisecond counts.
        let mut results = Vec::new();
        let remaining = budget.saturating_sub(start.elapsed());
        let tls_banner_cap = Duration::from_millis(500);

        let mut banner_buffer = vec![0u8; 4096];
        let banner_opt = if !remaining.is_zero() {
            match timeout(
                remaining.min(tls_banner_cap),
                stream.read(&mut banner_buffer),
            )
            .await
            {
                Ok(Ok(0)) => None,
                Ok(Ok(n)) => {
                    banner_buffer.truncate(n);
                    debug!("Got {} bytes TLS banner on port {}", n, port);
                    Some(banner_buffer)
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(ref banner) = banner_opt {
            // Match banner against all probe rules
            let probes = self.select_probes(port, "tcp");
            for probe in &probes {
                let matches = Self::match_response_with_fallback(&self.db, probe, banner)?;
                for match_result in matches {
                    results.push(ServiceInfo::from_match(match_result));
                }
            }
            if results.iter().any(|r| r.confidence >= 8) {
                return Ok(results);
            }
        }

        // Select probes that have this port in their sslports list
        let mut probes = self.select_probes_for_pass(port, "tcp", true);
        probes.retain(|p| p.name != "NULL");
        debug!(
            "TLS tunnel: {} probes selected for port {} (budget remaining: {}ms)",
            probes.len(),
            port,
            budget.saturating_sub(start.elapsed()).as_millis()
        );

        // Execute probes inside the TLS tunnel
        for probe in &probes {
            let remaining = budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                debug!(
                    "TLS tunnel budget exhausted on port {} after probe '{}'",
                    port, probe.name
                );
                break;
            }

            debug!(
                "TLS tunnel: sending probe '{}' on port {} ({}ms remaining)",
                probe.name,
                port,
                remaining.as_millis()
            );

            let response = self
                .send_probe_on_tls_stream(&mut stream, probe, remaining)
                .await;

            match &response {
                Ok(Some(data)) => {
                    debug!(
                        "TLS tunnel: got {} bytes from probe '{}' on port {}",
                        data.len(),
                        probe.name,
                        port
                    );
                }
                Ok(None) => {
                    debug!(
                        "TLS tunnel: no response from probe '{}' on port {}",
                        probe.name, port
                    );
                }
                Err(e) => {
                    debug!(
                        "TLS tunnel: probe '{}' failed on port {}: {}",
                        probe.name, port, e
                    );
                }
            }

            if let Ok(Some(response)) = response {
                let matches = Self::match_response_with_fallback(&self.db, probe, &response)?;
                debug!(
                    "TLS tunnel: {} matches from probe '{}' on port {}",
                    matches.len(),
                    probe.name,
                    port
                );
                for match_result in matches {
                    debug!(
                        "TLS tunnel: match service='{}' confidence={}",
                        match_result.service, match_result.confidence
                    );
                    results.push(ServiceInfo::from_match(match_result));
                }
                if results.iter().any(|r| r.confidence >= 8) {
                    break;
                }
            }
        }

        Ok(results)
    }

    /// Establish a TLS connection to the target.
    ///
    /// Performs TCP connect + TLS handshake. Returns None if handshake fails
    /// (not a TLS service). Retries once on connection reset, which can happen
    /// when a previous banner-grab connection hasn't fully closed yet.
    async fn establish_tls_connection(
        &self,
        target: &SocketAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<Option<TlsStream<TcpStream>>> {
        // Try up to 2 attempts. The first may fail with RST if a previous
        // connection to the same port (banner grab) is still closing.
        for attempt in 0..2 {
            let attempt_budget = if attempt == 0 {
                timeout_duration
            } else {
                // Brief pause before retry to let the server-side socket close.
                tokio::time::sleep(Duration::from_millis(100)).await;
                timeout_duration.saturating_sub(Duration::from_millis(100))
            };

            if attempt_budget.is_zero() {
                return Ok(None);
            }

            // TCP connect
            let tcp_stream =
                match timeout(attempt_budget, TcpStream::connect((target.ip(), port))).await {
                    Ok(Ok(s)) => s,
                    _ => {
                        if attempt == 0 {
                            continue;
                        }
                        return Ok(None);
                    }
                };

            // Build TLS config (accept any certificate, like nmap's --version-intensity)
            // Install ring crypto provider (idempotent if already installed)
            let _ = rustls::crypto::ring::default_provider().install_default();
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));

            // Use IP as server name (we may not know the hostname)
            let server_name_str = target.ip().to_string();
            let server_name = rustls::pki_types::ServerName::try_from(server_name_str)
                .unwrap_or_else(|_| {
                    rustls::pki_types::ServerName::try_from("localhost".to_string())
                        .expect("localhost is valid")
                });

            let tls_remaining = attempt_budget.saturating_sub(Duration::from_millis(100));
            match timeout(tls_remaining, connector.connect(server_name, tcp_stream)).await {
                Ok(Ok(tls_stream)) => return Ok(Some(tls_stream)),
                Ok(Err(e)) => {
                    debug!("TLS handshake to {}:{} failed: {}", target.ip(), port, e);
                    if attempt == 0 {
                        continue;
                    }
                    return Ok(None);
                }
                Err(_) => {
                    debug!("TLS handshake to {}:{} timed out", target.ip(), port);
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    /// Send a probe on an existing TLS stream.
    async fn send_probe_on_tls_stream(
        &self,
        stream: &mut TlsStream<TcpStream>,
        probe: &ProbeDefinition,
        timeout_duration: Duration,
    ) -> Result<Option<Vec<u8>>> {
        stream
            .write_all(&probe.payload)
            .await
            .map_err(|e| FingerprintError::Network {
                operation: "write probe on TLS stream".to_string(),
                reason: e.to_string(),
            })?;

        let mut buffer = vec![0u8; 4096];
        let n = match timeout(timeout_duration, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => return Ok(None),
        };

        if n > 0 {
            buffer.truncate(n);
            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// Check if a port is commonly known as an SSL/TLS port.
    ///
    /// Used as a fallback when the plain TCP pass returns no results and we
    /// want to try SSL detection anyway.
    fn is_probable_ssl_port(&self, port: u16) -> bool {
        // Check ALL probes for sslports, not just port-matching ones.
        // A probe can have an SSL variant on a port even if the port isn't
        // in its `ports` list (e.g., GetRequest targets 80,443 but has
        // sslports 443,993,995,...). If any probe lists this port as an
        // SSL port, we should try SSL tunnel detection.
        self.db
            .all_probes()
            .iter()
            .any(|p| p.ssl_ports.contains(&port))
    }

    /// Select probes for a specific detection pass (plain or SSL tunnel).
    ///
    /// In plain pass: returns all probes matching the port.
    /// In SSL tunnel pass: prioritizes probes where port is in ssl_ports.
    fn select_probes_for_pass(
        &self,
        port: u16,
        protocol: &str,
        in_ssl_tunnel: bool,
    ) -> Vec<&ProbeDefinition> {
        let target_protocol = if protocol.eq_ignore_ascii_case("udp") {
            Protocol::Udp
        } else {
            Protocol::Tcp
        };

        let max_rarity = self.intensity_to_max_rarity();

        let mut probes: Vec<&ProbeDefinition> = if in_ssl_tunnel {
            // In SSL tunnel pass, include ALL probes that either match the port
            // directly OR have this port in their ssl_ports list.
            // nmap's scanThroughTunnel() runs probes whose sslports include
            // the target port -- e.g., GetRequest has sslports 443,993,995,..
            // so it runs inside a TLS tunnel on port 443 even though its ports
            // list doesn't include 443.
            self.db
                .all_probes()
                .into_iter()
                .filter(|p| {
                    p.protocol == target_protocol
                        && p.rarity <= max_rarity
                        && (p.ports.contains(&port)
                            || p.ports.is_empty()
                            || p.ssl_ports.contains(&port))
                })
                .collect()
        } else {
            let mut probes = self.db.probes_for_port(port);
            probes.retain(|p| p.protocol == target_protocol && p.rarity <= max_rarity);
            probes
        };

        if in_ssl_tunnel {
            // SSL-matching probes first, then by rarity, then by name
            probes.sort_by(|a, b| {
                let a_ssl = a.ssl_ports.contains(&port) as u8;
                let b_ssl = b.ssl_ports.contains(&port) as u8;
                b_ssl
                    .cmp(&a_ssl)
                    .then_with(|| a.rarity.cmp(&b.rarity))
                    .then_with(|| a.name.cmp(&b.name))
            });
        } else {
            // Plain pass: sort by rarity, then by name (standard ordering)
            probes.sort_by(|a, b| a.rarity.cmp(&b.rarity).then_with(|| a.name.cmp(&b.name)));
        }

        probes
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
    /// Grab banner while keeping the TCP stream for connection reuse.
    ///
    /// Returns (banner_option, stream_option, closed_after_ms).
    /// `closed_after_ms` tracks how long after connect the remote closed
    /// the connection (EOF), used for tcpwrapped detection.
    /// Matches nmap's optimization in service_scan.cc lines 2095-2105.
    async fn grab_banner_and_keep_stream(
        &self,
        target: &SocketAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<(Option<Vec<u8>>, Option<tokio::net::TcpStream>, u64)> {
        trace!(
            "Grabbing banner from {}:{} (timeout: {}ms)",
            target.ip(),
            port,
            timeout_duration.as_millis()
        );

        let connect_start = Instant::now();

        let stream = timeout(timeout_duration, TcpStream::connect((target.ip(), port)))
            .await
            .map_err(|_| FingerprintError::Timeout {
                address: target.ip().to_string(),
                port,
            })?;

        let mut stream = stream?;

        // Cap read timeout to avoid consuming entire probe budget.
        // Non-banner services (HTTP) never send unsolicited data, so without
        // this cap the read blocks until the full timeout, leaving no time for
        // actual probes like GetRequest that detect HTTP server versions.
        let elapsed_connect = connect_start.elapsed();
        let remaining_after_connect = timeout_duration.saturating_sub(elapsed_connect);
        let read_timeout = remaining_after_connect.min(BANNER_READ_TIMEOUT_CAP);

        let mut buffer = vec![0u8; 4096];
        let mut total_read = 0;
        let read_deadline = Instant::now() + read_timeout;
        let connect_time = connect_start;
        let mut eof_received = false;

        // Read in a loop to accumulate banner data that may arrive in
        // multiple TCP segments. After the first successful read, continue
        // reading with whatever time remains (at most BANNER_READ_TIMEOUT_CAP).
        // This handles services like FTP that send multi-line banners in
        // separate packets.
        loop {
            let now = Instant::now();
            let remaining = read_deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                break;
            }

            // After the first read, use a short follow-up timeout to avoid
            // blocking too long while waiting for additional segments.
            let followup_timeout = if total_read > 0 {
                remaining.min(Duration::from_millis(200))
            } else {
                remaining
            };

            match timeout(followup_timeout, stream.read(&mut buffer[total_read..])).await {
                Ok(Ok(0)) => {
                    // EOF / connection closed — track time for tcpwrapped detection
                    eof_received = true;
                    break;
                }
                Ok(Ok(n)) => {
                    total_read += n;
                    if total_read >= buffer.len() {
                        break; // Buffer full
                    }
                    // Continue reading to accumulate more data
                }
                Ok(Err(_)) => {
                    // Read error but connection may still be open
                    break;
                }
                Err(_) => {
                    // Timeout -- no more data arriving
                    break;
                }
            }
        }

        // Calculate ms from connect to EOF for tcpwrapped detection.
        // If the server closed the connection before tcpwrappedms and no banner
        // was received, this is characteristic of TCP wrappers / xinetd reject.
        let closed_after_ms = if eof_received {
            connect_time.elapsed().as_millis() as u64
        } else {
            u64::MAX
        };

        if total_read > 0 {
            buffer.truncate(total_read);
            trace!("Banner grabbed: {} bytes", total_read);
            Ok((Some(buffer), Some(stream), closed_after_ms))
        } else {
            // No data but connection was established
            Ok((None, Some(stream), closed_after_ms))
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
        let connect_start = Instant::now();
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

        // Subtract connect time from the read timeout so the total probe
        // time stays within the allocated budget.
        let read_timeout = timeout_duration.saturating_sub(connect_start.elapsed());
        let mut buffer = vec![0u8; 4096];
        let n = match timeout(read_timeout, stream.read(&mut buffer)).await {
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
    /// Returns the tcpwrappedms threshold from the NULL probe definition.
    /// Defaults to 3000ms (nmap's default) if not explicitly set.
    /// Returns the tcpwrappedms threshold from the NULL probe definition.
    /// Defaults to 3000ms (nmap's default) if not explicitly set.
    fn get_tcpwrappedms(&self) -> u64 {
        if let Some(null_probe) = self.db.get_probe("NULL") {
            if null_probe.tcpwrappedms > 0 {
                return null_probe.tcpwrappedms;
            }
        }
        // nmap default: 3000ms
        3000
    }

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

    /// Match response against probe rules, with fallback support.
    ///
    /// If the probe's own match rules produce no results and it has a `fallback`
    /// list (e.g. `fallback GetRequest`), the fallback probes' match rules are
    /// tried in order until a match is found.
    fn match_response_with_fallback(
        db: &ProbeDatabase,
        probe: &ProbeDefinition,
        response: &[u8],
    ) -> Result<Vec<MatchResult>> {
        let mut results = Self::match_probe_rules(probe, response)?;

        if results.is_empty() && !probe.fallback.is_empty() {
            for fallback_name in &probe.fallback {
                if let Some(fallback_probe) = db.get_probe(fallback_name) {
                    debug!(
                        "Trying fallback probe '{}' for '{}'",
                        fallback_name, probe.name
                    );
                    let fallback_results = Self::match_probe_rules(fallback_probe, response)?;
                    if !fallback_results.is_empty() {
                        debug!(
                            "Fallback '{}' matched with {} results",
                            fallback_name,
                            fallback_results.len()
                        );
                        results = fallback_results;
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    /// Match response against a single probe's own match rules.
    fn match_probe_rules(probe: &ProbeDefinition, response: &[u8]) -> Result<Vec<MatchResult>> {
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

/// Certificate verifier that accepts any certificate (insecure).
///
/// Service detection does not need to verify certificates - we just need
/// to complete the TLS handshake so we can send probes inside the tunnel.
/// This matches nmap's behavior which also does not verify certificates.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
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
        let results = ServiceDetector::match_probe_rules(&probe, response).unwrap();

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
        let results = ServiceDetector::match_probe_rules(&probe, response).unwrap();

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
        let results = ServiceDetector::match_probe_rules(&probe, response).unwrap();

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
        let results = ServiceDetector::match_probe_rules(&probe, b"SSH-2.0-OpenSSH").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "ssh");

        // Test HTTP match
        let results = ServiceDetector::match_probe_rules(&probe, b"HTTP/1.1 200 OK").unwrap();
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
        let result = ServiceDetector::match_probe_rules(&probe, response);

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
        let results = ServiceDetector::match_probe_rules(&probe, &response).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, "binary");
    }

    #[test]
    fn test_fallback_matching() {
        // Create a database with GetRequest probe that has match rules
        let content = r"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 3
ports 80,8080
match http m|^HTTP/1\.0 200 OK\r\n.*Server: Apache|s p/Apache httpd/

Probe TCP FourOhFourRequest q|GET /nonexistent HTTP/1.0\r\n\r\n|
rarity 6
ports 80-85
fallback GetRequest
match http m|^HTTP/1\.0 404 SpecialNotFound| p/SpecialServer/
";
        let db = ProbeDatabase::parse(content).unwrap();
        let fofr = db.get_probe("FourOhFourRequest").unwrap();

        // Response that matches GetRequest rules but NOT FourOhFourRequest rules
        let response = b"HTTP/1.0 200 OK\r\nServer: Apache/2.4\r\n\r\n<html>...</html>";

        // Direct match against FourOhFourRequest rules should fail
        let direct = ServiceDetector::match_probe_rules(fofr, response).unwrap();
        assert!(direct.is_empty());

        // With fallback, should find match via GetRequest rules
        let with_fallback =
            ServiceDetector::match_response_with_fallback(&db, fofr, response).unwrap();
        assert_eq!(with_fallback.len(), 1);
        assert_eq!(with_fallback[0].service, "http");
        assert_eq!(with_fallback[0].product, Some("Apache httpd".to_string()));
    }

    #[test]
    fn test_fallback_not_used_when_direct_match() {
        let content = r"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 3
match http m|^HTTP/1\.0 200| p/GetRequestProduct/

Probe TCP FourOhFourRequest q|GET /nonexistent HTTP/1.0\r\n\r\n|
rarity 6
fallback GetRequest
match http m|^HTTP/1\.0 404| p/FourOhFourProduct/
";
        let db = ProbeDatabase::parse(content).unwrap();
        let fofr = db.get_probe("FourOhFourRequest").unwrap();

        // Response that matches FourOhFourRequest's own rules
        let response = b"HTTP/1.0 404 Not Found";
        let results = ServiceDetector::match_response_with_fallback(&db, fofr, response).unwrap();
        assert_eq!(results.len(), 1);
        // Should use FourOhFour's own match, not the fallback
        assert_eq!(results[0].product, Some("FourOhFourProduct".to_string()));
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
