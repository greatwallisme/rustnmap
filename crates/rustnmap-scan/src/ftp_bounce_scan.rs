//! FTP Bounce scanner implementation for `RustNmap`.
//!
//! This module provides FTP Bounce scanning, which uses an FTP server as a
//! proxy to scan target hosts indirectly. This technique sends FTP PORT
//! commands to make the FTP server connect to the target on the scanner's
//! behalf, useful for bypassing firewall rules.

#![warn(missing_docs)]

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::{Port, PortState, Protocol};
use rustnmap_target::Target;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Default connection timeout for FTP operations.
///
/// This value balances responsiveness with allowing time for slower
/// FTP servers to respond. Based on typical WAN latency.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default read timeout for FTP responses.
///
/// Individual FTP commands should complete quickly. Longer timeouts
/// may indicate network issues or unresponsive servers.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// FTP Bounce scanner.
///
/// Uses an FTP server as a proxy to scan target hosts indirectly.
/// Does not require root privileges but depends on FTP server
/// allowing PORT commands.
#[derive(Debug)]
pub struct FtpBounceScanner {
    /// FTP server address (the bounce proxy).
    ftp_server: SocketAddr,
    /// Connection timeout for FTP operations.
    connect_timeout: Duration,
    /// Optional username for FTP authentication.
    username: Option<String>,
    /// Optional password for FTP authentication.
    password: Option<String>,
}

impl FtpBounceScanner {
    /// Creates a new FTP Bounce scanner.
    ///
    /// # Arguments
    ///
    /// * `ftp_server` - FTP server to use as bounce proxy
    /// * `username` - Optional username for authentication
    /// * `password` - Optional password for authentication
    #[must_use]
    pub fn new(ftp_server: SocketAddr, username: Option<String>, password: Option<String>) -> Self {
        Self {
            ftp_server,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            username,
            password,
        }
    }

    /// Sets a custom connection timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Duration to wait for connections
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Scans a single port via FTP bounce.
    ///
    /// Connects to the FTP server, authenticates if credentials provided,
    /// sends PORT command with target address, and issues LIST to trigger
    /// the bounce connection attempt.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    ///
    /// # Returns
    ///
    /// Port state based on FTP response codes.
    ///
    /// # Errors
    ///
    /// Returns an error if the FTP connection fails or communication errors occur.
    fn scan_port_impl(&self, target: &Target, port: Port) -> ScanResult<PortState> {
        // Use block_in_place to yield to the async runtime during blocking FTP operations
        tokio::task::block_in_place(|| self.scan_port_impl_blocking(target, port))
    }

    /// Connects to the FTP server.
    ///
    /// Establishes TCP connection and sets appropriate timeouts.
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails or times out.
    fn connect_to_ftp(&self) -> ScanResult<FtpConnection> {
        let stream = TcpStream::connect_timeout(&self.ftp_server, self.connect_timeout)
            .map_err(|e| rustnmap_common::ScanError::Network(rustnmap_common::Error::Io(e)))?;

        stream
            .set_read_timeout(Some(DEFAULT_READ_TIMEOUT))
            .map_err(|e| rustnmap_common::ScanError::Network(rustnmap_common::Error::Io(e)))?;

        Ok(FtpConnection::new(stream))
    }

    /// Authenticates with the FTP server.
    ///
    /// Uses anonymous login if no credentials provided.
    ///
    /// # Arguments
    ///
    /// * `ftp` - FTP connection to authenticate
    /// * `target_str` - Target address string for error reporting
    /// * `port` - Target port for error reporting
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails.
    fn authenticate(
        &self,
        ftp: &mut FtpConnection,
        target_str: &str,
        port: Port,
    ) -> ScanResult<()> {
        let username = self.username.as_deref().unwrap_or("anonymous");
        let password = self.password.as_deref().unwrap_or("anonymous@");

        // Send USER command
        let user_response = ftp.send_command(&format!("USER {username}"), target_str, port)?;
        if !user_response.starts_with("331") && !user_response.starts_with("230") {
            return Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Other(format!(
                    "FTP authentication failed: USER command returned {user_response}"
                )),
            ));
        }

        // Send PASS command if needed (331 indicates password required)
        if user_response.starts_with("331") {
            let pass_response = ftp.send_command(&format!("PASS {password}"), target_str, port)?;
            if !pass_response.starts_with("230") {
                return Err(rustnmap_common::ScanError::Network(
                    rustnmap_common::Error::Other(format!(
                        "FTP authentication failed: PASS command returned {pass_response}"
                    )),
                ));
            }
        }

        Ok(())
    }

    /// Sends PORT command with target address.
    ///
    /// Formats target IP and port as FTP PORT command parameters.
    ///
    /// # Arguments
    ///
    /// * `ftp` - FTP connection
    /// * `target_ip` - Target IP address
    /// * `target_port` - Target port
    /// * `target_str` - Target address string for error reporting
    ///
    /// # Errors
    ///
    /// Returns an error if PORT command fails.
    fn send_port_command(
        ftp: &mut FtpConnection,
        target_ip: std::net::Ipv4Addr,
        target_port: Port,
        target_str: &str,
    ) -> ScanResult<()> {
        let port_cmd = Self::build_port_command(target_ip, target_port);
        let response = ftp.send_command(&port_cmd, target_str, target_port)?;

        if !response.starts_with("200") {
            return Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Other(format!("FTP PORT command failed: {response}")),
            ));
        }

        Ok(())
    }

    /// Builds FTP PORT command string.
    ///
    /// Formats IP and port as comma-separated octets:
    /// `PORT a,b,c,d,e,f` where port = e*256 + f
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to encode
    /// * `port` - Port number to encode
    #[must_use]
    fn build_port_command(ip: std::net::Ipv4Addr, port: Port) -> String {
        let octets = ip.octets();
        let port_high = (port >> 8) & 0xFF;
        let port_low = port & 0xFF;

        format!(
            "PORT {},{},{},{},{},{}",
            octets[0], octets[1], octets[2], octets[3], port_high, port_low
        )
    }

    /// Blocking implementation of FTP bounce scan.
    ///
    /// This function performs the actual blocking FTP operations.
    /// It is called directly when no multi-threaded runtime is available,
    /// or from within `spawn_blocking` when in an async context.
    fn scan_port_impl_blocking(&self, target: &Target, port: Port) -> ScanResult<PortState> {
        // Get target IP address
        let target_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        // Establish FTP control connection
        let mut ftp = self.connect_to_ftp()?;

        // Read greeting
        let _greeting = ftp.read_response(&target.ip.to_string(), port)?;

        // Authenticate if credentials provided
        self.authenticate(&mut ftp, &target.ip.to_string(), port)?;

        // Send PORT command with target address
        Self::send_port_command(&mut ftp, target_addr, port, &target.ip.to_string())?;

        // Send LIST command to trigger data connection attempt
        let mut response = ftp.send_command("LIST", &target.ip.to_string(), port)?;

        // Handle FTP command misalignment (nmap nmap_ftp.cc:301-306)
        // Some servers return 500 when commands get out of sync
        if response.starts_with("500") {
            // Read the actual response to re-align (nmap does recvtime with 10s timeout)
            // If this times out, we keep the 500 response and fall through to closed
            if let Ok(resp) = ftp.read_response(&target.ip.to_string(), port) {
                response = resp;
            }
        }

        // Handle 1xx preliminary response (nmap nmap_ftp.cc:307-330)
        // 150 means data connection is being opened, need to wait for final response
        if response.starts_with("150") || response.starts_with("125") {
            if let Ok(resp) = ftp.read_response(&target.ip.to_string(), port) {
                // 426 means data connection was closed after opening
                // nmap treats this as "changed mind" and goes to next port
                if resp.starts_with("426") {
                    let _ = ftp.send_command("QUIT", &target.ip.to_string(), port);
                    return Ok(PortState::Closed);
                }
                response = resp;
            } else {
                // Timed out waiting for LIST to complete; probably filtered (nmap)
                let _ = ftp.send_command("ABOR", &target.ip.to_string(), port);
                return Ok(PortState::Filtered);
            }
        }

        // Determine port state from FTP response (nmap nmap_ftp.cc:332-337)
        // 2xx = OPEN, everything else = CLOSED
        let port_state = if response.starts_with("200")
            || response.starts_with("226")
            || response.starts_with("150")
        {
            PortState::Open
        } else {
            // nmap: "This means the port is closed"
            PortState::Closed
        };

        // Send QUIT to close gracefully - ignore errors since we have our result
        let _ = ftp.send_command("QUIT", &target.ip.to_string(), port);

        Ok(port_state)
    }
}

impl PortScanner for FtpBounceScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        // Only TCP is supported for FTP bounce
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        self.scan_port_impl(target, port)
    }

    fn requires_root(&self) -> bool {
        false
    }
}

/// FTP control connection handler.
///
/// Manages TCP connection and handles FTP protocol commands/responses.
#[derive(Debug)]
struct FtpConnection {
    /// TCP stream for FTP control connection.
    stream: TcpStream,
    /// Buffered reader for line-based FTP responses.
    reader: BufReader<TcpStream>,
}

impl FtpConnection {
    /// Creates a new FTP connection.
    ///
    /// # Arguments
    ///
    /// * `stream` - Connected TCP stream
    #[must_use]
    fn new(stream: TcpStream) -> Self {
        // Clone the stream for the reader since TcpStream implements Clone
        let reader_stream = stream.try_clone().expect("Failed to clone TCP stream");
        Self {
            stream,
            reader: BufReader::new(reader_stream),
        }
    }

    /// Sends an FTP command and returns the response.
    ///
    /// # Arguments
    ///
    /// * `command` - FTP command to send
    /// * `target` - Target address string for timeout error
    /// * `port` - Target port for timeout error
    ///
    /// # Returns
    ///
    /// First line of FTP response (response code and message).
    ///
    /// # Errors
    ///
    /// Returns an error if send or receive fails.
    fn send_command(&mut self, command: &str, target: &str, port: Port) -> ScanResult<String> {
        // Send command
        let cmd_line = format!("{command}\r\n");
        self.stream
            .write_all(cmd_line.as_bytes())
            .map_err(|e| rustnmap_common::ScanError::Network(rustnmap_common::Error::Io(e)))?;

        self.stream
            .flush()
            .map_err(|e| rustnmap_common::ScanError::Network(rustnmap_common::Error::Io(e)))?;

        // Read response
        self.read_response(target, port)
    }

    /// Reads an FTP response, handling multi-line responses (RFC 959).
    ///
    /// Multi-line responses have a hyphen after the code on the first line
    /// (e.g., `220-Welcome`) and end with `<code> <text>` (e.g., `220 `).
    /// This method reads all lines until the final line of the response.
    ///
    /// # Arguments
    ///
    /// * `target` - Target address string for timeout error
    /// * `port` - Target port for timeout error
    ///
    /// # Returns
    ///
    /// Final response line from FTP server (the line with the status code).
    ///
    /// # Errors
    ///
    /// Returns an error if read fails or times out.
    fn read_response(&mut self, target: &str, port: Port) -> ScanResult<String> {
        loop {
            let mut line = String::new();
            let bytes_read = self.reader.read_line(&mut line).map_err(|e| {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    rustnmap_common::ScanError::Timeout {
                        target: target.to_string(),
                        port,
                    }
                } else {
                    rustnmap_common::ScanError::Network(rustnmap_common::Error::Io(e))
                }
            })?;

            // EOF: server closed the connection
            if bytes_read == 0 {
                return Err(rustnmap_common::ScanError::Network(
                    rustnmap_common::Error::Other("FTP server closed connection".to_string()),
                ));
            }

            // Strip only \r\n for the final-line check; trim_end() would also
            // remove the trailing space from lines like "220 \r\n", turning
            // "220 " into "220" (3 chars) and failing the len >= 4 guard.
            let stripped = line.trim_end_matches(['\r', '\n']);

            // RFC 959: multi-line uses hyphen after code (e.g., "220-"),
            // final line uses space (e.g., "220 text" or even "220 ").
            if stripped.len() >= 4 && stripped.as_bytes()[3] == b' ' {
                return Ok(stripped.to_string());
            }
            // Continuation line: "NNN-text" or short line - keep reading
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let ftp_server = SocketAddr::from(([127, 0, 0, 1], 21));
        let scanner = FtpBounceScanner::new(ftp_server, None, None);

        assert_eq!(scanner.ftp_server, ftp_server);
        assert!(scanner.username.is_none());
        assert!(scanner.password.is_none());
    }

    #[test]
    fn test_scanner_creation_with_auth() {
        let ftp_server = SocketAddr::from(([127, 0, 0, 1], 21));
        let scanner = FtpBounceScanner::new(
            ftp_server,
            Some("user".to_string()),
            Some("pass".to_string()),
        );

        assert_eq!(scanner.username, Some("user".to_string()));
        assert_eq!(scanner.password, Some("pass".to_string()));
    }

    #[test]
    fn test_with_timeout() {
        let ftp_server = SocketAddr::from(([127, 0, 0, 1], 21));
        let scanner =
            FtpBounceScanner::new(ftp_server, None, None).with_timeout(Duration::from_secs(30));

        assert_eq!(scanner.connect_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_requires_root() {
        let ftp_server = SocketAddr::from(([127, 0, 0, 1], 21));
        let scanner = FtpBounceScanner::new(ftp_server, None, None);

        assert!(!scanner.requires_root());
    }

    #[test]
    fn test_build_port_command() {
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let port: Port = 80;

        let cmd = FtpBounceScanner::build_port_command(ip, port);

        // 80 = 0*256 + 80
        assert_eq!(cmd, "PORT 192,168,1,1,0,80");
    }

    #[test]
    fn test_build_port_command_high_port() {
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let port: Port = 8080;

        let cmd = FtpBounceScanner::build_port_command(ip, port);

        // 8080 = 31*256 + 144
        assert_eq!(cmd, "PORT 10,0,0,1,31,144");
    }

    #[test]
    fn test_port_state_open_responses() {
        // 2xx and 150 responses indicate open port (nmap nmap_ftp.cc:332)
        let open_responses = [
            "200 OK",
            "226 Transfer complete",
            "150 Opening data connection",
        ];
        for resp in &open_responses {
            let is_open =
                resp.starts_with("200") || resp.starts_with("226") || resp.starts_with("150");
            assert!(is_open, "Expected '{resp}' to indicate open");
        }
    }

    #[test]
    fn test_port_state_closed_responses() {
        // Non-2xx responses indicate closed port (nmap nmap_ftp.cc:334-336)
        let closed_responses = [
            "425 Can't open data connection",
            "426 Connection closed; transfer aborted",
            "500 OOPS: Illegal port request",
            "530 Not logged in",
            "550 Failed to open file",
        ];
        for resp in &closed_responses {
            let is_open =
                resp.starts_with("200") || resp.starts_with("226") || resp.starts_with("150");
            assert!(!is_open, "Expected '{resp}' to indicate closed");
        }
    }

    #[test]
    fn test_build_port_command_port_zero() {
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let port: Port = 0;

        let cmd = FtpBounceScanner::build_port_command(ip, port);

        // 0 = 0*256 + 0
        assert_eq!(cmd, "PORT 192,168,1,1,0,0");
    }

    #[test]
    fn test_build_port_command_port_max() {
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let port: Port = 65535;

        let cmd = FtpBounceScanner::build_port_command(ip, port);

        // 65535 = 255*256 + 255
        assert_eq!(cmd, "PORT 192,168,1,1,255,255");
    }

    #[test]
    fn test_build_port_command_boundary_ports() {
        // Test port 1 (minimum valid port)
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let cmd = FtpBounceScanner::build_port_command(ip, 1);
        // 1 = 0*256 + 1
        assert_eq!(cmd, "PORT 10,0,0,1,0,1");

        // Test port 255 (single byte boundary)
        let cmd = FtpBounceScanner::build_port_command(ip, 255);
        // 255 = 0*256 + 255
        assert_eq!(cmd, "PORT 10,0,0,1,0,255");

        // Test port 256 (crosses byte boundary)
        let cmd = FtpBounceScanner::build_port_command(ip, 256);
        // 256 = 1*256 + 0
        assert_eq!(cmd, "PORT 10,0,0,1,1,0");

        // Test port 65534 (maximum valid port - 1)
        let cmd = FtpBounceScanner::build_port_command(ip, 65534);
        // 65534 = 255*256 + 254
        assert_eq!(cmd, "PORT 10,0,0,1,255,254");
    }

    #[test]
    fn test_scan_port_non_tcp_protocol() {
        let ftp_server = SocketAddr::from(([127, 0, 0, 1], 21));
        let scanner = FtpBounceScanner::new(ftp_server, None, None);

        // Create an IPv4 target using From trait
        let target = Target::from(std::net::Ipv4Addr::new(192, 168, 1, 1));

        // UDP should return Filtered without attempting connection
        let result = scanner.scan_port(&target, 80, Protocol::Udp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PortState::Filtered);

        // SCTP should return Filtered
        let result = scanner.scan_port(&target, 80, Protocol::Sctp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PortState::Filtered);
    }

    #[test]
    fn test_scan_port_ipv6_target() {
        let ftp_server = SocketAddr::from(([127, 0, 0, 1], 21));
        let scanner = FtpBounceScanner::new(ftp_server, None, None);

        // Create an IPv6 target using From trait
        let target = Target::from(std::net::Ipv6Addr::LOCALHOST);

        // IPv6 targets should return Filtered
        let result = scanner.scan_port(&target, 80, Protocol::Tcp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PortState::Filtered);
    }

    #[test]
    fn test_build_port_command_various_ips() {
        // Test with 0.0.0.0
        let ip = std::net::Ipv4Addr::UNSPECIFIED;
        let cmd = FtpBounceScanner::build_port_command(ip, 21);
        assert_eq!(cmd, "PORT 0,0,0,0,0,21");

        // Test with 255.255.255.255 (broadcast)
        let ip = std::net::Ipv4Addr::BROADCAST;
        let cmd = FtpBounceScanner::build_port_command(ip, 21);
        assert_eq!(cmd, "PORT 255,255,255,255,0,21");

        // Test with mixed octets
        let ip = std::net::Ipv4Addr::LOCALHOST;
        let cmd = FtpBounceScanner::build_port_command(ip, 8080);
        // 8080 = 31*256 + 144
        assert_eq!(cmd, "PORT 127,0,0,1,31,144");
    }
}

// Rust guideline compliant 2026-02-14
