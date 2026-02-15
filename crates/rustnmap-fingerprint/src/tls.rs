//! TLS/SSL detection and certificate parsing.
//!
//! This module provides TLS version detection, cipher suite identification,
//! and X.509 certificate parsing for SSL/TLS services.

use std::{
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, rustls, TlsConnector};
use tracing::{debug, trace};
use x509_parser::prelude::*;

use crate::{FingerprintError, Result};

/// TLS detection results.
#[derive(Debug, Clone, PartialEq)]
pub struct TlsInfo {
    /// TLS version negotiated.
    pub version: TlsVersion,

    /// Cipher suite used.
    pub cipher_suite: String,

    /// Certificate information.
    pub certificate: Option<CertificateInfo>,

    /// Certificate chain depth.
    pub chain_depth: usize,

    /// ALPN protocol negotiated.
    pub alpn_protocol: Option<String>,

    /// Server name from SNI.
    pub server_name: Option<String>,

    /// Whether the certificate is self-signed.
    pub is_self_signed: bool,

    /// Whether the certificate is expired.
    pub is_expired: bool,

    /// Days until certificate expires.
    pub days_until_expiry: Option<i64>,
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// SSL 3.0
    Ssl3,

    /// TLS 1.0
    Tls1_0,

    /// TLS 1.1
    Tls1_1,

    /// TLS 1.2
    Tls1_2,

    /// TLS 1.3
    Tls1_3,

    /// Unknown version
    Unknown,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssl3 => write!(f, "SSLv3"),
            Self::Tls1_0 => write!(f, "TLSv1.0"),
            Self::Tls1_1 => write!(f, "TLSv1.1"),
            Self::Tls1_2 => write!(f, "TLSv1.2"),
            Self::Tls1_3 => write!(f, "TLSv1.3"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<rustls::ProtocolVersion> for TlsVersion {
    fn from(version: rustls::ProtocolVersion) -> Self {
        match version {
            rustls::ProtocolVersion::SSLv3 => Self::Ssl3,
            rustls::ProtocolVersion::TLSv1_0 => Self::Tls1_0,
            rustls::ProtocolVersion::TLSv1_1 => Self::Tls1_1,
            rustls::ProtocolVersion::TLSv1_2 => Self::Tls1_2,
            rustls::ProtocolVersion::TLSv1_3 => Self::Tls1_3,
            _ => Self::Unknown,
        }
    }
}

/// Certificate information extracted from X.509.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateInfo {
    /// Subject name (e.g., "CN=example.com").
    pub subject: String,

    /// Issuer name.
    pub issuer: String,

    /// Serial number as hex string.
    pub serial_number: String,

    /// Subject Alternative Names.
    pub subject_alt_names: Vec<String>,

    /// Not valid before timestamp.
    pub not_before: SystemTime,

    /// Not valid after timestamp.
    pub not_after: SystemTime,

    /// Signature algorithm.
    pub signature_algorithm: String,

    /// Key algorithm and size.
    pub public_key_info: String,

    /// Certificate fingerprints (SHA-256).
    pub fingerprint_sha256: String,
}

impl TlsInfo {
    /// Create empty TLS info.
    pub fn new() -> Self {
        Self {
            version: TlsVersion::Unknown,
            cipher_suite: String::new(),
            certificate: None,
            chain_depth: 0,
            alpn_protocol: None,
            server_name: None,
            is_self_signed: false,
            is_expired: false,
            days_until_expiry: None,
        }
    }

    /// Set TLS version.
    pub fn with_version(mut self, version: TlsVersion) -> Self {
        self.version = version;
        self
    }

    /// Set cipher suite.
    pub fn with_cipher_suite(mut self, cipher: impl Into<String>) -> Self {
        self.cipher_suite = cipher.into();
        self
    }

    /// Set certificate info.
    pub fn with_certificate(mut self, cert: CertificateInfo) -> Self {
        self.certificate = Some(cert);
        self
    }
}

impl Default for TlsInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS detector for service fingerprinting.
#[derive(Debug)]
pub struct TlsDetector {
    /// Connection timeout.
    timeout: Duration,

    /// Whether to verify certificates.
    verify_certificates: bool,
}

impl TlsDetector {
    /// Create a new TLS detector.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            verify_certificates: false,
        }
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set certificate verification.
    pub fn with_verify_certificates(mut self, verify: bool) -> Self {
        self.verify_certificates = verify;
        self
    }

    /// Detect TLS on a target address.
    pub async fn detect_tls(
        &self,
        target: &SocketAddr,
        server_name: Option<&str>,
    ) -> Result<Option<TlsInfo>> {
        trace!("Starting TLS detection on {}", target);

        // Connect via TCP first
        let tcp_stream = match tokio::time::timeout(
            self.timeout,
            TcpStream::connect(target),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("TCP connection failed: {}", e);
                return Ok(None);
            }
            Err(_) => {
                debug!("TCP connection timeout");
                return Ok(None);
            }
        };

        // Configure TLS client
        let config = self.build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(config));

        // Create server name for SNI
        let server_name = if let Some(name) = server_name {
            name.to_string()
        } else {
            target.ip().to_string()
        };

        let rustls_server_name = match rustls::pki_types::ServerName::try_from(server_name.clone()) {
            Ok(name) => name,
            Err(_) => {
                // If the server name is not a valid DNS name (e.g., an IP address),
                // try to use it as-is without SNI
                trace!("Invalid server name for SNI: {}", server_name);
                rustls::pki_types::ServerName::try_from("localhost".to_string())
                    .map_err(|_| FingerprintError::Tls {
                        context: "failed to create server name".to_string(),
                    })?
            }
        };

        // Perform TLS handshake
        let tls_stream = match tokio::time::timeout(
            self.timeout,
            connector.connect(rustls_server_name, tcp_stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("TLS handshake failed: {}", e);
                return Ok(None);
            }
            Err(_) => {
                debug!("TLS handshake timeout");
                return Ok(None);
            }
        };

        // Extract TLS information
        let info = self.extract_tls_info(&tls_stream, &server_name).await?;

        Ok(Some(info))
    }

    /// Build TLS client configuration.
    fn build_tls_config(&self) -> Result<rustls::ClientConfig> {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();

        Ok(config)
    }

    /// Extract TLS information from established connection.
    async fn extract_tls_info(
        &self,
        stream: &TlsStream<TcpStream>,
        server_name: &str,
    ) -> Result<TlsInfo> {
        let (_, conn) = stream.get_ref();

        // Get negotiated version
        let version = conn
            .protocol_version()
            .map(TlsVersion::from)
            .unwrap_or(TlsVersion::Unknown);

        // Get cipher suite
        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|cs| cs.suite().as_str().unwrap_or("Unknown").to_string())
            .unwrap_or_default();

        // Get ALPN protocol
        let alpn_protocol = conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string());

        // Get peer certificates
        let certificates = conn.peer_certificates();
        let chain_depth = certificates.map(|c| c.len()).unwrap_or(0);

        // Parse certificate info if available
        let certificate: Option<CertificateInfo> = if let Some(certs) = certificates {
            if let Some(first_cert) = certs.first() {
                match self.parse_certificate(first_cert) {
                    Ok(Some(cert)) => Some(cert),
                    Ok(None) => None,
                    Err(e) => {
                        debug!("Certificate parsing failed: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Check if self-signed and expiry
        let (is_self_signed, is_expired, days_until_expiry) =
            if let Some(ref cert) = certificate {
                let now = SystemTime::now();
                let is_expired = now > cert.not_after;
                let is_self_signed = cert.subject == cert.issuer;

                let days_until = if is_expired {
                    Some(
                        -(now.duration_since(cert.not_after)
                            .unwrap_or_default()
                            .as_secs() as i64)
                            / 86400,
                    )
                } else {
                    Some(
                        (cert
                            .not_after
                            .duration_since(now)
                            .unwrap_or_default()
                            .as_secs() as i64)
                            / 86400,
                    )
                };

                (is_self_signed, is_expired, days_until)
            } else {
                (false, false, None)
            };

        Ok(TlsInfo {
            version,
            cipher_suite,
            certificate,
            chain_depth,
            alpn_protocol,
            server_name: Some(server_name.to_string()),
            is_self_signed,
            is_expired,
            days_until_expiry,
        })
    }

    /// Parse X.509 certificate.
    fn parse_certificate(
        &self,
        cert: &rustls::pki_types::CertificateDer<'_>,
    ) -> Result<Option<CertificateInfo>> {
        match X509Certificate::from_der(cert.as_ref()) {
            Ok((_, cert)) => {
                // Extract subject
                let subject = cert.subject().to_string();

                // Extract issuer
                let issuer = cert.issuer().to_string();

                // Extract serial number
                let serial_number = cert.serial.to_string();

                // Extract SANs
                let mut subject_alt_names = Vec::new();
                for ext in cert.extensions() {
                    if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                        for name in &san.general_names {
                            match name {
                                GeneralName::DNSName(dns) => {
                                    subject_alt_names.push(dns.to_string());
                                }
                                GeneralName::IPAddress(ip) => {
                                    subject_alt_names.push(format!("{:?}", ip));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Extract validity
                let not_before = SystemTime::UNIX_EPOCH
                    + Duration::from_secs(cert.validity.not_before.timestamp() as u64);
                let not_after = SystemTime::UNIX_EPOCH
                    + Duration::from_secs(cert.validity.not_after.timestamp() as u64);

                // Extract signature algorithm
                let signature_algorithm = cert.signature_algorithm.oid().to_string();

                // Extract public key info - algorithm is a field, not a method
                let public_key_info = format!("{:?}", cert.public_key().algorithm);

                // Calculate fingerprint
                let fingerprint_sha256 = self.calculate_fingerprint(cert.as_ref());

                Ok(Some(CertificateInfo {
                    subject,
                    issuer,
                    serial_number,
                    subject_alt_names,
                    not_before,
                    not_after,
                    signature_algorithm,
                    public_key_info,
                    fingerprint_sha256,
                }))
            }
            Err(e) => {
                debug!("Failed to parse certificate: {}", e);
                Ok(None)
            }
        }
    }

    /// Calculate SHA-256 fingerprint of certificate.
    fn calculate_fingerprint(&self, cert_der: &[u8]) -> String {
        use std::fmt::Write;

        let hash = ring::digest::digest(&ring::digest::SHA256, cert_der);
        let mut result = String::with_capacity(hash.as_ref().len() * 3);
        for (i, byte) in hash.as_ref().iter().enumerate() {
            if i > 0 {
                result.push(':');
            }
            write!(&mut result, "{:02X}", byte).unwrap();
        }
        result
    }

    /// Check if a port commonly uses TLS/SSL.
    pub fn is_tls_port(port: u16) -> bool {
        matches!(
            port,
            443 | 465 | 636 | 993 | 995 | 3389 | 8443 | 990 | 991 | 992 | 994
        )
    }
}

impl Default for TlsDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// No-op certificate verifier that accepts all certificates.
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
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
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_info_new() {
        let info = TlsInfo::new();
        assert_eq!(info.version, TlsVersion::Unknown);
        assert!(info.cipher_suite.is_empty());
        assert!(info.certificate.is_none());
    }

    #[test]
    fn test_tls_version_display() {
        assert_eq!(TlsVersion::Tls1_2.to_string(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls1_3.to_string(), "TLSv1.3");
        assert_eq!(TlsVersion::Ssl3.to_string(), "SSLv3");
    }

    #[test]
    fn test_tls_detector_new() {
        let detector = TlsDetector::new();
        assert_eq!(detector.timeout, Duration::from_secs(10));
        assert!(!detector.verify_certificates);
    }

    #[test]
    fn test_is_tls_port() {
        assert!(TlsDetector::is_tls_port(443));
        assert!(TlsDetector::is_tls_port(465));
        assert!(TlsDetector::is_tls_port(993));
        assert!(!TlsDetector::is_tls_port(80));
        assert!(!TlsDetector::is_tls_port(8080));
    }

    #[test]
    fn test_tls_info_builder() {
        let info = TlsInfo::new()
            .with_version(TlsVersion::Tls1_2)
            .with_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        assert_eq!(info.version, TlsVersion::Tls1_2);
        assert_eq!(info.cipher_suite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    }
}
