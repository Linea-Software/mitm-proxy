//! Runtime configuration for the proxy.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration for a [`crate::MitmProxy`] instance.
///
/// Construct one directly, or start from [`ProxyConfig::new`] and override the
/// fields you care about.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// TCP address the forward proxy listens on. Browsers point their
    /// `http`/`https` proxy setting here. Serves HTTP/1.x and HTTP/2
    /// (the latter after TLS termination of a CONNECT tunnel).
    pub listen_addr: SocketAddr,

    /// Optional UDP address for the HTTP/3 (QUIC) listener. When `None`, the
    /// HTTP/3 endpoint is not started. This is a *direct* interception endpoint
    /// (QUIC has no cleartext CONNECT equivalent), so it is typically only
    /// useful behind a transparent-redirect layer.
    pub http3_addr: Option<SocketAddr>,

    /// Path to the CA certificate (PEM). Generated on first run if missing.
    pub ca_cert_path: PathBuf,

    /// Path to the CA private key (PEM). Generated on first run if missing.
    pub ca_key_path: PathBuf,

    /// Attempt to install the generated CA into the OS trust store on startup.
    /// On Windows this shells out to `certutil` and requires elevation to be
    /// silent. Off by default — trusting a MITM root is the caller's decision.
    pub install_ca: bool,

    /// Whether to verify upstream (origin) TLS certificates. Enabled by
    /// default. Disable only for testing against hosts with self-signed certs.
    pub verify_upstream: bool,
}

impl ProxyConfig {
    /// Create a config listening on `listen_addr`, keeping CA material next to
    /// each other under `ca_dir` (`mitm_ca.pem` / `mitm_ca.key`).
    pub fn new(listen_addr: SocketAddr, ca_dir: impl Into<PathBuf>) -> Self {
        let dir = ca_dir.into();
        Self {
            listen_addr,
            http3_addr: None,
            ca_cert_path: dir.join("mitm_ca.pem"),
            ca_key_path: dir.join("mitm_ca.key"),
            install_ca: false,
            verify_upstream: true,
        }
    }

    /// Enable the HTTP/3 listener on `addr`.
    pub fn with_http3(mut self, addr: SocketAddr) -> Self {
        self.http3_addr = Some(addr);
        self
    }

    /// Request installation of the CA into the OS trust store on startup.
    pub fn install_ca(mut self, install: bool) -> Self {
        self.install_ca = install;
        self
    }

    /// Toggle upstream certificate verification.
    pub fn verify_upstream(mut self, verify: bool) -> Self {
        self.verify_upstream = verify;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn default_ports_correct() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let config = ProxyConfig::new(addr, "./ca");
        assert_eq!(config.listen_addr.port(), 8080);
        assert_eq!(config.http3_addr, None);
        assert!(!config.install_ca);
        assert!(config.verify_upstream);
    }

    #[test]
    fn builder_sets_every_field() {
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let h3: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let config = ProxyConfig::new(addr, "/tmp/ca")
            .with_http3(h3)
            .install_ca(true)
            .verify_upstream(false);

        assert_eq!(config.listen_addr, addr);
        assert_eq!(config.http3_addr, Some(h3));
        assert!(config.install_ca);
        assert!(!config.verify_upstream);
    }

    #[test]
    fn ca_paths_derive_from_dir() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = ProxyConfig::new(addr, std::path::Path::new("/tmp/myca"));
        assert_eq!(
            config.ca_cert_path,
            std::path::PathBuf::from("/tmp/myca/mitm_ca.pem")
        );
        assert_eq!(
            config.ca_key_path,
            std::path::PathBuf::from("/tmp/myca/mitm_ca.key")
        );
    }

    #[test]
    fn http3_defaults_to_none() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = ProxyConfig::new(addr, "./ca");
        assert_eq!(config.http3_addr, None);
    }
}
