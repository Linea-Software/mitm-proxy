//! Error type shared across the crate.
//!
//! We lean on [`eyre`] for rich, contextual error reporting. Most fallible
//! functions return [`Result<T>`], which is simply `eyre::Result<T>`. A small
//! [`ProxyError`] enum is provided for the few cases where callers benefit from
//! matching on a specific, stable variant (e.g. distinguishing a TLS handshake
//! failure from an upstream connection failure).

use std::net::SocketAddr;

/// Convenience alias used throughout the crate.
pub type Result<T> = eyre::Result<T>;

/// Structured errors for the cases a caller may want to match on.
///
/// Everything else is reported as an ad-hoc [`eyre::Report`] with context.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to bind the listening socket.
    #[error("failed to bind proxy listener on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },

    /// The TLS handshake with the *client* (browser) failed.
    #[error("client TLS handshake failed: {0}")]
    ClientHandshake(String),

    /// Connecting or handshaking with the *upstream* origin failed.
    #[error("upstream connection to {authority} failed: {source}")]
    Upstream {
        authority: String,
        #[source]
        source: eyre::Report,
    },

    /// A request could not be forwarded because it lacked routing information
    /// (no authority / Host header).
    #[error("request is missing a target authority (Host header / :authority)")]
    MissingAuthority,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn bind_error_contains_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let err = ProxyError::Bind {
            addr,
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"),
        };
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:1"));
        assert!(msg.contains("bind"));
    }

    #[test]
    fn client_handshake_error_contains_message() {
        let err = ProxyError::ClientHandshake("bad cert".into());
        assert!(err.to_string().contains("bad cert"));
    }

    #[test]
    fn upstream_error_contains_authority() {
        let err = ProxyError::Upstream {
            authority: "example.com:443".into(),
            source: eyre::eyre!("timeout"),
        };
        let msg = err.to_string();
        assert!(msg.contains("example.com:443"));
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn missing_authority_displays_nicely() {
        let err = ProxyError::MissingAuthority;
        assert!(err.to_string().contains("missing"));
    }
}
