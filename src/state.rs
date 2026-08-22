//! Shared, immutable-after-startup state handed to every connection task.

use std::sync::Arc;

use rustls::ServerConfig;

use crate::InterceptDecider;
use crate::config::ProxyConfig;
use crate::inspect::Inspectors;
use crate::upstream::Upstream;

/// Everything a connection handler needs. Cheap to clone (all `Arc`s).
pub struct ProxyState {
    /// TLS config for MITM'ing TCP connections (advertises h2 + http/1.1).
    pub server_tls: Arc<ServerConfig>,
    /// TLS config for the QUIC/HTTP/3 listener (advertises h3).
    pub h3_tls: Arc<ServerConfig>,
    /// Upstream forwarding client.
    pub upstream: Upstream,
    /// Request/response inspection hooks.
    pub inspectors: Inspectors,
    /// Decides which `CONNECT` tunnels get TLS-terminated. Tunnels the decider
    /// rejects are relayed byte-for-byte without touching TLS.
    pub intercept_decider: Arc<dyn InterceptDecider>,
    /// Effective configuration.
    pub config: Arc<ProxyConfig>,
}

/// Reference-counted handle to [`ProxyState`].
pub type SharedState = Arc<ProxyState>;
