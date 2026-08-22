//! Dynamic per-host certificate resolution for rustls.
//!
//! [`DynamicCertResolver`] implements [`rustls::server::ResolvesServerCert`].
//! During each TLS handshake rustls calls [`resolve`](DynamicCertResolver::resolve)
//! with the client's SNI; we mint (and cache) a leaf certificate for that host
//! signed by the proxy CA. The same resolver instance is shared by the TCP
//! (HTTP/1.x + h2) and QUIC (HTTP/3) listeners.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, warn};

use crate::ca::CertAuthority;

/// Generates leaf certificates on demand and caches them by host.
#[derive(Debug)]
pub struct DynamicCertResolver {
    ca: Arc<CertAuthority>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

// `CertAuthority` holds an rcgen `Issuer`, which is not `Debug`; provide a
// minimal manual impl so the resolver can derive/participate in `Debug`.
impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority").finish_non_exhaustive()
    }
}

impl DynamicCertResolver {
    pub fn new(ca: Arc<CertAuthority>) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get a cached certified key for `host`, or mint and cache a new one.
    fn certified_key(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(existing) = self.cache.lock().unwrap().get(host) {
            return Some(existing.clone());
        }

        let (chain, key_der) = match self.ca.issue_leaf(host) {
            Ok(pair) => pair,
            Err(e) => {
                warn!("failed to issue leaf for {host}: {e:#}");
                return None;
            }
        };

        let signing_key = match any_supported_type(&key_der) {
            Ok(k) => k,
            Err(e) => {
                warn!("unsupported leaf key type for {host}: {e}");
                return None;
            }
        };

        let certified = Arc::new(CertifiedKey::new(chain, signing_key));
        debug!("issued leaf certificate for {host}");
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), certified.clone());
        Some(certified)
    }

    /// Expose the cache size for testing.
    #[cfg(test)]
    pub(crate) fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Whether a leaf certificate is cached for `host`. Test-only: used to
    /// assert that tunneled (non-intercepted) hosts never get a cert minted.
    #[cfg(test)]
    pub(crate) fn has_cached_key(&self, host: &str) -> bool {
        self.cache.lock().unwrap().contains_key(host)
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Without SNI we cannot know which host to impersonate. Fall back to a
        // generic "localhost" leaf so the handshake can still complete for
        // clients that connect by IP.
        let host = client_hello.server_name().unwrap_or("localhost").to_owned();
        self.certified_key(&host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertAuthority;

    fn make_ca() -> Arc<CertAuthority> {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        Arc::new(CertAuthority::from_pem(cert_pem, &key_pem).unwrap())
    }

    #[test]
    fn resolve_returns_cert_for_sni() {
        let ca = make_ca();
        let resolver = DynamicCertResolver::new(ca);

        // Use the internal method directly
        let cert = resolver.certified_key("example.com");
        assert!(cert.is_some(), "should return a cert for valid host");
    }

    #[test]
    fn resolve_caches_same_arc_on_repeat() {
        let ca = make_ca();
        let resolver = DynamicCertResolver::new(ca);

        let c1 = resolver.certified_key("example.com").unwrap();
        assert_eq!(resolver.cache_len(), 1);

        let c2 = resolver.certified_key("example.com").unwrap();
        assert_eq!(resolver.cache_len(), 1, "cache should not grow on repeat");

        // Same Arc (pointer identity)
        assert!(Arc::ptr_eq(&c1, &c2), "must return the same cached Arc");
    }

    #[test]
    fn resolve_ip_sni_works() {
        let ca = make_ca();
        let resolver = DynamicCertResolver::new(ca);
        let cert = resolver.certified_key("127.0.0.1");
        assert!(cert.is_some(), "should handle IP SNI");
    }

    #[test]
    fn resolve_different_hosts_separate_cache() {
        let ca = make_ca();
        let resolver = DynamicCertResolver::new(ca);

        let _a = resolver.certified_key("foo.example.com").unwrap();
        let _b = resolver.certified_key("bar.example.com").unwrap();
        assert_eq!(
            resolver.cache_len(),
            2,
            "different hosts = separate entries"
        );
    }
}
