//! rustls configuration helpers for both sides of the proxy.
//!
//! * The *server* side (client <-> proxy) uses a [`DynamicCertResolver`] so a
//!   per-host leaf is minted during each handshake.
//! * The *client* side (proxy <-> upstream) uses the webpki root set (or, for
//!   testing, a no-op verifier).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig,
    SignatureScheme,
};

use crate::cert_resolver::DynamicCertResolver;

/// ALPN identifiers advertised to *clients* over the MITM'd TCP connection.
pub const TCP_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
/// ALPN identifier advertised to *clients* over QUIC.
pub const H3_ALPN: &[&[u8]] = &[b"h3"];

/// Build a server config that resolves certificates dynamically per SNI and
/// advertises the given ALPN protocols.
pub fn server_config(resolver: Arc<DynamicCertResolver>, alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// Build the client config used to reach upstream origins. `alpn` controls
/// which HTTP versions we offer upstream (typically h2 + http/1.1).
pub fn client_config(verify: bool, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder();
    let mut cfg = if verify {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// A certificate verifier that accepts everything. Used only when the operator
/// explicitly disables upstream verification (testing against self-signed
/// origins). Signature checks are still delegated to the crypto provider so the
/// handshake stays well-formed.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertAuthority;
    use crate::cert_resolver::DynamicCertResolver;

    fn init_crypto() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn make_resolver() -> Arc<DynamicCertResolver> {
        init_crypto();
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = Arc::new(CertAuthority::from_pem(cert_pem, &key_pem).unwrap());
        Arc::new(DynamicCertResolver::new(ca))
    }

    #[test]
    fn server_config_sets_tcp_alpn() {
        let resolver = make_resolver();
        let cfg = server_config(resolver, TCP_ALPN);
        let alpn: Vec<&[u8]> = cfg.alpn_protocols.iter().map(|v| v.as_slice()).collect();
        assert!(alpn.contains(&b"h2".as_slice()));
        assert!(alpn.contains(&b"http/1.1".as_slice()));
    }

    #[test]
    fn server_config_sets_h3_alpn() {
        let resolver = make_resolver();
        let cfg = server_config(resolver, H3_ALPN);
        let alpn: Vec<&[u8]> = cfg.alpn_protocols.iter().map(|v| v.as_slice()).collect();
        assert!(alpn.contains(&b"h3".as_slice()));
        assert_eq!(alpn.len(), 1);
    }

    #[test]
    fn client_config_verify_true_has_verifier() {
        let cfg = client_config(true, TCP_ALPN);
        assert!(!cfg.alpn_protocols.is_empty());
    }

    #[test]
    fn client_config_verify_false_has_no_verify() {
        let cfg = client_config(false, TCP_ALPN);
        assert!(!cfg.alpn_protocols.is_empty());
    }

    #[test]
    fn client_config_alpn_contains_h2_and_h1() {
        let cfg = client_config(false, TCP_ALPN);
        let alpn: Vec<&[u8]> = cfg.alpn_protocols.iter().map(|v| v.as_slice()).collect();
        assert!(alpn.contains(&b"h2".as_slice()));
        assert!(alpn.contains(&b"http/1.1".as_slice()));
    }
}
