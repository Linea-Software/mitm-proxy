//! Certificate authority: load or generate the proxy's root CA and issue
//! per-host leaf certificates on the fly.
//!
//! On startup we either load an existing CA keypair from disk or generate a
//! fresh one. During each intercepted TLS handshake the [`crate::cert_resolver`]
//! asks us to [`CertAuthority::issue_leaf`] a certificate for the requested
//! SNI host, signed by this CA, so the client sees a valid chain for every
//! domain (provided it trusts our root).

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use eyre::{Context, eyre};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

use crate::error::Result;

/// The proxy's certificate authority. Holds the signing key (wrapped in an
/// [`Issuer`]) plus the encoded root certificate for installation/serving.
pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    /// DER-encoded root CA certificate.
    pub cert_der: CertificateDer<'static>,
    /// PEM-encoded root CA certificate (what the user installs / trusts).
    pub cert_pem: String,
}

impl CertAuthority {
    /// Load the CA from `cert_path`/`key_path`, generating and persisting a new
    /// one if either file is missing or unreadable.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> Result<Self> {
        match (fs::read_to_string(cert_path), fs::read_to_string(key_path)) {
            (Ok(cert_pem), Ok(key_pem)) => {
                info!("loading CA from {}", cert_path.display());
                Self::from_pem(cert_pem, &key_pem)
            }
            _ => {
                info!("no CA found — generating a new root CA");
                let (cert_pem, key_pem) = Self::generate_root()?;

                if let Some(parent) = cert_path.parent() {
                    fs::create_dir_all(parent).wrap_err("creating CA directory")?;
                }
                fs::write(cert_path, &cert_pem).wrap_err("writing CA cert")?;
                fs::write(key_path, &key_pem).wrap_err("writing CA key")?;
                info!(
                    "wrote new CA to {} / {}",
                    cert_path.display(),
                    key_path.display()
                );

                Self::from_pem(cert_pem, &key_pem)
            }
        }
    }

    /// Build a [`CertAuthority`] from PEM-encoded certificate and key.
    pub fn from_pem(cert_pem: String, key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(key_pem).wrap_err("parsing CA key PEM")?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .map_err(|e| eyre!("building issuer from CA cert: {e}"))?;

        // Decode the PEM certificate into DER for serving / installation.
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or_else(|| eyre!("CA PEM contained no certificate"))?
            .wrap_err("decoding CA certificate DER")?;

        Ok(Self {
            issuer,
            cert_der,
            cert_pem,
        })
    }

    /// Generate a fresh self-signed root CA, returning `(cert_pem, key_pem)`.
    pub fn generate_root() -> Result<(String, String)> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "mitm-proxy Root CA");
        dn.push(DnType::OrganizationName, "mitm-proxy");
        params.distinguished_name = dn;

        // Long-lived root; the browser only checks leaf validity windows.
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365 * 20);

        let key_pair = KeyPair::generate().wrap_err("generating CA key")?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| eyre!("self-signing CA: {e}"))?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }

    /// Issue a leaf certificate for `host`, signed by this CA. Returns the
    /// certificate chain (leaf only — the root is the trust anchor) and the
    /// leaf's private key, both DER-encoded.
    pub fn issue_leaf(
        &self,
        host: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::default();

        // SNI may be an IP literal or a DNS name.
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                host.try_into()
                    .map_err(|e| eyre!("invalid DNS name {host:?}: {e}"))?,
            ),
        };
        params.subject_alt_names = vec![san];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Emit an Authority Key Identifier matching the CA's Subject Key
        // Identifier. Strict verifiers (OpenSSL 3 / Python's `ssl`) reject leaf
        // certificates that omit it with `Missing Authority Key Identifier`.
        params.use_authority_key_identifier_extension = true;

        // Keep the leaf well under the ~398-day cap browsers enforce for
        // server certificates, or they reject it as `VALIDITY_TOO_LONG`.
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365);

        let leaf_key = KeyPair::generate().wrap_err("generating leaf key")?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| eyre!("signing leaf for {host}: {e}"))?;

        let chain = vec![leaf.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((chain, key))
    }

    /// Attempt to install the root CA into the OS trust store. Best-effort:
    /// logs and returns `Ok(())` even when the platform tool reports failure,
    /// since the proxy is still usable (clients just won't trust it yet).
    #[cfg(target_os = "windows")]
    pub fn install_to_trust_store(&self, cert_path: &Path) -> Result<()> {
        use std::process::Command;
        info!("installing CA into the machine Root store via certutil");
        let out = Command::new("certutil")
            .args(["-addstore", "-f", "Root"])
            .arg(cert_path)
            .output()
            .wrap_err("spawning certutil")?;
        if out.status.success() {
            info!("CA installed into machine Root store");
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            warn!("certutil did not install the CA (run elevated?): {stderr}");
        }
        Ok(())
    }

    /// Non-Windows stub: log guidance rather than attempting installation.
    #[cfg(not(target_os = "windows"))]
    pub fn install_to_trust_store(&self, cert_path: &Path) -> Result<()> {
        warn!(
            "automatic CA installation is only implemented on Windows; \
             manually trust {}",
            cert_path.display()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn parse_der<'a>(der: &'a [u8]) -> X509Certificate<'a> {
        let (_, cert) = X509Certificate::from_der(der).expect("valid DER");
        cert
    }

    #[test]
    fn generate_root_is_parseable_ca() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();
        let parsed = parse_der(ca.cert_der.as_ref());

        // Verify we got a valid parsed cert
        assert!(!parsed.subject().to_string().is_empty());

        // Subject Key Identifier should be present
        let has_ski = parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER);
        assert!(has_ski, "CA must have Subject Key Identifier");

        // BasicConstraints extension should be present on a CA
        let has_bc = parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS);
        assert!(has_bc, "CA must have BasicConstraints extension");
    }

    #[test]
    fn issue_leaf_cn_and_san_match() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();

        let (chain, _leaf_key) = ca.issue_leaf("example.com").unwrap();
        assert_eq!(chain.len(), 1);

        let parsed = parse_der(chain[0].as_ref());

        // Subject contains the CN
        let subject_str = parsed.subject().to_string();
        assert!(
            subject_str.contains("example.com"),
            "subject must contain hostname, got: {subject_str}"
        );

        // SAN has DNS:example.com
        let has_san = parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);
        assert!(has_san, "leaf must have SAN");
    }

    #[test]
    fn leaf_aki_matches_ca_ski() {
        use x509_parser::extensions::ParsedExtension;

        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();

        let (chain, _) = ca.issue_leaf("example.com").unwrap();
        let ca_parsed = parse_der(ca.cert_der.as_ref());
        let leaf_parsed = parse_der(chain[0].as_ref());

        // Extract CA's Subject Key Identifier value
        let ca_ski_ext = ca_parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .expect("CA must have SKI extension");
        let ski_key_id = match ca_ski_ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ski) => ski.0.to_vec(),
            _ => panic!("expected SubjectKeyIdentifier extension"),
        };

        // Extract leaf's Authority Key Identifier value
        let leaf_aki_ext = leaf_parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            .expect("leaf must have AKI extension");
        let aki_key_id = match leaf_aki_ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => aki
                .key_identifier
                .as_ref()
                .expect("AKI must contain key_identifier")
                .0
                .to_vec(),
            _ => panic!("expected AuthorityKeyIdentifier extension"),
        };

        assert_eq!(
            ski_key_id, aki_key_id,
            "leaf AKI key identifier must match CA SKI key identifier"
        );
    }

    #[test]
    fn leaf_signature_verified_by_ca() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();

        let (chain, _leaf_key) = ca.issue_leaf("example.com").unwrap();

        let ca_parsed = parse_der(ca.cert_der.as_ref());
        let leaf_parsed = parse_der(chain[0].as_ref());

        // Verify the leaf certificate's signature cryptographically using the
        // CA's public key. This proves the CA actually signed the leaf.
        let ca_spki = ca_parsed.public_key();
        leaf_parsed
            .verify_signature(Some(ca_spki))
            .expect("leaf signature must be valid against CA public key");
    }

    #[test]
    fn issue_leaf_ip_san() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();

        let (chain, _) = ca.issue_leaf("127.0.0.1").unwrap();
        let parsed = parse_der(chain[0].as_ref());

        // Subject contains the IP
        let subject_str = parsed.subject().to_string();
        assert!(
            subject_str.contains("127.0.0.1"),
            "subject must contain IP, got: {subject_str}"
        );

        // SAN should be present
        let has_san = parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);
        assert!(has_san, "leaf must have SAN");
    }

    #[test]
    fn issue_leaf_has_authority_key_identifier() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();

        let (chain, _) = ca.issue_leaf("example.com").unwrap();
        let parsed = parse_der(chain[0].as_ref());

        let aki = parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER);
        assert!(aki, "leaf must have Authority Key Identifier");
    }

    #[test]
    fn issue_leaf_validity_window_within_398_days() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem, &key_pem).unwrap();

        let (chain, _) = ca.issue_leaf("example.com").unwrap();
        let parsed = parse_der(chain[0].as_ref());

        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        let duration_days = (not_after - not_before) / 86400;
        assert!(
            duration_days <= 398,
            "validity must be <= 398 days, got {duration_days}"
        );
        assert!(duration_days > 0, "validity must be positive");
    }

    #[test]
    fn leaf_chains_to_and_verified_by_ca() {
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = CertAuthority::from_pem(cert_pem.clone(), &key_pem).unwrap();

        let (chain, _leaf_key) = ca.issue_leaf("example.com").unwrap();

        let ca_parsed = parse_der(ca.cert_der.as_ref());
        let leaf_parsed = parse_der(chain[0].as_ref());

        // Leaf issuer must match CA subject
        let leaf_issuer = format!("{}", leaf_parsed.issuer());
        let ca_subject = format!("{}", ca_parsed.subject());
        assert_eq!(leaf_issuer, ca_subject, "leaf issuer must be the CA");

        // Verify the leaf cert is different from the CA
        let ca_der = ca.cert_der.as_ref();
        let leaf_der = chain[0].as_ref();
        assert_ne!(ca_der, leaf_der, "CA and leaf must differ");

        // Leaf must have AKI extension
        let has_aki = leaf_parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER);
        assert!(has_aki, "leaf must have Authority Key Identifier");

        // CA must have SKI extension
        let has_ski = ca_parsed
            .extensions()
            .iter()
            .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER);
        assert!(has_ski, "CA must have Subject Key Identifier");
    }

    #[test]
    fn load_or_generate_persists_and_reuses() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");

        // First call: generate
        let ca1 = CertAuthority::load_or_generate(&cert_path, &key_path).unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Second call: reload
        let ca2 = CertAuthority::load_or_generate(&cert_path, &key_path).unwrap();
        assert_eq!(ca1.cert_pem, ca2.cert_pem);

        // Issue a leaf — should succeed with loaded CA
        let (chain, _) = ca2.issue_leaf("example.com").unwrap();
        assert_eq!(chain.len(), 1);
    }
}
