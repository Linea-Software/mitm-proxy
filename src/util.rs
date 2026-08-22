//! Helpers shared by the HTTP/1.x+2 and HTTP/3 request pipelines.

use bytes::Bytes;
use http::header::{HOST, HeaderMap, HeaderValue};
use http::uri::{Authority, Scheme};
use http::{Request, Uri, Version};
use http_body_util::Full;

use crate::error::Result;

/// Render `host[:port]`, omitting the port when it is the scheme default.
pub fn authority_display(host: &str, port: u16, secure: bool) -> String {
    let default = if secure { 443 } else { 80 };
    if port == default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Build an absolute URI from a possibly origin-form request URI.
pub fn absolute_uri(uri: &Uri, host: &str, port: u16, secure: bool) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }
    let pq = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_owned();
    let scheme = if secure { Scheme::HTTPS } else { Scheme::HTTP };
    let authority: Authority = authority_display(host, port, secure)
        .parse()
        .map_err(|e| eyre::eyre!("authority parse: {e}"))?;
    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(pq)
        .build()
        .map_err(|e| eyre::eyre!("uri build: {e}"))
}

/// Clone the routing-relevant parts of a request head (method/uri/version/
/// headers) into a fresh [`http::request::Parts`] for the response inspector.
/// `http::request::Parts` has no public constructor and is not `Clone`, so we
/// round-trip through a throwaway `Request`.
pub fn snapshot_request_head(head: &http::request::Parts) -> http::request::Parts {
    let mut snap = Request::new(());
    *snap.method_mut() = head.method.clone();
    *snap.uri_mut() = head.uri.clone();
    *snap.version_mut() = head.version;
    *snap.headers_mut() = head.headers.clone();
    let (parts, ()) = snap.into_parts();
    parts
}

/// Ensure a `Host` header is present (needed for HTTP/1.x upstreams; HTTP/2 and
/// HTTP/3 carry the authority as a pseudo-header instead).
pub fn ensure_host_header(req: &mut Request<Full<Bytes>>, host: &str, port: u16, secure: bool) {
    if req.version() == Version::HTTP_2 || req.version() == Version::HTTP_3 {
        return;
    }
    if req.headers().contains_key(HOST) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&authority_display(host, port, secure)) {
        req.headers_mut().insert(HOST, value);
    }
}

/// True when `host` is a literal IPv4 or IPv6 address.
pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Strip a `:port` suffix from a `host[:port]` string (e.g. a `Host` header
/// value), leaving bracketed IPv6 literals intact.
pub fn strip_port(host_port: &str) -> &str {
    if let Some(rest) = host_port.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => &host_port[..end + 2],
            None => host_port,
        };
    }
    match host_port.rfind(':') {
        Some(idx) => &host_port[..idx],
        None => host_port,
    }
}

/// Remove hop-by-hop headers that must not be forwarded across a proxy.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    const HOP: &[&str] = &[
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    ];
    for name in HOP {
        headers.remove(*name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HOST;
    use http::{Method, Uri, Version};

    // ---- authority_display ----

    #[test]
    fn authority_omits_default_ports() {
        assert_eq!(authority_display("example.com", 443, true), "example.com");
        assert_eq!(authority_display("example.com", 80, false), "example.com");
    }

    #[test]
    fn authority_keeps_non_default_ports() {
        assert_eq!(
            authority_display("example.com", 8443, true),
            "example.com:8443"
        );
        assert_eq!(
            authority_display("example.com", 8080, false),
            "example.com:8080"
        );
    }

    // ---- absolute_uri ----

    #[test]
    fn absolute_uri_upgrades_origin_form() {
        let uri: Uri = "/path?q=1".parse().unwrap();
        let abs = absolute_uri(&uri, "example.com", 443, true).unwrap();
        assert_eq!(abs.scheme().unwrap().as_str(), "https");
        assert_eq!(abs.authority().unwrap().as_str(), "example.com");
        assert_eq!(abs.path(), "/path");
        assert_eq!(abs.query(), Some("q=1"));
    }

    #[test]
    fn absolute_uri_passes_absolute_through() {
        let uri: Uri = "https://example.com:8443/path".parse().unwrap();
        let abs = absolute_uri(&uri, "ignored", 443, true).unwrap();
        assert_eq!(abs.to_string(), "https://example.com:8443/path");
    }

    #[test]
    fn absolute_uri_plaintext_uses_http_scheme() {
        let uri: Uri = "/path".parse().unwrap();
        let abs = absolute_uri(&uri, "host", 80, false).unwrap();
        assert_eq!(abs.scheme().unwrap().as_str(), "http");
        assert_eq!(abs.authority().unwrap().as_str(), "host");
    }

    // ---- snapshot_request_head ----

    #[test]
    fn snapshot_clones_method_uri_version_headers() {
        let mut req = Request::new(());
        *req.method_mut() = Method::POST;
        *req.uri_mut() = "/test".parse().unwrap();
        *req.version_mut() = Version::HTTP_11;
        req.headers_mut().insert("x-custom", "val".parse().unwrap());

        let parts = snapshot_request_head(&req.into_parts().0);
        assert_eq!(parts.method, Method::POST);
        assert_eq!(parts.uri, "/test".parse::<Uri>().unwrap());
        assert_eq!(parts.version, Version::HTTP_11);
        assert_eq!(parts.headers.get("x-custom").unwrap(), "val");
    }

    // ---- strip_hop_by_hop ----

    #[test]
    fn strip_removes_all_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("trailer", "x-foo".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("proxy-connection", "keep-alive".parse().unwrap());
        headers.insert("proxy-authenticate", "Basic".parse().unwrap());
        headers.insert("proxy-authorization", "Basic xxx".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap()); // end-to-end

        strip_hop_by_hop(&mut headers);

        // Only content-type should survive
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("content-type"));
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("transfer-encoding"));
    }

    // ---- is_ip_literal ----

    #[test]
    fn ip_literal_detects_v4_and_v6() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("3.173.21.63"));
        assert!(is_ip_literal("::1"));
        assert!(is_ip_literal("2001:db8::1"));
    }

    #[test]
    fn ip_literal_rejects_domains() {
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("localhost"));
        assert!(!is_ip_literal("[::1]")); // bracketed form is not a bare IpAddr
    }

    // ---- strip_port ----

    #[test]
    fn strip_port_removes_port_suffix() {
        assert_eq!(strip_port("example.com:8443"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("127.0.0.1:443"), "127.0.0.1");
    }

    #[test]
    fn strip_port_keeps_bracketed_ipv6() {
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
    }

    // ---- ensure_host_header ----

    #[test]
    fn ensure_host_header_sets_for_h1() {
        let mut req = Request::new(Full::new(Bytes::from("body")));
        *req.version_mut() = Version::HTTP_11;
        ensure_host_header(&mut req, "example.com", 443, true);
        assert_eq!(req.headers().get(HOST).unwrap(), "example.com");
    }

    #[test]
    fn ensure_host_header_skips_when_already_present() {
        let mut req = Request::new(Full::new(Bytes::from("body")));
        *req.version_mut() = Version::HTTP_11;
        req.headers_mut().insert(HOST, "existing".parse().unwrap());
        ensure_host_header(&mut req, "example.com", 443, true);
        assert_eq!(req.headers().get(HOST).unwrap(), "existing");
    }

    #[test]
    fn ensure_host_header_skips_for_h2() {
        let mut req = Request::new(Full::new(Bytes::from("body")));
        *req.version_mut() = Version::HTTP_2;
        ensure_host_header(&mut req, "example.com", 443, true);
        assert!(req.headers().get(HOST).is_none());
    }

    #[test]
    fn ensure_host_header_skips_for_h3() {
        let mut req = Request::new(Full::new(Bytes::from("body")));
        *req.version_mut() = Version::HTTP_3;
        ensure_host_header(&mut req, "example.com", 443, true);
        assert!(req.headers().get(HOST).is_none());
    }

    #[test]
    fn ensure_host_header_includes_non_default_port() {
        let mut req = Request::new(Full::new(Bytes::from("body")));
        *req.version_mut() = Version::HTTP_11;
        ensure_host_header(&mut req, "example.com", 8443, true);
        assert_eq!(req.headers().get(HOST).unwrap(), "example.com:8443");
    }
}
