//! Regression tests: when a CONNECT target is an IP literal, the proxy must
//! use the hostname carried by the request (`:authority` for HTTP/2, the
//! `Host` header for HTTP/1.x) as the upstream host — SNI, absolute URI and
//! Host header — instead of the IP. CDNs reject SNI literals with a
//! handshake failure, which surfaces as a 502 to the browser.
//!
//! The scenario mirrors ace-tun: it normally tunnels `CONNECT host:port` with
//! the domain, but when its DNS snoop misses it sends the IP literal instead.

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tempfile::TempDir;

/// Raw `CONNECT connect_host:port` through the proxy, then TLS toward the
/// proxy with SNI `sni_host` (the certificate is minted per client SNI).
async fn connect_and_tls(
    proxy_addr: std::net::SocketAddr,
    ca_pem: &str,
    connect_host: &str,
    port: u16,
    sni_host: &str,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|r| r.ok()) {
        roots.add(cert).unwrap();
    }
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let tls_cfg = Arc::new(tls_cfg);

    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    tcp.set_nodelay(true).ok();

    let connect_req =
        format!("CONNECT {connect_host}:{port} HTTP/1.1\r\nHost: {connect_host}:{port}\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut tcp, connect_req.as_bytes())
        .await
        .unwrap();

    // Read the response head, then the tunnel is established.
    let mut buf = [0u8; 4096];
    use tokio::io::AsyncReadExt;
    let mut total = 0;
    let mut found_end = false;
    while total < buf.len() {
        let n = tcp.read(&mut buf[total..total + 1]).await.unwrap();
        if n == 0 {
            break;
        }
        total += n;
        if total >= 4 && &buf[total - 4..total] == b"\r\n\r\n" {
            found_end = true;
            break;
        }
    }
    assert!(found_end, "CONNECT response must end with double CRLF");
    let head = String::from_utf8_lossy(&buf[..total]);
    assert!(head.contains("200"), "CONNECT must return 200, got: {head}");

    tokio_rustls::TlsConnector::from(tls_cfg)
        .connect(
            rustls::pki_types::ServerName::try_from(sni_host.to_string()).unwrap(),
            tcp,
        )
        .await
        .unwrap()
}

/// HTTP/1.x: CONNECT to the mock origin's IP literal, inner request carries
/// the domain in its `Host` header. The proxy must send the domain — not the
/// IP — as the upstream SNI.
#[tokio::test]
async fn ip_literal_connect_uses_request_host_as_upstream_sni() {
    init_tracing();

    let (origin_addr, _cert, mut sni_rx) = spawn_https_origin_with_sni_capture().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let tls = connect_and_tls(
        tcp_addr,
        &ca_pem,
        "127.0.0.1",
        origin_addr.port(),
        "localhost",
        &[b"http/1.1"],
    )
    .await;

    let tls_io = TokioIo::new(tls);
    let req = Request::builder()
        .method("GET")
        .uri("/echo?ip-connect=1")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("/echo?ip-connect=1"));
    // The upstream mock must see the domain in the Host header, not the IP.
    assert!(
        body.contains("\"header_host\":\"localhost\""),
        "upstream Host header must be the domain, got: {body}"
    );

    // The upstream handshake must carry the domain as SNI, not the IP.
    let sni = sni_rx
        .recv()
        .await
        .expect("origin must accept exactly one TLS connection");
    assert_eq!(sni.as_deref(), Some("localhost"));
}

/// HTTP/2: CONNECT to the IP literal, inner request carries the domain in its
/// `:authority`. The proxy must forward the domain upstream — as SNI and as
/// the `:authority` the mock origin sees.
#[tokio::test]
async fn ip_literal_connect_uses_request_authority_upstream() {
    init_tracing();

    let (origin_addr, _cert, mut sni_rx) = spawn_https_origin_with_sni_capture().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let tls = connect_and_tls(
        tcp_addr,
        &ca_pem,
        "127.0.0.1",
        origin_addr.port(),
        "localhost",
        &[b"h2"],
    )
    .await;

    let tls_io = TokioIo::new(tls);
    let (mut h2_sender, h2_conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), tls_io)
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("https://localhost/echo?ip-connect-h2=1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = h2_sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    // The echo shows the URI the mock origin received; its authority must be
    // the domain, not the CONNECT IP.
    assert!(
        body.contains("https://localhost/echo?ip-connect-h2=1"),
        "upstream :authority must be the domain, got: {body}"
    );

    let sni = sni_rx
        .recv()
        .await
        .expect("origin must accept exactly one TLS connection");
    assert_eq!(sni.as_deref(), Some("localhost"));
}

/// Shared-CDN regression: ace-tun's passive cache is `IP -> hostname`, so a
/// later lookup for another hostname on the same edge IP can overwrite the
/// entry. A stale domain CONNECT target must not win over the authority carried
/// by the decrypted browser request.
#[tokio::test]
async fn stale_domain_connect_uses_request_host_upstream() {
    init_tracing();

    let (origin_addr, _cert, mut sni_rx) = spawn_https_origin_with_sni_capture().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let tls = connect_and_tls(
        tcp_addr,
        &ca_pem,
        "stale-cache.example",
        origin_addr.port(),
        "localhost",
        &[b"http/1.1"],
    )
    .await;

    let tls_io = TokioIo::new(tls);
    let req = Request::builder()
        .method("GET")
        .uri("/echo?stale-domain=1")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("/echo?stale-domain=1"));

    let sni = sni_rx
        .recv()
        .await
        .expect("origin must accept exactly one TLS connection");
    assert_eq!(sni.as_deref(), Some("localhost"));
}

/// Control: when the CONNECT target already matches the decrypted request host,
/// the recovery is a no-op and existing domain routing stays unchanged.
#[tokio::test]
async fn domain_connect_keeps_existing_behavior() {
    init_tracing();

    let (origin_addr, _cert, mut sni_rx) = spawn_https_origin_with_sni_capture().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let tls = connect_and_tls(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "localhost",
        &[b"http/1.1"],
    )
    .await;

    let tls_io = TokioIo::new(tls);
    let req = Request::builder()
        .method("GET")
        .uri("/echo?domain-connect=1")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("/echo?domain-connect=1"));

    // Unchanged behavior: the domain from CONNECT is used upstream.
    let sni = sni_rx
        .recv()
        .await
        .expect("origin must accept exactly one TLS connection");
    assert_eq!(sni.as_deref(), Some("localhost"));
}
