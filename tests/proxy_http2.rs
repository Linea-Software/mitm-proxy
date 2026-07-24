//! Integration tests for HTTP/2 MITM through the CONNECT tunnel.

mod common;

use bytes::Bytes;
use common::*;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tempfile::TempDir;

/// Helper: do a CONNECT tunnel, then make multiple h2 requests on the same connection.
async fn h2_multiplexed_requests(
    proxy_addr: std::net::SocketAddr,
    ca_pem: &str,
    host: &str,
    port: u16,
) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|r| r.ok()) {
        roots.add(cert).unwrap();
    }
    let tls_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let io = TokioIo::new(tcp);

    let connect_req = Request::builder()
        .method("CONNECT")
        .uri(format!("{host}:{port}"))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async {
        let _ = conn.await;
    });
    let resp = sender.send_request(connect_req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let upgraded = hyper::upgrade::on(resp).await.unwrap();
    let tls_stream = tokio_rustls::TlsConnector::from(tls_cfg)
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            TokioIo::new(upgraded),
        )
        .await
        .unwrap();

    let (tls_stream, tls_state) = tls_stream.into_inner();
    assert_eq!(
        tls_state.alpn_protocol(),
        Some(b"h2".as_slice()),
        "ALPN must negotiate h2"
    );

    let tls_io = TokioIo::new(tls_stream);
    let (mut h2_sender, h2_conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), tls_io)
            .await
            .unwrap();
    tokio::spawn(async {
        let _ = h2_conn.await;
    });

    let req1 = Request::builder()
        .method("GET")
        .uri("/echo?a=1")
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let req2 = Request::builder()
        .method("GET")
        .uri("/echo?b=2")
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let (resp1, resp2) = tokio::join!(h2_sender.send_request(req1), h2_sender.send_request(req2));

    let resp1 = resp1.unwrap();
    let resp2 = resp2.unwrap();

    assert_eq!(resp1.status(), 200);
    assert_eq!(resp2.status(), 200);

    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let b1 = String::from_utf8_lossy(&body1);
    let b2 = String::from_utf8_lossy(&body2);

    assert!(b1.contains("/echo?a=1"));
    assert!(b2.contains("/echo?b=2"));
}

#[tokio::test]
async fn http2_mitm_get() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (status, body) = proxy_connect_get(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/echo?h2=1",
    )
    .await;

    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("\"method\":\"GET\""));
    assert!(body.contains("/echo?h2=1"));
}

#[tokio::test]
async fn http2_post_body_roundtrip() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (status, body) = proxy_connect_post(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/echo",
        r#"{"key":"value"}"#,
        &[("x-test", "h2-post")],
    )
    .await;

    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("\"method\":\"POST\""));
    assert!(body.contains("\"key\":\"value\""));
    assert!(body.contains("h2-post"));
}

#[tokio::test]
async fn http2_concurrent_multiplexed_streams() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    h2_multiplexed_requests(tcp_addr, &ca_pem, "localhost", origin_addr.port()).await;
}
