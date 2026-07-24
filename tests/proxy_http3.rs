//! Integration tests for HTTP/3 (QUIC) interception.
//!
//! Uses a Rust h3 client (h3 + h3-quinn + quinn) to drive our own server.
//! This is the canonical h3 regression test for the stream-FIN bug.

mod common;

use bytes::Buf;
use bytes::Bytes;
use common::*;
use futures::future;
use http::{Request, StatusCode};
use std::sync::Arc;
use tempfile::TempDir;

/// Build a Rust h3 client that trusts our proxy CA.
fn h3_client_config(ca_pem: &str) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|r| r.ok()) {
        roots.add(cert).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg
}

async fn h3_get(
    proxy_h3_addr: std::net::SocketAddr,
    ca_pem: &str,
    target_host: &str,
    target_port: u16,
    path: &str,
) -> (StatusCode, String) {
    let tls_cfg = h3_client_config(ca_pem);
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_cfg)).unwrap();

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(8).try_into().unwrap()));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(proxy_h3_addr, target_host)
        .unwrap()
        .await
        .unwrap();

    let (mut connection, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();

    let drive_handle = tokio::spawn(async move {
        future::poll_fn(|cx| connection.poll_close(cx)).await;
    });

    let uri = if target_port == 443 {
        format!("https://{target_host}{path}")
    } else {
        format!("https://{target_host}:{target_port}{path}")
    };
    let req = Request::builder().method("GET").uri(&uri).body(()).unwrap();

    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();

    let resp = stream.recv_response().await.unwrap();
    let status = resp.status();
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(chunk.chunk());
    }

    let trailers = stream.recv_trailers().await.unwrap();
    assert!(trailers.is_none(), "should be no trailers for a simple GET");

    drop(send_request);
    drive_handle.await.unwrap();

    (status, String::from_utf8_lossy(&body).to_string())
}

async fn h3_post(
    proxy_h3_addr: std::net::SocketAddr,
    ca_pem: &str,
    target_host: &str,
    target_port: u16,
    path: &str,
    body_bytes: &[u8],
) -> (StatusCode, String) {
    let tls_cfg = h3_client_config(ca_pem);
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_cfg)).unwrap();

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(8).try_into().unwrap()));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(proxy_h3_addr, target_host)
        .unwrap()
        .await
        .unwrap();

    let (mut connection, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();

    let drive_handle = tokio::spawn(async move {
        future::poll_fn(|cx| connection.poll_close(cx)).await;
    });

    let uri = if target_port == 443 {
        format!("https://{target_host}{path}")
    } else {
        format!("https://{target_host}:{target_port}{path}")
    };
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("content-type", "application/json")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(req).await.unwrap();
    stream
        .send_data(Bytes::from(body_bytes.to_vec()))
        .await
        .unwrap();
    stream.finish().await.unwrap();

    let resp = stream.recv_response().await.unwrap();
    let status = resp.status();
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(chunk.chunk());
    }

    let trailers = stream.recv_trailers().await.unwrap();
    assert!(trailers.is_none());

    drop(send_request);
    drive_handle.await.unwrap();

    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn http3_get_body() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;
    let h3_addr = pick_udp_addr();

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) =
        start_proxy_on(tcp_addr, Some(h3_addr), ca_dir.path(), inspectors).await;

    let (status, body) = h3_get(
        h3_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/echo?h3=1",
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.contains("\"method\":\"GET\""));
    assert!(body.contains("/echo?h3=1"));
}

#[tokio::test]
async fn http3_post_body_roundtrip() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;
    let h3_addr = pick_udp_addr();

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) =
        start_proxy_on(tcp_addr, Some(h3_addr), ca_dir.path(), inspectors).await;

    let body_bytes = br#"{"h3":"post-test"}"#;
    let (status, body) = h3_post(
        h3_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/echo",
        body_bytes,
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.contains("\"method\":\"POST\""));
    assert!(body.contains("h3"));
    assert!(body.contains("post-test"));
}

#[tokio::test]
async fn http3_stream_finishes_cleanly() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;
    let h3_addr = pick_udp_addr();

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) =
        start_proxy_on(tcp_addr, Some(h3_addr), ca_dir.path(), inspectors).await;

    for i in 0..3 {
        let (status, body) = h3_get(
            h3_addr,
            &ca_pem,
            "localhost",
            origin_addr.port(),
            &format!("/echo?seq={i}"),
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains(&format!("?seq={i}")));
    }
}
