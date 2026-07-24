//! Integration tests for HTTP/1.1 plaintext forwarding and CONNECT MITM.

mod common;

use common::*;
use tempfile::TempDir;

#[tokio::test]
async fn http1_plaintext_forward() {
    init_tracing();

    let origin = spawn_http1_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (_ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let target = format!("http://127.0.0.1:{}/echo", origin.port());
    let (status, body) = proxy_plaintext_get(tcp_addr, &target).await;

    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("\"method\":\"GET\""));
    assert!(body.contains("/echo"));
}

#[tokio::test]
async fn http1_connect_mitm() {
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
        "/echo?x=1",
    )
    .await;

    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("\"method\":\"GET\""));
    assert!(body.contains("/echo"));
}

#[tokio::test]
async fn http1_connect_post_body_roundtrip() {
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
        r#"{"hello":"world"}"#,
        &[],
    )
    .await;

    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("\"method\":\"POST\""));
    assert!(body.contains("hello"));
    assert!(body.contains("world"));
}

#[tokio::test]
async fn http1_connect_with_custom_header() {
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
        "test",
        &[("x-test", "hello-from-proxy")],
    )
    .await;

    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("\"header_x_test\":\"hello-from-proxy\""));
}
