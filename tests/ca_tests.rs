//! Integration tests for the CA lifecycle.

mod common;

use common::*;
use tempfile::TempDir;

#[tokio::test]
async fn first_run_generates_and_persists_ca() {
    init_tracing();
    let ca_dir = TempDir::new().unwrap();
    let cert_path = ca_dir.path().join("mitm_ca.pem");
    let key_path = ca_dir.path().join("mitm_ca.key");

    assert!(!cert_path.exists());
    assert!(!key_path.exists());

    let (_origin_addr, _cert) = spawn_https_origin().await;
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    assert!(cert_path.exists(), "CA cert should be generated");
    assert!(key_path.exists(), "CA key should be generated");
    assert!(!ca_pem.is_empty());
}

#[tokio::test]
async fn second_run_reuses_ca() {
    init_tracing();
    let ca_dir = TempDir::new().unwrap();

    let ca_pem1;
    {
        let (_origin_addr, _cert) = spawn_https_origin().await;
        let tcp_addr = pick_tcp_addr().await;
        let inspectors = Inspectors::default();
        let (pem, handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;
        ca_pem1 = pem;
        drop(handle);
    }

    // Second run with same CA dir — need a new port
    {
        let tcp_addr = pick_tcp_addr().await;
        let inspectors = Inspectors::default();
        let (ca_pem2, _handle2) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

        assert_eq!(ca_pem1, ca_pem2, "CA PEM should be identical on second run");
    }
}

#[tokio::test]
async fn leaf_cache_reuse_across_requests() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (status1, body1) = proxy_connect_get(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/echo?1",
    )
    .await;
    assert_eq!(status1, http::StatusCode::OK);

    let (status2, body2) = proxy_connect_get(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/echo?2",
    )
    .await;
    assert_eq!(status2, http::StatusCode::OK);

    assert!(body1.contains("\"method\":\"GET\""));
    assert!(body2.contains("\"method\":\"GET\""));
}
