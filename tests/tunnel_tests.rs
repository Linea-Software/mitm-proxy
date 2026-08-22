//! Integration tests for narrow interception: opaque (non-intercepted) TCP
//! tunnels must relay bytes untouched, and the intercepted path must keep
//! working when a decider opts into it.

mod common;

use common::*;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Read exactly `buf.len()` bytes from `stream`, byte-by-byte (kept simple and
/// deterministic for the small payloads used here).
async fn read_exact(stream: &mut tokio::net::TcpStream, buf: &mut [u8]) {
    let mut got = 0;
    while got < buf.len() {
        let n = stream.read(&mut buf[got..]).await.unwrap();
        assert!(
            n > 0,
            "connection closed after {} of {} bytes",
            got,
            buf.len()
        );
        got += n;
    }
}

/// Raw CONNECT through the proxy, asserting a `200` response head.
async fn raw_connect(
    proxy_addr: std::net::SocketAddr,
    host: &str,
    port: u16,
) -> tokio::net::TcpStream {
    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    tcp.set_nodelay(true).ok();

    let connect_req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Read the response head until the double CRLF.
    let mut buf = [0u8; 4096];
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
    let response_head = String::from_utf8_lossy(&buf[..total]);
    assert!(
        response_head.starts_with("HTTP/1.1 200"),
        "CONNECT must return 200, got: {response_head}"
    );

    tcp
}

// ---------------------------------------------------------------------------
// Invariant: byte-for-byte passthrough on the non-intercepted path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn opaque_tunnel_relays_bytes_unchanged_both_directions() {
    init_tracing();

    // Raw byte origin: pushes a banner, then echoes everything back verbatim.
    let banner: Vec<u8> = (0..257u32).map(|i| (i % 251) as u8).collect();
    let origin = spawn_raw_tcp_echo(&banner).await;

    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (_ca_pem, _handle) = start_proxy_on_with_decider(
        tcp_addr,
        None,
        ca_dir.path(),
        inspectors,
        Arc::new(TunnelAll),
    )
    .await;

    let mut tunnel = raw_connect(tcp_addr, "127.0.0.1", origin.port()).await;

    // Upstream -> client: the banner must arrive untouched (no TLS in the way).
    let mut got_banner = vec![0u8; banner.len()];
    read_exact(&mut tunnel, &mut got_banner).await;
    assert_eq!(
        got_banner, banner,
        "upstream -> client bytes must be unchanged"
    );

    // Client -> upstream -> client: echo round-trip must be byte-for-byte.
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    tunnel.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    read_exact(&mut tunnel, &mut echoed).await;
    assert_eq!(
        echoed, payload,
        "client -> upstream -> client bytes must be unchanged"
    );
}

// ---------------------------------------------------------------------------
// Invariant: no leaf certificate is minted for a tunneled host
// ---------------------------------------------------------------------------
//
// The certificate cache lives inside `DynamicCertResolver`, which is created
// in `MitmProxy::run` and is not reachable through the public API, so this
// test lives in the crate (`src/http.rs`) where it can hold the resolver and
// assert on its cache directly.

// ---------------------------------------------------------------------------
// Regression guard: the intercepted path still works when opted in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn intercepted_path_still_works_with_decider() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on_with_decider(
        tcp_addr,
        None,
        ca_dir.path(),
        inspectors,
        Arc::new(InterceptAll),
    )
    .await;

    // Same flow as the classic `http1_connect_mitm` test, but with an
    // explicit intercept-all decider: TLS must be terminated and the request
    // must round-trip through the MITM pipeline.
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
    assert!(body.contains("/echo?x=1"));
}
