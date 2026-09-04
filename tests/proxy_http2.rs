//! Integration tests for HTTP/2 MITM through the CONNECT tunnel.

mod common;

use bytes::Bytes;
use common::*;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tempfile::TempDir;

async fn h2_extended_connect_echo(
    req: Request<Incoming>,
) -> Result<Response<Incoming>, Infallible> {
    assert_eq!(req.method(), http::Method::CONNECT);
    let protocol = req
        .extensions()
        .get::<hyper::ext::Protocol>()
        .expect(":protocol must reach the origin");
    assert_eq!(protocol.as_str(), "websocket");
    Ok(Response::new(req.into_body()))
}

async fn spawn_h2_extended_connect_origin() -> (std::net::SocketAddr, SelfSignedCert) {
    let cert = self_signed_cert();
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert.cert_chain.clone(), cert.key_der())
        .unwrap();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let service = service_fn(h2_extended_connect_echo);
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        builder.enable_connect_protocol();
        let _ = builder
            .serve_connection(TokioIo::new(tls), service)
            .await;
    });

    (addr, cert)
}

/// Helper: do a CONNECT tunnel (raw TCP), then make multiple h2 requests on
/// the same TLS connection.
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
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    // Raw CONNECT — write the request, read the 200, then upgrade to TLS.
    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    tcp.set_nodelay(true).ok();

    let connect_bytes = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut tcp, connect_bytes.as_bytes())
        .await
        .unwrap();

    // Read response until double CRLF
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
    let response_head = String::from_utf8_lossy(&buf[..total]);
    assert!(
        response_head.contains("200"),
        "CONNECT must return 200, got: {response_head}"
    );

    let tls_stream = tokio_rustls::TlsConnector::from(tls_cfg)
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .unwrap();

    // Verify ALPN via the TLS session state without consuming the stream.
    let (_, tls_state) = tls_stream.get_ref();
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

#[tokio::test]
async fn http2_extended_connect_preserves_protocol_and_stream_body() {
    init_tracing();

    let (origin_addr, _cert) = spawn_h2_extended_connect_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;
    let inspectors = Inspectors::default();
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let tls = connect_tls_through_proxy(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        vec![b"h2".to_vec()],
    )
    .await;
    let (mut sender, mut connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // Give the connection task a chance to process the proxy's
    // SETTINGS_ENABLE_CONNECT_PROTOCOL before sending :protocol.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let request = Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_2)
        .uri("/websocket")
        .header("host", "localhost")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Full::new(Bytes::from_static(b"extended-connect-payload")))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"extended-connect-payload");
}
