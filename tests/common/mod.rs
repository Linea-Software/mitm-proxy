//! Shared test infrastructure for mitm-proxy integration tests.
//!
//! Provides local HTTP/1.1 and HTTPS (HTTP/1.1+HTTP/2) echo servers bound to
//! ephemeral ports, helper functions to start the proxy in-process, and
//! convenience HTTP clients that route through the proxy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rcgen::{CertificateParams, IsCa, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

// ----- re-exports for test files -----
#[allow(unused_imports)]
pub use mitm_proxy::inspect::{
    Inspectors, NoopInspector, RequestAction, RequestInspector, ResponseAction, ResponseInspector,
};
pub use mitm_proxy::{MitmProxy, ProxyConfig};

// ----- single tracing init -----
static TRACING_INIT: std::sync::Once = std::sync::Once::new();
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("warn,mitm_proxy=info")),
            )
            .with_test_writer()
            .try_init()
            .ok();
    });
}

// =========================================================================
// In-process proxy
// =========================================================================

/// Start a proxy on a **fixed** TCP address (and optional h3 address).
/// Returns the addresses, CA PEM, and a join handle.  Drop the handle to stop.
pub async fn start_proxy_on(
    tcp_addr: SocketAddr,
    h3_addr: Option<SocketAddr>,
    ca_dir: &std::path::Path,
    inspectors: Inspectors,
) -> (String, tokio::task::JoinHandle<()>) {
    let mut config = ProxyConfig::new(tcp_addr, ca_dir.to_path_buf()).verify_upstream(false);
    if let Some(addr) = h3_addr {
        config = config.with_http3(addr);
    }

    let proxy = MitmProxy::new(config.clone()).with_inspectors(inspectors);
    let handle = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    // Let the proxy bind and generate/load CA
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let ca_pem = std::fs::read_to_string(&config.ca_cert_path).unwrap_or_default();
    (ca_pem, handle)
}

/// Bind a TCP listener to get an ephemeral port, then return the address
/// (the listener is dropped so the proxy can reuse the port immediately).
pub async fn pick_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Bind a UDP socket to get an ephemeral port for QUIC.
#[allow(dead_code)]
pub fn pick_udp_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    addr
}

// =========================================================================
// Self-signed cert for local HTTPS origins
// =========================================================================

pub struct SelfSignedCert {
    pub cert_chain: Vec<CertificateDer<'static>>,
    key_der_bytes: Vec<u8>,
}

impl SelfSignedCert {
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der_bytes.clone()))
    }
}

pub fn self_signed_cert() -> SelfSignedCert {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    SelfSignedCert {
        cert_chain: vec![cert.der().clone()],
        key_der_bytes: key.serialize_der(),
    }
}

pub fn tls_server_config(cert: &SelfSignedCert) -> Arc<ServerConfig> {
    let key_der = cert.key_der();
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert.cert_chain.clone(), key_der)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

// =========================================================================
// Echo server handler (shared)
// =========================================================================

async fn echo_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body = req
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body);

    let json = format!(
        r#"{{"method":"{}","uri":"{}","header_x_test":"{}","header_host":"{}","body":"{}"}}"#,
        method,
        uri,
        headers
            .get("x-test")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or(""),
        headers
            .get("host")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or(""),
        body_text
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap())
}

// =========================================================================
// HTTP/1.1 plaintext origin
// =========================================================================

#[allow(dead_code)]
pub async fn spawn_http1_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async {
                let io = TokioIo::new(stream);
                let svc = service_fn(echo_handler);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

// =========================================================================
// HTTPS origin (h1+h2)
// =========================================================================

pub async fn spawn_https_origin() -> (SocketAddr, SelfSignedCert) {
    let cert = self_signed_cert();
    let tls_cfg = tls_server_config(&cert);
    let acceptor = TlsAcceptor::from(tls_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let a = acceptor.clone();
            tokio::spawn(async move {
                let tls = match a.accept(stream).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let svc = service_fn(echo_handler);
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (addr, cert)
}

/// Like [`spawn_https_origin`], but also reports the TLS SNI of every accepted
/// connection: one `Option<String>` per connection, in accept order (`None`
/// when no SNI was sent). Lets tests assert which hostname the *proxy* used
/// for the upstream handshake.
#[allow(dead_code)]
pub async fn spawn_https_origin_with_sni_capture() -> (
    SocketAddr,
    SelfSignedCert,
    tokio::sync::mpsc::UnboundedReceiver<Option<String>>,
) {
    let (sni_tx, sni_rx) = tokio::sync::mpsc::unbounded_channel();
    let cert = self_signed_cert();
    let tls_cfg = tls_server_config(&cert);
    let acceptor = TlsAcceptor::from(tls_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let a = acceptor.clone();
            let sni_tx = sni_tx.clone();
            tokio::spawn(async move {
                let tls = match a.accept(stream).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let sni = tls.get_ref().1.server_name().map(|name| name.to_string());
                let _ = sni_tx.send(sni);
                let io = TokioIo::new(tls);
                let svc = service_fn(echo_handler);
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (addr, cert, sni_rx)
}

// =========================================================================
// Proxy client helpers
// =========================================================================

/// Plaintext GET through the proxy.
#[allow(dead_code)]
pub async fn proxy_plaintext_get(proxy_addr: SocketAddr, target_url: &str) -> (StatusCode, String) {
    let stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let req = Request::builder()
        .method("GET")
        .uri(target_url)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

/// CONNECT + TLS request through the proxy, trusting the proxy CA.
#[allow(dead_code)]
pub async fn proxy_connect_get(
    proxy_addr: SocketAddr,
    ca_pem: &str,
    host: &str,
    port: u16,
    path: &str,
) -> (StatusCode, String) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|r| r.ok()) {
        roots.add(cert).unwrap();
    }
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    // Raw CONNECT: send CONNECT request, read 200, then upgrade to TLS.
    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    tcp.set_nodelay(true).ok();

    // Send CONNECT request
    let connect_req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    use tokio::io::AsyncWriteExt;
    tcp.write_all(connect_req.as_bytes()).await.unwrap();

    // Read response: drain until double CRLF, then the tunnel is established.
    // Use a simple byte-by-byte read to avoid BufReader borrow issues.
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

    // Now we have a raw tunnel. Upgrade to TLS.
    let tls_stream = tokio_rustls::TlsConnector::from(tls_cfg)
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .unwrap();

    let tls_io = TokioIo::new(tls_stream);

    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();

    // Always use HTTP/1.1 for GET tests (h2 has interop issues with hyper-to-hyper)
    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_io).await.unwrap();
    tokio::spawn(async {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

/// POST body through the CONNECT proxy, return status + body.
#[allow(dead_code)]
pub async fn proxy_connect_post(
    proxy_addr: SocketAddr,
    ca_pem: &str,
    host: &str,
    port: u16,
    path: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(|r| r.ok()) {
        roots.add(cert).unwrap();
    }
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_cfg = Arc::new(tls_cfg);

    // Raw CONNECT
    let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    tcp.set_nodelay(true).ok();
    let connect_req_line = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    use tokio::io::AsyncWriteExt;
    tcp.write_all(connect_req_line.as_bytes()).await.unwrap();

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
    assert!(found_end);
    let response_head = String::from_utf8_lossy(&buf[..total]);
    assert!(response_head.starts_with("HTTP/1.1 200"));

    let tls_stream = tokio_rustls::TlsConnector::from(tls_cfg)
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .unwrap();

    let tls_io = TokioIo::new(tls_stream);

    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();

    // Always use HTTP/1.1 for test requests
    let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_io).await.unwrap();
    tokio::spawn(async {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body_bytes).to_string())
}
