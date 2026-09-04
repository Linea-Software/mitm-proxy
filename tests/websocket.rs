//! WebSocket regression tests through an intercepted TLS connection.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use common::*;
use http::{Response, StatusCode};
use mitm_proxy::inspect::{BufferedRequest, ConnMeta};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CLIENT_FRAME: &[u8] = &[0x81, 0x82, 0x01, 0x02, 0x03, 0x04, b'h' ^ 0x01, b'i' ^ 0x02];
const SERVER_FRAME: &[u8] = &[0x81, 0x02, b'o', b'k'];

async fn read_head<I>(io: &mut I) -> Vec<u8>
where
    I: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let count = io.read(&mut byte).await.unwrap();
        assert_ne!(count, 0, "connection closed before the HTTP head completed");
        head.push(byte[0]);
        assert!(head.len() < 64 * 1024, "HTTP head exceeded test limit");
    }
    head
}

async fn connect_intercepted_h1(
    proxy_addr: std::net::SocketAddr,
    ca_pem: &str,
    origin_port: u16,
) -> TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()).filter_map(Result::ok) {
        roots.add(cert).unwrap();
    }
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
    tcp.write_all(
        format!(
            "CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let connect_head = String::from_utf8(read_head(&mut tcp).await).unwrap();
    assert!(connect_head.starts_with("HTTP/1.1 200"), "{connect_head}");

    TlsConnector::from(Arc::new(tls_config))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap()
}

fn websocket_request(origin_port: u16) -> String {
    format!(
        "GET /socket HTTP/1.1\r\n\
         Host: localhost:{origin_port}\r\n\
         Connection: keep-alive, Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
}

async fn spawn_websocket_origin() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    oneshot::Receiver<()>,
) {
    let cert = self_signed_cert();
    let mut tls_config = (*tls_server_config(&cert)).clone();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (closed_tx, closed_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let head = String::from_utf8(read_head(&mut stream).await).unwrap();
        let lower = head.to_ascii_lowercase();
        if !lower.contains("\r\nconnection: upgrade\r\n")
            || !lower.contains("\r\nupgrade: websocket\r\n")
        {
            stream
                .write_all(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            return;
        }

        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test-value\r\n\r\n",
            )
            .await
            .unwrap();

        let mut client_frame = [0_u8; CLIENT_FRAME.len()];
        stream.read_exact(&mut client_frame).await.unwrap();
        assert_eq!(client_frame, CLIENT_FRAME);
        stream.write_all(SERVER_FRAME).await.unwrap();

        let mut eof = [0_u8; 1];
        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
        let _ = closed_tx.send(());
    });

    (addr, handle, closed_rx)
}

#[tokio::test]
async fn intercepted_websocket_relays_both_directions_and_closes() {
    init_tracing();
    let (origin_addr, origin_task, closed) = spawn_websocket_origin().await;
    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let (ca_pem, proxy_task) =
        start_proxy_on(proxy_addr, None, ca_dir.path(), Inspectors::default()).await;

    let mut client = connect_intercepted_h1(proxy_addr, &ca_pem, origin_addr.port()).await;
    client
        .write_all(websocket_request(origin_addr.port()).as_bytes())
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(
        response_head.starts_with("HTTP/1.1 101"),
        "expected an upgraded response, got: {response_head}"
    );

    client.write_all(CLIENT_FRAME).await.unwrap();
    let mut server_frame = [0_u8; SERVER_FRAME.len()];
    client.read_exact(&mut server_frame).await.unwrap();
    assert_eq!(server_frame, SERVER_FRAME);

    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), closed)
        .await
        .expect("origin did not observe WebSocket disconnect")
        .unwrap();

    origin_task.await.unwrap();
    proxy_task.abort();
}

struct BlockWebSockets;

#[async_trait]
impl RequestInspector for BlockWebSockets {
    async fn inspect_request(
        &self,
        _meta: &ConnMeta,
        _request: &mut BufferedRequest,
    ) -> RequestAction {
        RequestAction::Respond(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Bytes::new())
                .unwrap(),
        )
    }
}

#[tokio::test]
async fn blocked_websocket_never_connects_to_origin() {
    init_tracing();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        if listener.accept().await.is_ok() {
            let _ = accepted_tx.send(());
        }
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let inspectors = Inspectors::new(Arc::new(BlockWebSockets), Arc::new(NoopInspector));
    let (ca_pem, proxy_task) = start_proxy_on(proxy_addr, None, ca_dir.path(), inspectors).await;

    let mut client = connect_intercepted_h1(proxy_addr, &ca_pem, origin_addr.port()).await;
    client
        .write_all(websocket_request(origin_addr.port()).as_bytes())
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"), "{response_head}");
    assert!(
        tokio::time::timeout(Duration::from_millis(150), accepted_rx)
            .await
            .is_err(),
        "blocked WebSocket unexpectedly reached the origin"
    );

    origin_task.abort();
    proxy_task.abort();
}
