//! Response streaming and bounded transformation regression tests.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use common::*;
use mitm_proxy::inspect::{BufferedRequest, BufferedResponse, ConnMeta};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

async fn read_request_head(stream: &mut TcpStream) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_ne!(stream.read(&mut byte).await.unwrap(), 0);
        head.push(byte[0]);
    }
}

async fn connect_via_proxy(
    proxy_addr: std::net::SocketAddr,
    origin_addr: std::net::SocketAddr,
    path: &str,
) -> TcpStream {
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin_addr}{path} HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client
}

async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buf = [0_u8; 4096];
    while !received
        .windows(needle.len())
        .any(|window| window == needle)
    {
        let count = stream.read(&mut buf).await.unwrap();
        assert_ne!(count, 0, "connection closed before expected bytes arrived");
        received.extend_from_slice(&buf[..count]);
    }
    received
}

#[tokio::test]
async fn sse_first_event_arrives_before_origin_closes() {
    init_tracing();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (finish_tx, finish_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n13\r\ndata: first-event\n\n\r\n",
            )
            .await
            .unwrap();
        let _ = finish_rx.await;
        stream.write_all(b"0\r\n\r\n").await.unwrap();
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let (_, proxy_task) =
        start_proxy_on(proxy_addr, None, ca_dir.path(), Inspectors::default()).await;
    let mut client = connect_via_proxy(proxy_addr, origin_addr, "/events").await;

    let received = tokio::time::timeout(
        Duration::from_millis(500),
        read_until(&mut client, b"data: first-event"),
    )
    .await
    .expect("SSE event was buffered until the origin closed");
    assert!(
        received
            .windows(b"text/event-stream".len())
            .any(|window| window == b"text/event-stream")
    );

    finish_tx.send(()).unwrap();
    origin_task.await.unwrap();
    proxy_task.abort();
}

#[tokio::test]
async fn large_response_starts_before_the_complete_body_exists() {
    init_tracing();
    const TOTAL: usize = 2 * 1024 * 1024;
    const FIRST: usize = 64 * 1024;

    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (finish_tx, finish_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        stream.write_all(&vec![b'a'; FIRST]).await.unwrap();
        let _ = finish_rx.await;
        stream.write_all(&vec![b'b'; TOTAL - FIRST]).await.unwrap();
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let (_, proxy_task) =
        start_proxy_on(proxy_addr, None, ca_dir.path(), Inspectors::default()).await;
    let mut client = connect_via_proxy(proxy_addr, origin_addr, "/large").await;
    let first = tokio::time::timeout(Duration::from_millis(500), async {
        let mut buf = vec![0_u8; 4096];
        let count = client.read(&mut buf).await.unwrap();
        assert_ne!(count, 0);
        buf.truncate(count);
        buf
    })
    .await
    .expect("large response was buffered before delivery");
    assert!(first.starts_with(b"HTTP/1.1 200"));

    finish_tx.send(()).unwrap();
    origin_task.await.unwrap();
    proxy_task.abort();
}

struct AppendMarker;

#[async_trait]
impl RequestInspector for AppendMarker {
    async fn inspect_request(
        &self,
        _meta: &ConnMeta,
        _request: &mut BufferedRequest,
    ) -> RequestAction {
        RequestAction::Continue
    }
}

#[async_trait]
impl ResponseInspector for AppendMarker {
    async fn response_body_policy(
        &self,
        _meta: &ConnMeta,
        _request: &http::request::Parts,
        _response: &http::Response<()>,
    ) -> mitm_proxy::ResponseBodyPolicy {
        mitm_proxy::ResponseBodyPolicy::Buffer { max_bytes: 1024 }
    }

    async fn inspect_response(
        &self,
        _meta: &ConnMeta,
        _request: &http::request::Parts,
        response: &mut BufferedResponse,
    ) -> ResponseAction {
        let mut body = response.body().to_vec();
        body.extend_from_slice(b"-inspected");
        *response.body_mut() = Bytes::from(body);
        ResponseAction::Continue
    }
}

#[tokio::test]
async fn buffered_response_inspector_can_still_transform_html() {
    init_tracing();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: close\r\n\r\n<html></html>",
            )
            .await
            .unwrap();
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let inspector = Arc::new(AppendMarker);
    let inspectors = Inspectors::new(inspector.clone(), inspector);
    let (_, proxy_task) = start_proxy_on(proxy_addr, None, ca_dir.path(), inspectors).await;
    let mut client = connect_via_proxy(proxy_addr, origin_addr, "/page").await;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.ends_with(b"<html></html>-inspected"));

    origin_task.await.unwrap();
    proxy_task.abort();
}

#[tokio::test]
async fn client_disconnect_cancels_streaming_upstream_body() {
    init_tracing();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (closed_tx, closed_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n13\r\ndata: first-event\n\n\r\n",
            )
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let result = stream.read(&mut byte).await;
        if matches!(result, Ok(0) | Err(_)) {
            let _ = closed_tx.send(());
        }
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let (_, proxy_task) =
        start_proxy_on(proxy_addr, None, ca_dir.path(), Inspectors::default()).await;
    let mut client = connect_via_proxy(proxy_addr, origin_addr, "/events").await;
    tokio::time::timeout(
        Duration::from_millis(500),
        read_until(&mut client, b"data: first-event"),
    )
    .await
    .unwrap();
    drop(client);

    tokio::time::timeout(Duration::from_secs(1), closed_rx)
        .await
        .expect("client disconnect did not cancel the upstream response")
        .unwrap();
    origin_task.await.unwrap();
    proxy_task.abort();
}

#[tokio::test]
async fn upstream_failure_mid_stream_terminates_downstream() {
    init_tracing();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
            .await
            .unwrap();
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let (_, proxy_task) =
        start_proxy_on(proxy_addr, None, ca_dir.path(), Inspectors::default()).await;
    let mut client = connect_via_proxy(proxy_addr, origin_addr, "/truncated").await;
    tokio::time::timeout(
        Duration::from_millis(500),
        read_until(&mut client, b"short"),
    )
    .await
    .expect("partial upstream data did not stream to the client");

    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut rest))
        .await
        .expect("mid-stream upstream failure left the client hanging");
    origin_task.await.unwrap();
    proxy_task.abort();
}

#[tokio::test]
async fn transformable_response_over_limit_fails_closed() {
    init_tracing();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_request_head(&mut stream).await;
        let body = vec![b'x'; 2048];
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
    });

    let ca_dir = tempfile::TempDir::new().unwrap();
    let proxy_addr = pick_tcp_addr().await;
    let inspector = Arc::new(AppendMarker);
    let inspectors = Inspectors::new(inspector.clone(), inspector);
    let (_, proxy_task) = start_proxy_on(proxy_addr, None, ca_dir.path(), inspectors).await;
    let mut client = connect_via_proxy(proxy_addr, origin_addr, "/too-large").await;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502"));

    origin_task.await.unwrap();
    proxy_task.abort();
}
