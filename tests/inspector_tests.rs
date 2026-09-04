//! Integration tests for the request/response inspector hooks.

mod common;

use async_trait::async_trait;
use bytes::Bytes;
use common::*;
use http::StatusCode;
use mitm_proxy::inspect::ConnMeta;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tempfile::TempDir;
// ---------------------------------------------------------------------------
// Observer inspector
// ---------------------------------------------------------------------------
struct CountingInspector {
    requests: AtomicUsize,
    responses: AtomicUsize,
}

impl CountingInspector {
    fn new() -> Self {
        Self {
            requests: AtomicUsize::new(0),
            responses: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl RequestInspector for CountingInspector {
    async fn inspect_request(
        &self,
        _meta: &ConnMeta,
        _req: &mut mitm_proxy::inspect::BufferedRequest,
    ) -> RequestAction {
        self.requests.fetch_add(1, Ordering::SeqCst);
        RequestAction::Continue
    }
}

#[async_trait]
impl ResponseInspector for CountingInspector {
    async fn inspect_response(
        &self,
        _meta: &ConnMeta,
        _req_head: &http::request::Parts,
        _res: &mut mitm_proxy::inspect::BufferedResponse,
    ) -> ResponseAction {
        self.responses.fetch_add(1, Ordering::SeqCst);
        ResponseAction::Continue
    }
}

// ---------------------------------------------------------------------------
// Header-mutating inspector
// ---------------------------------------------------------------------------
struct HeaderMutator {
    request_header_set: AtomicBool,
}

impl HeaderMutator {
    fn new() -> Self {
        Self {
            request_header_set: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl RequestInspector for HeaderMutator {
    async fn inspect_request(
        &self,
        _meta: &ConnMeta,
        req: &mut mitm_proxy::inspect::BufferedRequest,
    ) -> RequestAction {
        req.headers_mut()
            .insert("x-mutated-request", "yes".parse().unwrap());
        self.request_header_set.store(true, Ordering::SeqCst);
        RequestAction::Continue
    }
}

// ---------------------------------------------------------------------------
// Body-mutating inspector
// ---------------------------------------------------------------------------
struct BodyMutator;

#[async_trait]
impl ResponseInspector for BodyMutator {
    async fn response_body_policy(
        &self,
        _meta: &ConnMeta,
        _req_head: &http::request::Parts,
        _res_head: &http::Response<()>,
    ) -> mitm_proxy::ResponseBodyPolicy {
        mitm_proxy::ResponseBodyPolicy::Buffer {
            max_bytes: 1024 * 1024,
        }
    }

    async fn inspect_response(
        &self,
        _meta: &ConnMeta,
        _req_head: &http::request::Parts,
        res: &mut mitm_proxy::inspect::BufferedResponse,
    ) -> ResponseAction {
        let new_body = Bytes::from(format!("MUTATED:{}", String::from_utf8_lossy(res.body())));
        *res.body_mut() = new_body;
        ResponseAction::Continue
    }
}

// ---------------------------------------------------------------------------
// Blocker inspector
// ---------------------------------------------------------------------------
struct Blocker;

#[async_trait]
impl RequestInspector for Blocker {
    async fn inspect_request(
        &self,
        _meta: &ConnMeta,
        _req: &mut mitm_proxy::inspect::BufferedRequest,
    ) -> RequestAction {
        let resp = http::Response::builder()
            .status(StatusCode::IM_A_TEAPOT)
            .header("x-blocked", "true")
            .body(Bytes::from("blocked-by-inspector"))
            .unwrap();
        RequestAction::Respond(resp)
    }
}

// =========================================================================

#[tokio::test]
async fn observer_inspector_counts_calls() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let counter = Arc::new(CountingInspector::new());
    let inspectors = Inspectors::new(counter.clone(), counter.clone());
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (status, _body) =
        proxy_connect_get(tcp_addr, &ca_pem, "localhost", origin_addr.port(), "/echo").await;

    assert_eq!(status, StatusCode::OK);
    assert!(counter.requests.load(Ordering::SeqCst) >= 1);
    assert!(counter.responses.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn request_header_mutation_reaches_origin() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let mutator = Arc::new(HeaderMutator::new());
    let inspectors = Inspectors::new(mutator.clone(), Arc::new(NoopInspector));
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (status, _body) =
        proxy_connect_get(tcp_addr, &ca_pem, "localhost", origin_addr.port(), "/echo").await;

    assert_eq!(status, StatusCode::OK);
    assert!(mutator.request_header_set.load(Ordering::SeqCst));
}

#[tokio::test]
async fn response_body_mutation_reaches_client() {
    init_tracing();

    let (origin_addr, _cert) = spawn_https_origin().await;
    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::new(Arc::new(NoopInspector), Arc::new(BodyMutator));
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (status, body) =
        proxy_connect_get(tcp_addr, &ca_pem, "localhost", origin_addr.port(), "/echo").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.starts_with("MUTATED:"),
        "response body should be mutated, got: {body}"
    );
    assert!(body.contains("\"method\":\"GET\""));
}

#[tokio::test]
async fn request_action_respond_blocks_request() {
    init_tracing();

    let ca_dir = TempDir::new().unwrap();
    let tcp_addr = pick_tcp_addr().await;

    let inspectors = Inspectors::new(Arc::new(Blocker), Arc::new(NoopInspector));
    let (ca_pem, _handle) = start_proxy_on(tcp_addr, None, ca_dir.path(), inspectors).await;

    let (origin_addr, _cert) = spawn_https_origin().await;

    let (status, body) = proxy_connect_get(
        tcp_addr,
        &ca_pem,
        "localhost",
        origin_addr.port(),
        "/anything",
    )
    .await;

    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert!(body.contains("blocked-by-inspector"));
}
