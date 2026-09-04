//! The transparent inspect point.
//!
//! After the proxy decrypts a request (and, later, its response) it hands the
//! message metadata and, when requested, a buffered body to the caller's
//! inspectors. An inspector may:
//!
//! * observe the request/response,
//! * mutate it in place (headers or body), or
//! * short-circuit a request with a synthetic response (block / redirect).
//!
//! Request bodies are buffered before normal request inspection. Response
//! inspectors can choose per response whether the body must be buffered for
//! mutation or may be streamed without aggregation. HTTP upgrades are relayed
//! as opaque byte streams after their opening handshake.
//!

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

/// Which wire protocol a message arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::Http1 => "HTTP/1.x",
            Protocol::Http2 => "HTTP/2",
            Protocol::Http3 => "HTTP/3",
        };
        f.write_str(s)
    }
}

/// Metadata about the connection a message belongs to. Shared by request and
/// response inspection so a caller can correlate the two.
#[derive(Debug, Clone)]
pub struct ConnMeta {
    /// Peer address of the client (browser).
    pub client_addr: SocketAddr,
    /// Protocol spoken between client and proxy.
    pub protocol: Protocol,
    /// Whether the client<->proxy hop is TLS (i.e. was MITM'd).
    pub is_tls: bool,
    /// The target authority (`host[:port]`) the request is bound for.
    pub authority: String,
}

/// A request body buffered into memory alongside its head.
pub type BufferedRequest = Request<Bytes>;
/// A response body buffered into memory alongside its head.
pub type BufferedResponse = Response<Bytes>;

/// Outcome of inspecting a request.
pub enum RequestAction {
    /// Forward the (possibly-mutated) request upstream.
    Continue,
    /// Do not forward; return this response to the client instead.
    Respond(BufferedResponse),
}

/// Outcome of inspecting a response.
pub enum ResponseAction {
    /// Return the (possibly-mutated) response to the client.
    Continue,
}

/// Whether an upstream response body must be aggregated before inspection or
/// can be forwarded frame-by-frame to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBodyMode {
    /// Collect the whole body, run the body inspector, then return it.
    Buffer,
    /// Forward body frames immediately. Only the response-head hook runs.
    Stream,
}

/// Hook invoked for every decrypted request before it is forwarded upstream.
#[async_trait]
pub trait RequestInspector: Send + Sync {
    /// Inspect `req` in place. Return [`RequestAction::Respond`] to block.
    async fn inspect_request(&self, meta: &ConnMeta, req: &mut BufferedRequest) -> RequestAction;
}

/// Hook invoked for every response received from upstream before it is
/// returned to the client.
#[async_trait]
pub trait ResponseInspector: Send + Sync {
    /// Inspect or mutate response metadata before its body is handled. The
    /// response body is intentionally empty in this hook.
    async fn inspect_response_head(
        &self,
        _meta: &ConnMeta,
        _req_head: &http::request::Parts,
        _res_head: &mut BufferedResponse,
    ) -> ResponseAction {
        ResponseAction::Continue
    }

    /// Select body handling for this response. Buffering remains the default
    /// so existing third-party inspectors retain their previous semantics.
    fn response_body_mode(
        &self,
        _meta: &ConnMeta,
        _req_head: &http::request::Parts,
        _res_head: &BufferedResponse,
    ) -> ResponseBodyMode {
        ResponseBodyMode::Buffer
    }

    /// Inspect `res` in place.
    async fn inspect_response(
        &self,
        meta: &ConnMeta,
        req_head: &http::request::Parts,
        res: &mut BufferedResponse,
    ) -> ResponseAction;
}

/// Bundle of the two inspectors handed to the proxy.
#[derive(Clone)]
pub struct Inspectors {
    pub request: Arc<dyn RequestInspector>,
    pub response: Arc<dyn ResponseInspector>,
}

impl Inspectors {
    pub fn new(request: Arc<dyn RequestInspector>, response: Arc<dyn ResponseInspector>) -> Self {
        Self { request, response }
    }
}

impl Default for Inspectors {
    fn default() -> Self {
        let noop = Arc::new(NoopInspector);
        Self {
            request: noop.clone(),
            response: noop,
        }
    }
}

/// An inspector that observes nothing and forwards everything unchanged.
pub struct NoopInspector;

#[async_trait]
impl RequestInspector for NoopInspector {
    async fn inspect_request(&self, _: &ConnMeta, _: &mut BufferedRequest) -> RequestAction {
        RequestAction::Continue
    }
}

#[async_trait]
impl ResponseInspector for NoopInspector {
    fn response_body_mode(
        &self,
        _: &ConnMeta,
        _: &http::request::Parts,
        _: &BufferedResponse,
    ) -> ResponseBodyMode {
        ResponseBodyMode::Stream
    }

    async fn inspect_response(
        &self,
        _: &ConnMeta,
        _: &http::request::Parts,
        _: &mut BufferedResponse,
    ) -> ResponseAction {
        ResponseAction::Continue
    }
}

/// A simple inspector that logs a one-line summary of each request and
/// response at `INFO`. Useful as a demo and for smoke-testing.
pub struct LoggingInspector;

#[async_trait]
impl RequestInspector for LoggingInspector {
    async fn inspect_request(&self, meta: &ConnMeta, req: &mut BufferedRequest) -> RequestAction {
        info!(
            proto = %meta.protocol,
            client = %meta.client_addr,
            "-> {} {} ({} body bytes)",
            req.method(),
            req.uri(),
            req.body().len()
        );
        RequestAction::Continue
    }
}

#[async_trait]
impl ResponseInspector for LoggingInspector {
    async fn inspect_response_head(
        &self,
        meta: &ConnMeta,
        req_head: &http::request::Parts,
        res: &mut BufferedResponse,
    ) -> ResponseAction {
        info!(
            proto = %meta.protocol,
            client = %meta.client_addr,
            "<- {} for {} {}",
            res.status(),
            req_head.method,
            req_head.uri,
        );
        ResponseAction::Continue
    }

    fn response_body_mode(
        &self,
        _: &ConnMeta,
        _: &http::request::Parts,
        _: &BufferedResponse,
    ) -> ResponseBodyMode {
        ResponseBodyMode::Stream
    }

    async fn inspect_response(
        &self,
        meta: &ConnMeta,
        req_head: &http::request::Parts,
        res: &mut BufferedResponse,
    ) -> ResponseAction {
        info!(
            proto = %meta.protocol,
            client = %meta.client_addr,
            "<- {} for {} {} ({} body bytes)",
            res.status(),
            req_head.method,
            req_head.uri,
            res.body().len()
        );
        ResponseAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_meta() -> ConnMeta {
        ConnMeta {
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            protocol: Protocol::Http1,
            is_tls: false,
            authority: "example.com".to_string(),
        }
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Http1.to_string(), "HTTP/1.x");
        assert_eq!(Protocol::Http2.to_string(), "HTTP/2");
        assert_eq!(Protocol::Http3.to_string(), "HTTP/3");
    }

    #[test]
    fn conn_meta_fields() {
        let meta = test_meta();
        assert_eq!(meta.authority, "example.com");
        assert!(!meta.is_tls);
        assert_eq!(meta.protocol, Protocol::Http1);
    }

    #[tokio::test]
    async fn noop_inspector_returns_continue() {
        let inspector = NoopInspector;
        let mut req = Request::new(Bytes::from("hello"));
        let action = inspector.inspect_request(&test_meta(), &mut req).await;
        assert!(matches!(action, RequestAction::Continue));

        let mut res = Response::new(Bytes::from("world"));
        let req_parts = Request::new(()).into_parts().0;
        let action = inspector
            .inspect_response(&test_meta(), &req_parts, &mut res)
            .await;
        assert!(matches!(action, ResponseAction::Continue));
    }

    #[tokio::test]
    async fn custom_request_inspector_can_respond() {
        struct Blocker;
        #[async_trait]
        impl RequestInspector for Blocker {
            async fn inspect_request(
                &self,
                _: &ConnMeta,
                _: &mut BufferedRequest,
            ) -> RequestAction {
                let resp = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Bytes::from("blocked"))
                    .unwrap();
                RequestAction::Respond(resp)
            }
        }

        let inspector = Blocker;
        let mut req = Request::new(Bytes::new());
        let action = inspector.inspect_request(&test_meta(), &mut req).await;
        match action {
            RequestAction::Respond(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert_eq!(resp.body(), &Bytes::from("blocked"));
            }
            RequestAction::Continue => panic!("expected Respond"),
        }
    }

    #[tokio::test]
    async fn request_mutation_visible_downstream() {
        struct SetHeader;
        #[async_trait]
        impl RequestInspector for SetHeader {
            async fn inspect_request(
                &self,
                _: &ConnMeta,
                req: &mut BufferedRequest,
            ) -> RequestAction {
                req.headers_mut()
                    .insert("x-inspected", "true".parse().unwrap());
                RequestAction::Continue
            }
        }

        let inspector = SetHeader;
        let mut req = Request::new(Bytes::from("body"));
        let _ = inspector.inspect_request(&test_meta(), &mut req).await;
        assert_eq!(req.headers().get("x-inspected").unwrap(), "true");
        assert_eq!(req.body(), &Bytes::from("body"));
    }

    #[tokio::test]
    async fn response_mutation_visible_downstream() {
        struct SetHeader;
        #[async_trait]
        impl ResponseInspector for SetHeader {
            async fn inspect_response(
                &self,
                _: &ConnMeta,
                _: &http::request::Parts,
                res: &mut BufferedResponse,
            ) -> ResponseAction {
                res.headers_mut()
                    .insert("x-inspected", "true".parse().unwrap());
                let new_body = Bytes::from([res.body().as_ref(), b"-modified" as &[u8]].concat());
                *res.body_mut() = new_body;
                ResponseAction::Continue
            }
        }

        let inspector = SetHeader;
        let mut res = Response::new(Bytes::from("original"));
        let req_parts = Request::new(()).into_parts().0;
        inspector
            .inspect_response(&test_meta(), &req_parts, &mut res)
            .await;
        assert_eq!(res.headers().get("x-inspected").unwrap(), "true");
        assert_eq!(res.body(), &Bytes::from("original-modified"));
    }

    #[test]
    fn inspectors_default_is_noop() {
        let inspectors = Inspectors::default();
        // Default inspectors should be NoopInspector — we can't check the type
        // at runtime, but we can verify they are functional.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut req = Request::new(Bytes::new());
            let action = inspectors
                .request
                .inspect_request(&test_meta(), &mut req)
                .await;
            assert!(matches!(action, RequestAction::Continue));
        });
    }
}
