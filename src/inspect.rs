//! The transparent inspect point.
//!
//! After the proxy decrypts a request (and, later, its response) it hands the
//! message to the caller's inspectors. An inspector may:
//!
//! * observe the request/response,
//! * mutate it in place (headers or body), or
//! * short-circuit a request with a synthetic response (block / redirect).
//!
//! Requests remain buffered. Response inspectors select bounded buffering for
//! transformable bodies or head-only inspection with streaming passthrough.
//! Traditional HTTP/1.1 WebSockets are inspected before their successful
//! upgrade becomes an opaque bidirectional stream.

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

/// Whether a response body must be collected before inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBodyPolicy {
    /// Inspect the response head and forward body frames with backpressure.
    Stream,
    /// Buffer at most `max_bytes` before invoking the response inspector.
    Buffer { max_bytes: usize },
}

/// Compatibility default for inspectors that transform response bodies.
pub const DEFAULT_MAX_BUFFERED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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
    /// Select body handling from request and response metadata. By default,
    /// only browser document responses with an HTML content type are buffered;
    /// inspectors that transform other body types must override this method.
    async fn response_body_policy(
        &self,
        _meta: &ConnMeta,
        req_head: &http::request::Parts,
        res_head: &Response<()>,
    ) -> ResponseBodyPolicy {
        let is_document = req_head.method == http::Method::GET
            && match req_head
                .headers
                .get("sec-fetch-dest")
                .and_then(|value| value.to_str().ok())
            {
                Some("document") => true,
                Some(_) => false,
                None => req_head
                    .headers
                    .get(http::header::ACCEPT)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.contains("text/html")),
            };
        let is_html = res_head
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/html"));

        if is_document && is_html {
            ResponseBodyPolicy::Buffer {
                max_bytes: DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
            }
        } else {
            ResponseBodyPolicy::Stream
        }
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
    async fn response_body_policy(
        &self,
        _: &ConnMeta,
        _: &http::request::Parts,
        _: &Response<()>,
    ) -> ResponseBodyPolicy {
        ResponseBodyPolicy::Stream
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
        let host = request_host(req, &meta.authority);
        info!(
            proto = %meta.protocol,
            client = %meta.client_addr,
            "-> {} host={} ({} buffered request body bytes)",
            req.method(),
            host,
            req.body().len()
        );
        RequestAction::Continue
    }
}

#[async_trait]
impl ResponseInspector for LoggingInspector {
    async fn inspect_response(
        &self,
        meta: &ConnMeta,
        req_head: &http::request::Parts,
        res: &mut BufferedResponse,
    ) -> ResponseAction {
        let host = request_parts_host(req_head, &meta.authority);
        info!(
            proto = %meta.protocol,
            client = %meta.client_addr,
            "<- {} for {} host={} ({} inspected response body bytes)",
            res.status(),
            req_head.method,
            host,
            res.body().len()
        );
        ResponseAction::Continue
    }
}

fn request_host<B>(request: &Request<B>, fallback: &str) -> String {
    request
        .uri()
        .host()
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<http::uri::Authority>().ok())
                .map(|authority| authority.host().to_owned())
        })
        .or_else(|| {
            fallback
                .parse::<http::uri::Authority>()
                .ok()
                .map(|authority| authority.host().to_owned())
        })
        .unwrap_or_else(|| "<unknown>".to_owned())
}

fn request_parts_host(request: &http::request::Parts, fallback: &str) -> String {
    request
        .uri
        .host()
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<http::uri::Authority>().ok())
                .map(|authority| authority.host().to_owned())
        })
        .or_else(|| {
            fallback
                .parse::<http::uri::Authority>()
                .ok()
                .map(|authority| authority.host().to_owned())
        })
        .unwrap_or_else(|| "<unknown>".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn log_host_excludes_path_query_and_userinfo() {
        let request = Request::builder()
            .uri("https://user:secret@example.com/private/token?api_key=secret")
            .body(Bytes::new())
            .unwrap();

        assert_eq!(
            request_host(&request, "fallback.invalid:443"),
            "example.com"
        );
    }

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
