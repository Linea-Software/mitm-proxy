//! Forwarding decrypted requests to the origin server.
//!
//! Given a fully-buffered request, [`Upstream::send`] opens a fresh connection
//! to the origin (TCP, optionally wrapped in TLS with ALPN negotiation),
//! performs the matching hyper client handshake (HTTP/1.x or HTTP/2), sends the
//! request, and buffers the response back into memory.
//!
//! Connections are not pooled — each request gets its own. That keeps the code
//! self-contained; pooling (via `hyper-util`'s legacy client) is a documented
//! non-goal for now.

use std::sync::Arc;

use bytes::Bytes;
use eyre::{Context, eyre};
use http::header::{HOST, HeaderValue};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::{ProxyError, Result};

/// Opens connections to upstream origins and relays buffered requests.
#[derive(Clone)]
pub struct Upstream {
    tls: Arc<ClientConfig>,
}

impl Upstream {
    pub fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    /// Send `req` to `host:port`, using TLS when `secure` is set. Returns the
    /// response with its body buffered into [`Bytes`].
    pub async fn send(
        &self,
        secure: bool,
        host: &str,
        port: u16,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Bytes>> {
        let authority = format!("{host}:{port}");

        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| ProxyError::Upstream {
                authority: authority.clone(),
                source: eyre!("tcp connect: {e}"),
            })?;
        tcp.set_nodelay(true).ok();

        if secure {
            let connector = TlsConnector::from(self.tls.clone());
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| eyre!("invalid upstream server name {host:?}: {e}"))?;
            let tls =
                connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| ProxyError::Upstream {
                        authority: authority.clone(),
                        source: eyre!("tls handshake: {e}"),
                    })?;

            let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            debug!(
                "upstream {authority} negotiated {}",
                if is_h2 { "h2" } else { "http/1.1" }
            );

            if is_h2 {
                self.send_h2(TokioIo::new(tls), &authority, req).await
            } else {
                self.send_h1(TokioIo::new(tls), &authority, req).await
            }
        } else {
            // Plaintext HTTP is always HTTP/1.x for a forward proxy target.
            self.send_h1(TokioIo::new(tcp), &authority, req).await
        }
    }

    async fn send_h1<I>(
        &self,
        io: I,
        authority: &str,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Bytes>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    {
        // RFC 7230 §5.4: every HTTP/1.1 request MUST carry a Host header.
        // Requests that arrived as HTTP/2 carry the authority as a
        // pseudo-header instead, which an HTTP/1.x transport never emits, and
        // hyper's http1 client does not insert Host automatically. Without it
        // strict origin servers (e.g. Zoho's ZGS gateway) reject the request
        // with 400 Bad Request.
        let mut req = req;
        if !req.headers().contains_key(HOST)
            && let Some(authority) = req.uri().authority()
            && let Ok(value) = HeaderValue::from_str(authority.as_str())
        {
            req.headers_mut().insert(HOST, value);
        }

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ProxyError::Upstream {
                authority: authority.to_string(),
                source: eyre!("http/1 handshake: {e}"),
            })?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("upstream http/1 connection closed: {e}");
            }
        });

        let resp = sender
            .send_request(req)
            .await
            .wrap_err_with(|| format!("http/1 request to {authority} failed"))?;
        buffer_response(resp).await
    }

    async fn send_h2<I>(
        &self,
        io: I,
        authority: &str,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Bytes>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| ProxyError::Upstream {
                authority: authority.to_string(),
                source: eyre!("http/2 handshake: {e}"),
            })?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("upstream http/2 connection closed: {e}");
            }
        });

        let resp = sender
            .send_request(req)
            .await
            .wrap_err_with(|| format!("http/2 request to {authority} failed"))?;
        buffer_response(resp).await
    }
}

/// Collect a streaming response body into memory.
async fn buffer_response(resp: Response<hyper::body::Incoming>) -> Result<Response<Bytes>> {
    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .wrap_err("reading upstream response body")?
        .to_bytes();
    Ok(Response::from_parts(parts, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Version;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn init_crypto() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn test_upstream() -> Upstream {
        init_crypto();
        let tls = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        Upstream::new(tls)
    }

    /// An HTTP/2 client request carries the authority as a pseudo-header, so
    /// the relayed request has no `Host` header. When such a request is
    /// forwarded over an HTTP/1.x upstream transport, the origin must still
    /// receive a `Host` header (RFC 7230 §5.4) or strict servers (Zoho's ZGS
    /// gateway) answer 400.
    #[tokio::test]
    async fn h1_transport_adds_host_for_h2_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let upstream = test_upstream();
        let req = Request::builder()
            .method("GET")
            .uri("https://accounts.example.com/signin?x=1")
            .version(Version::HTTP_2)
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(req.headers().get(HOST).is_none(), "precondition: no Host");

        let send_task =
            tokio::spawn(async move { upstream.send(false, "127.0.0.1", addr.port(), req).await });

        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);

        assert!(
            head.to_lowercase()
                .contains("\r\nhost: accounts.example.com\r\n"),
            "upstream h1 request must carry Host from the URI authority, got: {head}"
        );

        // Answer so the send completes.
        conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        let resp = send_task.await.unwrap().unwrap();
        assert_eq!(resp.status(), 200);
    }

    /// Requests that already carry a Host header must keep it untouched.
    #[tokio::test]
    async fn h1_transport_keeps_existing_host() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let upstream = test_upstream();
        let req = Request::builder()
            .method("GET")
            .uri("https://accounts.example.com/signin?x=1")
            .header(HOST, "custom.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let send_task =
            tokio::spawn(async move { upstream.send(false, "127.0.0.1", addr.port(), req).await });

        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);

        assert!(
            head.to_lowercase()
                .contains("\r\nhost: custom.example.com\r\n"),
            "existing Host must be preserved, got: {head}"
        );
        assert!(
            !head.to_lowercase().contains("host: accounts.example.com"),
            "URI authority must not override an existing Host, got: {head}"
        );

        conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        let resp = send_task.await.unwrap().unwrap();
        assert_eq!(resp.status(), 200);
    }
}
