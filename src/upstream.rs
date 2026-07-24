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
            let tls = connector
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
