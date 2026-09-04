//! Forwarding decrypted requests to the origin server.
//!
//! Each request currently opens a fresh origin connection. Response bodies are
//! intentionally returned as [`hyper::body::Incoming`] so the caller can
//! either inspect a fully-buffered body or relay frames as they arrive.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use std::sync::Arc;

use bytes::Bytes;
use eyre::{Context, eyre};
use http::{Request, Response};
use hyper::body::{Body, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::{ProxyError, Result};

type BoxError = Box<dyn Error + Send + Sync>;

/// Opens connections to upstream origins and relays requests without
/// aggregating their response bodies.
#[derive(Clone)]
pub struct Upstream {
    tls: Arc<ClientConfig>,
}

impl Upstream {
    pub fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    /// Send `req` to `host:port`, using TLS when `secure` is set. The response
    /// body remains streaming; callers decide whether it needs aggregation.
    pub async fn send<B>(
        &self,
        secure: bool,
        host: &str,
        port: u16,
        req: Request<B>,
    ) -> Result<Response<Incoming>>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let authority = format!("{host}:{port}");
        let requires_h2 = req.extensions().get::<hyper::ext::Protocol>().is_some();
        let requires_h1_upgrade = req.version() == http::Version::HTTP_11
            && req.headers().contains_key(http::header::UPGRADE)
            && req
                .headers()
                .get_all(http::header::CONNECTION)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));

        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| ProxyError::Upstream {
                authority: authority.clone(),
                source: eyre!("tcp connect: {e}"),
            })?;
        tcp.set_nodelay(true).ok();

        if secure {
            let tls_config = if requires_h2 || requires_h1_upgrade {
                let mut config = (*self.tls).clone();
                config.alpn_protocols = if requires_h2 {
                    vec![b"h2".to_vec()]
                } else {
                    vec![b"http/1.1".to_vec()]
                };
                Arc::new(config)
            } else {
                self.tls.clone()
            };
            let connector = TlsConnector::from(tls_config);
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

            if is_h2 && requires_h1_upgrade {
                Err(ProxyError::Upstream {
                    authority,
                    source: eyre!("origin negotiated HTTP/2 for an HTTP/1.1 upgrade"),
                })
            } else if is_h2 {
                self.send_h2(TokioIo::new(tls), &authority, req).await
            } else if requires_h2 {
                Err(ProxyError::Upstream {
                    authority,
                    source: eyre!("origin did not negotiate HTTP/2 for extended CONNECT"),
                })
            } else {
                self.send_h1(TokioIo::new(tls), &authority, req).await
            }
        } else if requires_h2 {
            Err(ProxyError::Upstream {
                authority,
                source: eyre!("extended CONNECT requires an HTTP/2 upstream"),
            })
        } else {
            self.send_h1(TokioIo::new(tcp), &authority, req).await
        }
    }

    async fn send_h1<I, B>(
        &self,
        io: I,
        authority: &str,
        req: Request<B>,
    ) -> Result<Response<Incoming>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ProxyError::Upstream {
                authority: authority.to_string(),
                source: eyre!("http/1 handshake: {e}"),
            })?;

        // `with_upgrades` is required for WebSocket and other HTTP/1.1 protocol
        // switches. Without it, `hyper::upgrade::on(response)` never resolves.
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                debug!("upstream http/1 connection closed: {e}");
            }
        });

        sender
            .send_request(req)
            .await
            .wrap_err_with(|| format!("http/1 request to {authority} failed"))
    }

    async fn send_h2<I, B>(
        &self,
        io: I,
        authority: &str,
        req: Request<B>,
    ) -> Result<Response<Incoming>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let (mut sender, mut conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| ProxyError::Upstream {
                authority: authority.to_string(),
                source: eyre!("http/2 handshake: {e}"),
            })?;

        if req.extensions().get::<hyper::ext::Protocol>().is_some() {
            let wait_for_setting = std::future::poll_fn(|cx| {
                let connection_poll = Pin::new(&mut conn).poll(cx);
                if conn.is_extended_connect_protocol_enabled() {
                    return Poll::Ready(Ok(()));
                }

                match connection_poll {
                    Poll::Ready(Ok(())) => Poll::Ready(Err(eyre!(
                        "HTTP/2 connection closed before enabling extended CONNECT"
                    ))),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(eyre!(
                        "HTTP/2 connection failed before enabling extended CONNECT: {error}"
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            });

            tokio::time::timeout(Duration::from_secs(5), wait_for_setting)
                .await
                .map_err(|_| ProxyError::Upstream {
                    authority: authority.to_string(),
                    source: eyre!("timed out waiting for SETTINGS_ENABLE_CONNECT_PROTOCOL"),
                })?
                .map_err(|source| ProxyError::Upstream {
                    authority: authority.to_string(),
                    source,
                })?;
        }

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("upstream http/2 connection closed: {e}");
            }
        });

        sender
            .send_request(req)
            .await
            .wrap_err_with(|| format!("http/2 request to {authority} failed"))
    }
}
