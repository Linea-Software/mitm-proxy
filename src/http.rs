//! HTTP/1.x and HTTP/2 forward proxy with TLS interception.
//!
//! The listener speaks HTTP/1.1 to the browser (the classic forward-proxy
//! protocol). Two request shapes arrive:
//!
//! * **Plaintext** (`GET http://host/path`) — forwarded directly to the origin
//!   over cleartext HTTP/1.x.
//! * **`CONNECT host:port`** — we answer `200`, take over the tunnel, terminate
//!   TLS with a freshly-minted per-host certificate, then serve the decrypted
//!   inner connection (HTTP/1.x *or* HTTP/2, chosen by ALPN). Every decrypted
//!   request/response passes through the inspect hooks before being re-encrypted
//!   toward the origin.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::uri::Authority;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::error::{ProxyError, Result};
use crate::inspect::{BufferedResponse, ConnMeta, Protocol, RequestAction};
use crate::state::SharedState;
use crate::util::{
    absolute_uri, authority_display, ensure_host_header, is_ip_literal, snapshot_request_head,
    strip_hop_by_hop, strip_port,
};
use rustls::pki_types::ServerName;

/// Bind and serve the HTTP/1.x + HTTP/2 forward proxy until the process exits.
pub async fn serve(state: SharedState) -> Result<()> {
    let addr = state.config.listen_addr;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ProxyError::Bind { addr, source })?;
    info!("HTTP/1.x + HTTP/2 proxy listening on http://{addr}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, peer, state).await {
                debug!("client connection {peer} ended: {e:#}");
            }
        });
    }
}

/// Serve one browser<->proxy TCP connection (HTTP/1.1, with CONNECT upgrades).
async fn serve_connection(stream: TcpStream, peer: SocketAddr, state: SharedState) -> Result<()> {
    stream.set_nodelay(true).ok();
    let io = TokioIo::new(stream);

    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(outer_handler(req, peer, state).await) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(|e| eyre::eyre!("serving client connection: {e}"))
}

/// Dispatch a request from the browser: CONNECT tunnels vs. plaintext forwards.
async fn outer_handler(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: SharedState,
) -> Response<Full<Bytes>> {
    if req.method() == Method::CONNECT {
        // e.g. `CONNECT example.com:443`.
        let Some(authority) = req.uri().authority().cloned() else {
            return simple(StatusCode::BAD_REQUEST, "CONNECT requires an authority");
        };

        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let io = TokioIo::new(upgraded);
                    if let Err(e) = mitm_tunnel(io, authority, peer, state).await {
                        debug!("MITM tunnel error: {e:#}");
                    }
                }
                Err(e) => debug!("CONNECT upgrade failed: {e}"),
            }
        });

        // `200` tells the browser the tunnel is established; body is empty.
        Response::new(Full::new(Bytes::new()))
    } else {
        forward_plaintext(req, peer, state).await
    }
}

/// Handle a cleartext, absolute-form request (`GET http://host/path`).
async fn forward_plaintext(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: SharedState,
) -> Response<Full<Bytes>> {
    let uri = req.uri().clone();
    let Some(host) = uri.host().map(str::to_owned) else {
        return simple(
            StatusCode::BAD_REQUEST,
            "expected absolute-form request URI",
        );
    };
    let port = uri.port_u16().unwrap_or(80);

    let meta = ConnMeta {
        client_addr: peer,
        protocol: Protocol::Http1,
        is_tls: false,
        authority: authority_display(&host, port, false),
    };

    relay(req, meta, false, host, port, state).await
}

/// Terminate TLS on an accepted CONNECT tunnel and serve the decrypted stream.
async fn mitm_tunnel<I>(
    io: I,
    authority: Authority,
    peer: SocketAddr,
    state: SharedState,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    let acceptor = TlsAcceptor::from(state.server_tls.clone());
    let tls = acceptor
        .accept(io)
        .await
        .map_err(|e| ProxyError::ClientHandshake(e.to_string()))?;

    // ALPN tells us which HTTP version the client negotiated inside the tunnel.
    let protocol = match tls.get_ref().1.alpn_protocol() {
        Some(b"h2") => Protocol::Http2,
        _ => Protocol::Http1,
    };
    debug!("MITM {host}:{port} negotiated {protocol}");

    let host = Arc::new(host);
    let hyper_io = TokioIo::new(tls);

    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let host = host.clone();
        async move {
            let meta = ConnMeta {
                client_addr: peer,
                protocol,
                is_tls: true,
                authority: authority_display(&host, port, true),
            };
            Ok::<_, Infallible>(relay(req, meta, true, host.to_string(), port, state).await)
        }
    });

    // `auto` serves either HTTP/1.x or HTTP/2 based on the negotiated protocol.
    auto::Builder::new(TokioExecutor::new())
        .serve_connection(hyper_io, service)
        .await
        .map_err(|e| eyre::eyre!("serving decrypted connection: {e}"))
}

/// Choose the upstream host for a request. When the CONNECT target is an IP
/// literal (ace-tun falls back to the snooped IP when its DNS snoop misses),
/// the real hostname is recovered from the request itself — the URI authority
/// (`:authority` for HTTP/2, also absolute-form HTTP/1.1) first, then the
/// `Host` header with any `:port` suffix stripped — so the upstream SNI
/// carries a domain instead of an IP (CDNs reject SNI literals with a
/// handshake failure). Returns `None` when the CONNECT target is already a
/// domain or the request offers no usable hostname; the caller then keeps the
/// CONNECT-derived host, so IP-literal requests that worked before keep
/// working.
fn upstream_host_for<B>(req: &Request<B>, connect_host: &str) -> Option<String> {
    if !is_ip_literal(connect_host) {
        return None;
    }
    let candidate = req
        .uri()
        .authority()
        .map(|authority| authority.host())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(strip_port)
        })?;
    if is_ip_literal(candidate) || ServerName::try_from(candidate.to_owned()).is_err() {
        return None;
    }
    Some(candidate.to_owned())
}

/// The shared request pipeline: buffer, inspect, forward upstream, inspect the
/// response, return it. `secure` selects the upstream scheme.
async fn relay(
    req: Request<Incoming>,
    meta: ConnMeta,
    secure: bool,
    host: String,
    port: u16,
    state: SharedState,
) -> Response<Full<Bytes>> {
    // An IP-literal CONNECT target must not be used as the upstream SNI — CDNs
    // reject SNI literals with a handshake failure. Prefer the hostname the
    // request itself carries (`:authority` for HTTP/2, `Host` for HTTP/1.x).
    let upstream_host = upstream_host_for(&req, &host).unwrap_or(host);

    // Rebuild an absolute target URI (origin-form requests inside a tunnel lack
    // scheme/authority; plaintext ones already have them).
    let abs_uri = match absolute_uri(req.uri(), &upstream_host, port, secure) {
        Ok(u) => u,
        Err(e) => return simple(StatusCode::BAD_REQUEST, &format!("bad request URI: {e}")),
    };

    // Buffer the request body so inspectors get the whole message.
    let (mut parts, body) = req.into_parts();
    parts.uri = abs_uri;
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return simple(
                StatusCode::BAD_REQUEST,
                &format!("reading request body: {e}"),
            );
        }
    };
    let mut buffered = Request::from_parts(parts, body_bytes);

    // --- request inspect hook -------------------------------------------
    match state
        .inspectors
        .request
        .inspect_request(&meta, &mut buffered)
        .await
    {
        RequestAction::Continue => {}
        RequestAction::Respond(resp) => return into_full(resp),
    }

    // Snapshot the (possibly-mutated) request head for the response hook, then
    // consume the request to build the upstream call.
    let (req_head, req_body) = buffered.into_parts();
    let head_snapshot = snapshot_request_head(&req_head);

    let mut ureq = Request::from_parts(req_head, Full::new(req_body));
    strip_hop_by_hop(ureq.headers_mut());
    ensure_host_header(&mut ureq, &upstream_host, port, secure);

    // --- forward upstream -----------------------------------------------
    let upstream_resp = match state
        .upstream
        .send(secure, &upstream_host, port, ureq)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("upstream {upstream_host}:{port} failed: {e:#}");
            return simple(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    // --- response inspect hook ------------------------------------------
    let mut buffered_resp: BufferedResponse = upstream_resp;
    state
        .inspectors
        .response
        .inspect_response(&meta, &head_snapshot, &mut buffered_resp)
        .await;

    into_full(buffered_resp)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Convert a buffered response into one hyper can serve, fixing framing headers.
fn into_full(resp: Response<Bytes>) -> Response<Full<Bytes>> {
    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    // Body is fully buffered: let hyper set an accurate Content-Length.
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Full::new(body))
}

/// A tiny plaintext response (used for proxy-level errors).
fn simple(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(msg.to_owned())))
        .expect("static response is always valid")
}
