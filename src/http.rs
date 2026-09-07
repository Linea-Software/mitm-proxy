//! HTTP/1.x and HTTP/2 forward proxy with TLS interception.
//!
//! The listener speaks HTTP/1.1 to the browser (the classic forward-proxy
//! protocol). Two request shapes arrive:
//!
//! * **Plaintext** (`GET http://host/path`) — forwarded directly to the origin
//!   over cleartext HTTP/1.x.
//! * **`CONNECT host:port`** — we answer `200`, then ask the
//!   [`InterceptDecider`](crate::InterceptDecider) whether to terminate TLS:
//!   approved tunnels are MITM'd with a freshly-minted per-host certificate
//!   and the decrypted inner connection is served (HTTP/1.x *or* HTTP/2,
//!   chosen by ALPN); rejected tunnels are relayed to the origin byte-for-byte
//!   with no TLS setup at all, so no certificate is minted and nothing is
//!   decrypted.

use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::uri::Authority;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::error::{ProxyError, Result};
use crate::inspect::{ConnMeta, Protocol, RequestAction, ResponseBodyMode};
use crate::state::SharedState;
use crate::util::{
    absolute_uri, authority_display, ensure_host_header, is_ip_literal, snapshot_request_head,
    strip_hop_by_hop, strip_hop_by_hop_for_upgrade, strip_port,
};
use rustls::pki_types::ServerName;

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

// Browser HTTP/2 requests can legitimately exceed Hyper's 16 KiB default once
// cookies and client-hint headers accumulate. Keep the limit bounded while
// leaving enough headroom for header-heavy applications such as ChatGPT.
const CLIENT_HTTP2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

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
        debug!(client = %peer, "accepted proxy client TCP connection");
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
) -> Response<ProxyBody> {
    if req.method() == Method::CONNECT {
        // e.g. `CONNECT example.com:443`.
        let Some(authority) = req.uri().authority().cloned() else {
            return simple(StatusCode::BAD_REQUEST, "CONNECT requires an authority");
        };
        debug!(client = %peer, authority = %authority, "received CONNECT request");

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
        Response::new(full_body(Bytes::new()))
    } else {
        forward_plaintext(req, peer, state).await
    }
}

/// Handle a cleartext, absolute-form request (`GET http://host/path`).
async fn forward_plaintext(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: SharedState,
) -> Response<ProxyBody> {
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

    // Narrow interception: only terminate TLS for hosts the decider approves.
    // Anything else is relayed opaquely — no TLS setup runs on that branch, so
    // no leaf certificate is minted and no decryption happens. `sni` is a
    // placeholder (always `None` for now); see `InterceptDecider`.
    let should_intercept = state.intercept_decider.should_intercept(&authority, None);
    debug!(
        client = %peer,
        authority = %authority,
        should_intercept,
        "CONNECT interception decision"
    );
    if !should_intercept {
        return opaque_tunnel(io, &authority, &host, port).await;
    }

    let acceptor = TlsAcceptor::from(state.server_tls.clone());
    debug!(client = %peer, authority = %authority, "starting client TLS handshake");
    let tls = acceptor
        .accept(io)
        .await
        .map_err(|e| ProxyError::ClientHandshake(e.to_string()))?;

    // ALPN tells us which HTTP version the client negotiated inside the tunnel.
    let protocol = match tls.get_ref().1.alpn_protocol() {
        Some(b"h2") => Protocol::Http2,
        _ => Protocol::Http1,
    };
    debug!(
        client = %peer,
        authority = %authority,
        protocol = %protocol,
        "client TLS handshake completed"
    );

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
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http2()
        .max_header_list_size(CLIENT_HTTP2_MAX_HEADER_LIST_SIZE)
        .enable_connect_protocol();
    builder
        .serve_connection_with_upgrades(hyper_io, service)
        .await
        .map_err(|e| eyre::eyre!("serving decrypted connection: {e}"))
}

/// Relay a CONNECT tunnel to the origin without touching TLS.
///
/// Both directions are copied verbatim: no certificate is minted and no bytes
/// are decrypted. This branch is intentionally free of any TLS setup so the
/// no-TLS invariant is auditable at a glance.
async fn opaque_tunnel<I>(io: I, authority: &Authority, host: &str, port: u16) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut upstream =
        TcpStream::connect((host, port))
            .await
            .map_err(|source| ProxyError::Upstream {
                authority: authority.to_string(),
                source: eyre::eyre!(source),
            })?;
    upstream.set_nodelay(true).ok();

    let mut client = io;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|e| eyre::eyre!("opaque tunnel relay to {authority} failed: {e}"))?;
    Ok(())
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
) -> Response<ProxyBody> {
    // An IP-literal CONNECT target must not be used as the upstream SNI — CDNs
    // reject SNI literals with a handshake failure. Prefer the hostname the
    // request itself carries (`:authority` for HTTP/2, `Host` for HTTP/1.x).
    let upstream_host = upstream_host_for(&req, &host).unwrap_or(host);
    debug!(
        client = %meta.client_addr,
        protocol = %meta.protocol,
        tls = meta.is_tls,
        method = %req.method(),
        version = ?req.version(),
        path = %req.uri().path(),
        authority = %meta.authority,
        upstream_host = %upstream_host,
        upstream_port = port,
        "relaying request"
    );

    // Rebuild an absolute target URI (origin-form requests inside a tunnel lack
    // scheme/authority; plaintext ones already have them).
    let abs_uri = match absolute_uri(req.uri(), &upstream_host, port, secure) {
        Ok(u) => u,
        Err(e) => return simple(StatusCode::BAD_REQUEST, &format!("bad request URI: {e}")),
    };

    // HTTP/2 Extended CONNECT carries the tunneled protocol in the request and
    // response body streams. Aggregating either side would deadlock a long-lived
    // WebSocket, so inspect only the request head and relay both bodies.
    if req.method() == Method::CONNECT
        && req.version() == http::Version::HTTP_2
        && req.extensions().get::<hyper::ext::Protocol>().is_some()
    {
        return relay_extended_connect(req, meta, secure, upstream_host, port, state, abs_uri).await;
    }

    let mut req = req;
    let client_upgrade = if is_http1_upgrade_request(&req) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    // Buffer ordinary request bodies so inspectors retain their mutation API.
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
    debug!(
        client = %meta.client_addr,
        method = %parts.method,
        path = %parts.uri.path(),
        request_body_bytes = body_bytes.len(),
        "request body buffered"
    );
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
    if client_upgrade.is_some() {
        strip_hop_by_hop_for_upgrade(ureq.headers_mut());
    } else {
        strip_hop_by_hop(ureq.headers_mut());
    }
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

    finish_upstream_response(upstream_resp, meta, head_snapshot, state, client_upgrade).await
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn is_http1_upgrade_request<B>(req: &Request<B>) -> bool {
    if req.version() != http::Version::HTTP_11
        || !req.headers().contains_key(http::header::UPGRADE)
    {
        return false;
    }

    req.headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

async fn relay_extended_connect(
    req: Request<Incoming>,
    meta: ConnMeta,
    secure: bool,
    upstream_host: String,
    port: u16,
    state: SharedState,
    abs_uri: http::Uri,
) -> Response<ProxyBody> {
    let (mut parts, body) = req.into_parts();
    let extended_protocol = parts.extensions.get::<hyper::ext::Protocol>().cloned();
    parts.uri = abs_uri;

    // The CONNECT body is the tunneled byte stream. Give inspectors the request
    // metadata with an empty body so blocking decisions still run without
    // consuming the protocol stream.
    let mut buffered_head = Request::from_parts(snapshot_request_head(&parts), Bytes::new());
    match state
        .inspectors
        .request
        .inspect_request(&meta, &mut buffered_head)
        .await
    {
        RequestAction::Continue => {}
        RequestAction::Respond(resp) => return into_full(resp),
    }

    let (mut req_head, _) = buffered_head.into_parts();
    if let Some(protocol) = extended_protocol {
        req_head.extensions.insert(protocol);
    }
    let head_snapshot = snapshot_request_head(&req_head);

    let mut ureq = Request::from_parts(req_head, body);
    strip_hop_by_hop(ureq.headers_mut());
    ensure_host_header(&mut ureq, &upstream_host, port, secure);

    let upstream_resp = match state
        .upstream
        .send(secure, &upstream_host, port, ureq)
        .await
    {
        Ok(resp) => resp,
        Err(error) => {
            warn!("extended CONNECT upstream {upstream_host}:{port} failed: {error:#}");
            return simple(StatusCode::BAD_GATEWAY, "upstream extended CONNECT failed");
        }
    };

    finish_upstream_response(upstream_resp, meta, head_snapshot, state, None).await
}

async fn finish_upstream_response(
    mut upstream_resp: Response<Incoming>,
    meta: ConnMeta,
    head_snapshot: http::request::Parts,
    state: SharedState,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response<ProxyBody> {
    if client_upgrade.is_some() && upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);
        let (parts, _) = upstream_resp.into_parts();
        let mut response_head = Response::from_parts(parts, Bytes::new());
        state
            .inspectors
            .response
            .inspect_response_head(&meta, &head_snapshot, &mut response_head)
            .await;
        let (mut parts, _) = response_head.into_parts();
        strip_hop_by_hop_for_upgrade(&mut parts.headers);

        let client_upgrade = client_upgrade.expect("upgrade request checked above");
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((client, upstream)) => {
                    let mut client = TokioIo::new(client);
                    let mut upstream = TokioIo::new(upstream);
                    if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        debug!("upgraded protocol relay ended: {error}");
                    }
                }
                Err(error) => debug!("protocol upgrade failed: {error}"),
            }
        });

        return Response::from_parts(parts, full_body(Bytes::new()));
    }

    let (parts, body) = upstream_resp.into_parts();
    let mut response_head = Response::from_parts(parts, Bytes::new());
    state
        .inspectors
        .response
        .inspect_response_head(&meta, &head_snapshot, &mut response_head)
        .await;
    let body_mode = state
        .inspectors
        .response
        .response_body_mode(&meta, &head_snapshot, &response_head);
    debug!(
        client = %meta.client_addr,
        protocol = %meta.protocol,
        method = %head_snapshot.method,
        path = %head_snapshot.uri.path(),
        status = %response_head.status(),
        body_mode = ?body_mode,
        "upstream response ready for client"
    );
    let (mut parts, _) = response_head.into_parts();

    match body_mode {
        ResponseBodyMode::Stream => {
            strip_hop_by_hop(&mut parts.headers);
            Response::from_parts(parts, streaming_body(body))
        }
        ResponseBodyMode::Buffer => {
            let body = match body.collect().await {
                Ok(body) => body.to_bytes(),
                Err(error) => {
                    warn!("reading upstream response body failed: {error}");
                    return simple(StatusCode::BAD_GATEWAY, "reading upstream response failed");
                }
            };
            let mut buffered = Response::from_parts(parts, body);
            state
                .inspectors
                .response
                .inspect_response(&meta, &head_snapshot, &mut buffered)
                .await;
            into_full(buffered)
        }
    }
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never: Infallible| -> BoxError { match never {} })
        .boxed_unsync()
}

fn streaming_body(body: Incoming) -> ProxyBody {
    body.map_err(|error| Box::new(error) as BoxError)
        .boxed_unsync()
}

/// Convert a buffered response into one hyper can serve, fixing framing headers.
fn into_full(resp: Response<Bytes>) -> Response<ProxyBody> {
    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    // Body is fully buffered: let hyper set an accurate Content-Length.
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, full_body(body))
}

/// A tiny plaintext response (used for proxy-level errors).
fn simple(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(msg.to_owned())))
        .expect("static response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertAuthority;
    use crate::cert_resolver::DynamicCertResolver;
    use crate::inspect::Inspectors;
    use crate::state::ProxyState;
    use crate::upstream::Upstream;
    use crate::{NoInterceptDecider, ProxyConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Read exactly `buf.len()` bytes from `stream`.
    async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) {
        let mut got = 0;
        while got < buf.len() {
            let n = stream.read(&mut buf[got..]).await.unwrap();
            assert!(
                n > 0,
                "connection closed after {} of {} bytes",
                got,
                buf.len()
            );
            got += n;
        }
    }

    /// Raw CONNECT through the proxy, asserting a `200` response head.
    async fn raw_connect(proxy_addr: SocketAddr, host: &str, port: u16) -> TcpStream {
        let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
        tcp.set_nodelay(true).ok();

        let connect_req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        tcp.write_all(connect_req.as_bytes()).await.unwrap();

        let mut buf = [0u8; 4096];
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
        let head = String::from_utf8_lossy(&buf[..total]);
        assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
        tcp
    }

    /// Invariant: a tunnel the decider rejects must never mint a leaf
    /// certificate for the host.
    ///
    /// This lives in the crate (rather than `tests/`) because the certificate
    /// cache lives inside `DynamicCertResolver`, which `MitmProxy::run`
    /// constructs internally and does not expose. Here we build the same
    /// [`ProxyState`] `run` would build, but keep the resolver so we can
    /// assert on its cache after the relay completes.
    #[tokio::test]
    async fn tunneled_host_gets_no_certificate_minted() {
        crate::install_crypto_provider();

        // Raw byte origin: pushes a banner, echoes everything back, and
        // signals when the connection closes so the test knows the tunneled
        // relay has fully completed.
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = origin_listener.local_addr().unwrap();
        let banner: Vec<u8> = (0..257u32).map(|i| (i % 251) as u8).collect();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let banner_for_server = banner.clone();
        tokio::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let _ = stream.write_all(&banner_for_server).await;
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = close_tx.send(());
        });

        // Same state construction `MitmProxy::run` uses, with a resolver the
        // test holds on to.
        let (cert_pem, key_pem) = CertAuthority::generate_root().unwrap();
        let ca = Arc::new(CertAuthority::from_pem(cert_pem, &key_pem).unwrap());
        let resolver = Arc::new(DynamicCertResolver::new(ca));
        let server_tls = crate::tls::server_config(resolver.clone(), crate::tls::TCP_ALPN);
        let client_tls = crate::tls::client_config(false, crate::tls::TCP_ALPN);

        let ca_dir = tempfile::TempDir::new().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        drop(proxy_listener);

        let state = Arc::new(ProxyState {
            server_tls,
            h3_tls: crate::tls::server_config(resolver.clone(), crate::tls::H3_ALPN),
            upstream: Upstream::new(client_tls),
            inspectors: Inspectors::default(),
            intercept_decider: Arc::new(NoInterceptDecider),
            config: Arc::new(ProxyConfig::new(proxy_addr, ca_dir.path())),
        });
        let serve_handle = tokio::spawn(async move {
            let _ = serve(state).await;
        });

        // Let the listener bind before connecting.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // The decider (NoInterceptDecider) rejects everything: the tunnel must
        // be relayed raw, so verify bytes flow both ways untouched.
        let mut tunnel = raw_connect(proxy_addr, "127.0.0.1", origin.port()).await;
        let mut got_banner = vec![0u8; banner.len()];
        read_exact(&mut tunnel, &mut got_banner).await;
        assert_eq!(got_banner, banner);

        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        tunnel.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        read_exact(&mut tunnel, &mut echoed).await;
        assert_eq!(echoed, payload);

        // Close the client side and wait for the relay to wind down.
        drop(tunnel);
        let _ = close_rx.await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The core invariant: no leaf certificate was minted for the tunneled
        // host — in fact the cache must be entirely empty.
        assert!(
            !resolver.has_cached_key("127.0.0.1"),
            "tunneled host must not have a cached certificate"
        );
        assert_eq!(
            resolver.cache_len(),
            0,
            "no certificate may be minted on the opaque tunnel path"
        );

        serve_handle.abort();
    }
}
