//! HTTP/3 over QUIC interception.
//!
//! Unlike the TCP proxy there is no cleartext CONNECT step in QUIC: a client
//! that reaches this UDP endpoint is already speaking QUIC + HTTP/3 to us. We
//! terminate QUIC with a per-host certificate (same [`DynamicCertResolver`] the
//! TCP side uses), decode each HTTP/3 request, run it through the inspect hooks,
//! and forward it upstream over HTTPS (HTTP/2 or HTTP/1.x — protocol downgrade
//! toward the origin is transparent to the client).
//!
//! QUIC concerns the task didn't have to solve by hand are handled by quinn:
//! * unreliable UDP transport, loss recovery and flow control,
//! * connection migration across network paths,
//! * 0-RTT (accepted when the client offers it and the TLS config allows it).
//!
//! Each request stream is served on its own task, so the multiplexed streams of
//! one connection are handled concurrently.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tracing::{debug, info, warn};

use crate::error::Result;
use crate::inspect::{ConnMeta, Protocol, RequestAction};
use crate::state::SharedState;
use crate::util::{absolute_uri, ensure_host_header, snapshot_request_head, strip_hop_by_hop};

/// The h3 request stream type over a quinn connection, carrying `Bytes` bodies.
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Bind the QUIC endpoint and serve HTTP/3 until the process exits.
pub async fn serve(state: SharedState, addr: SocketAddr) -> Result<()> {
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(state.h3_tls.clone())
        .map_err(|e| eyre::eyre!("building QUIC server crypto: {e}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .map_err(|e| eyre::eyre!("binding QUIC endpoint on {addr}: {e}"))?;
    info!("HTTP/3 (QUIC) proxy listening on udp://{addr}");

    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(incoming, state).await {
                debug!("h3 connection ended: {e:#}");
            }
        });
    }

    Ok(())
}

/// Complete the QUIC handshake and serve every HTTP/3 request on the connection.
async fn serve_connection(incoming: quinn::Incoming, state: SharedState) -> Result<()> {
    let connecting = incoming
        .accept()
        .map_err(|e| eyre::eyre!("accepting QUIC connection: {e}"))?;
    let conn = connecting
        .await
        .map_err(|e| eyre::eyre!("QUIC handshake failed: {e}"))?;
    let peer = conn.remote_address();
    debug!("QUIC connection established from {peer}");

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
        .send_grease(false)
        .build(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| eyre::eyre!("establishing h3 connection: {e}"))?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            debug!("resolving h3 request failed: {e}");
                            return;
                        }
                    };
                    if let Err(e) = handle_request(req, stream, peer, state).await {
                        debug!("h3 request error: {e:#}");
                    }
                });
            }
            // No more requests on this connection.
            Ok(None) => break,
            Err(e) => {
                debug!("h3 accept error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single decoded HTTP/3 request end-to-end.
async fn handle_request(
    req: Request<()>,
    mut stream: H3Stream,
    peer: SocketAddr,
    state: SharedState,
) -> Result<()> {
    let (parts, ()) = req.into_parts();

    // The `:authority`/`:scheme`/`:path` pseudo-headers give us an absolute URI.
    let Some(host) = parts.uri.host().map(str::to_owned) else {
        return respond_error(&mut stream, StatusCode::BAD_REQUEST, "missing :authority").await;
    };
    let port = parts.uri.port_u16().unwrap_or(443);
    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    // Drain the request body from the QUIC stream.
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| eyre::eyre!("reading h3 request body: {e}"))?
    {
        body.put(&mut chunk);
    }
    let body = body.freeze();

    let meta = ConnMeta {
        client_addr: peer,
        protocol: Protocol::Http3,
        is_tls: true,
        authority,
    };

    let mut buffered = Request::from_parts(parts, body);

    // Rebuild an absolute target URI to match TCP path behaviour inside the
    // tunnel — origin-form URIs from HTTP/3 pseudo-headers may lack
    // scheme/authority depending on the h3 library version.
    let abs_uri = absolute_uri(buffered.uri(), &host, port, true)
        .map_err(|e| eyre::eyre!("bad h3 request URI: {e}"))?;
    let (mut new_parts, new_body) = buffered.into_parts();
    new_parts.uri = abs_uri;
    buffered = Request::from_parts(new_parts, new_body);

    // --- request inspect hook -------------------------------------------
    match state
        .inspectors
        .request
        .inspect_request(&meta, &mut buffered)
        .await
    {
        RequestAction::Continue => {}
        RequestAction::Respond(resp) => return send_response(&mut stream, resp).await,
    }

    // Build the upstream call (always HTTPS from an intercepted h3 request).
    let (req_head, req_body) = buffered.into_parts();
    let head_snapshot = snapshot_request_head(&req_head);
    let mut ureq = Request::from_parts(req_head, Full::new(req_body));
    strip_hop_by_hop(ureq.headers_mut());
    ensure_host_header(&mut ureq, &host, port, true);

    // --- forward upstream -----------------------------------------------
    let upstream_resp = match state.upstream.send(true, &host, port, ureq).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("h3 upstream {host}:{port} failed: {e:#}");
            return respond_error(&mut stream, StatusCode::BAD_GATEWAY, "upstream failed").await;
        }
    };

    // --- response inspect hook ------------------------------------------
    let mut buffered_resp = upstream_resp;
    state
        .inspectors
        .response
        .inspect_response(&meta, &head_snapshot, &mut buffered_resp)
        .await;

    send_response(&mut stream, buffered_resp).await
}

/// Send a buffered response over an HTTP/3 request stream.
async fn send_response(stream: &mut H3Stream, resp: Response<Bytes>) -> Result<()> {
    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    // HTTP/3 frames the body by stream length; drop HTTP/1-style framing hints.
    parts.headers.remove(http::header::CONTENT_LENGTH);
    parts.headers.remove(http::header::TRANSFER_ENCODING);
    // Do not advertise QUIC/H3 to the client: the UDP path is not available
    // through the proxy, and an `alt-svc` hint would make browsers retry there.
    parts.headers.remove(http::header::ALT_SVC);

    let head = Response::from_parts(parts, ());
    stream
        .send_response(head)
        .await
        .map_err(|e| eyre::eyre!("sending h3 response head: {e}"))?;

    if !body.is_empty() {
        stream
            .send_data(body)
            .await
            .map_err(|e| eyre::eyre!("sending h3 response body: {e}"))?;
    }

    stream
        .finish()
        .await
        .map_err(|e| eyre::eyre!("finishing h3 stream: {e}"))
}

/// Send a minimal error response over an HTTP/3 stream.
async fn respond_error(stream: &mut H3Stream, status: StatusCode, msg: &str) -> Result<()> {
    let resp = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::from(msg.to_owned()))
        .expect("static error response is valid");
    send_response(stream, resp).await
}
