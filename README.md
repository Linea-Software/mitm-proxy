# mitm-proxy

A standalone man-in-the-middle proxy that terminates and inspects every major
HTTP version and its secure counterpart. Written in Rust (edition 2024).

```rust
use std::sync::Arc;
use mitm_proxy::{MitmProxy, ProxyConfig};
use mitm_proxy::inspect::LoggingInspector;

let config = ProxyConfig::new("127.0.0.1:8080".parse().unwrap(), "./ca");
MitmProxy::new(config)
    .with_request_inspector(Arc::new(LoggingInspector))
    .with_response_inspector(Arc::new(LoggingInspector))
    .run()
    .await?;
```

## Features

- **HTTP/1.0 / HTTP/1.1** — forward proxy (plaintext forwarding and CONNECT
  tunnelling), TLS terminated with a dynamically-issued per-host cert.
- **HTTP/2** — served over the decrypted CONNECT tunnel, chosen by ALPN,
  with multiplexed streams handled by hyper.
- **HTTP/3 (QUIC)** — a QUIC endpoint that terminates the transport and
  decodes HTTP/3 request streams.
- **Transparent inspect point** — every decrypted request/response passes
  through caller-supplied `RequestInspector` / `ResponseInspector` hooks for
  observation, mutation, or blocking (synthetic responses).
- **Dynamic certificate authority** — auto-generates a root CA on first run,
  mints per-host leaf certs signed by that CA during each intercepted TLS
  handshake. Clients that trust the root CA see valid TLS chains.
- **GREASE-free HTTP/3** — the h3 server explicitly disables GREASE frames
  for compatibility with strict HTTP/3 clients.

## CLI

```text
Standalone MITM proxy for HTTP/1.x, HTTP/2 and HTTP/3.

Usage: mitm-proxy [OPTIONS]

Options:
  -l, --listen <LISTEN>      TCP address to listen on [default: 127.0.0.1:8080]
      --http3 <HTTP3>        Also start an HTTP/3 (QUIC) listener on this UDP address
      --ca-dir <CA_DIR>      Directory for the generated CA [default: ./mitm-ca]
      --install-ca           Install CA into the OS trust store (requires elevation)
      --insecure-upstream    Skip upstream TLS verification (testing only)
  -h, --help                 Print help
  -V, --version              Print version
```

## Architecture

```
┌─────────┐    CONNECT      ┌─────────────┐    HTTPS/1.1    ┌──────────┐
│ Browser  │ ──────────────→ │  mitm-proxy  │ ─────────────→ │  Origin  │
│ (HTTP/1) │ ←────────────── │    (TCP)     │ ←───────────── │ (HTTP/1) │
└─────────┘                  └─────────────┘                 └──────────┘
                                      │
┌─────────┐    h2 (ALPN)     ┌─────────────┐    HTTP/2       ┌──────────┐
│ Browser  │ ──────────────→ │  mitm-proxy  │ ─────────────→ │  Origin  │
│ (HTTP/2) │ ←────────────── │  (TLS term)  │ ←───────────── │ (HTTP/2) │
└─────────┘                  └─────────────┘                 └──────────┘
                                      │
┌─────────┐    QUIC / h3     ┌─────────────┐    HTTPS        ┌──────────┐
│  Client  │ ──────────────→ │  mitm-proxy  │ ─────────────→ │  Origin  │
│ (HTTP/3) │ ←────────────── │   (UDP)      │ ←───────────── │(HTTP/1/2)│
└─────────┘                  └─────────────┘                 └──────────┘
                                      │
                               ┌──────┴──────┐
                               │  Inspectors  │
                               │ (observe /   │
                               │  mutate /    │
                               │  block)      │
                               └─────────────┘
```

### Key design decisions

| Decision | Rationale |
|----------|-----------|
| **Bodies buffered to `Bytes`** | Keeps the inspect hook simple and makes modification trivial, at the cost of not streaming very large payloads. Acceptable for an inspection-focused MITM. |
| **No connection pooling upstream** | Each request gets its own upstream connection. Keeps the code self-contained; pooling is a documented non-goal. |
| **`.send_grease(false)` on h3** | `h3` 0.0.8 writes GREASE frames during `finish()` on the first request per connection, which confuses strict h3 clients (notably aioquic). Disabled to maximise interop. |
| **Dynamic per-host leaf certs via rcgen** | The `DynamicCertResolver` mints and caches a leaf certificate per SNI host, signed by the proxy's root CA. The root CA is generated once and persisted to `./mitm-ca/`. |
| **`auto::Builder` for decrypted tunnels** | The decrypted CONNECT tunnel is served with hyper-util's `auto` builder, which negotiates HTTP/1.x or HTTP/2 based on ALPN without separate listener logic. |

## Source layout

| Module | Visibility | Purpose |
|--------|-----------|---------|
| `lib.rs` | — | `MitmProxy` builder (`new`, `with_request_inspector`, `run`), wires everything together |
| `main.rs` | — | CLI entry point (clap) |
| `config.rs` | `pub` | `ProxyConfig` builder |
| `error.rs` | `pub` | `ProxyError` enum, `Result<T>` alias |
| `inspect.rs` | `pub` | `Protocol`, `ConnMeta`, `RequestInspector`/`ResponseInspector` traits, `Inspectors` bundle, `NoopInspector`, `LoggingInspector` |
| `ca.rs` | `pub` | `CertAuthority` (load/generate, issue leaf certs, install to trust store) |
| `cert_resolver.rs` | `mod` | `DynamicCertResolver` — per-SNI leaf minting and caching for rustls |
| `tls.rs` | `mod` | `server_config`/`client_config` factory functions |
| `upstream.rs` | `mod` | `Upstream::send` — forward a buffered request to the origin |
| `http.rs` | `mod` | HTTP/1.x + HTTP/2 proxy listener, CONNECT handler, `relay` pipeline |
| `http3.rs` | `mod` | HTTP/3 (QUIC) listener, connection/request handlers |
| `state.rs` | `mod` | `ProxyState` / `SharedState` |
| `util.rs` | `mod` | `authority_display`, `absolute_uri`, `snapshot_request_head`, `ensure_host_header`, `strip_hop_by_hop` |

## Testing

```sh
# Run the full suite (71 tests — hermetic, no network required)
cargo test

# Run only unit tests
cargo test --lib

# Run a specific integration test binary
cargo test --test proxy_http3
```

See [`TESTING.md`](TESTING.md) for the full test suite breakdown and the
HTTP/3 stream-FIN bug postmortem.

## Dependencies

- **Async runtime:** tokio
- **HTTP framework:** hyper 1 + hyper-util (auto builder)
- **QUIC / HTTP/3:** quinn 0.11 + h3 0.0.8 + h3-quinn 0.0.10
- **TLS:** rustls 0.23 (ring crypto provider), tokio-rustls 0.26
- **Certificate generation:** rcgen 0.14 (x509-parser feature)
- **Parsing & validation:** x509-parser 0.17
- **Error handling:** eyre / color-eyre + thiserror
- **Logging:** tracing + tracing-subscriber
- **CLI:** clap (derive)
- **Entropy / time:** time

## License

MIT OR Apache-2.0
