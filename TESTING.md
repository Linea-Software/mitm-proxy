# mitm-proxy Test Suite

## Quick start

```sh
# Run the full suite (unit + integration + CLI + doc tests)
cargo test

# Run only unit tests (fast, no network)
cargo test --lib

# Run a specific test binary
cargo test --test proxy_http3

# Run with tracing output visible
RUST_LOG=mitm_proxy=debug cargo test -- --nocapture
```

## Prerequisites

- **Rust 1.97+** (edition 2024)
- **Windows 11** — the test suite is designed for Windows; some tests may not
  work on other platforms without modification (the `cli_tests` binary tests
  launch the compiled exe and expect Windows path behavior).

No external services are required — all tests spin up local echo servers inside
the process.

## Test structure

### Unit tests (`src/` — in-module `#[cfg(test)]`)

| Module | Tests | What they cover |
|--------|-------|-----------------|
| `config` | 4 | Builder field defaults, CA paths, `with_http3`/`install_ca`/`verify_upstream` |
| `error` | 4 | `ProxyError` variants display correctly |
| `inspect` | 7 | `NoopInspector`, custom inspectors, mutation, `RequestAction::Respond`, `Protocol::Display`, `ConnMeta` |
| `ca` | 10 | Root generation (SKI, BasicConstraints), leaf issuance (CN+SAN, IP SAN, AKI presence, AKI matches CA's SKI, validity ≤398 days, signature verification against CA), `load_or_generate` persistence |
| `cert_resolver` | 4 | Cert minting by SNI, Arc caching, IP SNI, separate cache entries per host |
| `tls` | 5 | Server ALPN (TCP/H3), client config with/without verification, ALPN set |
| `util` | 11 | `authority_display` (default/non-default ports), `absolute_uri` (upgrade/passthrough), `snapshot_request_head`, `strip_hop_by_hop` (all 9 headers), `ensure_host_header` (h1/h2/h3/already-present) |

### Integration tests (`tests/`)

| Test file | Tests | Protocol | What they cover |
|-----------|-------|----------|-----------------|
| `ca_tests.rs` | 3 | — | First-run CA generation, second-run reuse, leaf cache reuse |
| `cli_tests.rs` | 8 | — | Compile binary `--help`/`--version`, `--listen`, `--http3`, `--ca-dir`, `--insecure-upstream`, starts without `--install-ca`, defaults shown in help |
| `inspector_tests.rs` | 4 | HTTPS | Observer counts calls, request header mutation, response body mutation, `RequestAction::Respond` blocks upstream |
| `proxy_http1.rs` | 4 | HTTP/1.1 | Plaintext forward, CONNECT MITM GET, CONNECT MITM POST body round-trip, custom header |
| `proxy_http2.rs` | 3 | HTTP/2 | CONNECT+MITM GET, POST body, two concurrent multiplexed streams on one h2 connection |
| `proxy_http3.rs` | 3 | HTTP/3 (QUIC) | GET body, POST body round-trip, stream finishes cleanly (FIN regression test) |

All integration tests use hermetically-bound local echo servers on
`127.0.0.1:0` (ephemeral ports). The proxy runs **in-process** via
`MitmProxy::new(...)`. No internet access is required.

### CLI binary tests (`tests/cli_tests.rs`)

These launch the **compiled `mitm-proxy.exe`** binary via `assert_cmd` and
verify flags, port binding, and CA file creation. They are separate from the
library tests and prove the compiled binary + clap wiring works.

## HTTP/3 test client

The h3 tests use a **Rust in-process HTTP/3 client** (`h3` + `h3-quinn` +
`quinn`) that drives our own server directly. This is the canonical h3
regression test and avoids external dependencies on aioquic or other Python
clients.

## HTTP/3 stream-FIN bug — resolved

**Root cause:** `h3` 0.0.8 writes a **GREASE frame** on the first request
stream of each connection during `finish()`. The aioquic Python client does not
handle the GREASE-frame-then-FIN sequence correctly, causing it to never see
the QUIC stream FIN.

**Fix:** Disable GREASE frames in the h3 server with `.send_grease(false)` on
the connection builder (`src/http3.rs` line 68). The Rust in-process h3 client
in the test suite handles this correctly either way, and is the canonical
integration test for HTTP/3.

## `#[ignore]`d / network-dependent tests

There are **none** currently. All tests are hermetic. If network-dependent
tests are added in the future, gate them behind `#[ignore]` or an environment
variable.

## Tools used

- **Test framework:** `cargo test` (Rust built-in)
- **CLI assertion:** `assert_cmd` + `predicates`
- **Certificate parsing:** `x509-parser` (with `verify` feature for signature checks)
- **Temp directories:** `tempfile`
- **HTTP libraries:** `hyper`, `hyper-util`, `h3`, `h3-quinn`, `quinn`, `tokio-rustls`

## Known warnings

The `tests/common/mod.rs` helper module has `#[allow(dead_code)]` annotations
on functions that are only used by a subset of test binaries. This is a
consequence of Rust's per-binary test compilation model and is harmless.
