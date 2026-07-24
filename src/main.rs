//! CLI entry point: start the MITM proxy with a logging inspector.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use mitm_proxy::inspect::LoggingInspector;
use mitm_proxy::{MitmProxy, ProxyConfig};
use tracing_subscriber::EnvFilter;

/// Standalone MITM proxy for HTTP/1.x, HTTP/2 and HTTP/3.
#[derive(Debug, Parser)]
#[command(name = "mitm-proxy", version, about)]
struct Args {
    /// TCP address to listen on (HTTP/1.x + HTTP/2 forward proxy).
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Also start an HTTP/3 (QUIC) listener on this UDP address.
    #[arg(long)]
    http3: Option<SocketAddr>,

    /// Directory for the generated CA certificate and key.
    #[arg(long, default_value = "./mitm-ca")]
    ca_dir: PathBuf,

    /// Attempt to install the CA into the OS trust store on startup.
    #[arg(long)]
    install_ca: bool,

    /// Do not verify upstream (origin) TLS certificates. Testing only.
    #[arg(long)]
    insecure_upstream: bool,
}

#[tokio::main]
async fn main() -> mitm_proxy::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,mitm_proxy=debug")),
        )
        .init();

    let args = Args::parse();

    let mut config = ProxyConfig::new(args.listen, &args.ca_dir)
        .install_ca(args.install_ca)
        .verify_upstream(!args.insecure_upstream);
    if let Some(addr) = args.http3 {
        config = config.with_http3(addr);
    }

    MitmProxy::new(config)
        .with_request_inspector(Arc::new(LoggingInspector))
        .with_response_inspector(Arc::new(LoggingInspector))
        .run()
        .await
}
