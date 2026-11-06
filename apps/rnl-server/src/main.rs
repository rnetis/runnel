use std::sync::Arc;

use clap::Parser;
use rnl_config::ServerConfig;

#[derive(Parser)]
#[command(name = "rnl-server", version, about = "Runnel VPN server (RNL v1, UDP)")]
struct Args {
    /// Path to server.toml
    #[arg(short, long)]
    config: Option<String>,

    /// Listen address (overrides config)
    #[arg(long)]
    listen: Option<String>,

    /// Listen port (overrides config)
    #[arg(long)]
    port: Option<u16>,

    /// Echo mode: return decrypted packets to the client (loopback testing,
    /// no TUN privileges needed)
    #[arg(long)]
    echo: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let mut cfg = match &args.config {
        Some(p) => ServerConfig::load(std::path::Path::new(p))?,
        None => ServerConfig::parse(&std::env::var("RNL_SERVER_CONFIG").map_err(|_| {
            anyhow::anyhow!("pass --config server.toml or set RNL_SERVER_CONFIG")
        })?)?,
    };
    if let Some(l) = args.listen {
        cfg.server.listen = l;
    }
    if let Some(p) = args.port {
        cfg.server.port = p;
    }

    if args.echo {
        tracing::info!(port = cfg.server.port, "starting in echo (loopback) mode");
        rnl_server::run(cfg, Arc::new(rnl_tun::LoopbackDevice::new()), true).await?;
    } else {
        anyhow::bail!(
            "kernel TUN mode is not wired in v0.1 yet; use --echo to exercise the \
             full encrypted data path, or run a client against an echo server"
        );
    }
    Ok(())
}
