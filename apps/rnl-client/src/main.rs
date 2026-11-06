use clap::Parser;
use rnl_config::ClientConfig;

#[derive(Parser)]
#[command(name = "rnl-client", version, about = "Runnel VPN client (RNL v1, UDP)")]
struct Args {
    /// Path to client.toml
    #[arg(short, long)]
    config: Option<String>,

    /// Server endpoint host:port (overrides config)
    #[arg(long)]
    server: Option<String>,

    /// Loopback echo demo: send 100 synthetic packets through the tunnel
    /// and verify the encrypted echo. Useful as a smoke test.
    #[arg(long)]
    echo_demo: bool,
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
        Some(p) => ClientConfig::load(std::path::Path::new(p))?,
        None => ClientConfig::parse(&std::env::var("RNL_CLIENT_CONFIG").map_err(|_| {
            anyhow::anyhow!("pass --config client.toml or set RNL_CLIENT_CONFIG")
        })?)?,
    };
    if let Some(s) = args.server {
        cfg.client.server = s;
    }

    if args.echo_demo {
        let stats = rnl_client::run_echo_demo(cfg).await?;
        println!(
            "echo demo: sent {} packets, received {}, verified {} — {}",
            stats.sent,
            stats.received,
            stats.verified,
            if stats.verified == stats.sent {
                "OK"
            } else {
                "MISMATCH"
            }
        );
        if stats.verified != stats.sent {
            anyhow::bail!("echo verification failed");
        }
    } else {
        anyhow::bail!(
            "kernel TUN mode is not wired in v0.1 yet; use --echo-demo to exercise \
             the full encrypted path"
        );
    }
    Ok(())
}
