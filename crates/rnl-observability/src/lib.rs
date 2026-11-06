//! RNL metrics registry (Phase 5: observability).
//!
//! Lock-free counters over atomics; rendered in Prometheus text format.
//! Secrets (keys, PSKs, plaintext payloads) never pass through telemetry —
//! the registry only sees counts, sizes and durations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Canonical metric set (design doc §10 + operational additions).
pub const METRIC_NAMES: &[&str] = &[
    "rnl_sessions_active",
    "rnl_sessions_established_total",
    "rnl_sessions_closed_total",
    "rnl_bytes_tx_total",
    "rnl_bytes_rx_total",
    "rnl_packets_tx_total",
    "rnl_packets_rx_total",
    "rnl_packets_dropped_total",
    "rnl_replay_rejections_total",
    "rnl_transport_reconnections_total",
    "rnl_handshake_duration_ms",
    "rnl_mtu_bytes",
];

pub const SESSIONS_ACTIVE: usize = 0;
pub const SESSIONS_ESTABLISHED: usize = 1;
pub const SESSIONS_CLOSED: usize = 2;
pub const BYTES_TX: usize = 3;
pub const BYTES_RX: usize = 4;
pub const PACKETS_TX: usize = 5;
pub const PACKETS_RX: usize = 6;
pub const PACKETS_DROPPED: usize = 7;
pub const REPLAY_REJECTIONS: usize = 8;
pub const TRANSPORT_RECONNECTIONS: usize = 9;
pub const HANDSHAKE_DURATION_MS: usize = 10;
pub const MTU_BYTES: usize = 11;

/// Process-wide registry.
pub struct Metrics {
    values: Vec<AtomicU64>,
}

static GLOBAL: OnceLock<Metrics> = OnceLock::new();

impl Metrics {
    fn new() -> Self {
        Self {
            values: METRIC_NAMES.iter().map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// The process-global registry (created on first use).
    pub fn global() -> &'static Metrics {
        GLOBAL.get_or_init(Metrics::new)
    }

    pub fn inc(&self, metric: usize, by: u64) {
        if let Some(v) = self.values.get(metric) {
            v.fetch_add(by, Ordering::Relaxed);
        }
    }

    pub fn dec(&self, metric: usize, by: u64) {
        if let Some(v) = self.values.get(metric) {
            v.fetch_sub(by, Ordering::Relaxed);
        }
    }

    pub fn set(&self, metric: usize, value: u64) {
        if let Some(v) = self.values.get(metric) {
            v.store(value, Ordering::Relaxed);
        }
    }

    pub fn get(&self, metric: usize) -> u64 {
        self.values
            .get(metric)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Prometheus text exposition (no labels; per-session series are a
    /// management-API concern and would risk leaking identities).
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(METRIC_NAMES.len() * 80);
        for (i, name) in METRIC_NAMES.iter().enumerate() {
            let (help, typ) = match *name {
                n if n.ends_with("_total") => ("Cumulative counter.", "counter"),
                "rnl_handshake_duration_ms" | "rnl_mtu_bytes" => {
                    ("Last observed value.", "gauge")
                }
                _ => ("Current value.", "gauge"),
            };
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {typ}\n{name} {}\n", self.get(i)));
        }
        out
    }
}

/// Serve GET /metrics in Prometheus text format on `addr` until cancelled.
/// Minimal HTTP: one response per connection, no keep-alive.
pub async fn serve_metrics(
    addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics endpoint listening");
    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            // Read the request head (we ignore its content; only GET /metrics
            // is meaningful and every response is the same body).
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                sock.read(&mut buf),
            )
            .await;
            let body = Metrics::global().render();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_roundtrip() {
        let m = Metrics::new();
        m.inc(PACKETS_RX, 5);
        m.inc(PACKETS_RX, 2);
        m.dec(PACKETS_RX, 1);
        assert_eq!(m.get(PACKETS_RX), 6);
        m.set(MTU_BYTES, 1380);
        assert_eq!(m.get(MTU_BYTES), 1380);
    }

    #[test]
    fn prometheus_render_contains_all_metrics() {
        let m = Metrics::new();
        m.inc(SESSIONS_ESTABLISHED, 3);
        let text = m.render();
        for name in METRIC_NAMES {
            assert!(text.contains(&format!("# TYPE {name}")), "missing {name}");
        }
        assert!(text.contains("rnl_sessions_established_total 3"));
    }

    #[test]
    fn global_registry_is_shared() {
        Metrics::global().inc(TRANSPORT_RECONNECTIONS, 1);
        assert!(Metrics::global().get(TRANSPORT_RECONNECTIONS) >= 1);
    }
}
