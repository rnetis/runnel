//! Client engine: handshake, then full-duplex encrypted data path over any
//! carrier (UDP primary, TCP fallback).
//!
//! Packet path (out): TUN recv → congestion gate → packet number → AEAD
//! seal → carrier send.
//! Packet path (in):  carrier recv → parse → replay → AEAD open → TUN send.
//!
//! Failover: after the handshake the server advertises its capabilities
//! (CONFIGURATION frame, including a TCP endpoint). If the active carrier
//! goes silent for several keepalive intervals, the client reconnects over
//! the fallback carrier with a fresh handshake and resumes the tunnel.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rnl_config::ClientConfig;
use rnl_core::packet::{frame, Header};
use rnl_core::session::{new_session_id, Session};
use rnl_core::{Error, Result};
use rnl_crypto::handshake::client_builder;
use rnl_crypto::keys;
use rnl_transport::traits::Transport;
use rnl_tun::TunDevice;

const MAX_DATAGRAM: usize = 65536;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Carrier considered degraded after this many silent keepalive intervals.
const DEGRADED_AFTER_MISSES: u32 = 3;
const DEMO_PACKETS: usize = 100;

/// Loopback demo counters.
#[derive(Debug, Default, Clone)]
pub struct EchoStats {
    pub sent: usize,
    pub received: usize,
    pub verified: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    Udp,
    Tcp,
}

type SharedSession = Arc<tokio::sync::Mutex<Session>>;
type SharedMtu = Arc<AtomicU16>;
type SharedTransport = Arc<dyn Transport>;

/// Effective payload MTU shared between the MTU-discovery task (writer) and
/// the outbound loop (reader).
///
/// Run the client against a device (TUN or loopback) until cancelled, with
/// automatic failover from UDP to the advertised TCP endpoint.
pub async fn run(cfg: ClientConfig, tun: Arc<dyn TunDevice>) -> Result<()> {
    let server_pub = resolve_server_key(&cfg)?;
    let udp_host = cfg
        .client
        .server
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();

    let mut kind = CarrierKind::Udp;
    let udp_server: SocketAddr = cfg
        .client
        .server
        .parse()
        .map_err(|e| Error::Config(format!("bad server address: {e}")))?;
    let mut tcp_server: Option<SocketAddr> = cfg.client.fallback_server.as_ref().and_then(|s| {
        s.parse()
            .map_err(|e| tracing::warn!(error = %e, "bad fallback address"))
            .ok()
    });

    loop {
        let addr = match kind {
            CarrierKind::Udp => udp_server,
            CarrierKind::Tcp => match tcp_server {
                Some(a) => a,
                None => return Err(Error::Config("no TCP fallback endpoint".into())),
            },
        };
        let endpoint = cfg
            .client
            .fallback_server
            .clone()
            .unwrap_or_else(|| format!("{}:{}", udp_host, addr.port()));
        let mut cfg2 = cfg.clone();
        cfg2.client.server = addr.to_string();

        let result = connect_and_run(cfg2.clone(), &server_pub, tun.clone(), kind).await;
        match result {
            Ok(()) => return Ok(()),
            Err(Error::Degraded) => {
                // Advance to the next available carrier.
                match kind {
                    CarrierKind::Udp => {
                        // The server's CONFIG advertisement (parsed during
                        // handshake) may replace the configured endpoint.
                        if let Some(ep) = advertised_tcp(&cfg2) {
                            if let Ok(a) = ep.parse() {
                                tcp_server = Some(a);
                            }
                        }
                        kind = CarrierKind::Tcp;
                        tracing::warn!(to = %addr, "UDP degraded, failing over to TCP");
                    }
                    CarrierKind::Tcp => {
                        tracing::warn!("TCP degraded with no further carriers");
                        return Err(Error::Degraded);
                    }
                }
            }
            Err(e) => return Err(e),
        }
        let _ = endpoint;
    }
}

thread_local! {
    static ADVERTISED_TCP: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn advertised_tcp(_cfg: &ClientConfig) -> Option<String> {
    ADVERTISED_TCP.with(|c| c.borrow().clone())
}

async fn connect_and_run(
    cfg: ClientConfig,
    server_pub: &[u8; 32],
    tun: Arc<dyn TunDevice>,
    kind: CarrierKind,
) -> Result<()> {
    let server: SocketAddr = cfg
        .client
        .server
        .parse()
        .map_err(|e| Error::Config(format!("bad server address: {e}")))?;
    let transport: SharedTransport = match kind {
        CarrierKind::Udp => Arc::new(rnl_transport::UdpTransport::connect(server).await?),
        CarrierKind::Tcp => Arc::new(rnl_transport::TcpTransport::connect(server).await?),
    };
    let (session, transport, caps) = handshake(&cfg, server_pub, transport).await?;

    // Remember the server-advertised TCP endpoint for failover.
    if let Some(ep) = caps.tcp_endpoint.clone() {
        let ep = ep.replace("{udp_host}", &server.ip().to_string());
        ADVERTISED_TCP.with(|c| *c.borrow_mut() = Some(ep));
    }

    let mtu: SharedMtu = Arc::new(AtomicU16::new(cfg.client.mtu));
    let out = outbound_loop(session.clone(), transport.clone(), tun.clone(), mtu.clone());
    let input = inbound_loop(
        session,
        transport,
        tun,
        mtu,
        cfg.client.mtu,
        cfg.client.fallback_server.is_some() || caps.tcp_endpoint.is_some(),
    );
    tokio::select! {
        r = out => r,
        r = input => r,
    }
}

pub async fn handshake(
    cfg: &ClientConfig,
    server_pub: &[u8; 32],
    transport: SharedTransport,
) -> Result<(SharedSession, SharedTransport, rnl_core::Capabilities)> {
    let priv_key = cfg.private_key_bytes()?;
    let psk = cfg.security.psk_bytes()?;

    let mut hs = client_builder(&priv_key, server_pub, &psk)
        .map_err(Error::Handshake)?
        .build_initiator()?;
    let session_id = new_session_id();

    let mut msg1 = vec![0u8; 4096];
    let n = hs.write_message(rnl_crypto::PROLOGUE, &mut msg1)?;
    let mut wire = Vec::with_capacity(rnl_core::HEADER_LEN + n);
    wire.extend_from_slice(&Header::new(frame::CLIENT_HELLO, session_id, 0).encode());
    wire.extend_from_slice(&msg1[..n]);
    transport.send(&wire).await.map_err(te_to_error)?;

    // Wait for ServerHello (Noise msg2).
    let start = Instant::now();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if start.elapsed() > HANDSHAKE_TIMEOUT {
            return Err(Error::Timeout);
        }
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, transport.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(te_to_error)?;
        let (h, _) = Header::decode(&buf[..n])?;
        if h.session_id == session_id && h.frame_type == frame::SERVER_HELLO {
            hs.read_message(&buf[rnl_core::HEADER_LEN..n], &mut vec![0u8; 4096])
                .map_err(Error::Crypto)?;
            break;
        }
    }

    let mut session = match Session::from_handshake(session_id, hs, true) {
        Ok(s) => s,
        Err(e) => return Err(e),
    };
    session.remote_addr = Some(server_addr(&transport));

    // HandshakeFinish: first transport-mode frame confirms the transcript.
    let fin = session.seal(frame::HANDSHAKE_FINISH, &[1])?;
    transport.send(&fin).await.map_err(te_to_error)?;

    // Wait for the server ACK, then exchange capabilities.
    #[allow(unused_assignments)]
    let mut server_caps = rnl_core::Capabilities::default();
    #[allow(clippy::redundant_clone)]
    let mut acked = false;
    let client_caps = rnl_core::Capabilities {
        udp: true,
        tcp: true,
        sctp: false,
        tcp_endpoint: None,
    };
    let cfg_frame = session.seal(frame::CONFIGURATION, &client_caps.encode_client())?;
    transport.send(&cfg_frame).await.map_err(te_to_error)?;

    loop {
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, transport.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(te_to_error)?;
        let (h, _) = Header::decode(&buf[..n])?;
        match h.frame_type {
            frame::ACK if !acked => {
                session.open(&buf[..n])?;
                acked = true;
                tracing::info!(session = session_id, server = %session.remote_addr.unwrap_or(server_addr(&transport)), carrier = ?transport.kind(), "session active");
            }
            frame::CONFIGURATION => {
                let opened = session.open(&buf[..n])?;
                server_caps = rnl_core::Capabilities::decode_server(&opened)?;
                tracing::info!(
                    udp = server_caps.udp,
                    tcp = server_caps.tcp,
                    endpoint = ?server_caps.tcp_endpoint,
                    "server capabilities received"
                );
                break;
            }
            _ => {}
        }
    }
    Ok((
        Arc::new(tokio::sync::Mutex::new(session)),
        transport,
        server_caps,
    ))
}

fn server_addr(t: &SharedTransport) -> SocketAddr {
    t.remote_addr().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())
}

async fn outbound_loop(
    session: SharedSession,
    transport: SharedTransport,
    tun: Arc<dyn TunDevice>,
    mtu: SharedMtu,
) -> Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut congestion = rnl_congestion::NewReno::new(10, mtu.load(Ordering::Relaxed));
    loop {
        let delay = congestion.send_delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay.min(Duration::from_millis(20))).await;
        }
        let cap = mtu.load(Ordering::Relaxed) as usize;
        let n = tun.recv(&mut buf[..cap]).await?;
        congestion.on_packet_sent(n);
        let wire = {
            let mut s = session.lock().await;
            s.seal(frame::DATA, &buf[..n])?
        };
        transport.send(&wire).await.map_err(te_to_error)?;
    }
}

async fn inbound_loop(
    session: SharedSession,
    transport: SharedTransport,
    tun: Arc<dyn TunDevice>,
    mtu: SharedMtu,
    max_datagram: u16,
    failover_available: bool,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    // DPLPMTUD: probe upward from the 1200-byte base toward the underlay max.
    let mut mtud = rnl_core::MtuDiscovery::new(max_datagram + rnl_core::HEADER_LEN as u16 + 16);
    let mut mtu_tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_rx = Instant::now();

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                // Degradation check: no frames for several intervals.
                if last_rx.elapsed() > KEEPALIVE_INTERVAL * DEGRADED_AFTER_MISSES {
                    if failover_available {
                        tracing::warn!("carrier degraded (no inbound frames), failing over");
                        return Err(Error::Degraded);
                    }
                }
                let ka = {
                    let mut s = session.lock().await;
                    s.seal(frame::KEEPALIVE, &[])?
                };
                transport.send(&ka).await.map_err(te_to_error)?;
            }
            _ = mtu_tick.tick() => {
                let now = Instant::now();
                mtud.tick(now);
                if let Some(probe) = mtud.maybe_probe(now) {
                    let payload_len = (probe.size as usize)
                        .saturating_sub(rnl_core::HEADER_LEN + 16);
                    let payload = rnl_core::mtu::probe_payload(probe.token, payload_len);
                    let wire = {
                        let mut s = session.lock().await;
                        s.seal(frame::PATH_CHALLENGE, &payload)?
                    };
                    transport.send(&wire).await.map_err(te_to_error)?;
                }
            }
            r = transport.recv(&mut buf) => {
                let n = r.map_err(te_to_error)?;
                last_rx = Instant::now();
                let (h, _) = Header::decode(&buf[..n])?;
                match h.frame_type {
                    frame::DATA => {
                        let pkt = {
                            let mut s = session.lock().await;
                            match s.open(&buf[..n]) {
                                Ok(p) => p,
                                Err(Error::Replay(pn)) => {
                                    tracing::debug!(pn, "replay rejected");
                                    continue;
                                }
                                Err(e) => return Err(e),
                            }
                        };
                        tun.send(&pkt).await?;
                    }
                    frame::PATH_RESPONSE => {
                        let opened = {
                            let mut s = session.lock().await;
                            s.open(&buf[..n])?
                        };
                        if opened.len() >= 8 {
                            let token: [u8; 8] = opened[..8].try_into().unwrap();
                            if mtud.on_response(&token, n as u16, Instant::now()) {
                                let cap = mtud.payload_capacity();
                                tracing::info!(confirmed = n, payload_capacity = cap, "path MTU confirmed");
                                mtu.store(cap, Ordering::Relaxed);
                            }
                        }
                    }
                    frame::ACK | frame::KEEPALIVE => {
                        // Congestion/keepalive feedback; no retransmission implied.
                        let mut s = session.lock().await;
                        let _ = s.open(&buf[..n]);
                    }
                    frame::DISCONNECT => return Err(Error::Closed),
                    _ => {}
                }
            }
        }
    }
}

/// Loopback demo: send N synthetic "IP packets", verify the encrypted echo.
pub async fn run_echo_demo(cfg: ClientConfig) -> Result<EchoStats> {
    // The server's static key comes from RNL_SERVER_KEY in v0.1.
    let server_pub = resolve_server_key(&cfg)?;
    run_echo_demo_with_server_key(cfg, &server_pub, CarrierKind::Udp).await
}

/// Demo with an explicit server public key and carrier (tests).
pub async fn run_echo_demo_with_server_key(
    cfg: ClientConfig,
    server_pub: &[u8; 32],
    kind: CarrierKind,
) -> Result<EchoStats> {
    let server: SocketAddr = cfg
        .client
        .server
        .parse()
        .map_err(|e| Error::Config(format!("bad server address: {e}")))?;
    let transport: SharedTransport = match kind {
        CarrierKind::Udp => Arc::new(rnl_transport::UdpTransport::connect(server).await?),
        CarrierKind::Tcp => Arc::new(rnl_transport::TcpTransport::connect(server).await?),
    };
    let (session, _transport, _caps) = handshake(&cfg, server_pub, transport).await?;
    echo_demo_from_session(session, _transport).await
}

async fn echo_demo_from_session(
    session: SharedSession,
    transport: SharedTransport,
) -> Result<EchoStats> {
    let mut stats = EchoStats::default();

    for i in 0..DEMO_PACKETS {
        let mut pkt = vec![0x45u8, 0, 20, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        pkt.extend_from_slice(&(i as u32).to_be_bytes());
        pkt.extend_from_slice(&(i as u32).swap_bytes().to_be_bytes());
        let wire = {
            let mut s = session.lock().await;
            s.seal(frame::DATA, &pkt)?
        };
        transport.send(&wire).await.map_err(te_to_error)?;
        stats.sent += 1;
        if i % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let result: Result<()> = async {
        while stats.received < DEMO_PACKETS {
            let n = tokio::time::timeout_at(deadline, transport.recv(&mut buf))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(te_to_error)?;
            let (h, _) = Header::decode(&buf[..n])?;
            if h.frame_type != frame::DATA {
                continue;
            }
            let plain = {
                let mut s = session.lock().await;
                s.open(&buf[..n])?
            };
            stats.received += 1;
            let idx = u32::from_be_bytes(plain[12..16].try_into().unwrap());
            if plain[16..20] == (idx.swap_bytes()).to_be_bytes() {
                stats.verified += 1;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        eprintln!(
            "echo demo incomplete: sent {} received {} verified {}: {e}",
            stats.sent, stats.received, stats.verified
        );
        return Err(e);
    }
    Ok(stats)
}

/// v0.1: the server's static key is read from RNL_SERVER_KEY (64 hex chars)
/// until the client config grows a proper field.
fn resolve_server_key(_cfg: &ClientConfig) -> Result<[u8; 32]> {
    let raw = std::env::var("RNL_SERVER_KEY")
        .map_err(|_| Error::Config("RNL_SERVER_KEY env var required in v0.1".into()))?;
    let v = keys::parse_hex_key(&raw)
        .map_err(|_| Error::Config("RNL_SERVER_KEY must be 64 hex chars".into()))?;
    v.try_into()
        .map_err(|_| Error::Config("RNL_SERVER_KEY must be 32 bytes".into()))
}

/// Map a transport error into the core error type.
fn te_to_error(e: rnl_transport::TransportError) -> Error {
    match e {
        rnl_transport::TransportError::Io(io) => Error::Io(io),
        rnl_transport::TransportError::Closed => Error::Closed,
        rnl_transport::TransportError::NoPeer => Error::Closed,
        rnl_transport::TransportError::FrameTooLarge { .. } => Error::Closed,
    }
}

/// Test hook: run the handshake over an explicit transport and return the
/// negotiated server capabilities.
pub async fn handshake_for_test(
    cfg: &ClientConfig,
    server_pub: &[u8; 32],
    transport: SharedTransport,
) -> Result<(SharedSession, SharedTransport, rnl_core::Capabilities)> {
    handshake(cfg, server_pub, transport).await
}
