//! Server engine: one protocol, multiple carriers.
//!
//! - UDP loop (primary): batched recvmmsg/sendmmsg data path.
//! - TCP listener (compatibility): length-prefixed framing, per-connection
//!   tasks; kernel provides reliability/congestion control.
//! - Both carriers share one session table: a session established over UDP
//!   is the same protocol session regardless of carrier.
//! - After HandshakeFinish the server advertises its transport capabilities
//!   (CONFIGURATION frame) including the TCP fallback endpoint.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rnl_config::ServerConfig;
use rnl_core::packet::{frame, Header};
use rnl_core::session::Session;
use rnl_core::{Error, Result};
use rnl_crypto::handshake::server_builder;
use rnl_transport::{Transport, UdpTransport};
use rnl_tun::TunDevice;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const MAX_DATAGRAM: usize = 65536;
/// Send an ACK frame every N data packets (congestion feedback).
const ACK_INTERVAL: u64 = 16;
/// Drop pending handshakes older than this.
const HS_TIMEOUT: Duration = Duration::from_secs(10);
/// Drop sessions silent longer than this (UDP). TCP connections use their
/// own idle cutoff below.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Datagrams drained per receive batch.
const RECV_BATCH: usize = 64;
/// Close a TCP connection after this much silence.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

struct PendingHs {
    hs: snow::HandshakeState,
    #[allow(dead_code)]
    addr: SocketAddr,
    created: Instant,
}

struct ActiveSession {
    session: Session,
    /// Current validated peer address (data path).
    addr: SocketAddr,
    data_packets: u64,
    /// In-progress address validation for a NEW peer address:
    /// (candidate addr, challenge token, started).
    pending_validation: Option<(SocketAddr, [u8; 8], Instant)>,
    last_challenge: Instant,
}

#[derive(Default)]
struct SessionTable {
    pending: Mutex<HashMap<u64, PendingHs>>,
    sessions: Mutex<HashMap<u64, ActiveSession>>,
}

struct ServerContext {
    server_kp: snow::Keypair,
    authorized: Vec<Vec<u8>>,
    psk: [u8; 32],
    echo: bool,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    table: SessionTable,
    /// Server capabilities advertised to clients (CONFIGURATION frame).
    caps: rnl_core::Capabilities,
}

/// Run the server until cancelled. `echo` loops decrypted packets back to
/// clients instead of writing them to a real interface (loopback testing).
pub async fn run(cfg: ServerConfig, tun: Arc<dyn TunDevice>, echo: bool) -> Result<()> {
    run_with_keys(cfg, tun, echo, rnl_crypto::keys::generate_keypair()).await
}

/// Run with an explicit server keypair (tests, key reuse across restarts).
pub async fn run_with_keys(
    cfg: ServerConfig,
    tun: Arc<dyn TunDevice>,
    echo: bool,
    server_kp: snow::Keypair,
) -> Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.server.listen, cfg.server.port)
        .parse()
        .map_err(|e| Error::Config(format!("bad listen address: {e}")))?;
    let psk = cfg.security.psk_bytes()?;
    let authorized: Vec<Vec<u8>> = cfg
        .clients
        .iter()
        .filter(|c| c.enabled)
        .map(|c| hex::decode(c.public_key.trim()).expect("validated at config parse"))
        .collect();
    if authorized.is_empty() {
        return Err(Error::Config("no enabled clients configured".into()));
    }

    // TCP fallback endpoint advertised to clients.
    let tcp_endpoint = if cfg.transports.tcp {
        cfg.transports
            .tcp_advertise
            .clone()
            .or_else(|| {
                cfg.transports.tcp_port.map(|p| {
                    let host = if cfg.server.listen == "0.0.0.0" {
                        // Client reaches us at the same host it used for UDP.
                        format!("{{udp_host}}:{p}")
                    } else {
                        format!("{}:{p}", cfg.server.listen)
                    };
                    host
                })
            })
    } else {
        None
    };
    let caps = rnl_core::Capabilities {
        udp: true,
        tcp: cfg.transports.tcp && cfg.transports.tcp_port.is_some(),
        sctp: false,
        tcp_endpoint: tcp_endpoint.clone(),
    };

    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(pkt) = tun_rx.recv().await {
            if let Err(e) = tun.send(&pkt).await {
                tracing::warn!(error = %e, "TUN write failed");
            }
        }
    });

    let ctx = Arc::new(ServerContext {
        server_kp,
        authorized,
        psk,
        echo,
        tun_tx,
        table: SessionTable::default(),
        caps,
    });

    // Multi-core receive: N SO_REUSEPORT shards, each an independent loop.
    // Without the `reuseport` feature a single worker owns the socket.
    #[cfg(feature = "reuseport")]
    let workers = cfg
        .server
        .workers
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
        .clamp(1, 16);
    #[cfg(not(feature = "reuseport"))]
    let workers = 1usize;
    let use_reuseport = workers > 1;
    let mut udp_tasks = Vec::new();
    for _ in 0..workers {
        let ctx = ctx.clone();
        udp_tasks.push(tokio::spawn(async move {
            udp_loop(ctx, listen_addr, use_reuseport).await
        }));
    }

    let tcp_task = if let (true, Some(port)) = (cfg.transports.tcp, cfg.transports.tcp_port) {
        let host = if cfg.server.listen == "0.0.0.0" {
            "0.0.0.0".to_string()
        } else {
            cfg.server.listen.clone()
        };
        let addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| Error::Config(format!("bad tcp address: {e}")))?;
        let ctx = ctx.clone();
        Some(async move { tcp_listen(ctx, addr).await })
    } else {
        None
    };

    tracing::info!(
        udp = %listen_addr,
        tcp = ?tcp_endpoint,
        clients = ctx.authorized.len(),
        echo,
        "RNL server listening"
    );

    // Abort sibling workers when any loop exits (they share the process).
    let udp_all = async move {
        let mut first: Option<Result<()>> = None;
        for t in udp_tasks {
            match t.await {
                Ok(r) if first.is_none() => first = Some(r),
                Ok(_) => {}
                Err(e) => {
                    if first.is_none() {
                        first = Some(Err(Error::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))));
                    }
                }
            }
        }
        first.unwrap_or(Ok(()))
    };

    match tcp_task {
        Some(tcp) => {
            tokio::select! {
                r = udp_all => r,
                r = tcp => r,
            }
        }
        None => udp_all.await,
    }
}

// ---------------------------------------------------------------- UDP loop

async fn udp_loop(ctx: Arc<ServerContext>, addr: SocketAddr, reuse_port: bool) -> Result<()> {
    let sock = Arc::new(UdpTransport::bind_sharded(addr, None, reuse_port).await?);

    let mut raw_bufs: Vec<Vec<u8>> = vec![vec![0u8; MAX_DATAGRAM]; RECV_BATCH];
    let mut sizes = vec![0usize; RECV_BATCH];
    let mut addrs: Vec<Option<SocketAddr>> = vec![None; RECV_BATCH];
    let mut replies: Vec<Vec<u8>> = Vec::with_capacity(RECV_BATCH);
    let mut last_sweep = Instant::now();

    loop {
        let do_sweep = last_sweep.elapsed() > Duration::from_secs(5);

        let got = {
            let mut bufs: Vec<&mut [u8]> = raw_bufs
                .iter_mut()
                .map(|b| b.as_mut_slice())
                .collect();
            match tokio::time::timeout(
                Duration::from_secs(1),
                sock.recv_batch(&mut bufs[..], &mut sizes, &mut addrs),
            )
            .await
            {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    return Err(match e {
                        rnl_transport::TransportError::Io(io) => Error::Io(io),
                        _ => Error::Closed,
                    })
                }
                Err(_) => 0,
            }
        };

        if do_sweep {
            last_sweep = Instant::now();
            sweep(&ctx);
        }

        for i in 0..got {
            let peer = addrs[i].unwrap();
            let datagram = &raw_bufs[i][..sizes[i]];
            handle_frame(&ctx, datagram, peer, &mut replies).await;
            if !replies.is_empty() {
                // Replies go to THIS datagram's source: during address
                // validation that is the new candidate path, not the pinned
                // session address.
                let refs: Vec<&[u8]> = replies.iter().map(|r| r.as_slice()).collect();
                let _ = sock.send_batch_to(peer, &refs).await;
                replies.clear();
            }
        }

        if got == 0 {
            tokio::task::yield_now().await;
        }
        for s in sizes.iter_mut() {
            *s = 0;
        }
    }
}

fn sweep(ctx: &ServerContext) {
    ctx.table.pending.lock().unwrap().retain(|_, p| {
        p.created.elapsed() < HS_TIMEOUT
    });
    let dead: Vec<u64> = ctx
        .table
        .sessions
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, s)| s.session.last_seen.elapsed() > IDLE_TIMEOUT)
        .map(|(k, _)| *k)
        .collect();
    for k in dead {
        tracing::info!(session = k, "session idle timeout");
        ctx.table.sessions.lock().unwrap().remove(&k);
    }
}

// ---------------------------------------------------------------- TCP loop

async fn tcp_listen(ctx: Arc<ServerContext>, addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            tracing::debug!(%peer, "TCP connection accepted");
            if let Err(e) = tcp_conn(ctx, stream, peer).await {
                tracing::debug!(%peer, error = %e, "TCP connection ended");
            }
        });
    }
}

async fn tcp_conn(
    ctx: Arc<ServerContext>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let transport = Arc::new(rnl_transport::TcpTransport::from_stream(stream));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut last_rx = Instant::now();

    loop {
        if last_rx.elapsed() > TCP_IDLE_TIMEOUT {
            tracing::info!(%peer, "TCP connection idle timeout");
            return Ok(());
        }
        let n = match tokio::time::timeout(
            Duration::from_secs(30),
            transport.recv_frame(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(Error::Io(transport_io(e))),
            Err(_) => {
                // No frame in 30s: check idle cutoff, keep waiting otherwise.
                continue;
            }
        };
        last_rx = Instant::now();

        let mut replies: Vec<Vec<u8>> = Vec::new();
        handle_frame(&ctx, &buf[..n], peer, &mut replies).await;
        // Trait `send` applies the length-prefix framing; do not pre-frame.
        for r in &replies {
            transport.send(r).await.map_err(|e| Error::Io(transport_io(e)))?;
        }
    }
}

fn transport_io(e: rnl_transport::TransportError) -> std::io::Error {
    match e {
        rnl_transport::TransportError::Io(io) => io,
        rnl_transport::TransportError::Closed => {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "transport closed")
        }
        rnl_transport::TransportError::NoPeer => {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "no peer")
        }
        rnl_transport::TransportError::FrameTooLarge { size, max } => std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {size} > {max}"),
        ),
    }
}

// ------------------------------------------------------------- frame logic

/// Process one RNL frame from any carrier; encrypted replies are returned to
/// the caller (who sends them over the appropriate carrier, batched on UDP).
async fn handle_frame(
    ctx: &ServerContext,
    datagram: &[u8],
    peer: SocketAddr,
    replies: &mut Vec<Vec<u8>>,
) {
    let (header, hdr_len) = match Header::decode(datagram) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "dropping malformed datagram");
            return;
        }
    };
    let payload = &datagram[hdr_len..];

    match header.frame_type {
        frame::CLIENT_HELLO => {
            {
                let sessions = ctx.table.sessions.lock().unwrap();
                if sessions.contains_key(&header.session_id) {
                    return;
                }
            }
            let already_pending = {
                let mut pending = ctx.table.pending.lock().unwrap();
                let dup = pending.contains_key(&header.session_id);
                if dup {
                    true
                } else {
                    pending.insert(
                        header.session_id,
                        PendingHs {
                            // placeholder; replaced below on success
                            hs: match server_builder(&ctx.server_kp, &ctx.psk) {
                                Ok(b) => match b.build_responder() {
                                    Ok(hs) => hs,
                                    Err(_) => return,
                                },
                                Err(_) => return,
                            },
                            addr: peer,
                            created: Instant::now(),
                        },
                    );
                    false
                }
            };
            if already_pending {
                return;
            }
            let mut hs = match server_builder(&ctx.server_kp, &ctx.psk) {
                Ok(b) => match b.build_responder() {
                    Ok(hs) => hs,
                    Err(e) => {
                        tracing::error!(error = %e, "responder build failed");
                        return;
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "server builder failed");
                    return;
                }
            };
            let mut out = vec![0u8; MAX_DATAGRAM];
            if let Err(e) = hs.read_message(payload, &mut out) {
                tracing::debug!(session = header.session_id, error = %e, "ClientHello unreadable");
                ctx.table.pending.lock().unwrap().remove(&header.session_id);
                return;
            }
            let Some(remote_static) = hs.get_remote_static() else {
                tracing::warn!(session = header.session_id, "no remote static in ClientHello");
                ctx.table.pending.lock().unwrap().remove(&header.session_id);
                return;
            };
            if !ctx.authorized.iter().any(|k| k == remote_static) {
                tracing::warn!(session = header.session_id, "client public key not authorized");
                ctx.table.pending.lock().unwrap().remove(&header.session_id);
                return;
            }
            let mut msg2 = vec![0u8; MAX_DATAGRAM];
            let n = match hs.write_message(&[], &mut msg2) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "ServerHello write failed");
                    ctx.table.pending.lock().unwrap().remove(&header.session_id);
                    return;
                }
            };
            let mut wire = Vec::with_capacity(rnl_core::HEADER_LEN + n);
            wire.extend_from_slice(&Header::new(frame::SERVER_HELLO, header.session_id, 0).encode());
            wire.extend_from_slice(&msg2[..n]);
            replies.push(wire);
            // Swap the real handshake state into the pending entry.
            if let Some(p) = ctx.table.pending.lock().unwrap().get_mut(&header.session_id) {
                p.hs = hs;
                p.addr = peer;
                p.created = Instant::now();
            }
        }
        frame::HANDSHAKE_FINISH => {
            let established = {
                let mut sessions = ctx.table.sessions.lock().unwrap();
                if let Some(act) = sessions.get_mut(&header.session_id) {
                    let _ = act.session.open(datagram);
                    act.session.last_seen = Instant::now();
                    false
                } else {
                    let p = ctx.table.pending.lock().unwrap().remove(&header.session_id);
                    match p {
                        Some(p) => {
                            let mut session =
                                match Session::from_handshake(header.session_id, p.hs, false) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::warn!(
                                            session = header.session_id,
                                            error = %e,
                                            "session derive failed"
                                        );
                                        return;
                                    }
                                };
                            session.remote_addr = Some(peer);
                            // 0x03 is the first transport-mode frame; opening
                            // it confirms the transcript. IK msg1 always
                            // parses, so THIS is where unauthorized keys are
                            // finally rejected.
                            if let Err(e) = session.open(datagram) {
                                tracing::warn!(
                                    session = header.session_id,
                                    error = %e,
                                    "handshake finish rejected"
                                );
                                return;
                            }
                            tracing::info!(session = header.session_id, %peer, "session established");
                            match session.seal(frame::ACK, &[1]) {
                                Ok(ack) => replies.push(ack),
                                Err(e) => {
                                    tracing::warn!(error = %e, "ACK seal failed");
                                    return;
                                }
                            }
                            // Capability negotiation: advertise carriers.
                            match session.seal(frame::CONFIGURATION, &ctx.caps.encode_server()) {
                                Ok(cfgf) => replies.push(cfgf),
                                Err(e) => tracing::warn!(error = %e, "CONFIG seal failed"),
                            }
                            sessions.insert(
                                header.session_id,
                                ActiveSession {
                                    session,
                                    addr: peer,
                                    data_packets: 0,
                                    pending_validation: None,
                                    // Allow the first challenge immediately.
                                    last_challenge: Instant::now()
                                        .checked_sub(Duration::from_secs(10))
                                        .unwrap_or(Instant::now()),
                                },
                            );
                            true
                        }
                        None => false,
                    }
                }
            };
            let _ = established;
        }
        frame::CONFIGURATION => {
            // Client capability advertisement; consumed and logged. Server
            // capabilities were already sent with the handshake ACK.
            let mut sessions = ctx.table.sessions.lock().unwrap();
            if let Some(act) = sessions.get_mut(&header.session_id) {
                if let Ok(plain) = act.session.open(datagram) {
                    if let Ok(caps) = rnl_core::Capabilities::decode_client(&plain) {
                        tracing::info!(
                            session = header.session_id,
                            udp = caps.udp,
                            tcp = caps.tcp,
                            sctp = caps.sctp,
                            "client capabilities received"
                        );
                    }
                }
            }
        }
        frame::DATA | frame::KEEPALIVE | frame::PATH_CHALLENGE | frame::PATH_RESPONSE => {
            // Address change = potential NAT rebind or migration attempt.
            // A session ID alone never authorizes it: challenge the new
            // address and require a PATH_RESPONSE from it before switching.
            let peer_changed = {
                let sessions = ctx.table.sessions.lock().unwrap();
                sessions
                    .get(&header.session_id)
                    .map(|act| act.addr != peer)
                    .unwrap_or(false)
            };
            if peer_changed {
                handle_addr_change(ctx, header.session_id, peer, datagram, header.frame_type, replies);
                return;
            }
            let plain = {
                let mut sessions = ctx.table.sessions.lock().unwrap();
                let Some(act) = sessions.get_mut(&header.session_id) else {
                    return;
                };
                match act.session.open(datagram) {
                    Ok(p) => p,
                    Err(Error::Replay(pn)) => {
                        tracing::debug!(pn, "replay rejected");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(session = header.session_id, error = %e, "open failed, dropping");
                        return;
                    }
                }
            };
            // Replies are sealed outside the table lock.
            let mut sessions = ctx.table.sessions.lock().unwrap();
            let Some(act) = sessions.get_mut(&header.session_id) else {
                return;
            };
            match header.frame_type {
                frame::KEEPALIVE => {
                    if let Ok(ka) = act.session.seal(frame::KEEPALIVE, &[]) {
                        replies.push(ka);
                    }
                }
                frame::PATH_CHALLENGE => {
                    // MTU probe reflection: echo the payload verbatim so the
                    // client can confirm the full datagram size traversed.
                    if let Ok(resp) = act.session.seal(frame::PATH_RESPONSE, &plain) {
                        replies.push(resp);
                    }
                }
                frame::PATH_RESPONSE => {
                    // MTU probe responses from the client travel on the
                    // stable path; the client consumes its own. Nothing to
                    // do server-side beyond keeping the session fresh.
                    let _ = &plain;
                }
                frame::DATA => {
                    act.data_packets += 1;
                    if ctx.echo {
                        if let Ok(back) = act.session.seal(frame::DATA, &plain) {
                            replies.push(back);
                        }
                    } else {
                        let _ = ctx.tun_tx.send(plain);
                    }
                    if act.data_packets % ACK_INTERVAL == 0 {
                        if let Ok(ack) = act.session.seal(frame::ACK, &[]) {
                            replies.push(ack);
                        }
                    }
                }
                _ => {}
            }
        }
        frame::DISCONNECT => {
            if ctx.table.sessions.lock().unwrap().remove(&header.session_id).is_some() {
                tracing::info!(session = header.session_id, "session closed by client");
            }
        }
        _ => {
            tracing::debug!(frame = header.frame_type, "unhandled frame type");
        }
    }
}

/// Address validation for a known session whose frames arrive from a NEW
/// peer address (NAT rebind or deliberate migration). A session ID alone is
/// never sufficient: the new address must answer a PATH_CHALLENGE with a
/// PATH_RESPONSE sealed under the session's keys before it carries data.
/// Until then, frames from the new address are dropped (anti-amplification:
/// the challenge is one small frame, rate-limited per session).
fn handle_addr_change(
    ctx: &ServerContext,
    session_id: u64,
    peer: SocketAddr,
    datagram: &[u8],
    frame_type: u8,
    replies: &mut Vec<Vec<u8>>,
) {
    let mut sessions = ctx.table.sessions.lock().unwrap();
    let Some(act) = sessions.get_mut(&session_id) else {
        return;
    };

    // 1. A PATH_RESPONSE from the candidate address completes validation.
    if let Some((pending_addr, token, started)) = act.pending_validation {
        if pending_addr == peer {
            let opened = act.session.open(datagram);
            let valid = match opened {
                Ok(plain) => {
                    frame_type == frame::PATH_RESPONSE
                        && plain.len() >= 8
                        && plain[..8] == token
                }
                Err(_) => false,
            };
            if valid {
                tracing::info!(
                    session = session_id,
                    old = %act.addr,
                    new = %peer,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "session migrated to validated path"
                );
                act.addr = peer;
                act.pending_validation = None;
                if let Ok(ack) = act.session.seal(frame::ACK, &[2]) {
                    replies.push(ack);
                }
            } else {
                tracing::debug!(session = session_id, %peer, "migration validation failed");
                act.pending_validation = None;
            }
            return;
        }
        // Validation in progress toward another address; ignore others.
        return;
    }

    // 2. New candidate address: send a challenge (rate-limited).
    if act.last_challenge.elapsed() < Duration::from_secs(1) {
        return;
    }
    act.last_challenge = Instant::now();
    use rand::RngCore;
    let mut token = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut token);
    let payload = rnl_core::mtu::probe_payload(token, 32);
    match act.session.seal(frame::PATH_CHALLENGE, &payload) {
        Ok(ch) => replies.push(ch),
        Err(e) => {
            tracing::warn!(session = session_id, error = %e, "challenge seal failed");
            return;
        }
    }
    act.pending_validation = Some((peer, token, Instant::now()));
    tracing::debug!(session = session_id, %peer, "challenging new peer address");
}
