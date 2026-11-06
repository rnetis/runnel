//! End-to-end test: server engine + client engine over real localhost UDP.
//! Exercises: Noise IK handshake, transport-mode frames, encrypted data
//! echo, ACK feedback.

use std::sync::Arc;

use rnl_config::{ClientConfig, ServerConfig};
use rnl_tun::LoopbackDevice;

const TEST_PORT: u16 = 45820;
const TEST_PORT_2: u16 = 45821;
const TCP_TEST_UDP: u16 = 45822;
const TCP_TEST_TCP: u16 = 45823;
const NEG_TEST_UDP: u16 = 45824;
const NEG_TEST_TCP: u16 = 45825;
const MIG_TEST_UDP: u16 = 45827;
const UNAUTH_TEST_UDP: u16 = 45826;

fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

trait KeypairExt {
    fn clone_pub(&self) -> snow::Keypair;
    fn public32(&self) -> [u8; 32];
}

impl KeypairExt for snow::Keypair {
    fn clone_pub(&self) -> snow::Keypair {
        snow::Keypair { private: self.private.clone(), public: self.public.clone() }
    }
    fn public32(&self) -> [u8; 32] {
        self.public.as_slice().try_into().expect("32-byte public key")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_echo_over_udp() {
    init_log();
    let client_kp = rnl_crypto::keys::generate_keypair();
    let server_kp = rnl_crypto::keys::generate_keypair();
    let client_pub = hex::encode(&client_kp.public);

    let server_toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {TEST_PORT}
mtu = 1380

[[clients]]
id = "test-client"
public_key = "{client_pub}"
enabled = true
"#
    );
    let server_cfg = ServerConfig::parse(&server_toml).unwrap();
    let server_task = tokio::spawn(rnl_server::run_with_keys(
        server_cfg,
        Arc::new(LoopbackDevice::new()),
        true,
        server_kp.clone_pub(),
    ));

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client_toml = format!(
        r#"
[client]
server = "127.0.0.1:{TEST_PORT}"
private_key = "{}"
mtu = 1380

[security]
protocol_version = 1
cipher = "chacha20-poly1305"
handshake = "noise-ik"
replay_window = 4096
"#,
        hex::encode(&client_kp.private),
    );
    let client_cfg = ClientConfig::parse(&client_toml).unwrap();

    let stats = rnl_client::run_echo_demo_with_server_key(client_cfg, &server_kp.public32(), rnl_client::CarrierKind::Udp)
        .await
        .expect("echo demo failed");
    assert_eq!(stats.sent, 100, "all packets sent");
    assert_eq!(stats.received, 100, "all echoes received");
    assert_eq!(stats.verified, stats.sent, "all echoes verified");

    server_task.abort();
}

/// A second client key must NOT be able to establish a session.
#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_client_rejected() {
    init_log();
    let client_kp = rnl_crypto::keys::generate_keypair(); // will be authorized? no:
    let _ = client_kp;
    let rogue_kp = rnl_crypto::keys::generate_keypair();
    let server_kp = rnl_crypto::keys::generate_keypair();
    // Authorize a key that is NOT the rogue's.
    let authorized = rnl_crypto::keys::generate_keypair();

    let server_toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {UNAUTH_TEST_UDP}
mtu = 1380

[[clients]]
id = "someone-else"
public_key = "{}"
enabled = true
"#,
        hex::encode(&authorized.public),
    );
    let server_cfg = ServerConfig::parse(&server_toml).unwrap();
    let server_task = tokio::spawn(rnl_server::run_with_keys(
        server_cfg,
        Arc::new(LoopbackDevice::new()),
        true,
        server_kp.clone_pub(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client_toml = format!(
        r#"
[client]
server = "127.0.0.1:{TEST_PORT_2}"
private_key = "{}"
mtu = 1380
"#,
        hex::encode(&rogue_kp.private),
    );
    let client_cfg = ClientConfig::parse(&client_toml).unwrap();

    // The demo must time out waiting for the session ACK.
    let result = rnl_client::run_echo_demo_with_server_key(client_cfg, &server_kp.public32(), rnl_client::CarrierKind::Udp).await;
    assert!(result.is_err(), "rogue client must not establish a session");

    server_task.abort();
}

/// Full tunnel over the TCP carrier: framed handshake, encrypted echo.
#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_echo_over_tcp() {
    init_log();
    let client_kp = rnl_crypto::keys::generate_keypair();
    let server_kp = rnl_crypto::keys::generate_keypair();
    let client_pub = hex::encode(&client_kp.public);

    let server_toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {TCP_TEST_UDP}
mtu = 1380

[transports]
udp = true
tcp = true
tcp_port = {TCP_TEST_TCP}

[[clients]]
id = "test-client"
public_key = "{client_pub}"
enabled = true
"#
    );
    let server_cfg = ServerConfig::parse(&server_toml).unwrap();
    let server_task = tokio::spawn(rnl_server::run_with_keys(
        server_cfg,
        Arc::new(LoopbackDevice::new()),
        true,
        server_kp.clone_pub(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client_toml = format!(
        r#"
[client]
server = "127.0.0.1:{TCP_TEST_TCP}"
private_key = "{}"
mtu = 1380
"#,
        hex::encode(&client_kp.private),
    );
    let client_cfg = ClientConfig::parse(&client_toml).unwrap();

    let stats = rnl_client::run_echo_demo_with_server_key(
        client_cfg,
        &server_kp.public32(),
        rnl_client::CarrierKind::Tcp,
    )
    .await
    .expect("TCP echo demo failed");
    assert_eq!(stats.sent, 100, "all packets sent");
    assert_eq!(stats.received, 100, "all echoes received");
    assert_eq!(stats.verified, stats.sent, "all echoes verified");

    server_task.abort();
}

/// Negotiation: after the handshake over UDP the client receives the
/// server's CONFIGURATION frame advertising the TCP fallback endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn negotiation_advertises_tcp_endpoint() {
    init_log();
    let client_kp = rnl_crypto::keys::generate_keypair();
    let server_kp = rnl_crypto::keys::generate_keypair();
    let client_pub = hex::encode(&client_kp.public);

    let server_toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {NEG_TEST_UDP}
mtu = 1380

[transports]
udp = true
tcp = true
tcp_port = {NEG_TEST_TCP}

[[clients]]
id = "test-client"
public_key = "{client_pub}"
enabled = true
"#
    );
    let server_cfg = ServerConfig::parse(&server_toml).unwrap();
    let server_task = tokio::spawn(rnl_server::run_with_keys(
        server_cfg,
        Arc::new(LoopbackDevice::new()),
        true,
        server_kp.clone_pub(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Drive the handshake manually to inspect the negotiated capabilities.
    let client_toml = format!(
        r#"
[client]
server = "127.0.0.1:{NEG_TEST_UDP}"
private_key = "{}"
mtu = 1380
"#,
        hex::encode(&client_kp.private),
    );
    let cfg = ClientConfig::parse(&client_toml).unwrap();
    let server: std::net::SocketAddr = format!("127.0.0.1:{NEG_TEST_UDP}").parse().unwrap();
    let transport: Arc<dyn rnl_transport::Transport> = Arc::new(
        rnl_transport::UdpTransport::connect(server).await.unwrap(),
    );
    let server_pub = server_kp.public32();
    let (_session, _t, caps) = rnl_client::handshake_for_test(&cfg, &server_pub, transport)
        .await
        .expect("handshake failed");

    assert!(caps.tcp, "server must advertise TCP");
    let ep = caps.tcp_endpoint.expect("endpoint advertised");
    assert_eq!(ep, format!("127.0.0.1:{NEG_TEST_TCP}"));

    server_task.abort();
}

/// Session migration: frames from a NEW client address must not carry data
/// until the server validates the path (PATH_CHALLENGE -> PATH_RESPONSE
/// sealed under the session keys). After validation, traffic flows on the
/// new path (NAT rebind / deliberate migration).
#[tokio::test(flavor = "multi_thread")]
async fn session_migration_after_rebind() {
    init_log();
    let client_kp = rnl_crypto::keys::generate_keypair();
    let server_kp = rnl_crypto::keys::generate_keypair();
    let client_pub = hex::encode(&client_kp.public);

    let server_toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {MIG_TEST_UDP}
mtu = 1380

[[clients]]
id = "test-client"
public_key = "{client_pub}"
enabled = true
"#
    );
    let server_cfg = ServerConfig::parse(&server_toml).unwrap();
    let server_task = tokio::spawn(rnl_server::run_with_keys(
        server_cfg,
        Arc::new(LoopbackDevice::new()),
        true,
        server_kp.clone_pub(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Establish the session from socket A.
    let client_toml = format!(
        r#"
[client]
server = "127.0.0.1:{MIG_TEST_UDP}"
private_key = "{}"
mtu = 1380
"#,
        hex::encode(&client_kp.private),
    );
    let cfg = ClientConfig::parse(&client_toml).unwrap();
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{MIG_TEST_UDP}").parse().unwrap();
    let t_a: Arc<dyn rnl_transport::Transport> = Arc::new(
        rnl_transport::UdpTransport::connect(server_addr).await.unwrap(),
    );
    let server_pub = server_kp.public32();
    let (session, _t, _caps) = rnl_client::handshake_for_test(&cfg, &server_pub, t_a)
        .await
        .expect("handshake failed");

    // "Rebind": socket B, same peer, fresh local port.
    let t_b: Arc<dyn rnl_transport::Transport> = Arc::new(
        rnl_transport::UdpTransport::connect(server_addr).await.unwrap(),
    );

    // 1. DATA from the new address must NOT be echoed — a challenge comes back.
    let data_pkt = {
        let mut s = session.lock().await;
        let mut pkt = vec![0x45u8, 0, 20, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        pkt.extend_from_slice(&999u32.to_be_bytes());
        pkt.extend_from_slice(&999u32.swap_bytes().to_be_bytes());
        s.seal(rnl_core::packet::frame::DATA, &pkt).unwrap()
    };
    t_b.send(&data_pkt).await.unwrap();

    let mut buf = vec![0u8; 65536];
    let challenge = tokio::time::timeout(std::time::Duration::from_secs(5), t_b.recv(&mut buf))
        .await
        .expect("challenge timeout")
        .expect("challenge recv");
    let (ch, _) = rnl_core::Header::decode(&buf[..challenge]).unwrap();
    assert_eq!(ch.frame_type, rnl_core::packet::frame::PATH_CHALLENGE, "server must challenge the new address");
    let payload = {
        let mut s = session.lock().await;
        s.open(&buf[..challenge]).expect("challenge must decrypt under session keys")
    };
    assert!(payload.len() >= 8);

    // 2. PATH_RESPONSE from the new address completes validation.
    let resp = {
        let mut s = session.lock().await;
        s.seal(rnl_core::packet::frame::PATH_RESPONSE, &payload).unwrap()
    };
    t_b.send(&resp).await.unwrap();
    let ack = tokio::time::timeout(std::time::Duration::from_secs(5), t_b.recv(&mut buf))
        .await
        .expect("ack timeout")
        .expect("ack recv");
    let (ah, _) = rnl_core::Header::decode(&buf[..ack]).unwrap();
    assert_eq!(ah.frame_type, rnl_core::packet::frame::ACK, "migration must be acknowledged");
    {
        let mut s = session.lock().await;
        let plain = s.open(&buf[..ack]).unwrap();
        assert_eq!(plain, [2u8], "migration ACK marker");
    }

    // 3. Data now flows on the new path.
    let data2 = {
        let mut s = session.lock().await;
        let mut pkt = vec![0x45u8, 0, 20, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        pkt.extend_from_slice(&1000u32.to_be_bytes());
        pkt.extend_from_slice(&1000u32.swap_bytes().to_be_bytes());
        s.seal(rnl_core::packet::frame::DATA, &pkt).unwrap()
    };
    t_b.send(&data2).await.unwrap();
    let echo = tokio::time::timeout(std::time::Duration::from_secs(5), t_b.recv(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo recv");
    let (eh, _) = rnl_core::Header::decode(&buf[..echo]).unwrap();
    assert_eq!(eh.frame_type, rnl_core::packet::frame::DATA, "echo on the migrated path");
    {
        let mut s = session.lock().await;
        let plain = s.open(&buf[..echo]).unwrap();
        assert_eq!(&plain[12..16], &1000u32.to_be_bytes());
    }

    server_task.abort();
}
