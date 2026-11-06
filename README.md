# Runnel (RNL) — v0.1

A transport-independent encrypted VPN protocol in Rust. UDP is the primary
carrier; TCP and SCTP adapters are planned behind the same core interface.

Implements the Phase 1 scope of the RTP→RNL design:

- Fixed 24-byte RNL v1 header, big-endian, typed frames (`0x01`–`0x0B`, `0x20`, `0x21`)
- Noise **IKpsk0** handshake — X25519 / ChaChaPoly / BLAKE2s (via `snow`),
  optional 32-byte PSK, fixed suite (no negotiation, no downgrade surface)
- **Explicit-nonce AEAD**: directional traffic keys derived from the Noise
  handshake hash (keyed BLAKE2s, domain-separated); 96-bit nonce =
  `0000 || packet_number`, enabling true out-of-order delivery on UDP
- 4096-packet sliding **replay window** (RFC 6479-style bitmap)
- NewReno-style **congestion controller** with pacing + WRR priority
  scheduler (critical control / interactive / normal / bulk)
- Length-prefixed **stream framing** for future TCP/SCTP carriers
- Strict config parser (`deny_unknown_fields`); only the frozen v1 suite accepted
- Loopback echo mode for full end-to-end testing **without root**

## Layout

```
crates/
  rnl-core        packet format, framing, sessions, errors
  rnl-crypto      Noise IK handshake, replay window, key helpers
  rnl-transport   Transport trait + UDP adapter (socket2-tuned)
  rnl-congestion  NewReno controller, WRR scheduler
  rnl-tun         TunDevice trait + loopback device
  rnl-config      server/client TOML configs
  rnl-server      server engine (UDP data path, session table)
  rnl-client      client engine (handshake, in/out loops, echo demo)
apps/
  rnl-server      `rnl-server` binary
  rnl-client      `rnl-client` binary
```

## Build & test

```sh
cargo build --release
cargo test          # 31 tests incl. end-to-end over real localhost UDP
```

## Try it (loopback, no root)

```sh
# 1. Generate keys
server_pub=$(cargo run -q --bin rnl-client 2>/dev/null; true)  # see scripts below
```

Keys can be generated with any X25519 tool; for convenience use the test
helper approach: run the integration test to see the full flow, or generate
keypairs with `cargo test -p rnl-crypto -- --nocapture` once a keygen bin is
added. Minimal manual flow:

```sh
# server.toml
[server]
listen = "127.0.0.1"
port = 45820
mtu = 1380
[[clients]]
id = "laptop"
public_key = "<client x25519 public key, hex>"
enabled = true

RUST_LOG=info RNL_SERVER_CONFIG="$(cat server.toml)" ./target/release/rnl-server --echo

# client
RNL_SERVER_KEY="<server x25519 public key, hex>" \
RNL_CLIENT_CONFIG="$(cat client.toml)" ./target/release/rnl-client --echo-demo
# -> echo demo: sent 100 packets, received 100, verified 100 — OK
```

## Security notes

- The header (incl. type, session id, packet number) is AEAD associated data;
  decrypted payloads are never surfaced without authentication.
- IK handshake: the server learns the client static key from msg1 and
  authorizes by explicit membership in the configured client list. The
  HandshakeFinish transport-mode frame is where the transcript is confirmed.
- Replay: duplicates, stale (outside 4096 window) and mismatched-session
  packets are rejected before decryption work matters.
- No custom cryptographic primitives; suites are fixed at compile time.

## Phase 2 — performance work landed

- **Buffer pool** (`rnl-core::pool`): free-list reuse for hot-path buffers,
  ~58 ns acquire vs ~75 ns alloc (and avoids per-packet allocator traffic).
- **Batched crypto**: `Session::seal_into` / `Session::seal_batch` seal
  without intermediate allocations; server echoes are batched.
- **UDP batching**: `UdpTransport::recv_batch` / `send_batch` use
  `recvmmsg`/`sendmmsg` on Linux (MSG_DONTWAIT + readable-gating), with a
  portable fallback loop. Server drains up to 64 datagrams per wakeup.
- **Path MTU discovery** (`rnl-core::mtu`): DPLPMTUD-style probe ladder
  (1200 -> 1380 -> 1452 -> 1472 -> 1500) using PATH_CHALLENGE / PATH_RESPONSE
  reflection; client payload capacity follows the confirmed datagram size.
- **Criterion benchmarks** (`cargo bench`): header codec ~2 ns, ChaCha20-Poly1305
  seal 1.4–2.7 µs, open ~3–5.4 µs per packet (64–1340 B), replay window check
  ~171 ns, scheduler 1000 mixed ops ~7.5 µs.

Baseline numbers (this machine, quick mode) — rerun `cargo bench` to compare.

## Phase 3 — transport expansion landed

- **TCP carrier** (`rnl-transport::tcp`): length-prefixed framing over a
  stream — one read never maps to one frame; ahead-decoded frames are queued;
  bounded frame size. The server runs a TCP listener alongside the UDP loop;
  both carriers share one session table, so a session is carrier-agnostic.
  Full end-to-end tunnel over TCP is covered by an integration test.
- **SCTP carrier** (`rnl-transport::sctp`, `--features sctp`, Linux):
  SOCK_SEQPACKET / IPPROTO_SCTP — message boundaries come from SCTP, no
  length prefix. Optional by design; availability is platform-dependent.
- **Capability negotiation**: after the handshake the client sends a
  CONFIGURATION frame with its supported carriers; the server replies with
  its own plus the TCP fallback endpoint. Logged on both sides.
- **Failover**: the client monitors carrier health (no inbound frames for 3
  keepalive intervals = degraded) and reconnects over the advertised TCP
  endpoint with a fresh handshake. `rnl-client --server ... --fallback-server
  host:port` enables it; the server config gains `transports.tcp_port` /
  `tcp_advertise`.

## Phase 4 — advanced networking landed

- **Session migration with address validation**: frames arriving for a known
  session from a NEW peer address are never trusted — the server sends a
  rate-limited PATH_CHALLENGE to the candidate address and only switches the
  data path after a PATH_RESPONSE sealed under the session keys arrives from
  it (QUIC-style anti-hijack; a session ID alone authorizes nothing).
  Covered by an integration test (rebind -> challenge -> response -> ACK ->
  echo on the new path).
- **Multi-core receive**: `server.workers` (default: core count) SO_REUSEPORT
  shard loops, each with its own batched socket, sharing the session table.
  Feature-gated as `rnl-server/reuseport`; the server binary enables it.
- **Active/standby multipath primitive** (`rnl-congestion::paths`):
  `NetworkPath` + `PathManager` — validated-only activation, one active path,
  best-standby promotion on degradation (lowest loss, then RTT), path reaping.
  The scheduling decision layer both engines will share; packet-level
  distribution across paths remains future work by design.

## Known v0.1 constraints / roadmap

- Kernel TUN mode (feature-gated) is the next deliverable; binaries currently
  require `--echo` / `--echo-demo` for the loopback data path.
- Rekey policy is tracked (`Session::needs_rekey`) but key update frames are
  not implemented yet.
- TCP/SCTP adapters, path validation and migration come in Phases 3–4.
- Client takes the server static key via `RNL_SERVER_KEY`; config-file
  plumbing is planned.
- Session table is a single-task HashMap; sharding/multi-core comes later.
