//! RNL cryptography: Noise IK handshake, replay protection, key helpers.
//!
//! v1 suite is fixed (no negotiation, no downgrade surface):
//! `Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s` with an optional 32-byte PSK
//! (all-zero PSK when none is configured).

pub mod handshake;
pub use handshake::keys;
pub mod replay;

pub use handshake::{client_builder, server_builder, PROLOGUE, ZERO_PSK};
pub use replay::REPLAY_WINDOW;

/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Rekey policy default: rekey after this many bytes on the current epoch.
pub const TRAFFIC_REKEY_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
