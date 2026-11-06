//! Noise IK handshake construction.

use thiserror::Error;

pub const PROLOGUE: &[u8] = b"runnel-v1-handshake";
/// Cipher suite: Noise IK, PSK mixed at position 0.
pub const PATTERN: &str = "Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s";
/// PSK used when none is configured (public knowledge; enable PSK mode for
/// deployments that want it).
pub const ZERO_PSK: [u8; 32] = [0u8; 32];

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("no authorized client key matched this ClientHello")]
    Unauthorized,
}

pub type Result<T> = std::result::Result<T, HandshakeError>;

pub fn params() -> snow::params::NoiseParams {
    PATTERN.parse().expect("fixed v1 suite must parse")
}

/// Client (initiator) builder. IK requires the server's static public key.
/// `local_static_priv` is the raw X25519 private key.
pub fn client_builder<'a>(
    local_static_priv: &'a [u8],
    remote_static: &'a [u8],
    psk: &'a [u8; 32],
) -> Result<snow::Builder<'a>> {
    let b = snow::Builder::new(params())
        .local_private_key(local_static_priv)
        .remote_public_key(remote_static)
        .psk(0, psk);
    Ok(b)
}

/// Server (responder) builder. IK requires the initiator's static public key
/// to be known in advance; callers pass one authorized client key at a time
/// via `Builder::remote_static`.
pub fn server_builder<'a>(
    local_static: &'a snow::Keypair,
    psk: &'a [u8; 32],
) -> Result<snow::Builder<'a>> {
    let b = snow::Builder::new(params())
        .local_private_key(&local_static.private)
        .psk(0, psk);
    Ok(b)
}

/// Test helper: run a full IK handshake over memory and return both
/// completed handshake states (client, server), ready for
/// `Session::from_handshake` in rnl-core.
pub fn in_memory_handshake() -> Result<(snow::HandshakeState, snow::HandshakeState)> {
    let client_kp = keys::generate_keypair();
    let server_kp = keys::generate_keypair();

    let mut init = client_builder(&client_kp.private, &server_kp.public, &ZERO_PSK)?
        .build_initiator()?;
    let mut resp = server_builder(&server_kp, &ZERO_PSK)?
        .remote_public_key(&client_kp.public)
        .build_responder()?;

    let mut buf1 = vec![0u8; 4096];
    let n1 = init.write_message(PROLOGUE, &mut buf1)?;
    resp.read_message(&buf1[..n1], &mut vec![0u8; 4096])?;

    let mut buf2 = vec![0u8; 4096];
    let n2 = resp.write_message(&[], &mut buf2)?;
    init.read_message(&buf2[..n2], &mut vec![0u8; 4096])?;

    Ok((init, resp))
}

pub mod keys {
    use super::Result;

    pub fn generate_keypair() -> snow::Keypair {
        snow::Builder::new(super::params())
            .generate_keypair()
            .expect("X25519 keypair generation cannot fail")
    }

    pub fn parse_hex_key(s: &str) -> Result<Vec<u8>> {
        let s = s.trim();
        let s = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(s).map_err(|_| super::HandshakeError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_completes_with_matching_transcript() {
        let (c, s) = in_memory_handshake().unwrap();
        // Both sides derived the same handshake hash — the basis for the
        // HKDF-derived directional traffic keys.
        assert_eq!(c.get_handshake_hash(), s.get_handshake_hash());
    }

    #[test]
    fn initiator_identity_is_extractable_for_authorization() {
        // snow derives ss from the *decrypted* initiator static, so wire-level
        // parsing succeeds for any key. Authorization is therefore an explicit
        // membership check against get_remote_static() (as the server engine
        // does). This test pins that contract.
        let client_kp = keys::generate_keypair();
        let server_kp = keys::generate_keypair();

        let mut init = client_builder(&client_kp.private, &server_kp.public, &ZERO_PSK)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut resp = server_builder(&server_kp, &ZERO_PSK)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = init.write_message(PROLOGUE, &mut buf).unwrap();
        resp.read_message(&buf[..n], &mut vec![0u8; 4096]).unwrap();
        let seen = resp.get_remote_static().expect("static present");
        assert_eq!(seen, &client_kp.public);
    }

    #[test]
    fn psk_mismatch_fails() {
        let client_kp = keys::generate_keypair();
        let server_kp = keys::generate_keypair();
        let mut psk = ZERO_PSK;
        psk[0] = 0xAB;

        let mut init = client_builder(&client_kp.private, &server_kp.public, &psk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut resp = server_builder(&server_kp, &ZERO_PSK)
            .unwrap()
            .remote_public_key(&client_kp.public);

        let mut buf = vec![0u8; 4096];
        let n = init.write_message(PROLOGUE, &mut buf).unwrap();
        // psk0 mixes into message 1, so a PSK mismatch must fail here.
        let mut resp = resp.build_responder().unwrap();
        assert!(resp.read_message(&buf[..n], &mut vec![0u8; 4096]).is_err());
    }
}
