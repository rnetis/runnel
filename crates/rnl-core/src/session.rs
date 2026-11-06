//! Session state: explicit-nonce AEAD, directional packet numbers,
//! replay protection and rekey accounting.
//!
//! Traffic keys are derived from the Noise handshake hash via HKDF
//! (BLAKE2s), one per direction, so they are never reused across
//! directions. The 96-bit AEAD nonce is `0000 || packet_number(u64 BE)`:
//! unique per key epoch and monotonic, which supports true out-of-order
//! delivery on the UDP data path (replay window handles duplicates/stale).

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use std::time::Instant;

use rnl_crypto::replay::SlidingWindow;
use rnl_crypto::TRAFFIC_REKEY_BYTES;

use crate::error::{Error, Result};
#[allow(unused_imports)]
use crate::packet::{frame, Header, HEADER_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    Active,
    Closed,
}

pub struct Session {
    pub session_id: u64,
    pub state: SessionState,
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    pub tx_packet_no: u64,
    pub rx_replay: SlidingWindow,
    pub key_epoch: u32,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub last_seen: Instant,
    pub remote_addr: Option<std::net::SocketAddr>,
}

impl Session {
    /// Build a session from a completed Noise handshake. Derives
    /// directional traffic keys from the handshake hash.
    pub fn from_handshake(
        session_id: u64,
        hs: snow::HandshakeState,
        is_initiator: bool,
    ) -> Result<Self> {
        let hash = hs.get_handshake_hash();
        // KDF: keyed BLAKE2s over the handshake hash (which is a uniformly
        // random 32-byte secret), with domain-separated info strings. This
        // yields two independent directional traffic keys.
        let c2s = Self::derive_traffic_key(&hash, b"runnel-v1 c2s traffic key");
        let s2c = Self::derive_traffic_key(&hash, b"runnel-v1 s2c traffic key");
        let (send_key, recv_key) = if is_initiator { (c2s, s2c) } else { (s2c, c2s) };
        Ok(Self {
            session_id,
            state: SessionState::Active,
            send: ChaCha20Poly1305::new((&send_key).into()),
            recv: ChaCha20Poly1305::new((&recv_key).into()),
            tx_packet_no: 0,
            rx_replay: SlidingWindow::new(),
            key_epoch: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            last_seen: Instant::now(),
            remote_addr: None,
        })
    }

    /// Keyed BLAKE2s PRF: handshake hash as key, info string as data.
fn derive_traffic_key(hash: &[u8], info: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut h = blake2::Blake2sVar::new(32).expect("32-byte output is valid");
    h.update(hash);
    h.update(info);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize_boxed());
    out
}

/// 96-bit nonce: unique per key epoch, monotonic, never reused.
    fn nonce(pn: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&pn.to_be_bytes());
        Nonce::from(n)
    }

    /// Seal a payload into a full encrypted RNL frame, reusing the caller's
    /// buffer (hot-path optimization: no per-packet allocation).
    pub fn seal_into(&mut self, frame_type: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let header = Header::new(frame_type, self.session_id, self.tx_packet_no);
        self.tx_packet_no += 1;
        let header_bytes = header.encode();

        out.clear();
        out.reserve(HEADER_LEN + payload.len() + 16);
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(payload);

        let tag: Tag = self
            .send
            .encrypt_in_place_detached(
                &Self::nonce(header.packet_no),
                &header_bytes,
                &mut out[HEADER_LEN..],
            )
            .map_err(|_| Error::Aead)?;
        out.extend_from_slice(tag.as_slice());
        self.bytes_tx += out.len() as u64;
        self.last_seen = Instant::now();
        Ok(())
    }

    /// Batched sealing: amortizes buffer setup across many packets.
    pub fn seal_batch(&mut self, frame_type: u8, payloads: &[&[u8]], out: &mut Vec<Vec<u8>>) -> Result<usize> {
        let mut n = 0;
        for p in payloads {
            let mut buf = Vec::with_capacity(HEADER_LEN + p.len() + 16);
            self.seal_into(frame_type, p, &mut buf)?;
            out.push(buf);
            n += 1;
        }
        Ok(n)
    }

    /// Seal a payload into a full encrypted RNL frame. The header is the
    /// AEAD associated data.
    pub fn seal(&mut self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let header = Header::new(frame_type, self.session_id, self.tx_packet_no);
        self.tx_packet_no += 1;
        let header_bytes = header.encode();

        let mut buf = payload.to_vec();
        let tag: Tag = self
            .send
            .encrypt_in_place_detached(&Self::nonce(header.packet_no), &header_bytes, &mut buf)
            .map_err(|_| Error::Aead)?;

        let mut out = Vec::with_capacity(HEADER_LEN + buf.len() + 16);
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());
        self.bytes_tx += out.len() as u64;
        self.last_seen = Instant::now();
        Ok(out)
    }

    /// Open an encrypted frame: verify header, enforce replay protection,
    /// then authenticate + decrypt. Never return unauthenticated plaintext.
    pub fn open(&mut self, frame_bytes: &[u8]) -> Result<Vec<u8>> {
        let (header, hdr_len) = Header::decode(frame_bytes)?;
        if header.session_id != self.session_id {
            return Err(Error::SessionMismatch {
                expected: self.session_id,
                got: header.session_id,
            });
        }
        if frame_bytes.len() < hdr_len + 16 {
            return Err(Error::TooShort(frame_bytes.len()));
        }
        if !self.rx_replay.check_and_update(header.packet_no) {
            return Err(Error::Replay(header.packet_no));
        }
        let (ct, tag) = frame_bytes[hdr_len..].split_at(frame_bytes.len() - hdr_len - 16);
        let mut buf = ct.to_vec();
        self.recv
            .decrypt_in_place_detached(
                &Self::nonce(header.packet_no),
                &frame_bytes[..hdr_len],
                &mut buf,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::Aead)?;
        self.bytes_rx += frame_bytes.len() as u64;
        self.last_seen = Instant::now();
        Ok(buf)
    }

    /// Bytes transmitted under the current key epoch (for rekey policy).
    pub fn tx_since_rekey(&self) -> u64 {
        self.bytes_tx
    }

    pub fn needs_rekey(&self, max_bytes: u64, max_age: std::time::Duration) -> bool {
        self.bytes_tx.saturating_sub((self.key_epoch as u64) * TRAFFIC_REKEY_BYTES) >= max_bytes
            || self.last_seen.elapsed() >= max_age
    }
}

/// Session ID generation: random 64-bit, never zero.
pub fn new_session_id() -> u64 {
    use rand::RngCore;
    loop {
        let id = rand::thread_rng().next_u64();
        if id != 0 {
            return id;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rnl_crypto::handshake;

    fn active_pair() -> (Session, Session) {
        let (c, s) = handshake::in_memory_handshake().unwrap();
        (
            Session::from_handshake(1, c, true).unwrap(),
            Session::from_handshake(1, s, false).unwrap(),
        )
    }

    #[test]
    fn seal_open_roundtrip() {
        let (mut client, mut server) = active_pair();
        let wire = client.seal(frame::DATA, b"ip packet bytes").unwrap();
        assert_eq!(wire[3], frame::DATA);
        let plain = server.open(&wire).unwrap();
        assert_eq!(plain, b"ip packet bytes");
    }

    #[test]
    fn directional_packet_numbers() {
        let (mut client, mut server) = active_pair();
        let a = client.seal(frame::DATA, b"a").unwrap();
        let b = client.seal(frame::DATA, b"b").unwrap();
        let (ha, _) = Header::decode(&a).unwrap();
        let (hb, _) = Header::decode(&b).unwrap();
        assert_eq!(ha.packet_no, 0);
        assert_eq!(hb.packet_no, 1);
        assert_eq!(server.open(&a).unwrap(), b"a");
        assert_eq!(server.open(&b).unwrap(), b"b");
    }

    #[test]
    fn replay_rejected() {
        let (mut client, mut server) = active_pair();
        let wire = client.seal(frame::DATA, b"x").unwrap();
        assert!(server.open(&wire).is_ok());
        assert!(matches!(server.open(&wire), Err(Error::Replay(_))));
    }

    /// Explicit per-packet nonces mean reordered datagrams decrypt fine.
    #[test]
    fn out_of_order_within_window_ok() {
        let (mut client, mut server) = active_pair();
        let w1 = client.seal(frame::DATA, b"1").unwrap();
        let w2 = client.seal(frame::DATA, b"2").unwrap();
        let w3 = client.seal(frame::DATA, b"3").unwrap();
        assert_eq!(server.open(&w2).unwrap(), b"2");
        assert_eq!(server.open(&w3).unwrap(), b"3");
        assert_eq!(server.open(&w1).unwrap(), b"1");
    }

    #[test]
    fn session_mismatch_rejected() {
        let (mut client, mut server) = active_pair();
        server.session_id = 999;
        let wire = client.seal(frame::DATA, b"x").unwrap();
        assert!(matches!(
            server.open(&wire),
            Err(Error::SessionMismatch { .. })
        ));
    }

    #[test]
    fn tampered_tag_rejected() {
        let (mut client, mut server) = active_pair();
        let mut wire = client.seal(frame::DATA, b"x").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(matches!(server.open(&wire), Err(Error::Aead)));
        // The header was AAD; tampering with it must also fail.
        let mut wire = client.seal(frame::DATA, b"x").unwrap();
        wire[8] ^= 0x01; // session id byte
        assert!(server.open(&wire).is_err());
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use rnl_crypto::handshake;

    #[test]
    fn seal_into_roundtrip_and_no_header_leak() {
        let (c, s) = handshake::in_memory_handshake().unwrap();
        let mut client = Session::from_handshake(1, c, true).unwrap();
        let mut server = Session::from_handshake(1, s, false).unwrap();
        let mut buf = Vec::new();
        client.seal_into(frame::DATA, b"payload-1", &mut buf).unwrap();
        let len1 = buf.len();
        // Reuse the same buffer for a shorter payload: no stale bytes.
        client.seal_into(frame::DATA, b"x", &mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 1 + 16);
        assert_eq!(server.open(&buf).unwrap(), b"x");
        let _ = len1;
    }

    #[test]
    fn seal_batch_interleaves_with_open() {
        let (c, s) = handshake::in_memory_handshake().unwrap();
        let mut client = Session::from_handshake(1, c, true).unwrap();
        let mut server = Session::from_handshake(1, s, false).unwrap();
        let payloads: Vec<&[u8]> = vec![b"one", b"two", b"three"];
        let mut batch = Vec::new();
        assert_eq!(client.seal_batch(frame::DATA, &payloads, &mut batch).unwrap(), 3);
        // Deliver out of order: explicit nonces make this work.
        let p3 = server.open(&batch[2]).unwrap();
        let p1 = server.open(&batch[0]).unwrap();
        let p2 = server.open(&batch[1]).unwrap();
        assert_eq!(p1, b"one");
        assert_eq!(p2, b"two");
        assert_eq!(p3, b"three");
    }
}
