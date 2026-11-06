//! RNL v1 wire format: fixed 24-byte header + typed frames.
//!
//! Layout (big-endian / network byte order):
//!
//! ```text
//! offset  size  field
//! 0       2     Magic ("RN")
//! 2       1     Version (1)
//! 3       1     Frame type
//! 4       2     Flags
//! 6       2     Header length (24)
//! 8       8     Session ID
//! 16      8     Packet number (directional, per key epoch)
//! ```

use crate::error::{Error, Result};

pub const MAGIC: [u8; 2] = [0x52, 0x4E]; // "RN"
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;
pub const TAG_LEN: usize = 16; // Poly1305 tag appended by AEAD

/// Frame types. Unassigned values are reserved for future extensions.
pub mod frame {
    pub const CLIENT_HELLO: u8 = 0x01;
    pub const SERVER_HELLO: u8 = 0x02;
    pub const HANDSHAKE_FINISH: u8 = 0x03;
    pub const AUTHENTICATION: u8 = 0x04;
    pub const KEEPALIVE: u8 = 0x05;
    pub const PATH_CHALLENGE: u8 = 0x06;
    pub const PATH_RESPONSE: u8 = 0x07;
    pub const KEY_UPDATE: u8 = 0x08;
    pub const ACK: u8 = 0x09;
    pub const CONFIGURATION: u8 = 0x0A;
    pub const DISCONNECT: u8 = 0x0B;
    pub const DATA: u8 = 0x20;
    pub const RELIABLE_CONTROL: u8 = 0x21;

    pub fn is_known(t: u8) -> bool {
        matches!(
            t,
            CLIENT_HELLO
                | SERVER_HELLO
                | HANDSHAKE_FINISH
                | AUTHENTICATION
                | KEEPALIVE
                | PATH_CHALLENGE
                | PATH_RESPONSE
                | KEY_UPDATE
                | ACK
                | CONFIGURATION
                | DISCONNECT
                | DATA
                | RELIABLE_CONTROL
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub frame_type: u8,
    pub flags: u16,
    pub session_id: u64,
    pub packet_no: u64,
}

impl Header {
    pub fn new(frame_type: u8, session_id: u64, packet_no: u64) -> Self {
        Self {
            version: VERSION,
            frame_type,
            flags: 0,
            session_id,
            packet_no,
        }
    }

    pub fn encode_into(&self, buf: &mut [u8]) {
        assert!(buf.len() >= HEADER_LEN);
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = self.version;
        buf[3] = self.frame_type;
        buf[4..6].copy_from_slice(&self.flags.to_be_bytes());
        buf[6..8].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        buf[16..24].copy_from_slice(&self.packet_no.to_be_bytes());
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        self.encode_into(&mut out);
        out
    }

    /// Decode a header. Returns the header and the declared header length
    /// (allows future extensions to grow the header without breaking v1).
    pub fn decode(buf: &[u8]) -> Result<(Header, usize)> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort(buf.len()));
        }
        if buf[0..2] != MAGIC {
            return Err(Error::BadMagic);
        }
        if buf[2] != VERSION {
            return Err(Error::BadVersion(buf[2]));
        }
        let declared = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        if declared < HEADER_LEN {
            return Err(Error::BadHeaderLength {
                declared,
                available: buf.len(),
            });
        }
        if declared > buf.len() {
            return Err(Error::BadHeaderLength {
                declared,
                available: buf.len(),
            });
        }
        if !frame::is_known(buf[3]) {
            return Err(Error::UnknownFrame(buf[3]));
        }
        Ok((
            Header {
                version: buf[2],
                frame_type: buf[3],
                flags: u16::from_be_bytes([buf[4], buf[5]]),
                session_id: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
                packet_no: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
            },
            declared,
        ))
    }

    /// Header bytes as AEAD associated data.
    pub fn aad<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[..HEADER_LEN]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header::new(frame::DATA, 0xdead_beef_1234_5678, 42);
        let bytes = h.encode();
        assert_eq!(&bytes[0..2], b"RN");
        assert_eq!(bytes[2], 1);
        assert_eq!(bytes[3], frame::DATA);
        let (h2, len) = Header::decode(&bytes).unwrap();
        assert_eq!(len, HEADER_LEN);
        assert_eq!(h, h2);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = [0u8; HEADER_LEN];
        Header::new(frame::DATA, 1, 1).encode_into(&mut b);
        b[0] = 0x00;
        assert!(matches!(Header::decode(&b), Err(Error::BadMagic)));
    }

    #[test]
    fn rejects_unknown_frame() {
        let mut b = [0u8; HEADER_LEN];
        Header::new(0xEE, 1, 1).encode_into(&mut b);
        assert!(matches!(Header::decode(&b), Err(Error::UnknownFrame(0xEE))));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(matches!(Header::decode(&[0u8; 10]), Err(Error::TooShort(10))));
    }
}
