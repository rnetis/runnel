//! Transport capability negotiation (CONFIGURATION frames, type 0x0A).
//!
//! After the handshake, the client advertises what it supports; the server
//! responds with its own capabilities plus the endpoints for additional
//! carriers (currently the TCP fallback endpoint). Flags are bits so future
//! transports extend without a format change.

pub const FLAG_UDP: u8 = 1 << 0;
pub const FLAG_TCP: u8 = 1 << 1;
pub const FLAG_SCTP: u8 = 1 << 2;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub udp: bool,
    pub tcp: bool,
    pub sctp: bool,
    /// Endpoint for the additional carrier, e.g. "203.0.113.7:45821".
    pub tcp_endpoint: Option<String>,
}

impl Capabilities {
    pub fn flags(&self) -> u8 {
        let mut f = 0;
        if self.udp {
            f |= FLAG_UDP;
        }
        if self.tcp {
            f |= FLAG_TCP;
        }
        if self.sctp {
            f |= FLAG_SCTP;
        }
        f
    }

    /// Client advertisement: flags only.
    pub fn encode_client(&self) -> Vec<u8> {
        vec![self.flags()]
    }

    /// Server advertisement: flags + optional TCP endpoint.
    pub fn encode_server(&self) -> Vec<u8> {
        let mut out = vec![self.flags()];
        if let Some(ep) = &self.tcp_endpoint {
            let b = ep.as_bytes();
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            out.extend_from_slice(b);
        } else {
            out.extend_from_slice(&0u16.to_be_bytes());
        }
        out
    }

    pub fn decode_client(payload: &[u8]) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::TooShort(payload.len()));
        }
        Ok(Self {
            udp: payload[0] & FLAG_UDP != 0,
            tcp: payload[0] & FLAG_TCP != 0,
            sctp: payload[0] & FLAG_SCTP != 0,
            tcp_endpoint: None,
        })
    }

    pub fn decode_server(payload: &[u8]) -> Result<Self> {
        if payload.len() < 3 {
            return Err(Error::TooShort(payload.len()));
        }
        let mut caps = Self {
            udp: payload[0] & FLAG_UDP != 0,
            tcp: payload[0] & FLAG_TCP != 0,
            sctp: payload[0] & FLAG_SCTP != 0,
            tcp_endpoint: None,
        };
        let len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
        if len > 0 {
            if payload.len() < 3 + len {
                return Err(Error::TooShort(payload.len()));
            }
            caps.tcp_endpoint =
                Some(String::from_utf8_lossy(&payload[3..3 + len]).into_owned());
        }
        Ok(caps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_roundtrip() {
        let caps = Capabilities {
            udp: true,
            tcp: true,
            sctp: false,
            tcp_endpoint: None,
        };
        let dec = Capabilities::decode_client(&caps.encode_client()).unwrap();
        assert_eq!(dec, caps);
    }

    #[test]
    fn server_roundtrip_with_endpoint() {
        let caps = Capabilities {
            udp: true,
            tcp: true,
            sctp: false,
            tcp_endpoint: Some("203.0.113.7:45821".into()),
        };
        let dec = Capabilities::decode_server(&caps.encode_server()).unwrap();
        assert_eq!(dec, caps);
    }

    #[test]
    fn server_without_endpoint() {
        let caps = Capabilities {
            udp: true,
            ..Default::default()
        };
        let dec = Capabilities::decode_server(&caps.encode_server()).unwrap();
        assert!(dec.tcp_endpoint.is_none());
    }

    #[test]
    fn truncated_rejected() {
        assert!(Capabilities::decode_server(&[0x01]).is_err());
        assert!(Capabilities::decode_server(&[0x01, 0, 5, b'a']).is_err());
        assert!(Capabilities::decode_client(&[]).is_err());
    }
}
