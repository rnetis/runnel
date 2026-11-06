//! Stream framing for datagram-lossy transports.
//!
//! UDP preserves datagram boundaries natively, so each encrypted frame maps to
//! exactly one datagram. TCP/SCTP stream adapters use a 4-byte unsigned
//! big-endian length prefix per frame; a stream read never maps 1:1 to a
//! frame, so receivers must buffer and re-synchronize.

use crate::error::{Error, Result};

pub const LENGTH_PREFIX: usize = 4;
/// Hard cap on a single framed frame (prevents unbounded allocations).
pub const MAX_FRAME_LEN: usize = 65536;

/// Prefix a frame with its 4-byte big-endian length.
pub fn encode_framed(frame: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(Error::Oversized {
            size: frame.len(),
            max: MAX_FRAME_LEN,
        });
    }
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    Ok(())
}

/// Accumulated stream decoder state.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw stream bytes; returns complete frames in order.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        loop {
            if self.buf.len() < LENGTH_PREFIX {
                break;
            }
            let len = u32::from_be_bytes(self.buf[0..4].try_into().unwrap()) as usize;
            if len > MAX_FRAME_LEN {
                return Err(Error::Oversized {
                    size: len,
                    max: MAX_FRAME_LEN,
                });
            }
            if self.buf.len() < LENGTH_PREFIX + len {
                break;
            }
            let frame = self.buf[LENGTH_PREFIX..LENGTH_PREFIX + len].to_vec();
            self.buf.drain(..LENGTH_PREFIX + len);
            frames.push(frame);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_split_reads() {
        let mut wire = Vec::new();
        encode_framed(b"hello", &mut wire).unwrap();
        encode_framed(b"rnl frame two", &mut wire).unwrap();

        let mut dec = FrameDecoder::new();
        // Simulate TCP: partial reads never map 1:1 to frames; frames come
        // out in order as soon as their bytes are complete.
        assert_eq!(dec.feed(&wire[..3]).unwrap().len(), 0);
        let f1 = dec.feed(&wire[3..10]).unwrap();
        assert_eq!(f1, vec![b"hello".to_vec()]);
        let frames = dec.feed(&wire[10..]).unwrap();
        assert_eq!(frames, vec![b"rnl frame two".to_vec()]);
    }

    #[test]
    fn rejects_oversized() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes());
        assert!(decodes_err(&wire));
        fn decodes_err(w: &[u8]) -> bool {
            FrameDecoder::new().feed(w).is_err()
        }
    }
}
