//! TCP transport: compatibility carrier. Length-prefixed framing over a
//! stream — one read never maps to one frame. The kernel provides
//! reliability and congestion control; RNL adds no retransmission.

use std::net::SocketAddr;
use tokio::sync::Mutex;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use rnl_core::framing::{encode_framed, FrameDecoder, LENGTH_PREFIX};

use crate::traits::{Transport, TransportError, TransportKind};

/// Hard cap on buffered bytes for a single incoming frame.
const MAX_FRAME: usize = rnl_core::framing::MAX_FRAME_LEN;

pub struct TcpTransport {
    reader: Mutex<tokio::net::tcp::OwnedReadHalf>,
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    peer: SocketAddr,
    local: SocketAddr,
    decoder: Mutex<FrameDecoder>,
    /// Frames decoded ahead of consumption (multiple frames per read).
    pending: Mutex<std::collections::VecDeque<Vec<u8>>>,
}

impl TcpTransport {
    pub async fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self::from_stream(stream))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        let peer = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let local = stream
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let (r, w) = stream.into_split();
        Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            peer,
            local,
            decoder: Mutex::new(FrameDecoder::new()),
            pending: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Send one frame with its 4-byte big-endian length prefix.
    pub async fn send_frame(&self, frame: &[u8]) -> Result<(), TransportError> {
        let mut wire = Vec::with_capacity(LENGTH_PREFIX + frame.len());
        encode_framed(frame, &mut wire).map_err(|e| TransportError::FrameTooLarge {
            size: e_size(&e),
            max: MAX_FRAME,
        })?;
        let mut w = self.writer.lock().await;
        w.write_all(&wire).await?;
        w.flush().await?;
        Ok(())
    }

    /// Receive the next complete frame into `buf`. Blocks on the stream;
    /// partial reads are reassembled by the decoder and frames decoded ahead
    /// of consumption are queued. Returns the frame length.
    pub async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        loop {
            // Frames already decoded by previous reads?
            if let Some(f) = self.pending.lock().await.pop_front() {
                return self.copy_out(f, buf);
            }
            let mut r = self.reader.lock().await;
            let mut chunk = [0u8; 8192];
            let n = r.read(&mut chunk).await?;
            drop(r);
            if n == 0 {
                return Err(TransportError::Closed);
            }
            let frames = self
                .decoder
                .lock()
                .await
                .feed(&chunk[..n])
                .map_err(core_to_te)?;
            let mut q = self.pending.lock().await;
            for f in frames {
                q.push_back(f);
            }
        }
    }

    fn copy_out(
        &self,
        frame: Vec<u8>,
        buf: &mut [u8],
    ) -> Result<usize, TransportError> {
        if frame.len() > buf.len() {
            return Err(TransportError::FrameTooLarge {
                size: frame.len(),
                max: buf.len(),
            });
        }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        self.send_frame(frame).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.recv_frame(buf).await
    }

    async fn close(&self) -> Result<(), TransportError> {
        let mut w = self.writer.lock().await;
        w.shutdown().await?;
        Ok(())
    }
}

fn core_to_te(e: rnl_core::Error) -> TransportError {
    match e {
        rnl_core::Error::Oversized { size, max } => {
            TransportError::FrameTooLarge { size, max }
        }
        rnl_core::Error::Io(io) => TransportError::Io(io),
        _ => TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )),
    }
}

fn e_size(e: &rnl_core::Error) -> usize {
    match e {
        rnl_core::Error::Oversized { size, .. } => *size,
        _ => MAX_FRAME,
    }
}
