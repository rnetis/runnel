use std::net::SocketAddr;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Udp,
    Tcp,
    Sctp,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport closed")]
    Closed,
    #[error("no remote address bound yet")]
    NoPeer,
    #[error("frame too large: {size} bytes (buffer {max})")]
    FrameTooLarge { size: usize, max: usize },
}

/// The single interface the RNL core sees. The core never knows which
/// carrier is underneath.
///
/// UDP: one datagram per frame. TCP/SCTP adapters wrap this with
/// length-prefix / message-boundary framing internally.
#[async_trait]
pub trait Transport: Send + Sync {
    fn kind(&self) -> TransportKind;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn remote_addr(&self) -> Option<SocketAddr>;
    async fn send(&self, frame: &[u8]) -> Result<(), TransportError>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError>;
    async fn close(&self) -> Result<(), TransportError>;
}
