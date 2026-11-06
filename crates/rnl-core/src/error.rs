use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid magic bytes")]
    BadMagic,
    #[error("unsupported protocol version: {0}")]
    BadVersion(u8),
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownFrame(u8),
    #[error("packet too short: {0} bytes")]
    TooShort(usize),
    #[error("header length mismatch: declared {declared}, buffer {available}")]
    BadHeaderLength { declared: usize, available: usize },
    #[error("session mismatch: expected {expected:#x}, got {got:#x}")]
    SessionMismatch { expected: u64, got: u64 },
    #[error("replayed packet number: {0}")]
    Replay(u64),
    #[error("crypto error: {0}")]
    Crypto(#[from] snow::Error),
    #[error("AEAD authentication failed")]
    Aead,
    #[error("handshake error: {0}")]
    Handshake(#[from] rnl_crypto::handshake::HandshakeError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout")]
    Timeout,
    #[error("transport degraded, failover available")]
    Degraded,
    #[error("transport closed")]
    Closed,
    #[error("config error: {0}")]
    Config(String),
    #[error("oversized frame: {size} bytes (max {max})")]
    Oversized { size: usize, max: usize },
}
