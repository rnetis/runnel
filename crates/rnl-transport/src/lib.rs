//! Transport abstraction: one protocol, many carriers.

pub mod tcp;
pub mod traits;
pub mod udp;
#[cfg(all(feature = "sctp", target_os = "linux"))]
pub mod sctp;

pub use traits::{Transport, TransportError, TransportKind};
pub use tcp::TcpTransport;
pub use udp::UdpTransport;
#[cfg(all(feature = "sctp", target_os = "linux"))]
pub use sctp::SctpTransport;
