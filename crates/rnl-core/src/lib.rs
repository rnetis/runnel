//! RNL (Runnel) core: packet format, framing, sessions, errors.

pub mod error;
pub mod framing;
pub mod mtu;
pub mod negotiation;
pub mod packet;
pub mod pool;
pub mod session;

pub use error::{Error, Result};
pub use mtu::{MtuDiscovery, BASE_MTU};
pub use negotiation::Capabilities;
pub use packet::{Header, HEADER_LEN, MAGIC, VERSION};
pub use pool::BufferPool;
pub use session::{Session, SessionState};
