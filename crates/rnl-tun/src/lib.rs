//! Virtual network interface abstraction.
//!
//! `TunDevice` is what the engine reads/writes IP packets through. The
//! default build provides `LoopbackDevice` so the full encrypted data path
//! runs end-to-end without root. Kernel TUN (Linux, requires
//! CAP_NET_ADMIN) lands with Phase 1 completion; see README roadmap.

pub mod device;

pub use device::LoopbackDevice;
pub use device::TunDevice;
