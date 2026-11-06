//! Congestion control and scheduling for the UDP data path.
//!
//! v0.1 implements a NewReno-style, ACK-paced controller. ACKs here are
//! congestion feedback only — lost VPN data packets are *not* retransmitted;
//! reliability belongs to the inner transports.

pub mod controller;
pub mod paths;
pub mod scheduler;

pub use controller::NewReno;
pub use paths::{NetworkPath, PathManager};
pub use scheduler::{Priority, Scheduler};
