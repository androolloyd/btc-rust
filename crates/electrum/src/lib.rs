//! Embedded Electrum protocol server for btc-rust.
//!
//! Bounded local Electrum 1.4 service with an actual validated provider.

pub mod error;
pub mod handler;
pub mod methods;
mod negotiation;
pub mod protocol;
pub mod server;

pub use error::ElectrumError;
pub use handler::{ElectrumBackend, ElectrumHandler};
pub use protocol::{ElectrumError as ElectrumRpcError, ElectrumRequest, ElectrumResponse};
pub use server::ElectrumServer;
