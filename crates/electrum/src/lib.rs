//! Embedded Electrum protocol server for btc-rust.
//!
//! Experimental newline RPC chain/transaction subset with an actual provider.
//! Complete protocol negotiation awaits status subscriptions and remaining methods.

pub mod error;
pub mod handler;
pub mod methods;
pub mod protocol;
pub mod server;

pub use error::ElectrumError;
pub use handler::{ElectrumBackend, ElectrumHandler};
pub use protocol::{ElectrumError as ElectrumRpcError, ElectrumRequest, ElectrumResponse};
pub use server::ElectrumServer;
