//! Embedded Electrum protocol server for btc-rust.
//!
//! Experimental newline RPC chain/transaction subset with an actual provider.
//! Complete wallet protocol negotiation awaits the script-history index.

pub mod error;
pub mod handler;
pub mod methods;
pub mod protocol;
pub mod server;

pub use error::ElectrumError;
pub use handler::{ElectrumBackend, ElectrumHandler};
pub use protocol::{ElectrumError as ElectrumRpcError, ElectrumRequest, ElectrumResponse};
pub use server::ElectrumServer;
