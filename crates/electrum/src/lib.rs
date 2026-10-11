//! Embedded Electrum protocol server for btc-rust.
//!
//! Implements the Electrum protocol (newline-delimited JSON-RPC over TCP)
//! so that wallets such as Electrum, Sparrow, or Blue Wallet can connect
//! directly without requiring a separate Electrs process.

pub mod error;
pub mod handler;
pub mod methods;
pub mod protocol;
pub mod server;

pub use error::ElectrumError;
pub use handler::ElectrumHandler;
pub use protocol::{ElectrumError as ElectrumRpcError, ElectrumRequest, ElectrumResponse};
pub use server::ElectrumServer;
