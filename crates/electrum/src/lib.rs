//! Embedded Electrum protocol server for btc-rust.
//!
//! Implements the Electrum protocol (newline-delimited JSON-RPC over TCP)
//! so that wallets such as Electrum, Sparrow, or Blue Wallet can connect
//! directly without requiring a separate Electrs process.

pub mod protocol;
pub mod server;
pub mod methods;
pub mod handler;
pub mod error;

pub use error::ElectrumError;
pub use handler::ElectrumHandler;
pub use protocol::{ElectrumRequest, ElectrumResponse, ElectrumError as ElectrumRpcError};
pub use server::ElectrumServer;
