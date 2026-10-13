#[cfg(feature = "json-rpc")]
pub mod handler;
#[cfg(feature = "json-rpc")]
mod http;
#[cfg(feature = "json-rpc")]
pub mod methods;
#[cfg(feature = "json-rpc")]
pub mod server;
#[cfg(feature = "json-rpc")]
mod wire;

// JSON-RPC server for Bitcoin Core-compatible API
