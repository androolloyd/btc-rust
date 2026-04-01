pub mod addrv2;
pub mod codec;
pub mod connection;
pub mod discovery;
pub mod handshake;
pub mod message;
pub mod peer;
pub mod protocol;
pub mod tx_relay;

#[cfg(feature = "compact-blocks")]
pub mod compact_blocks;

#[cfg(feature = "erlay")]
pub mod erlay;

#[cfg(feature = "package-relay")]
pub mod package_relay;

#[cfg(feature = "v2")]
pub mod v2transport;

pub use codec::BitcoinCodec;
pub use connection::Connection;
pub use handshake::Handshake;
pub use message::{NetworkMessage, MessageHeader};
pub use protocol::ProtocolVersion;

#[cfg(feature = "compact-blocks")]
pub use compact_blocks::CompactBlock;
