use btc_primitives::encode::{Encodable, Decodable, EncodeError, ReadExt, WriteExt};
use btc_primitives::hash::sha256d;
use std::io::{Read, Write};

/// Bitcoin P2P message header (24 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    pub magic: [u8; 4],
    pub command: [u8; 12],
    pub payload_size: u32,
    pub checksum: [u8; 4],
}

impl MessageHeader {
    pub const SIZE: usize = 24;

    pub fn new(magic: [u8; 4], command: &str, payload: &[u8]) -> Self {
        let mut cmd = [0u8; 12];
        let cmd_bytes = command.as_bytes();
        cmd[..cmd_bytes.len().min(12)].copy_from_slice(&cmd_bytes[..cmd_bytes.len().min(12)]);

        let checksum = sha256d(payload);

        MessageHeader {
            magic,
            command: cmd,
            payload_size: payload.len() as u32,
            checksum: [checksum[0], checksum[1], checksum[2], checksum[3]],
        }
    }

    pub fn command_str(&self) -> &str {
        let end = self.command.iter().position(|&b| b == 0).unwrap_or(12);
        std::str::from_utf8(&self.command[..end]).unwrap_or("unknown")
    }

    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        let hash = sha256d(payload);
        self.checksum == [hash[0], hash[1], hash[2], hash[3]]
    }
}

impl Encodable for MessageHeader {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        writer.write_all(&self.magic)?;
        writer.write_all(&self.command)?;
        writer.write_u32_le(self.payload_size)?;
        writer.write_all(&self.checksum)?;
        Ok(24)
    }
}

impl Decodable for MessageHeader {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let mut command = [0u8; 12];
        reader.read_exact(&mut command)?;
        let payload_size = reader.read_u32_le()?;
        let mut checksum = [0u8; 4];
        reader.read_exact(&mut checksum)?;
        Ok(MessageHeader { magic, command, payload_size, checksum })
    }
}

/// Bitcoin P2P network messages
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders(GetHeadersMessage),
    Headers(Vec<btc_primitives::block::BlockHeader>),
    GetBlocks(GetHeadersMessage),
    Inv(Vec<InvItem>),
    GetData(Vec<InvItem>),
    Block(btc_primitives::block::Block),
    Tx(btc_primitives::transaction::Transaction),
    Addr(Vec<NetAddress>),
    SendHeaders,
    FeeFilter(u64),
    Unknown(String, Vec<u8>),
}

impl NetworkMessage {
    pub fn command(&self) -> &str {
        match self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::FeeFilter(_) => "feefilter",
            NetworkMessage::Unknown(cmd, _) => cmd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: i64,
    pub receiver: NetAddress,
    pub sender: NetAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

#[derive(Debug, Clone)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub locator_hashes: Vec<btc_primitives::hash::BlockHash>,
    pub stop_hash: btc_primitives::hash::BlockHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvItem {
    pub inv_type: InvType,
    pub hash: btc_primitives::hash::Hash256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InvType {
    Error = 0,
    Tx = 1,
    Block = 2,
    FilteredBlock = 3,
    CompactBlock = 4,
    WitnessTx = 0x40000001,
    WitnessBlock = 0x40000002,
}

#[derive(Debug, Clone)]
pub struct NetAddress {
    pub services: u64,
    pub ip: [u8; 16], // IPv6-mapped
    pub port: u16,
}

impl Default for NetAddress {
    fn default() -> Self {
        NetAddress {
            services: 0,
            ip: [0; 16],
            port: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::encode;
    use btc_primitives::network::Network;

    #[test]
    fn test_message_header_roundtrip() {
        let payload = b"test payload";
        let header = MessageHeader::new(Network::Mainnet.magic(), "version", payload);

        assert_eq!(header.command_str(), "version");
        assert!(header.verify_checksum(payload));
        assert!(!header.verify_checksum(b"wrong"));

        let encoded = encode::encode(&header);
        assert_eq!(encoded.len(), 24);
        let decoded: MessageHeader = encode::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_message_commands() {
        assert_eq!(NetworkMessage::Verack.command(), "verack");
        assert_eq!(NetworkMessage::Ping(0).command(), "ping");
        assert_eq!(NetworkMessage::SendHeaders.command(), "sendheaders");
    }
}
