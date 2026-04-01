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
    WtxidRelay,
    NotFound(Vec<InvItem>),
    Reject {
        message: String,
        code: u8,
        reason: String,
        data: Vec<u8>,
    },
    MemPool,
    GetAddr,
    SendCmpct {
        announce: bool,
        version: u64,
    },
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
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::Reject { .. } => "reject",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::SendCmpct { .. } => "sendcmpct",
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
    WtxId = 5,
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
        assert_eq!(NetworkMessage::WtxidRelay.command(), "wtxidrelay");
        assert_eq!(NetworkMessage::NotFound(vec![]).command(), "notfound");
        assert_eq!(NetworkMessage::MemPool.command(), "mempool");
        assert_eq!(NetworkMessage::GetAddr.command(), "getaddr");
        assert_eq!(
            NetworkMessage::SendCmpct { announce: false, version: 1 }.command(),
            "sendcmpct"
        );
        assert_eq!(
            NetworkMessage::Reject {
                message: String::new(),
                code: 0,
                reason: String::new(),
                data: vec![],
            }
            .command(),
            "reject"
        );
    }

    // --- All message variant command strings ---

    #[test]
    fn test_all_command_strings() {
        let test_cases: Vec<(NetworkMessage, &str)> = vec![
            (
                NetworkMessage::Version(VersionMessage {
                    version: 70016,
                    services: 1,
                    timestamp: 0,
                    receiver: NetAddress::default(),
                    sender: NetAddress::default(),
                    nonce: 0,
                    user_agent: String::new(),
                    start_height: 0,
                    relay: true,
                }),
                "version",
            ),
            (NetworkMessage::Verack, "verack"),
            (NetworkMessage::Ping(0), "ping"),
            (NetworkMessage::Pong(0), "pong"),
            (
                NetworkMessage::GetHeaders(GetHeadersMessage {
                    version: 70016,
                    locator_hashes: vec![],
                    stop_hash: btc_primitives::hash::BlockHash::ZERO,
                }),
                "getheaders",
            ),
            (NetworkMessage::Headers(vec![]), "headers"),
            (
                NetworkMessage::GetBlocks(GetHeadersMessage {
                    version: 70016,
                    locator_hashes: vec![],
                    stop_hash: btc_primitives::hash::BlockHash::ZERO,
                }),
                "getblocks",
            ),
            (NetworkMessage::Inv(vec![]), "inv"),
            (NetworkMessage::GetData(vec![]), "getdata"),
            (
                NetworkMessage::Block(btc_primitives::block::Block {
                    header: btc_primitives::block::BlockHeader {
                        version: 1,
                        prev_blockhash: btc_primitives::hash::BlockHash::ZERO,
                        merkle_root: btc_primitives::hash::TxHash::from_bytes([0; 32]),
                        time: 0,
                        bits: btc_primitives::compact::CompactTarget::from_u32(0x1d00ffff),
                        nonce: 0,
                    },
                    transactions: vec![],
                }),
                "block",
            ),
            (
                NetworkMessage::Tx(btc_primitives::transaction::Transaction {
                    version: 1,
                    inputs: vec![],
                    outputs: vec![],
                    witness: vec![],
                    lock_time: 0,
                }),
                "tx",
            ),
            (NetworkMessage::Addr(vec![]), "addr"),
            (NetworkMessage::SendHeaders, "sendheaders"),
            (NetworkMessage::FeeFilter(0), "feefilter"),
            (NetworkMessage::WtxidRelay, "wtxidrelay"),
            (NetworkMessage::NotFound(vec![]), "notfound"),
            (
                NetworkMessage::Reject {
                    message: String::new(),
                    code: 0,
                    reason: String::new(),
                    data: vec![],
                },
                "reject",
            ),
            (NetworkMessage::MemPool, "mempool"),
            (NetworkMessage::GetAddr, "getaddr"),
            (
                NetworkMessage::SendCmpct {
                    announce: false,
                    version: 1,
                },
                "sendcmpct",
            ),
            (
                NetworkMessage::Unknown("custom".to_string(), vec![]),
                "custom",
            ),
        ];

        for (msg, expected_cmd) in test_cases {
            assert_eq!(msg.command(), expected_cmd, "command mismatch for {:?}", expected_cmd);
        }
    }

    // --- MessageHeader ---

    #[test]
    fn test_message_header_new() {
        let magic = Network::Mainnet.magic();
        let payload = b"test";
        let header = MessageHeader::new(magic, "ping", payload);
        assert_eq!(header.magic, magic);
        assert_eq!(header.command_str(), "ping");
        assert_eq!(header.payload_size, 4);
        assert!(header.verify_checksum(payload));
    }

    #[test]
    fn test_message_header_size_constant() {
        assert_eq!(MessageHeader::SIZE, 24);
    }

    #[test]
    fn test_message_header_encode_decode() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "verack", b"");
        let encoded = encode::encode(&header);
        assert_eq!(encoded.len(), 24);
        let decoded: MessageHeader = encode::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_message_header_verify_checksum_wrong_data() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "ping", b"hello");
        assert!(header.verify_checksum(b"hello"));
        assert!(!header.verify_checksum(b"world"));
        assert!(!header.verify_checksum(b""));
    }

    #[test]
    fn test_message_header_command_str_null_padded() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "tx", b"");
        assert_eq!(header.command_str(), "tx");
    }

    #[test]
    fn test_message_header_command_str_full_length() {
        // 12-byte command name
        let header = MessageHeader::new(Network::Mainnet.magic(), "abcdefghijkl", b"");
        assert_eq!(header.command_str(), "abcdefghijkl");
    }

    #[test]
    fn test_message_header_command_truncates_long_name() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "toolongcommand", b"");
        // Should be truncated to 12 bytes
        assert_eq!(header.command_str(), "toolongcomma");
    }

    // --- NetAddress ---

    #[test]
    fn test_net_address_default() {
        let addr = NetAddress::default();
        assert_eq!(addr.services, 0);
        assert_eq!(addr.ip, [0; 16]);
        assert_eq!(addr.port, 0);
    }

    #[test]
    fn test_net_address_ipv4_mapped() {
        let addr = NetAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
            port: 8333,
        };
        assert_eq!(addr.services, 1);
        assert_eq!(addr.ip[12], 192);
        assert_eq!(addr.ip[13], 168);
        assert_eq!(addr.ip[14], 1);
        assert_eq!(addr.ip[15], 1);
        assert_eq!(addr.port, 8333);
    }

    // --- InvType ---

    #[test]
    fn test_inv_type_values() {
        assert_eq!(InvType::Error as u32, 0);
        assert_eq!(InvType::Tx as u32, 1);
        assert_eq!(InvType::Block as u32, 2);
        assert_eq!(InvType::FilteredBlock as u32, 3);
        assert_eq!(InvType::CompactBlock as u32, 4);
        assert_eq!(InvType::WtxId as u32, 5);
        assert_eq!(InvType::WitnessTx as u32, 0x40000001);
        assert_eq!(InvType::WitnessBlock as u32, 0x40000002);
    }

    // --- InvItem ---

    #[test]
    fn test_inv_item_equality() {
        let item1 = InvItem {
            inv_type: InvType::Tx,
            hash: btc_primitives::hash::Hash256::from_bytes([0xaa; 32]),
        };
        let item2 = InvItem {
            inv_type: InvType::Tx,
            hash: btc_primitives::hash::Hash256::from_bytes([0xaa; 32]),
        };
        let item3 = InvItem {
            inv_type: InvType::Block,
            hash: btc_primitives::hash::Hash256::from_bytes([0xaa; 32]),
        };
        assert_eq!(item1, item2);
        assert_ne!(item1, item3);
    }

    #[test]
    fn test_inv_item_copy() {
        let item = InvItem {
            inv_type: InvType::Tx,
            hash: btc_primitives::hash::Hash256::from_bytes([0xbb; 32]),
        };
        let copy = item;
        assert_eq!(item, copy);
    }

    // --- GetHeadersMessage ---

    #[test]
    fn test_get_headers_message_clone() {
        let msg = GetHeadersMessage {
            version: 70016,
            locator_hashes: vec![
                btc_primitives::hash::BlockHash::from_bytes([0x01; 32]),
                btc_primitives::hash::BlockHash::from_bytes([0x02; 32]),
            ],
            stop_hash: btc_primitives::hash::BlockHash::ZERO,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.version, msg.version);
        assert_eq!(cloned.locator_hashes.len(), msg.locator_hashes.len());
    }

    // --- VersionMessage ---

    #[test]
    fn test_version_message_clone() {
        let ver = VersionMessage {
            version: 70016,
            services: 0x040d,
            timestamp: 1_700_000_000,
            receiver: NetAddress {
                services: 1,
                ip: [0; 16],
                port: 8333,
            },
            sender: NetAddress {
                services: 1,
                ip: [0; 16],
                port: 8334,
            },
            nonce: 0xdeadbeef,
            user_agent: "/btc-rust:0.1.0/".to_string(),
            start_height: 800_000,
            relay: true,
        };
        let cloned = ver.clone();
        assert_eq!(cloned.version, ver.version);
        assert_eq!(cloned.services, ver.services);
        assert_eq!(cloned.timestamp, ver.timestamp);
        assert_eq!(cloned.nonce, ver.nonce);
        assert_eq!(cloned.user_agent, ver.user_agent);
        assert_eq!(cloned.start_height, ver.start_height);
        assert_eq!(cloned.relay, ver.relay);
        assert_eq!(cloned.receiver.port, ver.receiver.port);
        assert_eq!(cloned.sender.port, ver.sender.port);
    }

    // --- NetworkMessage Debug ---

    #[test]
    fn test_network_message_debug() {
        let msg = NetworkMessage::Verack;
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("Verack"));
    }

    #[test]
    fn test_network_message_clone() {
        let msg = NetworkMessage::Ping(42);
        let cloned = msg.clone();
        assert_eq!(cloned.command(), "ping");
    }
}
