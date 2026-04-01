use bytes::{Buf, BufMut, BytesMut};
use btc_primitives::encode::{
    Decodable, Encodable, EncodeError, ReadExt, VarInt, WriteExt,
};
use std::io::{Cursor, Read, Write};
use tokio_util::codec::{Decoder, Encoder};

use crate::message::{
    GetHeadersMessage, InvItem, InvType, MessageHeader, NetAddress, NetworkMessage, VersionMessage,
};

/// Maximum payload size (32 MB, matching Bitcoin Core MAX_SIZE)
const MAX_PAYLOAD_SIZE: u32 = 32 * 1024 * 1024;

/// Bitcoin P2P protocol codec for use with tokio_util::codec::Framed.
///
/// Implements Decoder/Encoder to handle the Bitcoin wire format:
/// - 24-byte header: magic(4) + command(12) + payload_size(4) + checksum(4)
/// - variable-length payload
pub struct BitcoinCodec {
    magic: [u8; 4],
}

impl BitcoinCodec {
    pub fn new(magic: [u8; 4]) -> Self {
        BitcoinCodec { magic }
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers for message sub-types
// ---------------------------------------------------------------------------

/// Encode a NetAddress (without timestamp, as used in version message)
fn encode_net_address<W: Write>(addr: &NetAddress, w: &mut W) -> Result<usize, EncodeError> {
    let mut written = 0;
    written += w.write_u64_le(addr.services)?;
    w.write_all(&addr.ip)?;
    written += 16;
    // Port is big-endian on the wire
    w.write_all(&addr.port.to_be_bytes())?;
    written += 2;
    Ok(written)
}

fn decode_net_address<R: Read>(r: &mut R) -> Result<NetAddress, EncodeError> {
    let services = r.read_u64_le()?;
    let mut ip = [0u8; 16];
    r.read_exact(&mut ip)?;
    let mut port_bytes = [0u8; 2];
    r.read_exact(&mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);
    Ok(NetAddress { services, ip, port })
}

/// Encode a VersionMessage payload
fn encode_version<W: Write>(msg: &VersionMessage, w: &mut W) -> Result<usize, EncodeError> {
    let mut written = 0;
    written += w.write_u32_le(msg.version)?;        // 4
    written += w.write_u64_le(msg.services)?;        // 8
    written += w.write_i64_le(msg.timestamp)?;       // 8
    written += encode_net_address(&msg.receiver, w)?; // 26
    written += encode_net_address(&msg.sender, w)?;   // 26
    written += w.write_u64_le(msg.nonce)?;           // 8
    // user_agent as var_str
    let ua_bytes = msg.user_agent.as_bytes();
    written += VarInt(ua_bytes.len() as u64).encode(w)?;
    w.write_all(ua_bytes)?;
    written += ua_bytes.len();
    written += w.write_i32_le(msg.start_height)?;    // 4
    written += w.write_u8(if msg.relay { 1 } else { 0 })?; // 1
    Ok(written)
}

fn decode_version<R: Read>(r: &mut R) -> Result<VersionMessage, EncodeError> {
    let version = r.read_u32_le()?;
    let services = r.read_u64_le()?;
    let timestamp = r.read_i64_le()?;
    let receiver = decode_net_address(r)?;
    let sender = decode_net_address(r)?;
    let nonce = r.read_u64_le()?;
    // user_agent as var_str
    let ua_len = VarInt::decode(r)?.0 as usize;
    if ua_len > 4096 {
        return Err(EncodeError::InvalidData("user agent too long".into()));
    }
    let ua_bytes = r.read_bytes(ua_len)?;
    let user_agent =
        String::from_utf8(ua_bytes).map_err(|e| EncodeError::InvalidData(e.to_string()))?;
    let start_height = r.read_i32_le()?;
    // relay byte is optional (BIP 37); if not present, default to true
    let relay = match r.read_u8() {
        Ok(b) => b != 0,
        Err(_) => true,
    };
    Ok(VersionMessage {
        version,
        services,
        timestamp,
        receiver,
        sender,
        nonce,
        user_agent,
        start_height,
        relay,
    })
}

fn encode_inv_item<W: Write>(item: &InvItem, w: &mut W) -> Result<usize, EncodeError> {
    let mut written = 0;
    written += w.write_u32_le(item.inv_type as u32)?;
    w.write_all(item.hash.as_bytes())?;
    written += 32;
    Ok(written)
}

fn decode_inv_item<R: Read>(r: &mut R) -> Result<InvItem, EncodeError> {
    let type_val = r.read_u32_le()?;
    let inv_type = match type_val {
        0 => InvType::Error,
        1 => InvType::Tx,
        2 => InvType::Block,
        3 => InvType::FilteredBlock,
        4 => InvType::CompactBlock,
        5 => InvType::WtxId,
        0x40000001 => InvType::WitnessTx,
        0x40000002 => InvType::WitnessBlock,
        // Treat unknown inv types as Error rather than failing the entire message
        _ => InvType::Error,
    };
    let hash = btc_primitives::hash::Hash256::from_bytes(r.read_hash256()?);
    Ok(InvItem { inv_type, hash })
}

fn encode_inv_vec<W: Write>(items: &[InvItem], w: &mut W) -> Result<usize, EncodeError> {
    let mut written = VarInt(items.len() as u64).encode(w)?;
    for item in items {
        written += encode_inv_item(item, w)?;
    }
    Ok(written)
}

fn decode_inv_vec<R: Read>(r: &mut R) -> Result<Vec<InvItem>, EncodeError> {
    let count = VarInt::decode(r)?.0 as usize;
    if count > 50_000 {
        return Err(EncodeError::InvalidData(format!(
            "inv vector too large: {count} items (max 50000)"
        )));
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(decode_inv_item(r)?);
    }
    Ok(items)
}

fn encode_getheaders<W: Write>(
    msg: &GetHeadersMessage,
    w: &mut W,
) -> Result<usize, EncodeError> {
    let mut written = 0;
    written += w.write_u32_le(msg.version)?;
    written += VarInt(msg.locator_hashes.len() as u64).encode(w)?;
    for hash in &msg.locator_hashes {
        w.write_all(hash.as_bytes())?;
        written += 32;
    }
    w.write_all(msg.stop_hash.as_bytes())?;
    written += 32;
    Ok(written)
}

fn decode_getheaders<R: Read>(r: &mut R) -> Result<GetHeadersMessage, EncodeError> {
    let version = r.read_u32_le()?;
    let count = VarInt::decode(r)?.0 as usize;
    if count > 101 {
        return Err(EncodeError::InvalidData("too many locator hashes".into()));
    }
    let mut locator_hashes = Vec::with_capacity(count.min(101));
    for _ in 0..count {
        locator_hashes.push(btc_primitives::hash::BlockHash::from_bytes(
            r.read_hash256()?,
        ));
    }
    let stop_hash = btc_primitives::hash::BlockHash::from_bytes(r.read_hash256()?);
    Ok(GetHeadersMessage {
        version,
        locator_hashes,
        stop_hash,
    })
}

/// Encode a vector of block headers for the "headers" message.
/// Each header is followed by a tx_count varint (always 0).
fn encode_headers<W: Write>(
    headers: &[btc_primitives::block::BlockHeader],
    w: &mut W,
) -> Result<usize, EncodeError> {
    let mut written = VarInt(headers.len() as u64).encode(w)?;
    for hdr in headers {
        written += hdr.encode(w)?;
        // tx_count = 0 (required by the protocol, even though we never send txs here)
        written += VarInt(0).encode(w)?;
    }
    Ok(written)
}

fn decode_headers<R: Read>(
    r: &mut R,
) -> Result<Vec<btc_primitives::block::BlockHeader>, EncodeError> {
    let count = VarInt::decode(r)?.0 as usize;
    if count > 2_000 {
        return Err(EncodeError::InvalidData("too many headers".into()));
    }
    let mut headers = Vec::with_capacity(count.min(2000));
    for _ in 0..count {
        headers.push(btc_primitives::block::BlockHeader::decode(r)?);
        // Read and discard the tx_count varint (should be 0)
        let _tx_count = VarInt::decode(r)?;
    }
    Ok(headers)
}

fn encode_addr_vec<W: Write>(addrs: &[NetAddress], w: &mut W) -> Result<usize, EncodeError> {
    let mut written = VarInt(addrs.len() as u64).encode(w)?;
    for addr in addrs {
        // addr messages include a 4-byte timestamp before each address
        written += w.write_u32_le(0)?; // timestamp placeholder
        written += encode_net_address(addr, w)?;
    }
    Ok(written)
}

fn decode_addr_vec<R: Read>(r: &mut R) -> Result<Vec<NetAddress>, EncodeError> {
    let count = VarInt::decode(r)?.0 as usize;
    if count > 1_000 {
        return Err(EncodeError::InvalidData("too many addresses".into()));
    }
    let mut addrs = Vec::with_capacity(count.min(1000));
    for _ in 0..count {
        let _timestamp = r.read_u32_le()?;
        addrs.push(decode_net_address(r)?);
    }
    Ok(addrs)
}

// ---------------------------------------------------------------------------
// Serialize a NetworkMessage to its payload bytes
// ---------------------------------------------------------------------------

/// Serialize the payload of a NetworkMessage.
pub fn encode_payload(msg: &NetworkMessage) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::new();
    match msg {
        NetworkMessage::Version(v) => {
            encode_version(v, &mut buf)?;
        }
        NetworkMessage::Verack => {} // empty payload
        NetworkMessage::Ping(nonce) => {
            buf.write_u64_le(*nonce)?;
        }
        NetworkMessage::Pong(nonce) => {
            buf.write_u64_le(*nonce)?;
        }
        NetworkMessage::Inv(items) => {
            encode_inv_vec(items, &mut buf)?;
        }
        NetworkMessage::GetData(items) => {
            encode_inv_vec(items, &mut buf)?;
        }
        NetworkMessage::GetHeaders(gh) => {
            encode_getheaders(gh, &mut buf)?;
        }
        NetworkMessage::GetBlocks(gb) => {
            encode_getheaders(gb, &mut buf)?;
        }
        NetworkMessage::Headers(hdrs) => {
            encode_headers(hdrs, &mut buf)?;
        }
        NetworkMessage::Block(block) => {
            block.encode(&mut buf)?;
        }
        NetworkMessage::Tx(tx) => {
            tx.encode(&mut buf)?;
        }
        NetworkMessage::Addr(addrs) => {
            encode_addr_vec(addrs, &mut buf)?;
        }
        NetworkMessage::SendHeaders => {} // empty payload
        NetworkMessage::FeeFilter(rate) => {
            buf.write_u64_le(*rate)?;
        }
        NetworkMessage::WtxidRelay => {} // empty payload
        NetworkMessage::NotFound(items) => {
            encode_inv_vec(items, &mut buf)?;
        }
        NetworkMessage::Reject {
            message,
            code,
            reason,
            data,
        } => {
            // var_str message
            let msg_bytes = message.as_bytes();
            VarInt(msg_bytes.len() as u64).encode(&mut buf)?;
            buf.write_all(msg_bytes)?;
            // u8 code
            buf.write_u8(*code)?;
            // var_str reason
            let reason_bytes = reason.as_bytes();
            VarInt(reason_bytes.len() as u64).encode(&mut buf)?;
            buf.write_all(reason_bytes)?;
            // extra data (e.g. hash)
            buf.extend_from_slice(data);
        }
        NetworkMessage::MemPool => {} // empty payload
        NetworkMessage::GetAddr => {} // empty payload
        NetworkMessage::SendCmpct { announce, version } => {
            buf.write_u8(if *announce { 1 } else { 0 })?;
            buf.write_u64_le(*version)?;
        }
        NetworkMessage::Unknown(_, data) => {
            buf.extend_from_slice(data);
        }
    }
    Ok(buf)
}

/// Deserialize a NetworkMessage payload given the command string.
pub fn decode_payload(command: &str, payload: &[u8]) -> Result<NetworkMessage, EncodeError> {
    let mut cursor = Cursor::new(payload);
    match command {
        "version" => Ok(NetworkMessage::Version(decode_version(&mut cursor)?)),
        "verack" => Ok(NetworkMessage::Verack),
        "ping" => {
            let nonce = cursor.read_u64_le()?;
            Ok(NetworkMessage::Ping(nonce))
        }
        "pong" => {
            let nonce = cursor.read_u64_le()?;
            Ok(NetworkMessage::Pong(nonce))
        }
        "inv" => Ok(NetworkMessage::Inv(decode_inv_vec(&mut cursor)?)),
        "getdata" => Ok(NetworkMessage::GetData(decode_inv_vec(&mut cursor)?)),
        "getheaders" => Ok(NetworkMessage::GetHeaders(decode_getheaders(&mut cursor)?)),
        "getblocks" => Ok(NetworkMessage::GetBlocks(decode_getheaders(&mut cursor)?)),
        "headers" => Ok(NetworkMessage::Headers(decode_headers(&mut cursor)?)),
        "block" => Ok(NetworkMessage::Block(
            btc_primitives::block::Block::decode(&mut cursor)?,
        )),
        "tx" => Ok(NetworkMessage::Tx(
            btc_primitives::transaction::Transaction::decode(&mut cursor)?,
        )),
        "addr" => Ok(NetworkMessage::Addr(decode_addr_vec(&mut cursor)?)),
        "sendheaders" => Ok(NetworkMessage::SendHeaders),
        "feefilter" => {
            let rate = cursor.read_u64_le()?;
            Ok(NetworkMessage::FeeFilter(rate))
        }
        "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),
        "notfound" => Ok(NetworkMessage::NotFound(decode_inv_vec(&mut cursor)?)),
        "reject" => {
            // var_str message
            let msg_len = VarInt::decode(&mut cursor)?.0 as usize;
            let msg_bytes = cursor.read_bytes(msg_len)?;
            let message = String::from_utf8(msg_bytes)
                .map_err(|e| EncodeError::InvalidData(e.to_string()))?;
            // u8 code
            let code = cursor.read_u8()?;
            // var_str reason
            let reason_len = VarInt::decode(&mut cursor)?.0 as usize;
            let reason_bytes = cursor.read_bytes(reason_len)?;
            let reason = String::from_utf8(reason_bytes)
                .map_err(|e| EncodeError::InvalidData(e.to_string()))?;
            // remaining bytes are extra data (e.g. txid/block hash)
            let pos = cursor.position() as usize;
            let data = payload[pos..].to_vec();
            Ok(NetworkMessage::Reject {
                message,
                code,
                reason,
                data,
            })
        }
        "mempool" => Ok(NetworkMessage::MemPool),
        "getaddr" => Ok(NetworkMessage::GetAddr),
        "sendcmpct" => {
            let announce = cursor.read_u8()? != 0;
            let version = cursor.read_u64_le()?;
            Ok(NetworkMessage::SendCmpct { announce, version })
        }
        other => Ok(NetworkMessage::Unknown(
            other.to_string(),
            payload.to_vec(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

impl Decoder for BitcoinCodec {
    type Item = NetworkMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least a full header
        if src.len() < MessageHeader::SIZE {
            return Ok(None);
        }

        // Parse the header without consuming bytes yet
        let header: MessageHeader = {
            let header_bytes = &src[..MessageHeader::SIZE];
            btc_primitives::encode::decode(header_bytes).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        };

        // Verify magic bytes
        if header.magic != self.magic {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid magic: expected {:?}, got {:?}",
                    self.magic, header.magic
                ),
            ));
        }

        // Reject oversized payloads
        if header.payload_size > MAX_PAYLOAD_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("payload too large: {} bytes", header.payload_size),
            ));
        }

        let total_len = MessageHeader::SIZE + header.payload_size as usize;

        // Wait for the full message
        if src.len() < total_len {
            // Reserve space so the next read can fill the rest
            src.reserve(total_len - src.len());
            return Ok(None);
        }

        // Consume the header
        src.advance(MessageHeader::SIZE);

        // Consume the payload
        let payload = src.split_to(header.payload_size as usize);

        // Verify checksum
        if !header.verify_checksum(&payload) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checksum mismatch",
            ));
        }

        let command = header.command_str().to_string();

        let msg = decode_payload(&command, &payload).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;

        Ok(Some(msg))
    }
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

impl Encoder<NetworkMessage> for BitcoinCodec {
    type Error = std::io::Error;

    fn encode(&mut self, msg: NetworkMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload = encode_payload(&msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let header = MessageHeader::new(self.magic, msg.command(), &payload);

        // Write header
        dst.reserve(MessageHeader::SIZE + payload.len());
        let mut header_buf = Vec::with_capacity(MessageHeader::SIZE);
        header
            .encode(&mut header_buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        dst.put_slice(&header_buf);

        // Write payload
        dst.put_slice(&payload);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::block::BlockHeader;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, Hash256, TxHash};
    use btc_primitives::network::Network;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::amount::Amount;
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    fn mainnet_codec() -> BitcoinCodec {
        BitcoinCodec::new(Network::Mainnet.magic())
    }

    /// Encode a message with the codec and then decode it, verifying roundtrip.
    fn roundtrip(msg: NetworkMessage) -> NetworkMessage {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).expect("encode failed");
        codec.decode(&mut buf).expect("decode failed").expect("incomplete")
    }

    fn sample_version() -> VersionMessage {
        VersionMessage {
            version: 70016,
            services: 1,
            timestamp: 1_700_000_000,
            receiver: NetAddress {
                services: 1,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
                port: 8333,
            },
            sender: NetAddress {
                services: 1,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
                port: 8333,
            },
            nonce: 0xdeadbeef,
            user_agent: "/btc-rust:0.1.0/".to_string(),
            start_height: 800_000,
            relay: true,
        }
    }

    // --- Roundtrip tests for every message type ---

    #[test]
    fn test_version_roundtrip() {
        let orig = sample_version();
        let decoded = roundtrip(NetworkMessage::Version(orig.clone()));
        match decoded {
            NetworkMessage::Version(v) => {
                assert_eq!(v.version, orig.version);
                assert_eq!(v.services, orig.services);
                assert_eq!(v.timestamp, orig.timestamp);
                assert_eq!(v.nonce, orig.nonce);
                assert_eq!(v.user_agent, orig.user_agent);
                assert_eq!(v.start_height, orig.start_height);
                assert_eq!(v.relay, orig.relay);
                assert_eq!(v.receiver.port, orig.receiver.port);
                assert_eq!(v.sender.ip, orig.sender.ip);
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn test_verack_roundtrip() {
        match roundtrip(NetworkMessage::Verack) {
            NetworkMessage::Verack => {}
            other => panic!("expected Verack, got {:?}", other),
        }
    }

    #[test]
    fn test_ping_roundtrip() {
        let nonce = 0x1234567890abcdef_u64;
        match roundtrip(NetworkMessage::Ping(nonce)) {
            NetworkMessage::Ping(n) => assert_eq!(n, nonce),
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[test]
    fn test_pong_roundtrip() {
        let nonce = 42u64;
        match roundtrip(NetworkMessage::Pong(nonce)) {
            NetworkMessage::Pong(n) => assert_eq!(n, nonce),
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    #[test]
    fn test_inv_roundtrip() {
        let items = vec![
            InvItem {
                inv_type: InvType::Tx,
                hash: Hash256::from_bytes([0xaa; 32]),
            },
            InvItem {
                inv_type: InvType::Block,
                hash: Hash256::from_bytes([0xbb; 32]),
            },
            InvItem {
                inv_type: InvType::WitnessTx,
                hash: Hash256::from_bytes([0xcc; 32]),
            },
        ];
        match roundtrip(NetworkMessage::Inv(items.clone())) {
            NetworkMessage::Inv(decoded) => assert_eq!(decoded, items),
            other => panic!("expected Inv, got {:?}", other),
        }
    }

    #[test]
    fn test_getdata_roundtrip() {
        let items = vec![InvItem {
            inv_type: InvType::Block,
            hash: Hash256::from_bytes([0x11; 32]),
        }];
        match roundtrip(NetworkMessage::GetData(items.clone())) {
            NetworkMessage::GetData(decoded) => assert_eq!(decoded, items),
            other => panic!("expected GetData, got {:?}", other),
        }
    }

    #[test]
    fn test_getheaders_roundtrip() {
        let msg = GetHeadersMessage {
            version: 70016,
            locator_hashes: vec![
                BlockHash::from_bytes([0x01; 32]),
                BlockHash::from_bytes([0x02; 32]),
            ],
            stop_hash: BlockHash::ZERO,
        };
        match roundtrip(NetworkMessage::GetHeaders(msg.clone())) {
            NetworkMessage::GetHeaders(decoded) => {
                assert_eq!(decoded.version, msg.version);
                assert_eq!(decoded.locator_hashes.len(), msg.locator_hashes.len());
                assert_eq!(
                    decoded.locator_hashes[0].as_bytes(),
                    msg.locator_hashes[0].as_bytes()
                );
                assert_eq!(decoded.stop_hash.as_bytes(), msg.stop_hash.as_bytes());
            }
            other => panic!("expected GetHeaders, got {:?}", other),
        }
    }

    #[test]
    fn test_getblocks_roundtrip() {
        let msg = GetHeadersMessage {
            version: 70016,
            locator_hashes: vec![BlockHash::from_bytes([0xab; 32])],
            stop_hash: BlockHash::ZERO,
        };
        match roundtrip(NetworkMessage::GetBlocks(msg.clone())) {
            NetworkMessage::GetBlocks(decoded) => {
                assert_eq!(decoded.version, msg.version);
                assert_eq!(decoded.locator_hashes.len(), 1);
            }
            other => panic!("expected GetBlocks, got {:?}", other),
        }
    }

    #[test]
    fn test_headers_roundtrip() {
        let headers = vec![
            BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0xab; 32]),
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 2083236893,
            },
            BlockHeader {
                version: 2,
                prev_blockhash: BlockHash::from_bytes([0x01; 32]),
                merkle_root: TxHash::from_bytes([0xcd; 32]),
                time: 1231006506,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 12345,
            },
        ];
        match roundtrip(NetworkMessage::Headers(headers.clone())) {
            NetworkMessage::Headers(decoded) => {
                assert_eq!(decoded.len(), 2);
                assert_eq!(decoded[0], headers[0]);
                assert_eq!(decoded[1], headers[1]);
            }
            other => panic!("expected Headers, got {:?}", other),
        }
    }

    #[test]
    fn test_block_roundtrip() {
        let block = btc_primitives::block::Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0xab; 32]),
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 2083236893,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::COINBASE,
                    script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                    sequence: TxIn::SEQUENCE_FINAL,
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(5_000_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
                }],
                witness: Vec::new(),
                lock_time: 0,
            }],
        };
        match roundtrip(NetworkMessage::Block(block.clone())) {
            NetworkMessage::Block(decoded) => {
                assert_eq!(decoded.header, block.header);
                assert_eq!(decoded.transactions.len(), 1);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_tx_roundtrip() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x02, 0x03]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        match roundtrip(NetworkMessage::Tx(tx.clone())) {
            NetworkMessage::Tx(decoded) => {
                assert_eq!(decoded, tx);
            }
            other => panic!("expected Tx, got {:?}", other),
        }
    }

    #[test]
    fn test_addr_roundtrip() {
        let addrs = vec![
            NetAddress {
                services: 1,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
                port: 8333,
            },
            NetAddress {
                services: 0,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1],
                port: 18333,
            },
        ];
        match roundtrip(NetworkMessage::Addr(addrs.clone())) {
            NetworkMessage::Addr(decoded) => {
                assert_eq!(decoded.len(), 2);
                assert_eq!(decoded[0].port, 8333);
                assert_eq!(decoded[1].port, 18333);
                assert_eq!(decoded[0].services, 1);
            }
            other => panic!("expected Addr, got {:?}", other),
        }
    }

    #[test]
    fn test_sendheaders_roundtrip() {
        match roundtrip(NetworkMessage::SendHeaders) {
            NetworkMessage::SendHeaders => {}
            other => panic!("expected SendHeaders, got {:?}", other),
        }
    }

    #[test]
    fn test_feefilter_roundtrip() {
        let rate = 1000_u64;
        match roundtrip(NetworkMessage::FeeFilter(rate)) {
            NetworkMessage::FeeFilter(r) => assert_eq!(r, rate),
            other => panic!("expected FeeFilter, got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_roundtrip() {
        let data = vec![1, 2, 3, 4, 5];
        match roundtrip(NetworkMessage::Unknown("notreal".into(), data.clone())) {
            NetworkMessage::Unknown(cmd, d) => {
                assert_eq!(cmd, "notreal");
                assert_eq!(d, data);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    // --- Header and checksum tests ---

    #[test]
    fn test_header_construction_and_checksum() {
        let payload = b"hello world";
        let header = MessageHeader::new(Network::Mainnet.magic(), "version", payload);
        assert_eq!(header.magic, Network::Mainnet.magic());
        assert_eq!(header.command_str(), "version");
        assert_eq!(header.payload_size, payload.len() as u32);
        assert!(header.verify_checksum(payload));
        assert!(!header.verify_checksum(b"wrong data"));
    }

    #[test]
    fn test_header_checksum_empty_payload() {
        let payload = b"";
        let header = MessageHeader::new(Network::Mainnet.magic(), "verack", payload);
        assert_eq!(header.payload_size, 0);
        assert!(header.verify_checksum(payload));
    }

    #[test]
    fn test_version_message_serialization() {
        let ver = sample_version();
        let payload = encode_payload(&NetworkMessage::Version(ver.clone())).unwrap();
        // Verify we can decode it back
        let decoded = decode_payload("version", &payload).unwrap();
        match decoded {
            NetworkMessage::Version(v) => {
                assert_eq!(v.version, ver.version);
                assert_eq!(v.services, ver.services);
                assert_eq!(v.timestamp, ver.timestamp);
                assert_eq!(v.nonce, ver.nonce);
                assert_eq!(v.user_agent, ver.user_agent);
                assert_eq!(v.start_height, ver.start_height);
                assert_eq!(v.relay, ver.relay);
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        // Encode a message with the correct codec
        codec
            .encode(NetworkMessage::Verack, &mut buf)
            .expect("encode failed");
        // Corrupt the magic bytes
        buf[0] = 0x00;
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(err.to_string().contains("invalid magic"));
    }

    #[test]
    fn test_checksum_mismatch_rejected() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(NetworkMessage::Ping(42), &mut buf)
            .expect("encode failed");
        // Corrupt a payload byte (after 24-byte header)
        let payload_start = MessageHeader::SIZE;
        buf[payload_start] ^= 0xff;
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(err.to_string().contains("checksum"));
    }

    #[test]
    fn test_partial_data_returns_none() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(NetworkMessage::Verack, &mut buf)
            .expect("encode failed");
        let full_len = buf.len();
        // Provide only part of the data
        let mut partial = buf.split_to(full_len - 1);
        assert!(codec.decode(&mut partial).unwrap().is_none());
    }

    // --- Roundtrip tests for new message types ---

    #[test]
    fn test_wtxidrelay_roundtrip() {
        match roundtrip(NetworkMessage::WtxidRelay) {
            NetworkMessage::WtxidRelay => {}
            other => panic!("expected WtxidRelay, got {:?}", other),
        }
    }

    #[test]
    fn test_notfound_roundtrip() {
        let items = vec![
            InvItem {
                inv_type: InvType::Tx,
                hash: Hash256::from_bytes([0xdd; 32]),
            },
            InvItem {
                inv_type: InvType::WitnessTx,
                hash: Hash256::from_bytes([0xee; 32]),
            },
        ];
        match roundtrip(NetworkMessage::NotFound(items.clone())) {
            NetworkMessage::NotFound(decoded) => assert_eq!(decoded, items),
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_notfound_empty_roundtrip() {
        match roundtrip(NetworkMessage::NotFound(vec![])) {
            NetworkMessage::NotFound(decoded) => assert!(decoded.is_empty()),
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_reject_roundtrip() {
        let msg = NetworkMessage::Reject {
            message: "tx".to_string(),
            code: 0x10, // REJECT_INVALID
            reason: "mandatory-script-verify-flag-failed".to_string(),
            data: vec![0xab; 32], // txid
        };
        match roundtrip(msg) {
            NetworkMessage::Reject {
                message,
                code,
                reason,
                data,
            } => {
                assert_eq!(message, "tx");
                assert_eq!(code, 0x10);
                assert_eq!(reason, "mandatory-script-verify-flag-failed");
                assert_eq!(data, vec![0xab; 32]);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_reject_empty_data_roundtrip() {
        let msg = NetworkMessage::Reject {
            message: "version".to_string(),
            code: 0x11,
            reason: "obsolete".to_string(),
            data: vec![],
        };
        match roundtrip(msg) {
            NetworkMessage::Reject {
                message,
                code,
                reason,
                data,
            } => {
                assert_eq!(message, "version");
                assert_eq!(code, 0x11);
                assert_eq!(reason, "obsolete");
                assert!(data.is_empty());
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_mempool_roundtrip() {
        match roundtrip(NetworkMessage::MemPool) {
            NetworkMessage::MemPool => {}
            other => panic!("expected MemPool, got {:?}", other),
        }
    }

    #[test]
    fn test_getaddr_roundtrip() {
        match roundtrip(NetworkMessage::GetAddr) {
            NetworkMessage::GetAddr => {}
            other => panic!("expected GetAddr, got {:?}", other),
        }
    }

    #[test]
    fn test_sendcmpct_roundtrip() {
        let msg = NetworkMessage::SendCmpct {
            announce: true,
            version: 2,
        };
        match roundtrip(msg) {
            NetworkMessage::SendCmpct { announce, version } => {
                assert!(announce);
                assert_eq!(version, 2);
            }
            other => panic!("expected SendCmpct, got {:?}", other),
        }
    }

    #[test]
    fn test_sendcmpct_no_announce_roundtrip() {
        let msg = NetworkMessage::SendCmpct {
            announce: false,
            version: 1,
        };
        match roundtrip(msg) {
            NetworkMessage::SendCmpct { announce, version } => {
                assert!(!announce);
                assert_eq!(version, 1);
            }
            other => panic!("expected SendCmpct, got {:?}", other),
        }
    }

    #[test]
    fn test_multiple_messages_in_buffer() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(NetworkMessage::Ping(1), &mut buf)
            .expect("encode failed");
        codec
            .encode(NetworkMessage::Pong(2), &mut buf)
            .expect("encode failed");

        let msg1 = codec.decode(&mut buf).unwrap().unwrap();
        let msg2 = codec.decode(&mut buf).unwrap().unwrap();

        match msg1 {
            NetworkMessage::Ping(n) => assert_eq!(n, 1),
            other => panic!("expected Ping, got {:?}", other),
        }
        match msg2 {
            NetworkMessage::Pong(n) => assert_eq!(n, 2),
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    #[test]
    fn test_version_message_rejects_long_user_agent() {
        // Build a raw version message payload with a user agent > 256 bytes
        let mut payload = Vec::new();
        payload.extend_from_slice(&70016u32.to_le_bytes()); // version
        payload.extend_from_slice(&1u64.to_le_bytes());     // services
        payload.extend_from_slice(&1_700_000_000i64.to_le_bytes()); // timestamp
        // receiver net_address (26 bytes)
        payload.extend_from_slice(&1u64.to_le_bytes()); // services
        payload.extend_from_slice(&[0u8; 16]);           // ip
        payload.extend_from_slice(&8333u16.to_be_bytes()); // port
        // sender net_address (26 bytes)
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        payload.extend_from_slice(&42u64.to_le_bytes()); // nonce
        // user_agent: varint length 257 followed by bytes
        VarInt(5000).encode(&mut payload).unwrap();
        payload.extend_from_slice(&vec![b'A'; 5000]);
        payload.extend_from_slice(&0i32.to_le_bytes()); // start_height
        payload.push(1); // relay

        let result = decode_version(&mut std::io::Cursor::new(&payload));
        assert!(result.is_err(), "Version message with user agent > 4096 bytes should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("user agent too long"), "Error should mention user agent too long, got: {}", err_msg);
    }

    #[test]
    fn test_version_message_accepts_valid_user_agent() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&70016u32.to_le_bytes());
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        payload.extend_from_slice(&42u64.to_le_bytes());
        // user_agent: 10 bytes (valid)
        VarInt(10).encode(&mut payload).unwrap();
        payload.extend_from_slice(b"btc-rust/1");
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.push(1);

        let result = decode_version(&mut std::io::Cursor::new(&payload));
        assert!(result.is_ok(), "Version message with valid user agent should succeed");
        assert_eq!(result.unwrap().user_agent, "btc-rust/1");
    }

    // --- Oversized payload rejected ---

    #[test]
    fn test_oversized_payload_rejected() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        // Manually build a header with payload_size > MAX_PAYLOAD_SIZE
        let magic = Network::Mainnet.magic();
        buf.extend_from_slice(&magic);
        let mut cmd = [0u8; 12];
        cmd[..4].copy_from_slice(b"ping");
        buf.extend_from_slice(&cmd);
        // payload_size = MAX_PAYLOAD_SIZE + 1
        let oversize = (32 * 1024 * 1024 + 1) as u32;
        buf.extend_from_slice(&oversize.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]); // checksum
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(err.to_string().contains("payload too large"));
    }

    // --- Partial header returns None ---

    #[test]
    fn test_partial_header_returns_none() {
        let mut codec = mainnet_codec();
        // Fewer than 24 bytes
        let mut buf = BytesMut::from(&[0xf9, 0xbe, 0xb4, 0xd9, 0x00][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // --- Partial payload returns None (header present, payload not complete) ---

    #[test]
    fn test_partial_payload_returns_none() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(NetworkMessage::Ping(999), &mut buf)
            .expect("encode failed");
        let full_len = buf.len();
        // Remove last byte so payload is incomplete
        buf.truncate(full_len - 1);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // --- Net address encoding/decoding ---

    #[test]
    fn test_net_address_encode_decode_roundtrip() {
        let addr = NetAddress {
            services: 0x040d,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 20, 30, 40],
            port: 8333,
        };
        let mut buf = Vec::new();
        encode_net_address(&addr, &mut buf).unwrap();
        let decoded = decode_net_address(&mut std::io::Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.services, addr.services);
        assert_eq!(decoded.ip, addr.ip);
        assert_eq!(decoded.port, addr.port);
    }

    #[test]
    fn test_net_address_port_big_endian() {
        let addr = NetAddress {
            services: 0,
            ip: [0; 16],
            port: 0x1234,
        };
        let mut buf = Vec::new();
        encode_net_address(&addr, &mut buf).unwrap();
        // Port is the last 2 bytes, big-endian
        let len = buf.len();
        assert_eq!(buf[len - 2], 0x12);
        assert_eq!(buf[len - 1], 0x34);
    }

    // --- InvItem encoding/decoding ---

    #[test]
    fn test_inv_item_all_types_roundtrip() {
        let types = [
            InvType::Error,
            InvType::Tx,
            InvType::Block,
            InvType::FilteredBlock,
            InvType::CompactBlock,
            InvType::WtxId,
            InvType::WitnessTx,
            InvType::WitnessBlock,
        ];
        for inv_type in types {
            let item = InvItem {
                inv_type,
                hash: Hash256::from_bytes([0xab; 32]),
            };
            let mut buf = Vec::new();
            encode_inv_item(&item, &mut buf).unwrap();
            let decoded = decode_inv_item(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(decoded.inv_type, inv_type);
            assert_eq!(decoded.hash, item.hash);
        }
    }

    #[test]
    fn test_inv_item_unknown_type_becomes_error() {
        // Unknown inv type should be mapped to InvType::Error
        let mut buf = Vec::new();
        buf.extend_from_slice(&9999u32.to_le_bytes()); // unknown type
        buf.extend_from_slice(&[0xcc; 32]); // hash
        let decoded = decode_inv_item(&mut std::io::Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.inv_type, InvType::Error);
    }

    // --- Inv vector too large ---

    #[test]
    fn test_inv_vec_too_large_rejected() {
        let mut buf = Vec::new();
        VarInt(50_001).encode(&mut buf).unwrap();
        let result = decode_inv_vec(&mut std::io::Cursor::new(&buf));
        assert!(result.is_err());
    }

    // --- Empty inv vector ---

    #[test]
    fn test_empty_inv_roundtrip() {
        match roundtrip(NetworkMessage::Inv(vec![])) {
            NetworkMessage::Inv(items) => assert!(items.is_empty()),
            other => panic!("expected Inv, got {:?}", other),
        }
    }

    // --- GetHeaders/GetBlocks with too many locator hashes ---

    #[test]
    fn test_getheaders_too_many_locators_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&70016u32.to_le_bytes());
        VarInt(102).encode(&mut buf).unwrap(); // max is 101
        let result = decode_getheaders(&mut std::io::Cursor::new(&buf));
        assert!(result.is_err());
    }

    // --- Headers message too many headers ---

    #[test]
    fn test_headers_too_many_rejected() {
        let mut buf = Vec::new();
        VarInt(2001).encode(&mut buf).unwrap(); // max is 2000
        let result = decode_headers(&mut std::io::Cursor::new(&buf));
        assert!(result.is_err());
    }

    // --- Addr vec too many addresses ---

    #[test]
    fn test_addr_vec_too_many_rejected() {
        let mut buf = Vec::new();
        VarInt(1001).encode(&mut buf).unwrap(); // max is 1000
        let result = decode_addr_vec(&mut std::io::Cursor::new(&buf));
        assert!(result.is_err());
    }

    // --- Empty addr message ---

    #[test]
    fn test_empty_addr_roundtrip() {
        match roundtrip(NetworkMessage::Addr(vec![])) {
            NetworkMessage::Addr(decoded) => assert!(decoded.is_empty()),
            other => panic!("expected Addr, got {:?}", other),
        }
    }

    // --- Version message without relay byte (optional per BIP37) ---

    #[test]
    fn test_version_without_relay_byte_defaults_to_true() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&70016u32.to_le_bytes());
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        // receiver
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        // sender
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        payload.extend_from_slice(&42u64.to_le_bytes());
        // user_agent
        VarInt(0).encode(&mut payload).unwrap();
        payload.extend_from_slice(&800_000i32.to_le_bytes());
        // no relay byte

        let result = decode_version(&mut std::io::Cursor::new(&payload));
        assert!(result.is_ok());
        assert!(result.unwrap().relay);
    }

    // --- Version message with relay=false ---

    #[test]
    fn test_version_relay_false() {
        let ver = VersionMessage {
            version: 70016,
            services: 1,
            timestamp: 1_700_000_000,
            receiver: NetAddress::default(),
            sender: NetAddress::default(),
            nonce: 42,
            user_agent: "/test/".to_string(),
            start_height: 0,
            relay: false,
        };
        let decoded = roundtrip(NetworkMessage::Version(ver));
        match decoded {
            NetworkMessage::Version(v) => assert!(!v.relay),
            other => panic!("expected Version, got {:?}", other),
        }
    }

    // --- encode_payload and decode_payload for each message type ---

    #[test]
    fn test_encode_decode_payload_verack() {
        let payload = encode_payload(&NetworkMessage::Verack).unwrap();
        assert!(payload.is_empty());
        let decoded = decode_payload("verack", &payload).unwrap();
        assert!(matches!(decoded, NetworkMessage::Verack));
    }

    #[test]
    fn test_encode_decode_payload_sendheaders() {
        let payload = encode_payload(&NetworkMessage::SendHeaders).unwrap();
        assert!(payload.is_empty());
        let decoded = decode_payload("sendheaders", &payload).unwrap();
        assert!(matches!(decoded, NetworkMessage::SendHeaders));
    }

    #[test]
    fn test_encode_decode_payload_wtxidrelay() {
        let payload = encode_payload(&NetworkMessage::WtxidRelay).unwrap();
        assert!(payload.is_empty());
        let decoded = decode_payload("wtxidrelay", &payload).unwrap();
        assert!(matches!(decoded, NetworkMessage::WtxidRelay));
    }

    #[test]
    fn test_encode_decode_payload_mempool() {
        let payload = encode_payload(&NetworkMessage::MemPool).unwrap();
        assert!(payload.is_empty());
        let decoded = decode_payload("mempool", &payload).unwrap();
        assert!(matches!(decoded, NetworkMessage::MemPool));
    }

    #[test]
    fn test_encode_decode_payload_getaddr() {
        let payload = encode_payload(&NetworkMessage::GetAddr).unwrap();
        assert!(payload.is_empty());
        let decoded = decode_payload("getaddr", &payload).unwrap();
        assert!(matches!(decoded, NetworkMessage::GetAddr));
    }

    #[test]
    fn test_encode_decode_payload_ping() {
        let payload = encode_payload(&NetworkMessage::Ping(0xdeadbeef)).unwrap();
        assert_eq!(payload.len(), 8);
        let decoded = decode_payload("ping", &payload).unwrap();
        match decoded {
            NetworkMessage::Ping(n) => assert_eq!(n, 0xdeadbeef),
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[test]
    fn test_encode_decode_payload_pong() {
        let payload = encode_payload(&NetworkMessage::Pong(0xcafebabe)).unwrap();
        assert_eq!(payload.len(), 8);
        let decoded = decode_payload("pong", &payload).unwrap();
        match decoded {
            NetworkMessage::Pong(n) => assert_eq!(n, 0xcafebabe),
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    #[test]
    fn test_encode_decode_payload_feefilter() {
        let payload = encode_payload(&NetworkMessage::FeeFilter(1234)).unwrap();
        assert_eq!(payload.len(), 8);
        let decoded = decode_payload("feefilter", &payload).unwrap();
        match decoded {
            NetworkMessage::FeeFilter(r) => assert_eq!(r, 1234),
            other => panic!("expected FeeFilter, got {:?}", other),
        }
    }

    #[test]
    fn test_encode_decode_payload_sendcmpct() {
        let payload = encode_payload(&NetworkMessage::SendCmpct {
            announce: true,
            version: 2,
        })
        .unwrap();
        assert_eq!(payload.len(), 9); // 1 byte announce + 8 bytes version
        let decoded = decode_payload("sendcmpct", &payload).unwrap();
        match decoded {
            NetworkMessage::SendCmpct { announce, version } => {
                assert!(announce);
                assert_eq!(version, 2);
            }
            other => panic!("expected SendCmpct, got {:?}", other),
        }
    }

    #[test]
    fn test_encode_decode_payload_unknown() {
        let data = vec![0x01, 0x02, 0x03];
        let payload = encode_payload(&NetworkMessage::Unknown("foobar".into(), data.clone())).unwrap();
        assert_eq!(payload, data);
        let decoded = decode_payload("foobar", &payload).unwrap();
        match decoded {
            NetworkMessage::Unknown(cmd, d) => {
                assert_eq!(cmd, "foobar");
                assert_eq!(d, data);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    // --- GetheadersMessage encode/decode ---

    #[test]
    fn test_getheaders_encode_decode() {
        let msg = GetHeadersMessage {
            version: 70016,
            locator_hashes: vec![
                BlockHash::from_bytes([0x01; 32]),
                BlockHash::from_bytes([0x02; 32]),
                BlockHash::from_bytes([0x03; 32]),
            ],
            stop_hash: BlockHash::from_bytes([0xff; 32]),
        };
        let mut buf = Vec::new();
        encode_getheaders(&msg, &mut buf).unwrap();
        let decoded = decode_getheaders(&mut std::io::Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.version, 70016);
        assert_eq!(decoded.locator_hashes.len(), 3);
        assert_eq!(decoded.stop_hash.as_bytes(), &[0xff; 32]);
    }

    // --- GetBlocks uses same format as GetHeaders ---

    #[test]
    fn test_getblocks_encode_decode_payload() {
        let msg = GetHeadersMessage {
            version: 70015,
            locator_hashes: vec![BlockHash::from_bytes([0xaa; 32])],
            stop_hash: BlockHash::ZERO,
        };
        let payload = encode_payload(&NetworkMessage::GetBlocks(msg)).unwrap();
        let decoded = decode_payload("getblocks", &payload).unwrap();
        match decoded {
            NetworkMessage::GetBlocks(gh) => {
                assert_eq!(gh.version, 70015);
                assert_eq!(gh.locator_hashes.len(), 1);
            }
            other => panic!("expected GetBlocks, got {:?}", other),
        }
    }

    // --- Multiple inv items with different types ---

    #[test]
    fn test_inv_vec_encode_decode_multiple_types() {
        let items = vec![
            InvItem { inv_type: InvType::Error, hash: Hash256::from_bytes([0; 32]) },
            InvItem { inv_type: InvType::Tx, hash: Hash256::from_bytes([1; 32]) },
            InvItem { inv_type: InvType::Block, hash: Hash256::from_bytes([2; 32]) },
            InvItem { inv_type: InvType::FilteredBlock, hash: Hash256::from_bytes([3; 32]) },
            InvItem { inv_type: InvType::CompactBlock, hash: Hash256::from_bytes([4; 32]) },
            InvItem { inv_type: InvType::WtxId, hash: Hash256::from_bytes([5; 32]) },
            InvItem { inv_type: InvType::WitnessTx, hash: Hash256::from_bytes([6; 32]) },
            InvItem { inv_type: InvType::WitnessBlock, hash: Hash256::from_bytes([7; 32]) },
        ];
        let mut buf = Vec::new();
        encode_inv_vec(&items, &mut buf).unwrap();
        let decoded = decode_inv_vec(&mut std::io::Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, items);
    }

    // --- Reject message encode/decode via payload functions ---

    #[test]
    fn test_reject_payload_encode_decode() {
        let msg = NetworkMessage::Reject {
            message: "block".to_string(),
            code: 0x43,
            reason: "duplicate".to_string(),
            data: vec![0xab; 32],
        };
        let payload = encode_payload(&msg).unwrap();
        let decoded = decode_payload("reject", &payload).unwrap();
        match decoded {
            NetworkMessage::Reject { message, code, reason, data } => {
                assert_eq!(message, "block");
                assert_eq!(code, 0x43);
                assert_eq!(reason, "duplicate");
                assert_eq!(data.len(), 32);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    // --- Headers encode/decode with 0 tx_count varint ---

    #[test]
    fn test_headers_encode_decode_payload() {
        let headers = vec![BlockHeader {
            version: 536870912,
            prev_blockhash: BlockHash::from_bytes([0x11; 32]),
            merkle_root: TxHash::from_bytes([0x22; 32]),
            time: 1700000000,
            bits: CompactTarget::from_u32(0x1d00ffff),
            nonce: 42,
        }];
        let payload = encode_payload(&NetworkMessage::Headers(headers.clone())).unwrap();
        let decoded = decode_payload("headers", &payload).unwrap();
        match decoded {
            NetworkMessage::Headers(h) => {
                assert_eq!(h.len(), 1);
                assert_eq!(h[0], headers[0]);
            }
            other => panic!("expected Headers, got {:?}", other),
        }
    }

    // --- Addr encode/decode with timestamp ---

    #[test]
    fn test_addr_encode_decode_payload() {
        let addrs = vec![
            NetAddress { services: 0x0d, ip: [0; 16], port: 8333 },
            NetAddress { services: 0x01, ip: [0; 16], port: 18333 },
        ];
        let payload = encode_payload(&NetworkMessage::Addr(addrs.clone())).unwrap();
        let decoded = decode_payload("addr", &payload).unwrap();
        match decoded {
            NetworkMessage::Addr(a) => {
                assert_eq!(a.len(), 2);
                assert_eq!(a[0].services, 0x0d);
                assert_eq!(a[0].port, 8333);
                assert_eq!(a[1].port, 18333);
            }
            other => panic!("expected Addr, got {:?}", other),
        }
    }

    // --- Codec: testnet magic ---

    #[test]
    fn test_testnet_codec_roundtrip() {
        let mut codec = BitcoinCodec::new(Network::Testnet.magic());
        let mut buf = BytesMut::new();
        codec.encode(NetworkMessage::Ping(42), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        match decoded {
            NetworkMessage::Ping(n) => assert_eq!(n, 42),
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    // --- Codec: regtest magic ---

    #[test]
    fn test_regtest_codec_roundtrip() {
        let mut codec = BitcoinCodec::new(Network::Regtest.magic());
        let mut buf = BytesMut::new();
        codec.encode(NetworkMessage::Verack, &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(decoded, NetworkMessage::Verack));
    }

    // --- Codec: signet magic ---

    #[test]
    fn test_signet_codec_roundtrip() {
        let mut codec = BitcoinCodec::new(Network::Signet.magic());
        let mut buf = BytesMut::new();
        codec.encode(NetworkMessage::SendHeaders, &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(decoded, NetworkMessage::SendHeaders));
    }

    // --- Codec: wrong magic from different network ---

    #[test]
    fn test_wrong_network_magic_rejected() {
        let mut mainnet_codec = mainnet_codec();
        let mut testnet_codec = BitcoinCodec::new(Network::Testnet.magic());
        let mut buf = BytesMut::new();
        // Encode with testnet
        testnet_codec.encode(NetworkMessage::Verack, &mut buf).unwrap();
        // Decode with mainnet -- should fail
        let err = mainnet_codec.decode(&mut buf).unwrap_err();
        assert!(err.to_string().contains("invalid magic"));
    }

    // --- Empty buffer returns None ---

    #[test]
    fn test_empty_buffer_returns_none() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // --- Header with zero-length payload ---

    #[test]
    fn test_header_zero_payload_command() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "verack", b"");
        assert_eq!(header.payload_size, 0);
        assert!(header.verify_checksum(b""));
    }

    // --- Header command truncation ---

    #[test]
    fn test_header_command_long_name() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "verylongcommand", b"");
        // Command field is 12 bytes, should be truncated
        assert_eq!(header.command_str(), "verylongcomm");
    }

    // --- Header with full 12-byte command (no null terminator) ---

    #[test]
    fn test_header_full_12_byte_command() {
        let header = MessageHeader::new(Network::Mainnet.magic(), "123456789012", b"");
        assert_eq!(header.command_str(), "123456789012");
    }

    // --- NotFound payload roundtrip ---

    #[test]
    fn test_notfound_payload_roundtrip() {
        let items = vec![
            InvItem { inv_type: InvType::Tx, hash: Hash256::from_bytes([0x11; 32]) },
            InvItem { inv_type: InvType::Block, hash: Hash256::from_bytes([0x22; 32]) },
        ];
        let payload = encode_payload(&NetworkMessage::NotFound(items.clone())).unwrap();
        let decoded = decode_payload("notfound", &payload).unwrap();
        match decoded {
            NetworkMessage::NotFound(d) => assert_eq!(d, items),
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    // --- GetData payload roundtrip ---

    #[test]
    fn test_getdata_payload_roundtrip() {
        let items = vec![InvItem {
            inv_type: InvType::WitnessTx,
            hash: Hash256::from_bytes([0x33; 32]),
        }];
        let payload = encode_payload(&NetworkMessage::GetData(items.clone())).unwrap();
        let decoded = decode_payload("getdata", &payload).unwrap();
        match decoded {
            NetworkMessage::GetData(d) => assert_eq!(d, items),
            other => panic!("expected GetData, got {:?}", other),
        }
    }

    // --- Version with empty user agent ---

    #[test]
    fn test_version_empty_user_agent() {
        let ver = VersionMessage {
            version: 70016,
            services: 1,
            timestamp: 1_700_000_000,
            receiver: NetAddress::default(),
            sender: NetAddress::default(),
            nonce: 1,
            user_agent: "".to_string(),
            start_height: 0,
            relay: true,
        };
        let decoded = roundtrip(NetworkMessage::Version(ver));
        match decoded {
            NetworkMessage::Version(v) => assert_eq!(v.user_agent, ""),
            other => panic!("expected Version, got {:?}", other),
        }
    }

    // --- Decode unknown command ---

    #[test]
    fn test_decode_payload_unknown_command() {
        let data = vec![0xaa, 0xbb, 0xcc];
        let decoded = decode_payload("weirdcommand", &data).unwrap();
        match decoded {
            NetworkMessage::Unknown(cmd, d) => {
                assert_eq!(cmd, "weirdcommand");
                assert_eq!(d, data);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    // --- Encoder produces valid header ---

    #[test]
    fn test_encoder_produces_correct_header_size() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec.encode(NetworkMessage::Verack, &mut buf).unwrap();
        // Verack has no payload, so total = 24 (header only)
        assert_eq!(buf.len(), MessageHeader::SIZE);
    }

    #[test]
    fn test_encoder_header_magic_in_output() {
        let mut codec = mainnet_codec();
        let mut buf = BytesMut::new();
        codec.encode(NetworkMessage::Verack, &mut buf).unwrap();
        let magic = Network::Mainnet.magic();
        assert_eq!(&buf[0..4], &magic);
    }

    // --- inv/getdata roundtrip with WitnessBlock ---

    #[test]
    fn test_inv_witness_block_roundtrip() {
        let items = vec![InvItem {
            inv_type: InvType::WitnessBlock,
            hash: Hash256::from_bytes([0xff; 32]),
        }];
        match roundtrip(NetworkMessage::Inv(items.clone())) {
            NetworkMessage::Inv(decoded) => assert_eq!(decoded, items),
            other => panic!("expected Inv, got {:?}", other),
        }
    }

    // --- Block with multiple transactions ---

    #[test]
    fn test_block_multiple_txs_roundtrip() {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let tx1 = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let block = btc_primitives::block::Block {
            header: BlockHeader {
                version: 4,
                prev_blockhash: BlockHash::from_bytes([0xaa; 32]),
                merkle_root: TxHash::from_bytes([0xbb; 32]),
                time: 1700000000,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 999,
            },
            transactions: vec![coinbase, tx1],
        };
        match roundtrip(NetworkMessage::Block(block.clone())) {
            NetworkMessage::Block(decoded) => {
                assert_eq!(decoded.header, block.header);
                assert_eq!(decoded.transactions.len(), 2);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // --- FeeFilter zero ---

    #[test]
    fn test_feefilter_zero_roundtrip() {
        match roundtrip(NetworkMessage::FeeFilter(0)) {
            NetworkMessage::FeeFilter(r) => assert_eq!(r, 0),
            other => panic!("expected FeeFilter, got {:?}", other),
        }
    }

    // --- FeeFilter max value ---

    #[test]
    fn test_feefilter_max_roundtrip() {
        match roundtrip(NetworkMessage::FeeFilter(u64::MAX)) {
            NetworkMessage::FeeFilter(r) => assert_eq!(r, u64::MAX),
            other => panic!("expected FeeFilter, got {:?}", other),
        }
    }

    // --- Reject with empty strings ---

    #[test]
    fn test_reject_empty_strings_roundtrip() {
        let msg = NetworkMessage::Reject {
            message: "".to_string(),
            code: 0,
            reason: "".to_string(),
            data: vec![],
        };
        match roundtrip(msg) {
            NetworkMessage::Reject { message, code, reason, data } => {
                assert_eq!(message, "");
                assert_eq!(code, 0);
                assert_eq!(reason, "");
                assert!(data.is_empty());
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    // --- GetHeaders with no locator hashes ---

    #[test]
    fn test_getheaders_no_locators_roundtrip() {
        let msg = GetHeadersMessage {
            version: 70016,
            locator_hashes: vec![],
            stop_hash: BlockHash::ZERO,
        };
        match roundtrip(NetworkMessage::GetHeaders(msg)) {
            NetworkMessage::GetHeaders(decoded) => {
                assert!(decoded.locator_hashes.is_empty());
            }
            other => panic!("expected GetHeaders, got {:?}", other),
        }
    }

    // --- Headers empty list ---

    #[test]
    fn test_headers_empty_list_roundtrip() {
        match roundtrip(NetworkMessage::Headers(vec![])) {
            NetworkMessage::Headers(decoded) => assert!(decoded.is_empty()),
            other => panic!("expected Headers, got {:?}", other),
        }
    }
}
