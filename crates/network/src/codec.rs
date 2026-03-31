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
        0x40000001 => InvType::WitnessTx,
        0x40000002 => InvType::WitnessBlock,
        other => {
            return Err(EncodeError::InvalidData(format!(
                "unknown inv type: {other}"
            )))
        }
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
}
