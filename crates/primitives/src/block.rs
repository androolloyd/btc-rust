use crate::encode::{Encodable, Decodable, EncodeError, VarInt, ReadExt, WriteExt};
use crate::hash::{BlockHash, sha256d, TxHash};
use crate::compact::CompactTarget;
use crate::transaction::Transaction;
use std::io::{Read, Write};

/// An 80-byte Bitcoin block header containing version, previous hash, merkle root, timestamp, difficulty target, and nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: TxHash,
    pub time: u32,
    pub bits: CompactTarget,
    pub nonce: u32,
}

impl BlockHeader {
    pub const SIZE: usize = 80;

    /// Compute the block hash
    pub fn block_hash(&self) -> BlockHash {
        let mut buf = [0u8; 80];
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        self.encode(&mut cursor).expect("encoding 80 bytes should not fail");
        BlockHash::compute(&buf)
    }

    /// Check if the block hash meets the difficulty target
    pub fn check_proof_of_work(&self) -> bool {
        let hash = self.block_hash();
        self.bits.hash_meets_target(hash.as_bytes())
    }
}

impl Encodable for BlockHeader {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = 0;
        written += writer.write_i32_le(self.version)?;
        writer.write_all(self.prev_blockhash.as_bytes())?;
        written += 32;
        writer.write_all(self.merkle_root.as_bytes())?;
        written += 32;
        written += writer.write_u32_le(self.time)?;
        written += writer.write_u32_le(self.bits.to_u32())?;
        written += writer.write_u32_le(self.nonce)?;
        Ok(written)
    }

    fn encoded_size(&self) -> usize {
        Self::SIZE
    }
}

impl Decodable for BlockHeader {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let version = reader.read_i32_le()?;
        let prev_blockhash = BlockHash::from_bytes(reader.read_hash256()?);
        let merkle_root = TxHash::from_bytes(reader.read_hash256()?);
        let time = reader.read_u32_le()?;
        let bits = CompactTarget::from_u32(reader.read_u32_le()?);
        let nonce = reader.read_u32_le()?;
        Ok(BlockHeader { version, prev_blockhash, merkle_root, time, bits, nonce })
    }
}

/// A full Bitcoin block consisting of a header and an ordered list of transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Compute the merkle root from transactions
    pub fn compute_merkle_root(&self) -> TxHash {
        let txids: Vec<[u8; 32]> = self.transactions
            .iter()
            .map(|tx| tx.txid().to_bytes())
            .collect();
        TxHash::from_bytes(merkle_root(&txids))
    }

    /// Verify the merkle root matches
    pub fn check_merkle_root(&self) -> bool {
        self.compute_merkle_root() == self.header.merkle_root
    }
}

impl Encodable for Block {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = self.header.encode(writer)?;
        written += VarInt(self.transactions.len() as u64).encode(writer)?;
        for tx in &self.transactions {
            written += tx.encode(writer)?;
        }
        Ok(written)
    }
}

impl Decodable for Block {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let header = BlockHeader::decode(reader)?;
        let tx_count = VarInt::decode(reader)?.0 as usize;
        if tx_count > 100_000 {
            return Err(EncodeError::InvalidData("too many transactions".into()));
        }
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            transactions.push(Transaction::decode(reader)?);
        }
        Ok(Block { header, transactions })
    }
}

/// Compute merkle root from a list of hashes
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current_level: Vec<[u8; 32]> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        for pair in current_level.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            // If odd number, duplicate the last hash
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            combined[32..].copy_from_slice(right);
            next_level.push(sha256d(&combined));
        }

        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode;

    #[test]
    fn test_genesis_block_header() {
        let raw_header = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c"
        ).unwrap();

        let header: BlockHeader = encode::decode(&raw_header).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.prev_blockhash, BlockHash::ZERO);
        assert_eq!(header.time, 1231006505);
        assert_eq!(header.bits.to_u32(), 0x1d00ffff);
        assert_eq!(header.nonce, 2083236893);

        // Verify block hash
        assert_eq!(
            header.block_hash().to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );

        // Verify PoW
        assert!(header.check_proof_of_work());
    }

    #[test]
    fn test_block_header_roundtrip() {
        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0xab; 32]),
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 2083236893,
        };

        let encoded = encode::encode(&header);
        assert_eq!(encoded.len(), 80);
        let decoded: BlockHeader = encode::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_merkle_root_single() {
        let hash = [0xab; 32];
        assert_eq!(merkle_root(&[hash]), hash);
    }

    #[test]
    fn test_merkle_root_two() {
        let h1 = [0x01; 32];
        let h2 = [0x02; 32];
        let root = merkle_root(&[h1, h2]);
        // Root should be SHA256d(h1 || h2)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&h1);
        combined[32..].copy_from_slice(&h2);
        assert_eq!(root, sha256d(&combined));
    }

    #[test]
    fn test_merkle_root_odd() {
        let h1 = [0x01; 32];
        let h2 = [0x02; 32];
        let h3 = [0x03; 32];
        let root = merkle_root(&[h1, h2, h3]);
        // With 3 items: first pair = sha256d(h1||h2), second = sha256d(h3||h3)
        // then root = sha256d(pair1||pair2)
        let mut c1 = [0u8; 64];
        c1[..32].copy_from_slice(&h1);
        c1[32..].copy_from_slice(&h2);
        let p1 = sha256d(&c1);

        let mut c2 = [0u8; 64];
        c2[..32].copy_from_slice(&h3);
        c2[32..].copy_from_slice(&h3);
        let p2 = sha256d(&c2);

        let mut c3 = [0u8; 64];
        c3[..32].copy_from_slice(&p1);
        c3[32..].copy_from_slice(&p2);
        assert_eq!(root, sha256d(&c3));
    }

    #[test]
    fn test_block_decode_tx_count_limit() {
        // Construct a raw block with tx_count > 100_000 in the header
        let mut buf = Vec::new();
        // Write a valid 80-byte block header
        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0u8; 32]),
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 0,
        };
        header.encode(&mut buf).unwrap();
        // Write tx_count as varint > 100_000 (use 0xFE prefix for 4-byte varint)
        // 100_001 = 0x000186A1
        buf.push(0xFE); // varint prefix for 4-byte
        buf.extend_from_slice(&100_001u32.to_le_bytes());

        let result = encode::decode::<Block>(&buf);
        assert!(result.is_err(), "Block with >100k transactions should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too many transactions"), "Error should mention too many transactions, got: {}", err_msg);
    }
}
