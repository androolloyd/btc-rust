//! Versioned local undo records, bound to a block and protected by SHA256.
//! This is a repository storage format, not Bitcoin Core's rev*.dat format.
use crate::traits::StorageError;
use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
use btc_primitives::encode::{Decodable, Encodable, ReadExt, VarInt};
use btc_primitives::{BlockHash, OutPoint, TxOut};
use sha2::{Digest, Sha256};
use std::io::Cursor;

pub fn encode_undo(hash: BlockHash, update: &UtxoSetUpdate) -> Vec<u8> {
    let mut bytes = b"BTCUNDO\x01".to_vec();
    bytes.extend_from_slice(hash.as_bytes());
    for entries in [&update.spent, &update.created] {
        VarInt(entries.len() as u64).encode(&mut bytes).unwrap();
        for (outpoint, entry) in entries {
            outpoint.encode(&mut bytes).unwrap();
            bytes.extend_from_slice(&entry.height.to_le_bytes());
            bytes.push(entry.is_coinbase as u8);
            entry.txout.encode(&mut bytes).unwrap();
        }
    }
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}
pub fn decode_undo(hash: BlockHash, bytes: &[u8]) -> Result<UtxoSetUpdate, StorageError> {
    let bad = |message: &str| StorageError::Corruption(message.into());
    if bytes.len() < 74 || &bytes[..8] != b"BTCUNDO\x01" || &bytes[8..40] != hash.as_bytes() {
        return Err(bad("undo identity/version mismatch"));
    }
    let payload = &bytes[..bytes.len() - 32];
    if Sha256::digest(payload).as_slice() != &bytes[bytes.len() - 32..] {
        return Err(bad("undo checksum mismatch"));
    }
    let mut cursor = Cursor::new(&payload[40..]);
    let mut read_entries = || -> Result<Vec<(OutPoint, UtxoEntry)>, StorageError> {
        let count = VarInt::decode(&mut cursor)
            .map_err(|e| bad(&e.to_string()))?
            .0;
        if count > (payload.len() / 54) as u64 {
            return Err(bad("undo entry count exceeds payload"));
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            let outpoint = OutPoint::decode(&mut cursor).map_err(|e| bad(&e.to_string()))?;
            let height = cursor.read_u64_le().map_err(|e| bad(&e.to_string()))?;
            let flag = cursor.read_u8().map_err(|e| bad(&e.to_string()))?;
            if flag > 1 {
                return Err(bad("invalid undo coinbase flag"));
            }
            let txout = TxOut::decode(&mut cursor).map_err(|e| bad(&e.to_string()))?;
            entries.push((
                outpoint,
                UtxoEntry {
                    txout,
                    height,
                    is_coinbase: flag == 1,
                },
            ));
        }
        Ok(entries)
    };
    let spent = read_entries()?;
    let created = read_entries()?;
    if cursor.position() != (payload.len() - 40) as u64 {
        return Err(bad("trailing undo data"));
    }
    Ok(UtxoSetUpdate { spent, created })
}
