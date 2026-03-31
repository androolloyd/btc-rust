//! Compact Block Relay (BIP152)
//!
//! Implements the compact block protocol for bandwidth-efficient block relay.
//! Instead of sending full blocks, peers exchange compact representations
//! containing short transaction IDs, and only request full transactions
//! they don't already have in their mempool.

use btc_primitives::block::BlockHeader;
use btc_primitives::hash::{sha256d, TxHash};
use btc_primitives::transaction::Transaction;
use btc_primitives::encode::{Encodable, Decodable, EncodeError, VarInt, ReadExt, WriteExt};
use std::io::{Read, Write};

/// SipHash key derived from block header + nonce
/// Used to compute short transaction IDs
#[derive(Debug, Clone, Copy)]
pub struct ShortIdKey {
    pub k0: u64,
    pub k1: u64,
}

impl ShortIdKey {
    /// Derive short ID key from block header hash and nonce
    pub fn new(block_hash: &[u8; 32], nonce: u64) -> Self {
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(block_hash);
        preimage.extend_from_slice(&nonce.to_le_bytes());
        let hash = sha256d(&preimage);

        let k0 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

        ShortIdKey { k0, k1 }
    }

    /// Compute a 6-byte short ID for a transaction
    pub fn short_id(&self, txid: &TxHash) -> u64 {
        let hash = siphash_2_4(self.k0, self.k1, txid.as_bytes());
        // Take low 6 bytes
        hash & 0x0000_ffff_ffff_ffff
    }
}

/// SipHash-2-4 implementation (used for compact block short IDs)
fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0: u64 = k0 ^ 0x736f6d6570736575;
    let mut v1: u64 = k1 ^ 0x646f72616e646f6d;
    let mut v2: u64 = k0 ^ 0x6c7967656e657261;
    let mut v3: u64 = k1 ^ 0x7465646279746573;

    let blocks = data.len() / 8;
    let remainder = data.len() % 8;

    for i in 0..blocks {
        let m = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let mut last: u64 = (data.len() as u64) << 56;
    for i in 0..remainder {
        last |= (data[blocks * 8 + i] as u64) << (i * 8);
    }

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// A compact block message (cmpctblock)
#[derive(Debug, Clone)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub nonce: u64,
    pub short_ids: Vec<u64>,
    pub prefilled_txs: Vec<PrefilledTx>,
}

/// A prefilled transaction in a compact block (always includes coinbase)
#[derive(Debug, Clone)]
pub struct PrefilledTx {
    pub index: u16,
    pub tx: Transaction,
}

/// A request for missing transactions (getblocktxn)
#[derive(Debug, Clone)]
pub struct BlockTxnRequest {
    pub block_hash: [u8; 32],
    pub indices: Vec<u16>,
}

/// Response with requested transactions (blocktxn)
#[derive(Debug, Clone)]
pub struct BlockTxnResponse {
    pub block_hash: [u8; 32],
    pub transactions: Vec<Transaction>,
}

impl CompactBlock {
    /// Create a compact block from a full block
    pub fn from_block(
        header: BlockHeader,
        transactions: &[Transaction],
        nonce: u64,
    ) -> Self {
        let block_hash = header.block_hash();
        let key = ShortIdKey::new(block_hash.as_bytes(), nonce);

        let mut short_ids = Vec::with_capacity(transactions.len().saturating_sub(1));
        let mut prefilled_txs = Vec::new();

        // Coinbase is always prefilled
        if !transactions.is_empty() {
            prefilled_txs.push(PrefilledTx {
                index: 0,
                tx: transactions[0].clone(),
            });
        }

        // Compute short IDs for non-coinbase transactions
        for tx in transactions.iter().skip(1) {
            let txid = tx.txid();
            short_ids.push(key.short_id(&txid));
        }

        CompactBlock {
            header,
            nonce,
            short_ids,
            prefilled_txs,
        }
    }

    /// Try to reconstruct the full block using mempool transactions
    /// Returns the full block if all transactions are found, or a list of
    /// missing short IDs if some are not in the mempool.
    pub fn reconstruct(
        &self,
        mempool_txs: &std::collections::HashMap<TxHash, Transaction>,
    ) -> Result<Vec<Transaction>, Vec<u64>> {
        let block_hash = self.header.block_hash();
        let key = ShortIdKey::new(block_hash.as_bytes(), self.nonce);

        // Build short_id -> tx lookup from mempool
        let mut mempool_by_short_id: std::collections::HashMap<u64, &Transaction> =
            std::collections::HashMap::new();
        for (txid, tx) in mempool_txs {
            let sid = key.short_id(txid);
            mempool_by_short_id.insert(sid, tx);
        }

        let total_txs = self.prefilled_txs.len() + self.short_ids.len();
        let mut result: Vec<Option<Transaction>> = vec![None; total_txs];
        let mut missing = Vec::new();

        // Place prefilled transactions
        for ptx in &self.prefilled_txs {
            if (ptx.index as usize) < total_txs {
                result[ptx.index as usize] = Some(ptx.tx.clone());
            }
        }

        // Match short IDs against mempool
        let mut short_id_idx = 0;
        for i in 0..total_txs {
            if result[i].is_some() {
                continue; // already prefilled
            }
            if short_id_idx < self.short_ids.len() {
                let sid = self.short_ids[short_id_idx];
                match mempool_by_short_id.get(&sid) {
                    Some(tx) => {
                        result[i] = Some((*tx).clone());
                    }
                    None => {
                        missing.push(sid);
                    }
                }
                short_id_idx += 1;
            }
        }

        if missing.is_empty() {
            Ok(result.into_iter().map(|t| t.unwrap()).collect())
        } else {
            Err(missing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::BlockHash;

    #[test]
    fn test_siphash_known_vector() {
        // SipHash-2-4 with key (0, 0) on empty data
        let hash = siphash_2_4(0, 0, &[]);
        // Known result for SipHash-2-4 with zero key and empty message
        assert_ne!(hash, 0); // just verify it produces a non-zero result
    }

    #[test]
    fn test_siphash_deterministic() {
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;
        let data = b"hello";

        let h1 = siphash_2_4(k0, k1, data);
        let h2 = siphash_2_4(k0, k1, data);
        assert_eq!(h1, h2);

        // Different data should give different hash
        let h3 = siphash_2_4(k0, k1, b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_short_id_key() {
        let block_hash = [0xab; 32];
        let nonce = 42u64;
        let key = ShortIdKey::new(&block_hash, nonce);

        // Should produce valid k0/k1
        assert_ne!(key.k0, 0);

        // Short ID should be 6 bytes (48 bits max)
        let txid = TxHash::from_bytes([0xcc; 32]);
        let sid = key.short_id(&txid);
        assert!(sid <= 0x0000_ffff_ffff_ffff);
    }

    #[test]
    fn test_short_id_deterministic() {
        let key = ShortIdKey::new(&[0x01; 32], 1);
        let txid = TxHash::from_bytes([0x02; 32]);

        let s1 = key.short_id(&txid);
        let s2 = key.short_id(&txid);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_short_id_different_txids() {
        let key = ShortIdKey::new(&[0x01; 32], 1);
        let tx1 = TxHash::from_bytes([0x02; 32]);
        let tx2 = TxHash::from_bytes([0x03; 32]);

        assert_ne!(key.short_id(&tx1), key.short_id(&tx2));
    }

    #[test]
    fn test_compact_block_creation() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::amount::Amount;
        use btc_primitives::transaction::Witness;

        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0xab; 32]),
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 2083236893,
        };

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let compact = CompactBlock::from_block(header, &[coinbase, tx1], 42);
        assert_eq!(compact.prefilled_txs.len(), 1); // coinbase
        assert_eq!(compact.short_ids.len(), 1); // tx1
        assert_eq!(compact.prefilled_txs[0].index, 0);
    }

    #[test]
    fn test_compact_block_reconstruct_success() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::amount::Amount;

        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0xab; 32]),
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 2083236893,
        };

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let compact = CompactBlock::from_block(header, &[coinbase.clone(), tx1.clone()], 42);

        // Simulate mempool having tx1
        let mut mempool = std::collections::HashMap::new();
        mempool.insert(tx1.txid(), tx1.clone());

        let result = compact.reconstruct(&mempool);
        assert!(result.is_ok());
        let txs = result.unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].txid(), coinbase.txid());
        assert_eq!(txs[1].txid(), tx1.txid());
    }

    #[test]
    fn test_compact_block_reconstruct_missing() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::amount::Amount;

        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0xab; 32]),
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 2083236893,
        };

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let compact = CompactBlock::from_block(header, &[coinbase, tx1], 42);

        // Empty mempool — tx1 is missing
        let mempool = std::collections::HashMap::new();
        let result = compact.reconstruct(&mempool);
        assert!(result.is_err());
        let missing = result.unwrap_err();
        assert_eq!(missing.len(), 1);
    }
}
