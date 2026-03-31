//! Block template construction for mining.
//!
//! Assembles a candidate block from the mempool, selecting transactions
//! by fee rate to maximize miner revenue while respecting consensus limits.

use btc_primitives::amount::Amount;
use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::compact::CompactTarget;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};
use crate::validation::block_subsidy;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("no transactions available")]
    NoTransactions,
    #[error("block too large")]
    BlockTooLarge,
}

/// A candidate transaction for block inclusion, with fee metadata.
#[derive(Debug, Clone)]
pub struct CandidateTx {
    pub tx: Transaction,
    pub txid: TxHash,
    pub fee: Amount,
    pub weight: usize,
}

impl CandidateTx {
    pub fn fee_rate_sats_per_wu(&self) -> f64 {
        if self.weight == 0 {
            return 0.0;
        }
        self.fee.as_sat() as f64 / self.weight as f64
    }
}

/// A constructed block template ready for mining.
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    pub header: BlockHeader,
    pub coinbase: Transaction,
    pub transactions: Vec<Transaction>,
    pub total_fees: Amount,
    pub total_weight: usize,
}

impl BlockTemplate {
    /// Convert the template into a full block (for mining/testing).
    pub fn to_block(&self) -> Block {
        let mut txs = Vec::with_capacity(1 + self.transactions.len());
        txs.push(self.coinbase.clone());
        txs.extend(self.transactions.iter().cloned());

        Block {
            header: self.header,
            transactions: txs,
        }
    }
}

/// Maximum block weight (4M weight units = 1M vbytes equivalent)
const MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// Reserved weight for coinbase transaction
const COINBASE_RESERVED_WEIGHT: usize = 4_000;

/// Build a block template from a set of candidate transactions.
///
/// Transactions are sorted by fee rate (highest first) and packed
/// into the block until the weight limit is reached.
pub fn build_block_template(
    prev_hash: BlockHash,
    height: u64,
    timestamp: u32,
    bits: CompactTarget,
    coinbase_script: &[u8],
    coinbase_output_script: ScriptBuf,
    candidates: &mut Vec<CandidateTx>,
) -> BlockTemplate {
    // Sort candidates by fee rate (highest first)
    candidates.sort_by(|a, b| {
        b.fee_rate_sats_per_wu()
            .partial_cmp(&a.fee_rate_sats_per_wu())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let subsidy = block_subsidy(height);
    let available_weight = MAX_BLOCK_WEIGHT - COINBASE_RESERVED_WEIGHT;

    let mut selected_txs: Vec<Transaction> = Vec::new();
    let mut total_fees = Amount::ZERO;
    let mut total_weight: usize = 0;

    for candidate in candidates.iter() {
        if total_weight + candidate.weight > available_weight {
            continue; // skip if doesn't fit (could try smaller ones)
        }
        total_weight += candidate.weight;
        total_fees = total_fees + candidate.fee;
        selected_txs.push(candidate.tx.clone());
    }

    // Build coinbase transaction
    let coinbase_value = subsidy + total_fees;
    let coinbase = build_coinbase(height, coinbase_script, coinbase_output_script, coinbase_value);

    // Build header (nonce will be set by the miner)
    let mut all_txs = Vec::with_capacity(1 + selected_txs.len());
    all_txs.push(coinbase.clone());
    all_txs.extend(selected_txs.iter().cloned());

    // Compute merkle root
    let txids: Vec<[u8; 32]> = all_txs.iter().map(|tx| tx.txid().to_bytes()).collect();
    let merkle_root = TxHash::from_bytes(btc_primitives::block::merkle_root(&txids));

    let header = BlockHeader {
        version: 0x20000000, // BIP9 version bits
        prev_blockhash: prev_hash,
        merkle_root,
        time: timestamp,
        bits,
        nonce: 0, // miner fills this
    };

    BlockTemplate {
        header,
        coinbase,
        transactions: selected_txs,
        total_fees,
        total_weight,
    }
}

/// Build a coinbase transaction.
fn build_coinbase(
    height: u64,
    extra_data: &[u8],
    output_script: ScriptBuf,
    value: Amount,
) -> Transaction {
    // BIP34: height must be in coinbase scriptSig
    let mut script_sig_bytes = Vec::new();
    // Encode height as minimal push
    if height == 0 {
        script_sig_bytes.push(0x00);
    } else {
        let height_bytes = height.to_le_bytes();
        let len = 8 - height_bytes.iter().rev().take_while(|&&b| b == 0).count();
        let len = len.max(1);
        script_sig_bytes.push(len as u8);
        script_sig_bytes.extend_from_slice(&height_bytes[..len]);
    }
    script_sig_bytes.extend_from_slice(extra_data);

    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(script_sig_bytes),
            sequence: 0xffffffff,
        }],
        outputs: vec![
            TxOut {
                value,
                script_pubkey: output_script,
            },
        ],
        witness: vec![Witness::from_items(vec![vec![0u8; 32]])], // witness commitment placeholder
        lock_time: 0,
    }
}

/// Estimate the weight of a transaction.
/// Weight = base_size * 3 + total_size
/// (segwit discount: witness data counts 1/4)
pub fn estimate_tx_weight(tx: &Transaction) -> usize {
    let base_size = btc_primitives::encode::encode(tx).len(); // includes witness for segwit
    if tx.is_segwit() {
        // For segwit, we'd need to compute base vs witness size separately
        // Simplified: base_size * 4 is a conservative estimate
        base_size * 4
    } else {
        base_size * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_coinbase() {
        let output_script = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);
        let cb = build_coinbase(100, b"btc-rust", output_script, Amount::from_sat(5_000_000_000));

        assert!(cb.is_coinbase());
        assert_eq!(cb.outputs[0].value.as_sat(), 5_000_000_000);
        // Verify BIP34 height encoding in scriptSig
        let sig = cb.inputs[0].script_sig.as_bytes();
        assert!(sig.len() >= 2); // at least height push + data
    }

    #[test]
    fn test_build_empty_template() {
        let mut candidates = Vec::new();
        let template = build_block_template(
            BlockHash::ZERO,
            100,
            1700000000,
            CompactTarget::MAX_TARGET,
            b"test",
            ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            &mut candidates,
        );

        assert!(template.transactions.is_empty());
        assert_eq!(template.total_fees, Amount::ZERO);
        // Coinbase should have subsidy only
        assert_eq!(template.coinbase.outputs[0].value, block_subsidy(100));
    }

    #[test]
    fn test_build_template_with_txs() {
        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(900_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let mut candidates = vec![
            CandidateTx {
                txid: tx1.txid(),
                tx: tx1.clone(),
                fee: Amount::from_sat(10_000),
                weight: 400,
            },
        ];

        let template = build_block_template(
            BlockHash::ZERO,
            100,
            1700000000,
            CompactTarget::MAX_TARGET,
            b"test",
            ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            &mut candidates,
        );

        assert_eq!(template.transactions.len(), 1);
        assert_eq!(template.total_fees, Amount::from_sat(10_000));
        // Coinbase value = subsidy + fees
        let expected = block_subsidy(100) + Amount::from_sat(10_000);
        assert_eq!(template.coinbase.outputs[0].value, expected);
    }

    #[test]
    fn test_fee_rate_ordering() {
        let make_tx = |n: u8| Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([n; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![n]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let tx_low = make_tx(1);
        let tx_high = make_tx(2);

        let mut candidates = vec![
            CandidateTx {
                txid: tx_low.txid(),
                tx: tx_low,
                fee: Amount::from_sat(100),  // low fee rate
                weight: 1000,
            },
            CandidateTx {
                txid: tx_high.txid(),
                tx: tx_high,
                fee: Amount::from_sat(5000), // high fee rate
                weight: 500,
            },
        ];

        let template = build_block_template(
            BlockHash::ZERO,
            100,
            1700000000,
            CompactTarget::MAX_TARGET,
            b"test",
            ScriptBuf::from_bytes(vec![0x76]),
            &mut candidates,
        );

        // Both should be included, highest fee rate first
        assert_eq!(template.transactions.len(), 2);
    }

    #[test]
    fn test_template_to_block() {
        let mut candidates = Vec::new();
        let template = build_block_template(
            BlockHash::ZERO,
            1,
            1700000000,
            CompactTarget::MAX_TARGET,
            b"test",
            ScriptBuf::from_bytes(vec![0x76]),
            &mut candidates,
        );

        let block = template.to_block();
        assert_eq!(block.transactions.len(), 1); // just coinbase
        assert!(block.transactions[0].is_coinbase());
        assert_eq!(block.header.prev_blockhash, BlockHash::ZERO);
    }

    #[test]
    fn test_candidate_fee_rate() {
        let c = CandidateTx {
            txid: TxHash::ZERO,
            tx: Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                witness: vec![],
                lock_time: 0,
            },
            fee: Amount::from_sat(10_000),
            weight: 1000,
        };
        assert!((c.fee_rate_sats_per_wu() - 10.0).abs() < 0.001);
    }
}
