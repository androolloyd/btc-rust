//! Actual transaction/script rows bound to a block and its checksummed spent coins.
use crate::traits::{StorageError, TxBlockLocation};
use btc_consensus::utxo::UtxoSetUpdate;
use btc_primitives::hash::sha256;
use btc_primitives::{Block, BlockHash, TxHash};
use std::collections::{BTreeMap, HashMap, HashSet};
fn bad(s: &str) -> StorageError {
    StorageError::Corruption(s.into())
}
fn key(hash: &[u8; 32], height: u64, position: u32) -> [u8; 44] {
    let mut key = [0; 44];
    key[..32].copy_from_slice(hash);
    key[32..40].copy_from_slice(&height.to_be_bytes());
    key[40..].copy_from_slice(&position.to_be_bytes());
    key
}
#[derive(Clone)]
pub struct BlockIndexPlan {
    pub(crate) height: u64,
    pub(crate) hash: BlockHash,
    pub(crate) rows: BTreeMap<[u8; 44], TxHash>,
    pub(crate) transactions: Vec<(TxHash, TxBlockLocation)>,
    undo_hash: [u8; 32],
}
impl BlockIndexPlan {
    pub fn transaction_rows(block: &Block) -> Result<Vec<(TxHash, TxBlockLocation)>, StorageError> {
        if !block.check_merkle_root() {
            return Err(bad("index body/header mismatch"));
        }
        block
            .transactions
            .iter()
            .enumerate()
            .map(|(position, tx)| {
                Ok((
                    tx.txid(),
                    TxBlockLocation {
                        block_hash: block.block_hash(),
                        tx_position: u32::try_from(position)
                            .map_err(|_| bad("transaction position overflow"))?,
                    },
                ))
            })
            .collect()
    }
    pub fn new(
        height: u64,
        block: &Block,
        undo: &UtxoSetUpdate,
        transactions: Vec<(TxHash, TxBlockLocation)>,
    ) -> Result<Self, StorageError> {
        if height == 0 || transactions != Self::transaction_rows(block)? {
            return Err(bad("index input/height mismatch"));
        }
        Ok(Self {
            height,
            hash: block.block_hash(),
            rows: derive_rows(height, block, undo)?,
            transactions,
            undo_hash: sha256(&crate::undo::encode_undo(block.block_hash(), undo)),
        })
    }
    pub fn matches(&self, height: u64, block: &Block, undo: &UtxoSetUpdate) -> bool {
        self.height == height
            && self.hash == block.block_hash()
            && self.undo_hash == sha256(&crate::undo::encode_undo(block.block_hash(), undo))
    }
    pub fn transactions(&self) -> &[(TxHash, TxBlockLocation)] {
        &self.transactions
    }
    pub fn script_rows(&self) -> usize {
        self.rows.len()
    }
}
fn derive_rows(
    height: u64,
    block: &Block,
    undo: &UtxoSetUpdate,
) -> Result<BTreeMap<[u8; 44], TxHash>, StorageError> {
    let spent: HashMap<_, _> = undo.spent.iter().map(|(op, coin)| (*op, coin)).collect();
    if spent.len() != undo.spent.len() {
        return Err(bad("duplicate spent script-index undo coin"));
    }
    let mut rows = BTreeMap::new();
    let mut consumed = HashSet::new();
    for (position, tx) in block.transactions.iter().enumerate() {
        let position =
            u32::try_from(position).map_err(|_| bad("script-index position overflow"))?;
        let mut scripts = HashSet::new();
        for output in &tx.outputs {
            // Provably unspendable outputs are not coins. Genesis is excluded by
            // the caller, matching Electrum's explicitly unindexed coinbase.
            if !output.script_pubkey.is_op_return() && output.script_pubkey.len() <= 10_000 {
                scripts.insert(sha256(output.script_pubkey.as_bytes()));
            }
        }
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let op = input.previous_output;
                if !consumed.insert(op) {
                    return Err(bad("duplicate consumed script-index coin"));
                }
                let coin = spent
                    .get(&op)
                    .ok_or_else(|| bad("missing spent script-index coin"))?;
                scripts.insert(sha256(coin.txout.script_pubkey.as_bytes()));
            }
        }
        for script in scripts {
            rows.insert(key(&script, height, position), tx.txid());
        }
    }
    if spent.len() != consumed.len() {
        return Err(bad("extra spent script-index undo coin"));
    }
    Ok(rows)
}
