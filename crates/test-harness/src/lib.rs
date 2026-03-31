//! `btc-test` -- an in-process regtest harness for BIP authors.
//!
//! Provides [`TestNode`], [`TestKeyPair`], and [`ScriptBuilder`] so that
//! integration tests can spin up a lightweight regtest node, mine blocks,
//! submit transactions, and query UTXOs without any external process.

use std::collections::HashMap;

use btc_consensus::utxo::{connect_block, InMemoryUtxoSet, UtxoSet, UtxoSetUpdate};
use btc_consensus::validation::{block_subsidy, ChainParams};
use btc_mempool::pool::Mempool;
use btc_primitives::amount::Amount;
use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::compact::CompactTarget;
use btc_primitives::hash::{hash160, sha256d, TxHash};
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

// Re-export key types so test authors do not need to depend on lower crates
// directly for common items.
pub use btc_primitives::amount::Amount as TestAmount;
pub use btc_primitives::hash::TxHash as TestTxHash;
pub use btc_primitives::script::Opcode as TestOpcode;

// ---------------------------------------------------------------------------
// TestNode
// ---------------------------------------------------------------------------

/// An in-process regtest node suitable for use in test suites.
///
/// Maintains a chain of blocks, an in-memory UTXO set, and a mempool.
/// Blocks are mined with trivial proof-of-work (the regtest difficulty target
/// accepts almost any nonce).
pub struct TestNode {
    params: ChainParams,
    utxo_set: InMemoryUtxoSet,
    mempool: Mempool,
    blocks: Vec<Block>,
    height: u64,
    /// Maps block height to its UtxoSetUpdate for potential future disconnects.
    updates: HashMap<u64, UtxoSetUpdate>,
}

impl TestNode {
    /// Create a new regtest node initialised at the genesis block.
    ///
    /// The genesis block itself is *not* stored in the `blocks` vec because it
    /// is implicit; `height` starts at 0 and the first call to `mine_block`
    /// produces block 1.
    pub fn new() -> Self {
        let params = ChainParams::regtest();
        TestNode {
            params,
            utxo_set: InMemoryUtxoSet::new(),
            mempool: Mempool::new(10_000_000, 5_000),
            blocks: Vec::new(),
            height: 0,
            updates: HashMap::new(),
        }
    }

    /// Current best-chain height. Starts at 0 (genesis).
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Access the chain parameters.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// Return a reference to the UTXO set for low-level inspection.
    pub fn utxo_set(&self) -> &InMemoryUtxoSet {
        &self.utxo_set
    }

    /// Return a mutable reference to the mempool.
    pub fn mempool_mut(&mut self) -> &mut Mempool {
        &mut self.mempool
    }

    // ------------------------------------------------------------------
    // Mining
    // ------------------------------------------------------------------

    /// Create a coinbase transaction paying `output_script` at the current
    /// next-block height.
    pub fn create_coinbase(&self, output_script: ScriptBuf) -> Transaction {
        let next_height = self.height + 1;
        let subsidy = block_subsidy(next_height);

        // Coinbase script_sig must include the block height (BIP 34).
        let height_bytes = (next_height as u32).to_le_bytes();
        let mut sig = vec![height_bytes.len() as u8];
        sig.extend_from_slice(&height_bytes);

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(sig),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: subsidy,
                script_pubkey: output_script,
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    /// Mine a single block containing the given transactions (a coinbase is
    /// prepended automatically). Returns the mined block.
    ///
    /// The coinbase reward is sent to an `OP_TRUE` output by default.
    /// Use [`mine_block_to`] to direct the reward elsewhere.
    pub fn mine_block(&mut self, txs: Vec<Transaction>) -> Block {
        let coinbase_script = ScriptBuilder::op_true();
        self.mine_block_to(coinbase_script, txs)
    }

    /// Mine a single block whose coinbase pays `coinbase_script`, plus the
    /// supplied transactions. Returns the mined block.
    pub fn mine_block_to(
        &mut self,
        coinbase_script: ScriptBuf,
        mut txs: Vec<Transaction>,
    ) -> Block {
        let next_height = self.height + 1;

        // --- Compute fees from the included transactions ---
        let mut total_fees = Amount::ZERO;
        for tx in &txs {
            if tx.is_coinbase() {
                continue;
            }
            let mut input_sum = Amount::ZERO;
            for input in &tx.inputs {
                if let Some(entry) = self.utxo_set.get_utxo(&input.previous_output) {
                    input_sum = input_sum + entry.txout.value;
                }
            }
            let output_sum: Amount = tx
                .outputs
                .iter()
                .fold(Amount::ZERO, |acc, o| acc + o.value);
            if input_sum.as_sat() > output_sum.as_sat() {
                total_fees = total_fees + (input_sum - output_sum);
            }
        }

        // Build coinbase claiming subsidy + fees.
        let subsidy = block_subsidy(next_height);
        let reward = subsidy + total_fees;

        let height_bytes = (next_height as u32).to_le_bytes();
        let mut sig = vec![height_bytes.len() as u8];
        sig.extend_from_slice(&height_bytes);

        let coinbase_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(sig),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: reward,
                script_pubkey: coinbase_script,
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Coinbase first, then user txs.
        txs.insert(0, coinbase_tx);

        // Compute merkle root.
        let merkle_root = {
            let txids: Vec<[u8; 32]> = txs.iter().map(|tx| tx.txid().to_bytes()).collect();
            TxHash::from_bytes(btc_primitives::block::merkle_root(&txids))
        };

        // Determine prev_blockhash.
        let prev_hash = if let Some(last) = self.blocks.last() {
            last.block_hash()
        } else {
            // First mined block follows the regtest genesis.
            self.params.genesis_hash
        };

        // Build header. Regtest difficulty (0x207fffff) accepts nonce 0 for
        // virtually any block, but we iterate briefly to be safe.
        let time = 1_296_688_602 + (next_height as u32) * 600;
        let bits = CompactTarget::from_u32(0x207fffff);

        let mut header = BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: prev_hash,
            merkle_root,
            time,
            bits,
            nonce: 0,
        };

        // Grind nonce until PoW is satisfied (regtest: almost instant).
        while !header.check_proof_of_work() {
            header.nonce += 1;
            if header.nonce == u32::MAX {
                // Bump time and retry (extremely unlikely for regtest).
                header.time += 1;
                header.nonce = 0;
            }
        }

        let block = Block {
            header,
            transactions: txs,
        };

        // Connect the block to the UTXO set.
        let update =
            connect_block(&block, next_height, &self.utxo_set).expect("block should be valid");
        self.utxo_set.apply_update(&update);
        self.updates.insert(next_height, update);
        self.blocks.push(block.clone());
        self.height = next_height;

        block
    }

    /// Mine `n` empty blocks (no user transactions). Returns all mined blocks.
    pub fn mine_blocks(&mut self, n: u32) -> Vec<Block> {
        let mut blocks = Vec::with_capacity(n as usize);
        for _ in 0..n {
            blocks.push(self.mine_block(vec![]));
        }
        blocks
    }

    // ------------------------------------------------------------------
    // Transaction submission
    // ------------------------------------------------------------------

    /// Submit a transaction to the mempool. Returns the txid on success.
    ///
    /// The caller is responsible for providing a transaction with valid
    /// structure. Fee is computed from UTXO set lookups.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<TxHash, String> {
        // Compute fee from UTXO set.
        let mut input_sum = Amount::ZERO;
        for inp in &tx.inputs {
            let entry = self
                .utxo_set
                .get_utxo(&inp.previous_output)
                .ok_or_else(|| {
                    format!(
                        "input references unknown UTXO {:?}",
                        inp.previous_output
                    )
                })?;
            input_sum = input_sum + entry.txout.value;
        }
        let output_sum: Amount = tx
            .outputs
            .iter()
            .fold(Amount::ZERO, |acc, o| acc + o.value);

        if output_sum.as_sat() > input_sum.as_sat() {
            return Err(format!(
                "outputs ({}) exceed inputs ({})",
                output_sum.as_sat(),
                input_sum.as_sat(),
            ));
        }

        let fee = input_sum - output_sum;
        let now = self.height; // use height as a cheap timestamp stand-in

        self.mempool
            .add_tx(tx, fee, now)
            .map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Compute the total balance (in satoshis) for a given script hash.
    ///
    /// `script_hash` should be the SHA-256d hash of the `script_pubkey` bytes.
    /// This is a simplistic scan; for production use, a proper index would be
    /// needed.
    pub fn get_balance(&self, script_hash: &[u8; 32]) -> i64 {
        self.get_utxos(script_hash)
            .iter()
            .map(|(_, txo)| txo.value.as_sat())
            .sum()
    }

    /// Return all unspent outputs whose `script_pubkey` hashes to `script_hash`.
    ///
    /// The hash is the double-SHA-256 of the raw `script_pubkey` bytes.
    pub fn get_utxos(&self, script_hash: &[u8; 32]) -> Vec<(OutPoint, TxOut)> {
        self.utxo_set
            .iter()
            .filter_map(|(op, entry)| {
                let h = sha256d(entry.txout.script_pubkey.as_bytes());
                if &h == script_hash {
                    Some((*op, entry.txout.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get a block by height (1-indexed; height 1 is the first mined block
    /// after genesis).
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        if height == 0 || height as usize > self.blocks.len() {
            return None;
        }
        Some(&self.blocks[(height - 1) as usize])
    }
}

impl Default for TestNode {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TestKeyPair
// ---------------------------------------------------------------------------

/// A convenience wrapper around a secp256k1 key pair for generating test
/// addresses and signing transactions.
pub struct TestKeyPair {
    pub secret_key: secp256k1::SecretKey,
    pub public_key: secp256k1::PublicKey,
}

impl TestKeyPair {
    /// Generate a random key pair.
    pub fn generate() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        TestKeyPair {
            secret_key,
            public_key,
        }
    }

    /// Create from an existing secret key.
    pub fn from_secret(sk: secp256k1::SecretKey) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        TestKeyPair {
            secret_key: sk,
            public_key,
        }
    }

    /// The compressed public key bytes (33 bytes).
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }

    /// HASH160 of the compressed public key (20 bytes).
    pub fn pubkey_hash(&self) -> [u8; 20] {
        hash160(&self.pubkey_bytes())
    }

    /// Build a P2PKH `script_pubkey` for this key.
    pub fn p2pkh_script(&self) -> ScriptBuf {
        ScriptBuf::p2pkh(&self.pubkey_hash())
    }

    /// Build a P2WPKH `script_pubkey` for this key.
    pub fn p2wpkh_script(&self) -> ScriptBuf {
        ScriptBuf::p2wpkh(&self.pubkey_hash())
    }

    /// The SHA-256d hash of the P2PKH script_pubkey (for balance queries).
    pub fn p2pkh_script_hash(&self) -> [u8; 32] {
        sha256d(self.p2pkh_script().as_bytes())
    }

    /// The SHA-256d hash of the P2WPKH script_pubkey (for balance queries).
    pub fn p2wpkh_script_hash(&self) -> [u8; 32] {
        sha256d(self.p2wpkh_script().as_bytes())
    }

    /// Sign an input using legacy P2PKH sighash (SIGHASH_ALL).
    ///
    /// Returns the DER-encoded signature with the sighash byte appended,
    /// ready for use in `script_sig`.
    pub fn sign_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Vec<u8> {
        use btc_consensus::sighash::{sighash_legacy, SighashType};

        let hash = sighash_legacy(
            tx,
            input_index,
            prev_output.script_pubkey.as_bytes(),
            SighashType::ALL,
        )
        .expect("sighash computation should succeed");

        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(hash);
        let sig = secp.sign_ecdsa(&msg, &self.secret_key);
        let mut der = sig.serialize_der().to_vec();
        der.push(SighashType::ALL.0 as u8); // SIGHASH_ALL
        der
    }

    /// Sign a segwit v0 input (P2WPKH) using BIP-143 sighash (SIGHASH_ALL).
    ///
    /// Returns the DER-encoded signature with the sighash byte appended,
    /// suitable for inclusion in witness data.
    pub fn sign_input_segwit(
        &self,
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Vec<u8> {
        use btc_consensus::sighash::{sighash_segwit_v0, SighashType};

        // For P2WPKH, the script code is a synthetic P2PKH script:
        // OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_code = ScriptBuf::p2pkh(&self.pubkey_hash());

        let hash = sighash_segwit_v0(
            tx,
            input_index,
            script_code.as_bytes(),
            prev_output.value.as_sat(),
            SighashType::ALL,
        )
        .expect("segwit sighash computation should succeed");

        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(hash);
        let sig = secp.sign_ecdsa(&msg, &self.secret_key);
        let mut der = sig.serialize_der().to_vec();
        der.push(SighashType::ALL.0 as u8);
        der
    }

    /// Build a complete `script_sig` for a legacy P2PKH spend.
    ///
    /// Format: `<sig> <pubkey>`
    pub fn build_p2pkh_script_sig(
        &self,
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> ScriptBuf {
        let sig = self.sign_input(tx, input_index, prev_output);
        let pubkey = self.pubkey_bytes();
        let mut script = ScriptBuf::new();
        script.push_slice(&sig);
        script.push_slice(&pubkey);
        script
    }

    /// Build witness data for a P2WPKH spend.
    ///
    /// Witness: `[<sig>, <pubkey>]`
    pub fn build_p2wpkh_witness(
        &self,
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Witness {
        let sig = self.sign_input_segwit(tx, input_index, prev_output);
        let pubkey = self.pubkey_bytes();
        Witness::from_items(vec![sig, pubkey])
    }
}

// ---------------------------------------------------------------------------
// ScriptBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for constructing Bitcoin scripts in tests.
pub struct ScriptBuilder(ScriptBuf);

impl ScriptBuilder {
    /// Start with an empty script.
    pub fn new() -> Self {
        ScriptBuilder(ScriptBuf::new())
    }

    /// Push an opcode.
    pub fn push_op(mut self, op: Opcode) -> Self {
        self.0.push_opcode(op);
        self
    }

    /// Push a data slice (automatically selects the right push opcode).
    pub fn push_data(mut self, data: &[u8]) -> Self {
        self.0.push_slice(data);
        self
    }

    /// Push a small integer in Bitcoin's script number encoding.
    ///
    /// - 0 maps to `OP_0`
    /// - 1..=16 maps to `OP_1`..`OP_16`
    /// - -1 maps to `OP_1NEGATE`
    /// - Anything else is encoded as a data push in script-number format.
    pub fn push_num(mut self, n: i64) -> Self {
        if n == 0 {
            self.0.push_opcode(Opcode::OP_0);
        } else if n == -1 {
            self.0.push_opcode(Opcode::OP_1NEGATE);
        } else if (1..=16).contains(&n) {
            // OP_1 = 0x51, OP_2 = 0x52, ...
            let op = Opcode::from_u8(0x50 + n as u8);
            self.0.push_opcode(op);
        } else {
            // Encode as minimal CScriptNum
            let bytes = encode_script_num(n);
            self.0.push_slice(&bytes);
        }
        self
    }

    /// Finalise and return the script.
    pub fn build(self) -> ScriptBuf {
        self.0
    }

    // ----- Convenience constructors -----

    /// `OP_TRUE` (alias for `OP_1`) -- always succeeds.
    pub fn op_true() -> ScriptBuf {
        let mut s = ScriptBuf::new();
        s.push_opcode(Opcode::OP_1);
        s
    }

    /// `OP_RETURN <data>` -- provably unspendable.
    pub fn op_return(data: &[u8]) -> ScriptBuf {
        let mut s = ScriptBuf::new();
        s.push_opcode(Opcode::OP_RETURN);
        s.push_slice(data);
        s
    }
}

impl Default for ScriptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode an integer as a Bitcoin CScriptNum (minimal byte encoding).
fn encode_script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let negative = n < 0;
    let mut abs = if negative { -(n as i128) } else { n as i128 } as u64;

    let mut result = Vec::new();
    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // If the most significant byte has the sign bit set, add an extra byte
    // to disambiguate from a negative number.
    if result.last().map_or(false, |b| b & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----- TestNode: mine 100 blocks -----

    #[test]
    fn test_mine_100_blocks() {
        let mut node = TestNode::new();
        let blocks = node.mine_blocks(100);
        assert_eq!(blocks.len(), 100);
        assert_eq!(node.height(), 100);

        // Every block should have a valid PoW.
        for block in &blocks {
            assert!(block.header.check_proof_of_work());
        }

        // Every block should have at least the coinbase.
        for block in &blocks {
            assert!(!block.transactions.is_empty());
            assert!(block.transactions[0].is_coinbase());
        }
    }

    // ----- TestNode: mine a block with a transaction -----

    #[test]
    fn test_mine_block_with_transaction() {
        let mut node = TestNode::new();

        // Mine 100 blocks so the first coinbase matures.
        let key = TestKeyPair::generate();
        let _blocks = node.mine_blocks(100);

        // Mine block 101 paying the key, so we have a mature coinbase later.
        let block_101 = node.mine_block_to(key.p2pkh_script(), vec![]);
        assert_eq!(node.height(), 101);

        // Mine 100 more to mature block 101's coinbase.
        node.mine_blocks(100);
        assert_eq!(node.height(), 201);

        // Build a transaction spending block 101's coinbase.
        let coinbase_txid = block_101.transactions[0].txid();
        let outpoint = OutPoint::new(coinbase_txid, 0);
        let prev_output = block_101.transactions[0].outputs[0].clone();

        let key2 = TestKeyPair::generate();
        let spend_value = Amount::from_sat(prev_output.value.as_sat() - 10_000); // 10k sat fee

        let mut spend_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(), // placeholder
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: spend_value,
                script_pubkey: key2.p2pkh_script(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Sign the input.
        let script_sig = key.build_p2pkh_script_sig(&spend_tx, 0, &prev_output);
        spend_tx.inputs[0].script_sig = script_sig;

        // Mine the block containing this transaction.
        let block = node.mine_block(vec![spend_tx.clone()]);
        assert_eq!(block.transactions.len(), 2); // coinbase + spend
        assert_eq!(block.transactions[1].txid(), spend_tx.txid());
    }

    // ----- TestNode: spending a coinbase output -----

    #[test]
    fn test_spend_coinbase_output() {
        let mut node = TestNode::new();
        let key = TestKeyPair::generate();

        // Mine 1 block to the key.
        let block_1 = node.mine_block_to(key.p2pkh_script(), vec![]);
        let coinbase_txid = block_1.transactions[0].txid();

        // Mine 100 more blocks to mature the coinbase.
        node.mine_blocks(100);
        assert_eq!(node.height(), 101);

        // Now spend the matured coinbase.
        let outpoint = OutPoint::new(coinbase_txid, 0);
        let prev_output = block_1.transactions[0].outputs[0].clone();

        let key2 = TestKeyPair::generate();
        let spend_value = Amount::from_sat(prev_output.value.as_sat() - 5_000);

        let mut spend_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: spend_value,
                script_pubkey: key2.p2pkh_script(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let script_sig = key.build_p2pkh_script_sig(&spend_tx, 0, &prev_output);
        spend_tx.inputs[0].script_sig = script_sig;

        let block = node.mine_block(vec![spend_tx]);
        assert_eq!(block.transactions.len(), 2);

        // The key2 should now have the output.
        let key2_hash = key2.p2pkh_script_hash();
        let utxos = node.get_utxos(&key2_hash);
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].1.value.as_sat(), spend_value.as_sat());
    }

    // ----- TestNode: mempool submission -----

    #[test]
    fn test_mempool_submission() {
        let mut node = TestNode::new();
        let key = TestKeyPair::generate();

        // Mine a block to the key, then mature it.
        let block_1 = node.mine_block_to(key.p2pkh_script(), vec![]);
        node.mine_blocks(100);

        // Build a spend transaction.
        let coinbase_txid = block_1.transactions[0].txid();
        let outpoint = OutPoint::new(coinbase_txid, 0);
        let prev_output = block_1.transactions[0].outputs[0].clone();

        let key2 = TestKeyPair::generate();
        let spend_value = Amount::from_sat(prev_output.value.as_sat() - 5_000);

        let mut spend_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: spend_value,
                script_pubkey: key2.p2pkh_script(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let script_sig = key.build_p2pkh_script_sig(&spend_tx, 0, &prev_output);
        spend_tx.inputs[0].script_sig = script_sig;

        // Submit to mempool.
        let result = node.submit_transaction(spend_tx.clone());
        assert!(result.is_ok());
        let txid = result.unwrap();
        assert_eq!(txid, spend_tx.txid());

        // Verify it is in the mempool.
        assert!(node.mempool_mut().contains(&txid));

        // Submitting the same tx twice should fail.
        // We need a second copy with the same txid. Since the txid is
        // determined by the serialized tx, cloning gives us an identical tx.
        let dup_tx = spend_tx.clone();
        let result2 = node.submit_transaction(dup_tx);
        assert!(result2.is_err());
    }

    // ----- TestKeyPair: generation and signing -----

    #[test]
    fn test_key_generation_and_scripts() {
        let key = TestKeyPair::generate();

        // Public key should be 33 bytes (compressed).
        assert_eq!(key.pubkey_bytes().len(), 33);

        // HASH160 of pubkey should be 20 bytes.
        assert_eq!(key.pubkey_hash().len(), 20);

        // P2PKH script should be 25 bytes.
        let p2pkh = key.p2pkh_script();
        assert!(p2pkh.is_p2pkh());
        assert_eq!(p2pkh.len(), 25);

        // P2WPKH script should be 22 bytes.
        let p2wpkh = key.p2wpkh_script();
        assert!(p2wpkh.is_p2wpkh());
        assert_eq!(p2wpkh.len(), 22);

        // Two generated keys should be different.
        let key2 = TestKeyPair::generate();
        assert_ne!(key.pubkey_bytes(), key2.pubkey_bytes());
    }

    #[test]
    fn test_key_signing() {
        let key = TestKeyPair::generate();

        // Build a dummy transaction.
        let prev_output = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: key.p2pkh_script(),
        };

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::p2pkh(&[0u8; 20]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // sign_input should produce a valid DER signature + sighash byte.
        let sig = key.sign_input(&tx, 0, &prev_output);
        assert!(!sig.is_empty());
        // Last byte should be SIGHASH_ALL (0x01).
        assert_eq!(*sig.last().unwrap(), 0x01);

        // build_p2pkh_script_sig should produce a non-empty script.
        let script_sig = key.build_p2pkh_script_sig(&tx, 0, &prev_output);
        assert!(!script_sig.is_empty());
    }

    // ----- ScriptBuilder -----

    #[test]
    fn test_script_builder_basic() {
        // Build a simple OP_ADD script: <2> <3> OP_ADD <5> OP_EQUAL
        let script = ScriptBuilder::new()
            .push_num(2)
            .push_num(3)
            .push_op(Opcode::OP_ADD)
            .push_num(5)
            .push_op(Opcode::OP_EQUAL)
            .build();

        assert!(!script.is_empty());

        // Verify the opcodes are correct.
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], Opcode::OP_2 as u8); // push 2
        assert_eq!(bytes[1], Opcode::OP_3 as u8); // push 3
        assert_eq!(bytes[2], Opcode::OP_ADD as u8); // OP_ADD
        assert_eq!(bytes[3], Opcode::OP_5 as u8); // push 5
        assert_eq!(bytes[4], Opcode::OP_EQUAL as u8); // OP_EQUAL
    }

    #[test]
    fn test_script_builder_op_true() {
        let script = ScriptBuilder::op_true();
        assert_eq!(script.as_bytes(), &[Opcode::OP_1 as u8]);
    }

    #[test]
    fn test_script_builder_op_return() {
        let data = b"hello btc-test";
        let script = ScriptBuilder::op_return(data);
        assert!(script.is_op_return());
    }

    #[test]
    fn test_script_builder_push_data() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let script = ScriptBuilder::new().push_data(&data).build();

        // Should be: length-prefix (4) + data bytes
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 4); // push 4 bytes
        assert_eq!(&bytes[1..5], &data[..]);
    }

    #[test]
    fn test_script_builder_push_num_zero() {
        let script = ScriptBuilder::new().push_num(0).build();
        assert_eq!(script.as_bytes(), &[Opcode::OP_0 as u8]);
    }

    #[test]
    fn test_script_builder_push_num_negative() {
        let script = ScriptBuilder::new().push_num(-1).build();
        assert_eq!(script.as_bytes(), &[Opcode::OP_1NEGATE as u8]);
    }

    // ----- TestNode: get_block -----

    #[test]
    fn test_get_block() {
        let mut node = TestNode::new();
        node.mine_blocks(5);

        // Height 0 (genesis) is not stored; get_block returns None.
        assert!(node.get_block(0).is_none());

        // Heights 1..=5 should be available.
        for h in 1..=5 {
            let block = node.get_block(h).expect("block should exist");
            assert!(block.header.check_proof_of_work());
        }

        // Height 6 does not exist.
        assert!(node.get_block(6).is_none());
    }

    // ----- TestNode: balance query -----

    #[test]
    fn test_get_balance() {
        let mut node = TestNode::new();
        let key = TestKeyPair::generate();

        // Mine 3 blocks to the key.
        for _ in 0..3 {
            node.mine_block_to(key.p2pkh_script(), vec![]);
        }

        let script_hash = key.p2pkh_script_hash();
        let balance = node.get_balance(&script_hash);

        // Regtest subsidy at heights 1, 2, 3 -- all should be 50 BTC each
        // (halving interval on regtest is 150, so no halving yet).
        let expected = 3 * block_subsidy(1).as_sat();
        assert_eq!(balance, expected);
    }

    // ----- encode_script_num -----

    #[test]
    fn test_encode_script_num() {
        assert_eq!(encode_script_num(0), vec![] as Vec<u8>);
        assert_eq!(encode_script_num(1), vec![0x01]);
        assert_eq!(encode_script_num(-1), vec![0x81]);
        assert_eq!(encode_script_num(127), vec![0x7f]);
        assert_eq!(encode_script_num(128), vec![0x80, 0x00]);
        assert_eq!(encode_script_num(-128), vec![0x80, 0x80]);
        assert_eq!(encode_script_num(255), vec![0xff, 0x00]);
        assert_eq!(encode_script_num(256), vec![0x00, 0x01]);
    }
}
