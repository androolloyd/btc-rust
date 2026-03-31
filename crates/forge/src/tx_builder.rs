//! Transaction builder for constructing test transactions.

use btc_primitives::amount::Amount;
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};
use btc_test::TestKeyPair;

use crate::script_env::FundedUtxo;

/// Input being constructed for a transaction.
struct TxBuilderInput {
    outpoint: OutPoint,
    script_sig: ScriptBuf,
    sequence: u32,
    witness: Vec<Vec<u8>>,
}

/// A fluent builder for constructing Bitcoin transactions in tests.
pub struct TxBuilder {
    version: i32,
    inputs: Vec<TxBuilderInput>,
    outputs: Vec<TxOut>,
    lock_time: u32,
}

impl TxBuilder {
    /// Create a new transaction builder with default settings (version 2,
    /// no locktime).
    pub fn new() -> Self {
        TxBuilder {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    /// Add an input spending the given funded UTXO. The script_sig is left
    /// empty; use [`sign_input`] or [`with_witness`] to provide
    /// authorization.
    pub fn add_input(mut self, utxo: &FundedUtxo) -> Self {
        self.inputs.push(TxBuilderInput {
            outpoint: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: Vec::new(),
        });
        self
    }

    /// Add an input with an explicit outpoint and script_sig.
    pub fn add_input_with_script(mut self, outpoint: OutPoint, script_sig: ScriptBuf) -> Self {
        self.inputs.push(TxBuilderInput {
            outpoint,
            script_sig,
            sequence: TxIn::SEQUENCE_FINAL,
            witness: Vec::new(),
        });
        self
    }

    /// Add an output.
    pub fn add_output(mut self, script_pubkey: ScriptBuf, amount: Amount) -> Self {
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
        self
    }

    /// Set the transaction locktime.
    pub fn with_locktime(mut self, locktime: u32) -> Self {
        self.lock_time = locktime;
        self
    }

    /// Override the sequence number for a specific input.
    pub fn with_sequence(mut self, input_idx: usize, sequence: u32) -> Self {
        if input_idx < self.inputs.len() {
            self.inputs[input_idx].sequence = sequence;
        }
        self
    }

    /// Set the witness data for a specific input.
    pub fn with_witness(mut self, input_idx: usize, witness: Vec<Vec<u8>>) -> Self {
        if input_idx < self.inputs.len() {
            self.inputs[input_idx].witness = witness;
        }
        self
    }

    /// Sign a specific input with the given key for a legacy P2PKH spend.
    ///
    /// This builds a temporary transaction, computes the sighash, signs,
    /// and sets the `script_sig` on the input.
    pub fn sign_input(mut self, input_idx: usize, key: &TestKeyPair, prev_output: &TxOut) -> Self {
        // Build a temporary transaction to compute the sighash.
        let tmp_tx = self.build_internal();
        let script_sig = key.build_p2pkh_script_sig(&tmp_tx, input_idx, prev_output);
        self.inputs[input_idx].script_sig = script_sig;
        self
    }

    /// Consume the builder and produce a [`Transaction`].
    pub fn build(self) -> Transaction {
        self.build_internal()
    }

    /// Internal helper to build the transaction without consuming self.
    fn build_internal(&self) -> Transaction {
        let inputs: Vec<TxIn> = self
            .inputs
            .iter()
            .map(|inp| TxIn {
                previous_output: inp.outpoint,
                script_sig: inp.script_sig.clone(),
                sequence: inp.sequence,
            })
            .collect();

        let witness: Vec<Witness> = self
            .inputs
            .iter()
            .map(|inp| {
                if inp.witness.is_empty() {
                    Witness::new()
                } else {
                    Witness::from_items(inp.witness.clone())
                }
            })
            .collect();

        Transaction {
            version: self.version,
            inputs,
            outputs: self.outputs.clone(),
            witness,
            lock_time: self.lock_time,
        }
    }
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self::new()
    }
}
