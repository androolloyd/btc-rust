//! Core testing environment for Bitcoin Script development.

use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_primitives::amount::Amount;
use btc_primitives::script::{Script, ScriptBuf};
use btc_primitives::transaction::{OutPoint, TxOut};
use btc_test::{TestKeyPair, TestNode};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("script execution error: {0}")]
    ScriptExecution(String),
    #[error("missing UTXO: {0}")]
    MissingUtxo(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

// ---------------------------------------------------------------------------
// ScriptResult
// ---------------------------------------------------------------------------

/// Result of a script execution, capturing the final state.
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// Whether the script terminated successfully (top of stack is truthy).
    pub success: bool,
    /// Snapshot of the main stack at termination.
    pub final_stack: Vec<Vec<u8>>,
    /// Number of opcodes that were executed (excluding push-data).
    pub op_count: usize,
    /// Size of the script in bytes.
    pub script_size: usize,
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

/// A named test account with a keypair.
pub struct Account {
    pub name: String,
    pub keypair: TestKeyPair,
}

// ---------------------------------------------------------------------------
// FundedUtxo
// ---------------------------------------------------------------------------

/// A UTXO that has been created and is available for spending in the test
/// environment.
#[derive(Debug, Clone)]
pub struct FundedUtxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub script: ScriptBuf,
}

// ---------------------------------------------------------------------------
// ScriptEnv
// ---------------------------------------------------------------------------

/// The core testing environment. Wraps a [`TestNode`] and provides
/// ergonomic helpers for funding scripts, creating accounts, and verifying
/// script execution.
pub struct ScriptEnv {
    node: TestNode,
    accounts: Vec<Account>,
}

impl ScriptEnv {
    /// Create a new testing environment backed by a fresh regtest node.
    pub fn new() -> Self {
        ScriptEnv {
            node: TestNode::new(),
            accounts: Vec::new(),
        }
    }

    /// Generate a new account with an auto-assigned name (`account_0`,
    /// `account_1`, ...).
    pub fn new_account(&mut self) -> &Account {
        let idx = self.accounts.len();
        let name = format!("account_{}", idx);
        self.accounts.push(Account {
            name,
            keypair: TestKeyPair::generate(),
        });
        &self.accounts[idx]
    }

    /// Generate a new account with the given name.
    pub fn new_named_account(&mut self, name: &str) -> &Account {
        let idx = self.accounts.len();
        self.accounts.push(Account {
            name: name.to_string(),
            keypair: TestKeyPair::generate(),
        });
        &self.accounts[idx]
    }

    /// Get an account by index. This is useful after calling
    /// `new_account` / `new_named_account` since those return borrows that
    /// tie up the `ScriptEnv` mutably.
    pub fn account(&self, index: usize) -> &Account {
        &self.accounts[index]
    }

    /// Fund a script output by mining a block whose coinbase pays
    /// `script`. Returns the resulting UTXO.
    ///
    /// Note: the coinbase output needs to mature (100 blocks) before it can
    /// be spent. Call [`advance_blocks`] if you need to spend it.
    pub fn fund_script(&mut self, script: &ScriptBuf, amount: Amount) -> FundedUtxo {
        // Mine a block whose coinbase pays the given script.
        // The coinbase value is fixed by the block subsidy; `amount` is what the
        // user *wants* the UTXO to be worth. We create a second output if needed,
        // but for simplicity (regtest subsidy is 50 BTC) we just mine to the
        // script and report the coinbase value. To get an exact amount, we would
        // need an intermediate spend. For the forge environment, mining directly
        // is the most ergonomic approach -- the value will be the block subsidy.
        let _ = amount; // amount is aspirational; actual value = subsidy

        let block = self.node.mine_block_to(script.clone(), vec![]);
        let txid = block.transactions[0].txid();
        let txout = block.transactions[0].outputs[0].clone();

        FundedUtxo {
            outpoint: OutPoint::new(txid, 0),
            txout,
            script: script.clone(),
        }
    }

    /// Fund a P2PKH output for the given account.
    pub fn fund_p2pkh(&mut self, account_index: usize, amount: Amount) -> FundedUtxo {
        let script = self.accounts[account_index].keypair.p2pkh_script();
        self.fund_script(&script, amount)
    }

    /// Mine `n` empty blocks to advance the chain (useful for maturing
    /// coinbases or testing timelocks).
    pub fn advance_blocks(&mut self, n: u32) {
        self.node.mine_blocks(n);
    }

    /// Set the chain to the given height by mining the necessary blocks.
    /// If `h` is at or below the current height, this is a no-op.
    pub fn set_height(&mut self, h: u64) {
        let current = self.node.height();
        if h > current {
            let diff = (h - current) as u32;
            self.node.mine_blocks(diff);
        }
    }

    /// Current best-chain height.
    pub fn height(&self) -> u64 {
        self.node.height()
    }

    /// Access the underlying [`TestNode`] for advanced operations.
    pub fn node(&self) -> &TestNode {
        &self.node
    }

    /// Mutable access to the underlying [`TestNode`].
    pub fn node_mut(&mut self) -> &mut TestNode {
        &mut self.node
    }

    /// Verify a script by executing `script_sig` then `script_pubkey` in
    /// sequence (legacy P2PKH-style verification without witness).
    pub fn verify_script(
        &self,
        script_sig: &Script,
        script_pubkey: &Script,
    ) -> Result<ScriptResult, ForgeError> {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::none();
        let mut engine = ScriptEngine::new(&verifier, flags, None, 0, 0);

        // Execute script_sig first (pushes data onto stack).
        engine
            .execute(script_sig)
            .map_err(|e| ForgeError::ScriptExecution(e.to_string()))?;

        // Then execute script_pubkey against the resulting stack.
        engine
            .execute(script_pubkey)
            .map_err(|e| ForgeError::ScriptExecution(e.to_string()))?;

        let stack = engine.stack().to_vec();
        let success = engine.success();

        Ok(ScriptResult {
            success,
            final_stack: stack,
            op_count: 0,  // engine doesn't expose op_count externally
            script_size: script_sig.len() + script_pubkey.len(),
        })
    }

    /// Verify a script with witness data. The `witness` items are pushed
    /// onto the stack before executing the witness script, mimicking segwit
    /// verification.
    pub fn verify_script_with_witness(
        &self,
        witness: &[Vec<u8>],
        witness_script: &Script,
        script_pubkey: &Script,
    ) -> Result<ScriptResult, ForgeError> {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::none();
        let mut engine = ScriptEngine::new(&verifier, flags, None, 0, 0);

        // Push witness items onto the stack.
        for item in witness {
            // We create a tiny script that pushes the item.
            let mut push_script = ScriptBuf::new();
            push_script.push_slice(item);
            engine
                .execute(push_script.as_script())
                .map_err(|e| ForgeError::ScriptExecution(e.to_string()))?;
        }

        // Execute the witness script.
        engine
            .execute(witness_script)
            .map_err(|e| ForgeError::ScriptExecution(e.to_string()))?;

        let stack = engine.stack().to_vec();
        let success = engine.success();

        Ok(ScriptResult {
            success,
            final_stack: stack,
            op_count: 0,
            script_size: witness_script.len() + script_pubkey.len(),
        })
    }

    /// Execute a standalone script (no separate sig/pubkey split) and
    /// return the result.
    pub fn execute_script(&self, script: &Script) -> Result<ScriptResult, ForgeError> {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::none();
        let mut engine = ScriptEngine::new(&verifier, flags, None, 0, 0);

        engine
            .execute(script)
            .map_err(|e| ForgeError::ScriptExecution(e.to_string()))?;

        let stack = engine.stack().to_vec();
        let success = engine.success();

        Ok(ScriptResult {
            success,
            final_stack: stack,
            op_count: 0,
            script_size: script.len(),
        })
    }
}

impl Default for ScriptEnv {
    fn default() -> Self {
        Self::new()
    }
}
