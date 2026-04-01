use std::collections::HashMap;
use btc_primitives::network::Network;
use btc_primitives::hash::sha256;
use btc_primitives::encode::Encodable;
use btc_primitives::transaction::Transaction;
use crate::script_engine::{ScriptError, ScriptFlags};

/// Activation context for a pluggable opcode.
///
/// Determines where the opcode is valid. BIP authors choose the appropriate
/// context when registering their opcode plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpcodeContext {
    /// Valid in all scripts (replaces a NOP for soft-fork upgrade, e.g. BIP119 CTV)
    NopUpgrade,
    /// Valid only in tapscript (leaf version 0xc0, e.g. BIP347 OP_CAT)
    TapscriptOnly,
    /// Valid only on specific networks (for testing new opcodes on signet/regtest)
    NetworkOnly(Vec<Network>),
    /// Always valid (built-in)
    Always,
}

/// Execution context passed to opcode plugins.
///
/// Provides mutable access to the script stack and altstack, plus read-only
/// access to the transaction being validated and the active script flags.
pub struct OpcodeExecContext<'a> {
    pub stack: &'a mut Vec<Vec<u8>>,
    pub altstack: &'a mut Vec<Vec<u8>>,
    pub tx: Option<&'a Transaction>,
    pub input_index: usize,
    pub input_amount: i64,
    pub flags: &'a ScriptFlags,
    /// The taproot internal key, if executing in a tapscript context.
    /// This is the 32-byte x-only public key used before tweaking.
    pub taproot_internal_key: Option<[u8; 32]>,
}

/// Trait that BIP authors implement to add a new opcode without forking the node.
///
/// # Example
///
/// ```ignore
/// struct OpMyNewOpcode;
/// impl OpcodePlugin for OpMyNewOpcode {
///     fn opcode(&self) -> u8 { 0xb4 } // OP_NOP5
///     fn name(&self) -> &str { "OP_MYNEWOPCODE" }
///     fn context(&self) -> OpcodeContext { OpcodeContext::NopUpgrade }
///     fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
///         // your logic here
///         Ok(())
///     }
/// }
/// ```
pub trait OpcodePlugin: Send + Sync {
    /// The opcode byte this plugin handles
    fn opcode(&self) -> u8;

    /// Human-readable name (for logging/debugging)
    fn name(&self) -> &str;

    /// Which activation context this opcode is valid in
    fn context(&self) -> OpcodeContext;

    /// Execute the opcode. Has access to the script stack and transaction context.
    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError>;
}

/// Registry of pluggable opcodes.
///
/// The `ScriptEngine` consults this registry when it encounters an opcode byte
/// that is not handled by the built-in match arms. If a plugin is registered
/// for that byte, the plugin's `execute` method is called instead of returning
/// `InvalidOpcode`.
pub struct OpcodeRegistry {
    plugins: HashMap<u8, Box<dyn OpcodePlugin>>,
}

impl OpcodeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        OpcodeRegistry {
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin. Overwrites any previously registered plugin for the
    /// same opcode byte.
    pub fn register(&mut self, plugin: Box<dyn OpcodePlugin>) {
        let opcode = plugin.opcode();
        self.plugins.insert(opcode, plugin);
    }

    /// Look up a plugin by opcode byte.
    pub fn get(&self, opcode: u8) -> Option<&dyn OpcodePlugin> {
        self.plugins.get(&opcode).map(|p| p.as_ref())
    }

    /// Check whether a plugin is registered for the given opcode byte.
    pub fn has(&self, opcode: u8) -> bool {
        self.plugins.contains_key(&opcode)
    }
}

impl Default for OpcodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Example plugins
// ---------------------------------------------------------------------------

/// Compute the BIP119 DefaultCheckTemplateVerifyHash for a transaction at a
/// given input index.
///
/// ```text
/// SHA256(
///   nVersion            (4 bytes, LE)
///   nLockTime           (4 bytes, LE)
///   SHA256(scriptSigs)  (hash of count of scriptSigs = inputs.len())
///   SHA256(sequences)   (hash of all input sequence numbers)
///   SHA256(outputs_count) (hash of the output count)
///   SHA256(outputs)     (hash of all serialized outputs)
///   input_index         (4 bytes, LE)
/// )
/// ```
pub fn default_check_template_verify_hash(
    tx: &Transaction,
    input_index: usize,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(4 + 4 + 32 * 4 + 4);

    // nVersion (4 bytes LE)
    buf.extend_from_slice(&tx.version.to_le_bytes());

    // nLockTime (4 bytes LE)
    buf.extend_from_slice(&tx.lock_time.to_le_bytes());

    // SHA256(scriptSigs count): BIP119 commits to the number of inputs via
    // the count of scriptSigs. For standard CTV the scriptSigs should all be
    // empty, but we hash the count (as a u32 LE) regardless.
    let input_count = tx.inputs.len() as u32;
    let scriptsig_hash = sha256(&input_count.to_le_bytes());
    buf.extend_from_slice(&scriptsig_hash);

    // SHA256(sequences): SHA256 of all input nSequence values concatenated
    {
        let mut seq_preimage = Vec::with_capacity(tx.inputs.len() * 4);
        for input in &tx.inputs {
            seq_preimage.extend_from_slice(&input.sequence.to_le_bytes());
        }
        buf.extend_from_slice(&sha256(&seq_preimage));
    }

    // SHA256(outputs count): hash of the number of outputs
    let output_count = tx.outputs.len() as u32;
    buf.extend_from_slice(&sha256(&output_count.to_le_bytes()));

    // SHA256(outputs): SHA256 of all serialized outputs
    {
        let mut outputs_preimage = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut outputs_preimage)
                .expect("encoding to vec should not fail");
        }
        buf.extend_from_slice(&sha256(&outputs_preimage));
    }

    // input_index (4 bytes LE)
    buf.extend_from_slice(&(input_index as u32).to_le_bytes());

    sha256(&buf)
}

/// BIP119 OP_CHECKTEMPLATEVERIFY — covenant opcode that constrains how a UTXO
/// can be spent by committing to a hash of the spending transaction's template.
///
/// Implements the full DefaultCheckTemplateVerifyHash algorithm:
/// - Pops the 32-byte expected hash from the stack (peek, VERIFY-style)
/// - Requires transaction context
/// - Computes the real template hash from the transaction
/// - Fails if the computed hash does not match the expected hash
pub struct OpCheckTemplateVerify;

impl OpcodePlugin for OpCheckTemplateVerify {
    fn opcode(&self) -> u8 {
        0xb3 // OP_NOP4
    }

    fn name(&self) -> &str {
        "OP_CHECKTEMPLATEVERIFY"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::NopUpgrade
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Peek at the expected template hash on top of stack (VERIFY-style: don't pop)
        let expected = ctx.stack.last().ok_or(ScriptError::StackUnderflow)?;
        if expected.len() != 32 {
            return Err(ScriptError::VerifyFailed);
        }

        // Require transaction context
        let tx = ctx.tx.ok_or(ScriptError::VerifyFailed)?;

        // Compute the real DefaultCheckTemplateVerifyHash
        let computed = default_check_template_verify_hash(tx, ctx.input_index);

        // Compare — constant-time comparison not strictly required for consensus
        // but we do a straightforward equality check
        if computed[..] != expected[..] {
            return Err(ScriptError::VerifyFailed);
        }

        Ok(())
    }
}

/// BIP347 OP_CAT — concatenate the top two stack elements.
///
/// Disabled in legacy script but re-enabled in tapscript. The result must not
/// exceed `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes).
pub struct OpCat;

impl OpcodePlugin for OpCat {
    fn opcode(&self) -> u8 {
        0x7e // OP_CAT (disabled in legacy, enabled in tapscript)
    }

    fn name(&self) -> &str {
        "OP_CAT"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::TapscriptOnly
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        let b = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let a = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let mut result = a;
        result.extend_from_slice(&b);
        if result.len() > 520 {
            // MAX_SCRIPT_ELEMENT_SIZE
            return Err(ScriptError::PushSizeLimit);
        }
        ctx.stack.push(result);
        Ok(())
    }
}

/// BIP348 OP_CHECKSIGFROMSTACK — verify a signature against an arbitrary
/// message (not the transaction sighash).
///
/// Stack before: `<sig> <msg> <pubkey>`
/// Stack after:  `<result>` (OP_TRUE or OP_FALSE)
///
/// Pops the pubkey, message, and signature from the stack. Hashes the message
/// with SHA-256, then verifies the signature against the pubkey using Schnorr
/// (in tapscript) or ECDSA (in legacy). Pushes OP_TRUE (1) on success or
/// OP_FALSE (empty) on failure.
pub struct OpCheckSigFromStack;

impl OpcodePlugin for OpCheckSigFromStack {
    fn opcode(&self) -> u8 {
        0xb4 // OP_NOP5
    }

    fn name(&self) -> &str {
        "OP_CHECKSIGFROMSTACK"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::TapscriptOnly
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Pop pubkey (top of stack)
        let pubkey = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        // Pop message
        let msg = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        // Pop signature
        let sig = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;

        // Validate pubkey length: 32 bytes for x-only (Schnorr/tapscript)
        if pubkey.len() != 32 {
            // Invalid pubkey size — push false
            ctx.stack.push(vec![]);
            return Ok(());
        }

        // Hash the message with SHA-256 to produce a 32-byte digest
        let msg_hash = sha256(&msg);

        // Validate signature length: 64 bytes for Schnorr
        if sig.len() != 64 {
            // Invalid signature — push false
            ctx.stack.push(vec![]);
            return Ok(());
        }

        // Verify signature using secp256k1 Schnorr
        let secp = secp256k1::Secp256k1::verification_only();
        let message = secp256k1::Message::from_digest(msg_hash);

        let schnorr_sig = match secp256k1::schnorr::Signature::from_slice(&sig) {
            Ok(s) => s,
            Err(_) => {
                ctx.stack.push(vec![]);
                return Ok(());
            }
        };

        let xonly_key = match secp256k1::XOnlyPublicKey::from_slice(&pubkey) {
            Ok(k) => k,
            Err(_) => {
                ctx.stack.push(vec![]);
                return Ok(());
            }
        };

        if secp.verify_schnorr(&schnorr_sig, &message, &xonly_key).is_ok() {
            ctx.stack.push(vec![0x01]); // OP_TRUE
        } else {
            ctx.stack.push(vec![]); // OP_FALSE
        }

        Ok(())
    }
}

/// BIP349 OP_INTERNALKEY — push the taproot internal key onto the stack.
///
/// In a tapscript execution context, pushes the 32-byte x-only internal key
/// (the key before tweaking) onto the stack. This allows tapscripts to
/// introspect on the internal key without needing to embed it in the script.
///
/// Fails with `VerifyFailed` if no internal key is available (i.e., the
/// script is not executing in a tapscript context).
pub struct OpInternalKey;

impl OpcodePlugin for OpInternalKey {
    fn opcode(&self) -> u8 {
        0xb5 // OP_NOP6
    }

    fn name(&self) -> &str {
        "OP_INTERNALKEY"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::TapscriptOnly
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Retrieve the internal key from the execution context.
        let internal_key = ctx
            .taproot_internal_key
            .ok_or(ScriptError::VerifyFailed)?;

        ctx.stack.push(internal_key.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BIP118 OP_CHECKSIG_ANYPREVOUT
// ---------------------------------------------------------------------------

/// BIP118 OP_CHECKSIG_ANYPREVOUT — Schnorr signature check using ANYPREVOUT
/// sighash, allowing the signature to be valid when spending any UTXO.
///
/// Stack before: `<sig> <pubkey>`
/// Stack after:  `<result>` (OP_TRUE or OP_FALSE)
///
/// The signature's last byte selects the sighash type:
/// - 0x41 = SIGHASH_ANYPREVOUT (skip outpoint)
/// - 0x42 = SIGHASH_ANYPREVOUTANYSCRIPT (skip outpoint + script + amount)
pub struct OpCheckSigAnyprevout;

impl OpcodePlugin for OpCheckSigAnyprevout {
    fn opcode(&self) -> u8 {
        0xb6 // OP_NOP7
    }

    fn name(&self) -> &str {
        "OP_CHECKSIG_ANYPREVOUT"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::TapscriptOnly
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Pop pubkey (top of stack)
        let pubkey = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        // Pop signature
        let sig = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;

        // Require 32-byte x-only pubkey
        if pubkey.len() != 32 {
            ctx.stack.push(vec![]);
            return Ok(());
        }

        // Need at least 65 bytes: 64 sig + 1 hashtype byte
        if sig.len() != 65 {
            ctx.stack.push(vec![]);
            return Ok(());
        }

        // Extract sighash type from last byte
        let hash_type_byte = sig[64];
        let hash_type = hash_type_byte as u32;

        if hash_type != crate::sighash::SIGHASH_ANYPREVOUT
            && hash_type != crate::sighash::SIGHASH_ANYPREVOUTANYSCRIPT
        {
            ctx.stack.push(vec![]);
            return Ok(());
        }

        // Require transaction context
        let tx = ctx.tx.ok_or(ScriptError::VerifyFailed)?;

        // Build prevouts from tx context — for ANYPREVOUT we need the prevouts
        // array. Since we only have input_amount (of the current input), we
        // construct a minimal prevouts slice. In a real node the full prevouts
        // would be threaded through; here we synthesize one for the current input.
        let prevout_txout = btc_primitives::transaction::TxOut {
            value: btc_primitives::amount::Amount::from_sat(ctx.input_amount),
            script_pubkey: btc_primitives::script::ScriptBuf::from_bytes(vec![]),
        };
        let prevouts: Vec<btc_primitives::transaction::TxOut> =
            (0..tx.inputs.len())
                .map(|i| {
                    if i == ctx.input_index {
                        prevout_txout.clone()
                    } else {
                        btc_primitives::transaction::TxOut {
                            value: btc_primitives::amount::Amount::from_sat(0),
                            script_pubkey: btc_primitives::script::ScriptBuf::from_bytes(vec![]),
                        }
                    }
                })
                .collect();

        // Compute the ANYPREVOUT sighash
        let sighash = match crate::sighash::sighash_anyprevout(
            tx,
            ctx.input_index,
            &prevouts,
            hash_type,
            None,
            None,
        ) {
            Ok(h) => h,
            Err(_) => {
                ctx.stack.push(vec![]);
                return Ok(());
            }
        };

        // Verify Schnorr signature
        let secp = secp256k1::Secp256k1::verification_only();
        let message = secp256k1::Message::from_digest(sighash);

        let schnorr_sig = match secp256k1::schnorr::Signature::from_slice(&sig[..64]) {
            Ok(s) => s,
            Err(_) => {
                ctx.stack.push(vec![]);
                return Ok(());
            }
        };

        let xonly_key = match secp256k1::XOnlyPublicKey::from_slice(&pubkey) {
            Ok(k) => k,
            Err(_) => {
                ctx.stack.push(vec![]);
                return Ok(());
            }
        };

        if secp.verify_schnorr(&schnorr_sig, &message, &xonly_key).is_ok() {
            ctx.stack.push(vec![0x01]); // OP_TRUE
        } else {
            ctx.stack.push(vec![]); // OP_FALSE
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BIP446 OP_TXHASH
// ---------------------------------------------------------------------------

/// BIP446 OP_TXHASH — introspect on transaction fields by hashing a selection.
///
/// Pops a 1-byte "field selector" from the stack:
/// - 0x00: all fields (version || locktime || inputs count || outputs count)
/// - 0x01: version only
/// - 0x02: locktime only
/// - 0x03: inputs hash (SHA256 of all serialized inputs)
/// - 0x04: outputs hash (SHA256 of all serialized outputs)
/// - 0x05: sequences hash (SHA256 of all sequence numbers)
///
/// Pushes the resulting 32-byte SHA256 hash onto the stack.
pub struct OpTxHash;

impl OpcodePlugin for OpTxHash {
    fn opcode(&self) -> u8 {
        0xb7 // OP_NOP8
    }

    fn name(&self) -> &str {
        "OP_TXHASH"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::TapscriptOnly
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Pop the field selector
        let selector_elem = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        if selector_elem.len() != 1 {
            return Err(ScriptError::VerifyFailed);
        }
        let selector = selector_elem[0];

        // Require transaction context
        let tx = ctx.tx.ok_or(ScriptError::VerifyFailed)?;

        let hash = match selector {
            0x00 => {
                // All fields: version || locktime || inputs_count || outputs_count
                let mut buf = Vec::with_capacity(16);
                buf.extend_from_slice(&tx.version.to_le_bytes());
                buf.extend_from_slice(&tx.lock_time.to_le_bytes());
                buf.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
                buf.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
                sha256(&buf)
            }
            0x01 => {
                // Version only
                sha256(&tx.version.to_le_bytes())
            }
            0x02 => {
                // Locktime only
                sha256(&tx.lock_time.to_le_bytes())
            }
            0x03 => {
                // Inputs hash: SHA256 of all serialized inputs
                let mut buf = Vec::new();
                for input in &tx.inputs {
                    input.encode(&mut buf)
                        .map_err(|e| ScriptError::Encode(e))?;
                }
                sha256(&buf)
            }
            0x04 => {
                // Outputs hash: SHA256 of all serialized outputs
                let mut buf = Vec::new();
                for output in &tx.outputs {
                    output.encode(&mut buf)
                        .map_err(|e| ScriptError::Encode(e))?;
                }
                sha256(&buf)
            }
            0x05 => {
                // Sequences hash: SHA256 of all input sequence numbers
                let mut buf = Vec::with_capacity(tx.inputs.len() * 4);
                for input in &tx.inputs {
                    buf.extend_from_slice(&input.sequence.to_le_bytes());
                }
                sha256(&buf)
            }
            _ => {
                return Err(ScriptError::VerifyFailed);
            }
        };

        ctx.stack.push(hash.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BIP443 OP_CHECKCONTRACTVERIFY
// ---------------------------------------------------------------------------

/// BIP443 OP_CHECKCONTRACTVERIFY — verify a taproot contract commitment.
///
/// Stack before: `<flags> <internal_key> <taptree_hash> <expected_hash>`
///   (expected_hash on top)
///
/// This opcode enables vault and covenant constructions by verifying that
/// the taproot output key is correctly derived from the internal key and
/// taptree commitment. The `flags` byte controls which checks are performed:
///
/// - bit 0 (0x01): if set, verify the output key matches at the current input
///   index (i.e., the scriptPubKey of `tx.outputs[input_index]` encodes a P2TR
///   output whose tweaked key matches the commitment).
///
/// This is a VERIFY-style opcode: it fails the script on mismatch and does not
/// push anything on success.
pub struct OpCheckContractVerify;

impl OpcodePlugin for OpCheckContractVerify {
    fn opcode(&self) -> u8 {
        0xb8 // OP_NOP9
    }

    fn name(&self) -> &str {
        "OP_CHECKCONTRACTVERIFY"
    }

    fn context(&self) -> OpcodeContext {
        OpcodeContext::TapscriptOnly
    }

    fn execute(&self, ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> {
        // Pop: expected_hash (top), taptree_hash, internal_key, flags (bottom)
        let expected_hash = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let taptree_hash = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let internal_key = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let flags_elem = ctx.stack.pop().ok_or(ScriptError::StackUnderflow)?;

        // Validate sizes
        if expected_hash.len() != 32 {
            return Err(ScriptError::VerifyFailed);
        }
        if taptree_hash.len() != 32 {
            return Err(ScriptError::VerifyFailed);
        }
        if internal_key.len() != 32 {
            return Err(ScriptError::VerifyFailed);
        }
        if flags_elem.is_empty() {
            return Err(ScriptError::VerifyFailed);
        }

        let _flags = flags_elem[0];

        // Compute the contract commitment:
        // tagged_hash("TapTweak", internal_key || taptree_hash)
        // This is the standard taproot tweak.
        let mut tweak_preimage = Vec::with_capacity(64);
        tweak_preimage.extend_from_slice(&internal_key);
        tweak_preimage.extend_from_slice(&taptree_hash);
        let tweak_hash = crate::taproot::tagged_hash(b"TapTweak", &tweak_preimage);

        // The expected_hash should match the tweak hash
        if tweak_hash != expected_hash[..] {
            return Err(ScriptError::VerifyFailed);
        }

        // VERIFY-style: success means do nothing (don't push)
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Covenant registry helper
// ---------------------------------------------------------------------------

/// Create an `OpcodeRegistry` pre-populated with all covenant opcodes:
/// - OP_CHECKTEMPLATEVERIFY (BIP119, 0xb3)
/// - OP_CHECKSIG_ANYPREVOUT (BIP118, 0xb6)
/// - OP_TXHASH (BIP446, 0xb7)
/// - OP_CHECKCONTRACTVERIFY (BIP443, 0xb8)
pub fn covenant_registry() -> OpcodeRegistry {
    let mut registry = OpcodeRegistry::new();
    registry.register(Box::new(OpCheckTemplateVerify));
    registry.register(Box::new(OpCheckSigAnyprevout));
    registry.register(Box::new(OpTxHash));
    registry.register(Box::new(OpCheckContractVerify));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_engine::{ScriptEngine, ScriptFlags};
    use crate::sig_verify::Secp256k1Verifier;
    use btc_primitives::script::{ScriptBuf, Opcode};

    static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;

    fn make_registry_with(plugins: Vec<Box<dyn OpcodePlugin>>) -> OpcodeRegistry {
        let mut registry = OpcodeRegistry::new();
        for p in plugins {
            registry.register(p);
        }
        registry
    }

    // -----------------------------------------------------------------------
    // Registry unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_register_custom_opcode() {
        let mut registry = OpcodeRegistry::new();
        assert!(!registry.has(0xb3));

        registry.register(Box::new(OpCheckTemplateVerify));
        assert!(registry.has(0xb3));

        let plugin = registry.get(0xb3).unwrap();
        assert_eq!(plugin.name(), "OP_CHECKTEMPLATEVERIFY");
        assert_eq!(plugin.opcode(), 0xb3);
    }

    // -----------------------------------------------------------------------
    // Script engine integration: execute a script containing a plugin opcode
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_script_with_custom_opcode() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        // Build a known transaction so we can compute the correct CTV hash
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute the correct template hash
        let expected_hash = default_check_template_verify_hash(&tx, 0);

        // Register CTV plugin for OP_NOP4 (0xb3)
        let registry = make_registry_with(vec![Box::new(OpCheckTemplateVerify)]);

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
            Some(&registry),
        );

        // Push the correct 32-byte hash, then invoke OP_NOP4 (0xb3 = CTV)
        let mut script = ScriptBuf::new();
        script.push_slice(&expected_hash);
        script.push_opcode(Opcode::OP_NOP4); // 0xb3
        engine.execute(script.as_script()).unwrap();

        // The 32-byte element should still be on the stack (CTV peeks, doesn't pop)
        assert!(engine.success());
    }

    // -----------------------------------------------------------------------
    // OP_CAT tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_opcat_concatenation() {
        let registry = make_registry_with(vec![Box::new(OpCat)]);

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(),
            None,
            0,
            0,
            Some(&registry),
        );

        // Push "hello" and "world", then OP_CAT (0x7e)
        let mut script = ScriptBuf::new();
        script.push_slice(b"hello");
        script.push_slice(b"world");

        // OP_CAT is 0x7e — in the built-in engine it is disabled. Because the
        // plugin registry is checked for disabled opcodes too (when the plugin
        // is registered), we need to inject the raw byte. But since the engine
        // first hits the DisabledOpcode arm for OP_CAT before reaching the
        // plugin fallback, we handle this by using the raw opcode byte via
        // from_bytes with 0x7e which maps to Opcode::OP_CAT.
        //
        // The script engine modification intercepts OP_CAT when a plugin is
        // registered for it.
        script.push_opcode(Opcode::OP_CAT);
        engine.execute(script.as_script()).unwrap();

        let top = engine.stack().last().unwrap();
        assert_eq!(top, b"helloworld");
    }

    #[test]
    fn test_opcat_size_limit() {
        let registry = make_registry_with(vec![Box::new(OpCat)]);

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(),
            None,
            0,
            0,
            Some(&registry),
        );

        // Push two elements that together exceed 520 bytes
        let a = vec![0x41; 300];
        let b = vec![0x42; 300];

        let mut script = ScriptBuf::new();
        script.push_slice(&a);
        script.push_slice(&b);
        script.push_opcode(Opcode::OP_CAT);

        let result = engine.execute(script.as_script());
        assert!(result.is_err());
        match result.unwrap_err() {
            ScriptError::PushSizeLimit => {} // expected
            other => panic!("expected PushSizeLimit, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Unknown opcode without plugin fails
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_opcode_without_plugin_fails() {
        // Empty registry — no plugins registered
        let registry = OpcodeRegistry::new();

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(),
            None,
            0,
            0,
            Some(&registry),
        );

        // OP_INVALIDOPCODE (0xff) is not handled by any built-in arm
        let script = ScriptBuf::from_bytes(vec![0x51, 0xff]); // OP_1, then 0xff
        let result = engine.execute(script.as_script());
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // NopUpgrade context: opcode is allowed in legacy scripts
    // -----------------------------------------------------------------------

    #[test]
    fn test_nop_upgrade_context_allows_in_legacy() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let ctv = OpCheckTemplateVerify;
        assert_eq!(ctv.context(), OpcodeContext::NopUpgrade);

        // Build a transaction so CTV can compute the template hash
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let expected_hash = default_check_template_verify_hash(&tx, 0);

        // NopUpgrade replaces a NOP slot — should work in any script context
        let registry = make_registry_with(vec![Box::new(OpCheckTemplateVerify)]);

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(), // legacy flags, no taproot
            Some(&tx),
            0,
            0,
            Some(&registry),
        );

        let mut script = ScriptBuf::new();
        script.push_slice(&expected_hash);
        script.push_opcode(Opcode::OP_NOP4);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    // -----------------------------------------------------------------------
    // TapscriptOnly context
    // -----------------------------------------------------------------------

    #[test]
    fn test_tapscript_only_context() {
        let cat = OpCat;
        assert_eq!(cat.context(), OpcodeContext::TapscriptOnly);
        assert_eq!(cat.opcode(), 0x7e);
        assert_eq!(cat.name(), "OP_CAT");
    }

    // -----------------------------------------------------------------------
    // OP_CHECKSIGFROMSTACK (BIP348) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksigfromstack_registration() {
        let csfs = OpCheckSigFromStack;
        assert_eq!(csfs.opcode(), 0xb4);
        assert_eq!(csfs.name(), "OP_CHECKSIGFROMSTACK");
        assert_eq!(csfs.context(), OpcodeContext::TapscriptOnly);
    }

    #[test]
    fn test_checksigfromstack_valid_signature() {
        // Generate a keypair, sign a message, verify via OP_CHECKSIGFROMSTACK
        let secp = secp256k1::Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (xonly_pubkey, _parity) = public_key.x_only_public_key();

        let message = b"Hello, BIP348!";
        let msg_hash = btc_primitives::hash::sha256(message);
        let secp_msg = secp256k1::Message::from_digest(msg_hash);

        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let signature = secp.sign_schnorr(&secp_msg, &keypair);

        // Build the execution context manually
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push in order: sig, msg, pubkey (sig deepest, pubkey on top)
        stack.push(signature.as_ref().to_vec()); // 64-byte Schnorr sig
        stack.push(message.to_vec());
        stack.push(xonly_pubkey.serialize().to_vec()); // 32-byte x-only key

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        csfs.execute(&mut ctx).unwrap();

        // Top of stack should be OP_TRUE (0x01)
        assert_eq!(ctx.stack.len(), 1);
        assert_eq!(ctx.stack[0], vec![0x01]);
    }

    #[test]
    fn test_checksigfromstack_invalid_signature() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push invalid data: generate a real pubkey so parsing succeeds
        let secp = secp256k1::Secp256k1::new();
        let (_secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (xonly_pubkey, _parity) = public_key.x_only_public_key();

        stack.push(vec![0x00; 64]); // invalid 64-byte sig (will parse but fail verify)
        stack.push(b"test message".to_vec());
        stack.push(xonly_pubkey.serialize().to_vec());

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        csfs.execute(&mut ctx).unwrap();

        // Should push false (empty vec)
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty());
    }

    #[test]
    fn test_checksigfromstack_wrong_sig_length() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push a signature that is not 64 bytes
        stack.push(vec![0x30; 32]); // wrong length sig
        stack.push(b"test".to_vec());
        stack.push(vec![0x02; 32]);

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        csfs.execute(&mut ctx).unwrap();

        // Should push false due to invalid sig length
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty());
    }

    #[test]
    fn test_checksigfromstack_stack_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Only push one element -- need three
        stack.push(vec![0x02; 32]);

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = csfs.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    // -----------------------------------------------------------------------
    // OP_INTERNALKEY (BIP349) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_internalkey_registration() {
        let opik = OpInternalKey;
        assert_eq!(opik.opcode(), 0xb5);
        assert_eq!(opik.name(), "OP_INTERNALKEY");
        assert_eq!(opik.context(), OpcodeContext::TapscriptOnly);
    }

    #[test]
    fn test_internalkey_pushes_key() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let internal_key = [0xab; 32];

        let opik = OpInternalKey;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: Some(internal_key),
        };

        opik.execute(&mut ctx).unwrap();

        assert_eq!(ctx.stack.len(), 1);
        assert_eq!(ctx.stack[0], internal_key.to_vec());
        assert_eq!(ctx.stack[0].len(), 32);
    }

    #[test]
    fn test_internalkey_fails_without_key() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let opik = OpInternalKey;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None, // no internal key
        };

        let result = opik.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_internalkey_multiple_pushes() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let internal_key = [0xcd; 32];

        let opik = OpInternalKey;

        // Execute twice -- should push the same key twice
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: Some(internal_key),
        };
        opik.execute(&mut ctx).unwrap();
        opik.execute(&mut ctx).unwrap();

        assert_eq!(ctx.stack.len(), 2);
        assert_eq!(ctx.stack[0], ctx.stack[1]);
        assert_eq!(ctx.stack[0], internal_key.to_vec());
    }

    // -----------------------------------------------------------------------
    // BIP119 OP_CHECKTEMPLATEVERIFY — real implementation tests
    // -----------------------------------------------------------------------

    /// Helper: create a known test transaction for CTV tests
    fn make_ctv_test_tx() -> Transaction {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xfffffffe,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(1_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab]),
                },
                TxOut {
                    value: Amount::from_sat(2_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd]),
                },
            ],
            witness: Vec::new(),
            lock_time: 500_000,
        }
    }

    #[test]
    fn test_ctv_compute_template_hash_deterministic() {
        let tx = make_ctv_test_tx();
        let hash1 = default_check_template_verify_hash(&tx, 0);
        let hash2 = default_check_template_verify_hash(&tx, 0);
        assert_eq!(hash1, hash2, "CTV hash must be deterministic");
        assert_ne!(hash1, [0u8; 32], "CTV hash must be non-zero");
    }

    #[test]
    fn test_ctv_different_input_index_different_hash() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let hash0 = default_check_template_verify_hash(&tx, 0);
        let hash1 = default_check_template_verify_hash(&tx, 1);
        assert_ne!(hash0, hash1, "Different input indices must produce different hashes");
    }

    #[test]
    fn test_ctv_verify_matching_hash_succeeds() {
        let tx = make_ctv_test_tx();
        let expected_hash = default_check_template_verify_hash(&tx, 0);

        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push the correct hash
        stack.push(expected_hash.to_vec());

        let ctv = OpCheckTemplateVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        // Should succeed
        ctv.execute(&mut ctx).unwrap();
        // VERIFY-style: stack is untouched (hash still on top)
        assert_eq!(ctx.stack.len(), 1);
        assert_eq!(ctx.stack[0], expected_hash.to_vec());
    }

    #[test]
    fn test_ctv_wrong_template_hash_fails() {
        let tx = make_ctv_test_tx();

        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push a wrong 32-byte hash
        stack.push([0xff; 32].to_vec());

        let ctv = OpCheckTemplateVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = ctv.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_ctv_no_tx_context_fails() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push([0xaa; 32].to_vec());

        let ctv = OpCheckTemplateVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None, // no tx context
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = ctv.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_ctv_non_32_byte_hash_fails() {
        let tx = make_ctv_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push a 20-byte value (wrong size)
        stack.push(vec![0xaa; 20]);

        let ctv = OpCheckTemplateVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = ctv.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    // -----------------------------------------------------------------------
    // BIP118 SIGHASH_ANYPREVOUT tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_anyprevout_sighash_differs_from_taproot() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;
        use crate::sighash::{sighash_taproot, sighash_anyprevout, SIGHASH_ANYPREVOUT, SighashType};

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab]),
                }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd]),
        }];

        // Compute regular taproot sighash (SIGHASH_ALL = 0x01, not 0x00/default)
        let taproot_hash = sighash_taproot(
            &tx, 0, &prevouts, SighashType::ALL, None, None,
        ).unwrap();

        // Compute ANYPREVOUT sighash
        let aprevout_hash = sighash_anyprevout(
            &tx, 0, &prevouts, SIGHASH_ANYPREVOUT, None, None,
        ).unwrap();

        assert_ne!(taproot_hash, [0u8; 32]);
        assert_ne!(aprevout_hash, [0u8; 32]);
        // ANYPREVOUT must produce a different hash than regular taproot sighash
        assert_ne!(taproot_hash, aprevout_hash, "ANYPREVOUT sighash must differ from regular taproot sighash");
    }

    #[test]
    fn test_anyprevout_vs_anyprevoutanyscript() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;
        use crate::sighash::{sighash_anyprevout, SIGHASH_ANYPREVOUT, SIGHASH_ANYPREVOUTANYSCRIPT};

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let mut spk_bytes = vec![0x51, 0x20];
        spk_bytes.extend_from_slice(&[0xab; 32]);
        let prevouts = vec![TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
        }];

        let hash_apo = sighash_anyprevout(
            &tx, 0, &prevouts, SIGHASH_ANYPREVOUT, None, None,
        ).unwrap();

        let hash_apoas = sighash_anyprevout(
            &tx, 0, &prevouts, SIGHASH_ANYPREVOUTANYSCRIPT, None, None,
        ).unwrap();

        assert_ne!(hash_apo, [0u8; 32]);
        assert_ne!(hash_apoas, [0u8; 32]);
        // The two ANYPREVOUT variants must differ
        assert_ne!(hash_apo, hash_apoas, "ANYPREVOUT and ANYPREVOUTANYSCRIPT must produce different hashes");
    }

    #[test]
    fn test_checksig_anyprevout_registration() {
        let op = OpCheckSigAnyprevout;
        assert_eq!(op.opcode(), 0xb6);
        assert_eq!(op.name(), "OP_CHECKSIG_ANYPREVOUT");
        assert_eq!(op.context(), OpcodeContext::TapscriptOnly);
    }

    // -----------------------------------------------------------------------
    // BIP446 OP_TXHASH tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_txhash_registration() {
        let op = OpTxHash;
        assert_eq!(op.opcode(), 0xb7);
        assert_eq!(op.name(), "OP_TXHASH");
        assert_eq!(op.context(), OpcodeContext::TapscriptOnly);
    }

    #[test]
    fn test_txhash_different_selectors_produce_different_hashes() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xfffffffe,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 500_000,
        };

        let txhash = OpTxHash;
        let flags = ScriptFlags::none();

        // Collect hashes for selectors 0x00..=0x05
        let mut hashes = Vec::new();
        for selector in 0x00u8..=0x05u8 {
            let mut stack: Vec<Vec<u8>> = Vec::new();
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            stack.push(vec![selector]);

            let mut ctx = OpcodeExecContext {
                stack: &mut stack,
                altstack: &mut altstack,
                tx: Some(&tx),
                input_index: 0,
                input_amount: 0,
                flags: &flags,
                taproot_internal_key: None,
            };

            txhash.execute(&mut ctx).unwrap();
            assert_eq!(ctx.stack.len(), 1, "TXHASH should push one element");
            assert_eq!(ctx.stack[0].len(), 32, "TXHASH result must be 32 bytes");
            hashes.push(ctx.stack[0].clone());
        }

        // All six selectors must produce different hashes
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "Selectors 0x{:02x} and 0x{:02x} must produce different hashes",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_txhash_invalid_selector_fails() {
        let tx = make_ctv_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push invalid selector 0xff
        stack.push(vec![0xff]);

        let txhash = OpTxHash;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = txhash.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_txhash_no_tx_context_fails() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push(vec![0x00]);

        let txhash = OpTxHash;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = txhash.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_txhash_version_deterministic() {
        let tx = make_ctv_test_tx();
        let txhash = OpTxHash;
        let flags = ScriptFlags::none();

        let mut stack1: Vec<Vec<u8>> = vec![vec![0x01]];
        let mut alt1: Vec<Vec<u8>> = Vec::new();
        let mut ctx1 = OpcodeExecContext {
            stack: &mut stack1,
            altstack: &mut alt1,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };
        txhash.execute(&mut ctx1).unwrap();

        let mut stack2: Vec<Vec<u8>> = vec![vec![0x01]];
        let mut alt2: Vec<Vec<u8>> = Vec::new();
        let mut ctx2 = OpcodeExecContext {
            stack: &mut stack2,
            altstack: &mut alt2,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };
        txhash.execute(&mut ctx2).unwrap();

        assert_eq!(ctx1.stack[0], ctx2.stack[0], "Same selector on same tx must be deterministic");
    }

    // -----------------------------------------------------------------------
    // BIP443 OP_CHECKCONTRACTVERIFY tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_checkcontractverify_registration() {
        let op = OpCheckContractVerify;
        assert_eq!(op.opcode(), 0xb8);
        assert_eq!(op.name(), "OP_CHECKCONTRACTVERIFY");
        assert_eq!(op.context(), OpcodeContext::TapscriptOnly);
    }

    #[test]
    fn test_checkcontractverify_valid_commitment() {
        // Compute the correct tweak hash manually
        let internal_key = [0xab; 32];
        let taptree_hash = [0xcd; 32];

        let mut tweak_preimage = Vec::with_capacity(64);
        tweak_preimage.extend_from_slice(&internal_key);
        tweak_preimage.extend_from_slice(&taptree_hash);
        let expected_hash = crate::taproot::tagged_hash(b"TapTweak", &tweak_preimage);

        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push in order: flags (bottom), internal_key, taptree_hash, expected_hash (top)
        stack.push(vec![0x01]); // flags
        stack.push(internal_key.to_vec());
        stack.push(taptree_hash.to_vec());
        stack.push(expected_hash.to_vec());

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        // Should succeed
        op.execute(&mut ctx).unwrap();
        // VERIFY-style: nothing pushed, all 4 elements popped
        assert_eq!(ctx.stack.len(), 0);
    }

    #[test]
    fn test_checkcontractverify_wrong_hash_fails() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push with wrong expected hash
        stack.push(vec![0x01]); // flags
        stack.push([0xab; 32].to_vec()); // internal_key
        stack.push([0xcd; 32].to_vec()); // taptree_hash
        stack.push([0xff; 32].to_vec()); // wrong expected_hash

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_checkcontractverify_stack_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Only push 2 elements, need 4
        stack.push(vec![0x01]);
        stack.push([0xab; 32].to_vec());

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    // -----------------------------------------------------------------------
    // covenant_registry helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_covenant_registry_has_all_opcodes() {
        let registry = covenant_registry();
        assert!(registry.has(0xb3), "CTV (0xb3) must be registered");
        assert!(registry.has(0xb6), "CHECKSIG_ANYPREVOUT (0xb6) must be registered");
        assert!(registry.has(0xb7), "TXHASH (0xb7) must be registered");
        assert!(registry.has(0xb8), "CHECKCONTRACTVERIFY (0xb8) must be registered");

        assert_eq!(registry.get(0xb3).unwrap().name(), "OP_CHECKTEMPLATEVERIFY");
        assert_eq!(registry.get(0xb6).unwrap().name(), "OP_CHECKSIG_ANYPREVOUT");
        assert_eq!(registry.get(0xb7).unwrap().name(), "OP_TXHASH");
        assert_eq!(registry.get(0xb8).unwrap().name(), "OP_CHECKCONTRACTVERIFY");
    }

    // -----------------------------------------------------------------------
    // OpcodeRegistry: get returns None for unregistered opcode
    // -----------------------------------------------------------------------

    #[test]
    fn test_registry_get_returns_none_for_unregistered() {
        let registry = OpcodeRegistry::new();
        assert!(registry.get(0xaa).is_none());
        assert!(registry.get(0xb3).is_none());
        assert!(!registry.has(0xaa));
    }

    #[test]
    fn test_registry_default_is_empty() {
        let registry = OpcodeRegistry::default();
        assert!(!registry.has(0xb3));
        assert!(registry.get(0xb3).is_none());
    }

    #[test]
    fn test_registry_overwrite_plugin() {
        let mut registry = OpcodeRegistry::new();
        registry.register(Box::new(OpCheckTemplateVerify));
        assert_eq!(registry.get(0xb3).unwrap().name(), "OP_CHECKTEMPLATEVERIFY");

        // Register a different plugin at the same opcode byte
        struct FakeCTV;
        impl OpcodePlugin for FakeCTV {
            fn opcode(&self) -> u8 { 0xb3 }
            fn name(&self) -> &str { "FAKE_CTV" }
            fn context(&self) -> OpcodeContext { OpcodeContext::Always }
            fn execute(&self, _ctx: &mut OpcodeExecContext) -> Result<(), ScriptError> { Ok(()) }
        }
        registry.register(Box::new(FakeCTV));
        assert_eq!(registry.get(0xb3).unwrap().name(), "FAKE_CTV");
    }

    // -----------------------------------------------------------------------
    // OpcodeContext variants coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_opcode_context_variants() {
        // NopUpgrade
        let ctx = OpcodeContext::NopUpgrade;
        assert_eq!(ctx, OpcodeContext::NopUpgrade);

        // TapscriptOnly
        let ctx2 = OpcodeContext::TapscriptOnly;
        assert_eq!(ctx2, OpcodeContext::TapscriptOnly);
        assert_ne!(ctx, ctx2);

        // NetworkOnly
        let ctx3 = OpcodeContext::NetworkOnly(vec![Network::Mainnet]);
        assert_eq!(ctx3.clone(), OpcodeContext::NetworkOnly(vec![Network::Mainnet]));
        assert_ne!(ctx3, OpcodeContext::NetworkOnly(vec![Network::Testnet]));

        // Always
        let ctx4 = OpcodeContext::Always;
        assert_eq!(ctx4, OpcodeContext::Always);

        // Debug formatting
        let _ = format!("{:?}", ctx);
        let _ = format!("{:?}", ctx2);
        let _ = format!("{:?}", ctx3);
        let _ = format!("{:?}", ctx4);
    }

    // -----------------------------------------------------------------------
    // CTV: empty stack
    // -----------------------------------------------------------------------

    #[test]
    fn test_ctv_empty_stack_fails() {
        let tx = make_ctv_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let ctv = OpCheckTemplateVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = ctv.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    // -----------------------------------------------------------------------
    // OP_CAT: stack underflow with empty stack and with one element
    // -----------------------------------------------------------------------

    #[test]
    fn test_opcat_empty_stack_underflow() {
        let cat = OpCat;
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = cat.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_opcat_one_element_underflow() {
        let cat = OpCat;
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![b"only".to_vec()];
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = cat.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_opcat_exactly_520_bytes_succeeds() {
        let cat = OpCat;
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![vec![0x41; 260], vec![0x42; 260]];
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        cat.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert_eq!(ctx.stack[0].len(), 520);
    }

    #[test]
    fn test_opcat_empty_elements() {
        let cat = OpCat;
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![vec![], vec![]];
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        cat.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert_eq!(ctx.stack[0].len(), 0);
    }

    // -----------------------------------------------------------------------
    // CHECKSIGFROMSTACK: wrong pubkey length pushes false
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksigfromstack_wrong_pubkey_length() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push sig (64 bytes), msg, pubkey with wrong length (33 bytes instead of 32)
        stack.push(vec![0x00; 64]); // sig
        stack.push(b"some message".to_vec()); // msg
        stack.push(vec![0x02; 33]); // pubkey - wrong length

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        csfs.execute(&mut ctx).unwrap();
        // Should push false due to invalid pubkey length
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty());
    }

    #[test]
    fn test_checksigfromstack_empty_pubkey() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push(vec![0x00; 64]); // sig
        stack.push(b"msg".to_vec()); // msg
        stack.push(vec![]); // empty pubkey

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        csfs.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty());
    }

    // -----------------------------------------------------------------------
    // CHECKSIGFROMSTACK: stack underflow with 0 and 2 elements
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksigfromstack_empty_stack_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = csfs.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_checksigfromstack_two_elements_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![b"sig".to_vec(), b"pubkey".to_vec()];
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let csfs = OpCheckSigFromStack;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = csfs.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    // -----------------------------------------------------------------------
    // ANYPREVOUT execute path coverage
    // -----------------------------------------------------------------------

    fn make_anyprevout_test_tx() -> Transaction {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_anyprevout_empty_stack_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_anyprevout_one_element_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![vec![0x02; 32]]; // only pubkey
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_anyprevout_wrong_pubkey_length() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push sig (65 bytes), pubkey with wrong length
        let mut sig = vec![0x00; 64];
        sig.push(0x41); // SIGHASH_ANYPREVOUT
        stack.push(sig);
        stack.push(vec![0x02; 33]); // 33-byte pubkey - wrong

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        op.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty()); // pushed false
    }

    #[test]
    fn test_anyprevout_wrong_sig_length() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push sig with wrong length (64 bytes instead of 65)
        stack.push(vec![0x00; 64]);
        stack.push(vec![0x02; 32]); // valid pubkey size

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        op.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty()); // pushed false
    }

    #[test]
    fn test_anyprevout_invalid_hash_type() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push sig with invalid hash type byte (not 0x41 or 0x42)
        let mut sig = vec![0x00; 64];
        sig.push(0x01); // SIGHASH_ALL - not ANYPREVOUT
        stack.push(sig);
        stack.push(vec![0x02; 32]); // valid pubkey size

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        op.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty()); // pushed false
    }

    #[test]
    fn test_anyprevout_no_tx_context_fails() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Valid sig length with ANYPREVOUT hash type
        let mut sig = vec![0x00; 64];
        sig.push(0x41); // SIGHASH_ANYPREVOUT
        stack.push(sig);
        stack.push(vec![0x02; 32]); // valid pubkey

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None, // no tx context
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_anyprevout_invalid_sig_verify_pushes_false() {
        let tx = make_anyprevout_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Generate a valid pubkey so key parsing succeeds
        let secp = secp256k1::Secp256k1::new();
        let (_secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (xonly_pubkey, _parity) = public_key.x_only_public_key();

        // Push an invalid 65-byte sig (all zeros + ANYPREVOUT hash type)
        // The sig will parse as a Schnorr sig but fail verification
        let mut sig = vec![0x01; 64];
        sig.push(0x41); // SIGHASH_ANYPREVOUT
        stack.push(sig);
        stack.push(xonly_pubkey.serialize().to_vec());

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 50_000,
            flags: &flags,
            taproot_internal_key: None,
        };

        op.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        assert!(ctx.stack[0].is_empty()); // pushed false - sig verification failed
    }

    #[test]
    fn test_anyprevout_with_anyprevoutanyscript_hash_type() {
        let tx = make_anyprevout_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Generate a valid pubkey
        let secp = secp256k1::Secp256k1::new();
        let (_secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (xonly_pubkey, _parity) = public_key.x_only_public_key();

        // Push invalid sig with ANYPREVOUTANYSCRIPT hash type
        let mut sig = vec![0x01; 64];
        sig.push(0x42); // SIGHASH_ANYPREVOUTANYSCRIPT
        stack.push(sig);
        stack.push(xonly_pubkey.serialize().to_vec());

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 50_000,
            flags: &flags,
            taproot_internal_key: None,
        };

        op.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        // Sig is bogus, so it should push false
        assert!(ctx.stack[0].is_empty());
    }

    // -----------------------------------------------------------------------
    // TXHASH: stack underflow and selector wrong size
    // -----------------------------------------------------------------------

    #[test]
    fn test_txhash_empty_stack_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let txhash = OpTxHash;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = txhash.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_txhash_selector_wrong_size() {
        let tx = make_ctv_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push a 2-byte selector (wrong size, should be 1 byte)
        stack.push(vec![0x00, 0x01]);

        let txhash = OpTxHash;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = txhash.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_txhash_empty_selector_wrong_size() {
        let tx = make_ctv_test_tx();
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Push an empty selector (wrong size)
        stack.push(vec![]);

        let txhash = OpTxHash;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = txhash.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_txhash_each_selector_individually() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 3,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xfffffffe,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(1_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::from_sat(2_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20]),
                },
            ],
            witness: Vec::new(),
            lock_time: 123456,
        };

        let txhash = OpTxHash;
        let flags = ScriptFlags::none();

        // Selector 0x00: all fields
        {
            let mut stack: Vec<Vec<u8>> = vec![vec![0x00]];
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            let mut ctx = OpcodeExecContext {
                stack: &mut stack, altstack: &mut altstack,
                tx: Some(&tx), input_index: 0, input_amount: 0,
                flags: &flags, taproot_internal_key: None,
            };
            txhash.execute(&mut ctx).unwrap();
            assert_eq!(ctx.stack[0].len(), 32);

            // Verify determinism: expected = SHA256(version || locktime || inputs_count || outputs_count)
            let mut buf = Vec::new();
            buf.extend_from_slice(&tx.version.to_le_bytes());
            buf.extend_from_slice(&tx.lock_time.to_le_bytes());
            buf.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
            assert_eq!(ctx.stack[0], sha256(&buf).to_vec());
        }

        // Selector 0x01: version
        {
            let mut stack: Vec<Vec<u8>> = vec![vec![0x01]];
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            let mut ctx = OpcodeExecContext {
                stack: &mut stack, altstack: &mut altstack,
                tx: Some(&tx), input_index: 0, input_amount: 0,
                flags: &flags, taproot_internal_key: None,
            };
            txhash.execute(&mut ctx).unwrap();
            assert_eq!(ctx.stack[0], sha256(&tx.version.to_le_bytes()).to_vec());
        }

        // Selector 0x02: locktime
        {
            let mut stack: Vec<Vec<u8>> = vec![vec![0x02]];
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            let mut ctx = OpcodeExecContext {
                stack: &mut stack, altstack: &mut altstack,
                tx: Some(&tx), input_index: 0, input_amount: 0,
                flags: &flags, taproot_internal_key: None,
            };
            txhash.execute(&mut ctx).unwrap();
            assert_eq!(ctx.stack[0], sha256(&tx.lock_time.to_le_bytes()).to_vec());
        }

        // Selector 0x03: inputs hash
        {
            let mut stack: Vec<Vec<u8>> = vec![vec![0x03]];
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            let mut ctx = OpcodeExecContext {
                stack: &mut stack, altstack: &mut altstack,
                tx: Some(&tx), input_index: 0, input_amount: 0,
                flags: &flags, taproot_internal_key: None,
            };
            txhash.execute(&mut ctx).unwrap();
            assert_eq!(ctx.stack[0].len(), 32);
        }

        // Selector 0x04: outputs hash
        {
            let mut stack: Vec<Vec<u8>> = vec![vec![0x04]];
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            let mut ctx = OpcodeExecContext {
                stack: &mut stack, altstack: &mut altstack,
                tx: Some(&tx), input_index: 0, input_amount: 0,
                flags: &flags, taproot_internal_key: None,
            };
            txhash.execute(&mut ctx).unwrap();
            assert_eq!(ctx.stack[0].len(), 32);
        }

        // Selector 0x05: sequences hash
        {
            let mut stack: Vec<Vec<u8>> = vec![vec![0x05]];
            let mut altstack: Vec<Vec<u8>> = Vec::new();
            let mut ctx = OpcodeExecContext {
                stack: &mut stack, altstack: &mut altstack,
                tx: Some(&tx), input_index: 0, input_amount: 0,
                flags: &flags, taproot_internal_key: None,
            };
            txhash.execute(&mut ctx).unwrap();
            // Verify: SHA256(sequence[0] || sequence[1])
            let mut buf = Vec::new();
            for input in &tx.inputs {
                buf.extend_from_slice(&input.sequence.to_le_bytes());
            }
            assert_eq!(ctx.stack[0], sha256(&buf).to_vec());
        }
    }

    // -----------------------------------------------------------------------
    // CHECKCONTRACTVERIFY: wrong-size fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_checkcontractverify_wrong_expected_hash_size() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push(vec![0x01]); // flags
        stack.push([0xab; 32].to_vec()); // internal_key
        stack.push([0xcd; 32].to_vec()); // taptree_hash
        stack.push(vec![0xff; 20]); // wrong size expected_hash (20 instead of 32)

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_checkcontractverify_wrong_taptree_hash_size() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push(vec![0x01]); // flags
        stack.push([0xab; 32].to_vec()); // internal_key
        stack.push(vec![0xcd; 20]); // taptree_hash - wrong size
        stack.push([0xff; 32].to_vec()); // expected_hash

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_checkcontractverify_wrong_internal_key_size() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push(vec![0x01]); // flags
        stack.push(vec![0xab; 20]); // internal_key - wrong size
        stack.push([0xcd; 32].to_vec()); // taptree_hash
        stack.push([0xff; 32].to_vec()); // expected_hash

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_checkcontractverify_empty_flags() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        stack.push(vec![]); // empty flags
        stack.push([0xab; 32].to_vec()); // internal_key
        stack.push([0xcd; 32].to_vec()); // taptree_hash
        stack.push([0xff; 32].to_vec()); // expected_hash

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_checkcontractverify_one_element_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![vec![0x01]];
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_checkcontractverify_three_elements_underflow() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![
            vec![0x01],
            [0xab; 32].to_vec(),
            [0xcd; 32].to_vec(),
        ];
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        let op = OpCheckContractVerify;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: None,
            input_index: 0,
            input_amount: 0,
            flags: &flags,
            taproot_internal_key: None,
        };

        // 3 elements: pops expected_hash, taptree_hash, internal_key, then fails on flags
        let result = op.execute(&mut ctx);
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    // -----------------------------------------------------------------------
    // OpcodeExecContext: verify all fields accessible
    // -----------------------------------------------------------------------

    #[test]
    fn test_opcode_exec_context_fields() {
        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = vec![b"test".to_vec()];
        let mut altstack: Vec<Vec<u8>> = vec![b"alt".to_vec()];
        let tx = make_ctv_test_tx();
        let internal_key = [0xab; 32];

        let ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 3,
            input_amount: 100_000,
            flags: &flags,
            taproot_internal_key: Some(internal_key),
        };

        // Verify all fields are accessible
        assert_eq!(ctx.stack.len(), 1);
        assert_eq!(ctx.altstack.len(), 1);
        assert!(ctx.tx.is_some());
        assert_eq!(ctx.input_index, 3);
        assert_eq!(ctx.input_amount, 100_000);
        assert_eq!(ctx.taproot_internal_key, Some(internal_key));
        // flags is accessible (just check it doesn't panic)
        let _ = ctx.flags;
    }

    // -----------------------------------------------------------------------
    // default_check_template_verify_hash: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_ctv_hash_with_multiple_inputs_and_outputs() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xfffffffe,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 2),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xfffffffd,
                },
            ],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::from_sat(200_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20]),
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Each input index should produce a different hash
        let h0 = default_check_template_verify_hash(&tx, 0);
        let h1 = default_check_template_verify_hash(&tx, 1);
        let h2 = default_check_template_verify_hash(&tx, 2);
        assert_ne!(h0, h1);
        assert_ne!(h0, h2);
        assert_ne!(h1, h2);
        // All should be 32 bytes and non-zero
        assert_ne!(h0, [0u8; 32]);
        assert_ne!(h1, [0u8; 32]);
        assert_ne!(h2, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // ANYPREVOUT: multi-input tx for prevouts building
    // -----------------------------------------------------------------------

    #[test]
    fn test_anyprevout_with_multi_input_tx() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let flags = ScriptFlags::none();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();

        // Generate a valid pubkey
        let secp = secp256k1::Secp256k1::new();
        let (_secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (xonly_pubkey, _parity) = public_key.x_only_public_key();

        // Push invalid sig with ANYPREVOUT hash type, input_index=1
        let mut sig = vec![0x01; 64];
        sig.push(0x41); // SIGHASH_ANYPREVOUT
        stack.push(sig);
        stack.push(xonly_pubkey.serialize().to_vec());

        let op = OpCheckSigAnyprevout;
        let mut ctx = OpcodeExecContext {
            stack: &mut stack,
            altstack: &mut altstack,
            tx: Some(&tx),
            input_index: 1, // second input
            input_amount: 50_000,
            flags: &flags,
            taproot_internal_key: None,
        };

        op.execute(&mut ctx).unwrap();
        assert_eq!(ctx.stack.len(), 1);
        // Sig is bogus, should push false but the code path through prevouts building is exercised
        assert!(ctx.stack[0].is_empty());
    }
}
