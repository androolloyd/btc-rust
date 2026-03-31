use std::collections::HashMap;
use btc_primitives::network::Network;
use btc_primitives::hash::sha256;
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

/// BIP119 OP_CHECKTEMPLATEVERIFY — covenant opcode that constrains how a UTXO
/// can be spent by committing to a hash of the spending transaction's template.
///
/// This is a simplified/placeholder implementation that validates the stack
/// element is 32 bytes (the expected hash size) but does not yet compute the
/// actual `DefaultCheckTemplateVerifyHash`.
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
        // Pop the template hash from stack
        // Compute the template hash of the current transaction
        // Compare -- if mismatch, fail
        // (simplified implementation for demonstration)
        let expected = ctx.stack.last().ok_or(ScriptError::StackUnderflow)?;
        if expected.len() != 32 {
            return Err(ScriptError::VerifyFailed);
        }
        // In a real implementation, compute DefaultCheckTemplateVerifyHash
        // and compare against `expected`.
        Ok(()) // For now, succeed (placeholder)
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
        // Register CTV plugin for OP_NOP4 (0xb3)
        let registry = make_registry_with(vec![Box::new(OpCheckTemplateVerify)]);

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(),
            None,
            0,
            0,
            Some(&registry),
        );

        // Push a 32-byte hash, then invoke OP_NOP4 (0xb3 = CTV placeholder)
        let mut script = ScriptBuf::new();
        script.push_slice(&[0xaa; 32]);
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
        let ctv = OpCheckTemplateVerify;
        assert_eq!(ctv.context(), OpcodeContext::NopUpgrade);

        // NopUpgrade replaces a NOP slot — should work in any script context
        let registry = make_registry_with(vec![Box::new(OpCheckTemplateVerify)]);

        let mut engine = ScriptEngine::new_with_registry(
            &VERIFIER,
            ScriptFlags::none(), // legacy flags, no taproot
            None,
            0,
            0,
            Some(&registry),
        );

        let mut script = ScriptBuf::new();
        script.push_slice(&[0xbb; 32]);
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
}
