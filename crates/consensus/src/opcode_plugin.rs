use std::collections::HashMap;
use btc_primitives::network::Network;
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
}
