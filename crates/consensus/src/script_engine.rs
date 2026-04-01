use btc_primitives::script::{Opcode, Script, Instruction};
use btc_primitives::hash::{sha256, sha256d, hash160};
use btc_primitives::transaction::Transaction;
use crate::sig_verify::SignatureVerifier;
use crate::sighash::{sighash_legacy, SighashType};
use crate::opcode_plugin::{OpcodeRegistry, OpcodeExecContext};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("script failed: stack empty at end")]
    EmptyStack,
    #[error("script failed: top of stack is false")]
    EvalFalse,
    #[error("disabled opcode: {0:?}")]
    DisabledOpcode(Opcode),
    #[error("invalid opcode: {0:?}")]
    InvalidOpcode(Opcode),
    #[error("stack overflow")]
    StackOverflow,
    #[error("stack underflow")]
    StackUnderflow,
    #[error("invalid stack operation")]
    InvalidStackOperation,
    #[error("op_return encountered")]
    OpReturn,
    #[error("verify failed")]
    VerifyFailed,
    #[error("equalverify failed")]
    EqualVerifyFailed,
    #[error("checksig failed")]
    CheckSigFailed,
    #[error("unbalanced conditional")]
    UnbalancedConditional,
    #[error("negative locktime")]
    NegativeLocktime,
    #[error("unsatisfied locktime")]
    UnsatisfiedLocktime,
    #[error("push size limit exceeded")]
    PushSizeLimit,
    #[error("op count limit exceeded")]
    OpCountLimit,
    #[error("script size limit exceeded")]
    ScriptSizeLimit,
    #[error("number overflow")]
    NumberOverflow,
    #[error("invalid number encoding")]
    InvalidNumberEncoding,
    #[error("encode error: {0}")]
    Encode(#[from] btc_primitives::encode::EncodeError),
    #[error("sig verify error: {0}")]
    SigVerify(String),
    #[error("sig pushonly: scriptSig contains non-push opcode")]
    SigPushOnly,
    #[error("cleanstack: stack must have exactly one element after execution")]
    CleanStack,
    #[error("null fail: non-empty signature must succeed")]
    NullFail,
    #[error("minimal data: non-minimal push encoding")]
    MinimalData,
    #[error("minimal if: OP_IF/NOTIF argument must be empty or 0x01")]
    MinimalIf,
    #[error("discourage upgradable NOPs")]
    DiscourageUpgradableNops,
}

const MAX_STACK_SIZE: usize = 1000;
const MAX_SCRIPT_SIZE: usize = 10_000;
const MAX_OPS_PER_SCRIPT: usize = 201;
const MAX_PUSH_SIZE: usize = 520;
const MAX_SCRIPT_NUM_LENGTH: usize = 4;

/// Bitcoin Script execution engine
pub struct ScriptEngine<'a> {
    stack: Vec<Vec<u8>>,
    altstack: Vec<Vec<u8>>,
    sig_verifier: &'a dyn SignatureVerifier,
    /// Flags controlling which features are active (for consensus rule changes)
    flags: ScriptFlags,
    /// Transaction being validated (None for standalone script testing)
    tx: Option<&'a Transaction>,
    /// Index of the input being validated
    input_index: usize,
    /// Amount of the input being spent (for segwit/BIP143 sighash)
    input_amount: i64,
    /// Byte offset of the last OP_CODESEPARATOR in the currently executing script
    last_codeseparator_pos: Option<usize>,
    /// Raw bytes of the currently executing script (set during execute())
    script_code_bytes: Vec<u8>,
    /// Optional registry of pluggable opcodes. When set, the engine consults
    /// this registry before returning `InvalidOpcode` (or `DisabledOpcode` if
    /// a plugin overrides a disabled opcode like OP_CAT).
    opcode_registry: Option<&'a OpcodeRegistry>,
    /// Whether we are executing inside a witness script (for MINIMALIF enforcement).
    is_witness_execution: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScriptFlags {
    pub verify_p2sh: bool,
    pub verify_witness: bool,
    pub verify_strictenc: bool,
    pub verify_dersig: bool,
    pub verify_low_s: bool,
    pub verify_nulldummy: bool,
    pub verify_cleanstack: bool,
    pub verify_checklocktimeverify: bool,
    pub verify_checksequenceverify: bool,
    pub verify_taproot: bool,
    pub verify_sigpushonly: bool,
    pub verify_minimaldata: bool,
    pub verify_nullfail: bool,
    pub verify_minimalif: bool,
    pub verify_discourage_upgradable_nops: bool,
    pub verify_discourage_upgradable_witness_program: bool,
    pub verify_const_scriptcode: bool,
}

impl ScriptFlags {
    pub fn all() -> Self {
        ScriptFlags {
            verify_p2sh: true,
            verify_witness: true,
            verify_strictenc: true,
            verify_dersig: true,
            verify_low_s: true,
            verify_nulldummy: true,
            verify_cleanstack: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_taproot: true,
            verify_sigpushonly: true,
            verify_minimaldata: true,
            verify_nullfail: true,
            verify_minimalif: true,
            verify_discourage_upgradable_nops: true,
            verify_discourage_upgradable_witness_program: true,
            verify_const_scriptcode: true,
        }
    }

    pub fn none() -> Self {
        ScriptFlags::default()
    }

    /// Consensus-only flags — what's required for valid blocks.
    /// No policy flags (MINIMALDATA, SIGPUSHONLY, etc.).
    /// Use this for block validation during IBD.
    pub fn consensus() -> Self {
        ScriptFlags {
            verify_p2sh: true,
            verify_witness: true,
            verify_dersig: true,
            verify_nulldummy: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_taproot: true,
            ..ScriptFlags::default()
        }
    }

    /// Core-compliant — consensus + all policy flags that Bitcoin Core enforces.
    /// Use this for mempool acceptance.
    pub fn core_compliant() -> Self {
        ScriptFlags {
            verify_p2sh: true,
            verify_witness: true,
            verify_strictenc: true,
            verify_dersig: true,
            verify_low_s: true,
            verify_nulldummy: true,
            verify_cleanstack: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_taproot: true,
            verify_sigpushonly: true,
            verify_minimaldata: true,
            verify_nullfail: true,
            verify_minimalif: true,
            ..ScriptFlags::default()
        }
    }
}

impl<'a> ScriptEngine<'a> {
    pub fn new(
        sig_verifier: &'a dyn SignatureVerifier,
        flags: ScriptFlags,
        tx: Option<&'a Transaction>,
        input_index: usize,
        input_amount: i64,
    ) -> Self {
        ScriptEngine {
            stack: Vec::new(),
            altstack: Vec::new(),
            sig_verifier,
            flags,
            tx,
            input_index,
            input_amount,
            last_codeseparator_pos: None,
            script_code_bytes: Vec::new(),
            opcode_registry: None,
            is_witness_execution: false,
        }
    }

    /// Create a ScriptEngine with a pluggable opcode registry.
    ///
    /// The registry is consulted when the engine encounters an opcode byte that
    /// would otherwise return `InvalidOpcode` (or `DisabledOpcode` when a
    /// plugin overrides a disabled opcode like OP_CAT).
    pub fn new_with_registry(
        sig_verifier: &'a dyn SignatureVerifier,
        flags: ScriptFlags,
        tx: Option<&'a Transaction>,
        input_index: usize,
        input_amount: i64,
        opcode_registry: Option<&'a OpcodeRegistry>,
    ) -> Self {
        ScriptEngine {
            stack: Vec::new(),
            altstack: Vec::new(),
            sig_verifier,
            flags,
            tx,
            input_index,
            input_amount,
            last_codeseparator_pos: None,
            script_code_bytes: Vec::new(),
            opcode_registry,
            is_witness_execution: false,
        }
    }

    /// Mark this engine as executing a witness script (for MINIMALIF enforcement).
    pub fn set_witness_execution(&mut self, is_witness: bool) {
        self.is_witness_execution = is_witness;
    }

    /// Create a ScriptEngine without transaction context (for standalone script testing).
    /// Signature verification opcodes will fail since there is no transaction to compute
    /// sighash against.
    pub fn new_without_tx(sig_verifier: &'a dyn SignatureVerifier, flags: ScriptFlags) -> Self {
        Self::new(sig_verifier, flags, None, 0, 0)
    }

    /// Execute a script
    pub fn execute(&mut self, script: &Script) -> Result<(), ScriptError> {
        let script_bytes = script.as_bytes();
        if script_bytes.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSizeLimit);
        }

        // Store the raw script bytes for sighash script_code computation
        self.script_code_bytes = script_bytes.to_vec();
        self.last_codeseparator_pos = None;

        let mut op_count = 0;
        let mut exec_stack: Vec<bool> = Vec::new(); // for IF/ELSE/ENDIF
        let executing = |exec_stack: &[bool]| -> bool {
            exec_stack.iter().all(|&b| b)
        };

        // We need to track byte positions as we iterate instructions.
        // Use a manual position tracker alongside the instruction iterator.
        let mut byte_pos: usize = 0;
        for instruction in script.instructions() {
            let instruction = instruction?;
            // Calculate the size of this instruction in bytes
            let _instr_start = byte_pos;
            match &instruction {
                Instruction::PushBytes(data) => {
                    let len = data.len();
                    // Determine the opcode byte used for this push (for MINIMALDATA checking)
                    let push_opcode_byte = script_bytes[_instr_start];
                    if len == 0 {
                        // Could be OP_0 (1 byte) or OP_PUSHDATA1 with len=0 (2 bytes), etc.
                        if push_opcode_byte == Opcode::OP_PUSHDATA1 as u8 {
                            byte_pos += 2; // opcode + length byte
                        } else if push_opcode_byte == Opcode::OP_PUSHDATA2 as u8 {
                            byte_pos += 3; // opcode + 2 length bytes
                        } else if push_opcode_byte == Opcode::OP_PUSHDATA4 as u8 {
                            byte_pos += 5; // opcode + 4 length bytes
                        } else {
                            byte_pos += 1; // OP_0
                        }
                    } else if len <= 75 {
                        byte_pos += 1 + len;
                    } else if len <= 0xff {
                        byte_pos += 2 + len; // OP_PUSHDATA1 + 1 byte len
                    } else if len <= 0xffff {
                        byte_pos += 3 + len; // OP_PUSHDATA2 + 2 byte len
                    } else {
                        byte_pos += 5 + len; // OP_PUSHDATA4 + 4 byte len
                    };

                    if data.len() > MAX_PUSH_SIZE {
                        return Err(ScriptError::PushSizeLimit);
                    }

                    // MINIMALDATA: reject non-minimal push encodings
                    if self.flags.verify_minimaldata && executing(&exec_stack) {
                        if !is_minimal_push(data, push_opcode_byte) {
                            return Err(ScriptError::MinimalData);
                        }
                    }

                    if executing(&exec_stack) {
                        self.push(data.to_vec())?;
                    }
                }
                Instruction::Op(op) => {
                    byte_pos += 1; // opcodes are 1 byte
                    let op = *op;

                    // Conditionals always counted
                    if op as u8 > Opcode::OP_16 as u8 {
                        op_count += 1;
                        if op_count > MAX_OPS_PER_SCRIPT {
                            return Err(ScriptError::OpCountLimit);
                        }
                    }

                    // These opcodes are ALWAYS illegal, even in unexecuted branches
                    match op {
                        Opcode::OP_VERIF | Opcode::OP_VERNOTIF => {
                            return Err(ScriptError::DisabledOpcode(op));
                        }
                        _ => {}
                    }

                    // Handle flow control even when not executing
                    match op {
                        Opcode::OP_IF | Opcode::OP_NOTIF => {
                            let mut val = false;
                            if executing(&exec_stack) {
                                let top = self.pop()?;
                                // MINIMALIF: argument must be empty or exactly 0x01.
                                // Note: in Bitcoin Core, MINIMALIF is only enforced for
                                // segwit scripts. The `verify_minimalif_segwit` flag is set
                                // by the witness execution layer when executing inside a
                                // witness script context.
                                if self.flags.verify_minimalif && self.is_witness_execution {
                                    if !top.is_empty() && top != [0x01] {
                                        return Err(ScriptError::MinimalIf);
                                    }
                                }
                                val = !is_false(&top);
                                if op == Opcode::OP_NOTIF {
                                    val = !val;
                                }
                            }
                            exec_stack.push(val);
                            continue;
                        }
                        Opcode::OP_ELSE => {
                            if exec_stack.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }
                            let last = exec_stack.last_mut().unwrap();
                            *last = !*last;
                            continue;
                        }
                        Opcode::OP_ENDIF => {
                            if exec_stack.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }
                            exec_stack.pop();
                            continue;
                        }
                        _ => {}
                    }

                    // Disabled opcodes are also illegal in unexecuted branches
                    if !executing(&exec_stack) {
                        match op {
                            Opcode::OP_CAT | Opcode::OP_SUBSTR | Opcode::OP_LEFT | Opcode::OP_RIGHT |
                            Opcode::OP_INVERT | Opcode::OP_AND | Opcode::OP_OR | Opcode::OP_XOR |
                            Opcode::OP_2MUL | Opcode::OP_2DIV | Opcode::OP_MUL | Opcode::OP_DIV |
                            Opcode::OP_MOD | Opcode::OP_LSHIFT | Opcode::OP_RSHIFT => {
                                return Err(ScriptError::DisabledOpcode(op));
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // Track OP_CODESEPARATOR position
                    if op == Opcode::OP_CODESEPARATOR {
                        // The script_code starts AFTER the OP_CODESEPARATOR
                        self.last_codeseparator_pos = Some(byte_pos);
                    }

                    self.execute_opcode(op, &mut op_count)?;
                }
            }
        }

        if !exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(())
    }

    /// Get the script code for sighash computation.
    /// If OP_CODESEPARATOR was encountered, this is the subscript starting after
    /// the last OP_CODESEPARATOR. Otherwise, it is the full executing script.
    fn get_script_code(&self) -> Vec<u8> {
        match self.last_codeseparator_pos {
            Some(pos) => self.script_code_bytes[pos..].to_vec(),
            None => self.script_code_bytes.clone(),
        }
    }

    /// Verify a single signature against a public key using the transaction context.
    ///
    /// The signature byte slice must end with a sighash type byte. The preceding
    /// bytes are the DER-encoded ECDSA signature. The sighash is computed using
    /// `sighash_legacy()` over the current script code and the transaction.
    ///
    /// Returns Ok(false) for empty sigs or verification failure,
    /// Ok(true) for valid signature.
    fn verify_signature(&self, sig: &[u8], pubkey: &[u8]) -> Result<bool, ScriptError> {
        // Empty signature always fails (not an error, just false)
        if sig.is_empty() {
            return Ok(false);
        }

        // DERSIG, STRICTENC, or LOW_S all require strict DER encoding
        if self.flags.verify_dersig || self.flags.verify_strictenc || self.flags.verify_low_s {
            let der_sig = &sig[..sig.len() - 1];
            if !is_valid_der_signature(der_sig) {
                return Err(ScriptError::SigVerify("non-strict DER signature".into()));
            }
        }

        // STRICTENC: validate sighash type and pubkey encoding
        if self.flags.verify_strictenc {
            let hash_type_byte = sig[sig.len() - 1];
            if !is_defined_hashtype(hash_type_byte) {
                return Err(ScriptError::SigVerify("undefined hashtype".into()));
            }
            // Also validate pubkey encoding
            if !is_valid_pubkey_encoding(pubkey) {
                return Err(ScriptError::SigVerify("invalid pubkey type".into()));
            }
        }

        // LOW_S: check for low S value
        if self.flags.verify_low_s {
            let der_sig = &sig[..sig.len() - 1];
            if !is_low_der_signature(der_sig) {
                return Err(ScriptError::SigVerify("non-low-S signature".into()));
            }
        }

        // Need transaction context to compute sighash
        let tx = match self.tx {
            Some(tx) => tx,
            None => return Err(ScriptError::SigVerify(
                "no transaction context for signature verification".into()
            )),
        };

        // Last byte of signature is the sighash type
        let hash_type_byte = sig[sig.len() - 1];
        let der_sig = &sig[..sig.len() - 1];

        let hash_type = SighashType::from_u8(hash_type_byte);
        let script_code = self.get_script_code();

        // Compute the sighash
        let sighash = sighash_legacy(tx, self.input_index, &script_code, hash_type)
            .map_err(|e| ScriptError::SigVerify(e.to_string()))?;

        // Verify using the sig_verifier
        match self.sig_verifier.verify_ecdsa(&sighash, der_sig, pubkey) {
            Ok(valid) => Ok(valid),
            Err(_) => Ok(false), // Invalid encoding etc. => treat as false, not error
        }
    }

    /// Check if script succeeded (top of stack is true)
    pub fn success(&self) -> bool {
        if let Some(top) = self.stack.last() {
            !is_false(top)
        } else {
            false
        }
    }

    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    /// Check the CLEANSTACK rule: after script execution succeeds, the stack
    /// must have exactly 1 element. Call this after execute() and success() return OK.
    pub fn check_cleanstack(&self) -> Result<(), ScriptError> {
        if self.flags.verify_cleanstack && self.stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
        Ok(())
    }

    /// Return the flags being used by this engine.
    pub fn flags(&self) -> &ScriptFlags {
        &self.flags
    }

    /// Push an item onto the stack from external code (used for P2SH setup).
    pub fn push_item(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        self.push(data)
    }

    /// Clear the altstack. Called between scriptSig and scriptPubKey execution
    /// since Bitcoin Core does not share the altstack between them.
    pub fn clear_altstack(&mut self) {
        self.altstack.clear();
    }

    /// Pop a value from the stack and decode it as a script number,
    /// enforcing MINIMALDATA if the flag is set.
    fn pop_num(&mut self) -> Result<i64, ScriptError> {
        let data = self.pop()?;
        if self.flags.verify_minimaldata && !is_minimal_script_num(&data) {
            return Err(ScriptError::InvalidNumberEncoding);
        }
        decode_num(&data)
    }

    /// Peek at the top of stack and decode it as a script number,
    /// enforcing MINIMALDATA if the flag is set.
    #[allow(dead_code)]
    fn top_num(&self) -> Result<i64, ScriptError> {
        let data = self.top()?;
        if self.flags.verify_minimaldata && !is_minimal_script_num(data) {
            return Err(ScriptError::InvalidNumberEncoding);
        }
        decode_num(data)
    }

    fn push(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        if self.stack.len() + self.altstack.len() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackOverflow);
        }
        self.stack.push(data);
        Ok(())
    }

    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    fn top(&self) -> Result<&Vec<u8>, ScriptError> {
        self.stack.last().ok_or(ScriptError::StackUnderflow)
    }

    fn execute_opcode(&mut self, op: Opcode, op_count: &mut usize) -> Result<(), ScriptError> {
        match op {
            // Constants
            Opcode::OP_0 => self.push(Vec::new())?,
            Opcode::OP_1NEGATE => self.push(encode_num(-1))?,
            Opcode::OP_1 | Opcode::OP_2 | Opcode::OP_3 | Opcode::OP_4 |
            Opcode::OP_5 | Opcode::OP_6 | Opcode::OP_7 | Opcode::OP_8 |
            Opcode::OP_9 | Opcode::OP_10 | Opcode::OP_11 | Opcode::OP_12 |
            Opcode::OP_13 | Opcode::OP_14 | Opcode::OP_15 | Opcode::OP_16 => {
                let n = (op as u8 - Opcode::OP_1 as u8 + 1) as i64;
                self.push(encode_num(n))?;
            }

            // Flow control
            Opcode::OP_NOP => {}
            Opcode::OP_RETURN => return Err(ScriptError::OpReturn),
            Opcode::OP_VERIFY => {
                let top = self.pop()?;
                if is_false(&top) {
                    return Err(ScriptError::VerifyFailed);
                }
            }

            // Stack operations
            Opcode::OP_DUP => {
                let top = self.top()?.clone();
                self.push(top)?;
            }
            Opcode::OP_DROP => { self.pop()?; }
            Opcode::OP_2DROP => { self.pop()?; self.pop()?; }
            Opcode::OP_2DUP => {
                if self.stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                let a = self.stack[self.stack.len() - 2].clone();
                let b = self.stack[self.stack.len() - 1].clone();
                self.push(a)?;
                self.push(b)?;
            }
            Opcode::OP_3DUP => {
                if self.stack.len() < 3 { return Err(ScriptError::StackUnderflow); }
                let a = self.stack[self.stack.len() - 3].clone();
                let b = self.stack[self.stack.len() - 2].clone();
                let c = self.stack[self.stack.len() - 1].clone();
                self.push(a)?;
                self.push(b)?;
                self.push(c)?;
            }
            Opcode::OP_NIP => {
                if self.stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                let len = self.stack.len();
                self.stack.remove(len - 2);
            }
            Opcode::OP_OVER => {
                if self.stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                let val = self.stack[self.stack.len() - 2].clone();
                self.push(val)?;
            }
            Opcode::OP_SWAP => {
                let len = self.stack.len();
                if len < 2 { return Err(ScriptError::StackUnderflow); }
                self.stack.swap(len - 1, len - 2);
            }
            Opcode::OP_ROT => {
                let len = self.stack.len();
                if len < 3 { return Err(ScriptError::StackUnderflow); }
                let val = self.stack.remove(len - 3);
                self.stack.push(val);
            }
            Opcode::OP_TUCK => {
                if self.stack.len() < 2 { return Err(ScriptError::StackUnderflow); }
                if self.stack.len() + self.altstack.len() >= MAX_STACK_SIZE {
                    return Err(ScriptError::StackOverflow);
                }
                let top = self.stack.last().unwrap().clone();
                let len = self.stack.len();
                self.stack.insert(len - 2, top);
            }
            Opcode::OP_IFDUP => {
                let top = self.top()?.clone();
                if !is_false(&top) {
                    self.push(top)?;
                }
            }
            Opcode::OP_DEPTH => {
                let depth = self.stack.len() as i64;
                self.push(encode_num(depth))?;
            }
            Opcode::OP_TOALTSTACK => {
                let val = self.pop()?;
                self.altstack.push(val);
            }
            Opcode::OP_FROMALTSTACK => {
                let val = self.altstack.pop().ok_or(ScriptError::StackUnderflow)?;
                self.push(val)?;
            }
            Opcode::OP_SIZE => {
                let top = self.top()?;
                let size = top.len() as i64;
                self.push(encode_num(size))?;
            }

            // Bitwise
            Opcode::OP_EQUAL => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if a == b { encode_num(1) } else { encode_num(0) })?;
            }
            Opcode::OP_EQUALVERIFY => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a != b {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }

            // Arithmetic
            Opcode::OP_1ADD => {
                let a = self.pop_num()?;
                self.push(encode_num(a + 1))?;
            }
            Opcode::OP_1SUB => {
                let a = self.pop_num()?;
                self.push(encode_num(a - 1))?;
            }
            Opcode::OP_NEGATE => {
                let a = self.pop_num()?;
                self.push(encode_num(-a))?;
            }
            Opcode::OP_ABS => {
                let a = self.pop_num()?;
                self.push(encode_num(a.abs()))?;
            }
            Opcode::OP_NOT => {
                let a = self.pop_num()?;
                self.push(encode_num(if a == 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_0NOTEQUAL => {
                let a = self.pop_num()?;
                self.push(encode_num(if a != 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_ADD => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(a + b))?;
            }
            Opcode::OP_SUB => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(a - b))?;
            }
            Opcode::OP_BOOLAND => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a != 0 && b != 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_BOOLOR => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a != 0 || b != 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_NUMEQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a == b { 1 } else { 0 }))?;
            }
            Opcode::OP_NUMEQUALVERIFY => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                if a != b {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            Opcode::OP_NUMNOTEQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a != b { 1 } else { 0 }))?;
            }
            Opcode::OP_LESSTHAN => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a < b { 1 } else { 0 }))?;
            }
            Opcode::OP_GREATERTHAN => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a > b { 1 } else { 0 }))?;
            }
            Opcode::OP_LESSTHANOREQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a <= b { 1 } else { 0 }))?;
            }
            Opcode::OP_GREATERTHANOREQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(if a >= b { 1 } else { 0 }))?;
            }
            Opcode::OP_MIN => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(a.min(b)))?;
            }
            Opcode::OP_MAX => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(encode_num(a.max(b)))?;
            }
            Opcode::OP_WITHIN => {
                let max = self.pop_num()?;
                let min = self.pop_num()?;
                let x = self.pop_num()?;
                self.push(encode_num(if x >= min && x < max { 1 } else { 0 }))?;
            }

            // Crypto
            Opcode::OP_RIPEMD160 => {
                let data = self.pop()?;
                let mut hasher = ripemd::Ripemd160::new();
                use ripemd::Digest;
                hasher.update(&data);
                let result: [u8; 20] = hasher.finalize().into();
                self.push(result.to_vec())?;
            }
            Opcode::OP_SHA256 => {
                let data = self.pop()?;
                self.push(sha256(&data).to_vec())?;
            }
            Opcode::OP_HASH160 => {
                let data = self.pop()?;
                self.push(hash160(&data).to_vec())?;
            }
            Opcode::OP_HASH256 => {
                let data = self.pop()?;
                self.push(sha256d(&data).to_vec())?;
            }
            Opcode::OP_CHECKSIG => {
                let pubkey = self.pop()?;
                let sig = self.pop()?;
                let result = self.verify_signature(&sig, &pubkey)?;
                // NULLFAIL: non-empty signature that fails must error
                if !result && !sig.is_empty() && self.flags.verify_nullfail {
                    return Err(ScriptError::NullFail);
                }
                self.push(if result { encode_num(1) } else { encode_num(0) })?;
            }
            Opcode::OP_CHECKSIGVERIFY => {
                let pubkey = self.pop()?;
                let sig = self.pop()?;
                let result = self.verify_signature(&sig, &pubkey)?;
                if !result {
                    // NULLFAIL: non-empty signature that fails must give NULLFAIL error
                    if !sig.is_empty() && self.flags.verify_nullfail {
                        return Err(ScriptError::NullFail);
                    }
                    return Err(ScriptError::CheckSigFailed);
                }
            }

            // Timelock
            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                if !self.flags.verify_checklocktimeverify {
                    // Treat as NOP
                } else {
                    // CLTV uses 5-byte numbers (BIP65)
                    let data = self.top()?;
                    if self.flags.verify_minimaldata && !is_minimal_script_num(data) {
                        return Err(ScriptError::InvalidNumberEncoding);
                    }
                    let locktime = decode_num_ext(data, 5)?;
                    if locktime < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if let Some(tx) = self.tx {
                        let tx_locktime = tx.lock_time as i64;
                        // Both must be same type (block height < 500M, or timestamp >= 500M)
                        if (locktime < 500_000_000 && tx_locktime >= 500_000_000)
                            || (locktime >= 500_000_000 && tx_locktime < 500_000_000)
                        {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                        if locktime > tx_locktime {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                        // Check sequence is not SEQUENCE_FINAL (disabled)
                        if self.input_index < tx.inputs.len()
                            && tx.inputs[self.input_index].sequence == 0xffffffff
                        {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }
            }
            Opcode::OP_CHECKSEQUENCEVERIFY => {
                if !self.flags.verify_checksequenceverify {
                    // Treat as NOP
                } else {
                    // CSV uses 5-byte numbers (BIP112)
                    let data = self.top()?;
                    if self.flags.verify_minimaldata && !is_minimal_script_num(data) {
                        return Err(ScriptError::InvalidNumberEncoding);
                    }
                    let sequence = decode_num_ext(data, 5)?;
                    if sequence < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    } else {
                        let sequence = sequence as u32;
                        if sequence & (1 << 31) != 0 {
                            // disabled flag = NOP behavior
                        } else if let Some(tx) = self.tx {
                            if tx.version < 2 {
                                return Err(ScriptError::UnsatisfiedLocktime);
                            }
                            if self.input_index < tx.inputs.len() {
                                let tx_seq = tx.inputs[self.input_index].sequence;
                                if tx_seq & (1 << 31) != 0 {
                                    return Err(ScriptError::UnsatisfiedLocktime);
                                }
                                // Compare type flags (bit 22)
                                if (sequence & (1 << 22)) != (tx_seq & (1 << 22)) {
                                    return Err(ScriptError::UnsatisfiedLocktime);
                                }
                                // Compare masked 16-bit values
                                if (sequence & 0xffff) > (tx_seq & 0xffff) {
                                    return Err(ScriptError::UnsatisfiedLocktime);
                                }
                            }
                        }
                    }
                }
            }

            // NOPs (soft-fork safe) — if a plugin is registered, delegate to it;
            // otherwise treat as NOP (the original behavior).
            Opcode::OP_NOP1 | Opcode::OP_NOP4 | Opcode::OP_NOP5 |
            Opcode::OP_NOP6 | Opcode::OP_NOP7 | Opcode::OP_NOP8 |
            Opcode::OP_NOP9 | Opcode::OP_NOP10 => {
                if let Some(registry) = self.opcode_registry {
                    if let Some(plugin) = registry.get(op.to_u8()) {
                        let mut ctx = OpcodeExecContext {
                            stack: &mut self.stack,
                            altstack: &mut self.altstack,
                            tx: self.tx,
                            input_index: self.input_index,
                            input_amount: self.input_amount,
                            flags: &self.flags,
                            taproot_internal_key: None,
                        };
                        plugin.execute(&mut ctx)?;
                    } else if self.flags.verify_discourage_upgradable_nops {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                } else if self.flags.verify_discourage_upgradable_nops {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
                // If no plugin registered and flag not set, silently succeed (NOP behavior)
            }

            // Disabled opcodes — if a plugin overrides one (e.g. OP_CAT in
            // tapscript), delegate to the plugin instead of failing.
            Opcode::OP_CAT | Opcode::OP_SUBSTR | Opcode::OP_LEFT | Opcode::OP_RIGHT |
            Opcode::OP_INVERT | Opcode::OP_AND | Opcode::OP_OR | Opcode::OP_XOR |
            Opcode::OP_2MUL | Opcode::OP_2DIV | Opcode::OP_MUL | Opcode::OP_DIV |
            Opcode::OP_MOD | Opcode::OP_LSHIFT | Opcode::OP_RSHIFT => {
                if let Some(registry) = self.opcode_registry {
                    if let Some(plugin) = registry.get(op.to_u8()) {
                        let mut ctx = OpcodeExecContext {
                            stack: &mut self.stack,
                            altstack: &mut self.altstack,
                            tx: self.tx,
                            input_index: self.input_index,
                            input_amount: self.input_amount,
                            flags: &self.flags,
                            taproot_internal_key: None,
                        };
                        return plugin.execute(&mut ctx);
                    }
                }
                return Err(ScriptError::DisabledOpcode(op));
            }

            // Pick/Roll
            Opcode::OP_PICK => {
                let n_val = self.pop_num()?;
                if n_val < 0 { return Err(ScriptError::InvalidStackOperation); }
                let n = n_val as usize;
                if n >= self.stack.len() { return Err(ScriptError::StackUnderflow); }
                let val = self.stack[self.stack.len() - 1 - n].clone();
                self.push(val)?;
            }
            Opcode::OP_ROLL => {
                let n_val = self.pop_num()?;
                if n_val < 0 { return Err(ScriptError::InvalidStackOperation); }
                let n = n_val as usize;
                if n >= self.stack.len() { return Err(ScriptError::StackUnderflow); }
                let idx = self.stack.len() - 1 - n;
                let val = self.stack.remove(idx);
                self.stack.push(val);
            }

            Opcode::OP_2OVER => {
                if self.stack.len() < 4 { return Err(ScriptError::StackUnderflow); }
                let a = self.stack[self.stack.len() - 4].clone();
                let b = self.stack[self.stack.len() - 3].clone();
                self.push(a)?;
                self.push(b)?;
            }
            Opcode::OP_2ROT => {
                if self.stack.len() < 6 { return Err(ScriptError::StackUnderflow); }
                let len = self.stack.len();
                let a = self.stack.remove(len - 6);
                let b = self.stack.remove(len - 6); // shifted after removal
                self.stack.push(a);
                self.stack.push(b);
            }
            Opcode::OP_2SWAP => {
                let len = self.stack.len();
                if len < 4 { return Err(ScriptError::StackUnderflow); }
                self.stack.swap(len - 4, len - 2);
                self.stack.swap(len - 3, len - 1);
            }

            Opcode::OP_SHA1 => {
                // SHA1 is deprecated/weak but required for consensus
                let data = self.pop()?;
                use sha1::Digest;
                let mut hasher = sha1::Sha1::new();
                hasher.update(&data);
                let result: [u8; 20] = hasher.finalize().into();
                self.push(result.to_vec())?;
            }

            Opcode::OP_CODESEPARATOR => {
                // Position tracking is handled in execute() above
            }

            Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY => {
                // Pop number of keys
                let n_keys_val = self.pop_num()?;
                if n_keys_val < 0 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let n_keys = n_keys_val as usize;
                if n_keys > 20 {
                    return Err(ScriptError::InvalidStackOperation);
                }

                // BIP consensus: n_keys counts toward the 201-op limit
                *op_count += n_keys;
                if *op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCountLimit);
                }

                // Pop public keys
                let mut pubkeys = Vec::with_capacity(n_keys);
                for _ in 0..n_keys {
                    pubkeys.push(self.pop()?);
                }

                // Pop number of sigs
                let n_sigs_val = self.pop_num()?;
                if n_sigs_val < 0 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let n_sigs = n_sigs_val as usize;
                if n_sigs > n_keys {
                    return Err(ScriptError::InvalidStackOperation);
                }

                // Pop signatures
                let mut sigs = Vec::with_capacity(n_sigs);
                for _ in 0..n_sigs {
                    sigs.push(self.pop()?);
                }

                // Pop dummy element (off-by-one bug compatibility with Bitcoin Core)
                let dummy = self.pop()?;

                // BIP147: NULLDUMMY enforcement — the dummy element must be
                // empty when the NULLDUMMY flag is set.
                if self.flags.verify_nulldummy && !dummy.is_empty() {
                    return Err(ScriptError::VerifyFailed);
                }

                // Verify signatures: each signature must match a public key, and
                // keys must be consumed in order (a key used for one sig cannot be
                // reused for a later sig).
                //
                // This matches Bitcoin Core's CHECKMULTISIG loop structure:
                // for each sig, try keys in sequence. After each key is tried,
                // check if there are enough remaining keys for remaining sigs.
                // Exit early if not.
                let mut key_idx = 0;
                let mut sig_idx = 0;
                let mut success = true;
                let mut n_sigs_remaining = n_sigs;
                let mut n_keys_remaining = n_keys;

                while success && n_sigs_remaining > 0 {
                    let sig = &sigs[sig_idx];

                    if sig.is_empty() {
                        // Empty signatures always fail
                        success = false;
                        break;
                    }

                    let result = self.verify_signature(sig, &pubkeys[key_idx])?;
                    if result {
                        sig_idx += 1;
                        n_sigs_remaining -= 1;
                    }

                    key_idx += 1;
                    n_keys_remaining -= 1;

                    // Early exit: not enough remaining keys for remaining sigs
                    if n_sigs_remaining > n_keys_remaining {
                        success = false;
                    }
                }

                // NULLFAIL: if verification failed, check if any sig was non-empty
                if !success && self.flags.verify_nullfail {
                    for sig in &sigs {
                        if !sig.is_empty() {
                            return Err(ScriptError::NullFail);
                        }
                    }
                }

                if op == Opcode::OP_CHECKMULTISIG {
                    self.push(if success { encode_num(1) } else { encode_num(0) })?;
                } else {
                    // CHECKMULTISIGVERIFY
                    if !success {
                        return Err(ScriptError::CheckSigFailed);
                    }
                }
            }

            _ => {
                if let Some(registry) = self.opcode_registry {
                    if let Some(plugin) = registry.get(op.to_u8()) {
                        let mut ctx = OpcodeExecContext {
                            stack: &mut self.stack,
                            altstack: &mut self.altstack,
                            tx: self.tx,
                            input_index: self.input_index,
                            input_amount: self.input_amount,
                            flags: &self.flags,
                            taproot_internal_key: None,
                        };
                        plugin.execute(&mut ctx)?;
                    } else {
                        return Err(ScriptError::InvalidOpcode(op));
                    }
                } else {
                    return Err(ScriptError::InvalidOpcode(op));
                }
            }
        }
        Ok(())
    }
}

/// Encode a number as script number (little-endian with sign bit)
pub fn encode_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }

    let negative = n < 0;
    let mut abs = n.unsigned_abs();
    let mut result = Vec::new();

    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // If the most significant byte has the high bit set, add a sign byte
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}

/// Decode a script number (default 4-byte limit)
pub fn decode_num(data: &[u8]) -> Result<i64, ScriptError> {
    decode_num_ext(data, MAX_SCRIPT_NUM_LENGTH)
}

/// Decode a script number with a configurable maximum size.
/// Used for CLTV and CSV which accept 5-byte numbers.
pub fn decode_num_ext(data: &[u8], max_len: usize) -> Result<i64, ScriptError> {
    if data.is_empty() {
        return Ok(0);
    }

    if data.len() > max_len {
        return Err(ScriptError::NumberOverflow);
    }

    let negative = data.last().unwrap() & 0x80 != 0;
    let mut result: i64 = 0;

    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    // Remove the sign bit
    if negative {
        result &= !(0x80i64 << (8 * (data.len() - 1)));
        result = -result;
    }

    Ok(result)
}

/// Check if a script number encoding is minimal.
/// Returns true if the encoding is the shortest possible representation.
pub fn is_minimal_script_num(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // If the last byte is 0x00 and the second-to-last byte does NOT have
    // the high bit set, then the number could be encoded with fewer bytes.
    // (The 0x00 padding byte is unnecessary.)
    if data.last() == Some(&0x00) && (data.len() < 2 || data[data.len() - 2] & 0x80 == 0) {
        return false;
    }
    // If the last byte is 0x80 and the second-to-last byte does NOT have
    // the high bit set, then we have unnecessary negative-zero padding.
    if data.last() == Some(&0x80) && (data.len() < 2 || data[data.len() - 2] & 0x80 == 0) {
        return false;
    }
    true
}

/// Check if a DER-encoded ECDSA signature is strictly valid (BIP66).
/// This validates the DER encoding only — NOT the signature itself.
fn is_valid_der_signature(sig: &[u8]) -> bool {
    // Minimum DER signature: 30 06 02 01 R 02 01 S
    if sig.len() < 8 { return false; }
    if sig.len() > 72 { return false; }

    // Compound type tag
    if sig[0] != 0x30 { return false; }

    // Total length should cover the rest
    let total_len = sig[1] as usize;
    if total_len + 2 != sig.len() { return false; }

    // First element: R integer
    if sig[2] != 0x02 { return false; }
    let r_len = sig[3] as usize;
    if r_len == 0 { return false; }
    if 4 + r_len >= sig.len() { return false; }

    // Check R is not negative (high bit set without padding byte)
    if sig[4] & 0x80 != 0 { return false; }
    // Check R has no excess padding
    if r_len > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 { return false; }

    // Second element: S integer
    let s_pos = 4 + r_len;
    if s_pos >= sig.len() { return false; }
    if sig[s_pos] != 0x02 { return false; }
    if s_pos + 1 >= sig.len() { return false; }
    let s_len = sig[s_pos + 1] as usize;
    if s_len == 0 { return false; }
    if s_pos + 2 + s_len != sig.len() { return false; }

    // Check S is not negative
    if sig[s_pos + 2] & 0x80 != 0 { return false; }
    // Check S has no excess padding
    if s_len > 1 && sig[s_pos + 2] == 0 && sig[s_pos + 3] & 0x80 == 0 { return false; }

    true
}

/// Check if a DER signature has low S value (BIP62 rule 5).
/// S must be <= order/2.
fn is_low_der_signature(sig: &[u8]) -> bool {
    if !is_valid_der_signature(sig) { return false; }

    // Extract S value
    let r_len = sig[3] as usize;
    let s_pos = 4 + r_len;
    let s_len = sig[s_pos + 1] as usize;
    let s_bytes = &sig[s_pos + 2..s_pos + 2 + s_len];

    // secp256k1 half-order (order/2):
    // 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    let half_order: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
    ];

    // Pad S to 32 bytes for comparison
    let mut s_padded = [0u8; 32];
    if s_bytes.len() > 32 { return false; }
    let offset = 32 - s_bytes.len();
    s_padded[offset..].copy_from_slice(s_bytes);

    // S must be <= half_order
    s_padded <= half_order
}

/// Check if the hashtype byte is one of the defined types (STRICTENC).
fn is_defined_hashtype(hash_type: u8) -> bool {
    let base = hash_type & 0x1f;
    let rest = hash_type & !0x9f; // bits besides base and ANYONECANPAY
    if rest != 0 { return false; }
    matches!(base, 1 | 2 | 3) // ALL, NONE, SINGLE
}

/// Check if a public key has valid encoding (STRICTENC).
/// Valid encodings: compressed (02/03 + 32 bytes) or uncompressed (04 + 64 bytes).
/// Hybrid keys (06/07) are NOT valid under STRICTENC.
fn is_valid_pubkey_encoding(pubkey: &[u8]) -> bool {
    if pubkey.is_empty() { return false; }
    match pubkey[0] {
        0x02 | 0x03 => pubkey.len() == 33,
        0x04 => pubkey.len() == 65,
        _ => false, // 0x06, 0x07 (hybrid) and others are invalid
    }
}

/// Check if a script contains only push operations (no opcodes > OP_16 except push data ops).
/// Used for SIGPUSHONLY enforcement.
pub fn is_push_only(script: &Script) -> bool {
    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::PushBytes(_)) => {} // push data is OK
            Ok(Instruction::Op(op)) => {
                // OP_0 (0x00) through OP_16 (0x60) are push-value opcodes
                // OP_1NEGATE (0x4f) is also a push-value opcode
                // OP_RESERVED (0x50) is NOT a push opcode
                let b = op as u8;
                if b > Opcode::OP_16 as u8 {
                    return false;
                }
                // OP_RESERVED (0x50) is between OP_1NEGATE and OP_1 — it is NOT push-only
                if op == Opcode::OP_RESERVED {
                    return false;
                }
            }
            Err(_) => return false, // parse error
        }
    }
    true
}

/// Check if a push encoding is minimal (MINIMALDATA enforcement).
/// Returns true if the encoding is minimal, false otherwise.
fn is_minimal_push(data: &[u8], opcode_byte: u8) -> bool {
    let len = data.len();
    if len == 0 {
        // Should have used OP_0
        return opcode_byte == Opcode::OP_0 as u8;
    }
    if len == 1 {
        let val = data[0];
        if val >= 1 && val <= 16 {
            // Should have used OP_1 through OP_16
            return opcode_byte == (Opcode::OP_1 as u8 + val - 1);
        }
        if val == 0x81 {
            // Should have used OP_1NEGATE
            return opcode_byte == Opcode::OP_1NEGATE as u8;
        }
    }
    if len <= 75 {
        // Should have used a direct push (opcode = length)
        return opcode_byte == len as u8;
    }
    if len <= 255 {
        // Should have used OP_PUSHDATA1
        return opcode_byte == Opcode::OP_PUSHDATA1 as u8;
    }
    if len <= 65535 {
        // Should have used OP_PUSHDATA2
        return opcode_byte == Opcode::OP_PUSHDATA2 as u8;
    }
    true
}

/// Check if a stack element represents false (empty or all zeros, or negative zero)
fn is_false(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Negative zero: only the last byte can be 0x80 with rest zeros
            if i == data.len() - 1 && byte == 0x80 {
                return true;
            }
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig_verify::Secp256k1Verifier;
    use btc_primitives::script::{ScriptBuf, Opcode};

    fn make_engine() -> ScriptEngine<'static> {
        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none())
    }

    #[test]
    fn test_op_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        engine.execute(script.as_script()).unwrap();
        assert!(!engine.success());
    }

    #[test]
    fn test_op_add() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_ADD);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_EQUAL);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_dup_hash160_equalverify() {
        let mut engine = make_engine();
        // Simulate P2PKH unlocking: push data, dup, hash160, push expected hash, equalverify
        let data = b"test pubkey";
        let expected_hash = btc_primitives::hash::hash160(data);

        let mut script = ScriptBuf::new();
        script.push_slice(data);
        script.push_opcode(Opcode::OP_DUP);
        script.push_opcode(Opcode::OP_HASH160);
        script.push_slice(&expected_hash);
        script.push_opcode(Opcode::OP_EQUALVERIFY);
        // After equalverify, the original data remains, which is truthy
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_return_fails() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_RETURN);
        assert!(engine.execute(script.as_script()).is_err());
    }

    #[test]
    fn test_op_if_else_endif() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1); // true
        script.push_opcode(Opcode::OP_IF);
        script.push_opcode(Opcode::OP_2); // push 2 if true
        script.push_opcode(Opcode::OP_ELSE);
        script.push_opcode(Opcode::OP_3); // push 3 if false
        script.push_opcode(Opcode::OP_ENDIF);
        engine.execute(script.as_script()).unwrap();
        let top = decode_num(engine.stack().last().unwrap()).unwrap();
        assert_eq!(top, 2);
    }

    #[test]
    fn test_encode_decode_num() {
        assert_eq!(encode_num(0), Vec::<u8>::new());
        assert_eq!(decode_num(&[]).unwrap(), 0);

        assert_eq!(encode_num(1), vec![0x01u8]);
        assert_eq!(decode_num(&[0x01]).unwrap(), 1);

        assert_eq!(encode_num(-1), vec![0x81u8]);
        assert_eq!(decode_num(&[0x81]).unwrap(), -1);

        assert_eq!(encode_num(127), vec![0x7fu8]);
        assert_eq!(encode_num(128), vec![0x80u8, 0x00]);
        assert_eq!(encode_num(-128), vec![0x80u8, 0x80]);

        assert_eq!(encode_num(255), vec![0xffu8, 0x00]);
        assert_eq!(encode_num(256), vec![0x00u8, 0x01]);
    }

    #[test]
    fn test_is_false() {
        assert!(is_false(&[]));
        assert!(is_false(&[0x00]));
        assert!(is_false(&[0x00, 0x00]));
        assert!(is_false(&[0x80])); // negative zero
        assert!(!is_false(&[0x01]));
        assert!(!is_false(&[0x00, 0x01]));
    }

    #[test]
    fn test_disabled_opcodes() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_CAT);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::DisabledOpcode(Opcode::OP_CAT))));
    }

    // --- Helper for signature verification tests ---

    use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
    use btc_primitives::hash::TxHash;
    use btc_primitives::amount::Amount;

    /// Create a simple test transaction. Signature creation is done separately
    /// since the sighash depends on the script_code, which is the full script
    /// being executed by the engine.
    fn make_test_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    /// Sign a sighash with the given key and return the DER sig + hashtype byte.
    fn sign_sighash(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        secret_key: &secp256k1::SecretKey,
        sighash: &[u8; 32],
    ) -> Vec<u8> {
        use crate::sighash::SighashType;
        let message = secp256k1::Message::from_digest(*sighash);
        let sig = secp.sign_ecdsa(&message, secret_key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(SighashType::ALL.0 as u8);
        sig_bytes
    }

    #[test]
    fn test_checksig_real_signature() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pubkey_bytes = public_key.serialize().to_vec();

        let tx = make_test_tx();

        // We need to know the full script to compute sighash, but the full script
        // contains the signature which we haven't computed yet. To break the
        // circular dependency, we pre-compute the script_code as the full script
        // bytes with a placeholder signature of the expected length, then sign
        // that. But actually, the simpler approach: compute sighash over the
        // full_script bytes. Since the DER sig length can vary, we build the
        // full_script first with a dummy sig, compute its size, then use a
        // two-pass approach.
        //
        // Alternatively, the correct approach for Bitcoin: the script_code is
        // the executed script (full_script), and sighash is computed over it.
        // We can pre-build the full_script with a placeholder, compute sighash,
        // sign, rebuild, and the sighash will match because sighash_legacy strips
        // the signature from script_code via FindAndDelete.
        //
        // Actually, in Bitcoin consensus, the sighash computation does NOT
        // FindAndDelete the signature from the script_code. It only strips
        // OP_CODESEPARATOR. The script_code IS the full executing script.
        //
        // For a simple test, let's just compute sighash over the known full_script:
        // <sig> <pubkey> OP_CHECKSIG. Since we don't know sig yet, we sign over
        // the script without the sig push. This works because the engine's
        // script_code_bytes is set to the full script INCLUDING the sig push,
        // but the sighash is also computed over that same data.
        //
        // The simplest correct approach: use the FULL script as script_code.
        // Build it, compute sighash, sign, rebuild. Since DER sig length may vary,
        // do two passes. In practice, we just build with a fixed-length dummy.

        // Build full_script to get its bytes for sighash
        // But we have a chicken-and-egg: sig is part of script, sighash is over script.
        // Solution: compute sighash over the full_script bytes, which includes the sig.
        // Since we don't have the sig yet, we use a fixed placeholder of the same length.

        // Actually, the cleanest test approach: sign the sighash over just the
        // pubkey-script portion (what would be the scriptPubKey in real Bitcoin).
        // Then in the engine, the script_code_bytes is the full combined script.
        // The sighash won't match because the engine computes it over full_script.
        //
        // The real fix: in actual Bitcoin, scriptSig and scriptPubKey are executed
        // separately. The engine's script_code_bytes should be set when executing
        // the scriptPubKey, not the scriptSig. Let's test by executing the scripts
        // in two phases: first execute scriptSig (push sig), then execute scriptPubKey.

        // Phase 1: Build scriptSig (just pushes) and scriptPubKey separately
        // scriptPubKey: <pubkey> OP_CHECKSIG
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_slice(&pubkey_bytes);
        script_pubkey.push_opcode(Opcode::OP_CHECKSIG);

        // Compute sighash using the scriptPubKey as script_code
        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig_bytes = sign_sighash(&secp, &secret_key, &sighash);

        // scriptSig: <sig>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig_bytes);

        // Execute in two phases (as Bitcoin does)
        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        // Phase 1: execute scriptSig (pushes sig onto stack)
        engine.execute(script_sig.as_script()).unwrap();
        // Phase 2: execute scriptPubKey (pops sig+pubkey, verifies)
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "OP_CHECKSIG should succeed with valid signature");
    }

    #[test]
    fn test_checksig_wrong_key_fails() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (secret_key, _public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (_other_secret, other_public) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let wrong_pubkey_bytes = other_public.serialize().to_vec();

        let tx = make_test_tx();

        // scriptPubKey with wrong key: <wrong_pubkey> OP_CHECKSIG
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_slice(&wrong_pubkey_bytes);
        script_pubkey.push_opcode(Opcode::OP_CHECKSIG);

        // Sign using the script_pubkey as script_code (same as engine will use)
        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig_bytes = sign_sighash(&secp, &secret_key, &sighash);

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(!engine.success(), "OP_CHECKSIG should fail with wrong public key");
    }

    #[test]
    fn test_checksigverify_real_signature() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pubkey_bytes = public_key.serialize().to_vec();

        let tx = make_test_tx();

        // scriptPubKey: <pubkey> OP_CHECKSIGVERIFY OP_1
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_slice(&pubkey_bytes);
        script_pubkey.push_opcode(Opcode::OP_CHECKSIGVERIFY);
        script_pubkey.push_opcode(Opcode::OP_1);

        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig_bytes = sign_sighash(&secp, &secret_key, &sighash);

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "OP_CHECKSIGVERIFY should pass with valid sig");
    }

    #[test]
    fn test_checksigverify_wrong_key_errors() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (secret_key, _public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (_other_secret, other_public) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let wrong_pubkey_bytes = other_public.serialize().to_vec();

        let tx = make_test_tx();

        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_slice(&wrong_pubkey_bytes);
        script_pubkey.push_opcode(Opcode::OP_CHECKSIGVERIFY);

        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig_bytes = sign_sighash(&secp, &secret_key, &sighash);

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        let result = engine.execute(script_pubkey.as_script());
        assert!(matches!(result, Err(ScriptError::CheckSigFailed)),
            "OP_CHECKSIGVERIFY with wrong key should return CheckSigFailed");
    }

    #[test]
    fn test_checkmultisig_2_of_3() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();

        // Generate 3 keypairs
        let (sk1, pk1) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (sk2, pk2) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (_sk3, pk3) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());

        let pk1_bytes = pk1.serialize().to_vec();
        let pk2_bytes = pk2.serialize().to_vec();
        let pk3_bytes = pk3.serialize().to_vec();

        // Build scriptPubKey: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_opcode(Opcode::OP_2);
        script_pubkey.push_slice(&pk1_bytes);
        script_pubkey.push_slice(&pk2_bytes);
        script_pubkey.push_slice(&pk3_bytes);
        script_pubkey.push_opcode(Opcode::OP_3);
        script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute sighash using the scriptPubKey as script_code
        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();

        let sig1_bytes = sign_sighash(&secp, &sk1, &sighash);
        let sig2_bytes = sign_sighash(&secp, &sk2, &sighash);

        // Build scriptSig: OP_0 <sig1> <sig2>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_0); // dummy for off-by-one bug
        script_sig.push_slice(&sig1_bytes);
        script_sig.push_slice(&sig2_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        // Phase 1: execute scriptSig (pushes dummy + sigs)
        engine.execute(script_sig.as_script()).unwrap();
        // Phase 2: execute scriptPubKey (pops and verifies)
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "2-of-3 OP_CHECKMULTISIG should succeed");
    }

    #[test]
    fn test_checkmultisig_wrong_sigs_fails() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();

        // Generate 3 keypairs, but sign with key3 and key2 in wrong order
        let (_sk1, pk1) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (sk2, pk2) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let (sk3, pk3) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());

        let pk1_bytes = pk1.serialize().to_vec();
        let pk2_bytes = pk2.serialize().to_vec();
        let pk3_bytes = pk3.serialize().to_vec();

        // scriptPubKey: 2-of-3 multisig
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_opcode(Opcode::OP_2);
        script_pubkey.push_slice(&pk1_bytes);
        script_pubkey.push_slice(&pk2_bytes);
        script_pubkey.push_slice(&pk3_bytes);
        script_pubkey.push_opcode(Opcode::OP_3);
        script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();

        // Sign with sk3 and sk2, but provide them in wrong order (sig3 first, then sig2).
        // sig3 matches pk3 (index 2), consuming all keys. sig2 has no key left -> fails.
        let sig3_bytes = sign_sighash(&secp, &sk3, &sighash);
        let sig2_bytes = sign_sighash(&secp, &sk2, &sighash);

        // scriptSig: OP_0 <sig3> <sig2> (wrong order)
        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_0);
        script_sig.push_slice(&sig3_bytes);
        script_sig.push_slice(&sig2_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(!engine.success(), "2-of-3 CHECKMULTISIG with out-of-order sigs should fail");
    }

    #[test]
    fn test_checksig_no_tx_context_errors() {
        // Using new_without_tx should error on OP_CHECKSIG
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        // Push some dummy sig and pubkey
        script.push_slice(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]); // dummy sig + hashtype
        script.push_slice(&[0x02; 33]); // dummy pubkey
        script.push_opcode(Opcode::OP_CHECKSIG);
        let result = engine.execute(script.as_script());
        assert!(result.is_err(), "OP_CHECKSIG without tx context should error");
    }

    // ========== Stack operation tests ==========

    #[test]
    fn test_op_drop() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_DROP);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(engine.stack().len(), 1);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 2);
    }

    #[test]
    fn test_op_2drop() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_2DROP);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(engine.stack().len(), 1);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_2dup() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_2DUP);
        engine.execute(script.as_script()).unwrap();
        // Stack should be [4, 5, 4, 5]
        assert_eq!(engine.stack().len(), 4);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 5);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[3]).unwrap(), 5);
    }

    #[test]
    fn test_op_3dup() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_3DUP);
        engine.execute(script.as_script()).unwrap();
        // Stack should be [3, 4, 5, 3, 4, 5]
        assert_eq!(engine.stack().len(), 6);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 5);
        assert_eq!(decode_num(&engine.stack()[3]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[4]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[5]).unwrap(), 5);
    }

    #[test]
    fn test_op_nip() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_NIP);
        engine.execute(script.as_script()).unwrap();
        // NIP removes second-to-top, leaving [3]
        assert_eq!(engine.stack().len(), 1);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 3);
    }

    #[test]
    fn test_op_over() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_OVER);
        engine.execute(script.as_script()).unwrap();
        // OVER copies second-to-top to top: [2, 3, 2]
        assert_eq!(engine.stack().len(), 3);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 2);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 2);
    }

    #[test]
    fn test_op_swap() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_SWAP);
        engine.execute(script.as_script()).unwrap();
        // Stack should be [3, 2]
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 2);
        assert_eq!(decode_num(&engine.stack()[engine.stack().len() - 2]).unwrap(), 3);
    }

    #[test]
    fn test_op_rot() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_ROT);
        engine.execute(script.as_script()).unwrap();
        // ROT moves third-to-top to top: [2, 3, 1]
        assert_eq!(engine.stack().len(), 3);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 2);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 1);
    }

    #[test]
    fn test_op_tuck() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_TUCK);
        engine.execute(script.as_script()).unwrap();
        // TUCK copies top and inserts before second-to-top: [3, 2, 3]
        assert_eq!(engine.stack().len(), 3);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 2);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 3);
    }

    #[test]
    fn test_op_ifdup_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_IFDUP);
        engine.execute(script.as_script()).unwrap();
        // 5 is truthy, so it gets duplicated: [5, 5]
        assert_eq!(engine.stack().len(), 2);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 5);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 5);
    }

    #[test]
    fn test_op_ifdup_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_IFDUP);
        engine.execute(script.as_script()).unwrap();
        // 0 is falsy, so no duplication: [<empty>]
        assert_eq!(engine.stack().len(), 1);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_depth() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_DEPTH);
        engine.execute(script.as_script()).unwrap();
        // Stack was [1,2,3], depth = 3, now [1,2,3,3]
        assert_eq!(engine.stack().len(), 4);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 3);
    }

    #[test]
    fn test_op_toaltstack_fromaltstack() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_7);
        script.push_opcode(Opcode::OP_TOALTSTACK);
        // Main stack is now empty, push something else
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_FROMALTSTACK);
        engine.execute(script.as_script()).unwrap();
        // Stack should be [1, 7]
        assert_eq!(engine.stack().len(), 2);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 1);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 7);
    }

    #[test]
    fn test_op_size() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_slice(b"hello");
        script.push_opcode(Opcode::OP_SIZE);
        engine.execute(script.as_script()).unwrap();
        // Stack should be ["hello", 5]
        assert_eq!(engine.stack().len(), 2);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 5);
    }

    #[test]
    fn test_op_pick() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_7);
        script.push_opcode(Opcode::OP_8);
        script.push_opcode(Opcode::OP_9);
        script.push_opcode(Opcode::OP_2); // pick index 2 (third from top = 7)
        script.push_opcode(Opcode::OP_PICK);
        engine.execute(script.as_script()).unwrap();
        // Stack: [7, 8, 9, 7]
        assert_eq!(engine.stack().len(), 4);
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 7);
    }

    #[test]
    fn test_op_roll() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_7);
        script.push_opcode(Opcode::OP_8);
        script.push_opcode(Opcode::OP_9);
        script.push_opcode(Opcode::OP_2); // roll index 2 (third from top = 7, move to top)
        script.push_opcode(Opcode::OP_ROLL);
        engine.execute(script.as_script()).unwrap();
        // Stack: [8, 9, 7]
        assert_eq!(engine.stack().len(), 3);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 8);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 9);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 7);
    }

    #[test]
    fn test_op_2over() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_2OVER);
        engine.execute(script.as_script()).unwrap();
        // 2OVER copies the pair below the top pair: [1, 2, 3, 4, 1, 2]
        assert_eq!(engine.stack().len(), 6);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 1);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 2);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[3]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[4]).unwrap(), 1);
        assert_eq!(decode_num(&engine.stack()[5]).unwrap(), 2);
    }

    #[test]
    fn test_op_2rot() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_6);
        script.push_opcode(Opcode::OP_2ROT);
        engine.execute(script.as_script()).unwrap();
        // 2ROT moves the bottom pair to top: [3, 4, 5, 6, 1, 2]
        assert_eq!(engine.stack().len(), 6);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 5);
        assert_eq!(decode_num(&engine.stack()[3]).unwrap(), 6);
        assert_eq!(decode_num(&engine.stack()[4]).unwrap(), 1);
        assert_eq!(decode_num(&engine.stack()[5]).unwrap(), 2);
    }

    #[test]
    fn test_op_2swap() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_2SWAP);
        engine.execute(script.as_script()).unwrap();
        // 2SWAP swaps top two pairs: [3, 4, 1, 2]
        assert_eq!(engine.stack().len(), 4);
        assert_eq!(decode_num(&engine.stack()[0]).unwrap(), 3);
        assert_eq!(decode_num(&engine.stack()[1]).unwrap(), 4);
        assert_eq!(decode_num(&engine.stack()[2]).unwrap(), 1);
        assert_eq!(decode_num(&engine.stack()[3]).unwrap(), 2);
    }

    // ========== Flow control tests ==========

    #[test]
    fn test_op_verify_success() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_VERIFY);
        // Push something truthy so success() works
        script.push_opcode(Opcode::OP_1);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_verify_failure() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_VERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_op_notif_true_branch() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0); // false -> NOTIF takes the "then" branch
        script.push_opcode(Opcode::OP_NOTIF);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_ELSE);
        script.push_opcode(Opcode::OP_6);
        script.push_opcode(Opcode::OP_ENDIF);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 5);
    }

    #[test]
    fn test_op_notif_false_branch() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1); // true -> NOTIF skips to ELSE branch
        script.push_opcode(Opcode::OP_NOTIF);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_ELSE);
        script.push_opcode(Opcode::OP_6);
        script.push_opcode(Opcode::OP_ENDIF);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 6);
    }

    #[test]
    fn test_op_nop() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_NOP);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(engine.stack().len(), 1);
        assert!(engine.success());
    }

    #[test]
    fn test_op_1negate() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1NEGATE);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), -1);
    }

    // ========== Arithmetic operation tests ==========

    #[test]
    fn test_op_1add() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_1ADD);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 6);
    }

    #[test]
    fn test_op_1sub() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_1SUB);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 4);
    }

    #[test]
    fn test_op_negate() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_NEGATE);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), -5);
    }

    #[test]
    fn test_op_negate_negative() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1NEGATE);
        script.push_opcode(Opcode::OP_NEGATE);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_abs() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1NEGATE);
        script.push_opcode(Opcode::OP_ABS);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_abs_positive() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_ABS);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 5);
    }

    #[test]
    fn test_op_not_zero() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_NOT);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_not_nonzero() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_NOT);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_0notequal_zero() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_0NOTEQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_0notequal_nonzero() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_0NOTEQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_sub() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_7);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_SUB);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 4);
    }

    #[test]
    fn test_op_booland_both_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_BOOLAND);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_booland_one_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_BOOLAND);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_boolor_both_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_BOOLOR);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_boolor_one_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_BOOLOR);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_numequal_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_NUMEQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_numequal_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_NUMEQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_numequalverify_success() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_NUMEQUALVERIFY);
        script.push_opcode(Opcode::OP_1); // push truthy value so test can check success
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_numequalverify_failure() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_NUMEQUALVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_op_numnotequal_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_NUMNOTEQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_numnotequal_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_NUMNOTEQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_lessthan_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_LESSTHAN);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_lessthan_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_LESSTHAN);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_greaterthan_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_GREATERTHAN);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_greaterthan_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_GREATERTHAN);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_lessthanorequal_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_LESSTHANOREQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_lessthanorequal_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_LESSTHANOREQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_greaterthanorequal_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_GREATERTHANOREQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_greaterthanorequal_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_GREATERTHANOREQUAL);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    #[test]
    fn test_op_min() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_7);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_MIN);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 3);
    }

    #[test]
    fn test_op_max() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_7);
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_MAX);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 7);
    }

    #[test]
    fn test_op_within_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3); // x
        script.push_opcode(Opcode::OP_2); // min
        script.push_opcode(Opcode::OP_5); // max
        script.push_opcode(Opcode::OP_WITHIN);
        engine.execute(script.as_script()).unwrap();
        // 3 >= 2 && 3 < 5 => true
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 1);
    }

    #[test]
    fn test_op_within_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5); // x
        script.push_opcode(Opcode::OP_2); // min
        script.push_opcode(Opcode::OP_5); // max
        script.push_opcode(Opcode::OP_WITHIN);
        engine.execute(script.as_script()).unwrap();
        // 5 >= 2 && 5 < 5 => false (upper bound exclusive)
        assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), 0);
    }

    // ========== Crypto operation tests ==========

    #[test]
    fn test_op_ripemd160() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_slice(b"hello");
        script.push_opcode(Opcode::OP_RIPEMD160);
        engine.execute(script.as_script()).unwrap();
        let result = engine.stack().last().unwrap();
        assert_eq!(result.len(), 20);
        // Known RIPEMD160("hello") = 108f07b8382412612c048d07d13f814118445acd
        assert_eq!(hex::encode(result), "108f07b8382412612c048d07d13f814118445acd");
    }

    #[test]
    fn test_op_sha256() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_slice(b"hello");
        script.push_opcode(Opcode::OP_SHA256);
        engine.execute(script.as_script()).unwrap();
        let result = engine.stack().last().unwrap();
        assert_eq!(result.len(), 32);
        // Known SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(hex::encode(result), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_op_hash256() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_slice(b"hello");
        script.push_opcode(Opcode::OP_HASH256);
        engine.execute(script.as_script()).unwrap();
        let result = engine.stack().last().unwrap();
        assert_eq!(result.len(), 32);
        // HASH256 is double SHA256: SHA256(SHA256("hello"))
        let expected = btc_primitives::hash::sha256d(b"hello");
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    // ========== Equality tests ==========

    #[test]
    fn test_op_equal_true() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_EQUAL);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_equal_false() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_5);
        script.push_opcode(Opcode::OP_6);
        script.push_opcode(Opcode::OP_EQUAL);
        engine.execute(script.as_script()).unwrap();
        assert!(!engine.success());
    }

    // ========== Misc tests ==========

    #[test]
    fn test_op_checklocktimeverify_as_nop() {
        // With flag disabled, CLTV should act as NOP
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        engine.execute(script.as_script()).unwrap();
        // Stack should still have [1]
        assert_eq!(engine.stack().len(), 1);
        assert!(engine.success());
    }

    #[test]
    fn test_op_checksequenceverify_as_nop() {
        // With flag disabled, CSV should act as NOP
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(engine.stack().len(), 1);
        assert!(engine.success());
    }

    #[test]
    fn test_op_nop1() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_NOP1);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_op_push_numbers() {
        // Test all OP_1 through OP_16
        for n in 1..=16i64 {
            let mut engine = make_engine();
            let mut script = ScriptBuf::new();
            let opcode = Opcode::from_u8(0x50 + n as u8); // OP_1=0x51 ... OP_16=0x60
            script.push_opcode(opcode);
            engine.execute(script.as_script()).unwrap();
            assert_eq!(decode_num(engine.stack().last().unwrap()).unwrap(), n,
                "OP_{} should push {}", n, n);
        }
    }

    #[test]
    fn test_op_equalverify_failure() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_4);
        script.push_opcode(Opcode::OP_EQUALVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::EqualVerifyFailed)));
    }

    #[test]
    fn test_unbalanced_if() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_IF);
        // Missing ENDIF
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }

    #[test]
    fn test_unbalanced_else() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_ELSE);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }

    #[test]
    fn test_unbalanced_endif() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_ENDIF);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }

    #[test]
    fn test_op_codeseparator() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_CODESEPARATOR);
        engine.execute(script.as_script()).unwrap();
        assert!(engine.success());
    }

    #[test]
    fn test_stack_underflow() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_DUP); // stack empty, should underflow
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::StackUnderflow)));
    }

    #[test]
    fn test_op_sha1() {
        // SHA1 is implemented as a stub returning 20 zero bytes
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_slice(b"test");
        script.push_opcode(Opcode::OP_SHA1);
        engine.execute(script.as_script()).unwrap();
        let result = engine.stack().last().unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_checkmultisig_1_of_1() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (sk1, pk1) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pk1_bytes = pk1.serialize().to_vec();

        // scriptPubKey: OP_1 <pk1> OP_1 OP_CHECKMULTISIG
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_slice(&pk1_bytes);
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

        let tx = make_test_tx();
        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig1_bytes = sign_sighash(&secp, &sk1, &sighash);

        // scriptSig: OP_0 <sig1>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_0); // dummy
        script_sig.push_slice(&sig1_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "1-of-1 OP_CHECKMULTISIG should succeed");
    }

    #[test]
    fn test_checkmultisigverify() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (sk1, pk1) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pk1_bytes = pk1.serialize().to_vec();

        // scriptPubKey: OP_1 <pk1> OP_1 OP_CHECKMULTISIGVERIFY OP_1
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_slice(&pk1_bytes);
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIGVERIFY);
        script_pubkey.push_opcode(Opcode::OP_1);

        let tx = make_test_tx();
        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig1_bytes = sign_sighash(&secp, &sk1, &sighash);

        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_0);
        script_sig.push_slice(&sig1_bytes);

        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            ScriptFlags::none(),
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "OP_CHECKMULTISIGVERIFY should succeed and leave OP_1 on stack");
    }

    // ========== Security audit fix tests ==========

    #[test]
    fn test_op_sha1_correct_hash() {
        // Fix 2: OP_SHA1 must produce real SHA1, not zeros.
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_slice(b"abc");
        script.push_opcode(Opcode::OP_SHA1);
        engine.execute(script.as_script()).unwrap();
        let result = engine.stack().last().unwrap();
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let expected = hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        assert_eq!(result, &expected, "OP_SHA1 must produce the real SHA1 hash, not zeros");
    }

    #[test]
    fn test_op_sha1_empty_input() {
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0); // push empty
        script.push_opcode(Opcode::OP_SHA1);
        engine.execute(script.as_script()).unwrap();
        let result = engine.stack().last().unwrap();
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let expected = hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert_eq!(result, &expected);
    }

    #[test]
    fn test_op_pick_negative_rejected() {
        // Fix 4: OP_PICK must reject negative values.
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_1NEGATE); // push -1
        script.push_opcode(Opcode::OP_PICK);
        let result = engine.execute(script.as_script());
        assert!(
            matches!(result, Err(ScriptError::InvalidStackOperation)),
            "OP_PICK with negative index must fail with InvalidStackOperation, got {:?}",
            result
        );
    }

    #[test]
    fn test_op_roll_negative_rejected() {
        // Fix 4: OP_ROLL must reject negative values.
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_opcode(Opcode::OP_2);
        script.push_opcode(Opcode::OP_1NEGATE); // push -1
        script.push_opcode(Opcode::OP_ROLL);
        let result = engine.execute(script.as_script());
        assert!(
            matches!(result, Err(ScriptError::InvalidStackOperation)),
            "OP_ROLL with negative index must fail with InvalidStackOperation, got {:?}",
            result
        );
    }

    #[test]
    fn test_op_tuck_stack_overflow() {
        // Fix 5: OP_TUCK must check stack size before inserting.
        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut engine = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
        // Fill the stack to MAX_STACK_SIZE - 1 (999 elements).
        // We push manually because the script op_count limit (201) would trigger
        // before we could push 999 items via opcodes.
        for _ in 0..999 {
            engine.stack.push(vec![0x01]);
        }
        assert_eq!(engine.stack.len(), 999);
        // Now the stack has 999 elements. OP_TUCK would add 1 element (the insert),
        // making it 1000. That should be allowed since MAX_STACK_SIZE is 1000.
        // Actually, the check is >= MAX_STACK_SIZE, so len 999 + altstack 0 = 999,
        // which is < 1000, so it should succeed.
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_TUCK);
        engine.execute(script.as_script()).unwrap();
        assert_eq!(engine.stack.len(), 1000);

        // Now stack is at 1000. Another OP_TUCK should fail.
        let mut engine2 = ScriptEngine::new_without_tx(&VERIFIER, ScriptFlags::none());
        for _ in 0..1000 {
            engine2.stack.push(vec![0x01]);
        }
        let mut script2 = ScriptBuf::new();
        script2.push_opcode(Opcode::OP_TUCK);
        let result = engine2.execute(script2.as_script());
        assert!(
            matches!(result, Err(ScriptError::StackOverflow)),
            "OP_TUCK at MAX_STACK_SIZE must fail with StackOverflow, got {:?}",
            result
        );
    }

    #[test]
    fn test_checkmultisig_nkeys_counts_toward_op_limit() {
        // Fix 3: n_keys in OP_CHECKMULTISIG must be added to op_count.
        // If we execute a script with enough ops that n_keys pushes it over 201,
        // it should fail with OpCountLimit.
        let mut engine = make_engine();
        // Build a script with 200 NOPs (each counted), then OP_CHECKMULTISIG with n_keys=2.
        // 200 NOPs + 1 CHECKMULTISIG = 201 op_count, then +2 from n_keys = 203 -> exceeds limit.
        let mut script = ScriptBuf::new();
        for _ in 0..200 {
            script.push_opcode(Opcode::OP_NOP);
        }
        // Push dummy, n_sigs=0, n_keys=2, two dummy pubkeys
        script.push_opcode(Opcode::OP_0); // dummy element
        script.push_opcode(Opcode::OP_0); // n_sigs = 0
        script.push_slice(&[0x02; 33]); // dummy pubkey 1
        script.push_slice(&[0x02; 33]); // dummy pubkey 2
        script.push_opcode(Opcode::OP_2); // n_keys = 2
        script.push_opcode(Opcode::OP_CHECKMULTISIG);
        let result = engine.execute(script.as_script());
        assert!(
            matches!(result, Err(ScriptError::OpCountLimit)),
            "OP_CHECKMULTISIG with n_keys pushing op_count over 201 must fail, got {:?}",
            result
        );
    }

    #[test]
    fn test_checkmultisig_negative_nkeys_rejected() {
        // Fix 3/4: negative n_keys must be rejected.
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0); // dummy
        script.push_opcode(Opcode::OP_1NEGATE); // n_keys = -1
        script.push_opcode(Opcode::OP_CHECKMULTISIG);
        let result = engine.execute(script.as_script());
        assert!(
            matches!(result, Err(ScriptError::InvalidStackOperation)),
            "OP_CHECKMULTISIG with negative n_keys must fail, got {:?}",
            result
        );
    }

    #[test]
    fn test_checkmultisig_negative_nsigs_rejected() {
        // Fix 3/4: negative n_sigs must be rejected.
        let mut engine = make_engine();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0); // dummy
        script.push_opcode(Opcode::OP_1NEGATE); // n_sigs = -1
        script.push_opcode(Opcode::OP_0); // n_keys = 0
        script.push_opcode(Opcode::OP_CHECKMULTISIG);
        let result = engine.execute(script.as_script());
        assert!(
            matches!(result, Err(ScriptError::InvalidStackOperation)),
            "OP_CHECKMULTISIG with negative n_sigs must fail, got {:?}",
            result
        );
    }

    // ========== CLTV / CSV timelock tests ==========

    fn make_cltv_engine(lock_time: u32, sequence: u32, version: i32) -> ScriptEngine<'static> {
        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let tx = Box::leak(Box::new(Transaction {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time,
        }));
        // Use flags with CLTV and CSV enabled, but without MINIMALDATA
        // (which would reject push_slice-encoded numbers that should use OP_N)
        let mut flags = ScriptFlags::none();
        flags.verify_checklocktimeverify = true;
        flags.verify_checksequenceverify = true;
        ScriptEngine::new(
            &VERIFIER,
            flags,
            Some(tx),
            0,
            0,
        )
    }

    #[test]
    fn test_cltv_satisfied() {
        // locktime on stack = 100, tx locktime = 200, sequence != FINAL
        let mut engine = make_cltv_engine(200, 0xfffffffe, 1);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(100));
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(result.is_ok(), "CLTV should succeed when tx locktime >= script locktime");
    }

    #[test]
    fn test_cltv_unsatisfied_too_low() {
        // locktime on stack = 300, tx locktime = 200
        let mut engine = make_cltv_engine(200, 0xfffffffe, 1);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(300));
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CLTV should fail when script locktime > tx locktime");
    }

    #[test]
    fn test_cltv_negative_locktime() {
        let mut engine = make_cltv_engine(200, 0xfffffffe, 1);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(-1));
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::NegativeLocktime)),
            "CLTV should fail with negative locktime");
    }

    #[test]
    fn test_cltv_sequence_final_fails() {
        // Even if locktimes match, SEQUENCE_FINAL disables locktime
        let mut engine = make_cltv_engine(200, 0xffffffff, 1);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(100));
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CLTV should fail when sequence is SEQUENCE_FINAL");
    }

    #[test]
    fn test_cltv_type_mismatch_fails() {
        // Script locktime is block height (<500M), tx locktime is timestamp (>=500M)
        let mut engine = make_cltv_engine(500_000_001, 0xfffffffe, 1);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(100));
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CLTV should fail when locktime types mismatch");
    }

    #[test]
    fn test_cltv_disabled_flag_nop() {
        // When verify_checklocktimeverify is disabled, CLTV acts as NOP
        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let mut flags = ScriptFlags::none();
        flags.verify_checklocktimeverify = false;
        let mut engine = ScriptEngine::new_without_tx(&VERIFIER, flags);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(-1));  // negative locktime would fail if enabled
        script.push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(result.is_ok(), "CLTV should be NOP when flag is disabled");
    }

    #[test]
    fn test_csv_satisfied() {
        // sequence on stack = 10, tx sequence = 20, version = 2
        let mut engine = make_cltv_engine(0, 20, 2);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(10));
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(result.is_ok(), "CSV should succeed when tx sequence >= script sequence");
    }

    #[test]
    fn test_csv_unsatisfied_too_low() {
        // sequence on stack = 30, tx sequence = 20
        let mut engine = make_cltv_engine(0, 20, 2);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(30));
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CSV should fail when script sequence > tx sequence");
    }

    #[test]
    fn test_csv_version_1_fails() {
        // CSV requires tx version >= 2
        let mut engine = make_cltv_engine(0, 20, 1);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(10));
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CSV should fail when tx version < 2");
    }

    #[test]
    fn test_csv_negative_fails() {
        // Negative sequence value = NegativeLocktime error (matches Bitcoin Core)
        let mut engine = make_cltv_engine(0, 20, 2);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(-1));
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::NegativeLocktime)),
            "CSV with negative sequence should return NegativeLocktime");
    }

    #[test]
    fn test_csv_disable_flag_bit31() {
        // bit 31 set on a positive 5-byte value = disabled = NOP behavior.
        // For a 5-byte script number, bit 31 is in the 4th byte and isn't the sign bit.
        // E.g., 0x00000080 00 = 0x80000000 = 2147483648 as unsigned, which is positive
        // in 5-byte encoding (sign bit is bit 39).
        // Use raw bytes: [0x00, 0x00, 0x00, 0x80, 0x00] = 0x80000000 positive
        let mut engine = make_cltv_engine(0, 20, 2);
        let mut script = ScriptBuf::new();
        // Push raw bytes for 0x80000000 (bit 31 set, positive in 5-byte encoding)
        script.push_slice(&[0x00, 0x00, 0x00, 0x80, 0x00]);
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(result.is_ok(), "CSV with bit 31 set (disabled) should be NOP");
    }

    #[test]
    fn test_csv_type_mismatch_fails() {
        // Script sequence has bit 22 set (time-based), tx sequence does not (block-based)
        let script_seq: i64 = (1 << 22) | 10; // time-based
        let tx_seq: u32 = 20; // block-based (bit 22 not set)
        let mut engine = make_cltv_engine(0, tx_seq, 2);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(script_seq));
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CSV should fail when sequence type flags mismatch");
    }

    #[test]
    fn test_csv_tx_sequence_disabled_fails() {
        // tx sequence has bit 31 set (locktime disabled for this input)
        let mut engine = make_cltv_engine(0, 0x80000014, 2);
        let mut script = ScriptBuf::new();
        script.push_slice(&encode_num(10));
        script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        let result = engine.execute(script.as_script());
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)),
            "CSV should fail when tx sequence has disable flag (bit 31) set");
    }

    // ---- Test: BIP147 NULLDUMMY enforcement ----

    #[test]
    fn test_nulldummy_enforcement_rejects_non_empty_dummy() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();

        // Generate 1 keypair for a simple 1-of-1 multisig
        let (sk1, pk1) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pk1_bytes = pk1.serialize().to_vec();

        // scriptPubKey: OP_1 <pk1> OP_1 OP_CHECKMULTISIG
        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_slice(&pk1_bytes);
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig1_bytes = sign_sighash(&secp, &sk1, &sighash);

        // Build scriptSig with a NON-EMPTY dummy element (violates BIP147)
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&[0x01]); // non-empty dummy!
        script_sig.push_slice(&sig1_bytes);

        // With verify_nulldummy OFF, it should succeed
        {
            static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
            let mut engine = ScriptEngine::new(
                &VERIFIER,
                ScriptFlags::none(), // nulldummy not enforced
                Some(&tx),
                0,
                0,
            );
            engine.execute(script_sig.as_script()).unwrap();
            engine.execute(script_pubkey.as_script()).unwrap();
            assert!(engine.success(), "should succeed without NULLDUMMY enforcement");
        }

        // With verify_nulldummy ON, it should fail
        {
            static VERIFIER2: Secp256k1Verifier = Secp256k1Verifier;
            let flags = ScriptFlags {
                verify_nulldummy: true,
                ..ScriptFlags::none()
            };
            let mut engine = ScriptEngine::new(
                &VERIFIER2,
                flags,
                Some(&tx),
                0,
                0,
            );
            engine.execute(script_sig.as_script()).unwrap();
            let result = engine.execute(script_pubkey.as_script());
            assert!(
                matches!(result, Err(ScriptError::VerifyFailed)),
                "NULLDUMMY enforcement should reject non-empty dummy, got: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_nulldummy_enforcement_allows_empty_dummy() {
        use crate::sighash::{sighash_legacy, SighashType};

        let secp = secp256k1::Secp256k1::new();
        let (sk1, pk1) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pk1_bytes = pk1.serialize().to_vec();

        let mut script_pubkey = ScriptBuf::new();
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_slice(&pk1_bytes);
        script_pubkey.push_opcode(Opcode::OP_1);
        script_pubkey.push_opcode(Opcode::OP_CHECKMULTISIG);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let sighash = sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL).unwrap();
        let sig1_bytes = sign_sighash(&secp, &sk1, &sighash);

        // Build scriptSig with EMPTY dummy (OP_0 pushes empty)
        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_0); // empty dummy -- valid
        script_sig.push_slice(&sig1_bytes);

        // With verify_nulldummy ON, empty dummy should pass
        static VERIFIER: Secp256k1Verifier = Secp256k1Verifier;
        let flags = ScriptFlags {
            verify_nulldummy: true,
            ..ScriptFlags::none()
        };
        let mut engine = ScriptEngine::new(
            &VERIFIER,
            flags,
            Some(&tx),
            0,
            0,
        );
        engine.execute(script_sig.as_script()).unwrap();
        engine.execute(script_pubkey.as_script()).unwrap();
        assert!(engine.success(), "NULLDUMMY with empty dummy should succeed");
    }
}
