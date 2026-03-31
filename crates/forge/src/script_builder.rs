//! Ergonomic script construction with common Bitcoin Script patterns.

use btc_primitives::script::{Opcode, ScriptBuf};

/// A fluent builder for constructing Bitcoin scripts with common patterns
/// built in.
pub struct ForgeScript {
    buf: ScriptBuf,
}

impl ForgeScript {
    /// Start building a new empty script.
    pub fn new() -> Self {
        ForgeScript {
            buf: ScriptBuf::new(),
        }
    }

    /// Push an opcode.
    pub fn op(mut self, opcode: Opcode) -> Self {
        self.buf.push_opcode(opcode);
        self
    }

    /// Push raw bytes as a data push.
    pub fn push_bytes(mut self, data: &[u8]) -> Self {
        self.buf.push_slice(data);
        self
    }

    /// Push a number using Bitcoin's CScriptNum encoding.
    ///
    /// - 0 maps to `OP_0`
    /// - 1..=16 maps to `OP_1`..`OP_16`
    /// - -1 maps to `OP_1NEGATE`
    /// - Anything else is encoded as a minimal data push.
    pub fn push_num(mut self, n: i64) -> Self {
        if n == 0 {
            self.buf.push_opcode(Opcode::OP_0);
        } else if n == -1 {
            self.buf.push_opcode(Opcode::OP_1NEGATE);
        } else if (1..=16).contains(&n) {
            let op = Opcode::from_u8(0x50 + n as u8);
            self.buf.push_opcode(op);
        } else {
            let bytes = encode_script_num(n);
            self.buf.push_slice(&bytes);
        }
        self
    }

    /// Push a compressed public key (33 bytes).
    pub fn push_pubkey(self, key: &[u8]) -> Self {
        self.push_bytes(key)
    }

    /// Push a hash value.
    pub fn push_hash(self, hash: &[u8]) -> Self {
        self.push_bytes(hash)
    }

    /// Finalise the builder and return the completed script.
    pub fn build(self) -> ScriptBuf {
        self.buf
    }

    // ----- Common script patterns -----

    /// Standard P2PKH: `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG`
    pub fn p2pkh(pubkey_hash: &[u8; 20]) -> Self {
        ForgeScript::new()
            .op(Opcode::OP_DUP)
            .op(Opcode::OP_HASH160)
            .push_bytes(pubkey_hash)
            .op(Opcode::OP_EQUALVERIFY)
            .op(Opcode::OP_CHECKSIG)
    }

    /// Standard P2WPKH: `OP_0 <pubkey_hash>`
    pub fn p2wpkh(pubkey_hash: &[u8; 20]) -> Self {
        ForgeScript::new()
            .op(Opcode::OP_0)
            .push_bytes(pubkey_hash)
    }

    /// Standard P2SH: `OP_HASH160 <script_hash> OP_EQUAL`
    pub fn p2sh(script_hash: &[u8; 20]) -> Self {
        ForgeScript::new()
            .op(Opcode::OP_HASH160)
            .push_bytes(script_hash)
            .op(Opcode::OP_EQUAL)
    }

    /// Hash Time-Locked Contract (HTLC):
    ///
    /// ```text
    /// OP_IF
    ///   OP_SHA256 <hash> OP_EQUALVERIFY
    ///   <receiver_pubkey> OP_CHECKSIG
    /// OP_ELSE
    ///   <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
    ///   <sender_pubkey> OP_CHECKSIG
    /// OP_ENDIF
    /// ```
    pub fn htlc(
        receiver_pubkey: &[u8],
        sender_pubkey: &[u8],
        hash: &[u8; 32],
        timeout: i64,
    ) -> Self {
        ForgeScript::new()
            .op(Opcode::OP_IF)
            .op(Opcode::OP_SHA256)
            .push_bytes(hash)
            .op(Opcode::OP_EQUALVERIFY)
            .push_bytes(receiver_pubkey)
            .op(Opcode::OP_CHECKSIG)
            .op(Opcode::OP_ELSE)
            .push_num(timeout)
            .op(Opcode::OP_CHECKLOCKTIMEVERIFY)
            .op(Opcode::OP_DROP)
            .push_bytes(sender_pubkey)
            .op(Opcode::OP_CHECKSIG)
            .op(Opcode::OP_ENDIF)
    }

    /// Multisig: `OP_<threshold> <pubkey1> ... <pubkeyN> OP_<N> OP_CHECKMULTISIG`
    pub fn multisig(threshold: u8, pubkeys: &[&[u8]]) -> Self {
        assert!(
            threshold >= 1 && (threshold as usize) <= pubkeys.len(),
            "threshold must be between 1 and the number of pubkeys"
        );
        assert!(
            pubkeys.len() <= 16,
            "multisig supports at most 16 pubkeys"
        );

        let mut s = ForgeScript::new().push_num(threshold as i64);
        for pk in pubkeys {
            s = s.push_bytes(pk);
        }
        s.push_num(pubkeys.len() as i64)
            .op(Opcode::OP_CHECKMULTISIG)
    }

    /// Timelock wrapper: `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <inner>`
    pub fn timelock(locktime: i64, inner: &ScriptBuf) -> Self {
        let s = ForgeScript::new()
            .push_num(locktime)
            .op(Opcode::OP_CHECKLOCKTIMEVERIFY)
            .op(Opcode::OP_DROP);
        // Append the inner script bytes directly.
        let mut buf = s.buf.into_bytes();
        buf.extend_from_slice(inner.as_bytes());
        ForgeScript {
            buf: ScriptBuf::from_bytes(buf),
        }
    }

    /// Hashlock wrapper: `OP_SHA256 <hash> OP_EQUALVERIFY <inner>`
    pub fn hashlock(hash: &[u8; 32], inner: &ScriptBuf) -> Self {
        let s = ForgeScript::new()
            .op(Opcode::OP_SHA256)
            .push_bytes(hash)
            .op(Opcode::OP_EQUALVERIFY);
        let mut buf = s.buf.into_bytes();
        buf.extend_from_slice(inner.as_bytes());
        ForgeScript {
            buf: ScriptBuf::from_bytes(buf),
        }
    }
}

impl Default for ForgeScript {
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

    if result.last().map_or(false, |b| b & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}
