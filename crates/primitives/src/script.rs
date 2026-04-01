use std::fmt;
use crate::encode::{Encodable, Decodable, EncodeError, VarInt, ReadExt};
use std::io::{Read, Write};

/// A borrowed reference to a Bitcoin script byte slice, providing inspection methods.
#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Script([u8]);

impl Script {
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        // SAFETY: Script is a transparent wrapper around [u8]
        unsafe { &*(bytes as *const [u8] as *const Script) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_owned(&self) -> ScriptBuf {
        ScriptBuf(self.0.to_vec())
    }

    /// Check if this is a P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == Opcode::OP_DUP as u8
            && self.0[1] == Opcode::OP_HASH160 as u8
            && self.0[2] == 0x14
            && self.0[23] == Opcode::OP_EQUALVERIFY as u8
            && self.0[24] == Opcode::OP_CHECKSIG as u8
    }

    /// Check if this is a P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == Opcode::OP_HASH160 as u8
            && self.0[1] == 0x14
            && self.0[22] == Opcode::OP_EQUAL as u8
    }

    /// Check if this is a P2WPKH script: OP_0 <20 bytes>
    pub fn is_p2wpkh(&self) -> bool {
        self.0.len() == 22
            && self.0[0] == Opcode::OP_0 as u8
            && self.0[1] == 0x14
    }

    /// Check if this is a P2WSH script: OP_0 <32 bytes>
    pub fn is_p2wsh(&self) -> bool {
        self.0.len() == 34
            && self.0[0] == Opcode::OP_0 as u8
            && self.0[1] == 0x20
    }

    /// Check if this is a P2TR (Taproot) script: OP_1 <32 bytes>
    pub fn is_p2tr(&self) -> bool {
        self.0.len() == 34
            && self.0[0] == Opcode::OP_1 as u8
            && self.0[1] == 0x20
    }

    /// Check if this is a witness program (v0-v16)
    pub fn is_witness_program(&self) -> bool {
        if self.0.len() < 4 || self.0.len() > 42 {
            return false;
        }
        let version = self.0[0];
        let valid_version = version == Opcode::OP_0 as u8
            || (version >= Opcode::OP_1 as u8 && version <= Opcode::OP_16 as u8);
        if !valid_version {
            return false;
        }
        let push_len = self.0[1] as usize;
        push_len >= 2 && push_len <= 40 && push_len + 2 == self.0.len()
    }

    /// Check if this is an OP_RETURN (provably unspendable) script
    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == Opcode::OP_RETURN as u8
    }

    /// Iterate over script instructions (opcodes + push data)
    pub fn instructions(&self) -> ScriptInstructions<'_> {
        ScriptInstructions { data: &self.0, pos: 0 }
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Script({})", hex::encode(&self.0))
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// An owned, mutable Bitcoin script buffer for constructing and serialising scripts.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct ScriptBuf(Vec<u8>);

impl ScriptBuf {
    pub fn new() -> Self {
        ScriptBuf(Vec::new())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        ScriptBuf(bytes)
    }

    pub fn as_script(&self) -> &Script {
        Script::from_bytes(&self.0)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn push_opcode(&mut self, op: Opcode) {
        self.0.push(op as u8);
    }

    pub fn push_slice(&mut self, data: &[u8]) {
        let len = data.len();
        if len == 0 {
            // Nothing to push
        } else if len <= 75 {
            self.0.push(len as u8);
            self.0.extend_from_slice(data);
        } else if len <= 0xff {
            self.0.push(Opcode::OP_PUSHDATA1 as u8);
            self.0.push(len as u8);
            self.0.extend_from_slice(data);
        } else if len <= 0xffff {
            self.0.push(Opcode::OP_PUSHDATA2 as u8);
            self.0.extend_from_slice(&(len as u16).to_le_bytes());
            self.0.extend_from_slice(data);
        } else {
            self.0.push(Opcode::OP_PUSHDATA4 as u8);
            self.0.extend_from_slice(&(len as u32).to_le_bytes());
            self.0.extend_from_slice(data);
        }
    }

    /// Build a standard P2PKH script
    pub fn p2pkh(pubkey_hash: &[u8; 20]) -> Self {
        let mut s = ScriptBuf::new();
        s.push_opcode(Opcode::OP_DUP);
        s.push_opcode(Opcode::OP_HASH160);
        s.push_slice(pubkey_hash);
        s.push_opcode(Opcode::OP_EQUALVERIFY);
        s.push_opcode(Opcode::OP_CHECKSIG);
        s
    }

    /// Build a standard P2SH script
    pub fn p2sh(script_hash: &[u8; 20]) -> Self {
        let mut s = ScriptBuf::new();
        s.push_opcode(Opcode::OP_HASH160);
        s.push_slice(script_hash);
        s.push_opcode(Opcode::OP_EQUAL);
        s
    }

    /// Build a standard P2WPKH script
    pub fn p2wpkh(pubkey_hash: &[u8; 20]) -> Self {
        let mut s = ScriptBuf::new();
        s.0.push(Opcode::OP_0 as u8);
        s.0.push(0x14);
        s.0.extend_from_slice(pubkey_hash);
        s
    }

    /// Build a standard P2WSH script
    pub fn p2wsh(script_hash: &[u8; 32]) -> Self {
        let mut s = ScriptBuf::new();
        s.0.push(Opcode::OP_0 as u8);
        s.0.push(0x20);
        s.0.extend_from_slice(script_hash);
        s
    }

    /// Build a standard P2TR (Taproot) script
    pub fn p2tr(output_key: &[u8; 32]) -> Self {
        let mut s = ScriptBuf::new();
        s.0.push(Opcode::OP_1 as u8);
        s.0.push(0x20);
        s.0.extend_from_slice(output_key);
        s
    }
}

impl std::ops::Deref for ScriptBuf {
    type Target = Script;
    fn deref(&self) -> &Script {
        self.as_script()
    }
}

impl fmt::Debug for ScriptBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScriptBuf({})", hex::encode(&self.0))
    }
}

impl Encodable for ScriptBuf {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let vi = VarInt(self.0.len() as u64);
        let mut written = vi.encode(writer)?;
        writer.write_all(&self.0)?;
        written += self.0.len();
        Ok(written)
    }
}

/// Maximum script size for decoding (10 KB consensus limit + margin)
const MAX_SCRIPT_DECODE_SIZE: usize = 100_000;

impl Decodable for ScriptBuf {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let len = VarInt::decode(reader)?.0 as usize;
        if len > MAX_SCRIPT_DECODE_SIZE {
            return Err(EncodeError::InvalidData(
                format!("script length {} exceeds maximum", len)
            ));
        }
        let data = reader.read_bytes(len)?;
        Ok(ScriptBuf(data))
    }
}

/// Script instruction — either an opcode or push data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction<'a> {
    Op(Opcode),
    PushBytes(&'a [u8]),
}

/// Iterator over script instructions
pub struct ScriptInstructions<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for ScriptInstructions<'a> {
    type Item = Result<Instruction<'a>, EncodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        let opcode = self.data[self.pos];
        self.pos += 1;

        // Data push opcodes
        if opcode == 0 {
            return Some(Ok(Instruction::Op(Opcode::OP_0)));
        }

        if (1..=75).contains(&opcode) {
            let len = opcode as usize;
            if self.pos + len > self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let data = &self.data[self.pos..self.pos + len];
            self.pos += len;
            return Some(Ok(Instruction::PushBytes(data)));
        }

        if opcode == Opcode::OP_PUSHDATA1 as u8 {
            if self.pos >= self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let len = self.data[self.pos] as usize;
            self.pos += 1;
            if self.pos + len > self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let data = &self.data[self.pos..self.pos + len];
            self.pos += len;
            return Some(Ok(Instruction::PushBytes(data)));
        }

        if opcode == Opcode::OP_PUSHDATA2 as u8 {
            if self.pos + 2 > self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let len = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
            self.pos += 2;
            if self.pos + len > self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let data = &self.data[self.pos..self.pos + len];
            self.pos += len;
            return Some(Ok(Instruction::PushBytes(data)));
        }

        if opcode == Opcode::OP_PUSHDATA4 as u8 {
            if self.pos + 4 > self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let len = u32::from_le_bytes([
                self.data[self.pos],
                self.data[self.pos + 1],
                self.data[self.pos + 2],
                self.data[self.pos + 3],
            ]) as usize;
            self.pos += 4;
            if self.pos + len > self.data.len() {
                return Some(Err(EncodeError::UnexpectedEof));
            }
            let data = &self.data[self.pos..self.pos + len];
            self.pos += len;
            return Some(Ok(Instruction::PushBytes(data)));
        }

        // Regular opcode
        Some(Ok(Instruction::Op(Opcode::from_u8(opcode))))
    }
}

/// Bitcoin Script opcodes as defined by the consensus rules (OP_0 through OP_CHECKSIGADD).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    // Push value
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Flow control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // Splice
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // Bitwise logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // Arithmetic
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,

    // Crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // Expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // Tapscript
    OP_CHECKSIGADD = 0xba,

    OP_INVALIDOPCODE = 0xff,
}

impl Opcode {
    pub fn from_u8(v: u8) -> Self {
        // Map known opcodes, default to OP_INVALIDOPCODE for unknown
        match v {
            0x00 => Opcode::OP_0,
            0x4c => Opcode::OP_PUSHDATA1,
            0x4d => Opcode::OP_PUSHDATA2,
            0x4e => Opcode::OP_PUSHDATA4,
            0x4f => Opcode::OP_1NEGATE,
            0x50 => Opcode::OP_RESERVED,
            0x51 => Opcode::OP_1,
            0x52 => Opcode::OP_2,
            0x53 => Opcode::OP_3,
            0x54 => Opcode::OP_4,
            0x55 => Opcode::OP_5,
            0x56 => Opcode::OP_6,
            0x57 => Opcode::OP_7,
            0x58 => Opcode::OP_8,
            0x59 => Opcode::OP_9,
            0x5a => Opcode::OP_10,
            0x5b => Opcode::OP_11,
            0x5c => Opcode::OP_12,
            0x5d => Opcode::OP_13,
            0x5e => Opcode::OP_14,
            0x5f => Opcode::OP_15,
            0x60 => Opcode::OP_16,
            0x61 => Opcode::OP_NOP,
            0x62 => Opcode::OP_VER,
            0x63 => Opcode::OP_IF,
            0x64 => Opcode::OP_NOTIF,
            0x65 => Opcode::OP_VERIF,
            0x66 => Opcode::OP_VERNOTIF,
            0x67 => Opcode::OP_ELSE,
            0x68 => Opcode::OP_ENDIF,
            0x69 => Opcode::OP_VERIFY,
            0x6a => Opcode::OP_RETURN,
            0x6b => Opcode::OP_TOALTSTACK,
            0x6c => Opcode::OP_FROMALTSTACK,
            0x6d => Opcode::OP_2DROP,
            0x6e => Opcode::OP_2DUP,
            0x6f => Opcode::OP_3DUP,
            0x70 => Opcode::OP_2OVER,
            0x71 => Opcode::OP_2ROT,
            0x72 => Opcode::OP_2SWAP,
            0x73 => Opcode::OP_IFDUP,
            0x74 => Opcode::OP_DEPTH,
            0x75 => Opcode::OP_DROP,
            0x76 => Opcode::OP_DUP,
            0x77 => Opcode::OP_NIP,
            0x78 => Opcode::OP_OVER,
            0x79 => Opcode::OP_PICK,
            0x7a => Opcode::OP_ROLL,
            0x7b => Opcode::OP_ROT,
            0x7c => Opcode::OP_SWAP,
            0x7d => Opcode::OP_TUCK,
            0x7e => Opcode::OP_CAT,
            0x7f => Opcode::OP_SUBSTR,
            0x80 => Opcode::OP_LEFT,
            0x81 => Opcode::OP_RIGHT,
            0x82 => Opcode::OP_SIZE,
            0x83 => Opcode::OP_INVERT,
            0x84 => Opcode::OP_AND,
            0x85 => Opcode::OP_OR,
            0x86 => Opcode::OP_XOR,
            0x87 => Opcode::OP_EQUAL,
            0x88 => Opcode::OP_EQUALVERIFY,
            0x89 => Opcode::OP_RESERVED1,
            0x8a => Opcode::OP_RESERVED2,
            0x8b => Opcode::OP_1ADD,
            0x8c => Opcode::OP_1SUB,
            0x8d => Opcode::OP_2MUL,
            0x8e => Opcode::OP_2DIV,
            0x8f => Opcode::OP_NEGATE,
            0x90 => Opcode::OP_ABS,
            0x91 => Opcode::OP_NOT,
            0x92 => Opcode::OP_0NOTEQUAL,
            0x93 => Opcode::OP_ADD,
            0x94 => Opcode::OP_SUB,
            0x95 => Opcode::OP_MUL,
            0x96 => Opcode::OP_DIV,
            0x97 => Opcode::OP_MOD,
            0x98 => Opcode::OP_LSHIFT,
            0x99 => Opcode::OP_RSHIFT,
            0x9a => Opcode::OP_BOOLAND,
            0x9b => Opcode::OP_BOOLOR,
            0x9c => Opcode::OP_NUMEQUAL,
            0x9d => Opcode::OP_NUMEQUALVERIFY,
            0x9e => Opcode::OP_NUMNOTEQUAL,
            0x9f => Opcode::OP_LESSTHAN,
            0xa0 => Opcode::OP_GREATERTHAN,
            0xa1 => Opcode::OP_LESSTHANOREQUAL,
            0xa2 => Opcode::OP_GREATERTHANOREQUAL,
            0xa3 => Opcode::OP_MIN,
            0xa4 => Opcode::OP_MAX,
            0xa5 => Opcode::OP_WITHIN,
            0xa6 => Opcode::OP_RIPEMD160,
            0xa7 => Opcode::OP_SHA1,
            0xa8 => Opcode::OP_SHA256,
            0xa9 => Opcode::OP_HASH160,
            0xaa => Opcode::OP_HASH256,
            0xab => Opcode::OP_CODESEPARATOR,
            0xac => Opcode::OP_CHECKSIG,
            0xad => Opcode::OP_CHECKSIGVERIFY,
            0xae => Opcode::OP_CHECKMULTISIG,
            0xaf => Opcode::OP_CHECKMULTISIGVERIFY,
            0xb0 => Opcode::OP_NOP1,
            0xb1 => Opcode::OP_CHECKLOCKTIMEVERIFY,
            0xb2 => Opcode::OP_CHECKSEQUENCEVERIFY,
            0xb3 => Opcode::OP_NOP4,
            0xb4 => Opcode::OP_NOP5,
            0xb5 => Opcode::OP_NOP6,
            0xb6 => Opcode::OP_NOP7,
            0xb7 => Opcode::OP_NOP8,
            0xb8 => Opcode::OP_NOP9,
            0xb9 => Opcode::OP_NOP10,
            0xba => Opcode::OP_CHECKSIGADD,
            _ => Opcode::OP_INVALIDOPCODE,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_script() {
        let hash = [0u8; 20];
        let script = ScriptBuf::p2pkh(&hash);
        assert!(script.is_p2pkh());
        assert!(!script.is_p2sh());
        assert!(!script.is_p2wpkh());
        assert_eq!(script.len(), 25);
    }

    #[test]
    fn test_p2sh_script() {
        let hash = [0u8; 20];
        let script = ScriptBuf::p2sh(&hash);
        assert!(script.is_p2sh());
        assert!(!script.is_p2pkh());
        assert_eq!(script.len(), 23);
    }

    #[test]
    fn test_p2wpkh_script() {
        let hash = [0u8; 20];
        let script = ScriptBuf::p2wpkh(&hash);
        assert!(script.is_p2wpkh());
        assert!(script.is_witness_program());
        assert_eq!(script.len(), 22);
    }

    #[test]
    fn test_p2wsh_script() {
        let hash = [0u8; 32];
        let script = ScriptBuf::p2wsh(&hash);
        assert!(script.is_p2wsh());
        assert!(script.is_witness_program());
        assert_eq!(script.len(), 34);
    }

    #[test]
    fn test_p2tr_script() {
        let key = [0u8; 32];
        let script = ScriptBuf::p2tr(&key);
        assert!(script.is_p2tr());
        assert!(script.is_witness_program());
        assert_eq!(script.len(), 34);
    }

    #[test]
    fn test_op_return() {
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_RETURN);
        script.push_slice(b"hello world");
        assert!(script.is_op_return());
    }

    #[test]
    fn test_script_instructions() {
        // P2PKH script
        let hash = [0xab; 20];
        let script = ScriptBuf::p2pkh(&hash);
        let instructions: Vec<_> = script.instructions().collect::<Result<_, _>>().unwrap();
        assert_eq!(instructions.len(), 5);
        assert_eq!(instructions[0], Instruction::Op(Opcode::OP_DUP));
        assert_eq!(instructions[1], Instruction::Op(Opcode::OP_HASH160));
        assert_eq!(instructions[2], Instruction::PushBytes(&hash));
        assert_eq!(instructions[3], Instruction::Op(Opcode::OP_EQUALVERIFY));
        assert_eq!(instructions[4], Instruction::Op(Opcode::OP_CHECKSIG));
    }

    #[test]
    fn test_script_encode_decode_roundtrip() {
        let hash = [0xab; 20];
        let script = ScriptBuf::p2pkh(&hash);
        let encoded = crate::encode::encode(&script);
        let decoded: ScriptBuf = crate::encode::decode(&encoded).unwrap();
        assert_eq!(script, decoded);
    }
}
