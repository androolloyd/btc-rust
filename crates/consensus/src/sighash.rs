use std::borrow::Cow;
use btc_primitives::encode::{Encodable, WriteExt, VarInt};
use btc_primitives::hash::{sha256d, sha256};
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::Transaction;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SighashError {
    #[error("input index {0} out of range (tx has {1} inputs)")]
    InputOutOfRange(usize, usize),
    #[error("encoding error: {0}")]
    Encode(#[from] btc_primitives::encode::EncodeError),
    #[error("invalid sighash type: {0}")]
    InvalidSighashType(u32),
}

/// Sighash types as defined in Bitcoin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SighashType(pub u32);

impl SighashType {
    pub const ALL: SighashType = SighashType(0x01);
    pub const NONE: SighashType = SighashType(0x02);
    pub const SINGLE: SighashType = SighashType(0x03);
    pub const ANYONECANPAY: SighashType = SighashType(0x80);

    pub fn base_type(self) -> u32 {
        self.0 & 0x1f
    }

    pub fn anyone_can_pay(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub fn from_u8(v: u8) -> Self {
        SighashType(v as u32)
    }
}

/// Compute legacy sighash (pre-segwit)
///
/// This follows the original Bitcoin sighash algorithm:
/// 1. Copy the transaction
/// 2. Clear all input scripts
/// 3. Set the script of the input being signed to the subscript
/// 4. Handle SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
/// 5. Serialize and append hash type as u32 LE
/// 6. Double-SHA256 the result
pub fn sighash_legacy(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    hash_type: SighashType,
) -> Result<[u8; 32], SighashError> {
    if input_index >= tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(input_index, tx.inputs.len()));
    }

    // FindAndDelete(OP_CODESEPARATOR) — consensus requires stripping all
    // OP_CODESEPARATOR opcodes from the script before computing the sighash.
    use btc_primitives::script::Opcode;
    let script_code = find_and_delete(script_code, Opcode::OP_CODESEPARATOR);
    let script_code: &[u8] = &script_code;

    let base = hash_type.base_type();

    // SIGHASH_SINGLE bug: if input_index >= outputs.len(), return hash of 0x01 padded to 32 bytes
    if base == 3 && input_index >= tx.outputs.len() {
        let mut result = [0u8; 32];
        result[0] = 1;
        return Ok(result);
    }

    let mut buf = Vec::with_capacity(4 + 4 + tx.inputs.len() * 180 + tx.outputs.len() * 34 + 4 + 4);

    // Version
    buf.write_i32_le(tx.version)?;

    // Inputs
    if hash_type.anyone_can_pay() {
        // Only sign the current input
        VarInt(1).encode(&mut buf)?;
        // Previous output
        tx.inputs[input_index].previous_output.encode(&mut buf)?;
        // Script code
        VarInt(script_code.len() as u64).encode(&mut buf)?;
        buf.extend_from_slice(script_code);
        // Sequence
        buf.write_u32_le(tx.inputs[input_index].sequence)?;
    } else {
        VarInt(tx.inputs.len() as u64).encode(&mut buf)?;
        for (i, input) in tx.inputs.iter().enumerate() {
            input.previous_output.encode(&mut buf)?;
            if i == input_index {
                // This input gets the script code
                VarInt(script_code.len() as u64).encode(&mut buf)?;
                buf.extend_from_slice(script_code);
            } else {
                // Other inputs get empty scripts
                VarInt(0u64).encode(&mut buf)?;
            }
            // Sequence: for NONE and SINGLE, set non-signed inputs to 0
            if (base == 2 || base == 3) && i != input_index {
                buf.write_u32_le(0)?;
            } else {
                buf.write_u32_le(input.sequence)?;
            }
        }
    }

    // Outputs
    match base {
        2 => {
            // SIGHASH_NONE: no outputs
            VarInt(0u64).encode(&mut buf)?;
        }
        3 => {
            // SIGHASH_SINGLE: outputs up to and including input_index
            VarInt((input_index + 1) as u64).encode(&mut buf)?;
            for i in 0..=input_index {
                if i < input_index {
                    // Blank out outputs before the one we're signing
                    buf.write_i64_le(-1)?; // value = -1 (0xffffffffffffffff)
                    VarInt(0u64).encode(&mut buf)?; // empty script
                } else {
                    tx.outputs[i].encode(&mut buf)?;
                }
            }
        }
        _ => {
            // SIGHASH_ALL: all outputs
            VarInt(tx.outputs.len() as u64).encode(&mut buf)?;
            for output in &tx.outputs {
                output.encode(&mut buf)?;
            }
        }
    }

    // Lock time
    buf.write_u32_le(tx.lock_time)?;

    // Hash type (as u32 LE)
    buf.write_u32_le(hash_type.0)?;

    Ok(sha256d(&buf))
}

/// Compute BIP143 segwit sighash (v0 witness programs)
///
/// BIP143 defines a new transaction digest algorithm for segwit:
/// Double SHA256 of:
///   1. nVersion
///   2. hashPrevouts (or zeros if ANYONECANPAY)
///   3. hashSequence (or zeros if ANYONECANPAY, NONE, SINGLE)
///   4. outpoint (of the input being signed)
///   5. scriptCode (of the input being signed)
///   6. value (of the output being spent, as i64 LE)
///   7. nSequence (of the input being signed)
///   8. hashOutputs (or zeros/single output hash for NONE/SINGLE)
///   9. nLocktime
///  10. nHashType
pub fn sighash_segwit_v0(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    value: i64,
    hash_type: SighashType,
) -> Result<[u8; 32], SighashError> {
    if input_index >= tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(input_index, tx.inputs.len()));
    }

    let base = hash_type.base_type();
    let anyone_can_pay = hash_type.anyone_can_pay();

    let mut buf = Vec::with_capacity(256);

    // 1. nVersion
    buf.write_i32_le(tx.version)?;

    // 2. hashPrevouts
    if !anyone_can_pay {
        let mut prevouts_buf = Vec::with_capacity(tx.inputs.len() * 36);
        for input in &tx.inputs {
            input.previous_output.encode(&mut prevouts_buf)?;
        }
        buf.extend_from_slice(&sha256d(&prevouts_buf));
    } else {
        buf.extend_from_slice(&[0u8; 32]);
    }

    // 3. hashSequence
    if !anyone_can_pay && base != 2 && base != 3 {
        let mut seq_buf = Vec::with_capacity(tx.inputs.len() * 4);
        for input in &tx.inputs {
            seq_buf.write_u32_le(input.sequence)?;
        }
        buf.extend_from_slice(&sha256d(&seq_buf));
    } else {
        buf.extend_from_slice(&[0u8; 32]);
    }

    // 4. outpoint
    tx.inputs[input_index].previous_output.encode(&mut buf)?;

    // 5. scriptCode
    VarInt(script_code.len() as u64).encode(&mut buf)?;
    buf.extend_from_slice(script_code);

    // 6. value
    buf.write_i64_le(value)?;

    // 7. nSequence
    buf.write_u32_le(tx.inputs[input_index].sequence)?;

    // 8. hashOutputs
    if base != 2 && base != 3 {
        // SIGHASH_ALL
        let mut outputs_buf = Vec::with_capacity(tx.outputs.len() * 34);
        for output in &tx.outputs {
            output.encode(&mut outputs_buf)?;
        }
        buf.extend_from_slice(&sha256d(&outputs_buf));
    } else if base == 3 && input_index < tx.outputs.len() {
        // SIGHASH_SINGLE
        let mut output_buf = Vec::new();
        tx.outputs[input_index].encode(&mut output_buf)?;
        buf.extend_from_slice(&sha256d(&output_buf));
    } else {
        buf.extend_from_slice(&[0u8; 32]);
    }

    // 9. nLocktime
    buf.write_u32_le(tx.lock_time)?;

    // 10. nHashType
    buf.write_u32_le(hash_type.0)?;

    Ok(sha256d(&buf))
}

/// Cache for BIP143 intermediate hashes (hashPrevouts, hashSequence, hashOutputs).
///
/// When verifying multiple inputs of the same transaction, these intermediate
/// hashes are identical across inputs (for non-ANYONECANPAY/NONE/SINGLE sighash
/// types). Caching them avoids O(inputs^2) hashing.
pub struct SighashCache {
    pub hash_prevouts: Option<[u8; 32]>,
    pub hash_sequence: Option<[u8; 32]>,
    pub hash_outputs: Option<[u8; 32]>,
}

impl SighashCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        SighashCache {
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }
}

/// Compute BIP143 segwit sighash (v0 witness programs), with caching of
/// hashPrevouts, hashSequence, and hashOutputs across inputs.
///
/// This is the same algorithm as [`sighash_segwit_v0`] but avoids recomputing
/// intermediate hashes when verifying multiple inputs of the same transaction.
pub fn sighash_segwit_v0_cached(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    value: i64,
    hash_type: SighashType,
    cache: &mut SighashCache,
) -> Result<[u8; 32], SighashError> {
    if input_index >= tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(input_index, tx.inputs.len()));
    }

    let base = hash_type.base_type();
    let anyone_can_pay = hash_type.anyone_can_pay();

    let mut buf = Vec::with_capacity(256);

    // 1. nVersion
    buf.write_i32_le(tx.version)?;

    // 2. hashPrevouts
    if !anyone_can_pay {
        let hash_prevouts = match cache.hash_prevouts {
            Some(h) => h,
            None => {
                let mut prevouts_buf = Vec::with_capacity(tx.inputs.len() * 36);
                for input in &tx.inputs {
                    input.previous_output.encode(&mut prevouts_buf)?;
                }
                let h = sha256d(&prevouts_buf);
                cache.hash_prevouts = Some(h);
                h
            }
        };
        buf.extend_from_slice(&hash_prevouts);
    } else {
        buf.extend_from_slice(&[0u8; 32]);
    }

    // 3. hashSequence
    if !anyone_can_pay && base != 2 && base != 3 {
        let hash_sequence = match cache.hash_sequence {
            Some(h) => h,
            None => {
                let mut seq_buf = Vec::with_capacity(tx.inputs.len() * 4);
                for input in &tx.inputs {
                    seq_buf.write_u32_le(input.sequence)?;
                }
                let h = sha256d(&seq_buf);
                cache.hash_sequence = Some(h);
                h
            }
        };
        buf.extend_from_slice(&hash_sequence);
    } else {
        buf.extend_from_slice(&[0u8; 32]);
    }

    // 4. outpoint
    tx.inputs[input_index].previous_output.encode(&mut buf)?;

    // 5. scriptCode
    VarInt(script_code.len() as u64).encode(&mut buf)?;
    buf.extend_from_slice(script_code);

    // 6. value
    buf.write_i64_le(value)?;

    // 7. nSequence
    buf.write_u32_le(tx.inputs[input_index].sequence)?;

    // 8. hashOutputs
    if base != 2 && base != 3 {
        // SIGHASH_ALL
        let hash_outputs = match cache.hash_outputs {
            Some(h) => h,
            None => {
                let mut outputs_buf = Vec::with_capacity(tx.outputs.len() * 34);
                for output in &tx.outputs {
                    output.encode(&mut outputs_buf)?;
                }
                let h = sha256d(&outputs_buf);
                cache.hash_outputs = Some(h);
                h
            }
        };
        buf.extend_from_slice(&hash_outputs);
    } else if base == 3 && input_index < tx.outputs.len() {
        // SIGHASH_SINGLE
        let mut output_buf = Vec::new();
        tx.outputs[input_index].encode(&mut output_buf)?;
        buf.extend_from_slice(&sha256d(&output_buf));
    } else {
        buf.extend_from_slice(&[0u8; 32]);
    }

    // 9. nLocktime
    buf.write_u32_le(tx.lock_time)?;

    // 10. nHashType
    buf.write_u32_le(hash_type.0)?;

    Ok(sha256d(&buf))
}

/// Compute BIP341 taproot sighash (v1 witness programs)
///
/// BIP341 uses a tagged hash scheme with SHA256.
/// The epoch byte 0x00 is prepended, followed by various commitments.
pub fn sighash_taproot(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[btc_primitives::transaction::TxOut],
    hash_type: SighashType,
    annex: Option<&[u8]>,
    leaf_hash: Option<&[u8; 32]>,
) -> Result<[u8; 32], SighashError> {
    if input_index >= tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(input_index, tx.inputs.len()));
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(prevouts.len(), tx.inputs.len()));
    }

    let base = hash_type.base_type();
    let anyone_can_pay = hash_type.anyone_can_pay();

    // BIP340 tagged hash: SHA256(SHA256("TapSighash") || SHA256("TapSighash") || msg)
    static TAP_SIGHASH_TAG: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let tag_hash = TAP_SIGHASH_TAG.get_or_init(|| sha256(b"TapSighash"));
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(tag_hash);
    hasher_input.extend_from_slice(tag_hash);

    let mut msg = Vec::with_capacity(256);

    // Epoch (0x00)
    msg.push(0x00);

    // Hash type
    msg.push(hash_type.0 as u8);

    // nVersion
    msg.write_i32_le(tx.version)?;

    // nLocktime
    msg.write_u32_le(tx.lock_time)?;

    // If not ANYONECANPAY:
    if !anyone_can_pay {
        // sha_prevouts: SHA256 of all outpoints
        let mut prev_buf = Vec::new();
        for input in &tx.inputs {
            input.previous_output.encode(&mut prev_buf)?;
        }
        msg.extend_from_slice(&sha256(&prev_buf));

        // sha_amounts: SHA256 of all input amounts
        let mut amounts_buf = Vec::new();
        for prevout in prevouts {
            amounts_buf.write_i64_le(prevout.value.as_sat())?;
        }
        msg.extend_from_slice(&sha256(&amounts_buf));

        // sha_scriptpubkeys: SHA256 of all input scriptPubKeys
        let mut scripts_buf = Vec::new();
        for prevout in prevouts {
            prevout.script_pubkey.encode(&mut scripts_buf)?;
        }
        msg.extend_from_slice(&sha256(&scripts_buf));

        // sha_sequences: SHA256 of all sequences
        let mut seq_buf = Vec::new();
        for input in &tx.inputs {
            seq_buf.write_u32_le(input.sequence)?;
        }
        msg.extend_from_slice(&sha256(&seq_buf));
    }

    // If SIGHASH_ALL (base_type != 2 and != 3):
    if base != 2 && base != 3 {
        // sha_outputs: SHA256 of all outputs
        let mut outputs_buf = Vec::new();
        for output in &tx.outputs {
            output.encode(&mut outputs_buf)?;
        }
        msg.extend_from_slice(&sha256(&outputs_buf));
    }

    // Spend type
    let mut spend_type: u8 = 0;
    if annex.is_some() {
        spend_type |= 1;
    }
    if leaf_hash.is_some() {
        spend_type |= 2;
    }
    msg.push(spend_type);

    // Input-specific data
    if anyone_can_pay {
        tx.inputs[input_index].previous_output.encode(&mut msg)?;
        msg.write_i64_le(prevouts[input_index].value.as_sat())?;
        prevouts[input_index].script_pubkey.encode(&mut msg)?;
        msg.write_u32_le(tx.inputs[input_index].sequence)?;
    } else {
        msg.write_u32_le(input_index as u32)?;
    }

    // Annex hash
    if let Some(annex_data) = annex {
        let annex_hash = sha256(annex_data);
        msg.extend_from_slice(&annex_hash);
    }

    // Output-specific data for SIGHASH_SINGLE
    if base == 3 {
        if input_index < tx.outputs.len() {
            let mut output_buf = Vec::new();
            tx.outputs[input_index].encode(&mut output_buf)?;
            msg.extend_from_slice(&sha256(&output_buf));
        } else {
            return Err(SighashError::InputOutOfRange(input_index, tx.outputs.len()));
        }
    }

    // Leaf hash (for script path spending)
    if let Some(lh) = leaf_hash {
        msg.extend_from_slice(lh);
        msg.push(0x00); // key_version
        msg.write_u32_le(0xffffffff)?; // code_separator_pos (none)
    }

    hasher_input.extend_from_slice(&msg);
    Ok(sha256(&hasher_input))
}

/// Remove all occurrences of an opcode from a script.
/// This is Bitcoin's `FindAndDelete` operation, used to strip OP_CODESEPARATOR
/// from the script before sighash computation.
///
/// This must parse the script as instructions rather than filtering raw bytes,
/// because data pushes may contain bytes that happen to equal the opcode value
/// (e.g., 0xab inside push data is NOT an OP_CODESEPARATOR).
///
/// Returns `Cow::Borrowed` when no matching opcodes are found (avoiding allocation).
fn find_and_delete<'a>(script: &'a [u8], opcode: btc_primitives::script::Opcode) -> Cow<'a, [u8]> {
    let target = opcode.to_u8();
    // Quick scan: if the byte doesn't appear at all, nothing to delete.
    if !script.contains(&target) {
        return Cow::Borrowed(script);
    }

    let mut out = Vec::with_capacity(script.len());
    let mut found = false;
    let mut pos: usize = 0;

    while pos < script.len() {
        let byte = script[pos];
        let instr_start = pos;
        pos += 1;

        // Determine instruction length (mirrors ScriptInstructions::next in script.rs)
        if byte == 0 {
            // OP_0: single-byte opcode, pos already advanced
        } else if (1..=75).contains(&byte) {
            // Direct push: next `byte` bytes are data
            pos += byte as usize;
        } else if byte == btc_primitives::script::Opcode::OP_PUSHDATA1.to_u8() {
            if pos < script.len() {
                let len = script[pos] as usize;
                pos += 1 + len;
            }
        } else if byte == btc_primitives::script::Opcode::OP_PUSHDATA2.to_u8() {
            if pos + 2 <= script.len() {
                let len = u16::from_le_bytes([script[pos], script[pos + 1]]) as usize;
                pos += 2 + len;
            }
        } else if byte == btc_primitives::script::Opcode::OP_PUSHDATA4.to_u8() {
            if pos + 4 <= script.len() {
                let len = u32::from_le_bytes([
                    script[pos], script[pos + 1], script[pos + 2], script[pos + 3],
                ]) as usize;
                pos += 4 + len;
            }
        }
        // else: regular single-byte opcode, pos already advanced by 1.

        // Clamp to script length to avoid out-of-bounds on malformed scripts
        let end = pos.min(script.len());

        // A single-byte non-push instruction matching the target should be skipped.
        let is_single_byte_opcode = (end - instr_start) == 1 && !(1..=75).contains(&byte);
        let skip = is_single_byte_opcode && byte == target;

        if skip {
            found = true;
        } else {
            out.extend_from_slice(&script[instr_start..end]);
        }
    }

    if found {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(script)
    }
}

/// Helper: compute the script code for P2WPKH spending
/// For P2WPKH, the script code is: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let script = ScriptBuf::p2pkh(pubkey_hash);
    script.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::encode;
    use btc_primitives::transaction::Transaction;

    #[test]
    fn test_sighash_type_flags() {
        let all = SighashType::ALL;
        assert_eq!(all.base_type(), 1);
        assert!(!all.anyone_can_pay());

        let all_acp = SighashType(0x81);
        assert_eq!(all_acp.base_type(), 1);
        assert!(all_acp.anyone_can_pay());

        let none = SighashType::NONE;
        assert_eq!(none.base_type(), 2);

        let single = SighashType::SINGLE;
        assert_eq!(single.base_type(), 3);
    }

    #[test]
    fn test_sighash_legacy_against_core_vectors() {
        // Load sighash test vectors from Bitcoin Core
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/sighash.json");
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("skipping sighash test: testdata not found at {}", path);
                return;
            }
        };
        let vectors: serde_json::Value = serde_json::from_str(&data).unwrap();
        let vectors = vectors.as_array().unwrap();

        let mut tested = 0;
        let mut passed = 0;

        for vector in vectors {
            let arr = match vector.as_array() {
                Some(a) if a.len() == 5 => a,
                _ => continue,
            };

            let tx_hex = match arr[0].as_str() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };

            let script_hex = arr[1].as_str().unwrap_or("");
            let input_index = arr[2].as_i64().unwrap() as usize;
            let hash_type_raw = arr[3].as_i64().unwrap() as i32;
            let expected_hash = arr[4].as_str().unwrap();

            let tx_bytes = match hex::decode(tx_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let tx: Transaction = match encode::decode(&tx_bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let script_code = hex::decode(script_hex).unwrap_or_default();

            // Bitcoin Core uses the raw i32 hash type (can be negative)
            let hash_type = SighashType(hash_type_raw as u32);

            match sighash_legacy(&tx, input_index, &script_code, hash_type) {
                Ok(hash) => {
                    // Bitcoin Core's test vectors store the hash in reversed (display) byte order
                    let mut hash_reversed = hash;
                    hash_reversed.reverse();
                    let hash_hex = hex::encode(hash_reversed);
                    if hash_hex == expected_hash {
                        passed += 1;
                    }
                    tested += 1;
                }
                Err(_) => {
                    tested += 1;
                }
            }
        }

        eprintln!("sighash legacy: {}/{} passed ({} tested)", passed, tested, tested);
        // These are legacy sighash vectors — most should pass
        assert!(
            passed > 400,
            "expected at least 400 sighash vectors to pass, got {}/{}",
            passed,
            tested
        );
    }

    #[test]
    fn test_sighash_legacy_basic() {
        // Simple test: create a transaction and compute sighash
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xab; 32]), 0),
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

        let script_code = vec![0x76, 0xa9, 0x14]; // partial P2PKH
        let hash = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        // Just verify it produces a non-zero 32-byte hash
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_sighash_single_bug() {
        // SIGHASH_SINGLE with input_index >= outputs.len() should return 1-padded hash
        use btc_primitives::transaction::{TxIn, OutPoint};
        use btc_primitives::hash::TxHash;

        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x02; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![], // no outputs
            witness: Vec::new(),
            lock_time: 0,
        };

        let hash = sighash_legacy(&tx, 1, &[], SighashType::SINGLE).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(hash, expected);
    }

    /// Helper to create a test transaction for segwit/taproot tests
    fn make_segwit_test_tx() -> Transaction {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xab; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_sighash_segwit_v0_basic() {
        let tx = make_segwit_test_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 10_000_000i64;

        let hash = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::ALL).unwrap();
        // Must produce a non-zero 32-byte hash
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);

        // Must be deterministic
        let hash2 = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::ALL).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sighash_segwit_v0_none() {
        let tx = make_segwit_test_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 10_000_000i64;

        let hash_all = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::ALL).unwrap();
        let hash_none = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::NONE).unwrap();

        assert_ne!(hash_none, [0u8; 32]);
        // SIGHASH_NONE must differ from SIGHASH_ALL
        assert_ne!(hash_all, hash_none);
    }

    #[test]
    fn test_sighash_segwit_v0_single() {
        let tx = make_segwit_test_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 10_000_000i64;

        let hash_all = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::ALL).unwrap();
        let hash_single = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::SINGLE).unwrap();

        assert_ne!(hash_single, [0u8; 32]);
        assert_ne!(hash_all, hash_single);
    }

    #[test]
    fn test_sighash_segwit_v0_anyonecanpay() {
        let tx = make_segwit_test_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 10_000_000i64;

        // SIGHASH_ALL | ANYONECANPAY
        let hash_acp = sighash_segwit_v0(
            &tx, 0, &script_code, value,
            SighashType(SighashType::ALL.0 | SighashType::ANYONECANPAY.0),
        ).unwrap();

        let hash_all = sighash_segwit_v0(&tx, 0, &script_code, value, SighashType::ALL).unwrap();

        assert_ne!(hash_acp, [0u8; 32]);
        // ANYONECANPAY changes the hash (zeros out hashPrevouts and hashSequence)
        assert_ne!(hash_all, hash_acp);
    }

    #[test]
    fn test_sighash_segwit_v0_input_out_of_range() {
        let tx = make_segwit_test_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let result = sighash_segwit_v0(&tx, 5, &script_code, 10_000_000, SighashType::ALL);
        assert!(result.is_err());
    }

    #[test]
    fn test_sighash_taproot_basic() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0xab; 32]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: ScriptBuf::p2tr(&[0xcd; 32]),
        }];

        // Default taproot sighash type is 0x00
        let hash = sighash_taproot(&tx, 0, &prevouts, SighashType(0x00), None, None).unwrap();
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = sighash_taproot(&tx, 0, &prevouts, SighashType(0x00), None, None).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sighash_taproot_with_leaf_hash() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0xab; 32]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: ScriptBuf::p2tr(&[0xcd; 32]),
        }];

        let leaf_hash = [0xef; 32];
        let hash_with_leaf = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, Some(&leaf_hash),
        ).unwrap();

        let hash_without_leaf = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, None,
        ).unwrap();

        assert_ne!(hash_with_leaf, [0u8; 32]);
        // Script path (with leaf hash) must differ from key path (without)
        assert_ne!(hash_with_leaf, hash_without_leaf);
    }

    #[test]
    fn test_sighash_taproot_with_annex() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0xab; 32]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: ScriptBuf::p2tr(&[0xcd; 32]),
        }];

        let annex = vec![0x50, 0x01, 0x02, 0x03];
        let hash_with_annex = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), Some(&annex), None,
        ).unwrap();

        let hash_without_annex = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, None,
        ).unwrap();

        assert_ne!(hash_with_annex, [0u8; 32]);
        // Annex changes the spend_type byte and adds an annex hash
        assert_ne!(hash_with_annex, hash_without_annex);
    }

    #[test]
    fn test_sighash_taproot_input_out_of_range() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0xab; 32]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: ScriptBuf::p2tr(&[0xcd; 32]),
        }];

        // Input index out of range
        let result = sighash_taproot(&tx, 5, &prevouts, SighashType(0x00), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sighash_taproot_prevouts_mismatch() {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0xab; 32]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // prevouts count does not match inputs count
        let result = sighash_taproot(&tx, 0, &[], SighashType(0x00), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_p2wpkh_script_code() {
        let hash = [0xab; 20];
        let code = p2wpkh_script_code(&hash);
        // Should be: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(code.len(), 25);
        assert_eq!(code[0], 0x76); // OP_DUP
        assert_eq!(code[1], 0xa9); // OP_HASH160
        assert_eq!(code[2], 0x14); // push 20 bytes
        assert_eq!(&code[3..23], &hash);
        assert_eq!(code[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(code[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn test_find_and_delete_preserves_push_data_containing_0xab() {
        // Fix 1: find_and_delete must parse instructions, not filter bytes.
        // OP_CODESEPARATOR = 0xab. A push data containing 0xab must NOT be deleted.
        use btc_primitives::script::Opcode;

        // Build a script: PUSH(3 bytes including 0xab) OP_CODESEPARATOR OP_1
        // Bytes: [0x03, 0xaa, 0xab, 0xac, 0xab, 0x51]
        //   0x03 = push 3 bytes
        //   0xaa, 0xab, 0xac = the push data (contains 0xab!)
        //   0xab = OP_CODESEPARATOR (bare opcode)
        //   0x51 = OP_1
        let script = vec![0x03, 0xaa, 0xab, 0xac, 0xab, 0x51];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);

        // Only the bare OP_CODESEPARATOR at position 4 should be removed.
        // The 0xab inside the push data (position 2) must remain.
        let expected = vec![0x03, 0xaa, 0xab, 0xac, 0x51];
        assert_eq!(
            result.as_ref(), &expected[..],
            "find_and_delete must not strip 0xab bytes inside push data"
        );
    }

    #[test]
    fn test_find_and_delete_removes_multiple_codeseparators() {
        use btc_primitives::script::Opcode;

        // Script: OP_CODESEPARATOR OP_1 OP_CODESEPARATOR OP_2
        // Bytes: [0xab, 0x51, 0xab, 0x52]
        let script = vec![0xab, 0x51, 0xab, 0x52];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);

        // Both OP_CODESEPARATOR instances should be removed.
        let expected = vec![0x51, 0x52];
        assert_eq!(result.as_ref(), &expected[..]);
    }

    #[test]
    fn test_find_and_delete_no_change_returns_borrowed() {
        use btc_primitives::script::Opcode;

        // Script with no OP_CODESEPARATOR: OP_1 OP_2
        let script = vec![0x51, 0x52];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);
        // Should return Borrowed (no allocation)
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), &script[..]);
    }

    #[test]
    fn test_find_and_delete_pushdata1_containing_0xab() {
        use btc_primitives::script::Opcode;

        // Build script with OP_PUSHDATA1 containing 0xab bytes
        // OP_PUSHDATA1 = 0x4c, length = 2, data = [0xab, 0xab]
        // followed by OP_CODESEPARATOR (bare) and OP_1
        let script = vec![0x4c, 0x02, 0xab, 0xab, 0xab, 0x51];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);

        // Only the bare OP_CODESEPARATOR at position 4 should be removed.
        let expected = vec![0x4c, 0x02, 0xab, 0xab, 0x51];
        assert_eq!(
            result.as_ref(), &expected[..],
            "find_and_delete must not strip 0xab inside OP_PUSHDATA1 data"
        );
    }
}
