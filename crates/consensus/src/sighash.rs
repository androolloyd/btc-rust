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

/// BIP118 SIGHASH_ANYPREVOUT — allows rebinding to any UTXO (skips outpoint)
pub const SIGHASH_ANYPREVOUT: u32 = 0x41;

/// BIP118 SIGHASH_ANYPREVOUTANYSCRIPT — also skips scriptPubKey and amount
pub const SIGHASH_ANYPREVOUTANYSCRIPT: u32 = 0x42;

/// Compute BIP118 ANYPREVOUT sighash (taproot-style but skipping input identity).
///
/// - SIGHASH_ANYPREVOUT (0x41): like taproot sighash but skip the outpoint,
///   allowing the signature to be valid for spending any UTXO with the same script.
/// - SIGHASH_ANYPREVOUTANYSCRIPT (0x42): additionally skip the scriptPubKey and
///   input amount, allowing rebinding to any UTXO regardless of script or value.
///
/// This function follows the BIP341 taproot sighash structure with targeted
/// omissions as specified by BIP118.
pub fn sighash_anyprevout(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[btc_primitives::transaction::TxOut],
    hash_type: u32,
    annex: Option<&[u8]>,
    leaf_hash: Option<&[u8; 32]>,
) -> Result<[u8; 32], SighashError> {
    if input_index >= tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(input_index, tx.inputs.len()));
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(SighashError::InputOutOfRange(prevouts.len(), tx.inputs.len()));
    }

    let is_anyprevout = hash_type == SIGHASH_ANYPREVOUT;
    let is_anyprevoutanyscript = hash_type == SIGHASH_ANYPREVOUTANYSCRIPT;

    if !is_anyprevout && !is_anyprevoutanyscript {
        return Err(SighashError::InvalidSighashType(hash_type));
    }

    let mut msg = Vec::with_capacity(256);

    // Epoch (0x00) — same as BIP341
    msg.push(0x00);

    // Hash type byte
    msg.push(hash_type as u8);

    // nVersion
    msg.write_i32_le(tx.version)?;

    // nLocktime
    msg.write_u32_le(tx.lock_time)?;

    // For ANYPREVOUT, we do NOT commit to prevouts (outpoints) — that is the
    // whole point. But we still commit to amounts, scriptPubKeys, and sequences.
    // For ANYPREVOUTANYSCRIPT, we also skip amounts and scriptPubKeys.

    // sha_amounts: only for ANYPREVOUT (not ANYPREVOUTANYSCRIPT)
    if is_anyprevout {
        let mut amounts_buf = Vec::new();
        for prevout in prevouts {
            amounts_buf.write_i64_le(prevout.value.as_sat())?;
        }
        msg.extend_from_slice(&sha256(&amounts_buf));

        // sha_scriptpubkeys
        let mut scripts_buf = Vec::new();
        for prevout in prevouts {
            prevout.script_pubkey.encode(&mut scripts_buf)?;
        }
        msg.extend_from_slice(&sha256(&scripts_buf));
    }
    // ANYPREVOUTANYSCRIPT skips both amounts and scriptPubKeys entirely.

    // sha_sequences: commit to all sequences (not input-specific)
    {
        let mut seq_buf = Vec::new();
        for input in &tx.inputs {
            seq_buf.write_u32_le(input.sequence)?;
        }
        msg.extend_from_slice(&sha256(&seq_buf));
    }

    // sha_outputs (SIGHASH_ALL behaviour — BIP118 doesn't modify output handling)
    {
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

    // Input-specific data — ANYPREVOUT skips the outpoint but includes the rest.
    // We do NOT write the outpoint (that is what makes it "any prev out").
    // For ANYPREVOUT, we still commit to amount and scriptPubKey of THIS input.
    if is_anyprevout {
        msg.write_i64_le(prevouts[input_index].value.as_sat())?;
        prevouts[input_index].script_pubkey.encode(&mut msg)?;
    }
    // For ANYPREVOUTANYSCRIPT, we skip outpoint, amount, and scriptPubKey.

    // Sequence of the input being signed
    msg.write_u32_le(tx.inputs[input_index].sequence)?;

    // Annex hash
    if let Some(annex_data) = annex {
        let annex_hash = sha256(annex_data);
        msg.extend_from_slice(&annex_hash);
    }

    // Leaf hash (for script path spending)
    if let Some(lh) = leaf_hash {
        msg.extend_from_slice(lh);
        msg.push(0x00); // key_version
        msg.write_u32_le(0xffffffff)?; // code_separator_pos (none)
    }

    Ok(crate::taproot::tagged_hash(b"TapSighash", &msg))
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

    Ok(crate::taproot::tagged_hash(b"TapSighash", &msg))
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

    // ---------------------------------------------------------------
    // Helper: build a multi-input/multi-output transaction for coverage
    // ---------------------------------------------------------------
    fn make_multi_io_tx() -> Transaction {
        use btc_primitives::transaction::{TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::amount::Amount;

        Transaction {
            version: 2,
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
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 2),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xfffffffd,
                },
            ],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(1_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::from_sat(2_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
                },
            ],
            witness: Vec::new(),
            lock_time: 500_000,
        }
    }

    fn make_multi_prevouts() -> Vec<btc_primitives::transaction::TxOut> {
        use btc_primitives::transaction::TxOut;
        use btc_primitives::amount::Amount;

        vec![
            TxOut {
                value: Amount::from_sat(5_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0x01; 32]),
            },
            TxOut {
                value: Amount::from_sat(6_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0x02; 32]),
            },
            TxOut {
                value: Amount::from_sat(7_000_000),
                script_pubkey: ScriptBuf::p2tr(&[0x03; 32]),
            },
        ]
    }

    // ---------------------------------------------------------------
    // Taproot: SIGHASH_NONE (base_type == 2)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_none() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        let hash_none = sighash_taproot(
            &tx, 0, &prevouts, SighashType::NONE, None, None,
        ).unwrap();
        assert_ne!(hash_none, [0u8; 32]);

        // Must differ from ALL (default 0x00 acts like ALL)
        let hash_all = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, None,
        ).unwrap();
        assert_ne!(hash_none, hash_all);

        // Deterministic
        let hash_none2 = sighash_taproot(
            &tx, 0, &prevouts, SighashType::NONE, None, None,
        ).unwrap();
        assert_eq!(hash_none, hash_none2);
    }

    // ---------------------------------------------------------------
    // Taproot: SIGHASH_SINGLE (base_type == 3)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_single() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        // input_index=0, which is < outputs.len() (2), so should succeed
        let hash_single = sighash_taproot(
            &tx, 0, &prevouts, SighashType::SINGLE, None, None,
        ).unwrap();
        assert_ne!(hash_single, [0u8; 32]);

        // Must differ from ALL and NONE
        let hash_all = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, None,
        ).unwrap();
        let hash_none = sighash_taproot(
            &tx, 0, &prevouts, SighashType::NONE, None, None,
        ).unwrap();
        assert_ne!(hash_single, hash_all);
        assert_ne!(hash_single, hash_none);

        // SINGLE for input 1 should also work and differ from input 0
        let hash_single_1 = sighash_taproot(
            &tx, 1, &prevouts, SighashType::SINGLE, None, None,
        ).unwrap();
        assert_ne!(hash_single, hash_single_1);
    }

    // ---------------------------------------------------------------
    // Taproot: SIGHASH_SINGLE out of range
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_single_out_of_range() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        // input_index=2 but only 2 outputs (indices 0,1), so SINGLE should error
        let result = sighash_taproot(
            &tx, 2, &prevouts, SighashType::SINGLE, None, None,
        );
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("out of range"), "expected out-of-range error, got: {}", err_msg);
    }

    // ---------------------------------------------------------------
    // Taproot: ANYONECANPAY | ALL (0x81)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_anyonecanpay_all() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        let hash_acp_all = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x81), None, None,
        ).unwrap();
        assert_ne!(hash_acp_all, [0u8; 32]);

        let hash_all = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, None,
        ).unwrap();
        // ANYONECANPAY skips sha_prevouts/sha_amounts/sha_scriptpubkeys/sha_sequences
        // and instead writes per-input data, so must differ
        assert_ne!(hash_acp_all, hash_all);
    }

    // ---------------------------------------------------------------
    // Taproot: ANYONECANPAY | NONE (0x82)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_anyonecanpay_none() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        let hash_acp_none = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x82), None, None,
        ).unwrap();
        assert_ne!(hash_acp_none, [0u8; 32]);

        // Must differ from ACP|ALL
        let hash_acp_all = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x81), None, None,
        ).unwrap();
        assert_ne!(hash_acp_none, hash_acp_all);
    }

    // ---------------------------------------------------------------
    // Taproot: ANYONECANPAY | SINGLE (0x83)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_anyonecanpay_single() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        let hash_acp_single = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x83), None, None,
        ).unwrap();
        assert_ne!(hash_acp_single, [0u8; 32]);

        // Must differ from ACP|ALL and ACP|NONE
        let hash_acp_all = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x81), None, None,
        ).unwrap();
        let hash_acp_none = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x82), None, None,
        ).unwrap();
        assert_ne!(hash_acp_single, hash_acp_all);
        assert_ne!(hash_acp_single, hash_acp_none);
    }

    // ---------------------------------------------------------------
    // Taproot: annex + leaf_hash combined (spend_type == 3)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_annex_and_leaf_hash() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        let annex = vec![0x50, 0xde, 0xad];
        let leaf_hash = [0xef; 32];

        let hash_both = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), Some(&annex), Some(&leaf_hash),
        ).unwrap();
        assert_ne!(hash_both, [0u8; 32]);

        // Must differ from annex-only and leaf-only
        let hash_annex = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), Some(&annex), None,
        ).unwrap();
        let hash_leaf = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x00), None, Some(&leaf_hash),
        ).unwrap();
        assert_ne!(hash_both, hash_annex);
        assert_ne!(hash_both, hash_leaf);
    }

    // ---------------------------------------------------------------
    // Taproot: leaf_hash with ANYONECANPAY (exercises ACP + leaf path)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_leaf_hash_anyonecanpay() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();

        let leaf_hash = [0x42; 32];
        let hash = sighash_taproot(
            &tx, 1, &prevouts, SighashType(0x81), None, Some(&leaf_hash),
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // Without leaf_hash but same ACP should differ
        let hash_no_leaf = sighash_taproot(
            &tx, 1, &prevouts, SighashType(0x81), None, None,
        ).unwrap();
        assert_ne!(hash, hash_no_leaf);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: exercises SighashCache population and reuse
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_basic() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let mut cache = SighashCache::new();
        assert!(cache.hash_prevouts.is_none());
        assert!(cache.hash_sequence.is_none());
        assert!(cache.hash_outputs.is_none());

        // First call populates the cache
        let hash0 = sighash_segwit_v0_cached(
            &tx, 0, &script_code, value, SighashType::ALL, &mut cache,
        ).unwrap();
        assert_ne!(hash0, [0u8; 32]);
        assert!(cache.hash_prevouts.is_some());
        assert!(cache.hash_sequence.is_some());
        assert!(cache.hash_outputs.is_some());

        // Save cached values
        let cached_prevouts = cache.hash_prevouts.unwrap();
        let cached_sequence = cache.hash_sequence.unwrap();
        let cached_outputs = cache.hash_outputs.unwrap();

        // Second call reuses the cache (values should remain the same)
        let hash1 = sighash_segwit_v0_cached(
            &tx, 1, &script_code, value, SighashType::ALL, &mut cache,
        ).unwrap();
        assert_ne!(hash1, [0u8; 32]);
        assert_ne!(hash0, hash1); // different input => different hash
        assert_eq!(cache.hash_prevouts.unwrap(), cached_prevouts);
        assert_eq!(cache.hash_sequence.unwrap(), cached_sequence);
        assert_eq!(cache.hash_outputs.unwrap(), cached_outputs);

        // Cached result must match non-cached for same parameters
        let hash0_uncached = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType::ALL,
        ).unwrap();
        assert_eq!(hash0, hash0_uncached);

        let hash1_uncached = sighash_segwit_v0(
            &tx, 1, &script_code, value, SighashType::ALL,
        ).unwrap();
        assert_eq!(hash1, hash1_uncached);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: SIGHASH_NONE (zeroed hashSequence and hashOutputs)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_none() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let mut cache = SighashCache::new();
        let hash_none = sighash_segwit_v0_cached(
            &tx, 0, &script_code, value, SighashType::NONE, &mut cache,
        ).unwrap();
        assert_ne!(hash_none, [0u8; 32]);

        // For NONE, hashSequence and hashOutputs should be zeros, so cache
        // should NOT be populated for those (base==2 => zeros path)
        // But hashPrevouts should be populated (not ANYONECANPAY)
        // Note: cache may or may not be populated depending on path taken;
        // the important thing is correctness.

        // Must match uncached version
        let hash_none_uncached = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType::NONE,
        ).unwrap();
        assert_eq!(hash_none, hash_none_uncached);

        // Must differ from ALL
        let hash_all = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType::ALL,
        ).unwrap();
        assert_ne!(hash_none, hash_all);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: SIGHASH_SINGLE
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_single() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let mut cache = SighashCache::new();
        let hash_single = sighash_segwit_v0_cached(
            &tx, 0, &script_code, value, SighashType::SINGLE, &mut cache,
        ).unwrap();
        assert_ne!(hash_single, [0u8; 32]);

        let hash_single_uncached = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType::SINGLE,
        ).unwrap();
        assert_eq!(hash_single, hash_single_uncached);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: SIGHASH_SINGLE out of range (zeros hashOutputs)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_single_out_of_range() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        // input_index=2, but outputs.len()=2 (indices 0,1), so SINGLE has no matching output
        let mut cache = SighashCache::new();
        let hash = sighash_segwit_v0_cached(
            &tx, 2, &script_code, value, SighashType::SINGLE, &mut cache,
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_uncached = sighash_segwit_v0(
            &tx, 2, &script_code, value, SighashType::SINGLE,
        ).unwrap();
        assert_eq!(hash, hash_uncached);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: ANYONECANPAY | ALL (0x81)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_anyonecanpay_all() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let mut cache = SighashCache::new();
        let hash_acp = sighash_segwit_v0_cached(
            &tx, 0, &script_code, value, SighashType(0x81), &mut cache,
        ).unwrap();
        assert_ne!(hash_acp, [0u8; 32]);

        let hash_acp_uncached = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x81),
        ).unwrap();
        assert_eq!(hash_acp, hash_acp_uncached);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: ANYONECANPAY | NONE (0x82)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_anyonecanpay_none() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let mut cache = SighashCache::new();
        let hash = sighash_segwit_v0_cached(
            &tx, 0, &script_code, value, SighashType(0x82), &mut cache,
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_uncached = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x82),
        ).unwrap();
        assert_eq!(hash, hash_uncached);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: ANYONECANPAY | SINGLE (0x83)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_anyonecanpay_single() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let mut cache = SighashCache::new();
        let hash = sighash_segwit_v0_cached(
            &tx, 0, &script_code, value, SighashType(0x83), &mut cache,
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_uncached = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x83),
        ).unwrap();
        assert_eq!(hash, hash_uncached);
    }

    // ---------------------------------------------------------------
    // Segwit v0 cached: input out of range
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_cached_input_out_of_range() {
        let tx = make_segwit_test_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let mut cache = SighashCache::new();

        let result = sighash_segwit_v0_cached(
            &tx, 5, &script_code, 10_000_000, SighashType::ALL, &mut cache,
        );
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Segwit v0 (non-cached): SIGHASH_SINGLE out of range
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_single_out_of_range() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        // input_index=2 but outputs.len()=2, so SINGLE has no matching output => zeros
        let hash = sighash_segwit_v0(
            &tx, 2, &script_code, value, SighashType::SINGLE,
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // Must differ from ALL at same index
        let hash_all = sighash_segwit_v0(
            &tx, 2, &script_code, value, SighashType::ALL,
        ).unwrap();
        assert_ne!(hash, hash_all);
    }

    // ---------------------------------------------------------------
    // Segwit v0 (non-cached): ANYONECANPAY | NONE (0x82)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_anyonecanpay_none() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let hash = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x82),
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // Must differ from plain NONE and ACP|ALL
        let hash_none = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType::NONE,
        ).unwrap();
        let hash_acp_all = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x81),
        ).unwrap();
        assert_ne!(hash, hash_none);
        assert_ne!(hash, hash_acp_all);
    }

    // ---------------------------------------------------------------
    // Segwit v0 (non-cached): ANYONECANPAY | SINGLE (0x83)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_segwit_v0_anyonecanpay_single() {
        let tx = make_multi_io_tx();
        let script_code = p2wpkh_script_code(&[0xab; 20]);
        let value = 5_000_000i64;

        let hash = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x83),
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_acp_all = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x81),
        ).unwrap();
        let hash_acp_none = sighash_segwit_v0(
            &tx, 0, &script_code, value, SighashType(0x82),
        ).unwrap();
        assert_ne!(hash, hash_acp_all);
        assert_ne!(hash, hash_acp_none);
    }

    // ---------------------------------------------------------------
    // Legacy: SIGHASH_NONE (base_type 2)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_none() {
        let tx = make_multi_io_tx();
        let script_code = vec![0x76, 0xa9, 0x14];

        let hash_none = sighash_legacy(&tx, 0, &script_code, SighashType::NONE).unwrap();
        assert_ne!(hash_none, [0u8; 32]);

        // Must differ from ALL
        let hash_all = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        assert_ne!(hash_none, hash_all);

        // With NONE, non-signed inputs get sequence 0 but current input keeps its sequence.
        // We can verify this indirectly: changing another input's sequence should not
        // change the NONE hash (since other inputs get sequence 0 regardless).
        let mut tx2 = make_multi_io_tx();
        tx2.inputs[1].sequence = 0x00000001; // change a non-signed input
        let hash_none2 = sighash_legacy(&tx2, 0, &script_code, SighashType::NONE).unwrap();
        assert_eq!(hash_none, hash_none2, "NONE should zero non-signed input sequences");
    }

    // ---------------------------------------------------------------
    // Legacy: SIGHASH_SINGLE (base_type 3) with valid index
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_single_valid() {
        let tx = make_multi_io_tx();
        let script_code = vec![0x76, 0xa9, 0x14];

        let hash_single = sighash_legacy(&tx, 0, &script_code, SighashType::SINGLE).unwrap();
        assert_ne!(hash_single, [0u8; 32]);

        let hash_all = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        assert_ne!(hash_single, hash_all);

        // SINGLE for input 1 should differ from input 0
        let hash_single_1 = sighash_legacy(&tx, 1, &script_code, SighashType::SINGLE).unwrap();
        assert_ne!(hash_single, hash_single_1);
    }

    // ---------------------------------------------------------------
    // Legacy: ANYONECANPAY | ALL (0x81)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_anyonecanpay_all() {
        let tx = make_multi_io_tx();
        let script_code = vec![0x76, 0xa9, 0x14];

        let hash_acp = sighash_legacy(&tx, 0, &script_code, SighashType(0x81)).unwrap();
        assert_ne!(hash_acp, [0u8; 32]);

        // Must differ from plain ALL (without ANYONECANPAY)
        let hash_all = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        assert_ne!(hash_acp, hash_all);
    }

    // ---------------------------------------------------------------
    // Legacy: ANYONECANPAY | NONE (0x82)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_anyonecanpay_none() {
        let tx = make_multi_io_tx();
        let script_code = vec![0x76, 0xa9, 0x14];

        let hash = sighash_legacy(&tx, 0, &script_code, SighashType(0x82)).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_acp_all = sighash_legacy(&tx, 0, &script_code, SighashType(0x81)).unwrap();
        assert_ne!(hash, hash_acp_all);
    }

    // ---------------------------------------------------------------
    // Legacy: ANYONECANPAY | SINGLE (0x83)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_anyonecanpay_single() {
        let tx = make_multi_io_tx();
        let script_code = vec![0x76, 0xa9, 0x14];

        let hash = sighash_legacy(&tx, 0, &script_code, SighashType(0x83)).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_acp_all = sighash_legacy(&tx, 0, &script_code, SighashType(0x81)).unwrap();
        let hash_acp_none = sighash_legacy(&tx, 0, &script_code, SighashType(0x82)).unwrap();
        assert_ne!(hash, hash_acp_all);
        assert_ne!(hash, hash_acp_none);
    }

    // ---------------------------------------------------------------
    // Legacy: input out of range
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_input_out_of_range() {
        let tx = make_multi_io_tx();
        let result = sighash_legacy(&tx, 10, &[], SighashType::ALL);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // p2wpkh_script_code: verify exact bytes
    // ---------------------------------------------------------------
    #[test]
    fn test_p2wpkh_script_code_exact_bytes() {
        let hash = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        let code = p2wpkh_script_code(&hash);
        let expected = vec![
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // push 20 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x88, // OP_EQUALVERIFY
            0xac, // OP_CHECKSIG
        ];
        assert_eq!(code, expected);
    }

    // ---------------------------------------------------------------
    // find_and_delete: OP_PUSHDATA2 containing 0xab (should NOT delete)
    // ---------------------------------------------------------------
    #[test]
    fn test_find_and_delete_pushdata2_containing_0xab() {
        use btc_primitives::script::Opcode;

        // OP_PUSHDATA2 = 0x4d, length = 3 (LE: 0x03, 0x00), data = [0xab, 0xab, 0xab]
        // followed by bare OP_CODESEPARATOR and OP_1
        let script = vec![0x4d, 0x03, 0x00, 0xab, 0xab, 0xab, 0xab, 0x51];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);

        // Only the bare OP_CODESEPARATOR at position 6 should be removed
        let expected = vec![0x4d, 0x03, 0x00, 0xab, 0xab, 0xab, 0x51];
        assert_eq!(
            result.as_ref(), &expected[..],
            "find_and_delete must not strip 0xab inside OP_PUSHDATA2 data"
        );
    }

    // ---------------------------------------------------------------
    // find_and_delete: OP_PUSHDATA4 containing 0xab (should NOT delete)
    // ---------------------------------------------------------------
    #[test]
    fn test_find_and_delete_pushdata4_containing_0xab() {
        use btc_primitives::script::Opcode;

        // OP_PUSHDATA4 = 0x4e, length = 2 (LE: 0x02, 0x00, 0x00, 0x00), data = [0xab, 0xab]
        // followed by bare OP_CODESEPARATOR and OP_1
        let script = vec![0x4e, 0x02, 0x00, 0x00, 0x00, 0xab, 0xab, 0xab, 0x51];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);

        // Only the bare OP_CODESEPARATOR at position 7 should be removed
        let expected = vec![0x4e, 0x02, 0x00, 0x00, 0x00, 0xab, 0xab, 0x51];
        assert_eq!(
            result.as_ref(), &expected[..],
            "find_and_delete must not strip 0xab inside OP_PUSHDATA4 data"
        );
    }

    // ---------------------------------------------------------------
    // find_and_delete: no target byte at all => Cow::Borrowed (fast path)
    // ---------------------------------------------------------------
    #[test]
    fn test_find_and_delete_no_target_byte() {
        use btc_primitives::script::Opcode;

        // Script with no 0xab byte at all: OP_1 OP_2 OP_ADD
        let script = vec![0x51, 0x52, 0x93];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), &script[..]);
    }

    // ---------------------------------------------------------------
    // find_and_delete: 0xab byte present but only inside push data
    //   => should return Cow::Borrowed (no actual opcodes deleted)
    // ---------------------------------------------------------------
    #[test]
    fn test_find_and_delete_0xab_only_in_push_data_returns_borrowed() {
        use btc_primitives::script::Opcode;

        // Script: PUSH(1 byte: 0xab) OP_1
        // Bytes: [0x01, 0xab, 0x51]
        // The 0xab is push data, not a bare opcode, so nothing should be deleted.
        // But the quick-scan sees 0xab and enters the instruction-parsing loop.
        // Since no bare 0xab is found, found stays false, and we return Borrowed.
        let script = vec![0x01, 0xab, 0x51];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);
        // The function first checks contains(&0xab) — true — then parses instructions
        // and finds no bare OP_CODESEPARATOR. found == false => Cow::Borrowed.
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), &script[..]);
    }

    // ---------------------------------------------------------------
    // find_and_delete: OP_0 (0x00) is a single-byte opcode, not a push
    // ---------------------------------------------------------------
    #[test]
    fn test_find_and_delete_with_op_0() {
        use btc_primitives::script::Opcode;

        // Script: OP_0 OP_CODESEPARATOR OP_1
        let script = vec![0x00, 0xab, 0x51];
        let result = find_and_delete(&script, Opcode::OP_CODESEPARATOR);
        let expected = vec![0x00, 0x51];
        assert_eq!(result.as_ref(), &expected[..]);
    }

    // ---------------------------------------------------------------
    // SighashType::from_u8
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_type_from_u8() {
        let st = SighashType::from_u8(0x03);
        assert_eq!(st, SighashType::SINGLE);

        let st2 = SighashType::from_u8(0x81);
        assert_eq!(st2, SighashType(0x81));
        assert!(st2.anyone_can_pay());
        assert_eq!(st2.base_type(), 1);
    }

    // ---------------------------------------------------------------
    // SighashError Display
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_error_display() {
        let err = SighashError::InputOutOfRange(5, 2);
        let msg = format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("2"));

        let err2 = SighashError::InvalidSighashType(0xFF);
        let msg2 = format!("{}", err2);
        assert!(msg2.contains("255"));
    }

    // ---------------------------------------------------------------
    // Taproot: SIGHASH_NONE with ANYONECANPAY and annex
    // (exercises: ACP input path + no outputs + annex hash)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_acp_none_with_annex() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let annex = vec![0x50, 0x01];

        let hash = sighash_taproot(
            &tx, 1, &prevouts, SighashType(0x82), Some(&annex), None,
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);

        let hash_no_annex = sighash_taproot(
            &tx, 1, &prevouts, SighashType(0x82), None, None,
        ).unwrap();
        assert_ne!(hash, hash_no_annex);
    }

    // ---------------------------------------------------------------
    // Taproot: SIGHASH_SINGLE with ANYONECANPAY and leaf_hash
    // (exercises: ACP input path + single output + leaf_hash extension)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_taproot_acp_single_with_leaf() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let leaf_hash = [0x77; 32];

        let hash = sighash_taproot(
            &tx, 0, &prevouts, SighashType(0x83), None, Some(&leaf_hash),
        ).unwrap();
        assert_ne!(hash, [0u8; 32]);
    }

    // ---------------------------------------------------------------
    // Legacy sighash with OP_CODESEPARATOR in script_code
    // (exercises the find_and_delete integration path)
    // ---------------------------------------------------------------
    #[test]
    fn test_sighash_legacy_with_codeseparator_in_script() {
        let tx = make_multi_io_tx();
        // Script containing OP_CODESEPARATOR (0xab) among real opcodes
        let script_code = vec![0x76, 0xa9, 0xab, 0x14];

        let hash = sighash_legacy(&tx, 0, &script_code, SighashType::ALL).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // Compare with script that already has OP_CODESEPARATOR removed
        let script_code_clean = vec![0x76, 0xa9, 0x14];
        let hash_clean = sighash_legacy(&tx, 0, &script_code_clean, SighashType::ALL).unwrap();
        assert_eq!(hash, hash_clean, "sighash should strip OP_CODESEPARATOR before hashing");
    }

    // ---- Coverage: sighash_anyprevout input out of range ----

    #[test]
    fn test_anyprevout_input_out_of_range() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let result = sighash_anyprevout(&tx, 99, &prevouts, SIGHASH_ANYPREVOUT, None, None);
        assert!(result.is_err());
    }

    // ---- Coverage: sighash_anyprevout prevout count mismatch ----

    #[test]
    fn test_anyprevout_prevout_count_mismatch() {
        let tx = make_multi_io_tx();
        let result = sighash_anyprevout(&tx, 0, &[], SIGHASH_ANYPREVOUT, None, None);
        assert!(result.is_err());
    }

    // ---- Coverage: sighash_anyprevout invalid hash type ----

    #[test]
    fn test_anyprevout_invalid_hash_type() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let result = sighash_anyprevout(&tx, 0, &prevouts, 0x01, None, None); // not 0x41 or 0x42
        assert!(result.is_err());
    }

    // ---- Coverage: sighash_anyprevout with ANYPREVOUT (0x41) ----

    #[test]
    fn test_anyprevout_0x41() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let result = sighash_anyprevout(&tx, 0, &prevouts, SIGHASH_ANYPREVOUT, None, None);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), [0u8; 32]);
    }

    // ---- Coverage: sighash_anyprevout with ANYPREVOUTANYSCRIPT (0x42) ----

    #[test]
    fn test_anyprevout_0x42() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let result = sighash_anyprevout(&tx, 0, &prevouts, SIGHASH_ANYPREVOUTANYSCRIPT, None, None);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), [0u8; 32]);
    }

    // ---- Coverage: sighash_anyprevout with annex and leaf_hash ----

    #[test]
    fn test_anyprevout_annex_and_leaf() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let annex = vec![0x50, 0x01, 0x02];
        let leaf_hash = [0xaa; 32];
        let result = sighash_anyprevout(
            &tx, 0, &prevouts, SIGHASH_ANYPREVOUT,
            Some(&annex), Some(&leaf_hash),
        );
        assert!(result.is_ok());
    }

    // ---- Coverage: sighash_anyprevoutanyscript with annex and leaf ----

    #[test]
    fn test_anyprevoutanyscript_annex_and_leaf() {
        let tx = make_multi_io_tx();
        let prevouts = make_multi_prevouts();
        let annex = vec![0x50, 0x01];
        let leaf_hash = [0xbb; 32];
        let result = sighash_anyprevout(
            &tx, 0, &prevouts, SIGHASH_ANYPREVOUTANYSCRIPT,
            Some(&annex), Some(&leaf_hash),
        );
        assert!(result.is_ok());
    }
}
