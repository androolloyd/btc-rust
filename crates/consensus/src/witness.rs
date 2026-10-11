//! Segregated Witness (BIP141) validation.
//!
//! This module implements witness program verification for BIP141 (segwit v0)
//! and integrates with BIP143 sighash computation. It provides:
//!
//! - `verify_witness_program()` -- validates witness data against a witness program
//! - `verify_input()` -- top-level per-input verification that dispatches based on script type

use crate::script_engine::{ScriptEngine, ScriptFlags};
use crate::sig_verify::SignatureVerifier;
use crate::sighash::p2wpkh_script_code;
#[cfg(test)]
use crate::sighash::{sighash_segwit_v0, SighashType};
use btc_primitives::hash::{hash160, sha256};
#[cfg(test)]
use btc_primitives::script::Opcode;
use btc_primitives::script::{Script, ScriptBuf};
use btc_primitives::transaction::{Transaction, TxOut, Witness};
use thiserror::Error;

/// Errors that can occur during witness verification.
#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("witness program mismatch: expected {expected} bytes, got {got}")]
    ProgramMismatch { expected: usize, got: usize },

    #[error("P2WPKH witness must have exactly 2 items, got {0}")]
    P2wpkhWitnessCount(usize),

    #[error("P2WPKH pubkey hash mismatch")]
    P2wpkhPubkeyMismatch,

    #[error("P2WSH witness script hash mismatch")]
    P2wshScriptMismatch,

    #[error("P2WSH empty witness")]
    P2wshEmptyWitness,

    #[error("witness program version {0} not supported")]
    UnsupportedVersion(u8),

    #[error("empty witness for segwit input")]
    EmptyWitness,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("script execution failed: {0}")]
    ScriptExecution(#[from] crate::script_engine::ScriptError),

    #[error("sighash computation failed: {0}")]
    Sighash(#[from] crate::sighash::SighashError),

    #[error("signature verifier error: {0}")]
    SigVerify(String),

    #[error("input index {0} out of range (tx has {1} inputs)")]
    InputOutOfRange(usize, usize),

    #[error("P2SH-segwit: scriptSig must be a single push of the witness program")]
    P2shSegwitScriptSig,

    #[error("legacy script verification failed")]
    LegacyScriptFailed,

    #[error("P2WSH script execution failed: stack result is false (witness_items={witness_items}, script_len={script_len})")]
    P2wshScriptFailed {
        witness_items: usize,
        script_len: usize,
    },

    #[error("P2SH redeem script verification failed")]
    P2shRedeemFailed,

    #[error("non-empty witness for non-witness input")]
    UnexpectedWitness,

    #[error("scriptSig must be empty for native segwit spend")]
    ScriptSigNotEmpty,
    #[error("Taproot verification requires all transaction prevouts")]
    MissingPrevouts,
}

/// Verify a witness program against its witness data.
///
/// Dispatches based on witness version and program length:
/// - v0, 20-byte program: P2WPKH
/// - v0, 32-byte program: P2WSH
/// - v1+: future versions (succeed if flag not set, per soft-fork rules)
pub fn verify_witness_program(
    version: u8,
    program: &[u8],
    witness: &Witness,
    tx: &Transaction,
    input_index: usize,
    input_amount: i64,
    sig_verifier: &dyn SignatureVerifier,
    flags: &ScriptFlags,
) -> Result<(), WitnessError> {
    // Per Bitcoin Core: the empty witness check is done per-version,
    // NOT globally. Unknown future versions (v1 non-32-byte, v2-v16)
    // succeed even with empty witness (soft-fork safe).
    match version {
        0 => {
            // v0 requires non-empty witness
            if witness.is_empty() {
                return Err(WitnessError::EmptyWitness);
            }
            match program.len() {
                20 => verify_p2wpkh(
                    program,
                    witness,
                    tx,
                    input_index,
                    input_amount,
                    sig_verifier,
                    flags,
                ),
                32 => verify_p2wsh(
                    program,
                    witness,
                    tx,
                    input_index,
                    input_amount,
                    sig_verifier,
                    flags,
                ),
                other => Err(WitnessError::ProgramMismatch {
                    expected: 20,
                    got: other,
                }),
            }
        }
        1 if program.len() == 32 => {
            if !flags.verify_taproot {
                return Ok(());
            }
            if witness.is_empty() {
                return Err(WitnessError::EmptyWitness);
            }
            if tx.inputs.len() != 1 {
                return Err(WitnessError::MissingPrevouts);
            }
            let output = TxOut {
                value: btc_primitives::amount::Amount::from_sat(input_amount),
                script_pubkey: ScriptBuf::p2tr(&program.try_into().unwrap()),
            };
            crate::taproot::verify_taproot_input(
                &program.try_into().unwrap(),
                witness,
                tx,
                input_index,
                &[output],
                sig_verifier,
                flags,
            )
            .map_err(|e| WitnessError::SigVerify(e.to_string()))
        }
        v if v >= 2 => {
            // Future witness versions: succeed unconditionally (soft-fork safe).
            // This is required by BIP141 so that old nodes don't reject future upgrades.
            Ok(())
        }
        _ => {
            // v1 with non-32-byte program: also future-safe
            Ok(())
        }
    }
}

/// Verify a P2WPKH witness spend.
///
/// BIP141 rules for P2WPKH (witness v0, 20-byte program):
/// 1. Witness must have exactly 2 items: [signature, pubkey]
/// 2. HASH160(pubkey) must equal the 20-byte program
/// 3. Build the BIP143 script_code as P2PKH equivalent
/// 4. Compute sighash via `sighash_segwit_v0()`
/// 5. Verify the ECDSA signature
fn verify_p2wpkh(
    program: &[u8],
    witness: &Witness,
    tx: &Transaction,
    input_index: usize,
    input_amount: i64,
    sig_verifier: &dyn SignatureVerifier,
    flags: &ScriptFlags,
) -> Result<(), WitnessError> {
    // Witness must have exactly 2 items: [signature, pubkey]
    if witness.len() != 2 {
        return Err(WitnessError::P2wpkhWitnessCount(witness.len()));
    }

    let sig = witness.get(0).unwrap();
    let pubkey = witness.get(1).unwrap();

    // Verify HASH160(pubkey) == program
    let pubkey_hash = hash160(pubkey);
    if pubkey_hash[..] != program[..] {
        return Err(WitnessError::P2wpkhPubkeyMismatch);
    }

    // Empty signature is a failure (not an error, but the spend is invalid)
    if sig.is_empty() {
        return Err(WitnessError::SignatureVerificationFailed);
    }

    // Build script_code as P2PKH equivalent for BIP143
    let program_array: [u8; 20] =
        program
            .try_into()
            .map_err(|_| WitnessError::ProgramMismatch {
                expected: 20,
                got: program.len(),
            })?;
    let script_code = p2wpkh_script_code(&program_array);

    // Execute the implied CHECKSIG script, including the active DER and
    // encoding flags; a direct equation-only call bypasses those script rules.
    let mut engine = ScriptEngine::new(sig_verifier, *flags, Some(tx), input_index, input_amount);
    engine.set_segwit_sighash(true);
    engine.set_witness_execution(true);
    match engine.verify_witness_script(
        Script::from_bytes(&script_code),
        witness.iter().map(Vec::as_slice),
    ) {
        Ok(()) => Ok(()),
        Err(
            crate::script_engine::ScriptError::EvalFalse
            | crate::script_engine::ScriptError::NullFail,
        ) => Err(WitnessError::SignatureVerificationFailed),
        Err(error) => Err(error.into()),
    }
}

/// Verify a P2WSH witness spend.
///
/// BIP141 rules for P2WSH (witness v0, 32-byte program):
/// 1. The last witness item is the witness script
/// 2. SHA256(witness_script) must equal the 32-byte program
/// 3. Execute the witness script with remaining witness items as stack
/// 4. CHECKSIG operations within use BIP143 sighash
fn verify_p2wsh(
    program: &[u8],
    witness: &Witness,
    tx: &Transaction,
    input_index: usize,
    input_amount: i64,
    sig_verifier: &dyn SignatureVerifier,
    flags: &ScriptFlags,
) -> Result<(), WitnessError> {
    if witness.is_empty() {
        return Err(WitnessError::P2wshEmptyWitness);
    }

    // Last witness item is the witness script
    let witness_script_bytes = witness.get(witness.len() - 1).unwrap();

    // Verify SHA256(witness_script) == program
    let script_hash = sha256(witness_script_bytes);
    if script_hash[..] != program[..] {
        return Err(WitnessError::P2wshScriptMismatch);
    }

    // Create a ScriptEngine in segwit sighash mode. When enabled, the engine
    // computes BIP143 sighash (using the post-OP_CODESEPARATOR scriptCode)
    // instead of legacy sighash for CHECKSIG/CHECKMULTISIG operations.
    let mut engine = ScriptEngine::new(sig_verifier, *flags, Some(tx), input_index, input_amount);
    engine.set_segwit_sighash(true);
    engine.set_witness_execution(true);

    // Initialize the real witness stack, without executing its data as pushes.
    let witness_script = Script::from_bytes(witness_script_bytes);
    match engine.verify_witness_script(
        witness_script,
        witness.iter().take(witness.len() - 1).map(Vec::as_slice),
    ) {
        Ok(()) => Ok(()),
        Err(crate::script_engine::ScriptError::EvalFalse) => Err(WitnessError::P2wshScriptFailed {
            witness_items: witness.len(),
            script_len: witness_script_bytes.len(),
        }),
        Err(error) => Err(error.into()),
    }
}

/// Verify with every spent output, as required by non-ANYONECANPAY BIP341
/// signatures. Legacy and SegWit v0 verification use the selected output.
pub fn verify_input_with_prevouts(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    sig_verifier: &dyn SignatureVerifier,
    flags: &ScriptFlags,
) -> Result<(), WitnessError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(WitnessError::MissingPrevouts);
    }
    let output = prevouts
        .get(input_index)
        .ok_or(WitnessError::InputOutOfRange(input_index, tx.inputs.len()))?;
    if flags.verify_witness && flags.verify_taproot && output.script_pubkey.is_p2tr() {
        if !tx.inputs[input_index].script_sig.is_empty() {
            return Err(WitnessError::ScriptSigNotEmpty);
        }
        let witness = tx
            .witness
            .get(input_index)
            .ok_or(WitnessError::EmptyWitness)?;
        let key = output.script_pubkey.as_bytes()[2..].try_into().unwrap();
        return crate::taproot::verify_taproot_input(
            &key,
            witness,
            tx,
            input_index,
            prevouts,
            sig_verifier,
            flags,
        )
        .map_err(|e| WitnessError::SigVerify(e.to_string()));
    }
    verify_input(tx, input_index, output, sig_verifier, flags)
}

/// Top-level per-input verification.
///
/// Determines the script type from the previous output's script_pubkey and dispatches
/// to the appropriate verification path:
/// - P2WPKH / P2WSH / P2TR: verify_witness_program
/// - P2SH wrapping segwit: extract witness program from scriptSig, verify
/// - P2SH (non-segwit): execute redeem script
/// - Legacy (P2PKH, bare scripts): run through ScriptEngine
pub fn verify_input(
    tx: &Transaction,
    input_index: usize,
    prev_output: &TxOut,
    sig_verifier: &dyn SignatureVerifier,
    flags: &ScriptFlags,
) -> Result<(), WitnessError> {
    if input_index >= tx.inputs.len() {
        return Err(WitnessError::InputOutOfRange(input_index, tx.inputs.len()));
    }

    let script_pubkey = prev_output.script_pubkey.as_script();
    let input_amount = prev_output.value.as_sat();

    // Check for native segwit outputs
    if script_pubkey.is_witness_program() && flags.verify_witness {
        let spk_bytes = script_pubkey.as_bytes();
        // Extract witness version and program
        let version = match spk_bytes[0] {
            0x00 => 0u8,                                 // OP_0
            v if (0x51..=0x60).contains(&v) => v - 0x50, // OP_1..OP_16
            _ => return Err(WitnessError::UnsupportedVersion(spk_bytes[0])),
        };
        let program = &spk_bytes[2..]; // skip version byte and push length byte

        // For native segwit, scriptSig MUST be empty (BIP141 anti-malleability)
        if !tx.inputs[input_index].script_sig.is_empty() {
            return Err(WitnessError::ScriptSigNotEmpty);
        }

        // Get the witness for this input.
        let witness = if input_index < tx.witness.len() {
            tx.witness[input_index].clone()
        } else {
            // No witness data — use empty witness.
            // For unknown future versions (v1 non-32-byte, v2-v16), empty
            // witness is valid (soft-fork safe per BIP141).
            btc_primitives::transaction::Witness::new()
        };

        return verify_witness_program(
            version,
            program,
            &witness,
            tx,
            input_index,
            input_amount,
            sig_verifier,
            flags,
        );
    } else if script_pubkey.is_witness_program() && !flags.verify_witness {
        // Witness flag not set — treat as legacy (succeed)
        return Ok(());
    }

    // BIP16 requires execution of the redeem script for every P2SH scriptSig,
    // including signature/data pushes preceding the script. Never fall through
    // to hash-only legacy validation just because there is more than one push.
    if script_pubkey.is_p2sh() && flags.verify_p2sh {
        let script_sig = tx.inputs[input_index].script_sig.as_script();
        if !crate::script_engine::is_push_only(script_sig) {
            return Err(crate::script_engine::ScriptError::SigPushOnly.into());
        }
        let mut engine =
            ScriptEngine::new(sig_verifier, *flags, Some(tx), input_index, input_amount);
        engine.execute(script_sig)?;
        let mut initial_stack = engine.stack().to_vec();
        engine.clear_altstack();
        engine.execute(script_pubkey)?;
        if !engine.success() {
            return Err(WitnessError::P2shRedeemFailed);
        }
        let redeem_script = initial_stack.pop().ok_or(WitnessError::P2shRedeemFailed)?;
        let redeem = Script::from_bytes(&redeem_script);
        let mut redeem_engine =
            ScriptEngine::new(sig_verifier, *flags, Some(tx), input_index, input_amount);
        for item in initial_stack {
            redeem_engine.push_item(item)?;
        }
        redeem_engine.execute(redeem)?;
        if !redeem_engine.success() {
            return Err(WitnessError::P2shRedeemFailed);
        }
        // Witness interpretation is activated by its flag. Before activation,
        // the same redeem bytes are evaluated only as a legacy script.
        if flags.verify_witness && redeem.is_witness_program() {
            let mut canonical = ScriptBuf::new();
            canonical.push_slice(&redeem_script);
            if tx.inputs[input_index].script_sig != canonical {
                return Err(WitnessError::P2shSegwitScriptSig);
            }
            let bytes = redeem.as_bytes();
            let version = if bytes[0] == 0 { 0 } else { bytes[0] - 0x50 };
            let witness = tx.witness.get(input_index).cloned().unwrap_or_default();
            let mut nested_flags = *flags;
            // BIP341 applies only to native v1/32-byte outputs. P2SH-wrapped
            // v1 programs retain the future-version consensus semantics.
            nested_flags.verify_taproot = false;
            return verify_witness_program(
                version,
                &bytes[2..],
                &witness,
                tx,
                input_index,
                input_amount,
                sig_verifier,
                &nested_flags,
            );
        }
        redeem_engine.check_cleanstack()?;
        if flags.verify_witness && tx.witness.get(input_index).is_some_and(|w| !w.is_empty()) {
            return Err(WitnessError::UnexpectedWitness);
        }
        return Ok(());
    }

    // Legacy script verification: run scriptSig + scriptPubKey
    let mut engine = ScriptEngine::new(sig_verifier, *flags, Some(tx), input_index, input_amount);

    // Execute scriptSig first
    let script_sig = &tx.inputs[input_index].script_sig;
    engine.execute(script_sig.as_script())?;

    // Each script has an independent altstack, as in Core EvalScript.
    engine.clear_altstack();
    // Then execute scriptPubKey
    engine.execute(script_pubkey)?;

    if !engine.success() {
        return Err(WitnessError::LegacyScriptFailed);
    }
    engine.check_cleanstack()?;

    // BIP141: reject non-empty witness for non-witness inputs
    if flags.verify_witness {
        let witness = tx.witness.get(input_index).cloned().unwrap_or_default();
        if !witness.is_empty() {
            return Err(WitnessError::UnexpectedWitness);
        }
    }

    Ok(())
}

/// Extract a single push from a script. Returns the pushed data if the script
/// consists of exactly one push operation, or None otherwise.
#[cfg(test)]
fn extract_single_push(script: &[u8]) -> Option<&[u8]> {
    if script.is_empty() {
        return None;
    }

    let first = script[0];
    let (data, consumed) = if first == 0 {
        // OP_0
        (&script[1..1], 1)
    } else if (1..=75).contains(&first) {
        let len = first as usize;
        if script.len() < 1 + len {
            return None;
        }
        (&script[1..1 + len], 1 + len)
    } else if first == Opcode::OP_PUSHDATA1 as u8 {
        if script.len() < 2 {
            return None;
        }
        let len = script[1] as usize;
        if script.len() < 2 + len {
            return None;
        }
        (&script[2..2 + len], 2 + len)
    } else if first == Opcode::OP_PUSHDATA2 as u8 {
        if script.len() < 3 {
            return None;
        }
        let len = u16::from_le_bytes([script[1], script[2]]) as usize;
        if script.len() < 3 + len {
            return None;
        }
        (&script[3..3 + len], 3 + len)
    } else {
        return None;
    };

    // Must have consumed the entire script
    if consumed == script.len() {
        Some(data)
    } else {
        None
    }
}

/// Extract all push data items from a push-only script.
#[cfg(test)]
fn extract_all_pushes(script: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < script.len() {
        let opcode = script[pos];

        if opcode == 0 {
            result.push(&script[pos + 1..pos + 1]); // empty push
            pos += 1;
        } else if (1..=75).contains(&opcode) {
            let len = opcode as usize;
            if pos + 1 + len > script.len() {
                break;
            }
            result.push(&script[pos + 1..pos + 1 + len]);
            pos += 1 + len;
        } else if opcode == Opcode::OP_PUSHDATA1 as u8 {
            if pos + 2 > script.len() {
                break;
            }
            let len = script[pos + 1] as usize;
            if pos + 2 + len > script.len() {
                break;
            }
            result.push(&script[pos + 2..pos + 2 + len]);
            pos += 2 + len;
        } else if opcode == Opcode::OP_PUSHDATA2 as u8 {
            if pos + 3 > script.len() {
                break;
            }
            let len = u16::from_le_bytes([script[pos + 1], script[pos + 2]]) as usize;
            if pos + 3 + len > script.len() {
                break;
            }
            result.push(&script[pos + 3..pos + 3 + len]);
            pos += 3 + len;
        } else {
            // Not a push opcode; stop parsing
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig_verify::Secp256k1Verifier;
    use btc_primitives::amount::Amount;
    use btc_primitives::hash::TxHash;
    use btc_primitives::transaction::{OutPoint, TxIn};

    #[test]
    fn witness_arguments_are_data_and_cleanstack_is_consensus() {
        let verifier = Secp256k1Verifier;
        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([1; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![],
            witness: vec![],
            lock_time: 0,
        };
        for wrapped in [false, true] {
            for (script, arguments, expected) in [
                (vec![0x51], vec![], true),
                (vec![0x51], vec![vec![1]], false),
                (vec![], vec![vec![1]], true),
                (vec![], vec![vec![0x80]], false),
                (vec![0x75, 0x51], vec![vec![1]], true),
                (vec![0x75, 0x51], vec![vec![2]], true),
                (vec![0x75, 0x51], vec![vec![0; 520]], true),
                (vec![0x75, 0x51], vec![vec![0; 521]], false),
                (
                    [vec![0x75; 20], vec![0x51]].concat(),
                    vec![vec![0; 520]; 20],
                    true,
                ),
            ] {
                let program = ScriptBuf::p2wsh(&sha256(&script));
                let previous = TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: if wrapped {
                        ScriptBuf::p2sh(&hash160(program.as_bytes()))
                    } else {
                        program.clone()
                    },
                };
                tx.inputs[0].script_sig = if wrapped {
                    let mut s = ScriptBuf::new();
                    s.push_slice(program.as_bytes());
                    s
                } else {
                    ScriptBuf::new()
                };
                let mut items = arguments;
                items.push(script);
                tx.witness = vec![Witness::from_items(items)];
                for flags in [ScriptFlags::consensus(), ScriptFlags::all()] {
                    assert_eq!(
                        verify_input_with_prevouts(&tx, 0, &[previous.clone()], &verifier, &flags)
                            .is_ok(),
                        expected,
                        "wrapped={wrapped}, witness={:?}, flags={flags:?}",
                        tx.witness
                    );
                }
            }
        }
    }

    #[test]
    fn p2wpkh_enforces_der_in_script_context() {
        let key = secp256k1::SecretKey::from_slice(&[17; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &key)
            .serialize()
            .to_vec();
        let program = hash160(&pubkey);
        let previous = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2wpkh(&program),
        };
        let mut tx = make_simple_tx(Witness::new());
        let digest = sighash_segwit_v0(
            &tx,
            0,
            &p2wpkh_script_code(&program),
            50_000,
            SighashType::ALL,
        )
        .unwrap();
        let signature = sign_sighash(&key, &digest, SighashType::ALL);
        tx.witness = vec![Witness::from_items(vec![signature.clone(), pubkey.clone()])];
        assert!(verify_input(
            &tx,
            0,
            &previous,
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_ok());
        // Redundant zero in R leaves the same ECDSA equation and is accepted
        // by historical lax DER parsing, but is invalid after BIP66 activation.
        let mut lax = signature.clone();
        lax[1] += 1;
        lax[3] += 1;
        lax.insert(4, 0);
        assert!(Secp256k1Verifier
            .verify_ecdsa(&digest, &lax[..lax.len() - 1], &pubkey)
            .unwrap());
        tx.witness[0] = Witness::from_items(vec![lax, pubkey]);
        let mut flags = ScriptFlags::consensus();
        flags.verify_dersig = false;
        assert!(verify_input(&tx, 0, &previous, &Secp256k1Verifier, &flags).is_ok());
        flags.verify_dersig = true;
        assert!(verify_input(&tx, 0, &previous, &Secp256k1Verifier, &flags).is_err());
    }

    fn p2sh_case(redeem: &[u8], script_sig: ScriptBuf) -> (Transaction, TxOut) {
        (
            Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x16; 32]), 0),
                    script_sig,
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(49_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
                witness: vec![],
                lock_time: 0,
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::p2sh(&hash160(redeem)),
            },
        )
    }

    #[test]
    fn p2sh_multiple_pushes_cannot_skip_false_redeem_scripts_or_push_only() {
        let redeem = [0x00]; // OP_FALSE: its hash alone is insufficient.
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_slice(&redeem);
        let (tx, output) = p2sh_case(&redeem, script.clone());
        assert!(verify_input_with_prevouts(
            &tx,
            0,
            std::slice::from_ref(&output),
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_err());
        let mut old = ScriptFlags::consensus();
        old.verify_p2sh = false;
        assert!(verify_input(&tx, 0, &output, &Secp256k1Verifier, &old).is_ok());
        // Restore the actual scriptSig stack, including small-number opcodes.
        let redeem = [0x5b, 0x87]; // 11 EQUAL
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_11);
        script.push_slice(&redeem);
        let (mut tx, output) = p2sh_case(&redeem, script.clone());
        assert!(verify_input(
            &tx,
            0,
            &output,
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_ok());
        tx.inputs[0].script_sig = {
            let mut s = ScriptBuf::new();
            s.push_opcode(Opcode::OP_12);
            s.push_slice(&redeem);
            s
        };
        assert!(verify_input(
            &tx,
            0,
            &output,
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_err());
        tx.inputs[0].script_sig =
            ScriptBuf::from_bytes([vec![0x61], script.as_bytes().to_vec()].concat());
        // SIGPUSHONLY is a BIP16 requirement even when its policy flag is false.
        assert!(matches!(
            verify_input(
                &tx,
                0,
                &output,
                &Secp256k1Verifier,
                &ScriptFlags::consensus()
            ),
            Err(WitnessError::ScriptExecution(
                crate::script_engine::ScriptError::SigPushOnly
            ))
        ));
    }

    #[test]
    fn p2sh_cleanstack_unexpected_witness_and_redeem_size_are_enforced() {
        let redeem = [0x51];
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_11);
        script.push_slice(&redeem);
        let (mut tx, output) = p2sh_case(&redeem, script);
        assert!(verify_input(
            &tx,
            0,
            &output,
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_ok());
        assert!(verify_input(&tx, 0, &output, &Secp256k1Verifier, &ScriptFlags::all()).is_err());
        tx.inputs[0].script_sig = {
            let mut s = ScriptBuf::new();
            s.push_slice(&redeem);
            s
        };
        tx.witness = vec![Witness::from_items(vec![vec![1]])];
        assert!(matches!(
            verify_input(
                &tx,
                0,
                &output,
                &Secp256k1Verifier,
                &ScriptFlags::consensus()
            ),
            Err(WitnessError::UnexpectedWitness)
        ));
        for len in [520, 521] {
            let mut redeem = vec![0x4d];
            redeem.extend_from_slice(&((len - 5) as u16).to_le_bytes());
            redeem.extend(vec![1; len - 5]);
            redeem.extend([0x75, 0x51]); // push, DROP, TRUE
            assert_eq!(redeem.len(), len);
            let mut script = ScriptBuf::new();
            script.push_slice(&redeem);
            let (tx, output) = p2sh_case(&redeem, script);
            assert_eq!(
                verify_input(
                    &tx,
                    0,
                    &output,
                    &Secp256k1Verifier,
                    &ScriptFlags::consensus()
                )
                .is_ok(),
                len == 520
            );
        }
    }

    #[test]
    fn nested_witness_requires_exact_push_and_respects_activation() {
        let witness_script = vec![0x51];
        let redeem = ScriptBuf::p2wsh(&sha256(&witness_script));
        let mut canonical = ScriptBuf::new();
        canonical.push_slice(redeem.as_bytes());
        let (mut tx, output) = p2sh_case(redeem.as_bytes(), canonical.clone());
        let mut before = ScriptFlags::consensus();
        before.verify_witness = false;
        assert!(verify_input(&tx, 0, &output, &Secp256k1Verifier, &before).is_ok());
        assert!(verify_input(
            &tx,
            0,
            &output,
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_err());
        tx.witness = vec![Witness::from_items(vec![witness_script])];
        assert!(verify_input(&tx, 0, &output, &Secp256k1Verifier, &ScriptFlags::all()).is_ok());
        // Even consensus without MINIMALDATA requires this exact single push.
        tx.inputs[0].script_sig = ScriptBuf::from_bytes(
            [vec![0x4c, redeem.len() as u8], redeem.as_bytes().to_vec()].concat(),
        );
        assert!(matches!(
            verify_input(
                &tx,
                0,
                &output,
                &Secp256k1Verifier,
                &ScriptFlags::consensus()
            ),
            Err(WitnessError::P2shSegwitScriptSig)
        ));
        tx.inputs[0].script_sig =
            ScriptBuf::from_bytes([vec![0x51], canonical.as_bytes().to_vec()].concat());
        assert!(matches!(
            verify_input(
                &tx,
                0,
                &output,
                &Secp256k1Verifier,
                &ScriptFlags::consensus()
            ),
            Err(WitnessError::P2shSegwitScriptSig)
        ));
        // Wrapped v1/32-byte is not native Taproot, and future versions can
        // carry an empty witness. Keep Core's forward-compatible consensus rule.
        for version in [0x51, 0x52] {
            let mut redeem = vec![version, 32];
            redeem.extend([1; 32]);
            let mut script = ScriptBuf::new();
            script.push_slice(&redeem);
            let (tx, output) = p2sh_case(&redeem, script);
            assert!(verify_input(
                &tx,
                0,
                &output,
                &Secp256k1Verifier,
                &ScriptFlags::consensus()
            )
            .is_ok());
        }
    }

    #[test]
    fn legacy_script_phases_cannot_share_altstack_or_ignore_cleanstack() {
        let script = ScriptBuf::from_bytes(vec![0x51, 0x6b, 0x51]); // 1 TOALTSTACK 1
        let (tx, mut output) = p2sh_case(&[0x51], script);
        output.script_pubkey = ScriptBuf::from_bytes(vec![0x6c]); // FROMALTSTACK
        assert!(verify_input(&tx, 0, &output, &Secp256k1Verifier, &ScriptFlags::none()).is_err());
        let (tx, mut output) = p2sh_case(&[0x51], ScriptBuf::from_bytes(vec![0x51]));
        output.script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        assert!(verify_input(
            &tx,
            0,
            &output,
            &Secp256k1Verifier,
            &ScriptFlags::consensus()
        )
        .is_ok());
        assert!(verify_input(&tx, 0, &output, &Secp256k1Verifier, &ScriptFlags::all()).is_err());
    }

    /// Helper: create a keypair and return (secret_key, compressed_pubkey_bytes)
    fn generate_keypair() -> (secp256k1::SecretKey, Vec<u8>) {
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pubkey_bytes = pk.serialize().to_vec(); // 33-byte compressed
        (sk, pubkey_bytes)
    }

    /// Helper: sign a sighash with a secret key, return DER sig + sighash type byte
    fn sign_sighash(
        sk: &secp256k1::SecretKey,
        sighash: &[u8; 32],
        hash_type: SighashType,
    ) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::signing_only();
        let msg = secp256k1::Message::from_digest(*sighash);
        let sig = secp.sign_ecdsa(&msg, sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(hash_type.0 as u8);
        sig_bytes
    }

    /// Helper: build a simple transaction with one input and one output
    fn make_simple_tx(witness: Witness) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::p2wpkh(&[0xbb; 20]),
            }],
            witness: vec![witness],
            lock_time: 0,
        }
    }

    #[test]
    fn test_p2wpkh_verification_with_real_keypair() {
        let verifier = Secp256k1Verifier;
        let (sk, pubkey) = generate_keypair();

        // Compute the pubkey hash (the witness program)
        let pubkey_hash = hash160(&pubkey);

        // Build the P2WPKH scriptPubKey: OP_0 <20-byte-hash>
        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        assert!(script_pubkey.is_p2wpkh());

        let input_amount: i64 = 50_000;

        // Build the transaction (without witness first, to compute sighash)
        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::ALL)
            .expect("sighash computation should succeed");

        // Sign
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Build witness
        let witness = Witness::from_items(vec![sig, pubkey.clone()]);
        tx.witness = vec![witness.clone()];

        // Verify using verify_witness_program
        let program = &script_pubkey.as_bytes()[2..]; // skip OP_0 and push-length
        let flags = ScriptFlags::all();
        let result = verify_witness_program(
            0,
            program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WPKH verification should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wpkh_wrong_pubkey_hash_fails() {
        let verifier = Secp256k1Verifier;
        let (sk, pubkey) = generate_keypair();

        let pubkey_hash = hash160(&pubkey);

        let input_amount: i64 = 50_000;

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Sign with the correct key
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash =
            sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::ALL).unwrap();
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        let witness = Witness::from_items(vec![sig, pubkey]);

        // Use a WRONG program (different hash)
        let wrong_program = [0xddu8; 20];
        let flags = ScriptFlags::all();
        let result = verify_witness_program(
            0,
            &wrong_program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(result.is_err(), "P2WPKH with wrong pubkey hash should fail");
        match result.unwrap_err() {
            WitnessError::P2wpkhPubkeyMismatch => {} // expected
            other => panic!("Expected P2wpkhPubkeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_p2wpkh_wrong_witness_count_fails() {
        let verifier = Secp256k1Verifier;
        let program = [0xaau8; 20];
        let flags = ScriptFlags::all();

        // Witness with 1 item (should need 2)
        let witness = Witness::from_items(vec![vec![0x01]]);
        let tx = make_simple_tx(witness.clone());
        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2wpkhWitnessCount(1) => {} // expected
            other => panic!("Expected P2wpkhWitnessCount(1), got {other:?}"),
        }

        // Witness with 3 items (should need 2)
        let witness = Witness::from_items(vec![vec![0x01], vec![0x02], vec![0x03]]);
        let tx = make_simple_tx(witness.clone());
        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
    }

    #[test]
    fn test_p2wsh_with_op_true() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Create a simple witness script: OP_TRUE (OP_1)
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_1);
        let witness_script_bytes = witness_script.as_bytes().to_vec();

        // Compute the program (SHA256 of the witness script)
        let program = sha256(&witness_script_bytes);

        // Build the P2WSH scriptPubKey
        let script_pubkey = ScriptBuf::p2wsh(&program);
        assert!(script_pubkey.is_p2wsh());

        // Witness: just the witness script itself (no data items needed for OP_TRUE)
        let witness = Witness::from_items(vec![witness_script_bytes]);

        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2WSH with OP_TRUE should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wsh_hash_mismatch_fails() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Create a witness script
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_1);
        let witness_script_bytes = witness_script.as_bytes().to_vec();

        // Use a wrong program hash
        let wrong_program = [0xffu8; 32];
        let witness = Witness::from_items(vec![witness_script_bytes]);

        let tx = make_simple_tx(witness.clone());

        let result = verify_witness_program(
            0,
            &wrong_program,
            &witness,
            &tx,
            0,
            50_000,
            &verifier,
            &flags,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2wshScriptMismatch => {} // expected
            other => panic!("Expected P2wshScriptMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_p2wsh_1of1_multisig() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();

        // Build 1-of-1 multisig witness script:
        // OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_1);
        witness_script.push_slice(&pubkey);
        witness_script.push_opcode(Opcode::OP_1);
        witness_script.push_opcode(Opcode::OP_CHECKMULTISIG);
        let witness_script_bytes = witness_script.as_bytes().to_vec();

        let program = sha256(&witness_script_bytes);
        let input_amount: i64 = 100_000;

        // Build the transaction
        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash using the witness script as script_code
        let sighash = sighash_segwit_v0(
            &tx,
            0,
            &witness_script_bytes,
            input_amount,
            SighashType::ALL,
        )
        .expect("sighash should succeed");

        // Sign
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Witness items: [dummy (for CHECKMULTISIG bug), sig, witness_script]
        let witness = Witness::from_items(vec![
            vec![], // dummy element for CHECKMULTISIG off-by-one
            sig,
            witness_script_bytes,
        ]);
        tx.witness = vec![witness.clone()];

        let result = verify_witness_program(
            0,
            &program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WSH 1-of-1 multisig should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_input_dispatches_p2wpkh() {
        let verifier = Secp256k1Verifier;
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash =
            sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::ALL).unwrap();
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        let witness = Witness::from_items(vec![sig, pubkey]);
        tx.witness = vec![witness];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let flags = ScriptFlags::all();
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "verify_input P2WPKH should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_input_dispatches_legacy_p2pkh() {
        let verifier = Secp256k1Verifier;
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pubkey = pk.serialize().to_vec();
        let pubkey_hash = hash160(&pubkey);

        // P2PKH scriptPubKey
        let script_pubkey = ScriptBuf::p2pkh(&pubkey_hash);
        let input_amount: i64 = 50_000;

        // Build the transaction first (without scriptSig, to compute sighash)
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute legacy sighash
        // For P2PKH, the script_code is the scriptPubKey
        let sighash =
            crate::sighash::sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL)
                .expect("legacy sighash should succeed");

        // Sign
        let msg = secp256k1::Message::from_digest(sighash);
        let ecdsa_sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_bytes = ecdsa_sig.serialize_der().to_vec();
        sig_bytes.push(SighashType::ALL.0 as u8);

        // Build scriptSig: <sig> <pubkey>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig_bytes);
        script_sig.push_slice(&pubkey);
        tx.inputs[0].script_sig = script_sig;

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let flags = ScriptFlags::all();
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "verify_input legacy P2PKH should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_input_dispatches_p2wsh() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Simple OP_TRUE witness script
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_1);
        let ws_bytes = witness_script.as_bytes().to_vec();
        let program = sha256(&ws_bytes);

        let script_pubkey = ScriptBuf::p2wsh(&program);
        let input_amount: i64 = 50_000;

        let witness = Witness::from_items(vec![ws_bytes]);
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: vec![witness],
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "verify_input P2WSH should succeed: {:?}",
            result.err()
        );
    }

    /// Test P2WSH with OP_CHECKSIG through the full verify_input path.
    /// This exercises the SegwitSignatureVerifier sighash recovery logic.
    #[test]
    fn test_verify_input_p2wsh_checksig() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();
        let (sk, pubkey) = generate_keypair();

        // Build witness script: <pubkey> OP_CHECKSIG
        let mut witness_script = ScriptBuf::new();
        witness_script.push_slice(&pubkey);
        witness_script.push_opcode(Opcode::OP_CHECKSIG);
        let ws_bytes = witness_script.as_bytes().to_vec();

        let program = sha256(&ws_bytes);
        let script_pubkey = ScriptBuf::p2wsh(&program);
        let input_amount: i64 = 100_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash using the witness script as script_code
        let sighash = sighash_segwit_v0(&tx, 0, &ws_bytes, input_amount, SighashType::ALL)
            .expect("sighash should succeed");

        // Sign
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Witness: [sig, witness_script]
        let witness = Witness::from_items(vec![sig, ws_bytes]);
        tx.witness = vec![witness];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "verify_input P2WSH CHECKSIG should succeed: {:?}",
            result.err()
        );
    }

    /// Test P2WSH with 2-of-3 CHECKMULTISIG through verify_input.
    #[test]
    fn test_verify_input_p2wsh_2of3_multisig() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        let (_sk3, pk3) = generate_keypair();

        // Build witness script: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_2);
        witness_script.push_slice(&pk1);
        witness_script.push_slice(&pk2);
        witness_script.push_slice(&pk3);
        witness_script.push_opcode(Opcode::OP_3);
        witness_script.push_opcode(Opcode::OP_CHECKMULTISIG);
        let ws_bytes = witness_script.as_bytes().to_vec();

        let program = sha256(&ws_bytes);
        let script_pubkey = ScriptBuf::p2wsh(&program);
        let input_amount: i64 = 200_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xee; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(190_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash using the witness script as script_code
        let sighash = sighash_segwit_v0(&tx, 0, &ws_bytes, input_amount, SighashType::ALL)
            .expect("sighash should succeed");

        // Sign with key1 and key2
        let sig1 = sign_sighash(&sk1, &sighash, SighashType::ALL);
        let sig2 = sign_sighash(&sk2, &sighash, SighashType::ALL);

        // Witness: [dummy, sig1, sig2, witness_script]
        let witness = Witness::from_items(vec![vec![], sig1, sig2, ws_bytes]);
        tx.witness = vec![witness];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "verify_input P2WSH 2-of-3 multisig should succeed: {:?}",
            result.err()
        );
    }

    /// Test P2WSH with OP_CODESEPARATOR — the exact pattern from signet block 277442.
    /// The witness script uses OP_CODESEPARATOR to split policy (CSV check) from
    /// the signing script code. BIP143 requires the sighash scriptCode to be
    /// only the portion AFTER the last executed OP_CODESEPARATOR.
    #[test]
    fn test_verify_input_p2wsh_with_codeseparator() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);

        // Build the witness script matching block 277442's pattern:
        // OP_SWAP OP_SIZE OP_DUP OP_ADD OP_DUP OP_ADD OP_CSV OP_DROP OP_SWAP
        // OP_CODESEPARATOR
        // OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_SWAP);
        witness_script.push_opcode(Opcode::OP_SIZE);
        witness_script.push_opcode(Opcode::OP_DUP);
        witness_script.push_opcode(Opcode::OP_ADD);
        witness_script.push_opcode(Opcode::OP_DUP);
        witness_script.push_opcode(Opcode::OP_ADD);
        witness_script.push_opcode(Opcode::OP_CHECKSEQUENCEVERIFY);
        witness_script.push_opcode(Opcode::OP_DROP);
        witness_script.push_opcode(Opcode::OP_SWAP);
        witness_script.push_opcode(Opcode::OP_CODESEPARATOR);
        witness_script.push_opcode(Opcode::OP_DUP);
        witness_script.push_opcode(Opcode::OP_HASH160);
        witness_script.push_slice(&pubkey_hash);
        witness_script.push_opcode(Opcode::OP_EQUALVERIFY);
        witness_script.push_opcode(Opcode::OP_CHECKSIG);
        let ws_bytes = witness_script.as_bytes().to_vec();

        let program = sha256(&ws_bytes);
        let script_pubkey = ScriptBuf::p2wsh(&program);
        let input_amount: i64 = 100_000;

        // The scriptCode for BIP143 sighash is only the part AFTER OP_CODESEPARATOR:
        // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        let codesep_pos = ws_bytes
            .iter()
            .position(|&b| b == Opcode::OP_CODESEPARATOR as u8)
            .unwrap();
        let script_code_after_codesep = &ws_bytes[codesep_pos + 1..];

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xff; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                // sequence must satisfy CSV: sig is 71 bytes, so 4*71 = 284
                sequence: 1000,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash using the POST-CODESEPARATOR scriptCode
        let sighash = sighash_segwit_v0(
            &tx,
            0,
            script_code_after_codesep,
            input_amount,
            SighashType::ALL,
        )
        .expect("sighash should succeed");

        // Sign
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Witness: [sig, pubkey, witness_script]
        let witness = Witness::from_items(vec![sig, pubkey, ws_bytes]);
        tx.witness = vec![witness];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2WSH with OP_CODESEPARATOR should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_input_out_of_range() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![]),
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_witness_fails() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let program = [0u8; 20];
        let witness = Witness::new();

        let tx = make_simple_tx(witness.clone());
        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::EmptyWitness => {}
            other => panic!("Expected EmptyWitness, got {other:?}"),
        }
    }

    #[test]
    fn test_future_witness_version_succeeds() {
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let program = [0u8; 20];
        let witness = Witness::from_items(vec![vec![0x01]]);

        let tx = make_simple_tx(witness.clone());

        // Version 2+ should succeed (future soft-fork safe)
        let result =
            verify_witness_program(2, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_ok(), "Future witness version should succeed");

        let result =
            verify_witness_program(16, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_ok(), "Witness v16 should succeed");
    }

    #[test]
    fn test_extract_single_push() {
        // Single 20-byte push
        let mut script = vec![20u8]; // push 20 bytes
        script.extend_from_slice(&[0xaa; 20]);
        let result = extract_single_push(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 20);

        // Two pushes -- should return None
        let script2 = vec![1u8, 0xbb, 1u8, 0xcc];
        let result2 = extract_single_push(&script2);
        assert!(result2.is_none());

        // Empty script
        assert!(extract_single_push(&[]).is_none());

        // OP_PUSHDATA1
        let script3 = vec![Opcode::OP_PUSHDATA1 as u8, 3, 0xaa, 0xbb, 0xcc];
        let result3 = extract_single_push(&script3);
        assert!(result3.is_some());
        assert_eq!(result3.unwrap(), &[0xaa, 0xbb, 0xcc]);

        // Truncated script
        let _ = script2; // suppress warning
        let truncated = vec![5u8, 0xaa, 0xbb]; // says 5 bytes but only 2
        assert!(extract_single_push(&truncated).is_none());
    }

    #[test]
    fn test_extract_all_pushes() {
        // Two pushes
        let script = vec![1u8, 0xaa, 2u8, 0xbb, 0xcc];
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0], &[0xaa]);
        assert_eq!(pushes[1], &[0xbb, 0xcc]);
    }

    #[test]
    fn test_segwit_verifier_uses_correct_sighash_type() {
        // Test that SegwitSignatureVerifier correctly identifies the sighash type
        // from the legacy sighash rather than brute-forcing ECDSA verification.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();

        let pubkey_hash = hash160(&pubkey);
        let input_amount: i64 = 50_000;

        // Test with SIGHASH_ALL
        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::ALL)
            .expect("sighash computation should succeed");

        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);
        let witness = Witness::from_items(vec![sig, pubkey.clone()]);
        tx.witness = vec![witness.clone()];

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let program = &script_pubkey.as_bytes()[2..];
        let result = verify_witness_program(
            0,
            program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WPKH with SIGHASH_ALL should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_segwit_verifier_sighash_none() {
        // Test P2WPKH verification with SIGHASH_NONE
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();

        let pubkey_hash = hash160(&pubkey);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::NONE)
            .expect("sighash computation should succeed");

        let sig = sign_sighash(&sk, &sighash, SighashType::NONE);
        let witness = Witness::from_items(vec![sig, pubkey.clone()]);
        tx.witness = vec![witness.clone()];

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let program = &script_pubkey.as_bytes()[2..];
        let result = verify_witness_program(
            0,
            program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WPKH with SIGHASH_NONE should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wsh_checksig_with_sighash_all() {
        // Test P2WSH with a simple <pubkey> OP_CHECKSIG witness script
        // This exercises the SegwitSignatureVerifier for P2WSH
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();

        // Build witness script: <pubkey> OP_CHECKSIG
        let mut witness_script = ScriptBuf::new();
        witness_script.push_slice(&pubkey);
        witness_script.push_opcode(Opcode::OP_CHECKSIG);
        let witness_script_bytes = witness_script.as_bytes().to_vec();

        let program = sha256(&witness_script_bytes);
        let input_amount: i64 = 100_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash using the witness script as script_code
        let sighash = sighash_segwit_v0(
            &tx,
            0,
            &witness_script_bytes,
            input_amount,
            SighashType::ALL,
        )
        .expect("sighash should succeed");

        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Witness items: [sig, witness_script]
        let witness = Witness::from_items(vec![sig, witness_script_bytes]);
        tx.witness = vec![witness.clone()];

        let result = verify_witness_program(
            0,
            &program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WSH CHECKSIG with SIGHASH_ALL should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_witness_flag_false_skips_verification() {
        // When verify_witness is false, witness programs should be treated as
        // legacy scripts and succeed without witness verification.
        let verifier = Secp256k1Verifier;
        let mut flags = ScriptFlags::all();
        flags.verify_witness = false;

        let pubkey_hash = [0xaa; 20];
        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let input_amount: i64 = 50_000;

        // Transaction with NO witness data at all -- would fail if witness
        // verification were attempted, but should succeed when flag is off.
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "verify_input with verify_witness=false should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_unexpected_witness_rejected() {
        // A legacy (non-witness) input that has non-empty witness data
        // should be rejected when verify_witness is true (BIP141).
        let verifier = Secp256k1Verifier;
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        let pubkey = pk.serialize().to_vec();
        let pubkey_hash = hash160(&pubkey);

        // P2PKH scriptPubKey (legacy, not witness)
        let script_pubkey = ScriptBuf::p2pkh(&pubkey_hash);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute legacy sighash and sign
        let sighash =
            crate::sighash::sighash_legacy(&tx, 0, script_pubkey.as_bytes(), SighashType::ALL)
                .expect("legacy sighash should succeed");
        let msg = secp256k1::Message::from_digest(sighash);
        let ecdsa_sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_bytes = ecdsa_sig.serialize_der().to_vec();
        sig_bytes.push(SighashType::ALL.0 as u8);

        // Build scriptSig: <sig> <pubkey>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&sig_bytes);
        script_sig.push_slice(&pubkey);
        tx.inputs[0].script_sig = script_sig;

        // Add unexpected witness data to a legacy input
        tx.witness = vec![Witness::from_items(vec![vec![0x01, 0x02, 0x03]])];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let flags = ScriptFlags::all(); // verify_witness = true
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_err(),
            "Legacy input with unexpected witness data should fail"
        );
        match result.unwrap_err() {
            WitnessError::UnexpectedWitness => {} // expected
            other => panic!("Expected UnexpectedWitness, got {other:?}"),
        }
    }

    #[test]
    fn test_scriptsig_must_be_empty_for_native_segwit() {
        // For native segwit spends, scriptSig must be empty (BIP141).
        let verifier = Secp256k1Verifier;
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                // Non-empty scriptSig for native segwit -- should be rejected
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Build valid witness
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash =
            sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::ALL).unwrap();
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);
        let witness = Witness::from_items(vec![sig, pubkey]);
        tx.witness = vec![witness];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let flags = ScriptFlags::all();
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_err(),
            "Native segwit with non-empty scriptSig should fail"
        );
        match result.unwrap_err() {
            WitnessError::ScriptSigNotEmpty => {} // expected
            other => panic!("Expected ScriptSigNotEmpty, got {other:?}"),
        }
    }

    #[test]
    fn test_future_witness_versions_succeed_in_verify_witness_program() {
        // Future witness versions (2-16) must succeed unconditionally.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let witness = Witness::from_items(vec![vec![0x01]]);
        let tx = make_simple_tx(witness.clone());

        // Test version 2 through 16 with various program sizes
        for version in 2..=16u8 {
            let program = vec![0xab; 20];
            let result = verify_witness_program(
                version, &program, &witness, &tx, 0, 50_000, &verifier, &flags,
            );
            assert!(
                result.is_ok(),
                "Witness version {} should succeed (soft-fork safe): {:?}",
                version,
                result.err()
            );
        }

        // Also test v1 with non-32-byte program (should also succeed as future-safe)
        let short_program = vec![0xcd; 20];
        let result = verify_witness_program(
            1,
            &short_program,
            &witness,
            &tx,
            0,
            50_000,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "Witness v1 with non-32-byte program should succeed: {:?}",
            result.err()
        );
    }

    // ------------------------------------------------------------------
    // Coverage gap tests
    // ------------------------------------------------------------------

    #[test]
    fn test_p2sh_wrapped_p2wpkh_verification() {
        // Test the P2SH-segwit path: the scriptPubKey is P2SH, the redeem script
        // is a P2WPKH witness program, and witness data provides sig + pubkey.
        let verifier = Secp256k1Verifier;
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);

        // The "redeem script" is the raw P2WPKH witness program: OP_0 <20-byte hash>
        let redeem_script = ScriptBuf::p2wpkh(&pubkey_hash);
        let redeem_bytes = redeem_script.as_bytes();

        // The P2SH scriptPubKey wraps the hash of the redeem script.
        let redeem_hash = hash160(redeem_bytes);
        let script_pubkey = ScriptBuf::p2sh(&redeem_hash);
        assert!(script_pubkey.is_p2sh());

        let input_amount: i64 = 60_000;

        // Build the scriptSig: a single push of the serialized redeem script.
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(redeem_bytes);

        // Build the transaction.
        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(55_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute BIP143 sighash for P2WPKH.
        let p2wpkh_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = sighash_segwit_v0(&tx, 0, &p2wpkh_code, input_amount, SighashType::ALL)
            .expect("sighash should succeed");
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Build the witness: [sig, pubkey]
        let witness = Witness::from_items(vec![sig, pubkey]);
        tx.witness = vec![witness];

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let flags = ScriptFlags::all();
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2SH-wrapped P2WPKH should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2sh_wrapped_p2wsh_verification() {
        // Test P2SH-P2WSH: the scriptPubKey is P2SH, the redeem script is a P2WSH
        // witness program, and the witness contains the actual script (OP_TRUE).
        let verifier = Secp256k1Verifier;

        // The witness script is simply OP_TRUE.
        let mut witness_script = ScriptBuf::new();
        witness_script.push_opcode(Opcode::OP_1);
        let ws_bytes = witness_script.as_bytes().to_vec();
        let ws_hash = sha256(&ws_bytes);

        // The redeem script is the P2WSH witness program: OP_0 <32-byte SHA256>
        let redeem_script = ScriptBuf::p2wsh(&ws_hash);
        let redeem_bytes = redeem_script.as_bytes();

        // The P2SH scriptPubKey wraps the hash of the redeem script.
        let redeem_hash = hash160(redeem_bytes);
        let script_pubkey = ScriptBuf::p2sh(&redeem_hash);
        assert!(script_pubkey.is_p2sh());

        let input_amount: i64 = 70_000;

        // scriptSig: single push of the serialized redeem script.
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(redeem_bytes);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xee; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(65_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            // Witness: just the witness script (OP_TRUE needs no data items)
            witness: vec![Witness::from_items(vec![ws_bytes])],
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey,
        };

        let flags = ScriptFlags::all();
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2SH-wrapped P2WSH with OP_TRUE should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_future_witness_v2_succeeds_via_verify_input() {
        // Ensure that a native segwit v2 output (which doesn't exist yet) passes
        // verify_input -- future witness versions must succeed for soft-fork safety.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Build a v2 witness program: OP_2 (0x52) OP_PUSH20 <20 bytes>
        let mut spk_bytes = vec![0x52u8]; // OP_2
        spk_bytes.push(20); // push 20 bytes
        spk_bytes.extend_from_slice(&[0xab; 20]);
        let script_pubkey = ScriptBuf::from_bytes(spk_bytes);
        assert!(
            script_pubkey.is_witness_program(),
            "should be a witness program"
        );

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xff; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]), // must be empty for native segwit
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(), // empty witness is fine for future versions
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "native segwit v2 should succeed for soft-fork safety: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_unexpected_witness_rejection() {
        // A legacy (non-witness) input with non-empty witness data should be
        // rejected when verify_witness is enabled.
        let verifier = Secp256k1Verifier;

        // scriptPubKey is OP_TRUE (legacy, non-witness, non-P2SH).
        let script_pubkey = ScriptBuf::from_bytes(vec![0x51]); // OP_1 = OP_TRUE
        assert!(!script_pubkey.is_witness_program());
        assert!(!script_pubkey.is_p2sh());

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]), // empty scriptSig is fine for OP_TRUE
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            // Non-empty witness on a non-witness input
            witness: vec![Witness::from_items(vec![vec![0x42]])],
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let flags = ScriptFlags::all(); // verify_witness = true
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_err(),
            "non-witness input with witness data should be rejected"
        );
        match result.unwrap_err() {
            WitnessError::UnexpectedWitness => {} // expected
            other => panic!("Expected UnexpectedWitness, got {other:?}"),
        }

        // With verify_witness = false, the same tx should succeed.
        let mut no_witness_flags = ScriptFlags::all();
        no_witness_flags.verify_witness = false;
        let result2 = verify_input(&tx, 0, &prev_output, &verifier, &no_witness_flags);
        // With verify_witness=false the engine doesn't check for unexpected witness
        // but the legacy script OP_TRUE should still succeed.
        assert!(
            result2.is_ok(),
            "with verify_witness=false, should succeed: {:?}",
            result2.err()
        );
    }

    // ==================================================================
    // Additional tests for 100% line coverage
    // ==================================================================

    #[test]
    fn test_p2sh_segwit_redeem_hash_mismatch() {
        // P2SH-wrapped segwit where the redeem script hash does NOT match
        // the P2SH hash in the scriptPubKey. Should return P2shRedeemFailed.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        let pubkey_hash = [0xaa; 20];
        // The real redeem script (P2WPKH witness program)
        let redeem_script = ScriptBuf::p2wpkh(&pubkey_hash);
        let redeem_bytes = redeem_script.as_bytes();

        // Build a P2SH scriptPubKey with a WRONG hash (not matching redeem_script)
        let wrong_hash: [u8; 20] = [0xff; 20];
        let script_pubkey = ScriptBuf::p2sh(&wrong_hash);

        // scriptSig: single push of the redeem script
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(redeem_bytes);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: vec![Witness::from_items(vec![vec![0x01], vec![0x02]])],
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2shRedeemFailed => {}
            other => panic!("Expected P2shRedeemFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_p2sh_non_witness_redeem_script_execution() {
        // P2SH with a non-witness redeem script (legacy P2SH).
        // The redeem script is OP_1 (OP_TRUE), so it should succeed.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Redeem script: OP_1 (always true)
        let redeem_script_bytes: Vec<u8> = vec![Opcode::OP_1 as u8];
        let redeem_hash = hash160(&redeem_script_bytes);
        let script_pubkey = ScriptBuf::p2sh(&redeem_hash);
        assert!(script_pubkey.is_p2sh());

        // scriptSig: single push of the redeem script
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&redeem_script_bytes);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xab; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2SH with OP_TRUE redeem should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2sh_non_witness_redeem_script_with_data_pushes() {
        // P2SH legacy with a redeem script that requires data items on the stack.
        // Redeem script: OP_1 OP_EQUAL (requires value 1 on the stack)
        // scriptSig: <1> <serialized redeem script>
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();

        // Redeem script: OP_1 OP_EQUAL
        let redeem_script_bytes: Vec<u8> = vec![Opcode::OP_1 as u8, Opcode::OP_EQUAL as u8];
        let redeem_hash = hash160(&redeem_script_bytes);
        let script_pubkey = ScriptBuf::p2sh(&redeem_hash);

        // scriptSig: push <0x01> then push the redeem script
        // This is: <OP_1> <redeem_script>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_opcode(Opcode::OP_1);
        script_sig.push_slice(&redeem_script_bytes);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xac; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2SH with OP_1 OP_EQUAL and correct data should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2sh_non_witness_redeem_hash_mismatch() {
        // P2SH non-witness with a redeem script that doesn't match the hash.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // The redeem script is OP_1 (not a witness program)
        let redeem_script_bytes: Vec<u8> = vec![Opcode::OP_1 as u8];

        // Build P2SH scriptPubKey with a WRONG hash
        let wrong_hash: [u8; 20] = [0xee; 20];
        let script_pubkey = ScriptBuf::p2sh(&wrong_hash);

        // scriptSig: single push of the redeem script
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&redeem_script_bytes);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xad; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2shRedeemFailed => {}
            other => panic!("Expected P2shRedeemFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_p2sh_non_witness_redeem_script_fails_execution() {
        // P2SH non-witness with a redeem script that fails execution.
        // Redeem script: OP_0 (pushes false onto stack)
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();

        let redeem_script_bytes: Vec<u8> = vec![Opcode::OP_0 as u8];
        let redeem_hash = hash160(&redeem_script_bytes);
        let script_pubkey = ScriptBuf::p2sh(&redeem_hash);

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&redeem_script_bytes);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xae; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2shRedeemFailed => {}
            other => panic!("Expected P2shRedeemFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_p2sh_extract_single_push_returns_none() {
        // P2SH where scriptSig is not a single push (extract_single_push returns None).
        // This causes the P2SH branch to fall through to legacy verification.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();

        // Build a P2SH scriptPubKey for some script
        let some_hash: [u8; 20] = [0xaa; 20];
        let script_pubkey = ScriptBuf::p2sh(&some_hash);

        // scriptSig has TWO pushes (not a single push)
        let script_sig = ScriptBuf::from_bytes(vec![1u8, 0xbb, 1u8, 0xcc]);

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaf; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        // When extract_single_push returns None for P2SH, it falls through
        // to legacy script verification. The scriptSig + scriptPubKey will
        // fail because it's not a valid spend.
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        // This should either fail legacy verification or pass through;
        // since the scriptSig doesn't properly satisfy the P2SH scriptPubKey,
        // it should fail.
        assert!(result.is_err());
    }

    #[test]
    fn test_p2wsh_script_fails_execution() {
        // P2WSH where the witness script execution leaves false on the stack.
        // Should return P2wshScriptFailed.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();

        // Witness script: OP_0 (pushes empty/false onto stack)
        let witness_script_bytes: Vec<u8> = vec![Opcode::OP_0 as u8];
        let program = sha256(&witness_script_bytes);

        let witness = Witness::from_items(vec![witness_script_bytes.clone()]);
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2wshScriptFailed { .. } => {}
            other => panic!("Expected P2wshScriptFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_single_push_op_pushdata2() {
        // OP_PUSHDATA2 with 3 bytes of data
        let mut script = vec![Opcode::OP_PUSHDATA2 as u8];
        script.extend_from_slice(&3u16.to_le_bytes()); // length = 3
        script.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let result = extract_single_push(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_extract_single_push_op_pushdata2_too_short_header() {
        // OP_PUSHDATA2 but script is too short to read 2-byte length
        let script = vec![Opcode::OP_PUSHDATA2 as u8, 0x03];
        let result = extract_single_push(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_single_push_op_pushdata2_too_short_data() {
        // OP_PUSHDATA2 with length indicating 10 bytes but only 2 available
        let mut script = vec![Opcode::OP_PUSHDATA2 as u8];
        script.extend_from_slice(&10u16.to_le_bytes());
        script.extend_from_slice(&[0xaa, 0xbb]);
        let result = extract_single_push(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_single_push_op_pushdata1_too_short_header() {
        // OP_PUSHDATA1 but script has no length byte
        let script = vec![Opcode::OP_PUSHDATA1 as u8];
        let result = extract_single_push(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_single_push_op_pushdata1_too_short_data() {
        // OP_PUSHDATA1 with length 10 but only 2 bytes of data
        let script = vec![Opcode::OP_PUSHDATA1 as u8, 10, 0xaa, 0xbb];
        let result = extract_single_push(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_single_push_non_push_opcode() {
        // A non-push opcode (e.g., OP_DUP = 0x76) should return None
        let script = vec![0x76];
        let result = extract_single_push(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_single_push_op_0() {
        // OP_0 as a single push (empty data)
        let script = vec![0x00];
        let result = extract_single_push(&script);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_extract_single_push_op_pushdata2_not_consumed_entirely() {
        // OP_PUSHDATA2 push followed by extra bytes (not a single push)
        let mut script = vec![Opcode::OP_PUSHDATA2 as u8];
        script.extend_from_slice(&2u16.to_le_bytes());
        script.extend_from_slice(&[0xaa, 0xbb]);
        script.push(0xcc); // extra byte
        let result = extract_single_push(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_all_pushes_op_pushdata1() {
        // extract_all_pushes with OP_PUSHDATA1
        let mut script = Vec::new();
        script.push(Opcode::OP_PUSHDATA1 as u8);
        script.push(3); // length
        script.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0], &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_extract_all_pushes_op_pushdata2() {
        // extract_all_pushes with OP_PUSHDATA2
        let mut script = Vec::new();
        script.push(Opcode::OP_PUSHDATA2 as u8);
        script.extend_from_slice(&4u16.to_le_bytes());
        script.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_extract_all_pushes_stops_at_non_push() {
        // extract_all_pushes should stop at a non-push opcode
        let mut script = Vec::new();
        script.push(1u8); // push 1 byte
        script.push(0xaa);
        script.push(0x76); // OP_DUP (non-push opcode) -- should stop here
        script.push(1u8);
        script.push(0xbb);
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0], &[0xaa]);
    }

    #[test]
    fn test_extract_all_pushes_op_0() {
        // OP_0 in extract_all_pushes (empty push)
        let script = vec![0x00, 1u8, 0xaa];
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].len(), 0); // empty push from OP_0
        assert_eq!(pushes[1], &[0xaa]);
    }

    #[test]
    fn test_extract_all_pushes_truncated_direct_push() {
        // Direct push opcode says 5 bytes but only 2 remain
        let script = vec![5u8, 0xaa, 0xbb];
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 0); // should break out
    }

    #[test]
    fn test_extract_all_pushes_truncated_pushdata1() {
        // OP_PUSHDATA1 at end of script (no length byte)
        let script = vec![Opcode::OP_PUSHDATA1 as u8];
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 0);
    }

    #[test]
    fn test_extract_all_pushes_pushdata1_truncated_data() {
        // OP_PUSHDATA1 with length 5 but only 2 bytes of data
        let script = vec![Opcode::OP_PUSHDATA1 as u8, 5, 0xaa, 0xbb];
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 0);
    }

    #[test]
    fn test_extract_all_pushes_truncated_pushdata2() {
        // OP_PUSHDATA2 at end of script (no length bytes)
        let script = vec![Opcode::OP_PUSHDATA2 as u8];
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 0);
    }

    #[test]
    fn test_extract_all_pushes_pushdata2_truncated_data() {
        // OP_PUSHDATA2 with length 10 but only 2 bytes of data
        let mut script = vec![Opcode::OP_PUSHDATA2 as u8];
        script.extend_from_slice(&10u16.to_le_bytes());
        script.extend_from_slice(&[0xaa, 0xbb]);
        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 0);
    }

    #[test]
    fn test_p2sh_segwit_missing_witness() {
        // P2SH-wrapped segwit where input_index >= tx.witness.len()
        // Should return EmptyWitness.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        let pubkey_hash = [0xaa; 20];
        let redeem_script = ScriptBuf::p2wpkh(&pubkey_hash);
        let redeem_bytes = redeem_script.as_bytes();
        let redeem_hash = hash160(redeem_bytes);
        let script_pubkey = ScriptBuf::p2sh(&redeem_hash);

        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(redeem_bytes);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(), // No witness data at all
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::EmptyWitness => {}
            other => panic!("Expected EmptyWitness, got {other:?}"),
        }
    }

    #[test]
    fn test_p2wpkh_empty_signature_fails() {
        // P2WPKH witness with an empty signature should fail.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (_sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);

        // Witness: [empty_sig, pubkey]
        let witness = Witness::from_items(vec![vec![], pubkey]);
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(0, &pubkey_hash, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::SignatureVerificationFailed => {}
            other => panic!("Expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_v0_wrong_program_length() {
        // Witness version 0 with a program that is neither 20 nor 32 bytes.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let program = [0xaa; 25]; // 25 bytes (not 20 or 32)
        let witness = Witness::from_items(vec![vec![0x01]]);
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::ProgramMismatch {
                expected: 20,
                got: 25,
            } => {}
            other => panic!("Expected ProgramMismatch {{ expected: 20, got: 25 }}, got {other:?}"),
        }
    }

    #[test]
    fn test_taproot_v1_32byte_program_empty_witness_fails() {
        // Taproot (v1, 32-byte program) with empty witness should fail.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let program = [0xab; 32]; // 32-byte program
        let witness = Witness::new(); // empty
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(1, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::EmptyWitness => {}
            other => panic!("Expected EmptyWitness, got {other:?}"),
        }
    }

    #[test]
    fn test_taproot_v1_32byte_program_invalid_signature_fails() {
        // Taproot (v1, 32-byte program) with non-empty witness should succeed.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let program = [0xab; 32];
        let witness = Witness::from_items(vec![vec![0x01]]);
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(1, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(
            result.is_err(),
            "Taproot v1 with an invalid signature must fail: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_taproot_v1_32byte_program_verify_taproot_false() {
        // Taproot (v1, 32-byte program) with verify_taproot = false should succeed.
        let verifier = Secp256k1Verifier;
        let mut flags = ScriptFlags::all();
        flags.verify_taproot = false;
        let program = [0xab; 32];
        let witness = Witness::from_items(vec![vec![0x01]]);
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(1, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(
            result.is_ok(),
            "Taproot v1 with verify_taproot=false should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_native_segwit_version_op1_through_op16() {
        // Test that native segwit with OP_1 through OP_16 version bytes are
        // correctly extracted in the verify_input path.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Test multiple witness versions through verify_input
        for version_byte in 0x51u8..=0x60u8 {
            let version = version_byte - 0x50;
            let mut spk_bytes = vec![version_byte];
            spk_bytes.push(20); // push 20 bytes
            spk_bytes.extend_from_slice(&[0xab; 20]);
            let script_pubkey = ScriptBuf::from_bytes(spk_bytes);

            let tx = Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xff; 32]), 0),
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

            let prev_output = TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey,
            };

            let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
            assert!(
                result.is_ok(),
                "Native segwit version {} (byte 0x{:02x}) should succeed: {:?}",
                version,
                version_byte,
                result.err()
            );
        }
    }

    #[test]
    fn test_p2sh_wrapped_segwit_version_op1_through_op16() {
        // Test P2SH-wrapped segwit with OP_1..OP_16 versions in the redeem script.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        for version_byte in 0x51u8..=0x60u8 {
            // Build a redeem script that is a witness program with this version
            let mut redeem_bytes = vec![version_byte];
            redeem_bytes.push(20); // push 20 bytes
            redeem_bytes.extend_from_slice(&[0xab; 20]);
            let redeem_script = ScriptBuf::from_bytes(redeem_bytes.clone());
            assert!(redeem_script.is_witness_program());

            let redeem_hash = hash160(&redeem_bytes);
            let script_pubkey = ScriptBuf::p2sh(&redeem_hash);

            let mut script_sig = ScriptBuf::new();
            script_sig.push_slice(&redeem_bytes);

            let tx = Transaction {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xff; 32]), 0),
                    script_sig,
                    sequence: 0xffffffff,
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                }],
                witness: vec![Witness::from_items(vec![vec![0x01]])],
                lock_time: 0,
            };

            let prev_output = TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey,
            };

            let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
            assert!(
                result.is_ok(),
                "P2SH-wrapped segwit version {} should succeed: {:?}",
                version_byte - 0x50,
                result.err()
            );
        }
    }

    #[test]
    fn test_p2wsh_checksig_sighash_none() {
        // P2WSH with <pubkey> OP_CHECKSIG using SIGHASH_NONE
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();
        let (sk, pubkey) = generate_keypair();

        let mut witness_script = ScriptBuf::new();
        witness_script.push_slice(&pubkey);
        witness_script.push_opcode(Opcode::OP_CHECKSIG);
        let ws_bytes = witness_script.as_bytes().to_vec();
        let program = sha256(&ws_bytes);
        let input_amount: i64 = 100_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let sighash = sighash_segwit_v0(&tx, 0, &ws_bytes, input_amount, SighashType::NONE)
            .expect("sighash should succeed");
        let sig = sign_sighash(&sk, &sighash, SighashType::NONE);

        let witness = Witness::from_items(vec![sig, ws_bytes]);
        tx.witness = vec![witness.clone()];

        let result = verify_witness_program(
            0,
            &program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WSH CHECKSIG with SIGHASH_NONE should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wsh_checksig_sighash_single() {
        // P2WSH with <pubkey> OP_CHECKSIG using SIGHASH_SINGLE
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();
        let (sk, pubkey) = generate_keypair();

        let mut witness_script = ScriptBuf::new();
        witness_script.push_slice(&pubkey);
        witness_script.push_opcode(Opcode::OP_CHECKSIG);
        let ws_bytes = witness_script.as_bytes().to_vec();
        let program = sha256(&ws_bytes);
        let input_amount: i64 = 100_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let sighash = sighash_segwit_v0(&tx, 0, &ws_bytes, input_amount, SighashType::SINGLE)
            .expect("sighash should succeed");
        let sig = sign_sighash(&sk, &sighash, SighashType::SINGLE);

        let witness = Witness::from_items(vec![sig, ws_bytes]);
        tx.witness = vec![witness.clone()];

        let result = verify_witness_program(
            0,
            &program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WSH CHECKSIG with SIGHASH_SINGLE should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wsh_checksig_sighash_anyonecanpay() {
        // P2WSH with <pubkey> OP_CHECKSIG using SIGHASH_ALL|ANYONECANPAY
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();
        let (sk, pubkey) = generate_keypair();

        let mut witness_script = ScriptBuf::new();
        witness_script.push_slice(&pubkey);
        witness_script.push_opcode(Opcode::OP_CHECKSIG);
        let ws_bytes = witness_script.as_bytes().to_vec();
        let program = sha256(&ws_bytes);
        let input_amount: i64 = 100_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let acp = SighashType(SighashType::ALL.0 | SighashType::ANYONECANPAY.0);
        let sighash = sighash_segwit_v0(&tx, 0, &ws_bytes, input_amount, acp)
            .expect("sighash should succeed");
        let sig = sign_sighash(&sk, &sighash, acp);

        let witness = Witness::from_items(vec![sig, ws_bytes]);
        tx.witness = vec![witness.clone()];

        let result = verify_witness_program(
            0,
            &program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WSH CHECKSIG with SIGHASH_ALL|ANYONECANPAY should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wpkh_sighash_single() {
        // P2WPKH verification with SIGHASH_SINGLE
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::SINGLE)
            .expect("sighash computation should succeed");
        let sig = sign_sighash(&sk, &sighash, SighashType::SINGLE);
        let witness = Witness::from_items(vec![sig, pubkey.clone()]);
        tx.witness = vec![witness.clone()];

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let program = &script_pubkey.as_bytes()[2..];
        let result = verify_witness_program(
            0,
            program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WPKH with SIGHASH_SINGLE should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wpkh_sighash_anyonecanpay() {
        // P2WPKH verification with SIGHASH_ALL|ANYONECANPAY
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let acp = SighashType(SighashType::ALL.0 | SighashType::ANYONECANPAY.0);
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = sighash_segwit_v0(&tx, 0, &script_code, input_amount, acp)
            .expect("sighash computation should succeed");
        let sig = sign_sighash(&sk, &sighash, acp);
        let witness = Witness::from_items(vec![sig, pubkey.clone()]);
        tx.witness = vec![witness.clone()];

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let program = &script_pubkey.as_bytes()[2..];
        let result = verify_witness_program(
            0,
            program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(
            result.is_ok(),
            "P2WPKH with SIGHASH_ALL|ANYONECANPAY should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_native_segwit_missing_witness_future_version() {
        // Native segwit where input_index >= tx.witness.len() -- should use empty
        // witness. For future versions this is fine (soft-fork safe).
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        // Build a v2 witness program
        let mut spk_bytes = vec![0x52u8]; // OP_2
        spk_bytes.push(20);
        spk_bytes.extend_from_slice(&[0xab; 20]);
        let script_pubkey = ScriptBuf::from_bytes(spk_bytes);

        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xff; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xfe; 32]), 1),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: vec![Witness::new()], // only 1 witness, but we'll verify input 1
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        // Verify input_index 1, which is >= tx.witness.len() (only 1 witness entry)
        let result = verify_input(&tx, 1, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "Future version with missing witness should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_p2wsh_empty_witness_fails() {
        // P2WSH with empty witness should return P2wshEmptyWitness.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let program = [0u8; 32];
        let witness = Witness::new();
        let tx = make_simple_tx(Witness::new());

        // This path is actually guarded by the version-0 empty witness check first,
        // so we need a non-empty witness that gets past that check but then is
        // empty when verify_p2wsh is called. Actually, the version-0 check
        // happens first. Let's test it through verify_witness_program directly,
        // where the outer check catches it as EmptyWitness. The P2wshEmptyWitness
        // path inside verify_p2wsh is also reachable if called directly.
        let result = verify_p2wsh(&program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::P2wshEmptyWitness => {}
            other => panic!("Expected P2wshEmptyWitness, got {other:?}"),
        }
    }

    #[test]
    fn test_legacy_script_fails() {
        // Legacy script that fails execution should return LegacyScriptFailed.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();

        // scriptPubKey: OP_0 (pushes false) -- but NOT a witness program
        // (too short to be a witness program)
        // Actually, let's use a script that is clearly not a witness program and not P2SH.
        // OP_VERIFY: pops top and fails if false. With empty stack, the script will error.
        // Let's use something simpler: scriptPubKey = OP_1 OP_1 OP_EQUAL OP_VERIFY OP_0
        // That would: push 1, push 1, check equal (true), verify (OK), push 0 => false on stack.
        let script_pubkey = ScriptBuf::from_bytes(vec![
            Opcode::OP_1 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_EQUALVERIFY as u8,
            Opcode::OP_0 as u8, // pushes false
        ]);
        assert!(!script_pubkey.is_witness_program());
        assert!(!script_pubkey.is_p2sh());

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

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
        match result.unwrap_err() {
            WitnessError::LegacyScriptFailed => {}
            other => panic!("Expected LegacyScriptFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_p2sh_segwit_unsupported_version_in_redeem_script() {
        // P2SH-wrapped segwit with an unsupported version byte in the redeem script.
        // This tests the `_ => return Err(WitnessError::UnsupportedVersion(...))` branch
        // in the P2SH path. However, to reach this, we need a redeem script that
        // is_witness_program() but has a version byte that is not OP_0 and not OP_1..OP_16.
        // Since is_witness_program() only returns true for OP_0 and OP_1..OP_16, this
        // branch is actually unreachable. Let's verify the UnsupportedVersion path
        // in the native segwit path instead. We can craft a scriptPubKey that
        // passes is_witness_program() = true but has a version byte that falls into
        // the catch-all. But is_witness_program() checks for OP_0 or OP_1..OP_16,
        // so any valid witness program will have a version in the extractable range.
        // This means the UnsupportedVersion branch in native is also unreachable
        // for well-formed witness programs.
        //
        // Instead, let's just verify that the existing OP_0 path works in P2SH too.
        // The OP_0 case in P2SH-wrapped is already covered by test_p2sh_wrapped_p2wpkh_verification.
        // This test intentionally left as a note that the UnsupportedVersion branches
        // in both native and P2SH paths are unreachable for scripts that pass is_witness_program().
    }

    #[test]
    fn test_p2wpkh_wrong_signature_fails() {
        // P2WPKH with a valid-looking but wrong ECDSA signature should fail.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();
        let (sk, pubkey) = generate_keypair();
        let pubkey_hash = hash160(&pubkey);
        let input_amount: i64 = 50_000;

        let mut tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Compute sighash for one message but sign a different one
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash =
            sighash_segwit_v0(&tx, 0, &script_code, input_amount, SighashType::ALL).unwrap();
        // Sign the correct sighash but then change the tx so the sighash is different
        let sig = sign_sighash(&sk, &sighash, SighashType::ALL);

        // Modify the tx AFTER signing (changes the sighash)
        tx.outputs[0].value = Amount::from_sat(48_000);

        let witness = Witness::from_items(vec![sig, pubkey.clone()]);
        tx.witness = vec![witness.clone()];

        let script_pubkey = ScriptBuf::p2wpkh(&pubkey_hash);
        let program = &script_pubkey.as_bytes()[2..];
        let result = verify_witness_program(
            0,
            program,
            &witness,
            &tx,
            0,
            input_amount,
            &verifier,
            &flags,
        );
        assert!(result.is_err(), "P2WPKH with wrong signature should fail");
        match result.unwrap_err() {
            WitnessError::SignatureVerificationFailed => {}
            other => panic!("Expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_p2wsh_with_witness_items_on_stack() {
        // P2WSH where the witness has data items pushed onto the stack before
        // executing the witness script. This exercises the init_script path
        // with non-empty items.
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::consensus();

        // Witness script: OP_ADD OP_3 OP_EQUAL
        // Needs two items on the stack that add to 3
        let ws_bytes: Vec<u8> = vec![
            Opcode::OP_ADD as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUAL as u8,
        ];
        let program = sha256(&ws_bytes);

        // Witness: [<1>, <2>, witness_script]
        // OP_1 and OP_2 as single-byte pushes
        let item1 = vec![0x01]; // value 1
        let item2 = vec![0x02]; // value 2
        let witness = Witness::from_items(vec![item1, item2, ws_bytes.clone()]);
        let tx = make_simple_tx(witness.clone());

        let result =
            verify_witness_program(0, &program, &witness, &tx, 0, 50_000, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2WSH with stack items should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_empty_witness_no_p2sh_legacy_path() {
        // Legacy script (not P2SH, not witness program) with empty witness
        // and verify_witness=true should succeed (no unexpected witness).
        let verifier = Secp256k1Verifier;
        let flags = ScriptFlags::all();

        let script_pubkey = ScriptBuf::from_bytes(vec![0x51]); // OP_1 = OP_TRUE

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(), // empty witness
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "Legacy OP_TRUE with empty witness should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_extract_all_pushes_empty_script() {
        let pushes = extract_all_pushes(&[]);
        assert!(pushes.is_empty());
    }

    #[test]
    fn test_extract_all_pushes_mixed_push_types() {
        // Mix of direct push, OP_PUSHDATA1, OP_PUSHDATA2, then non-push
        let mut script = Vec::new();
        // Direct push: 2 bytes
        script.push(2u8);
        script.extend_from_slice(&[0xaa, 0xbb]);
        // OP_PUSHDATA1: 1 byte
        script.push(Opcode::OP_PUSHDATA1 as u8);
        script.push(1);
        script.push(0xcc);
        // OP_PUSHDATA2: 2 bytes
        script.push(Opcode::OP_PUSHDATA2 as u8);
        script.extend_from_slice(&2u16.to_le_bytes());
        script.extend_from_slice(&[0xdd, 0xee]);
        // Non-push opcode to stop
        script.push(0x76); // OP_DUP

        let pushes = extract_all_pushes(&script);
        assert_eq!(pushes.len(), 3);
        assert_eq!(pushes[0], &[0xaa, 0xbb]);
        assert_eq!(pushes[1], &[0xcc]);
        assert_eq!(pushes[2], &[0xdd, 0xee]);
    }

    #[test]
    fn test_extract_single_push_pushdata1_not_consumed() {
        // OP_PUSHDATA1 push followed by extra bytes (not a single push)
        let script = vec![Opcode::OP_PUSHDATA1 as u8, 2, 0xaa, 0xbb, 0xcc];
        let result = extract_single_push(&script);
        assert!(
            result.is_none(),
            "OP_PUSHDATA1 with trailing bytes should not be a single push"
        );
    }

    #[test]
    fn test_p2sh_p2sh_flag_disabled() {
        // When verify_p2sh is false, a P2SH scriptPubKey should be treated as
        // legacy (the OP_HASH160 <hash> OP_EQUAL script is run directly).
        let verifier = Secp256k1Verifier;
        let mut flags = ScriptFlags::consensus();
        flags.verify_p2sh = false;

        // Build a P2SH scriptPubKey
        let some_hash = hash160(&[0x51]); // hash of OP_1
        let script_pubkey = ScriptBuf::p2sh(&some_hash);

        // With P2SH disabled, the scriptPubKey is treated literally:
        // OP_HASH160 <20 bytes> OP_EQUAL
        // We need to push data whose HASH160 matches the hash.
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(&[0x51]); // push the preimage

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xba; 32]), 0),
                script_sig,
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(
            result.is_ok(),
            "P2SH with verify_p2sh=false should run as legacy: {:?}",
            result.err()
        );
    }

    // ---- Coverage: verify_input with witness v0 and empty scriptSig ----

    #[test]
    fn test_verify_input_p2wpkh_non_empty_scriptsig_fails() {
        use crate::sig_verify::Secp256k1Verifier;
        let verifier = Secp256k1Verifier;
        let mut flags = ScriptFlags::none();
        flags.verify_witness = true;

        // P2WPKH output (OP_0 <20-byte hash>)
        let pubkey_hash = [0xab; 20];
        let mut spk = vec![0x00, 0x14]; // OP_0 PUSH(20)
        spk.extend_from_slice(&pubkey_hash);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xba; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x00]), // non-empty!
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: vec![Witness::from_items(vec![vec![0x30; 72], vec![0x02; 33]])],
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: ScriptBuf::from_bytes(spk),
        };

        // Should fail because scriptSig must be empty for native segwit
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_err());
    }

    // ---- Coverage: unknown witness version (v2+) succeeds (forward compat) ----

    #[test]
    fn test_verify_input_unknown_witness_version() {
        use crate::sig_verify::Secp256k1Verifier;
        let verifier = Secp256k1Verifier;
        let mut flags = ScriptFlags::none();
        flags.verify_witness = true;

        // Witness v2 output (OP_2 <20-byte program>) - unknown version succeeds
        let mut spk = vec![0x52, 0x14]; // OP_2 PUSH(20)
        spk.extend_from_slice(&[0xab; 20]);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xba; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: vec![Witness::new()],
            lock_time: 0,
        };

        let prev_output = TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: ScriptBuf::from_bytes(spk),
        };

        // Unknown witness versions succeed for forward compatibility
        let result = verify_input(&tx, 0, &prev_output, &verifier, &flags);
        assert!(result.is_ok(), "unknown witness version should succeed");
    }
}
