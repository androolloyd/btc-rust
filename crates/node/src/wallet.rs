//! Offline PSBT spending verification. This is not active-chain or policy admission.

use btc_consensus::script_engine::ScriptFlags;
use btc_consensus::sig_verify::{Secp256k1Verifier, SigError, SignatureVerifier};
use btc_consensus::witness::verify_input_with_prevouts;
use btc_primitives::amount::Amount;
use btc_primitives::psbt::Psbt;
use btc_primitives::script::{Instruction, Opcode, Script};
use btc_primitives::transaction::{Transaction, Witness};
use eyre::{bail, ensure, WrapErr};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct VerifiedPsbt {
    pub transaction: Transaction,
    /// Difference of supplied input and output values; not a chain lookup.
    pub fee_sat: i64,
    pub signatures_checked: usize,
    pub txid_linked_prevouts: Vec<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_consensus::sighash::{
        p2wpkh_script_code, sighash_segwit_v0, sighash_taproot, SighashType,
    };
    use btc_primitives::hash::{hash160, TxHash};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, TxIn, TxOut};
    use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};

    fn transaction(inputs: usize) -> Transaction {
        Transaction {
            version: 2,
            inputs: (0..inputs)
                .map(|i| TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([i as u8 + 1; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: 0xfffffffd,
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            witness: vec![],
            lock_time: 23,
        }
    }

    fn signed_wpkh(hash_type: u8) -> Psbt {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &key).serialize();
        let hash = hash160(&pubkey);
        let mut psbt = Psbt::from_unsigned_tx(transaction(1)).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2wpkh(&hash),
        });
        let message = sighash_segwit_v0(
            &psbt.unsigned_tx,
            0,
            &p2wpkh_script_code(&hash),
            50_000,
            SighashType(hash_type as u32),
        )
        .unwrap();
        let mut sig = secp
            .sign_ecdsa(&Message::from_digest(message), &key)
            .serialize_der()
            .to_vec();
        sig.push(hash_type);
        psbt.inputs[0].final_script_witness = Some(vec![sig, pubkey.to_vec()]);
        psbt
    }

    fn verify_cli(psbt: &Psbt) -> serde_json::Value {
        crate::cli::verify_psbt(&hex::encode(psbt.try_serialize().unwrap())).unwrap()
    }

    #[test]
    fn finalized_equations_and_scope_survive_both_psbt_versions() {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            let psbt = signed_wpkh(hash_type);
            let v0 = verify_cli(&psbt);
            let v2 = verify_cli(&psbt.convert_version(2).unwrap());
            assert_eq!(v0, v2);
            assert_eq!(v0["signatures_verified"], true);
            assert_eq!(v0["signatures_checked"], 1);
            assert_eq!(v0["fee_sat"], 1000);
            assert_eq!(v0["txid_linked_prevouts"], serde_json::json!([false]));
            assert_eq!(v0["active_chain_verified"], false);
            assert_eq!(v0["partial_signatures_verified"], false);
            let mut bad = psbt.clone();
            bad.inputs[0].final_script_witness.as_mut().unwrap()[0][10] ^= 1;
            assert!(verify_finalized_psbt(&bad).is_err());
            let mut bad = psbt.clone();
            bad.unsigned_tx.lock_time ^= 1;
            assert!(verify_finalized_psbt(&bad).is_err());
            let mut bad = psbt.clone();
            bad.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(50_001);
            assert!(verify_finalized_psbt(&bad).is_err());
            let mut bad = psbt.clone();
            bad.inputs[0].sighash_type = Some(if hash_type == 2 { 1 } else { 2 });
            assert!(verify_finalized_psbt(&bad)
                .unwrap_err()
                .to_string()
                .contains("input 0"));
            let mut changed = psbt.clone();
            changed.unsigned_tx.outputs[0].value = Amount::from_sat(48_999);
            assert_eq!(
                verify_finalized_psbt(&changed).is_ok(),
                hash_type & 0x7f == 2
            );
        }
    }

    #[test]
    fn taproot_verifies_other_inputs_prevouts_not_just_selected_amount() {
        let secp = Secp256k1::new();
        let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2; 32]).unwrap());
        let (public, _) = key.x_only_public_key();
        let mut psbt = Psbt::from_unsigned_tx(transaction(2)).unwrap();
        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey: ScriptBuf::p2tr(&public.serialize())
            };
            2
        ];
        for (i, out) in prevouts.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(out.clone());
            let hash = sighash_taproot(&psbt.unsigned_tx, i, &prevouts, SighashType(0), None, None)
                .unwrap();
            let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), &key);
            psbt.inputs[i].final_script_witness = Some(vec![sig.as_ref().to_vec()]);
        }
        assert_eq!(verify_cli(&psbt)["signatures_checked"], 2);
        let mut bad = psbt.clone();
        bad.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(25_001);
        assert!(verify_finalized_psbt(&bad)
            .unwrap_err()
            .to_string()
            .contains("input 0: spending verification failed"));
        let mut bad = psbt.clone();
        bad.inputs[1].witness_utxo = None;
        assert!(verify_finalized_psbt(&bad)
            .unwrap_err()
            .to_string()
            .contains("input 1: missing UTXO"));
        let mut bad = psbt.clone();
        bad.inputs[1].final_script_witness.as_mut().unwrap()[0].push(0);
        assert!(verify_finalized_psbt(&bad).is_err());
    }

    #[test]
    fn incomplete_unsafe_and_non_signature_spends_never_report_verification() {
        let psbt = signed_wpkh(1);
        let mut missing = psbt.clone();
        missing.inputs[0].final_script_witness = None;
        assert!(verify_finalized_psbt(&missing).is_err());
        let mut missing = psbt.clone();
        missing.inputs[0].witness_utxo = None;
        assert!(verify_finalized_psbt(&missing).is_err());
        for script in [
            vec![0x51],
            vec![0x52, 0x20].into_iter().chain([1; 32]).collect(),
            vec![0x51, 2, 0x4e, 0x73],
        ] {
            let mut future = psbt.clone();
            future.inputs[0]
                .witness_utxo
                .as_mut()
                .unwrap()
                .script_pubkey = ScriptBuf::from_bytes(script);
            future.inputs[0].final_script_witness = Some(vec![]);
            future.inputs[0].final_script_sig = Some(ScriptBuf::new());
            assert!(verify_finalized_psbt(&future).is_err());
        }
        let mut bad = psbt.clone();
        bad.unsigned_tx.outputs[0].value = Amount::from_sat(50_001);
        assert!(verify_finalized_psbt(&bad)
            .unwrap_err()
            .to_string()
            .contains("outputs exceed"));
        let mut bad = psbt.clone();
        bad.unsigned_tx.inputs[0].previous_output = OutPoint::COINBASE;
        assert!(verify_finalized_psbt(&bad)
            .unwrap_err()
            .to_string()
            .contains("null input"));
        let mut bad = psbt.clone();
        bad.unsigned_tx
            .inputs
            .push(bad.unsigned_tx.inputs[0].clone());
        bad.inputs.push(bad.inputs[0].clone());
        assert!(verify_finalized_psbt(&bad)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[test]
    fn finalized_encoding_and_wrapped_witness_are_strict() {
        let psbt = signed_wpkh(1);
        for bad_sig in [
            vec![],
            vec![1; 8],
            {
                let mut sig = psbt.inputs[0].final_script_witness.as_ref().unwrap()[0].clone();
                sig[0] = 0x31;
                sig
            },
            {
                let mut sig = psbt.inputs[0].final_script_witness.as_ref().unwrap()[0].clone();
                *sig.last_mut().unwrap() = 0x41;
                sig
            },
        ] {
            let mut bad = psbt.clone();
            bad.inputs[0].final_script_witness.as_mut().unwrap()[0] = bad_sig;
            assert!(verify_finalized_psbt(&bad).is_err());
        }
        let mut wrapped = psbt.clone();
        let redeem = wrapped.inputs[0]
            .witness_utxo
            .as_ref()
            .unwrap()
            .script_pubkey
            .clone();
        wrapped.inputs[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = ScriptBuf::p2sh(&hash160(redeem.as_bytes()));
        let mut canonical = ScriptBuf::new();
        canonical.push_slice(redeem.as_bytes());
        wrapped.inputs[0].final_script_sig = Some(canonical);
        assert!(verify_finalized_psbt(&wrapped).is_ok());
        let mut noncanonical = vec![0x4c, redeem.len() as u8];
        noncanonical.extend(redeem.as_bytes());
        wrapped.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(noncanonical));
        assert!(verify_finalized_psbt(&wrapped)
            .unwrap_err()
            .to_string()
            .contains("input 0"));
    }

    #[test]
    fn legacy_requires_a_txid_linked_parent_and_evaluates_its_signature() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[3; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &key).serialize();
        let output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2pkh(&hash160(&pubkey)),
        };
        let mut parent = transaction(1);
        parent.outputs = vec![output.clone()];
        let mut tx = transaction(1);
        tx.inputs[0].previous_output.txid = parent.txid();
        let hash = btc_consensus::sighash_legacy(
            &tx,
            0,
            output.script_pubkey.as_bytes(),
            SighashType::ALL,
        )
        .unwrap();
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest(hash), &key)
            .serialize_der()
            .to_vec();
        signature.push(1);
        let mut final_script = ScriptBuf::new();
        final_script.push_slice(&signature);
        final_script.push_slice(&pubkey);
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(output);
        psbt.inputs[0].final_script_sig = Some(final_script);
        assert!(verify_finalized_psbt(&psbt)
            .unwrap_err()
            .to_string()
            .contains("non-witness UTXO"));
        psbt.inputs[0].non_witness_utxo = Some(parent);
        assert_eq!(
            verify_cli(&psbt)["txid_linked_prevouts"],
            serde_json::json!([true])
        );
        let mut bad = psbt.clone();
        bad.unsigned_tx.outputs[0].value = Amount::from_sat(48_999);
        assert!(verify_finalized_psbt(&bad).is_err());
    }

    #[test]
    fn future_taproot_leaf_or_opcode_cannot_bypass_wallet_verification() {
        let mut psbt = signed_wpkh(1);
        let (internal, _) =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[4; 32]).unwrap())
                .x_only_public_key();
        for (version, script) in [
            (0xc2, vec![0x51]),
            (0xc0, vec![0x50]),
            (0xc0, vec![1, 1, 0xac]),
        ] {
            let leaf = btc_primitives::taproot::tap_leaf_hash(version, &script);
            let (output, parity) =
                btc_primitives::taproot::output_key(&internal.serialize(), Some(&leaf)).unwrap();
            let mut control = vec![version | parity];
            control.extend(internal.serialize());
            psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = ScriptBuf::p2tr(&output);
            psbt.inputs[0].final_script_witness = Some(vec![vec![1; 64], script, control]);
            assert!(verify_finalized_psbt(&psbt).is_err());
        }
    }
}

/// Strict DER/low-S checks also cover the direct P2WPKH dispatcher, which does
/// not run the script engine's encoding flags. Only count real successful equations.
#[derive(Default)]
struct WalletVerifier(AtomicUsize);

impl SignatureVerifier for WalletVerifier {
    fn verify_ecdsa(&self, hash: &[u8; 32], sig: &[u8], key: &[u8]) -> Result<bool, SigError> {
        let parsed = secp256k1::ecdsa::Signature::from_der(sig)?;
        let mut normalized = parsed;
        normalized.normalize_s();
        if parsed.serialize_der().as_ref() != sig || normalized != parsed {
            return Err(SigError::InvalidEncoding);
        }
        let valid = Secp256k1Verifier.verify_ecdsa(hash, sig, key)?;
        if valid {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        Ok(valid)
    }

    fn verify_schnorr(&self, hash: &[u8; 32], sig: &[u8], key: &[u8]) -> Result<bool, SigError> {
        let valid = Secp256k1Verifier.verify_schnorr(hash, sig, key)?;
        if valid {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        Ok(valid)
    }
}

fn push_stack(script: &Script) -> eyre::Result<Vec<&[u8]>> {
    script
        .instructions()
        .map(|item| match item? {
            Instruction::PushBytes(data) => Ok(data),
            Instruction::Op(Opcode::OP_0) => Ok(&[][..]),
            _ => Err(eyre::eyre!("unsupported final scriptSig operation")),
        })
        .collect()
}

fn valid_key(key: &[u8], witness: bool) -> bool {
    let shape =
        key.len() == 33 && matches!(key[0], 2 | 3) || !witness && key.len() == 65 && key[0] == 4;
    shape && secp256k1::PublicKey::from_slice(key).is_ok()
}

/// Only fully understood signature-bearing templates are accepted. In particular
/// OP_SUCCESS, future leaf/key versions and arbitrary scripts cannot imply verified signatures.
fn ecdsa_stack<'a>(
    script: &Script,
    stack: &[&'a [u8]],
    witness: bool,
) -> eyre::Result<Vec<&'a [u8]>> {
    if script.is_p2pkh() {
        ensure!(
            stack.len() == 2 && valid_key(stack[1], witness),
            "invalid P2PKH stack"
        );
        return Ok(vec![stack[0]]);
    }
    let code = script.as_bytes();
    if matches!(code.first(), Some(33 | 65))
        && code.len() == code[0] as usize + 2
        && code.last() == Some(&(Opcode::OP_CHECKSIG as u8))
        && valid_key(&code[1..code.len() - 1], witness)
    {
        ensure!(stack.len() == 1, "invalid P2PK stack");
        return Ok(vec![stack[0]]);
    }
    // Canonical m-of-n CHECKMULTISIG with actual compressed/uncompressed keys.
    if code.len() >= 3 && (0x51..=0x60).contains(&code[0]) && code.last() == Some(&0xae) {
        let m = (code[0] - 0x50) as usize;
        let n = code[code.len() - 2].wrapping_sub(0x50) as usize;
        let mut pos = 1;
        let mut keys = 0;
        while pos < code.len() - 2 {
            let len = code[pos] as usize;
            let end = pos + 1 + len;
            ensure!(end <= code.len() - 2, "unsupported multisig script");
            ensure!(
                valid_key(&code[pos + 1..end], witness),
                "unsupported multisig key"
            );
            keys += 1;
            pos = end;
        }
        ensure!(
            n <= 16 && m <= n && keys == n,
            "unsupported multisig script"
        );
        ensure!(
            stack.len() == m + 1 && stack[0].is_empty(),
            "invalid multisig stack"
        );
        return Ok(stack[1..].to_vec());
    }
    bail!("unsupported spending script template")
}

fn witness_signatures(witness: &Witness, program: &Script) -> eyre::Result<Vec<Vec<u8>>> {
    let items: Vec<&[u8]> = witness.iter().map(Vec::as_slice).collect();
    if program.is_p2wpkh() {
        ensure!(
            items.len() == 2 && valid_key(items[1], true),
            "invalid P2WPKH stack"
        );
        Ok(vec![items[0].to_vec()])
    } else if program.is_p2wsh() {
        let (script, stack) = items
            .split_last()
            .ok_or_else(|| eyre::eyre!("missing witness script"))?;
        Ok(ecdsa_stack(Script::from_bytes(script), stack, true)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect())
    } else {
        bail!("unsupported witness program")
    }
}

fn input_signatures(
    tx: &Transaction,
    index: usize,
    program: &Script,
) -> eyre::Result<(Vec<Vec<u8>>, bool, bool)> {
    let empty = Witness::new();
    let witness = tx.witness.get(index).unwrap_or(&empty);
    if program.is_p2tr() {
        let (_, len) = btc_consensus::taproot::extractannex(witness);
        ensure!(len > 0, "missing Taproot witness");
        if len != 1 {
            let control = witness.get(len - 1).unwrap();
            let script = witness.get(len - 2).unwrap();
            ensure!(
                control.first().is_some_and(|v| v & 0xfe == 0xc0),
                "unsupported Taproot leaf version"
            );
            ensure!(
                len == 3 && script.len() == 34 && script[0] == 32 && script[33] == 0xac,
                "unsupported tapscript template"
            );
            secp256k1::XOnlyPublicKey::from_slice(&script[1..33])?;
        }
        return Ok((vec![witness.get(0).unwrap().to_vec()], true, true));
    }
    if program.is_p2wpkh() || program.is_p2wsh() {
        return Ok((witness_signatures(witness, program)?, false, true));
    }
    let mut stack = push_stack(tx.inputs[index].script_sig.as_script())?;
    if program.is_p2sh() {
        let redeem = stack
            .pop()
            .ok_or_else(|| eyre::eyre!("missing redeem script"))?;
        let script = Script::from_bytes(redeem);
        if script.is_witness_program() {
            ensure!(stack.is_empty(), "invalid wrapped witness scriptSig");
            let bytes = tx.inputs[index].script_sig.as_bytes();
            ensure!(
                bytes.len() == redeem.len() + 1 && bytes[0] as usize == redeem.len(),
                "noncanonical wrapped witness scriptSig"
            );
            return Ok((witness_signatures(witness, script)?, false, true));
        }
        bail!("unsupported legacy P2SH spending template");
    }
    Ok((
        ecdsa_stack(program, &stack, false)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect(),
        false,
        false,
    ))
}

fn check_sighash(sig: &[u8], taproot: bool, declared: Option<u32>) -> eyre::Result<()> {
    let hash_type = if taproot {
        match sig.len() {
            64 => 0,
            65 if sig[64] != 0 => sig[64] as u32,
            _ => bail!("invalid finalized Taproot signature encoding"),
        }
    } else {
        ensure!(
            (9..=73).contains(&sig.len()),
            "invalid finalized ECDSA signature encoding"
        );
        sig[sig.len() - 1] as u32
    };
    ensure!(
        taproot && hash_type == 0 || matches!(hash_type, 1 | 2 | 3 | 0x81 | 0x82 | 0x83),
        "unsupported finalized signature sighash type"
    );
    ensure!(
        declared.is_none_or(|value| value == hash_type),
        "finalized signature differs from declared sighash type"
    );
    Ok(())
}

fn value_sum(mut values: impl Iterator<Item = i64>) -> eyre::Result<i64> {
    values.try_fold(0i64, |sum, value| {
        ensure!(
            (0..=Amount::MAX_MONEY.as_sat()).contains(&value),
            "value out of range"
        );
        sum.checked_add(value)
            .filter(|v| *v <= Amount::MAX_MONEY.as_sat())
            .ok_or_else(|| eyre::eyre!("total value out of range"))
    })
}

/// Verify final spending conditions using real ECDSA/Schnorr equations and every
/// supplied prevout. Known templates only; no chain lookup, maturity/finality,
/// fee policy, key-origin or unused partial-signature claim is made.
pub fn verify_finalized_psbt(psbt: &Psbt) -> eyre::Result<VerifiedPsbt> {
    let tx = psbt.clone().finalize()?;
    ensure!(
        !tx.inputs.is_empty() && !tx.outputs.is_empty(),
        "empty transaction"
    );
    ensure!(
        tx.weight() <= 4_000_000,
        "transaction exceeds maximum weight"
    );
    let mut seen = HashSet::new();
    for input in &tx.inputs {
        ensure!(
            !input.previous_output.is_coinbase() && seen.insert(input.previous_output),
            "duplicate or null input"
        );
    }
    let prevouts = (0..tx.inputs.len())
        .map(|index| {
            psbt.input_utxo(index)?
                .cloned()
                .ok_or_else(|| eyre::eyre!("input {index}: missing UTXO"))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    let input_value = value_sum(prevouts.iter().map(|out| out.value.as_sat()))?;
    let output_value = value_sum(tx.outputs.iter().map(|out| out.value.as_sat()))?;
    ensure!(
        input_value >= output_value,
        "outputs exceed supplied input values"
    );
    let verifier = WalletVerifier::default();
    for (index, output) in prevouts.iter().enumerate() {
        let (signatures, taproot, witness) =
            input_signatures(&tx, index, output.script_pubkey.as_script())
                .wrap_err_with(|| format!("input {index}"))?;
        ensure!(
            witness || psbt.inputs[index].non_witness_utxo.is_some(),
            "input {index}: legacy verification requires non-witness UTXO"
        );
        for sig in &signatures {
            check_sighash(sig, taproot, psbt.inputs[index].sighash_type)
                .wrap_err_with(|| format!("input {index}"))?;
        }
        let before = verifier.0.load(Ordering::Relaxed);
        verify_input_with_prevouts(&tx, index, &prevouts, &verifier, &ScriptFlags::all())
            .wrap_err_with(|| format!("input {index}: spending verification failed"))?;
        ensure!(
            verifier.0.load(Ordering::Relaxed) > before,
            "input {index}: no signature equation verified"
        );
    }
    Ok(VerifiedPsbt {
        transaction: tx,
        fee_sat: input_value - output_value,
        signatures_checked: verifier.0.load(Ordering::Relaxed),
        txid_linked_prevouts: psbt
            .inputs
            .iter()
            .map(|input| input.non_witness_utxo.is_some())
            .collect(),
    })
}
