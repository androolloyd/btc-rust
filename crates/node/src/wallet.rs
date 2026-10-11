//! Offline PSBT spending verification. This is not active-chain or policy admission.

use btc_consensus::script_engine::ScriptFlags;
use btc_consensus::sig_verify::{Secp256k1Verifier, SigError, SignatureVerifier};
use btc_consensus::sighash::{
    p2wpkh_script_code, sighash_legacy, sighash_segwit_v0, sighash_taproot, SighashType,
};
use btc_consensus::witness::verify_input_with_prevouts;
use btc_primitives::amount::Amount;
use btc_primitives::hash::hash160;
use btc_primitives::psbt::{Psbt, PsbtInput};
use btc_primitives::script::{Instruction, Opcode, Script, ScriptBuf};
use btc_primitives::transaction::{Transaction, TxOut, Witness};
use eyre::{bail, ensure, WrapErr};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct VerifiedPsbt {
    pub transaction: Transaction,
    /// Difference of supplied input and output values; not a chain lookup.
    pub fee_sat: i64,
    pub signatures_checked: usize,
    pub txid_linked_prevouts: Vec<bool>,
}

#[derive(Debug)]
pub struct VerifiedPartialSignatures {
    pub unsigned_transaction: Transaction,
    pub fee_sat: i64,
    pub signatures_checked: usize,
    pub signatures_per_input: Vec<usize>,
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
        let mut partial = psbt.clone();
        partial.inputs[0].final_script_sig = None;
        partial.inputs[0].partial_sigs = vec![(pubkey.to_vec(), signature)];
        assert!(verify_partial_signatures(&partial).is_err());
        psbt.inputs[0].non_witness_utxo = Some(parent);
        partial.inputs[0].non_witness_utxo = psbt.inputs[0].non_witness_utxo.clone();
        assert_eq!(partial_cli(&partial)["signatures_checked"], 1);
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

    fn partial_wpkh(hash_type: u8) -> Psbt {
        let mut psbt = signed_wpkh(hash_type);
        let witness = psbt.inputs[0].final_script_witness.take().unwrap();
        psbt.inputs[0].partial_sigs = vec![(witness[1].clone(), witness[0].clone())];
        psbt
    }

    fn partial_cli(psbt: &Psbt) -> serde_json::Value {
        crate::cli::verify_psbt_partials(&hex::encode(psbt.try_serialize().unwrap())).unwrap()
    }

    #[test]
    fn published_bip143_signature_verifies_without_local_signing() {
        // BIP143 P2SH-P2WPKH example (public domain), copied as published:
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        let tx = btc_primitives::decode(&hex::decode("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap()).unwrap();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1_000_000_000),
            script_pubkey: ScriptBuf::from_bytes(
                hex::decode("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387").unwrap(),
            ),
        });
        psbt.inputs[0].redeem_script = Some(ScriptBuf::from_bytes(
            hex::decode("001479091972186c449eb1ded22b78e40d009bdf0089").unwrap(),
        ));
        psbt.inputs[0].partial_sigs = vec![(
            hex::decode("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873").unwrap(),
            hex::decode("3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01").unwrap(),
        )];
        let hash = sighash_segwit_v0(
            &psbt.unsigned_tx,
            0,
            &p2wpkh_script_code(
                &hex::decode("79091972186c449eb1ded22b78e40d009bdf0089")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            1_000_000_000,
            SighashType::ALL,
        )
        .unwrap();
        assert_eq!(
            hex::encode(hash),
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
        );
        let before = psbt.clone();
        let checked = partial_cli(&psbt);
        assert_eq!(checked, partial_cli(&psbt.convert_version(2).unwrap()));
        assert_eq!(checked["signatures_checked"], 1);
        assert_eq!(checked["partial_signatures_verified"], true);
        assert_eq!(checked["spending_conditions_verified"], false);
        assert_eq!(checked["active_chain_verified"], false);
        assert_eq!(checked["key_origins_verified"], false);
        assert!(checked.get("tx_hex").is_none());
        assert_eq!(psbt, before);
        for mutate in 0..4 {
            let mut bad = psbt.clone();
            match mutate {
                0 => bad.inputs[0].partial_sigs[0].1[10] ^= 1,
                1 => bad.unsigned_tx.inputs[0].previous_output.vout ^= 1,
                2 => bad.unsigned_tx.inputs[0].sequence ^= 1,
                _ => {
                    bad.inputs[0].witness_utxo.as_mut().unwrap().value =
                        Amount::from_sat(1_000_000_001)
                }
            }
            assert!(verify_partial_signatures(&bad).is_err());
        }
    }

    #[test]
    fn partial_hash_modes_preserve_commitment_semantics_and_input_models() {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            let psbt = partial_wpkh(hash_type);
            let checked = partial_cli(&psbt);
            assert_eq!(checked, partial_cli(&psbt.convert_version(2).unwrap()));
            assert_eq!(checked["signatures_per_input"], serde_json::json!([1]));
            let mut outputs = psbt.clone();
            outputs.unsigned_tx.outputs[0].value = Amount::from_sat(48_999);
            assert_eq!(
                verify_partial_signatures(&outputs).is_ok(),
                hash_type & 0x7f == 2
            );
            let mut key = psbt.clone();
            key.inputs[0].partial_sigs[0].0 = PublicKey::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&[2; 32]).unwrap(),
            )
            .serialize()
            .to_vec();
            assert!(verify_partial_signatures(&key).is_err());
            let mut missing = psbt.clone();
            missing.inputs[0].partial_sigs.clear();
            assert!(verify_partial_signatures(&missing).is_err());
            let mut missing = psbt.clone();
            missing.inputs[0].witness_utxo = None;
            assert!(verify_partial_signatures(&missing).is_err());
            let mut missing = psbt.clone();
            missing.inputs[0].final_script_witness = Some(vec![]);
            assert!(verify_partial_signatures(&missing).is_err());
            let mut contradiction = psbt.clone();
            contradiction.inputs[0].sighash_type = Some(if hash_type == 2 { 1 } else { 2 });
            assert!(verify_partial_signatures(&contradiction).is_err());
            let mut malformed = psbt.clone();
            malformed.inputs.clear();
            assert!(verify_partial_signatures(&malformed).is_err());
            assert!(crate::cli::verify_psbt(&hex::encode(psbt.try_serialize().unwrap())).is_err());
        }
    }

    #[test]
    fn partial_taproot_requires_all_prevouts_and_the_committed_leaf_key() {
        use btc_primitives::psbt::TapLeafScript;
        let secp = Secp256k1::new();
        let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[5; 32]).unwrap());
        let (public, _) = key.x_only_public_key();
        let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[6; 32]).unwrap())
            .x_only_public_key()
            .0;
        let mut script = ScriptBuf::new();
        script.push_slice(&public.serialize());
        script.push_opcode(Opcode::OP_CHECKSIG);
        let leaf_hash = btc_primitives::taproot::tap_leaf_hash(0xc0, script.as_bytes());
        let (output, parity) =
            btc_primitives::taproot::output_key(&internal.serialize(), Some(&leaf_hash)).unwrap();
        let mut control = vec![0xc0 | parity];
        control.extend(internal.serialize());
        let mut psbt = Psbt::from_unsigned_tx(transaction(2)).unwrap();
        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey: ScriptBuf::p2tr(&output),
            },
            TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey: ScriptBuf::p2tr(&public.serialize()),
            },
        ];
        for (i, out) in prevouts.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(out.clone());
        }
        psbt.inputs[0].tap_leaf_scripts.push((
            control,
            TapLeafScript {
                script,
                leaf_version: 0xc0,
            },
        ));
        let digest = sighash_taproot(
            &psbt.unsigned_tx,
            0,
            &prevouts,
            SighashType(0),
            None,
            Some(&leaf_hash),
        )
        .unwrap();
        let sig = secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &key)
            .as_ref()
            .to_vec();
        let mut record = public.serialize().to_vec();
        record.extend(leaf_hash);
        psbt.inputs[0].tap_script_sigs.push((record, sig));
        let digest =
            sighash_taproot(&psbt.unsigned_tx, 1, &prevouts, SighashType(0), None, None).unwrap();
        psbt.inputs[1].tap_key_sig = Some(
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &key)
                .as_ref()
                .to_vec(),
        );
        assert_eq!(
            partial_cli(&psbt)["signatures_per_input"],
            serde_json::json!([1, 1])
        );
        assert_eq!(
            partial_cli(&psbt),
            partial_cli(&psbt.convert_version(2).unwrap())
        );
        let mut bad = psbt.clone();
        bad.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(25_001);
        assert!(verify_partial_signatures(&bad)
            .unwrap_err()
            .to_string()
            .contains("input 0"));
        let mut bad = psbt.clone();
        bad.inputs[0].tap_leaf_scripts.clear();
        assert!(verify_partial_signatures(&bad).is_err());
        let mut bad = psbt.clone();
        bad.inputs[0].tap_script_sigs[0].0[63] ^= 1;
        assert!(verify_partial_signatures(&bad).is_err());
        let mut bad = psbt.clone();
        bad.inputs[0].tap_script_sigs[0].0[..32].copy_from_slice(&internal.serialize());
        assert!(verify_partial_signatures(&bad).is_err());
        let mut bad = psbt.clone();
        bad.inputs[1].tap_key_sig.as_mut().unwrap()[63] ^= 1;
        assert!(verify_partial_signatures(&bad).is_err());
    }
}

/// Apply the wallet's strict DER/low-S requirements and only count real
/// successful equations, in addition to the shared script validation rules.
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

enum EcdsaTemplate<'a> {
    KeyHash(&'a [u8]),
    Key(&'a [u8]),
    Multisig {
        required: usize,
        keys: Vec<&'a [u8]>,
    },
}

fn ecdsa_template(script: &Script, witness: bool) -> eyre::Result<EcdsaTemplate<'_>> {
    let code = script.as_bytes();
    if script.is_p2pkh() {
        return Ok(EcdsaTemplate::KeyHash(&code[3..23]));
    }
    if matches!(code.first(), Some(33 | 65))
        && code.len() == code[0] as usize + 2
        && code.last() == Some(&(Opcode::OP_CHECKSIG as u8))
        && valid_key(&code[1..code.len() - 1], witness)
    {
        return Ok(EcdsaTemplate::Key(&code[1..code.len() - 1]));
    }
    if code.len() >= 3 && (0x51..=0x60).contains(&code[0]) && code.last() == Some(&0xae) {
        let required = (code[0] - 0x50) as usize;
        let n = code[code.len() - 2].wrapping_sub(0x50) as usize;
        ensure!(n <= 16 && required <= n, "unsupported multisig script");
        let mut pos = 1;
        let mut keys = Vec::with_capacity(n);
        while pos < code.len() - 2 {
            ensure!(keys.len() < n, "unsupported multisig script");
            let end = pos + 1 + code[pos] as usize;
            ensure!(end <= code.len() - 2, "unsupported multisig script");
            let key = &code[pos + 1..end];
            ensure!(valid_key(key, witness), "unsupported multisig key");
            keys.push(key);
            pos = end;
        }
        ensure!(keys.len() == n, "unsupported multisig script");
        return Ok(EcdsaTemplate::Multisig { required, keys });
    }
    bail!("unsupported spending script template")
}

/// Only fully understood signature-bearing templates are accepted. In particular
/// OP_SUCCESS, future leaf/key versions and arbitrary scripts cannot imply verified signatures.
fn ecdsa_stack<'a>(
    script: &Script,
    stack: &[&'a [u8]],
    witness: bool,
) -> eyre::Result<Vec<&'a [u8]>> {
    match ecdsa_template(script, witness)? {
        EcdsaTemplate::KeyHash(_) => {
            ensure!(
                stack.len() == 2 && valid_key(stack[1], witness),
                "invalid P2PKH stack"
            );
            Ok(vec![stack[0]])
        }
        EcdsaTemplate::Key(_) => {
            ensure!(stack.len() == 1, "invalid P2PK stack");
            Ok(vec![stack[0]])
        }
        EcdsaTemplate::Multisig { required, .. } => {
            ensure!(
                stack.len() == required + 1 && stack[0].is_empty(),
                "invalid multisig stack"
            );
            Ok(stack[1..].to_vec())
        }
    }
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
        return Ok((
            ecdsa_stack(script, &stack, false)?
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect(),
            false,
            false,
        ));
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

fn check_sighash(sig: &[u8], taproot: bool, declared: Option<u32>) -> eyre::Result<SighashType> {
    let hash_type = if taproot {
        match sig.len() {
            64 => 0,
            65 if sig[64] != 0 => sig[64] as u32,
            _ => bail!("invalid Taproot signature encoding"),
        }
    } else {
        ensure!(
            (9..=73).contains(&sig.len()),
            "invalid ECDSA signature encoding"
        );
        sig[sig.len() - 1] as u32
    };
    ensure!(
        taproot && hash_type == 0 || matches!(hash_type, 1 | 2 | 3 | 0x81 | 0x82 | 0x83),
        "unsupported signature sighash type"
    );
    ensure!(
        declared.is_none_or(|value| value == hash_type),
        "signature differs from declared sighash type"
    );
    Ok(SighashType(hash_type))
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

/// Check transaction shape/value conservation and resolve all supplied prevouts.
fn verification_context(psbt: &Psbt, tx: &Transaction) -> eyre::Result<(Vec<TxOut>, i64)> {
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
    Ok((prevouts, input_value - output_value))
}

/// Verify final spending conditions using real ECDSA/Schnorr equations and every
/// supplied prevout. Known templates only; no chain lookup, maturity/finality,
/// fee policy, key-origin or unused partial-signature claim is made.
pub fn verify_finalized_psbt(psbt: &Psbt) -> eyre::Result<VerifiedPsbt> {
    let tx = psbt.clone().finalize()?;
    let (prevouts, fee_sat) = verification_context(psbt, &tx)?;
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
        fee_sat,
        signatures_checked: verifier.0.load(Ordering::Relaxed),
        txid_linked_prevouts: psbt
            .inputs
            .iter()
            .map(|input| input.non_witness_utxo.is_some())
            .collect(),
    })
}

/// Resolve the exact scriptCode and BIP143/legacy mode. PSBT serialization has
/// already checked the supplied redeem/witness scripts against their commitments.
fn partial_script_code(output: &Script, input: &PsbtInput) -> eyre::Result<(ScriptBuf, bool)> {
    let program = if output.is_p2sh() {
        input
            .redeem_script
            .as_ref()
            .ok_or_else(|| eyre::eyre!("missing redeem script"))?
            .as_script()
    } else {
        output
    };
    if program.is_p2wpkh() {
        return Ok((
            ScriptBuf::from_bytes(p2wpkh_script_code(&program.as_bytes()[2..].try_into()?)),
            true,
        ));
    }
    if program.is_p2wsh() {
        return Ok((
            input
                .witness_script
                .clone()
                .ok_or_else(|| eyre::eyre!("missing witness script"))?,
            true,
        ));
    }
    ensure!(!program.is_witness_program(), "unsupported witness program");
    Ok((program.to_owned(), false))
}

fn verify_partial_input(
    psbt: &Psbt,
    index: usize,
    prevouts: &[TxOut],
    verifier: &WalletVerifier,
) -> eyre::Result<usize> {
    let input = &psbt.inputs[index];
    ensure!(
        input.final_script_sig.is_none() && input.final_script_witness.is_none(),
        "partial verification requires an unfinalized input"
    );
    let count = input.partial_sigs.len()
        + usize::from(input.tap_key_sig.is_some())
        + input.tap_script_sigs.len();
    ensure!(count > 0, "missing partial signatures");
    let output = &prevouts[index];
    let tx = &psbt.unsigned_tx;
    if output.script_pubkey.is_p2tr() {
        // BIP371 binds key signatures directly to Q, not the internal key.
        let q = &output.script_pubkey.as_bytes()[2..];
        if let Some(sig) = &input.tap_key_sig {
            let hash_type = check_sighash(sig, true, input.sighash_type)?;
            let hash = sighash_taproot(tx, index, prevouts, hash_type, None, None)?;
            ensure!(
                verifier.verify_schnorr(&hash, &sig[..64], q)?,
                "partial signature equation failed"
            );
        }
        // Leaf/control proofs are bound to Q by try_serialize; indexing their
        // actual hashes avoids trusting a signature's leaf-hash label or doing
        // quadratic scans across many supplied leaves.
        let leaves: HashMap<_, _> = input
            .tap_leaf_scripts
            .iter()
            .map(|(_, leaf)| {
                (
                    btc_primitives::taproot::tap_leaf_hash(
                        leaf.leaf_version,
                        leaf.script.as_bytes(),
                    ),
                    leaf,
                )
            })
            .collect();
        for (record, sig) in &input.tap_script_sigs {
            let leaf_hash: [u8; 32] = record[32..].try_into()?;
            let leaf = leaves
                .get(&leaf_hash)
                .ok_or_else(|| eyre::eyre!("missing committed Taproot leaf for signature"))?;
            let code = leaf.script.as_bytes();
            ensure!(
                leaf.leaf_version == 0xc0 && code.len() == 34 && code[0] == 32 && code[33] == 0xac,
                "unsupported tapscript template"
            );
            ensure!(
                code[1..33] == record[..32],
                "partial signature key does not belong to Taproot leaf"
            );
            let hash_type = check_sighash(sig, true, input.sighash_type)?;
            let hash = sighash_taproot(tx, index, prevouts, hash_type, None, Some(&leaf_hash))?;
            ensure!(
                verifier.verify_schnorr(&hash, &sig[..64], &record[..32])?,
                "partial signature equation failed"
            );
        }
        ensure!(
            input.partial_sigs.is_empty(),
            "ECDSA partial signature on Taproot input"
        );
    } else {
        ensure!(
            input.tap_key_sig.is_none() && input.tap_script_sigs.is_empty(),
            "Taproot signature on non-Taproot input"
        );
        let (code, witness) = partial_script_code(output.script_pubkey.as_script(), input)?;
        ensure!(
            witness || input.non_witness_utxo.is_some(),
            "legacy verification requires non-witness UTXO"
        );
        let template = ecdsa_template(code.as_script(), witness)?;
        for (key, sig) in &input.partial_sigs {
            ensure!(valid_key(key, witness), "unsupported partial signature key");
            let belongs = match &template {
                EcdsaTemplate::KeyHash(expected) => hash160(key).as_slice() == *expected,
                EcdsaTemplate::Key(expected) => key.as_slice() == *expected,
                EcdsaTemplate::Multisig { keys, .. } => keys.contains(&key.as_slice()),
            };
            ensure!(
                belongs,
                "partial signature key does not belong to spending script"
            );
            let hash_type = check_sighash(sig, false, input.sighash_type)?;
            let hash = if witness {
                sighash_segwit_v0(tx, index, code.as_bytes(), output.value.as_sat(), hash_type)?
            } else {
                sighash_legacy(tx, index, code.as_bytes(), hash_type)?
            };
            ensure!(
                verifier.verify_ecdsa(&hash, &sig[..sig.len() - 1], key)?,
                "partial signature equation failed"
            );
        }
    }
    Ok(count)
}

/// Verify every supplied partial record for each unfinalized input. This does not
/// establish a sufficient set of signatures, final spending conditions, origins
/// or chain admission. Taproot context is no annex, with known single-key leaves
/// (no OP_CODESEPARATOR); unsupported or missing context returns an error.
pub fn verify_partial_signatures(psbt: &Psbt) -> eyre::Result<VerifiedPartialSignatures> {
    psbt.try_serialize()?;
    let (prevouts, fee_sat) = verification_context(psbt, &psbt.unsigned_tx)?;
    let verifier = WalletVerifier::default();
    let signatures_per_input = (0..psbt.inputs.len())
        .map(|index| {
            verify_partial_input(psbt, index, &prevouts, &verifier)
                .wrap_err_with(|| format!("input {index}: partial verification failed"))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    let signatures_checked = verifier.0.load(Ordering::Relaxed);
    ensure!(
        signatures_checked == signatures_per_input.iter().sum::<usize>(),
        "partial signature verification count differs"
    );
    Ok(VerifiedPartialSignatures {
        unsigned_transaction: psbt.unsigned_tx.clone(),
        fee_sat,
        signatures_checked,
        signatures_per_input,
        txid_linked_prevouts: psbt
            .inputs
            .iter()
            .map(|input| input.non_witness_utxo.is_some())
            .collect(),
    })
}
