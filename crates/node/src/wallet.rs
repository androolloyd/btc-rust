//! Offline PSBT verification and finalization against supplied prevouts.

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

#[derive(Debug)]
pub struct FinalizedPsbt {
    pub psbt: Psbt,
    pub verified: VerifiedPsbt,
    /// All supplied partial records, including ones not selected for the spend.
    pub partial_signatures_checked: usize,
    pub partial_signatures_per_input: Vec<usize>,
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
        let finalized = finalize_psbt(&psbt).unwrap();
        // The actual published signature/key and implied BIP141 scriptSig,
        // independent of our signer or finalizer, must appear unchanged.
        assert_eq!(
            hex::encode(
                finalized.verified.transaction.inputs[0]
                    .script_sig
                    .as_bytes()
            ),
            "16001479091972186c449eb1ded22b78e40d009bdf0089"
        );
        assert_eq!(
            finalized.verified.transaction.witness[0],
            Witness::from_items(vec![
                before.inputs[0].partial_sigs[0].1.clone(),
                before.inputs[0].partial_sigs[0].0.clone()
            ])
        );
        assert_eq!(finalized.partial_signatures_checked, 1);
        assert_eq!(finalized.verified.signatures_checked, 1);
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

    fn partial_taproot_script_and_key() -> Psbt {
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
        psbt
    }

    #[test]
    fn partial_taproot_requires_all_prevouts_and_the_committed_leaf_key() {
        let psbt = partial_taproot_script_and_key();
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
        bad.inputs[0].tap_script_sigs[0].0[..32]
            .copy_from_slice(&psbt.inputs[0].tap_leaf_scripts[0].0[1..33]);
        assert!(
            format!("{:#}", verify_partial_signatures(&bad).unwrap_err())
                .contains("does not belong to Taproot leaf")
        );
        let mut bad = psbt.clone();
        bad.inputs[1].tap_key_sig.as_mut().unwrap()[63] ^= 1;
        assert!(verify_partial_signatures(&bad).is_err());
    }

    #[test]
    fn finalizer_cleans_metadata_and_preserves_v2_locktime_single_and_unknowns() {
        for hash_type in [1, 2, 3, 0x81, 0x82, 0x83] {
            for version in [0, 2] {
                let mut psbt = partial_wpkh(hash_type).convert_version(version).unwrap();
                psbt.inputs[0].sighash_type = Some(u32::from(hash_type));
                psbt.inputs[0].bip32_derivation = vec![(
                    psbt.inputs[0].partial_sigs[0].0.clone(),
                    ([1; 4], vec![2, 3]),
                )];
                psbt.inputs[0].unknown = vec![(vec![0x50], vec![1, 2])];
                psbt.outputs[0].unknown = vec![(vec![0x50], vec![3, 4])];
                if version == 2 {
                    psbt.inputs[0].required_height_lock_time = Some(23);
                }
                let before = psbt.clone();
                let finalization = finalize_psbt(&psbt).unwrap();
                let final_psbt = finalization.psbt;
                assert_eq!(psbt, before);
                assert_eq!(final_psbt.unsigned_tx, before.unsigned_tx);
                assert_eq!(final_psbt.outputs, before.outputs);
                assert_eq!(final_psbt.tx_modifiable, before.tx_modifiable);
                assert_eq!(final_psbt.fallback_lock_time, before.fallback_lock_time);
                let input = &final_psbt.inputs[0];
                assert_eq!(input.witness_utxo, before.inputs[0].witness_utxo);
                assert_eq!(input.unknown, before.inputs[0].unknown);
                assert_eq!(
                    input.required_height_lock_time,
                    before.inputs[0].required_height_lock_time
                );
                assert!(input.partial_sigs.is_empty() && input.bip32_derivation.is_empty());
                assert!(input.sighash_type.is_none() && input.final_script_sig.is_none());
                assert_eq!(finalization.partial_signatures_per_input, vec![1]);
                let wire = final_psbt.try_serialize().unwrap();
                assert_eq!(Psbt::deserialize(&wire).unwrap(), final_psbt);
                let repeated = finalize_psbt(&final_psbt).unwrap();
                assert_eq!(repeated.psbt, final_psbt);
                assert_eq!(repeated.partial_signatures_checked, 0);
                assert_eq!(
                    repeated.verified.transaction,
                    finalization.verified.transaction
                );
                let json = crate::cli::finalize_psbt(&hex::encode(before.try_serialize().unwrap()))
                    .unwrap();
                assert_eq!(json["complete"], true);
                assert_eq!(json["partial_signatures_checked"], 1);
                assert_eq!(json["active_chain_verified"], false);
                assert_eq!(json["key_origins_verified"], false);
                assert_eq!(json["psbt_hex"], hex::encode(wire));
            }
        }
    }

    fn partial_multisig(wrapped: bool, witness: bool) -> Psbt {
        let secp = Secp256k1::new();
        let keys: Vec<_> = [3, 1, 2]
            .into_iter()
            .map(|value| SecretKey::from_slice(&[value; 32]).unwrap())
            .collect();
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_2);
        for key in &keys {
            script.push_slice(&PublicKey::from_secret_key(&secp, key).serialize());
        }
        script.push_opcode(Opcode::OP_3);
        script.push_opcode(Opcode::OP_CHECKMULTISIG);
        let program = if witness {
            ScriptBuf::p2wsh(&btc_primitives::hash::sha256(script.as_bytes()))
        } else {
            script.clone()
        };
        let output = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: if wrapped {
                ScriptBuf::p2sh(&hash160(program.as_bytes()))
            } else {
                program.clone()
            },
        };
        let mut parent = transaction(1);
        parent.outputs = vec![output.clone()];
        let mut tx = transaction(1);
        tx.inputs[0].previous_output.txid = parent.txid();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(parent);
        if witness {
            psbt.inputs[0].witness_utxo = Some(output);
            psbt.inputs[0].witness_script = Some(script.clone());
        }
        if wrapped {
            psbt.inputs[0].redeem_script = Some(program);
        }
        let digest = if witness {
            sighash_segwit_v0(
                &psbt.unsigned_tx,
                0,
                script.as_bytes(),
                50_000,
                SighashType::ALL,
            )
            .unwrap()
        } else {
            sighash_legacy(&psbt.unsigned_tx, 0, script.as_bytes(), SighashType::ALL).unwrap()
        };
        // Deliberately reverse the script's key order, with an excess signature.
        psbt.inputs[0].partial_sigs = keys
            .iter()
            .rev()
            .map(|key| {
                let mut sig = secp
                    .sign_ecdsa(&Message::from_digest(digest), key)
                    .serialize_der()
                    .to_vec();
                sig.push(1);
                (
                    PublicKey::from_secret_key(&secp, key).serialize().to_vec(),
                    sig,
                )
            })
            .collect();
        psbt
    }

    #[test]
    fn finalizer_orders_multisig_and_checks_even_unselected_signatures() {
        for (wrapped, witness) in [(false, false), (true, false), (false, true), (true, true)] {
            for version in [0, 2] {
                let psbt = partial_multisig(wrapped, witness)
                    .convert_version(version)
                    .unwrap();
                let result = finalize_psbt(&psbt).unwrap();
                assert_eq!(result.partial_signatures_checked, 3);
                let tx = &result.verified.transaction;
                if witness {
                    assert_eq!(tx.witness[0].get(0), Some(&[][..]));
                    assert_eq!(
                        tx.witness[0].get(1),
                        Some(psbt.inputs[0].partial_sigs[2].1.as_slice())
                    );
                    assert_eq!(
                        tx.witness[0].get(2),
                        Some(psbt.inputs[0].partial_sigs[1].1.as_slice())
                    );
                    assert_eq!(tx.witness[0].len(), 4);
                } else {
                    let stack = push_stack(tx.inputs[0].script_sig.as_script()).unwrap();
                    assert!(stack[0].is_empty());
                    assert_eq!(stack[1], psbt.inputs[0].partial_sigs[2].1);
                    assert_eq!(stack[2], psbt.inputs[0].partial_sigs[1].1);
                    assert_eq!(stack.len(), if wrapped { 4 } else { 3 });
                }
                assert!(result.psbt.inputs[0].redeem_script.is_none());
                assert!(result.psbt.inputs[0].witness_script.is_none());
                let mut bad = psbt.clone();
                bad.inputs[0].partial_sigs[0].1[10] ^= 1;
                let before = bad.clone();
                assert!(finalize_psbt(&bad).is_err());
                assert_eq!(bad, before);
                let mut incomplete = psbt.clone();
                incomplete.inputs[0].partial_sigs.truncate(1);
                let before = incomplete.clone();
                assert!(format!("{:#}", finalize_psbt(&incomplete).unwrap_err())
                    .contains("insufficient multisig"));
                assert_eq!(incomplete, before);
            }
        }
    }

    #[test]
    fn finalizer_handles_mixed_inputs_and_never_repairs_invalid_final_fields() {
        for version in [0, 2] {
            let psbt = partial_taproot_script_and_key()
                .convert_version(version)
                .unwrap();
            let completed = finalize_psbt(&psbt).unwrap();
            assert_eq!(completed.partial_signatures_per_input, vec![1, 1]);
            assert_eq!(completed.verified.transaction.witness[0].len(), 3);
            assert_eq!(completed.verified.transaction.witness[1].len(), 1);
            assert!(completed
                .psbt
                .inputs
                .iter()
                .all(|input| input.tap_leaf_scripts.is_empty()
                    && input.tap_key_sig.is_none()
                    && input.tap_script_sigs.is_empty()));
            let mut mixed = psbt.clone();
            mixed.inputs[0] = completed.psbt.inputs[0].clone();
            let result = finalize_psbt(&mixed).unwrap();
            assert_eq!(result.psbt, completed.psbt);
            assert_eq!(result.partial_signatures_per_input, vec![0, 1]);
            // Present unused partial records on a final input are checked too.
            let mut both = psbt.clone();
            both.inputs[0].final_script_witness =
                completed.psbt.inputs[0].final_script_witness.clone();
            assert!(finalize_psbt(&both).is_ok());
            both.inputs[0].tap_script_sigs[0].1[63] ^= 1;
            assert!(finalize_psbt(&both).is_err());
            let mut bad = mixed.clone();
            bad.inputs[0].final_script_witness.as_mut().unwrap()[0][63] ^= 1;
            assert!(finalize_psbt(&bad).is_err());
            let mut bad = psbt.clone();
            bad.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(25_001);
            assert!(finalize_psbt(&bad).is_err());
            let mut bad = psbt.clone();
            bad.inputs[1].tap_key_sig = None;
            let before = bad.clone();
            assert!(finalize_psbt(&bad).is_err());
            assert_eq!(bad, before);
        }
    }

    #[test]
    fn finalizer_prefers_shortest_taproot_path_then_a_complete_key_path() {
        use btc_primitives::psbt::TapLeafScript;
        use btc_primitives::taproot::{output_key, tap_branch_hash, tap_leaf_hash, tap_tweak_hash};
        let secp = Secp256k1::new();
        let keys: Vec<_> = [5, 7, 8]
            .into_iter()
            .map(|v| Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[v; 32]).unwrap()))
            .collect();
        let scripts: Vec<_> = keys
            .iter()
            .map(|key| {
                let mut script = ScriptBuf::new();
                script.push_slice(&key.x_only_public_key().0.serialize());
                script.push_opcode(Opcode::OP_CHECKSIG);
                script
            })
            .collect();
        let hashes: Vec<_> = scripts
            .iter()
            .map(|script| tap_leaf_hash(0xc0, script.as_bytes()))
            .collect();
        let branch = tap_branch_hash(&hashes[1], &hashes[2]);
        let root = tap_branch_hash(&hashes[0], &branch);
        let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[6; 32]).unwrap());
        let internal_pub = internal.x_only_public_key().0.serialize();
        let (q, parity) = output_key(&internal_pub, Some(&root)).unwrap();
        let prevouts = vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2tr(&q),
        }];
        let mut psbt = Psbt::from_unsigned_tx(transaction(1)).unwrap();
        psbt.inputs[0].witness_utxo = Some(prevouts[0].clone());
        let paths = [
            vec![branch],
            vec![hashes[2], hashes[0]],
            vec![hashes[1], hashes[0]],
        ];
        for i in (0..3).rev() {
            let mut control = vec![0xc0 | parity];
            control.extend(internal_pub);
            for sibling in &paths[i] {
                control.extend(sibling);
            }
            psbt.inputs[0].tap_leaf_scripts.push((
                control,
                TapLeafScript {
                    script: scripts[i].clone(),
                    leaf_version: 0xc0,
                },
            ));
            let digest = sighash_taproot(
                &psbt.unsigned_tx,
                0,
                &prevouts,
                SighashType(0),
                None,
                Some(&hashes[i]),
            )
            .unwrap();
            let signature = secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keys[i])
                .as_ref()
                .to_vec();
            let mut record = keys[i].x_only_public_key().0.serialize().to_vec();
            record.extend(hashes[i]);
            psbt.inputs[0].tap_script_sigs.push((record, signature));
        }
        let result = finalize_psbt(&psbt).unwrap();
        assert_eq!(result.partial_signatures_checked, 3);
        assert_eq!(
            result.verified.transaction.witness[0].get(1),
            Some(scripts[0].as_bytes())
        );
        assert_eq!(
            result.verified.transaction.witness[0].get(2).unwrap().len(),
            65
        );
        let tweak =
            secp256k1::Scalar::from_be_bytes(tap_tweak_hash(&internal_pub, Some(&root))).unwrap();
        let tweaked = internal.add_xonly_tweak(&secp, &tweak).unwrap();
        assert_eq!(tweaked.x_only_public_key().0.serialize(), q);
        let digest =
            sighash_taproot(&psbt.unsigned_tx, 0, &prevouts, SighashType(0), None, None).unwrap();
        psbt.inputs[0].tap_key_sig = Some(
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &tweaked)
                .as_ref()
                .to_vec(),
        );
        let result = finalize_psbt(&psbt).unwrap();
        assert_eq!(result.partial_signatures_checked, 4);
        assert_eq!(result.verified.transaction.witness[0].len(), 1);
        // A valid key path does not excuse a bad, unused leaf signature.
        psbt.inputs[0].tap_script_sigs[0].1[63] ^= 1;
        assert!(finalize_psbt(&psbt).is_err());
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
            let input = &psbt.inputs[index];
            ensure!(
                input.final_script_sig.is_none() && input.final_script_witness.is_none(),
                "input {index}: partial verification requires an unfinalized input"
            );
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

/// Assemble signatures in script key order, rather than PSBT record order.
/// All records have already passed equation and committed-key verification.
fn final_ecdsa_stack(
    script: &Script,
    input: &PsbtInput,
    witness: bool,
) -> eyre::Result<Vec<Vec<u8>>> {
    let signatures: HashMap<_, _> = input
        .partial_sigs
        .iter()
        .map(|(key, sig)| (key.as_slice(), sig))
        .collect();
    match ecdsa_template(script, witness)? {
        EcdsaTemplate::KeyHash(expected) => {
            let (key, sig) = input
                .partial_sigs
                .iter()
                .filter(|(key, _)| hash160(key).as_slice() == expected)
                .min_by(|a, b| a.0.cmp(&b.0))
                .ok_or_else(|| eyre::eyre!("missing P2PKH signature"))?;
            Ok(vec![sig.clone(), key.clone()])
        }
        EcdsaTemplate::Key(key) => Ok(vec![(*signatures
            .get(key)
            .ok_or_else(|| eyre::eyre!("missing P2PK signature"))?)
        .clone()]),
        EcdsaTemplate::Multisig { required, keys } => {
            let mut stack = vec![Vec::new()]; // CHECKMULTISIG's mandatory dummy.
            for key in keys {
                if let Some(sig) = signatures.get(key) {
                    stack.push((*sig).clone());
                    if stack.len() == required + 1 {
                        break;
                    }
                }
            }
            ensure!(
                stack.len() == required + 1,
                "insufficient multisig signatures"
            );
            Ok(stack)
        }
    }
}

fn final_taproot_witness(input: &PsbtInput) -> eyre::Result<Vec<Vec<u8>>> {
    // Core prefers a complete key path, then the smallest serialized witness.
    if let Some(sig) = &input.tap_key_sig {
        return Ok(vec![sig.clone()]);
    }
    let signatures: HashMap<_, _> = input
        .tap_script_sigs
        .iter()
        .map(|(key, sig)| (key.as_slice(), sig.as_slice()))
        .collect();
    let mut best = None;
    for (control, leaf) in &input.tap_leaf_scripts {
        let script = leaf.script.as_bytes();
        if leaf.leaf_version != 0xc0 || script.len() != 34 || script[0] != 32 || script[33] != 0xac
        {
            continue;
        }
        let mut record = [0; 64];
        record[..32].copy_from_slice(&script[1..33]);
        record[32..].copy_from_slice(&btc_primitives::taproot::tap_leaf_hash(0xc0, script));
        if let Some(sig) = signatures.get(record.as_slice()) {
            let size = 1
                + sig.len()
                + 1
                + script.len()
                + 1
                + control.len()
                + btc_primitives::VarInt(control.len() as u64).encoded_size();
            // Core's script map is lexicographic; its control set orders by
            // length, then bytes. Match ties without depending on map order.
            let order = (size, script, control.len(), control.as_slice());
            if best.as_ref().is_none_or(|(previous, _)| order < *previous) {
                best = Some((order, *sig));
            }
        }
    }
    let ((_, script, _, control), sig) =
        best.ok_or_else(|| eyre::eyre!("missing supported Taproot script satisfaction"))?;
    Ok(vec![sig.to_vec(), script.to_vec(), control.to_vec()])
}

fn assemble_final_input(output: &Script, input: &mut PsbtInput) -> eyre::Result<()> {
    if output.is_p2tr() {
        input.final_script_witness = Some(final_taproot_witness(input)?);
        return Ok(());
    }
    let (code, witness) = partial_script_code(output, input)?;
    let mut stack = final_ecdsa_stack(code.as_script(), input, witness)?;
    let program = if output.is_p2sh() {
        input.redeem_script.as_ref().unwrap().as_script()
    } else {
        output
    };
    let mut script_sig = ScriptBuf::new();
    if witness {
        if program.is_p2wsh() {
            stack.push(input.witness_script.as_ref().unwrap().as_bytes().to_vec());
        }
        if output.is_p2sh() {
            script_sig.push_slice(program.as_bytes());
        }
        input.final_script_witness = Some(stack);
    } else {
        if output.is_p2sh() {
            stack.push(program.as_bytes().to_vec());
        }
        for item in stack {
            if item.is_empty() {
                script_sig.push_opcode(Opcode::OP_0);
            } else {
                script_sig.push_slice(&item);
            }
        }
    }
    if !script_sig.is_empty() {
        input.final_script_sig = Some(script_sig);
    }
    Ok(())
}

/// Finalize known signature-bearing templates, verifying all supplied partial
/// records and the resulting complete spend. Returns an isolated result: failure
/// never mutates the caller's PSBT. Existing final inputs are verified as well.
/// No signatures/keys are created, and no active-chain or key-origin claim is made.
pub fn finalize_psbt(psbt: &Psbt) -> eyre::Result<FinalizedPsbt> {
    psbt.try_serialize()?;
    let (prevouts, _) = verification_context(psbt, &psbt.unsigned_tx)?;
    let verifier = WalletVerifier::default();
    let mut finalized = psbt.clone();
    let mut partial_signatures_per_input = Vec::with_capacity(psbt.inputs.len());
    for (index, output) in prevouts.iter().enumerate() {
        let input = &psbt.inputs[index];
        let has_final = input.final_script_sig.is_some() || input.final_script_witness.is_some();
        let has_partial = !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty();
        let checked = if has_partial || !has_final {
            verify_partial_input(psbt, index, &prevouts, &verifier)
                .wrap_err_with(|| format!("input {index}: partial verification failed"))?
        } else {
            0
        };
        partial_signatures_per_input.push(checked);
        if !has_final {
            assemble_final_input(
                output.script_pubkey.as_script(),
                &mut finalized.inputs[index],
            )
            .wrap_err_with(|| format!("input {index}: finalization failed"))?;
        }
    }
    // Check the complete transaction before clearing declarations and metadata.
    let verified = verify_finalized_psbt(&finalized)?;
    for input in &mut finalized.inputs {
        let old = std::mem::take(input);
        *input = PsbtInput {
            non_witness_utxo: old.non_witness_utxo,
            witness_utxo: old.witness_utxo,
            final_script_sig: old.final_script_sig,
            final_script_witness: old.final_script_witness,
            // BIP370 explicitly retains construction and locktime fields.
            required_time_lock_time: old.required_time_lock_time,
            required_height_lock_time: old.required_height_lock_time,
            unknown: old.unknown,
            ..Default::default()
        };
    }
    ensure!(
        finalized.clone().finalize()? == verified.transaction,
        "finalizer cleanup changed the transaction"
    );
    let partial_signatures_checked = verifier.0.load(Ordering::Relaxed);
    ensure!(
        partial_signatures_checked == partial_signatures_per_input.iter().sum::<usize>(),
        "partial signature verification count differs"
    );
    Ok(FinalizedPsbt {
        psbt: finalized,
        verified,
        partial_signatures_checked,
        partial_signatures_per_input,
    })
}
