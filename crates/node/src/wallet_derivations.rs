//! Public derivation equations relative to supplied PSBT global xpub anchors.
//! An anchor and its master fingerprint are not authenticated wallet identities.

use btc_primitives::bip32::{ChildNumber, ExtendedPubKey};
use btc_primitives::psbt::{KeySource, Psbt};
use eyre::{bail, ensure, WrapErr};
use std::collections::HashMap;

const MAX_ANCHORS: usize = 256;
const MAX_RECORDS: usize = 4096;
const MAX_DERIVATION_STEPS: usize = 10_000;

#[derive(Debug)]
pub struct VerifiedKeyDerivation {
    pub scope: &'static str,
    pub index: usize,
    pub pubkey: Vec<u8>,
    pub taproot: bool,
    pub source: KeySource,
    pub global_xpub_index: usize,
    pub relative_path: Vec<u32>,
}

#[derive(Debug)]
pub struct VerifiedKeyDerivations {
    pub records: Vec<VerifiedKeyDerivation>,
    /// Unique CKDpub operations, shared between records using the same prefix.
    pub derivation_steps_checked: usize,
}

struct Record<'a> {
    scope: &'static str,
    index: usize,
    key: &'a [u8],
    source: &'a KeySource,
    taproot: bool,
}

/// Verify every supplied input/output legacy and Taproot derivation record.
/// Requires a matching supplied global xpub with a publicly derivable suffix.
/// Does not authenticate anchors, prove leaf membership or verify signatures.
pub fn verify_key_derivations(psbt: &Psbt) -> eyre::Result<VerifiedKeyDerivations> {
    ensure!(!psbt.xpub.is_empty(), "missing global xpub anchors");
    ensure!(
        psbt.xpub.len() <= MAX_ANCHORS,
        "too many global xpub anchors (maximum {MAX_ANCHORS})"
    );
    let count = psbt
        .inputs
        .iter()
        .map(|input| {
            input
                .bip32_derivation
                .len()
                .saturating_add(input.tap_bip32_derivation.len())
        })
        .chain(psbt.outputs.iter().map(|output| {
            output
                .bip32_derivation
                .len()
                .saturating_add(output.tap_bip32_derivation.len())
        }))
        .fold(0usize, usize::saturating_add);
    ensure!(count != 0, "missing key derivation records");
    ensure!(
        count <= MAX_RECORDS,
        "too many key derivation records (maximum {MAX_RECORDS})"
    );
    // Validate public models as strictly as parsed wire data before any proof.
    psbt.try_serialize().wrap_err("invalid PSBT model")?;
    let anchors = psbt
        .xpub
        .iter()
        .map(|(data, source)| Ok((ExtendedPubKey::deserialize(data)?, source)))
        .collect::<eyre::Result<Vec<_>>>()?;
    let mut records = Vec::with_capacity(count);
    for (index, input) in psbt.inputs.iter().enumerate() {
        for (key, source) in &input.bip32_derivation {
            records.push(Record {
                scope: "input",
                index,
                key,
                source,
                taproot: false,
            });
        }
        for (key, source) in &input.tap_bip32_derivation {
            records.push(Record {
                scope: "input",
                index,
                key,
                source: &source.key_source,
                taproot: true,
            });
        }
    }
    for (index, output) in psbt.outputs.iter().enumerate() {
        for (key, source) in &output.bip32_derivation {
            records.push(Record {
                scope: "output",
                index,
                key,
                source,
                taproot: false,
            });
        }
        for (key, source) in &output.tap_bip32_derivation {
            records.push(Record {
                scope: "output",
                index,
                key,
                source: &source.key_source,
                taproot: true,
            });
        }
    }
    let mut cache = HashMap::<(usize, Vec<u32>), ExtendedPubKey>::new();
    let mut steps = 0;
    let mut verified = Vec::with_capacity(count);
    for record in records {
        ensure!(
            record.source.1.len() <= 255,
            "{} {}: derivation path exceeds BIP32 depth",
            record.scope,
            record.index
        );
        let target = if record.taproot {
            None
        } else {
            Some(secp256k1::PublicKey::from_slice(record.key)?)
        };
        let mut matched = None;
        let mut hardened = false;
        'anchors: for (anchor_index, (anchor, source)) in anchors.iter().enumerate() {
            if source.0 != record.source.0 || !record.source.1.starts_with(&source.1) {
                continue;
            }
            let suffix = &record.source.1[source.1.len()..];
            if suffix.iter().any(|child| child & 0x80000000 != 0) {
                hardened = true;
                continue;
            }
            let mut derived = anchor.clone();
            let mut path = Vec::with_capacity(suffix.len());
            for child in suffix {
                path.push(*child);
                if let Some(key) = cache.get(&(anchor_index, path.clone())) {
                    derived = key.clone();
                } else {
                    ensure!(steps < MAX_DERIVATION_STEPS, "public derivation work limit exceeded (maximum {MAX_DERIVATION_STEPS} steps)");
                    steps += 1;
                    // An invalid CKDpub child cannot prove this record, but a
                    // colliding fingerprint may have another usable anchor.
                    derived = match derived.derive_child(ChildNumber(*child)) {
                        Ok(key) => key,
                        Err(_) => continue 'anchors,
                    };
                    cache.insert((anchor_index, path.clone()), derived.clone());
                }
            }
            let equal = if record.taproot {
                derived
                    .public_key
                    .x_only_public_key()
                    .0
                    .serialize()
                    .as_slice()
                    == record.key
            } else {
                Some(derived.public_key) == target
            };
            if equal {
                matched = Some((anchor_index, suffix.to_vec()));
                break;
            }
            // Four-byte fingerprints can collide. Try other matching anchors;
            // never interpret the fingerprint itself as a proof of identity.
        }
        let Some((global_xpub_index, relative_path)) = matched else {
            if hardened {
                bail!(
                    "{} {}: hardened derivation requires a deeper supplied xpub anchor",
                    record.scope,
                    record.index
                );
            }
            bail!(
                "{} {}: no supplied global xpub derives the claimed key/path",
                record.scope,
                record.index
            );
        };
        verified.push(VerifiedKeyDerivation {
            scope: record.scope,
            index: record.index,
            pubkey: record.key.to_vec(),
            taproot: record.taproot,
            source: record.source.clone(),
            global_xpub_index,
            relative_path,
        });
    }
    Ok(VerifiedKeyDerivations {
        records: verified,
        derivation_steps_checked: steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{
        psbt::TapKeySource, Amount, OutPoint, ScriptBuf, Transaction, TxHash, TxIn, TxOut,
    };

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../primitives/tests/data/bip32-keys.json")).unwrap()
    }

    fn model(anchor: &serde_json::Value, child: &serde_json::Value) -> Psbt {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([1; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            witness: vec![],
            lock_time: 0,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let source = |row: &serde_json::Value| {
            (
                hex::decode(row["master_fingerprint"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                row["child_indices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|child| child.as_u64().unwrap() as u32)
                    .collect::<Vec<_>>(),
            )
        };
        let public =
            hex::decode(child["serialized_xpub"].as_str().unwrap()).unwrap()[45..].to_vec();
        psbt.unsigned_tx.outputs[0].script_pubkey =
            ScriptBuf::p2tr(&public[1..].try_into().unwrap());
        psbt.xpub = vec![(
            hex::decode(anchor["serialized_xpub"].as_str().unwrap()).unwrap(),
            source(anchor),
        )];
        psbt.inputs[0].bip32_derivation = vec![(public.clone(), source(child))];
        psbt.outputs[0].bip32_derivation = vec![(public.clone(), source(child))];
        let tap = TapKeySource {
            leaf_hashes: vec![],
            key_source: source(child),
        };
        psbt.inputs[0].tap_bip32_derivation = vec![(public[1..].to_vec(), tap.clone())];
        psbt.outputs[0].tap_bip32_derivation = vec![(public[1..].to_vec(), tap)];
        psbt
    }

    #[test]
    fn published_bip32_keys_verify_all_record_kinds_and_cache_prefixes() {
        let data = fixture();
        let rows = data["valid_keys"].as_array().unwrap();
        assert_eq!(rows.len(), 17);
        for child in rows {
            let path = child["child_indices"].as_array().unwrap();
            let anchor = rows
                .iter()
                .find(|row| {
                    let base = row["child_indices"].as_array().unwrap();
                    row["vector"] == child["vector"]
                        && path.starts_with(base)
                        && path[base.len()..]
                            .iter()
                            .all(|index| index.as_u64().unwrap() < 0x80000000)
                })
                .unwrap();
            let psbt = model(anchor, child);
            let before = psbt.clone();
            let checked = verify_key_derivations(&psbt).unwrap();
            assert_eq!(checked.records.len(), 4);
            assert_eq!(
                checked.derivation_steps_checked,
                path.len() - anchor["child_indices"].as_array().unwrap().len()
            );
            assert_eq!(psbt, before);
            let mut uncompressed = psbt.clone();
            let point =
                secp256k1::PublicKey::from_slice(&uncompressed.inputs[0].bip32_derivation[0].0)
                    .unwrap();
            uncompressed.inputs[0].bip32_derivation[0].0 = point.serialize_uncompressed().to_vec();
            assert_eq!(
                verify_key_derivations(&uncompressed).unwrap().records.len(),
                4
            );
            let json =
                crate::cli::verify_psbt_derivations(&hex::encode(psbt.try_serialize().unwrap()))
                    .unwrap();
            assert!(json["derivation_equations_verified"].as_bool().unwrap());
            assert_eq!(json["key_origins_verified"], false);
            assert_eq!(json["wallet_ownership_verified"], false);
            assert_eq!(
                json,
                crate::cli::verify_psbt_derivations(&hex::encode(
                    psbt.convert_version(2).unwrap().try_serialize().unwrap()
                ))
                .unwrap()
            );
        }
    }

    #[test]
    fn changed_keys_paths_chaincodes_and_missing_or_hardened_anchors_fail() {
        let data = fixture();
        let rows = data["valid_keys"].as_array().unwrap();
        let good = model(&rows[1], &rows[2]);
        for variant in 0..6 {
            let mut bad = good.clone();
            match variant {
                0 => bad.inputs[0].bip32_derivation[0].1 .0[0] ^= 1,
                1 => bad.outputs[0].tap_bip32_derivation[0].1.key_source.1[1] ^= 1,
                2 => {
                    bad.inputs[0].bip32_derivation[0].0 =
                        hex::decode(rows[0]["serialized_xpub"].as_str().unwrap()).unwrap()[45..]
                            .to_vec()
                }
                3 => bad.xpub[0].0[13] ^= 1,
                4 => bad.xpub.clear(),
                _ => bad.inputs[0].bip32_derivation[0].1 .1 = vec![0; 256],
            }
            let before = bad.clone();
            assert!(verify_key_derivations(&bad).is_err());
            assert_eq!(before, bad);
        }
        let hardened = model(&rows[0], &rows[1]);
        assert!(verify_key_derivations(&hardened)
            .unwrap_err()
            .to_string()
            .contains("hardened"));
        let mut no_records = good.clone();
        no_records.inputs[0].bip32_derivation.clear();
        no_records.inputs[0].tap_bip32_derivation.clear();
        no_records.outputs[0].bip32_derivation.clear();
        no_records.outputs[0].tap_bip32_derivation.clear();
        assert!(verify_key_derivations(&no_records)
            .unwrap_err()
            .to_string()
            .contains("missing key derivation"));
    }

    #[test]
    fn fingerprints_are_only_candidates_and_untrusted_work_is_bounded() {
        let data = fixture();
        let rows = data["valid_keys"].as_array().unwrap();
        let mut psbt = model(&rows[1], &rows[2]);
        let real = psbt.xpub[0].clone();
        psbt.xpub[0].0[13] ^= 1; // same fingerprint, different supplied chain code
        psbt.xpub.push(real);
        assert!(verify_key_derivations(&psbt)
            .unwrap()
            .records
            .iter()
            .all(|record| record.global_xpub_index == 1));
        let mut excessive = psbt.clone();
        excessive.xpub = vec![psbt.xpub[0].clone(); MAX_ANCHORS + 1];
        assert!(verify_key_derivations(&excessive)
            .unwrap_err()
            .to_string()
            .contains("too many global xpub"));
        let mut excessive = model(&rows[0], &rows[0]);
        excessive.inputs[0].bip32_derivation =
            vec![excessive.inputs[0].bip32_derivation[0].clone(); MAX_RECORDS + 1];
        assert!(verify_key_derivations(&excessive)
            .unwrap_err()
            .to_string()
            .contains("too many key derivation"));
        let mut expensive = model(&rows[0], &rows[0]);
        let base = expensive.xpub[0].clone();
        expensive.xpub = (0..41)
            .map(|i| {
                let mut anchor = base.clone();
                anchor.0[13..45].fill(i);
                anchor
            })
            .collect();
        expensive.inputs[0].bip32_derivation[0].1 .1 = vec![0; 255];
        assert!(verify_key_derivations(&expensive)
            .unwrap_err()
            .to_string()
            .contains("work limit exceeded"));
    }
}
