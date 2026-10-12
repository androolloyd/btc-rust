//! Bounded CKDpriv signing relative to explicitly supplied private anchors.
//! Fingerprints select candidates; actual curve keys and full xpub payloads
//! prove derivations. A deep anchor alone cannot authenticate its master path.

use btc_primitives::{
    bip32::{ChildNumber, ExtendedPrivKey},
    psbt::{KeySource, Psbt},
    wif::WifPrivateKey,
    Network,
};
use eyre::{ensure, WrapErr};
use std::collections::{HashMap, HashSet};

const MAX_ANCHORS: usize = 64;
const MAX_RECORDS: usize = 4096;
const MAX_STEPS: usize = 10_000;
const MAX_LEAF_HASHES: usize = 16_384;

#[derive(Clone)]
pub struct HdSigningAnchor {
    key: ExtendedPrivKey,
    origin: KeySource,
}

impl std::fmt::Debug for HdSigningAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HdSigningAnchor")
            .field("origin", &self.origin)
            .field("depth", &self.key.depth)
            .finish_non_exhaustive()
    }
}

impl HdSigningAnchor {
    /// Bare master xprv/tprv, or [fingerprint/path]xprv/tprv for a deep anchor.
    /// Errors never include the private source text or a chain code.
    pub fn parse(text: &str, network: Network) -> eyre::Result<Self> {
        ensure!(
            text.len() <= 4096 && text.is_ascii(),
            "invalid HD anchor text"
        );
        let (origin, encoded) = if let Some(rest) = text.strip_prefix('[') {
            let (annotation, encoded) = rest
                .split_once(']')
                .ok_or_else(|| eyre::eyre!("invalid HD anchor origin"))?;
            let mut parts = annotation.split('/');
            let fingerprint = parts.next().unwrap_or_default();
            ensure!(
                fingerprint.len() == 8 && fingerprint.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid HD anchor fingerprint"
            );
            let fingerprint = u32::from_str_radix(fingerprint, 16)
                .map_err(|_| eyre::eyre!("invalid HD anchor fingerprint"))?
                .to_be_bytes();
            let mut path = Vec::new();
            for part in parts {
                ensure!(!part.is_empty(), "invalid HD anchor path");
                let (number, hardened) = if part.ends_with('h') || part.ends_with('\'') {
                    (&part[..part.len() - 1], true)
                } else {
                    (part, false)
                };
                ensure!(
                    !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit()),
                    "invalid HD anchor path"
                );
                let number: u32 = number
                    .parse()
                    .map_err(|_| eyre::eyre!("invalid HD anchor index"))?;
                ensure!(
                    number < 0x80000000 && path.len() < 255,
                    "invalid HD anchor path/depth"
                );
                path.push(number | if hardened { 0x80000000 } else { 0 });
            }
            (Some((fingerprint, path)), encoded)
        } else {
            (None, text)
        };
        let key = ExtendedPrivKey::from_base58(encoded)
            .map_err(|_| eyre::eyre!("invalid extended private key"))?;
        Self::from_key(key, origin, network)
    }

    pub fn from_key(
        key: ExtendedPrivKey,
        origin: Option<KeySource>,
        network: Network,
    ) -> eyre::Result<Self> {
        ExtendedPrivKey::deserialize(&key.serialize())
            .map_err(|_| eyre::eyre!("invalid private anchor model"))?;
        ensure!(
            (key.network == Network::Mainnet) == (network == Network::Mainnet),
            "HD private version does not match selected network"
        );
        let origin = match origin {
            Some(source) => source,
            None => {
                ensure!(
                    key.depth == 0,
                    "non-master private anchor requires an explicit origin"
                );
                (key.fingerprint(), Vec::new())
            }
        };
        ensure!(
            origin.1.len() == usize::from(key.depth),
            "HD anchor depth differs from origin"
        );
        if key.depth == 0 {
            ensure!(
                origin.0 == key.fingerprint(),
                "HD master fingerprint differs from actual key"
            );
        } else {
            ensure!(
                origin.1.last() == Some(&key.child_number.0),
                "HD anchor terminal child differs from origin"
            );
            if key.depth == 1 {
                ensure!(
                    origin.0 == key.parent_fingerprint,
                    "HD anchor parent fingerprint differs from origin"
                );
            }
        }
        Ok(Self { key, origin })
    }
}

#[derive(Debug)]
pub struct HdInputDerivation {
    pub input: usize,
    pub pubkey: Vec<u8>,
    pub taproot: bool,
    pub source: KeySource,
    pub anchor_index: usize,
    pub relative_path: Vec<u32>,
}

#[derive(Debug)]
pub struct SignedHdPsbt {
    pub signed: crate::wallet::SignedPsbt,
    pub input_derivations: Vec<HdInputDerivation>,
    pub derivation_steps_checked: usize,
    pub anchor_master_paths_verified: Vec<bool>,
    pub global_xpubs_checked: usize,
    pub input_foreign_records: usize,
}

struct Deriver<'a> {
    anchors: &'a [HdSigningAnchor],
    cache: HashMap<(usize, Vec<u32>), ExtendedPrivKey>,
    steps: usize,
}

impl Deriver<'_> {
    fn candidates(&self, source: &KeySource) -> Vec<usize> {
        self.anchors
            .iter()
            .enumerate()
            .filter_map(|(i, anchor)| {
                (source.0 == anchor.origin.0 && source.1.starts_with(&anchor.origin.1)).then_some(i)
            })
            .collect()
    }

    // Invalid exact children do not get substituted with the next index. They
    // cannot prove a PSBT path, but a colliding fingerprint may have a valid key.
    fn derive(&mut self, index: usize, path: &[u32]) -> eyre::Result<Option<ExtendedPrivKey>> {
        let anchor = &self.anchors[index];
        ensure!(
            path.len() <= 255 && path.starts_with(&anchor.origin.1),
            "invalid HD relative path"
        );
        let mut key = anchor.key.clone();
        let mut suffix = Vec::new();
        for child in &path[anchor.origin.1.len()..] {
            suffix.push(*child);
            if let Some(cached) = self.cache.get(&(index, suffix.clone())) {
                key = cached.clone();
                continue;
            }
            ensure!(
                self.steps < MAX_STEPS,
                "HD derivation work limit exceeded (10000)"
            );
            self.steps += 1;
            let Ok(derived) = key.derive_child(ChildNumber(*child)) else {
                return Ok(None);
            };
            self.cache.insert((index, suffix.clone()), derived.clone());
            key = derived;
        }
        Ok(Some(key))
    }

    fn prove(
        &mut self,
        source: &KeySource,
        matches: impl Fn(&ExtendedPrivKey) -> bool,
    ) -> eyre::Result<Option<(usize, ExtendedPrivKey)>> {
        let candidates = self.candidates(source);
        if candidates.is_empty() {
            return Ok(None);
        }
        let mut found: Option<(usize, ExtendedPrivKey)> = None;
        for i in candidates {
            if let Some(key) = self.derive(i, &source.1)? {
                if matches(&key) {
                    if let Some((_, old)) = &found {
                        ensure!(
                            old.public_key() == key.public_key()
                                && old.chain_code == key.chain_code,
                            "ambiguous HD private derivation"
                        );
                    } else {
                        found = Some((i, key));
                    }
                }
            }
        }
        ensure!(
            found.is_some(),
            "supplied private anchors cannot derive the claimed owned key/path"
        );
        Ok(found)
    }
}

struct HdPlan {
    input_keys: Vec<crate::wallet::InputSigningKeys>,
    proofs: Vec<HdInputDerivation>,
    steps: usize,
    anchor_origins: Vec<bool>,
    global_checked: usize,
    foreign: usize,
}

fn derive_signing_keys(psbt: &Psbt, anchors: &[HdSigningAnchor]) -> eyre::Result<HdPlan> {
    ensure!(
        !anchors.is_empty() && anchors.len() <= MAX_ANCHORS,
        "HD signer requires 1..64 private anchors"
    );
    crate::wallet::signing_work_bounds(psbt)?;
    let records = psbt.inputs.iter().fold(0usize, |n, input| {
        n.saturating_add(input.bip32_derivation.len())
            .saturating_add(input.tap_bip32_derivation.len())
    });
    ensure!(
        records > 0 && records <= MAX_RECORDS,
        "HD input derivation record limit (1..4096)"
    );
    ensure!(psbt.xpub.len() <= 256, "HD global xpub limit (256)");
    let hashes = psbt
        .inputs
        .iter()
        .flat_map(|input| &input.tap_bip32_derivation)
        .fold(0usize, |n, (_, source)| {
            n.saturating_add(source.leaf_hashes.len())
        });
    ensure!(
        hashes <= MAX_LEAF_HASHES,
        "HD leaf-membership record limit (16384)"
    );
    psbt.try_serialize().wrap_err("invalid HD PSBT model")?;
    let mut unique = HashSet::new();
    for anchor in anchors {
        ensure!(
            unique.insert((
                anchor.key.to_extended_pub_key().serialize(),
                anchor.origin.clone()
            )),
            "duplicate HD private anchor"
        );
    }
    let mut derive = Deriver {
        anchors,
        cache: HashMap::new(),
        steps: 0,
    };
    let mut anchor_origins = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        if anchor.key.depth == 0 {
            anchor_origins.push(true);
            continue;
        }
        let masters = anchors
            .iter()
            .enumerate()
            .filter_map(|(i, root)| {
                (root.key.depth == 0 && root.origin.0 == anchor.origin.0).then_some(i)
            })
            .collect::<Vec<_>>();
        if masters.is_empty() {
            anchor_origins.push(false);
            continue;
        }
        let expected = anchor.key.to_extended_pub_key().serialize();
        let mut matches = false;
        for i in masters {
            if let Some(key) = derive.derive(i, &anchor.origin.1)? {
                matches |= key.to_extended_pub_key().serialize() == expected;
            }
        }
        ensure!(
            matches,
            "private anchor origin does not match a supplied master"
        );
        anchor_origins.push(true);
    }
    let mut global_checked = 0;
    for (encoded, source) in &psbt.xpub {
        if derive
            .prove(source, |key| {
                key.to_extended_pub_key().serialize().as_slice() == encoded.as_slice()
            })?
            .is_some()
        {
            global_checked += 1;
        }
    }
    let mut input_keys = Vec::with_capacity(psbt.inputs.len());
    let mut proofs = Vec::new();
    let mut foreign = 0;
    let mut leaf_keys = HashMap::<(usize, [u8; 32]), HashSet<Vec<u8>>>::new();
    let mut unique_children = HashSet::new();
    for (index, input) in psbt.inputs.iter().enumerate() {
        let mut allowed = crate::wallet::InputSigningKeys::default();
        let output = psbt
            .input_utxo(index)?
            .ok_or_else(|| eyre::eyre!("input {index}: missing UTXO"))?;
        for (public, source) in &input.bip32_derivation {
            let target = secp256k1::PublicKey::from_slice(public)?;
            let Some((anchor_index, key)) = derive
                .prove(source, |key| key.public_key() == target)
                .wrap_err_with(|| format!("input {index}: HD derivation failed"))?
            else {
                foreign += 1;
                continue;
            };
            ensure!(
                !output.script_pubkey.is_p2tr(),
                "input {index}: legacy origin cannot authorize Taproot signing"
            );
            let key = WifPrivateKey::from_secret_key(key.secret_key, public.len() == 33);
            unique_children.insert(key.public_key());
            allowed.keys.push(key);
            proofs.push(HdInputDerivation {
                input: index,
                pubkey: public.clone(),
                taproot: false,
                source: source.clone(),
                anchor_index,
                relative_path: source.1[anchors[anchor_index].origin.1.len()..].to_vec(),
            });
        }
        for (public, source) in &input.tap_bip32_derivation {
            let Some((anchor_index, key)) = derive
                .prove(&source.key_source, |key| {
                    key.public_key()
                        .x_only_public_key()
                        .0
                        .serialize()
                        .as_slice()
                        == public.as_slice()
                })
                .wrap_err_with(|| format!("input {index}: Taproot HD derivation failed"))?
            else {
                foreign += 1;
                continue;
            };
            ensure!(
                output.script_pubkey.is_p2tr(),
                "input {index}: Taproot origin cannot authorize an ECDSA input"
            );
            let internal = input
                .tap_internal_key
                .as_ref()
                .is_some_and(|key| key == public);
            if source.leaf_hashes.is_empty() {
                ensure!(internal, "input {index}: owned empty-hash origin requires the actual internal key (raw output keys unsupported)");
            }
            if internal {
                allowed.taproot_internal.insert(public.clone());
            }
            for hash in &source.leaf_hashes {
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    leaf_keys.entry((index, *hash))
                {
                    let leaf = input
                        .tap_leaf_scripts
                        .iter()
                        .map(|(_, leaf)| leaf)
                        .find(|leaf| {
                            btc_primitives::taproot::tap_leaf_hash(
                                leaf.leaf_version,
                                leaf.script.as_bytes(),
                            ) == *hash
                        })
                        .ok_or_else(|| {
                            eyre::eyre!("input {index}: missing committed leaf for HD origin")
                        })?;
                    ensure!(
                        leaf.leaf_version == 0xc0,
                        "input {index}: unsupported owned HD leaf version"
                    );
                    entry.insert(
                        crate::wallet::known_tapleaf_keys(leaf.script.as_bytes())?
                            .into_iter()
                            .collect(),
                    );
                }
                ensure!(
                    leaf_keys[&(index, *hash)].contains(public),
                    "input {index}: HD key is not in its claimed leaf"
                );
                let mut record = public.clone();
                record.extend(hash);
                allowed.taproot_leaves.insert(record);
            }
            let key = WifPrivateKey::from_secret_key(key.secret_key, true);
            unique_children.insert(key.public_key());
            allowed.keys.push(key);
            proofs.push(HdInputDerivation {
                input: index,
                pubkey: public.clone(),
                taproot: true,
                source: source.key_source.clone(),
                anchor_index,
                relative_path: source.key_source.1[anchors[anchor_index].origin.1.len()..].to_vec(),
            });
        }
        ensure!(
            !allowed.keys.is_empty(),
            "input {index}: no private anchor proves an input signing key"
        );
        ensure!(
            unique_children.len() <= 1024,
            "HD derived signing-key limit (1024)"
        );
        input_keys.push(allowed);
    }
    Ok(HdPlan {
        input_keys,
        proofs,
        steps: derive.steps,
        anchor_origins,
        global_checked,
        foreign,
    })
}

/// Sign only keys proved for each input from actual normal/hardened CKDpriv.
/// Foreign records and output origins are preserved but not authenticated.
pub fn sign_hd_psbt(
    psbt: &Psbt,
    anchors: &[HdSigningAnchor],
    max_fee_sat: u64,
) -> eyre::Result<SignedHdPsbt> {
    let plan = derive_signing_keys(psbt, anchors)?;
    let signed = crate::wallet::sign_psbt_with_input_keys(psbt, &plan.input_keys, max_fee_sat)?;
    Ok(SignedHdPsbt {
        signed,
        input_derivations: plan.proofs,
        derivation_steps_checked: plan.steps,
        anchor_master_paths_verified: plan.anchor_origins,
        global_xpubs_checked: plan.global_checked,
        input_foreign_records: plan.foreign,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::Amount;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../primitives/tests/data/hd-signer.json")).unwrap()
    }
    fn anchors(vector: &serde_json::Value) -> Vec<HdSigningAnchor> {
        vector["anchors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| HdSigningAnchor::parse(key.as_str().unwrap(), Network::Mainnet).unwrap())
            .collect()
    }
    fn psbt(vector: &serde_json::Value) -> Psbt {
        Psbt::deserialize(&hex::decode(vector["psbt"].as_str().unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn published_private_derivations_and_strict_redacted_anchor_input() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../../primitives/tests/data/bip32-keys.json"))
                .unwrap();
        let rows = data["valid_keys"].as_array().unwrap();
        assert_eq!(rows.len(), 17);
        for row in rows {
            let root = rows
                .iter()
                .find(|root| {
                    root["vector"] == row["vector"]
                        && root["child_indices"].as_array().unwrap().is_empty()
                })
                .unwrap();
            let anchors =
                vec![
                    HdSigningAnchor::parse(root["xprv"].as_str().unwrap(), Network::Mainnet)
                        .unwrap(),
                ];
            let path = row["child_indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap() as u32)
                .collect::<Vec<_>>();
            let mut derive = Deriver {
                anchors: &anchors,
                cache: HashMap::new(),
                steps: 0,
            };
            let child = derive.derive(0, &path).unwrap().unwrap();
            assert_eq!(child.to_base58(), row["xprv"]);
            assert_eq!(child.to_extended_pub_key().to_base58(), row["xpub"]);
            assert_eq!(derive.steps, path.len());
            derive.derive(0, &path).unwrap();
            assert_eq!(derive.steps, path.len());
            let origin = (anchors[0].origin.0, path);
            HdSigningAnchor::from_key(child.clone(), Some(origin.clone()), Network::Mainnet)
                .unwrap();
            if child.depth != 0 {
                assert!(HdSigningAnchor::from_key(child, None, Network::Mainnet).is_err());
            }
            let debug = format!("{:?}", anchors[0]);
            assert!(!debug.contains(root["xprv"].as_str().unwrap()));
            assert!(!debug.contains(&hex::encode(anchors[0].key.secret_key.secret_bytes())));
            assert!(!debug.contains(&hex::encode(anchors[0].key.chain_code)));
        }
        let f = fixture();
        let first = &f["vectors"][0];
        let a = anchors(first);
        let encoded = first["anchors"][0].as_str().unwrap();
        for text in [
            format!("[00000000]{encoded}"),
            format!("[deadbeef//0]{encoded}"),
            format!("[deadbeef/2147483648]{encoded}"),
            format!("[deadbeef/0]{encoded}"),
            format!("[deadbeef/{}]{encoded}", "0/".repeat(256)),
            format!("é{encoded}"),
        ] {
            let error = HdSigningAnchor::parse(&text, Network::Mainnet)
                .unwrap_err()
                .to_string();
            assert!(!error.contains(encoded));
        }
        assert!(HdSigningAnchor::parse(encoded, Network::Regtest).is_err());
        let mut wrong = a[0].key.clone();
        wrong.parent_fingerprint = [1; 4];
        assert!(HdSigningAnchor::from_key(wrong, None, Network::Mainnet).is_err());
    }

    #[test]
    fn independent_hd_signatures_children_all_templates_versions_and_partial_cosigning() {
        let data = fixture();
        assert_eq!(data["vectors"].as_array().unwrap().len(), 28);
        for vector in data["vectors"].as_array().unwrap() {
            let roots = anchors(vector);
            for version in [0, 2] {
                let mut original = psbt(vector).convert_version(version).unwrap();
                if version == 2 {
                    original.tx_modifiable = Some(7);
                }
                original.unknown.push((vec![0x9e], vec![6, 7]));
                let before = original.try_serialize().unwrap();
                let plan = derive_signing_keys(&original, &roots).unwrap();
                let keys = plan
                    .input_keys
                    .iter()
                    .map(|input| {
                        input
                            .keys
                            .iter()
                            .map(|key| (key.public_key(), key))
                            .collect::<HashMap<_, _>>()
                    })
                    .collect::<Vec<_>>();
                for child in vector["children"].as_array().unwrap() {
                    let index = child["input"].as_u64().unwrap() as usize;
                    let public = hex::decode(child["public_key"].as_str().unwrap()).unwrap();
                    let key = keys[index].get(&public).unwrap();
                    assert_eq!(
                        hex::encode(key.secret_key().secret_bytes()),
                        child["secret"]
                    );
                }
                let signed = sign_hd_psbt(&original, &roots, 1000).unwrap();
                assert_eq!(original.try_serialize().unwrap(), before);
                assert_eq!(signed.signed.psbt.unknown, original.unknown);
                assert_eq!(
                    signed.signed.psbt.tx_modifiable,
                    (version == 2).then_some(4)
                );
                assert_eq!(
                    signed.input_derivations.len(),
                    vector["children"].as_array().unwrap().len()
                );
                if vector["deep"] == true && vector["master_and_deep"] != true {
                    assert_eq!(signed.anchor_master_paths_verified, vec![false]);
                } else {
                    assert!(signed.anchor_master_paths_verified.iter().all(|yes| *yes));
                }
                assert!(signed.global_xpubs_checked > 0);
                for (index, rows) in vector["expected"].as_array().unwrap().iter().enumerate() {
                    for row in rows.as_array().unwrap() {
                        let record = hex::decode(row["record"].as_str().unwrap()).unwrap();
                        let input = &signed.signed.psbt.inputs[index];
                        match record[0] {
                            2 => assert_eq!(
                                hex::encode(
                                    &input
                                        .partial_sigs
                                        .iter()
                                        .find(|(key, _)| key.as_slice() == &record[1..])
                                        .unwrap()
                                        .1
                                ),
                                row["signature"]
                            ),
                            0x13 => assert_eq!(
                                input.tap_key_sig.as_ref().unwrap().len(),
                                hex::decode(row["signature"].as_str().unwrap())
                                    .unwrap()
                                    .len()
                            ),
                            0x14 => assert_eq!(
                                input
                                    .tap_script_sigs
                                    .iter()
                                    .find(|(key, _)| key.as_slice() == &record[1..])
                                    .unwrap()
                                    .1
                                    .len(),
                                hex::decode(row["signature"].as_str().unwrap())
                                    .unwrap()
                                    .len()
                            ),
                            _ => panic!("unexpected reference record"),
                        }
                    }
                }
                let again = sign_hd_psbt(&signed.signed.psbt, &roots, 1000).unwrap();
                assert_eq!(again.signed.signatures_added, 0);
                assert_eq!(again.signed.psbt, signed.signed.psbt);
                if vector["partial"] == true {
                    assert!(crate::wallet::finalize_psbt(&signed.signed.psbt).is_err());
                    let remaining = vector["remaining_anchors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|key| {
                            HdSigningAnchor::parse(key.as_str().unwrap(), Network::Mainnet).unwrap()
                        })
                        .collect::<Vec<_>>();
                    let complete = sign_hd_psbt(&signed.signed.psbt, &remaining, 1000).unwrap();
                    assert_eq!(complete.signed.signatures_added, 1);
                    crate::wallet::finalize_psbt(&complete.signed.psbt).unwrap();
                } else {
                    crate::wallet::finalize_psbt(&signed.signed.psbt).unwrap();
                }
                assert!(sign_hd_psbt(&original, &roots, 999).is_err());
                if vector["name"] == "tr-declared-leaf-only" {
                    assert_eq!(signed.signed.psbt.inputs[0].tap_script_sigs.len(), 1);
                }
            }
        }
    }

    #[test]
    fn hd_spoofed_origins_private_chain_substitution_and_input_reuse_fail_closed() {
        let data = fixture();
        let base = psbt(&data["vectors"][3]);
        let roots = anchors(&data["vectors"][3]);
        let before = base.try_serialize().unwrap();
        let mut wrong = base.clone();
        wrong.inputs[0].bip32_derivation[0].1 .1[4] ^= 1;
        assert!(sign_hd_psbt(&wrong, &roots, 1000).is_err());
        let mut wrong = base.clone();
        wrong.inputs[0].bip32_derivation[0].1 .0[0] ^= 1;
        assert!(sign_hd_psbt(&wrong, &roots, 1000).is_err());
        let mut wrong = base.clone();
        wrong
            .xpub
            .iter_mut()
            .find(|(_, source)| source.0 == roots[0].origin.0)
            .unwrap()
            .0[13] ^= 1;
        assert!(sign_hd_psbt(&wrong, &roots, 1000).is_err());
        let mut wrong_root = roots[0].key.clone();
        wrong_root.chain_code[0] ^= 1;
        let wrong_root = HdSigningAnchor::from_key(wrong_root, None, Network::Mainnet).unwrap();
        assert!(sign_hd_psbt(&base, &[wrong_root], 1000).is_err());
        let mut two = base.clone();
        let mut parent = two.inputs[0].non_witness_utxo.clone().unwrap();
        parent.outputs.push(parent.outputs[0].clone());
        let txid = parent.txid();
        two.unsigned_tx.inputs[0].previous_output.txid = txid;
        let mut input = two.unsigned_tx.inputs[0].clone();
        input.previous_output.vout = 1;
        two.unsigned_tx.inputs.push(input);
        two.inputs.push(two.inputs[0].clone());
        for slot in &mut two.inputs {
            slot.non_witness_utxo = Some(parent.clone());
        }
        two.inputs[1].bip32_derivation.clear();
        two.unsigned_tx.outputs[0].value = Amount::from_sat(199000);
        let plan = derive_signing_keys(&base, &roots).unwrap();
        crate::wallet::sign_psbt(&two, &plan.input_keys[0].keys, 1000).unwrap();
        assert!(sign_hd_psbt(&two, &roots, 1000)
            .unwrap_err()
            .to_string()
            .contains("input 1"));
        let leaf = data["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "tr-pk")
            .unwrap();
        let mut wrong = psbt(leaf);
        wrong.inputs[0]
            .tap_bip32_derivation
            .iter_mut()
            .find(|(_, source)| !source.leaf_hashes.is_empty())
            .unwrap()
            .1
            .leaf_hashes[0][0] ^= 1;
        assert!(sign_hd_psbt(&wrong, &anchors(leaf), 1000).is_err());
        let mut wrong = psbt(leaf);
        wrong.inputs[0].tap_leaf_scripts.clear();
        assert!(sign_hd_psbt(&wrong, &anchors(leaf), 1000).is_err());
        let tree = data["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "tr-tree-key0")
            .unwrap();
        let mut wrong = psbt(tree);
        let hash = btc_primitives::taproot::tap_leaf_hash(
            0xc0,
            wrong.inputs[0].tap_leaf_scripts[0].1.script.as_bytes(),
        );
        wrong.inputs[0].tap_bip32_derivation[0]
            .1
            .leaf_hashes
            .push(hash);
        assert!(sign_hd_psbt(&wrong, &anchors(tree), 1000).is_err());
        assert!(sign_hd_psbt(&base, &[roots[0].clone(), roots[0].clone()], 1000).is_err());
        assert!(sign_hd_psbt(&base, &vec![roots[0].clone(); 65], 1000).is_err());
        assert_eq!(base.try_serialize().unwrap(), before);
    }

    #[test]
    fn deep_anchor_master_affiliation_and_fingerprint_collision_candidates() {
        let data = fixture();
        let vector = data["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "master-plus-account")
            .unwrap();
        let roots = anchors(vector);
        let original = psbt(vector);
        let mut bad = roots[1].clone();
        bad.origin.1[0] ^= 1;
        assert!(sign_hd_psbt(&original, &[roots[0].clone(), bad], 1000).is_err());
        let other = HdSigningAnchor::parse(
            data["vectors"][11]["remaining_anchors"][0]
                .as_str()
                .unwrap(),
            Network::Mainnet,
        )
        .unwrap();
        let path = roots[1].origin.1.clone();
        let mut key = other.key.clone();
        for child in &path {
            key = key.derive_child(ChildNumber(*child)).unwrap();
        }
        // No master is supplied, so both annotation prefixes are explicitly
        // unverified. Their actual child equations still select the real key.
        let collision =
            HdSigningAnchor::from_key(key, Some(roots[1].origin.clone()), Network::Mainnet)
                .unwrap();
        let signed = sign_hd_psbt(&original, &[collision, roots[1].clone()], 1000).unwrap();
        assert_eq!(signed.anchor_master_paths_verified, vec![false, false]);
        assert_eq!(signed.input_derivations[0].anchor_index, 1);
    }
}
