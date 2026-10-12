#![no_main]
use btc_primitives::psbt::Psbt;
use libfuzzer_sys::fuzz_target;

// Exercise the exact production proof implementation without pulling the
// node's unrelated database/network runtimes into the sanitizer workspace.
#[path = "../../crates/node/src/wallet.rs"]
mod wallet;
#[path = "../../crates/node/src/wallet_derivations.rs"]
mod wallet_derivations;

fuzz_target!(|data: &[u8]| {
    if let Ok(psbt) = Psbt::deserialize(data) {
        if data.len() <= 65_536 {
            let _ = wallet_derivations::verify_key_derivations(&psbt);
        }
        if data.len() <= 131_072
            && psbt.inputs.len() <= 4
            && psbt.outputs.len() <= 4
            && psbt
                .inputs
                .iter()
                .all(|input| input.partial_sigs.len() + input.tap_script_sigs.len() <= 24)
            && psbt.inputs.iter().all(|input| {
                input
                    .final_script_witness
                    .as_ref()
                    .is_none_or(|items| items.iter().filter(|item| !item.is_empty()).count() <= 34)
            })
        {
            // Exercise the exact wallet equations/finalizer with a bounded
            // sanitizer work budget, including unselected threshold records.
            let _ = wallet::verify_partial_signatures(&psbt);
            // Public test keys from the independent signer fixture; every
            // successful result still has its real equations checked.
            static KEYS: std::sync::OnceLock<Vec<btc_primitives::wif::WifPrivateKey>> =
                std::sync::OnceLock::new();
            let keys = KEYS.get_or_init(|| {
                let mut material = vec![
                    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreBR6zCMU",
                    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
                    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
                    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S",
                    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU76rnZwVdz",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
                // Generated public test keys from the same independent fixture.
                material.extend(
                    include_str!("../../crates/primitives/tests/data/taproot-key-signer.keys")
                        .lines()
                        .map(str::to_owned),
                );
                // Keep a bounded sanitizer key set; large distinct-key
                // thresholds have separate exact-vector/funded acceptance.
                material.extend(
                    include_str!("../../crates/primitives/tests/data/taproot-script-signer.keys")
                        .lines()
                        .map(str::to_owned),
                );
                material.sort();
                material.dedup();
                material
                    .iter()
                    .map(|key| {
                        btc_primitives::wif::WifPrivateKey::from_wif(
                            key,
                            btc_primitives::Network::Mainnet,
                        )
                        .unwrap()
                    })
                    .collect()
            });
            if let Ok(signed) = wallet::sign_psbt(&psbt, keys, 1_000_000) {
                assert_eq!(signed.psbt.unsigned_tx, psbt.unsigned_tx);
                wallet::verify_partial_signatures(&signed.psbt)
                    .expect("signer verified every record");
                if signed.input_signature_schemes.contains(&"ecdsa_all") {
                    assert!(signed
                        .verified
                        .txid_linked_prevouts
                        .iter()
                        .all(|linked| *linked));
                }
            }
            let _ = wallet::verify_finalized_psbt(&psbt);
            if let Ok(result) = wallet::finalize_psbt(&psbt) {
                wallet::verify_finalized_psbt(&result.psbt).expect("finalizer verified its spend");
            }
        }
        let canonical = psbt.try_serialize().expect("decoded PSBT must serialize");
        assert_eq!(Psbt::deserialize(&canonical).unwrap(), psbt);
        for version in [0, 2] {
            if let Ok(converted) = psbt.convert_version(version) {
                assert_eq!(converted.unsigned_tx, psbt.unsigned_tx);
                let bytes = converted.try_serialize().unwrap();
                assert_eq!(Psbt::deserialize(&bytes).unwrap(), converted);
            }
        }
    }
});
