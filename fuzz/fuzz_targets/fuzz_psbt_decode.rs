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
