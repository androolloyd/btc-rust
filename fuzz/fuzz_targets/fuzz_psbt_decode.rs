#![no_main]
use btc_primitives::psbt::Psbt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(psbt) = Psbt::deserialize(data) {
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
