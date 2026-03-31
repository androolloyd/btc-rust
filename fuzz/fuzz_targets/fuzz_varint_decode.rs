#![no_main]

use libfuzzer_sys::fuzz_target;

use btc_primitives::encode::{decode, encode, VarInt};

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a VarInt.
    let vi: VarInt = match decode(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // --- Roundtrip invariant ---
    let re_encoded = encode(&vi);
    let vi2: VarInt = decode(&re_encoded).expect("re-encoded VarInt must decode");
    assert_eq!(vi, vi2, "VarInt roundtrip value mismatch");

    // --- Size invariant ---
    assert_eq!(
        re_encoded.len(),
        vi.encoded_size(),
        "encoded_size() must match actual encoded length"
    );

    // --- Canonical encoding ---
    // The re-encoded form should be the canonical (shortest) encoding for
    // this value, so its length must be <= the original input length.
    assert!(
        re_encoded.len() <= data.len(),
        "canonical encoding must be no longer than original"
    );
});
