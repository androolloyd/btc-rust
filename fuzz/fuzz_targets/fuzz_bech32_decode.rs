#![no_main]

use libfuzzer_sys::fuzz_target;

use btc_primitives::bech32::{
    bech32_decode, bech32_encode, convert_bits, decode_witness_address, encode_witness_address,
};

fuzz_target!(|data: &[u8]| {
    // Interpret the fuzz input as a UTF-8 string.  Invalid UTF-8 is
    // uninteresting for bech32 (which operates on ASCII), so skip.
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Cap length to avoid wasting time on strings far beyond the 90-char
    // bech32 limit that will be immediately rejected.
    if s.len() > 200 {
        return;
    }

    // --- Raw bech32 decode ---
    if let Ok((hrp, decoded_data, variant)) = bech32_decode(s) {
        // Re-encode and verify roundtrip.
        if let Ok(re_encoded) = bech32_encode(&hrp, &decoded_data, variant) {
            // Bech32 is case-insensitive; canonical output is lowercase.
            assert_eq!(
                re_encoded,
                s.to_ascii_lowercase(),
                "bech32 roundtrip mismatch"
            );
        }
    }

    // --- Witness address decode for common HRPs ---
    for hrp in &["bc", "tb", "bcrt"] {
        if let Ok((version, program)) = decode_witness_address(s, hrp) {
            // Re-encode and verify roundtrip.
            if let Ok(re_encoded) = encode_witness_address(hrp, version, &program) {
                assert_eq!(
                    re_encoded,
                    s.to_ascii_lowercase(),
                    "witness address roundtrip mismatch"
                );
            }
        }
    }

    // --- convert_bits must not panic on arbitrary 5-bit data ---
    // If bech32_decode succeeded, the data is in 5-bit groups.  Convert
    // back to 8-bit and then to 5-bit again to exercise the bit converter.
    if let Ok((_hrp, five_bit_data, _variant)) = bech32_decode(s) {
        if let Ok(eight_bit) = convert_bits(&five_bit_data, 5, 8, false) {
            if let Ok(back_to_five) = convert_bits(&eight_bit, 8, 5, true) {
                assert_eq!(
                    five_bit_data, back_to_five,
                    "convert_bits roundtrip mismatch"
                );
            }
        }
    }
});
