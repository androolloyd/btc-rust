#![no_main]

use libfuzzer_sys::fuzz_target;

use btc_primitives::encode::{decode, encode};
use btc_primitives::transaction::Transaction;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a Bitcoin transaction.
    let tx: Transaction = match decode(data) {
        Ok(t) => t,
        Err(_) => return, // Invalid data is fine -- just must not panic.
    };

    // --- Roundtrip invariant ---
    // Re-encode the successfully decoded transaction and verify the bytes
    // decode to an identical transaction.
    let re_encoded = encode(&tx);
    let tx2: Transaction =
        decode(&re_encoded).expect("re-encoded transaction must decode successfully");
    assert_eq!(tx, tx2, "roundtrip mismatch");

    // --- Exercise hash code paths ---
    // Computing txid and wtxid must never panic regardless of field values.
    let _txid = tx.txid();
    let _wtxid = tx.wtxid();

    // Exercise helper predicates -- must not panic.
    let _is_segwit = tx.is_segwit();
    let _is_coinbase = tx.is_coinbase();
});
