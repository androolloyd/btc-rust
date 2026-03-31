#![no_main]

use libfuzzer_sys::fuzz_target;

use btc_primitives::block::Block;
use btc_primitives::encode::{decode, encode};

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a Bitcoin block.
    let block: Block = match decode(data) {
        Ok(b) => b,
        Err(_) => return,
    };

    // --- block_hash must never panic ---
    let _hash = block.block_hash();

    // --- Merkle root computation must never panic ---
    // (Even with pathological transaction counts or contents.)
    // Limit to blocks with a reasonable number of transactions so we
    // don't spend forever hashing in the fuzzer. 2000 txs is well above
    // the real-world maximum per block and keeps iterations fast.
    if block.transactions.len() <= 2000 {
        let _merkle = block.compute_merkle_root();
        let _check = block.check_merkle_root();
    }

    // --- Roundtrip invariant ---
    let re_encoded = encode(&block);
    let block2: Block =
        decode(&re_encoded).expect("re-encoded block must decode successfully");
    assert_eq!(block, block2, "roundtrip mismatch");

    // --- Header roundtrip ---
    let header_bytes = encode(&block.header);
    assert_eq!(header_bytes.len(), 80);
});
