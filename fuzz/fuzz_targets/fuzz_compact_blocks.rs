#![no_main]
use btc_network::compact_blocks::{
    BlockTxnRequest, BlockTxnResponse, CompactBlock, CompactVersion,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_537 || data.is_empty() {
        return;
    }
    let version = if data[0] & 1 == 0 {
        CompactVersion::V1
    } else {
        CompactVersion::V2
    };
    let bytes = &data[1..];
    match data[0] / 2 % 3 {
        0 => {
            if let Ok(compact) = CompactBlock::deserialize(bytes, version) {
                assert_eq!(compact.serialize(version).unwrap(), bytes);
                if let Ok(prepared) = compact.prepare(&[], version) {
                    let request = prepared.request();
                    assert!(request
                        .indices
                        .windows(2)
                        .all(|indices| indices[0] < indices[1]));
                    if request.indices.is_empty() {
                        let _ = prepared.finish(BlockTxnResponse {
                            block_hash: request.block_hash,
                            transactions: Vec::new(),
                        });
                    }
                }
            }
        }
        1 => {
            if let Ok(request) = BlockTxnRequest::deserialize(bytes) {
                assert_eq!(request.serialize().unwrap(), bytes);
                assert!(request
                    .indices
                    .windows(2)
                    .all(|indices| indices[0] < indices[1]));
            }
        }
        _ => {
            if let Ok(response) = BlockTxnResponse::deserialize(bytes, version) {
                assert_eq!(response.serialize(version).unwrap(), bytes);
            }
        }
    }
});
