#![no_main]
use btc_primitives::{descriptor::Descriptor, Network};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(descriptor) = Descriptor::parse(text) {
            for network in [Network::Mainnet, Network::Regtest] {
                for index in [None, Some(0), Some(2), Some(0x7fffffff)] {
                    if let Ok(expanded) = descriptor.expand(index, network) {
                        assert!(expanded.script_pubkey.as_bytes().len() <= 10_000);
                        for leaf in expanded.tap_leaves {
                            assert!(leaf.control_block.len() <= 33 + 32 * 128);
                        }
                    }
                }
            }
        }
    }
});
