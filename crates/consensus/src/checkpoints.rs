use std::collections::BTreeMap;

use btc_primitives::hash::BlockHash;
use btc_primitives::network::Network;

/// Hardcoded known block hashes at specific heights.
///
/// During IBD, if a header's hash at a checkpoint height doesn't match, reject it.
/// This prevents an attacker from feeding a long, low-work alternative chain.
pub struct Checkpoints {
    points: BTreeMap<u64, BlockHash>,
}

impl Checkpoints {
    /// Load checkpoints for the given network.
    pub fn new(network: Network) -> Self {
        let mut points = BTreeMap::new();

        match network {
            Network::Mainnet => {
                let mainnet_checkpoints: &[(u64, &str)] = &[
                    (11111,  "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
                    (33333,  "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
                    (74000,  "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
                    (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
                    (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
                    (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
                    (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
                    (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
                    (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
                    (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
                    (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
                    (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
                    (295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632473f"),
                    (330000, "00000000000000000faabab19f17c0178c754dbed023e6c871dcaf74571e5571"),
                    (360000, "00000000000000000ca6e07cf681390ff888b7f96790286a440da0f2b87c8ea6"),
                    (390000, "00000000000000000232f0c9c8c180ba9f2b8bfee62cd3e0bb6d4c9fcef0a715"),
                    (420000, "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74f3a2"),
                    (450000, "0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b"),
                    (480000, "000000000000000001024c5d7e477b173e60e2bbfe8685c5fa85ae3e895e0903"),
                    (510000, "00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd"),
                    (540000, "00000000000000000015dc777b3ff2611091336f926c15a461b52a26b3d513a2"),
                    (570000, "00000000000000000013c6b20a1e3cc39be4e23e8b4c26fedb0e50fbf42f18bc"),
                    (600000, "00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91"),
                    (630000, "00000000000000000008aeabc40f3df4d53efbf3a1beb6f4e0c7ed3b5e3b2e52"),
                    (660000, "00000000000000000008fb1a7c7f1c15c4f09a250ea437f9dd2025e8b77f98b2"),
                    (690000, "00000000000000000001c46e1aa52c8f0c5a3b6e3f48d537b2e0be25ab0a0a35"),
                    (720000, "00000000000000000009d9a89099fd5d97dfab0b3e152c4d1a48e8ea56be3fb2"),
                    (750000, "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"),
                    (780000, "0000000000000000000437d3aacd06a7d3a16f57eb1c28a0e42712dd62edf73f"),
                    (810000, "00000000000000000002c71f45de7cf52e0dfd1a8ce8b0a69f13bf67e9c53e67"),
                ];
                for &(height, hash_hex) in mainnet_checkpoints {
                    let hash = BlockHash::from_hex(hash_hex)
                        .expect("hardcoded checkpoint hash must be valid");
                    points.insert(height, hash);
                }
            }
            // Other networks: no hardcoded checkpoints for now.
            _ => {}
        }

        Checkpoints { points }
    }

    /// Returns `true` if there is no checkpoint at `height`, or if the checkpoint
    /// hash matches `hash`. Returns `false` only when there IS a checkpoint at
    /// this height and the hash does NOT match.
    pub fn verify(&self, height: u64, hash: &BlockHash) -> bool {
        match self.points.get(&height) {
            Some(expected) => expected == hash,
            None => true,
        }
    }

    /// The height of the highest hardcoded checkpoint, or 0 if none.
    pub fn last_checkpoint_height(&self) -> u64 {
        self.points.keys().next_back().copied().unwrap_or(0)
    }

    /// Returns `true` if there are no checkpoints at all.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Returns the expected hash at a given checkpoint height, if any.
    pub fn get(&self, height: u64) -> Option<&BlockHash> {
        self.points.get(&height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_checkpoints_loaded() {
        let cp = Checkpoints::new(Network::Mainnet);
        assert!(!cp.is_empty());
        assert_eq!(cp.last_checkpoint_height(), 810000);
    }

    #[test]
    fn test_verify_matching_checkpoint() {
        let cp = Checkpoints::new(Network::Mainnet);
        let hash = BlockHash::from_hex(
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
        )
        .unwrap();
        assert!(cp.verify(11111, &hash));
    }

    #[test]
    fn test_verify_wrong_checkpoint() {
        let cp = Checkpoints::new(Network::Mainnet);
        let wrong_hash = BlockHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert!(!cp.verify(11111, &wrong_hash));
    }

    #[test]
    fn test_verify_non_checkpoint_height() {
        let cp = Checkpoints::new(Network::Mainnet);
        // Height 12345 is not a checkpoint, so any hash should pass.
        let arbitrary_hash = BlockHash::ZERO;
        assert!(cp.verify(12345, &arbitrary_hash));
    }

    #[test]
    fn test_regtest_no_checkpoints() {
        let cp = Checkpoints::new(Network::Regtest);
        assert!(cp.is_empty());
        assert_eq!(cp.last_checkpoint_height(), 0);
    }

    #[test]
    fn test_testnet_no_checkpoints() {
        let cp = Checkpoints::new(Network::Testnet);
        assert!(cp.is_empty());
    }

    #[test]
    fn test_all_mainnet_checkpoints_verify() {
        let cp = Checkpoints::new(Network::Mainnet);
        let expected: &[(u64, &str)] = &[
            (11111,  "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
            (33333,  "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
            (74000,  "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
            (105000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
            (134444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
            (168000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
            (193000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
            (210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
            (216116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
            (225430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
            (250000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
            (279000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
            (295000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632473f"),
            (330000, "00000000000000000faabab19f17c0178c754dbed023e6c871dcaf74571e5571"),
            (360000, "00000000000000000ca6e07cf681390ff888b7f96790286a440da0f2b87c8ea6"),
            (390000, "00000000000000000232f0c9c8c180ba9f2b8bfee62cd3e0bb6d4c9fcef0a715"),
            (420000, "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74f3a2"),
            (450000, "0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b"),
            (480000, "000000000000000001024c5d7e477b173e60e2bbfe8685c5fa85ae3e895e0903"),
            (510000, "00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd"),
            (540000, "00000000000000000015dc777b3ff2611091336f926c15a461b52a26b3d513a2"),
            (570000, "00000000000000000013c6b20a1e3cc39be4e23e8b4c26fedb0e50fbf42f18bc"),
            (600000, "00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91"),
            (630000, "00000000000000000008aeabc40f3df4d53efbf3a1beb6f4e0c7ed3b5e3b2e52"),
            (660000, "00000000000000000008fb1a7c7f1c15c4f09a250ea437f9dd2025e8b77f98b2"),
            (690000, "00000000000000000001c46e1aa52c8f0c5a3b6e3f48d537b2e0be25ab0a0a35"),
            (720000, "00000000000000000009d9a89099fd5d97dfab0b3e152c4d1a48e8ea56be3fb2"),
            (750000, "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"),
            (780000, "0000000000000000000437d3aacd06a7d3a16f57eb1c28a0e42712dd62edf73f"),
            (810000, "00000000000000000002c71f45de7cf52e0dfd1a8ce8b0a69f13bf67e9c53e67"),
        ];
        for &(height, hash_hex) in expected {
            let hash = BlockHash::from_hex(hash_hex).unwrap();
            assert!(
                cp.verify(height, &hash),
                "checkpoint at height {} should verify",
                height
            );
        }
    }

    #[test]
    fn test_get_checkpoint() {
        let cp = Checkpoints::new(Network::Mainnet);
        assert!(cp.get(11111).is_some());
        assert!(cp.get(99999).is_none());
    }

    #[test]
    fn test_all_checkpoint_hashes_are_valid_hex() {
        // Verify every hardcoded checkpoint hash is a valid 64-character hex string
        // that decodes to exactly 32 bytes.
        let all_hashes: &[&str] = &[
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
            "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
            "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
            "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
            "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
            "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
            "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",
            "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
            "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",
            "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",
            "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
            "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40",
            "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632473f",
            "00000000000000000faabab19f17c0178c754dbed023e6c871dcaf74571e5571",
            "00000000000000000ca6e07cf681390ff888b7f96790286a440da0f2b87c8ea6",
            "00000000000000000232f0c9c8c180ba9f2b8bfee62cd3e0bb6d4c9fcef0a715",
            "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74f3a2",
            "0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b",
            "000000000000000001024c5d7e477b173e60e2bbfe8685c5fa85ae3e895e0903",
            "00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd",
            "00000000000000000015dc777b3ff2611091336f926c15a461b52a26b3d513a2",
            "00000000000000000013c6b20a1e3cc39be4e23e8b4c26fedb0e50fbf42f18bc",
            "00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91",
            "00000000000000000008aeabc40f3df4d53efbf3a1beb6f4e0c7ed3b5e3b2e52",
            "00000000000000000008fb1a7c7f1c15c4f09a250ea437f9dd2025e8b77f98b2",
            "00000000000000000001c46e1aa52c8f0c5a3b6e3f48d537b2e0be25ab0a0a35",
            "00000000000000000009d9a89099fd5d97dfab0b3e152c4d1a48e8ea56be3fb2",
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
            "0000000000000000000437d3aacd06a7d3a16f57eb1c28a0e42712dd62edf73f",
            "00000000000000000002c71f45de7cf52e0dfd1a8ce8b0a69f13bf67e9c53e67",
        ];

        for hash_hex in all_hashes {
            // Must be exactly 64 characters
            assert_eq!(
                hash_hex.len(),
                64,
                "checkpoint hash must be 64 hex chars, got {} for {}",
                hash_hex.len(),
                hash_hex,
            );
            // Must only contain valid hex characters
            assert!(
                hash_hex.chars().all(|c| c.is_ascii_hexdigit()),
                "checkpoint hash contains non-hex characters: {}",
                hash_hex,
            );
            // Must decode to exactly 32 bytes
            let bytes = hex::decode(hash_hex).expect("checkpoint hash must be valid hex");
            assert_eq!(
                bytes.len(),
                32,
                "checkpoint hash must decode to 32 bytes, got {} for {}",
                bytes.len(),
                hash_hex,
            );
            // Must successfully parse as a BlockHash
            BlockHash::from_hex(hash_hex)
                .expect(&format!("checkpoint hash must parse as BlockHash: {}", hash_hex));
        }
    }
}
