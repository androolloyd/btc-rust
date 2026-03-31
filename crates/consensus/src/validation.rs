use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::hash::BlockHash;
use btc_primitives::compact::CompactTarget;
use btc_primitives::script::ScriptBuf;
use btc_primitives::amount::Amount;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("block hash does not meet target")]
    InsufficientProofOfWork,
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    #[error("block timestamp too far in future")]
    TimeTooNew,
    #[error("block timestamp too old")]
    TimeTooOld,
    #[error("no transactions in block")]
    NoTransactions,
    #[error("first transaction is not coinbase")]
    NoCoinbase,
    #[error("multiple coinbase transactions")]
    MultipleCoinbase,
    #[error("coinbase reward too high: got {got}, max {max}")]
    CoinbaseRewardTooHigh { got: Amount, max: Amount },
    #[error("block too large: {size} bytes > {max} bytes")]
    BlockTooLarge { size: usize, max: usize },
    #[error("block version too low")]
    BadVersion,
    #[error("duplicate transaction")]
    DuplicateTransaction,
}

/// Maximum block size (1MB legacy limit, 4MW weight limit)
pub const MAX_BLOCK_SIZE: usize = 1_000_000;
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// Block subsidy schedule
pub fn block_subsidy(height: u64) -> Amount {
    let halvings = height / 210_000;
    if halvings >= 64 {
        return Amount::ZERO;
    }
    Amount::from_sat(50 * 100_000_000 >> halvings)
}

/// Validates block headers (stateless checks)
pub struct BlockValidator;

impl BlockValidator {
    /// Perform context-free validation of a block header
    pub fn validate_header(header: &BlockHeader) -> Result<(), ValidationError> {
        // Check proof of work
        if !header.check_proof_of_work() {
            return Err(ValidationError::InsufficientProofOfWork);
        }
        Ok(())
    }

    /// Perform context-free validation of a full block
    pub fn validate_block(block: &Block) -> Result<(), ValidationError> {
        // Validate header
        Self::validate_header(&block.header)?;

        // Must have at least one transaction
        if block.transactions.is_empty() {
            return Err(ValidationError::NoTransactions);
        }

        // First transaction must be coinbase
        if !block.transactions[0].is_coinbase() {
            return Err(ValidationError::NoCoinbase);
        }

        // Only one coinbase allowed
        if block.transactions[1..].iter().any(|tx| tx.is_coinbase()) {
            return Err(ValidationError::MultipleCoinbase);
        }

        // Check merkle root
        if !block.check_merkle_root() {
            return Err(ValidationError::InvalidMerkleRoot);
        }

        Ok(())
    }
}

/// Chain parameters — network-specific consensus rules
pub struct ChainParams {
    pub network: btc_primitives::network::Network,
    pub genesis_hash: BlockHash,
    pub pow_limit: CompactTarget,
    pub pow_target_timespan: u32,    // 14 days in seconds
    pub pow_target_spacing: u32,     // 10 minutes in seconds
    pub subsidy_halving_interval: u64,
    pub bip34_height: u64,
    pub bip65_height: u64,
    pub bip66_height: u64,
    pub segwit_height: u64,
    pub taproot_height: u64,
    /// When set, skip script verification for blocks at or below the block
    /// identified by this hash. This dramatically speeds up IBD by trusting
    /// that the scripts in historically-buried blocks have already been
    /// validated by the network.
    pub assume_valid: Option<BlockHash>,
    /// Signet challenge script (BIP325). When set, signet blocks must include
    /// a witness commitment satisfying this challenge script. Only applicable
    /// to signet networks; `None` for mainnet/testnet/regtest.
    pub signet_challenge: Option<ScriptBuf>,
}

impl ChainParams {
    pub fn mainnet() -> Self {
        ChainParams {
            network: btc_primitives::network::Network::Mainnet,
            genesis_hash: BlockHash::from_hex(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            ).unwrap(),
            pow_limit: CompactTarget::MAX_TARGET,
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 210_000,
            bip34_height: 227931,
            bip65_height: 388381,
            bip66_height: 363725,
            segwit_height: 481824,
            taproot_height: 709632,
            // Block 810000 — the latest hardcoded checkpoint, used as the
            // assume-valid block during IBD.
            assume_valid: Some(BlockHash::from_hex(
                "00000000000000000002c71f45de7cf52e0dfd1a8ce8b0a69f13bf67e9c53e67"
            ).unwrap()),
            signet_challenge: None,
        }
    }

    pub fn testnet() -> Self {
        ChainParams {
            network: btc_primitives::network::Network::Testnet,
            genesis_hash: BlockHash::from_hex(
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
            ).unwrap(),
            pow_limit: CompactTarget::MAX_TARGET,
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 210_000,
            bip34_height: 21111,
            bip65_height: 581885,
            bip66_height: 330776,
            segwit_height: 834624,
            taproot_height: 0, // always active on testnet
            assume_valid: None,
            signet_challenge: None,
        }
    }

    pub fn signet() -> Self {
        // Default signet challenge: 1-of-2 multisig controlled by signet operators
        let challenge_bytes = hex::decode(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430\
             2103348f40a18fc8ebbf4a26a07f8fb37c46eb9e6f1f87d3e0e5e8af20c6d26ae27852ae"
        ).expect("valid hex for default signet challenge");

        ChainParams {
            network: btc_primitives::network::Network::Signet,
            genesis_hash: BlockHash::from_hex(
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
            ).unwrap(),
            pow_limit: CompactTarget(0x1e0377ae),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 210_000,
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            segwit_height: 1,
            taproot_height: 1,
            assume_valid: None,
            signet_challenge: Some(ScriptBuf::from_bytes(challenge_bytes)),
        }
    }

    pub fn regtest() -> Self {
        ChainParams {
            network: btc_primitives::network::Network::Regtest,
            genesis_hash: BlockHash::from_hex(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            ).unwrap(),
            pow_limit: CompactTarget(0x207fffff),
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            subsidy_halving_interval: 150,
            bip34_height: 500,
            bip65_height: 1351,
            bip66_height: 1251,
            segwit_height: 0,
            taproot_height: 0,
            assume_valid: None,
            signet_challenge: None,
        }
    }

    pub fn from_network(network: btc_primitives::network::Network) -> Self {
        match network {
            btc_primitives::network::Network::Mainnet => Self::mainnet(),
            btc_primitives::network::Network::Testnet => Self::testnet(),
            btc_primitives::network::Network::Signet => Self::signet(),
            btc_primitives::network::Network::Regtest => Self::regtest(),
        }
    }

    /// Determine whether scripts should be verified for a block at the given
    /// height and hash.
    ///
    /// During IBD, blocks at or below the assume-valid block can skip script
    /// verification because the network has already validated them. Once a
    /// block's hash matches `assume_valid`, all blocks up to and including that
    /// height are trusted.
    ///
    /// Returns `false` (skip scripts) when `assume_valid` is set and
    /// `assume_valid_height` is `Some` with `height <= assume_valid_height`.
    /// In practice the caller tracks whether the assume-valid block has been
    /// seen and at what height; this helper takes both the block's own height
    /// and hash so it can be used in two ways:
    ///
    /// 1. Quick path: if the block's own hash equals `assume_valid`, scripts
    ///    can be skipped for this block (and all prior ones).
    /// 2. Height path: if `height` is below the height at which the
    ///    assume-valid block was found, scripts can be skipped.
    pub fn should_verify_scripts(&self, height: u64, hash: &BlockHash, assume_valid_height: Option<u64>) -> bool {
        match (&self.assume_valid, assume_valid_height) {
            // If assume-valid is set and we know its height, skip scripts for
            // blocks at or below that height.
            (Some(_), Some(av_height)) if height <= av_height => false,
            // If assume-valid is set and this block IS the assume-valid block,
            // skip scripts for it too.
            (Some(av_hash), None) if hash == av_hash => false,
            // Otherwise, full verification.
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_subsidy() {
        assert_eq!(block_subsidy(0).as_sat(), 5_000_000_000);
        assert_eq!(block_subsidy(209_999).as_sat(), 5_000_000_000);
        assert_eq!(block_subsidy(210_000).as_sat(), 2_500_000_000);
        assert_eq!(block_subsidy(420_000).as_sat(), 1_250_000_000);
        assert_eq!(block_subsidy(630_000).as_sat(), 625_000_000);
        assert_eq!(block_subsidy(13_440_000).as_sat(), 0); // after 64 halvings
    }

    #[test]
    fn test_total_supply() {
        let mut total: i64 = 0;
        let mut height: u64 = 0;
        loop {
            let subsidy = block_subsidy(height);
            if subsidy == Amount::ZERO {
                break;
            }
            // Each halving period is 210_000 blocks
            total += subsidy.as_sat() * 210_000;
            height += 210_000;
        }
        // Total supply should be just under 21M BTC
        assert_eq!(total, 2_099_999_997_690_000);
    }

    #[test]
    fn test_mainnet_params() {
        let params = ChainParams::mainnet();
        assert_eq!(params.subsidy_halving_interval, 210_000);
        assert_eq!(params.pow_target_spacing, 600); // 10 minutes
        assert_eq!(
            params.genesis_hash.to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_genesis_block_validation() {
        // Reconstruct genesis block header and validate
        let raw_header = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c"
        ).unwrap();

        let header: BlockHeader = btc_primitives::encode::decode(&raw_header).unwrap();
        assert!(BlockValidator::validate_header(&header).is_ok());
    }

    #[test]
    fn test_mainnet_has_assume_valid() {
        let params = ChainParams::mainnet();
        assert!(params.assume_valid.is_some());
    }

    #[test]
    fn test_regtest_no_assume_valid() {
        let params = ChainParams::regtest();
        assert!(params.assume_valid.is_none());
    }

    #[test]
    fn test_should_verify_scripts_below_assume_valid() {
        let params = ChainParams::mainnet();
        let some_hash = BlockHash::ZERO;
        // Block well below the assume-valid height should skip scripts.
        assert!(!params.should_verify_scripts(100, &some_hash, Some(500_000)));
    }

    #[test]
    fn test_should_verify_scripts_at_assume_valid() {
        let params = ChainParams::mainnet();
        let some_hash = BlockHash::ZERO;
        // Block exactly at assume-valid height should still skip scripts.
        assert!(!params.should_verify_scripts(500_000, &some_hash, Some(500_000)));
    }

    #[test]
    fn test_should_verify_scripts_above_assume_valid() {
        let params = ChainParams::mainnet();
        let some_hash = BlockHash::ZERO;
        // Block above the assume-valid height should verify scripts.
        assert!(params.should_verify_scripts(500_001, &some_hash, Some(500_000)));
    }

    #[test]
    fn test_should_verify_scripts_no_assume_valid() {
        let params = ChainParams::regtest();
        let some_hash = BlockHash::ZERO;
        // No assume-valid set => always verify scripts.
        assert!(params.should_verify_scripts(100, &some_hash, None));
    }

    #[test]
    fn test_should_verify_scripts_matching_hash_no_height() {
        let params = ChainParams::mainnet();
        let av_hash = params.assume_valid.clone().unwrap();
        // When the block hash matches assume-valid and no height is known yet,
        // skip scripts for this block.
        assert!(!params.should_verify_scripts(810000, &av_hash, None));
    }

    #[test]
    fn test_mainnet_genesis_hash_matches() {
        // Build the genesis header from ChainParams::mainnet() and verify
        // that hashing it produces the expected well-known genesis hash.
        let params = ChainParams::mainnet();
        let header = crate::chain::genesis_header(&params);
        let computed_hash = header.block_hash();

        let expected_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let expected_hash = BlockHash::from_hex(expected_hex).unwrap();

        assert_eq!(
            computed_hash, expected_hash,
            "mainnet genesis header hash does not match expected value"
        );
        assert_eq!(
            computed_hash, params.genesis_hash,
            "genesis_header() hash must equal params.genesis_hash"
        );
    }

    #[test]
    fn test_mainnet_difficulty_adjustment_params() {
        let params = ChainParams::mainnet();

        // pow_target_timespan = 14 days = 14 * 24 * 60 * 60 = 1_209_600 seconds
        assert_eq!(params.pow_target_timespan, 1_209_600);

        // pow_target_spacing = 10 minutes = 600 seconds
        assert_eq!(params.pow_target_spacing, 600);

        // The difficulty adjustment interval should be
        // pow_target_timespan / pow_target_spacing = 2016 blocks
        let interval = params.pow_target_timespan / params.pow_target_spacing;
        assert_eq!(interval, 2016);
    }
}
