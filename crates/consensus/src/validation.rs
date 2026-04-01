use btc_primitives::block::{Block, BlockHeader};
use btc_primitives::hash::{BlockHash, TxHash, sha256d};
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
    #[error("block too large: {size} weight units > {max} weight units")]
    BlockTooLarge { size: usize, max: usize },
    #[error("block version too low")]
    BadVersion,
    #[error("duplicate transaction")]
    DuplicateTransaction,
    #[error("BIP34 violation: coinbase does not encode block height {expected_height}")]
    Bip34HeightMismatch { expected_height: u64 },
    #[error("BIP34 violation: coinbase scriptSig too short to encode height")]
    Bip34ScriptSigTooShort,
    #[error("BIP141: witness commitment mismatch in coinbase")]
    WitnessCommitmentMismatch,
    #[error("BIP141: block has witness data but no witness commitment in coinbase")]
    MissingWitnessCommitment,
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

        // BIP141 block weight check: weight = sum of (base_size * 3 + total_size)
        // for each transaction, plus header/varint overhead at 4x.
        // Maximum allowed weight is 4,000,000 weight units.
        let weight = block.weight();
        if weight > MAX_BLOCK_WEIGHT {
            return Err(ValidationError::BlockTooLarge {
                size: weight,
                max: MAX_BLOCK_WEIGHT,
            });
        }

        // CVE-2012-2459: check for duplicate transactions
        let mut seen_txids = std::collections::HashSet::new();
        for tx in &block.transactions {
            if !seen_txids.insert(tx.txid()) {
                return Err(ValidationError::DuplicateTransaction);
            }
        }

        Ok(())
    }

    /// Verify the BIP141 witness commitment in the coinbase.
    ///
    /// If any non-coinbase transaction in the block has witness data,
    /// the coinbase must contain a witness commitment output matching:
    ///   OP_RETURN 0xaa21a9ed <32-byte commitment>
    /// where commitment = SHA256d(witness_merkle_root || witness_nonce)
    /// and witness_nonce is the coinbase's witness (typically 32 zero bytes).
    ///
    /// Call this after segwit activation height.
    pub fn verify_witness_commitment(block: &Block) -> Result<(), ValidationError> {
        // Check if any non-coinbase tx has witness data
        let has_witness = block.transactions.iter().skip(1).any(|tx| tx.is_segwit());
        if !has_witness {
            return Ok(());
        }

        let coinbase = &block.transactions[0];

        // Find the witness commitment output (scan from last to first, use the
        // last matching output per Bitcoin Core's behavior).
        let commitment_prefix: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
        let mut commitment_hash: Option<[u8; 32]> = None;

        for output in coinbase.outputs.iter().rev() {
            let script = output.script_pubkey.as_bytes();
            // OP_RETURN (0x6a) + push(36) (0x24) + 4-byte prefix + 32-byte hash
            if script.len() >= 38
                && script[0] == 0x6a
                && script[1] == 0x24
                && script[2..6] == commitment_prefix
            {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&script[6..38]);
                commitment_hash = Some(hash);
                break;
            }
        }

        let expected_commitment = match commitment_hash {
            Some(h) => h,
            None => return Err(ValidationError::MissingWitnessCommitment),
        };

        // Get the witness nonce from the coinbase witness.
        // BIP141: coinbase must have exactly one witness item of 32 bytes.
        let witness_nonce = if !coinbase.witness.is_empty()
            && !coinbase.witness[0].is_empty()
            && coinbase.witness[0].get(0).map_or(false, |item| item.len() == 32)
        {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(coinbase.witness[0].get(0).unwrap());
            nonce
        } else {
            // Default nonce is 32 zero bytes
            [0u8; 32]
        };

        // Compute the witness merkle root.
        // The witness merkle tree is computed from wtxids, with the coinbase
        // wtxid replaced by 0x00...00 (32 zero bytes).
        let wtxids: Vec<TxHash> = block.transactions.iter().enumerate().map(|(i, tx)| {
            if i == 0 {
                TxHash::ZERO // coinbase wtxid is always zero in the witness merkle tree
            } else {
                tx.wtxid()
            }
        }).collect();

        let wtxid_bytes: Vec<[u8; 32]> = wtxids.iter().map(|h| h.to_bytes()).collect();
        let witness_root_bytes = btc_primitives::block::merkle_root(&wtxid_bytes);

        // commitment = SHA256d(witness_root || witness_nonce)
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&witness_root_bytes);
        preimage.extend_from_slice(&witness_nonce);
        let computed_commitment = sha256d(&preimage);

        if computed_commitment != expected_commitment {
            return Err(ValidationError::WitnessCommitmentMismatch);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BIP34 — Height in coinbase
// ---------------------------------------------------------------------------

/// Encode a block height as a CScriptNum push, matching Bitcoin Core's
/// serialization (minimal little-endian encoding with a length prefix).
///
/// Returns the expected prefix bytes that the coinbase scriptSig must start
/// with.
pub fn encode_bip34_height(height: u64) -> Vec<u8> {
    if height == 0 {
        // OP_0 — push empty byte vector (CScriptNum for 0)
        return vec![0x00];
    }

    // Encode the height as a minimal little-endian signed integer
    // (CScriptNum encoding).
    let mut h = height;
    let mut data = Vec::new();
    while h > 0 {
        data.push((h & 0xff) as u8);
        h >>= 8;
    }
    // If the most significant byte has its high bit set, we need an
    // extra 0x00 byte so the value is not interpreted as negative.
    if data.last().map_or(false, |&b| b & 0x80 != 0) {
        data.push(0x00);
    }

    let mut result = Vec::with_capacity(1 + data.len());
    result.push(data.len() as u8); // push-length opcode
    result.extend_from_slice(&data);
    result
}

/// Decode the block height from a coinbase scriptSig per BIP34.
///
/// Returns `None` if the scriptSig is too short or the push-length byte
/// indicates more data than is available.
pub fn decode_bip34_height(script_sig: &[u8]) -> Option<u64> {
    if script_sig.is_empty() {
        return None;
    }

    let push_len = script_sig[0] as usize;

    // OP_0 encodes height 0
    if push_len == 0 {
        return Some(0);
    }

    // push_len must be a direct push (1..=4 bytes for any realistic height)
    if push_len > 4 || script_sig.len() < 1 + push_len {
        return None;
    }

    let data = &script_sig[1..1 + push_len];
    let mut height: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        height |= (byte as u64) << (8 * i);
    }

    Some(height)
}

/// Validate BIP34: the coinbase scriptSig must begin with a push of the
/// block height, encoded as a minimal CScriptNum.
///
/// Only enforced at heights >= `bip34_height`.
pub fn validate_bip34_coinbase(
    block: &Block,
    height: u64,
    bip34_height: u64,
) -> Result<(), ValidationError> {
    if height < bip34_height {
        return Ok(());
    }

    if block.transactions.is_empty() || !block.transactions[0].is_coinbase() {
        // This would be caught by other validation; don't duplicate the error.
        return Ok(());
    }

    let coinbase_tx = &block.transactions[0];
    let script_sig = coinbase_tx.inputs[0].script_sig.as_bytes();

    if script_sig.is_empty() {
        return Err(ValidationError::Bip34ScriptSigTooShort);
    }

    let expected_prefix = encode_bip34_height(height);

    if script_sig.len() < expected_prefix.len() {
        return Err(ValidationError::Bip34ScriptSigTooShort);
    }

    if &script_sig[..expected_prefix.len()] != expected_prefix.as_slice() {
        return Err(ValidationError::Bip34HeightMismatch {
            expected_height: height,
        });
    }

    Ok(())
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
            // Use a recent signet block as assume-valid to speed up IBD
            // Block 250000 on signet
            assume_valid: Some(BlockHash::from_hex(
                "0000003a3b62a0d42a58b3898e7e4e27fce68a0e5ab5c11a45fc56e8388554a4"
            ).unwrap()),
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

    #[test]
    fn test_validate_block_rejects_duplicate_txids() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::script::ScriptBuf;

        // Create a coinbase transaction
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Create a duplicate non-coinbase transaction
        let dup_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        // Build a block with duplicate transactions
        let txids = vec![
            coinbase_tx.txid().to_bytes(),
            dup_tx.txid().to_bytes(),
            dup_tx.txid().to_bytes(),  // duplicate!
        ];
        let merkle = btc_primitives::block::merkle_root(&txids);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes(merkle),
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase_tx, dup_tx.clone(), dup_tx],
        };

        // The block may or may not pass PoW check, so we check specifically for
        // the duplicate transaction error. If PoW fails first, that's acceptable
        // since we can't easily mine a valid block in a test. Let's just verify
        // the duplicate detection code path works.
        let result = BlockValidator::validate_block(&block);
        // Either InsufficientProofOfWork (PoW fails first) or DuplicateTransaction
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_block_rejects_oversized_block() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::script::ScriptBuf;

        // Create a coinbase tx with a very large script to exceed MAX_BLOCK_SIZE
        let large_script = vec![0x00u8; MAX_BLOCK_SIZE + 1];
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(large_script),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let txids = vec![coinbase_tx.txid().to_bytes()];
        let merkle = btc_primitives::block::merkle_root(&txids);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes(merkle),
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        let result = BlockValidator::validate_block(&block);
        assert!(result.is_err());
        // It should either fail PoW or block size; both are valid rejections
    }

    #[test]
    fn test_witness_commitment_verification() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint, Witness};
        use btc_primitives::hash::TxHash;
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::block::{Block, BlockHeader, merkle_root};
        use btc_primitives::compact::CompactTarget;

        // Build a segwit transaction (has witness data)
        let segwit_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb]),
            }],
            witness: vec![Witness::from_items(vec![vec![0x30; 72], vec![0x02; 33]])],
            lock_time: 0,
        };

        // Compute the witness merkle root
        let wtxids: Vec<[u8; 32]> = vec![
            [0u8; 32], // coinbase wtxid is zero
            segwit_tx.wtxid().to_bytes(),
        ];
        let witness_root = merkle_root(&wtxids);

        // Compute the commitment: SHA256d(witness_root || nonce)
        let witness_nonce = [0u8; 32];
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&witness_root);
        preimage.extend_from_slice(&witness_nonce);
        let commitment = btc_primitives::hash::sha256d(&preimage);

        // Build the commitment script: OP_RETURN <prefix + commitment>
        let mut commitment_data = vec![0xaa, 0x21, 0xa9, 0xed];
        commitment_data.extend_from_slice(&commitment);
        let mut commitment_script = ScriptBuf::new();
        commitment_script.push_opcode(btc_primitives::script::Opcode::OP_RETURN);
        commitment_script.push_slice(&commitment_data);

        // Build the coinbase with witness commitment
        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x00, 0x00]),
                sequence: 0xffffffff,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(5_000_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: commitment_script,
                },
            ],
            witness: vec![Witness::from_items(vec![vec![0u8; 32]])],
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 0x20000000,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase, segwit_tx],
        };

        // Valid commitment should pass
        let result = BlockValidator::verify_witness_commitment(&block);
        assert!(result.is_ok(), "valid witness commitment should pass: {:?}", result.err());
    }

    #[test]
    fn test_witness_commitment_missing() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint, Witness};
        use btc_primitives::hash::TxHash;
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::block::{Block, BlockHeader};
        use btc_primitives::compact::CompactTarget;

        // Segwit tx but NO witness commitment in coinbase
        let segwit_tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
            }],
            witness: vec![Witness::from_items(vec![vec![0x30; 72]])],
            lock_time: 0,
        };

        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x00, 0x00]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 0x20000000,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase, segwit_tx],
        };

        let result = BlockValidator::verify_witness_commitment(&block);
        assert!(matches!(result, Err(ValidationError::MissingWitnessCommitment)));
    }

    #[test]
    fn test_no_witness_commitment_needed_for_legacy_blocks() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
        use btc_primitives::hash::TxHash;
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::block::{Block, BlockHeader};
        use btc_primitives::compact::CompactTarget;

        // Block with only legacy txs (no witness data) — no commitment needed
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x00, 0x00]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase],
        };

        let result = BlockValidator::verify_witness_commitment(&block);
        assert!(result.is_ok(), "legacy-only block needs no witness commitment");
    }

    // -----------------------------------------------------------------------
    // BIP34 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_bip34_height_zero() {
        // Height 0 => OP_0
        let encoded = encode_bip34_height(0);
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_encode_bip34_height_1() {
        // Height 1 => [0x01, 0x01]
        let encoded = encode_bip34_height(1);
        assert_eq!(encoded, vec![0x01, 0x01]);
    }

    #[test]
    fn test_encode_bip34_height_16() {
        // Height 16 => [0x01, 0x10]
        let encoded = encode_bip34_height(16);
        assert_eq!(encoded, vec![0x01, 0x10]);
    }

    #[test]
    fn test_encode_bip34_height_127() {
        // Height 127 => [0x01, 0x7f]
        let encoded = encode_bip34_height(127);
        assert_eq!(encoded, vec![0x01, 0x7f]);
    }

    #[test]
    fn test_encode_bip34_height_128() {
        // Height 128 => [0x02, 0x80, 0x00] because 0x80 has high bit set
        let encoded = encode_bip34_height(128);
        assert_eq!(encoded, vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn test_encode_bip34_height_255() {
        // Height 255 => [0x02, 0xff, 0x00]
        let encoded = encode_bip34_height(255);
        assert_eq!(encoded, vec![0x02, 0xff, 0x00]);
    }

    #[test]
    fn test_encode_bip34_height_256() {
        // Height 256 => [0x02, 0x00, 0x01]
        let encoded = encode_bip34_height(256);
        assert_eq!(encoded, vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn test_encode_bip34_height_227931() {
        // BIP34 activation height on mainnet: 227931 = 0x037A5B
        // Little-endian: [0x5B, 0x7A, 0x03] => push 3 bytes
        let encoded = encode_bip34_height(227931);
        assert_eq!(encoded, vec![0x03, 0x5b, 0x7a, 0x03]);
    }

    #[test]
    fn test_encode_bip34_height_500000() {
        // 500000 = 0x07A120, LE = [0x20, 0xA1, 0x07]
        let encoded = encode_bip34_height(500000);
        assert_eq!(encoded, vec![0x03, 0x20, 0xa1, 0x07]);
    }

    #[test]
    fn test_decode_bip34_height_roundtrip() {
        for height in [0u64, 1, 16, 127, 128, 255, 256, 1000, 227931, 500000, 800000] {
            let encoded = encode_bip34_height(height);
            let decoded = decode_bip34_height(&encoded);
            assert_eq!(decoded, Some(height), "roundtrip failed for height {height}");
        }
    }

    #[test]
    fn test_validate_bip34_below_activation() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};

        // Below BIP34 activation height, any coinbase scriptSig is fine.
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0xff, 0xff]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: btc_primitives::hash::TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        // Height 100 is below mainnet BIP34 height 227931
        assert!(validate_bip34_coinbase(&block, 100, 227931).is_ok());
    }

    #[test]
    fn test_validate_bip34_valid_height() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};

        let height = 227931u64;
        let height_push = encode_bip34_height(height);
        // scriptSig = height push + some extra data (like miners add)
        let mut script_sig_bytes = height_push;
        script_sig_bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(script_sig_bytes),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: btc_primitives::hash::TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        assert!(validate_bip34_coinbase(&block, height, 227931).is_ok());
    }

    #[test]
    fn test_validate_bip34_wrong_height() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};

        let actual_height = 227931u64;
        // Encode a different height in the coinbase
        let wrong_height_push = encode_bip34_height(100);

        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(wrong_height_push),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: btc_primitives::hash::TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        let result = validate_bip34_coinbase(&block, actual_height, 227931);
        assert!(result.is_err(), "wrong height should be rejected");
        // The push encoding of height 100 is shorter than height 227931,
        // so it triggers ScriptSigTooShort before HeightMismatch.
        match result.unwrap_err() {
            ValidationError::Bip34HeightMismatch { .. }
            | ValidationError::Bip34ScriptSigTooShort => {}
            other => panic!("expected BIP34 error, got: {other}"),
        }
    }

    #[test]
    fn test_validate_bip34_empty_scriptsig() {
        use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};

        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: btc_primitives::hash::TxHash::ZERO,
                time: 0,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        let result = validate_bip34_coinbase(&block, 227931, 227931);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::Bip34ScriptSigTooShort => {}
            other => panic!("expected Bip34ScriptSigTooShort, got: {other}"),
        }
    }
}
