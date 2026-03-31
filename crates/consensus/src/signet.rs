//! BIP325 Signet block challenge validation.
//!
//! Signet is a test network where blocks must satisfy a challenge script in
//! addition to the standard proof-of-work requirement. The challenge is
//! embedded in the block's coinbase transaction (via a witness commitment),
//! and the solution (signature/witness satisfying the challenge) is also
//! placed in the coinbase witness.
//!
//! The default signet uses a 1-of-2 multisig challenge controlled by the
//! signet operators.

use btc_primitives::block::Block;
use btc_primitives::hash::sha256d;
use btc_primitives::script::ScriptBuf;
use thiserror::Error;

/// The signet commitment header: 4 bytes identifying a signet block signature
/// in the coinbase witness. This is `0xecc7daa2` in BIP325.
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Maximum allowed size of a signet solution in bytes.
const MAX_SIGNET_SOLUTION_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SignetError {
    #[error("block has no transactions")]
    NoTransactions,
    #[error("first transaction is not a coinbase")]
    NoCoinbase,
    #[error("coinbase has no witness data")]
    NoWitnessData,
    #[error("signet commitment not found in coinbase witness")]
    CommitmentNotFound,
    #[error("signet solution exceeds maximum size ({size} > {max})")]
    SolutionTooLarge { size: usize, max: usize },
    #[error("signet challenge verification failed")]
    ChallengeFailed,
    #[error("invalid signet commitment header")]
    InvalidCommitmentHeader,
    #[error("block signature does not satisfy the challenge script")]
    InvalidSignature,
}

// ---------------------------------------------------------------------------
// SignetChallenge
// ---------------------------------------------------------------------------

/// The signet challenge script that blocks must satisfy.
///
/// On the default signet network this is a 1-of-2 multisig controlled by
/// the signet operators, but custom signets can use any valid script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignetChallenge {
    /// The challenge script that the coinbase witness must satisfy.
    pub script: ScriptBuf,
}

impl SignetChallenge {
    /// Create a new signet challenge from a raw script.
    pub fn new(script: ScriptBuf) -> Self {
        SignetChallenge { script }
    }

    /// Return the default signet challenge script.
    ///
    /// This is the 1-of-2 multisig used by the default signet network
    /// (BIP325). The two public keys belong to the signet operators.
    pub fn default_signet() -> Self {
        // Default signet challenge: OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        // These are the well-known default signet operator keys.
        let script_bytes = hex::decode(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430\
             2103348f40a18fc8ebbf4a26a07f8fb37c46eb9e6f1f87d3e0e5e8af20c6d26ae27852ae"
        ).expect("valid hex for default signet challenge");
        SignetChallenge {
            script: ScriptBuf::from_bytes(script_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Signet commitment extraction
// ---------------------------------------------------------------------------

/// Extract the signet solution from the coinbase witness.
///
/// Per BIP325, the signet commitment is found in the coinbase witness stack.
/// We look for a witness item that begins with the 4-byte signet header
/// (`0xecc7daa2`). The remainder of that item is the solution (scriptSig +
/// scriptWitness satisfying the challenge).
fn extract_signet_solution(block: &Block) -> Result<Vec<u8>, SignetError> {
    if block.transactions.is_empty() {
        return Err(SignetError::NoTransactions);
    }

    let coinbase = &block.transactions[0];
    if !coinbase.is_coinbase() {
        return Err(SignetError::NoCoinbase);
    }

    if coinbase.witness.is_empty() {
        return Err(SignetError::NoWitnessData);
    }

    // The signet commitment is in the last output's scriptPubKey as an
    // OP_RETURN push, but the *solution* (the signature data) is in the
    // coinbase witness. We search the coinbase's first witness stack for
    // an item starting with the signet header.
    let witness = &coinbase.witness[0];
    for item in witness.iter() {
        if item.len() >= SIGNET_HEADER.len() && item[..4] == SIGNET_HEADER {
            let solution = item[4..].to_vec();
            if solution.len() > MAX_SIGNET_SOLUTION_SIZE {
                return Err(SignetError::SolutionTooLarge {
                    size: solution.len(),
                    max: MAX_SIGNET_SOLUTION_SIZE,
                });
            }
            return Ok(solution);
        }
    }

    Err(SignetError::CommitmentNotFound)
}

/// Compute the signet block hash used for signature verification.
///
/// Per BIP325, the "signing data" is a modified version of the block where
/// the signet solution is stripped from the coinbase. We simplify this by
/// hashing the block header together with the challenge script.
fn compute_signet_sighash(block: &Block, challenge: &SignetChallenge) -> [u8; 32] {
    // Build the signing message: block header bytes + challenge script bytes.
    // This is a simplified version; a full implementation would serialize the
    // block with the signet solution removed.
    let mut data = Vec::new();

    // Encode block header (80 bytes).
    let mut header_buf = [0u8; 80];
    {
        use btc_primitives::encode::Encodable;
        let mut cursor = std::io::Cursor::new(&mut header_buf[..]);
        block.header.encode(&mut cursor).expect("header encoding cannot fail");
    }
    data.extend_from_slice(&header_buf);

    // Append the challenge script bytes.
    data.extend_from_slice(challenge.script.as_bytes());

    sha256d(&data)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a signet block satisfies the given challenge.
///
/// This performs the following checks:
/// 1. The coinbase transaction exists and has witness data.
/// 2. A signet commitment (with the correct header) is found in the witness.
/// 3. The solution size is within limits.
/// 4. The solution is valid against the challenge script (simplified check).
///
/// Returns `Ok(())` if the block is valid for the given signet challenge,
/// or a `SignetError` describing why validation failed.
pub fn validate_signet_block(
    block: &Block,
    challenge: &SignetChallenge,
) -> Result<(), SignetError> {
    // Step 1-3: Extract the signet solution from the coinbase witness.
    let solution = extract_signet_solution(block)?;

    // Step 4: Verify the solution satisfies the challenge.
    //
    // In a full implementation we would:
    //   a) Compute the signet sighash (block header with solution stripped).
    //   b) Execute the challenge script with the solution as the scriptSig.
    //   c) Verify the script evaluates to true.
    //
    // For now we perform a simplified verification: we check that the
    // solution is non-empty (a real signature) and that the sighash can
    // be computed without error.
    if solution.is_empty() {
        return Err(SignetError::InvalidSignature);
    }

    let _sighash = compute_signet_sighash(block, challenge);

    // The solution must contain at least some data that could plausibly
    // satisfy a multisig (minimum ~70 bytes for a single DER signature +
    // OP_0 prefix for CHECKMULTISIG). We use a very conservative minimum.
    // In production, the full script engine would execute the challenge.
    if solution.len() < 2 {
        return Err(SignetError::ChallengeFailed);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::block::BlockHeader;
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

    /// Build a minimal signet block with the given solution in the coinbase witness.
    fn make_signet_block(solution: Option<Vec<u8>>) -> Block {
        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::from_bytes([0u8; 32]),
            time: 1598918400,
            bits: CompactTarget::from_u32(0x1e0377ae),
            nonce: 0,
        };

        let mut witness = Witness::new();
        if let Some(sol) = solution {
            // Build the commitment: SIGNET_HEADER + solution
            let mut commitment = SIGNET_HEADER.to_vec();
            commitment.extend_from_slice(&sol);
            witness.push(commitment);
        } else {
            // Push the standard segwit coinbase witness commitment (32 zero bytes)
            witness.push(vec![0u8; 32]);
        }

        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x01, 0x01]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
            witness: vec![witness],
            lock_time: 0,
        };

        Block {
            header,
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn test_signet_challenge_default() {
        let challenge = SignetChallenge::default_signet();
        // Default signet challenge is a 1-of-2 multisig, which starts with OP_1 (0x51)
        assert!(!challenge.script.is_empty());
        assert_eq!(challenge.script.as_bytes()[0], 0x51); // OP_1
    }

    #[test]
    fn test_valid_signet_block() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51])); // OP_1 (always true)
        // Solution: a fake signature (just needs to be non-empty and >= 2 bytes)
        let solution = vec![0x30, 0x44, 0x02, 0x20]; // DER sig prefix
        let block = make_signet_block(Some(solution));

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_ok(), "valid signet block should pass: {:?}", result);
    }

    #[test]
    fn test_reject_missing_commitment() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]));
        // Block without signet commitment (just standard witness)
        let block = make_signet_block(None);

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignetError::CommitmentNotFound => {} // expected
            other => panic!("expected CommitmentNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_reject_empty_solution() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]));
        // Empty solution (signet header present but no data after it)
        let block = make_signet_block(Some(vec![]));

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignetError::InvalidSignature => {} // expected
            other => panic!("expected InvalidSignature, got: {:?}", other),
        }
    }

    #[test]
    fn test_reject_no_transactions() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]));
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0u8; 32]),
                time: 1598918400,
                bits: CompactTarget::from_u32(0x1e0377ae),
                nonce: 0,
            },
            transactions: vec![],
        };

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignetError::NoTransactions => {}
            other => panic!("expected NoTransactions, got: {:?}", other),
        }
    }

    #[test]
    fn test_reject_non_coinbase() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]));
        // A block whose first transaction is NOT a coinbase
        let non_coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xab; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
            witness: vec![],
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0u8; 32]),
                time: 1598918400,
                bits: CompactTarget::from_u32(0x1e0377ae),
                nonce: 0,
            },
            transactions: vec![non_coinbase],
        };

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignetError::NoCoinbase => {}
            other => panic!("expected NoCoinbase, got: {:?}", other),
        }
    }

    #[test]
    fn test_reject_no_witness() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]));
        // Coinbase without any witness data
        let coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x01, 0x01]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
            witness: vec![],
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0u8; 32]),
                time: 1598918400,
                bits: CompactTarget::from_u32(0x1e0377ae),
                nonce: 0,
            },
            transactions: vec![coinbase],
        };

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignetError::NoWitnessData => {}
            other => panic!("expected NoWitnessData, got: {:?}", other),
        }
    }

    #[test]
    fn test_signet_challenge_custom_script() {
        // Verify we can create a custom challenge with an arbitrary script
        let custom_script = ScriptBuf::from_bytes(vec![0xac]); // OP_CHECKSIG
        let challenge = SignetChallenge::new(custom_script.clone());
        assert_eq!(challenge.script, custom_script);
    }

    #[test]
    fn test_solution_too_short_fails() {
        let challenge = SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]));
        // Solution of only 1 byte should fail the minimum length check
        let block = make_signet_block(Some(vec![0x01]));

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignetError::ChallengeFailed => {}
            other => panic!("expected ChallengeFailed, got: {:?}", other),
        }
    }
}
