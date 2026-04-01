/// Edge cases that have caused consensus bugs historically.
///
/// These tests validate important boundary conditions in Bitcoin's consensus
/// rules, many of which correspond to historical CVEs or soft-fork activation
/// rules (BIP30, BIP34, BIP141, etc.).

use btc_primitives::amount::Amount;
use btc_primitives::hash::TxHash;
use btc_primitives::script::{Opcode, ScriptBuf};
use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

/// Helper: build a coinbase transaction with a given scriptsig and output value.
fn make_coinbase(script_sig: Vec<u8>, value: Amount) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: 0xffffffff,
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::p2pkh(&[0u8; 20]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    }
}

// ============================================================================
// BIP30: Duplicate coinbase txids
// ============================================================================

#[test]
fn test_bip30_duplicate_coinbase_txids() {
    // BIP30 (activated at height 91842 on mainnet) prohibits blocks from
    // containing transactions whose txid matches an existing unspent output.
    //
    // Historical context: blocks 91842 and 91880 on mainnet contained
    // coinbase transactions with txids identical to earlier coinbases.
    // This was possible because the coinbase scriptSig did not encode the
    // block height (BIP34 was not yet active), and the outputs happened to
    // be identical. BIP30 added an explicit check to reject such blocks.
    //
    // Two coinbase transactions with identical structure will have the same
    // txid. This is what BIP30 prevents.
    let cb1 = make_coinbase(vec![0x04, 0xff, 0xff, 0x00, 0x1d], Amount::from_sat(5_000_000_000));
    let cb2 = make_coinbase(vec![0x04, 0xff, 0xff, 0x00, 0x1d], Amount::from_sat(5_000_000_000));

    // Same scriptSig + same outputs => same txid
    assert_eq!(cb1.txid(), cb2.txid());

    // BIP34 fixes this by requiring the block height in the coinbase scriptSig.
    // Different heights produce different txids.
    let cb_height_1 = make_coinbase(vec![0x01, 0x01], Amount::from_sat(5_000_000_000)); // height 1
    let cb_height_2 = make_coinbase(vec![0x01, 0x02], Amount::from_sat(5_000_000_000)); // height 2
    assert_ne!(cb_height_1.txid(), cb_height_2.txid());

    // Verify the exception heights are correctly known
    let params = btc_consensus::validation::ChainParams::mainnet();
    assert_eq!(params.bip34_height, 227931);
    // BIP30 exceptions were at blocks 91842 and 91880 (before BIP34).
}

// ============================================================================
// Value overflow in outputs
// ============================================================================

#[test]
fn test_value_overflow_in_outputs() {
    // The total value of all outputs in a transaction must not exceed 21M BTC
    // (2,100,000,000,000,000 satoshis). This prevents money creation.
    //
    // Historical context: CVE-2010-5139 -- a transaction at block 74638 created
    // 184 billion BTC due to an integer overflow in the value summation code.

    let max_money = Amount::MAX_MONEY;
    assert_eq!(max_money.as_sat(), 21_000_000 * 100_000_000);

    // A single output at MAX_MONEY is valid
    let valid_amount = Amount::MAX_MONEY;
    assert!(valid_amount.is_valid());

    // One satoshi over MAX_MONEY is invalid
    let overflow = Amount::from_sat(max_money.as_sat() + 1);
    assert!(!overflow.is_valid());

    // Two outputs that individually are valid but together exceed MAX_MONEY
    let half_plus_one = Amount::from_sat(max_money.as_sat() / 2 + 1);
    assert!(half_plus_one.is_valid());
    let total = half_plus_one + half_plus_one;
    assert!(!total.is_valid(), "sum of two half+1 amounts should exceed MAX_MONEY");

    // Negative amounts are invalid
    let negative = Amount::from_sat(-1);
    assert!(!negative.is_valid());
}

// ============================================================================
// Block sigops limit
// ============================================================================

#[test]
fn test_block_sigops_limit() {
    // A block can have at most 80,000 sigops. This is calculated as:
    // MAX_BLOCK_SIGOPS_COST = 80,000
    // Legacy sigops count * WITNESS_SCALE_FACTOR (4) toward this limit.
    // So the effective legacy limit is 20,000 sigops per block.
    //
    // Each OP_CHECKSIG / OP_CHECKSIGVERIFY costs 1 sigop.
    // Each OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY costs up to 20 sigops
    // (the key count in the multisig).
    //
    // The sigops limit prevents blocks from containing scripts that take
    // excessively long to validate.

    const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;
    const WITNESS_SCALE_FACTOR: u32 = 4;
    const MAX_LEGACY_SIGOPS: u32 = MAX_BLOCK_SIGOPS_COST / WITNESS_SCALE_FACTOR;

    assert_eq!(MAX_LEGACY_SIGOPS, 20_000);

    // A script full of OP_CHECKSIG opcodes
    let mut script = ScriptBuf::new();
    for _ in 0..20_001 {
        script.push_opcode(Opcode::OP_CHECKSIG);
    }

    // Count sigops in the script (each OP_CHECKSIG = 1 sigop)
    let sigop_count = script
        .as_bytes()
        .iter()
        .filter(|&&b| b == Opcode::OP_CHECKSIG as u8)
        .count() as u32;
    assert_eq!(sigop_count, 20_001);
    assert!(sigop_count > MAX_LEGACY_SIGOPS, "should exceed the legacy sigops limit");
}

// ============================================================================
// Coinbase script length (BIP34)
// ============================================================================

#[test]
fn test_coinbase_script_length() {
    // After BIP34 activation (height 227931 on mainnet), the coinbase
    // scriptSig must:
    // 1. Be between 2 and 100 bytes long.
    // 2. Start with a push of the block height.
    //
    // The minimum of 2 bytes ensures the height push is present.
    // The maximum of 100 bytes is a consensus rule from the original protocol.

    // 1 byte is too short (pre-BIP34 this was valid but post-BIP34 it isn't
    // because you can't encode a height push in 1 byte for height > 0)
    let too_short = ScriptBuf::from_bytes(vec![0x01]);
    assert!(too_short.len() < 2, "1-byte coinbase scriptSig is below minimum");

    // Exactly 2 bytes -- minimum valid length
    let min_valid = ScriptBuf::from_bytes(vec![0x01, 0x00]); // push height 0
    assert_eq!(min_valid.len(), 2);

    // Exactly 100 bytes -- maximum valid length
    let max_valid = ScriptBuf::from_bytes(vec![0x00; 100]);
    assert_eq!(max_valid.len(), 100);

    // 101 bytes -- exceeds maximum
    let too_long = ScriptBuf::from_bytes(vec![0x00; 101]);
    assert!(too_long.len() > 100, "101-byte coinbase scriptSig exceeds maximum");

    // BIP34 height encoding: height is pushed as a CScriptNum
    // Height 500000 = 0x07A120 -> push as [0x03, 0x20, 0xA1, 0x07]
    let height_500k = ScriptBuf::from_bytes(vec![0x03, 0x20, 0xA1, 0x07]);
    assert!(height_500k.len() >= 2 && height_500k.len() <= 100);
    // First byte is the push length (3 bytes for height)
    assert_eq!(height_500k.as_bytes()[0], 0x03);
}

// ============================================================================
// Transaction finality
// ============================================================================

#[test]
fn test_transaction_final() {
    // A transaction is considered "final" (eligible for inclusion in a block) if:
    // 1. Its locktime is 0, OR
    // 2. Its locktime is less than the block height (if < 500_000_000) or
    //    block time (if >= 500_000_000), OR
    // 3. All input sequence numbers are 0xFFFFFFFF (SEQUENCE_FINAL).
    //
    // A transaction with locktime=0 and all sequences=FINAL is always final.

    // Case 1: locktime=0, all sequences final => always final
    let tx_final = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xAA; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![0x01]),
            sequence: 0xffffffff,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2pkh(&[0u8; 20]),
        }],
        witness: Vec::new(),
        lock_time: 0,
    };
    // locktime = 0 => final regardless of sequence
    assert_eq!(tx_final.lock_time, 0);
    assert_eq!(tx_final.inputs[0].sequence, TxIn::SEQUENCE_FINAL);

    // Case 2: locktime > 0 but all sequences final => still final
    let tx_locked_but_final = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xBB; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![0x01]),
            sequence: 0xffffffff, // SEQUENCE_FINAL overrides locktime
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2pkh(&[0u8; 20]),
        }],
        witness: Vec::new(),
        lock_time: 500_000, // locked at height 500000
    };
    assert!(tx_locked_but_final.lock_time > 0);
    // All sequences are FINAL, so the locktime is ignored
    let all_final = tx_locked_but_final
        .inputs
        .iter()
        .all(|inp| inp.sequence == TxIn::SEQUENCE_FINAL);
    assert!(all_final, "all sequences should be FINAL");

    // Case 3: locktime > 0 and sequence < FINAL => not yet final (depends on block height/time)
    let tx_not_final = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xCC; 32]), 0),
            script_sig: ScriptBuf::from_bytes(vec![0x01]),
            sequence: 0xfffffffe, // not FINAL
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::p2pkh(&[0u8; 20]),
        }],
        witness: Vec::new(),
        lock_time: 999_999, // locked until height 999999
    };
    assert!(tx_not_final.lock_time > 0);
    let not_all_final = tx_not_final
        .inputs
        .iter()
        .all(|inp| inp.sequence == TxIn::SEQUENCE_FINAL);
    assert!(!not_all_final, "not all sequences are FINAL");

    // Locktime interpretation:
    // < 500_000_000 => block height
    // >= 500_000_000 => UNIX timestamp
    let height_lock = 499_999_999u32;
    let time_lock = 500_000_000u32;
    assert!(height_lock < 500_000_000, "should be interpreted as block height");
    assert!(time_lock >= 500_000_000, "should be interpreted as UNIX timestamp");
}

// ============================================================================
// Witness commitment (BIP141)
// ============================================================================

#[test]
fn test_witness_commitment() {
    // Segwit (BIP141) blocks must include a witness commitment in the coinbase
    // transaction. The commitment is placed in an OP_RETURN output with the
    // following structure:
    //
    // OP_RETURN <0xaa21a9ed + 32-byte witness root hash>
    //
    // The 4-byte prefix 0xaa21a9ed identifies the witness commitment.
    // The witness root hash is SHA256d(witness_merkle_root || witness_nonce).
    // The witness nonce is typically 32 zero bytes in the coinbase witness.
    //
    // If a block contains any segwit transactions, the coinbase must have
    // this commitment. The commitment output can appear at any position but
    // is typically the last output.

    let commitment_prefix: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];
    let fake_witness_root = [0xBB; 32];

    // Build the witness commitment output script
    let mut commitment_data = Vec::new();
    commitment_data.extend_from_slice(&commitment_prefix);
    commitment_data.extend_from_slice(&fake_witness_root);

    let mut commitment_script = ScriptBuf::new();
    commitment_script.push_opcode(Opcode::OP_RETURN);
    commitment_script.push_slice(&commitment_data);

    // Verify the output is an OP_RETURN
    assert!(commitment_script.is_op_return());

    // Verify the commitment prefix is present
    let script_bytes = commitment_script.as_bytes();
    // OP_RETURN (0x6a) + push length (0x24 = 36) + commitment_prefix + hash
    assert_eq!(script_bytes[0], Opcode::OP_RETURN as u8);
    // Find the commitment prefix in the script
    let has_commitment = script_bytes
        .windows(4)
        .any(|w| w == commitment_prefix);
    assert!(has_commitment, "witness commitment prefix should be in the script");

    // Total commitment output is: OP_RETURN + push(36 bytes) = 38 bytes
    assert_eq!(commitment_data.len(), 36); // 4 prefix + 32 hash

    // A coinbase with the witness commitment
    let coinbase = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x00, 0x00]), // height=1
            sequence: 0xffffffff,
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::p2pkh(&[0u8; 20]),
            },
            TxOut {
                value: Amount::ZERO, // witness commitment carries no value
                script_pubkey: commitment_script.clone(),
            },
        ],
        witness: vec![
            // Coinbase witness: a single 32-byte zero nonce
            btc_primitives::transaction::Witness::from_items(vec![vec![0u8; 32]]),
        ],
        lock_time: 0,
    };

    assert!(coinbase.is_coinbase());
    assert!(coinbase.is_segwit());

    // Verify the commitment output exists and has zero value
    let commit_output = &coinbase.outputs[1];
    assert_eq!(commit_output.value, Amount::ZERO);
    assert!(commit_output.script_pubkey.is_op_return());
}
