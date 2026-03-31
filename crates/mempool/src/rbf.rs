//! BIP125 Replace-By-Fee (RBF) implementation.
//!
//! Opt-in RBF allows an unconfirmed transaction to be replaced with a
//! higher-fee version, provided the original transaction signals
//! replaceability (nSequence < 0xfffffffe on at least one input).
//!
//! See: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>

use btc_primitives::{Amount, OutPoint, Transaction, TxHash};
use thiserror::Error;

use crate::pool::MempoolEntry;

/// The nSequence threshold for RBF signaling.
/// Any input with nSequence strictly less than this value signals opt-in RBF.
const RBF_SEQUENCE_THRESHOLD: u32 = 0xfffffffe;

/// Errors that can occur when evaluating an RBF replacement.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RbfError {
    #[error("RBF is disabled by policy")]
    Disabled,

    #[error("replaced transaction {0} does not signal replaceability")]
    NotSignaling(String),

    #[error(
        "new transaction fee {new_fee} does not exceed total replaced fee {old_fee} by at least {min_increment}"
    )]
    InsufficientFee {
        new_fee: i64,
        old_fee: i64,
        min_increment: i64,
    },

    #[error("replacement would displace {count} transactions, exceeding max {max}")]
    TooManyReplacements { count: usize, max: usize },

    #[error("new transaction introduces unconfirmed input {0} not present in replaced set")]
    NewUnconfirmedInput(String),
}

/// Policy knobs for RBF acceptance.
#[derive(Debug, Clone)]
pub struct RbfPolicy {
    /// Whether RBF replacement is enabled at all.
    pub enabled: bool,
    /// Minimum fee increase (in satoshis) the replacement must pay on top
    /// of the combined fee of all replaced transactions.
    pub min_fee_increment: Amount,
    /// Maximum number of original transactions (including descendants) that
    /// may be displaced by a single replacement.
    pub max_replacements: usize,
}

impl Default for RbfPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_fee_increment: Amount::from_sat(1_000),
            max_replacements: 100,
        }
    }
}

/// Check whether a transaction signals opt-in RBF.
///
/// Per BIP125, a transaction is considered to have opted in to RBF if any
/// of its inputs has an nSequence number strictly less than `0xfffffffe`.
pub fn signals_rbf(tx: &Transaction) -> bool {
    tx.inputs.iter().any(|input| input.sequence < RBF_SEQUENCE_THRESHOLD)
}

/// Determine whether `new_tx` may replace the given set of conflicting
/// mempool entries according to BIP125 rules and the supplied policy.
///
/// `conflicts` contains each conflicting transaction's hash and mempool
/// entry.  The caller is responsible for collecting all conflicts (i.e.,
/// transactions that spend any of the same inputs as `new_tx`).
///
/// # BIP125 Rules
///
/// 1. Every replaced transaction must signal replaceability.
/// 2. The replacement must pay a strictly higher absolute fee than the
///    combined fees of all replaced transactions.
/// 3. The fee increase must be at least `policy.min_fee_increment`.
/// 4. The total number of displaced transactions (including their
///    in-mempool descendants) must not exceed `policy.max_replacements`.
/// 5. The replacement must not introduce any new unconfirmed inputs that
///    were not already present in the replaced set.
pub fn can_replace(
    new_tx: &Transaction,
    new_fee: Amount,
    conflicts: &[(TxHash, &MempoolEntry)],
    policy: &RbfPolicy,
) -> Result<(), RbfError> {
    // -- 0. Policy gate -------------------------------------------------------
    if !policy.enabled {
        return Err(RbfError::Disabled);
    }

    // -- 1. All replaced txs must signal RBF ----------------------------------
    for (txid, entry) in conflicts {
        if !signals_rbf(&entry.tx) {
            return Err(RbfError::NotSignaling(txid.to_hex()));
        }
    }

    // -- 2 & 3. Fee comparison ------------------------------------------------
    let total_old_fee: i64 = conflicts.iter().map(|(_, e)| e.fee.as_sat()).sum();

    if new_fee.as_sat() <= total_old_fee {
        return Err(RbfError::InsufficientFee {
            new_fee: new_fee.as_sat(),
            old_fee: total_old_fee,
            min_increment: policy.min_fee_increment.as_sat(),
        });
    }

    let increment = new_fee.as_sat() - total_old_fee;
    if increment < policy.min_fee_increment.as_sat() {
        return Err(RbfError::InsufficientFee {
            new_fee: new_fee.as_sat(),
            old_fee: total_old_fee,
            min_increment: policy.min_fee_increment.as_sat(),
        });
    }

    // -- 4. Replacement count limit -------------------------------------------
    // In practice each conflict may have descendants in the mempool.
    // The `descendants` field on MempoolEntry tracks how many.  We sum them
    // up, counting each conflict itself as one displaced tx.
    let total_displaced: usize = conflicts
        .iter()
        .map(|(_, e)| 1 + e.descendants)
        .sum();

    if total_displaced > policy.max_replacements {
        return Err(RbfError::TooManyReplacements {
            count: total_displaced,
            max: policy.max_replacements,
        });
    }

    // -- 5. No new unconfirmed inputs -----------------------------------------
    // Build a set of all outpoints consumed by the original transactions.
    let old_inputs: std::collections::HashSet<OutPoint> = conflicts
        .iter()
        .flat_map(|(_, e)| e.tx.inputs.iter().map(|i| i.previous_output))
        .collect();

    for input in &new_tx.inputs {
        let outpoint = input.previous_output;

        // An input is considered "new unconfirmed" if:
        //   a) it was not consumed by any of the replaced transactions, AND
        //   b) it references a transaction that is itself in the mempool
        //      (indicated by being in the conflict set -- since the caller
        //       only knows about mempool entries they passed in, we check
        //       whether the outpoint's txid matches any conflict).
        //
        // In a full node integration the caller would additionally look up
        // the UTXO set.  Here we approximate: if the input was NOT spent by
        // any of the replaced txs AND its txid matches a conflict, it is
        // a new unconfirmed input.
        if !old_inputs.contains(&outpoint) {
            let spends_conflict = conflicts
                .iter()
                .any(|(txid, _)| *txid == outpoint.txid);
            if spends_conflict {
                return Err(RbfError::NewUnconfirmedInput(outpoint.txid.to_hex()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{OutPoint, ScriptBuf, TxHash, TxIn, TxOut};

    // ---- helpers ------------------------------------------------------------

    /// Build a transaction whose txid is unique thanks to `id_byte` being
    /// used as the outpoint hash, with the given nSequence on all inputs.
    fn make_tx(id_byte: u8, sequence: u32, output_value: i64) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76; 25]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    fn make_entry(tx: Transaction, fee: Amount) -> MempoolEntry {
        let size = btc_primitives::Encodable::encoded_size(&tx);
        MempoolEntry {
            tx,
            fee,
            size,
            time_added: 0,
            ancestors: 0,
            descendants: 0,
        }
    }

    // ---- signal detection ---------------------------------------------------

    #[test]
    fn test_signals_rbf_with_low_sequence() {
        let tx = make_tx(0x01, 0x00000000, 50_000);
        assert!(signals_rbf(&tx));
    }

    #[test]
    fn test_signals_rbf_boundary() {
        // 0xfffffffd is the highest value that still signals RBF
        let tx = make_tx(0x01, 0xfffffffd, 50_000);
        assert!(signals_rbf(&tx));
    }

    #[test]
    fn test_no_signal_at_threshold() {
        // 0xfffffffe does NOT signal RBF
        let tx = make_tx(0x01, 0xfffffffe, 50_000);
        assert!(!signals_rbf(&tx));
    }

    #[test]
    fn test_no_signal_final() {
        let tx = make_tx(0x01, 0xffffffff, 50_000);
        assert!(!signals_rbf(&tx));
    }

    #[test]
    fn test_signals_rbf_multiple_inputs() {
        // One final input, one signaling -- should return true
        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0xffffffff,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x02; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: 0x00000001,
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76; 25]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        assert!(signals_rbf(&tx));
    }

    // ---- can_replace: successful case ---------------------------------------

    #[test]
    fn test_replacement_accepted() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(2_000));
        let old_txid = old_tx.txid();

        // New tx spends the same input but pays more
        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        let new_fee = Amount::from_sat(5_000);

        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(can_replace(&new_tx, new_fee, &conflicts, &policy).is_ok());
    }

    // ---- can_replace: disabled policy ---------------------------------------

    #[test]
    fn test_rbf_disabled() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(2_000));
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        let conflicts = vec![(old_txid, &old_entry)];

        let policy = RbfPolicy {
            enabled: false,
            ..RbfPolicy::default()
        };

        assert_eq!(
            can_replace(&new_tx, Amount::from_sat(5_000), &conflicts, &policy),
            Err(RbfError::Disabled),
        );
    }

    // ---- can_replace: not signaling -----------------------------------------

    #[test]
    fn test_replaced_tx_not_signaling() {
        // Old tx does NOT signal RBF (sequence = 0xffffffff)
        let old_tx = make_tx(0x01, 0xffffffff, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(2_000));
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000001, 48_000);
        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(5_000), &conflicts, &policy),
            Err(RbfError::NotSignaling(_)),
        ));
    }

    // ---- can_replace: insufficient fee --------------------------------------

    #[test]
    fn test_fee_not_higher() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(5_000));
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        // Same fee -- not higher
        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(5_000), &conflicts, &policy),
            Err(RbfError::InsufficientFee { .. }),
        ));
    }

    #[test]
    fn test_fee_increase_below_min_increment() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(5_000));
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        // Only 500 sat more, but min_increment is 1000
        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(5_500), &conflicts, &policy),
            Err(RbfError::InsufficientFee { .. }),
        ));
    }

    #[test]
    fn test_fee_exactly_at_min_increment() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(5_000));
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        // Exactly min_increment (1000) more
        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(can_replace(&new_tx, Amount::from_sat(6_000), &conflicts, &policy).is_ok());
    }

    // ---- can_replace: too many replacements ---------------------------------

    #[test]
    fn test_too_many_displaced() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let mut old_entry = make_entry(old_tx.clone(), Amount::from_sat(2_000));
        // Simulate 100 descendants -- together with the tx itself that is 101
        old_entry.descendants = 100;
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default(); // max_replacements = 100

        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(10_000), &conflicts, &policy),
            Err(RbfError::TooManyReplacements { count: 101, max: 100 }),
        ));
    }

    #[test]
    fn test_exactly_at_max_replacements() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let mut old_entry = make_entry(old_tx.clone(), Amount::from_sat(2_000));
        old_entry.descendants = 99; // 1 + 99 = 100 = max
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(can_replace(&new_tx, Amount::from_sat(10_000), &conflicts, &policy).is_ok());
    }

    // ---- can_replace: multiple conflicts ------------------------------------

    #[test]
    fn test_multiple_conflicts_combined_fee() {
        let old_tx1 = make_tx(0x01, 0x00000001, 50_000);
        let old_entry1 = make_entry(old_tx1.clone(), Amount::from_sat(3_000));
        let txid1 = old_tx1.txid();

        let old_tx2 = make_tx(0x02, 0x00000001, 50_000);
        let old_entry2 = make_entry(old_tx2.clone(), Amount::from_sat(4_000));
        let txid2 = old_tx2.txid();

        // Combined old fee = 7000.  New fee must be >= 7000 + 1000 = 8000.
        let new_tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                    sequence: 0x00000002,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x02; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                    sequence: 0x00000002,
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76; 25]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let conflicts = vec![(txid1, &old_entry1), (txid2, &old_entry2)];
        let policy = RbfPolicy::default();

        // 7999 is not enough (need 8000)
        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(7_999), &conflicts, &policy),
            Err(RbfError::InsufficientFee { .. }),
        ));

        // 8000 is exactly enough
        assert!(can_replace(&new_tx, Amount::from_sat(8_000), &conflicts, &policy).is_ok());
    }

    // ---- can_replace: new unconfirmed input ---------------------------------

    #[test]
    fn test_new_unconfirmed_input_rejected() {
        // Old tx spends outpoint [0x01;32]:0
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(2_000));
        let old_txid = old_tx.txid();

        // New tx spends the same outpoint AND an output of the old_tx itself
        // (i.e., a new unconfirmed input that is in the conflict set).
        let new_tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                    sequence: 0x00000002,
                },
                TxIn {
                    // This spends an output of old_txid -- a new unconfirmed input
                    previous_output: OutPoint::new(old_txid, 0),
                    script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                    sequence: 0x00000002,
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76; 25]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let conflicts = vec![(old_txid, &old_entry)];
        let policy = RbfPolicy::default();

        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(10_000), &conflicts, &policy),
            Err(RbfError::NewUnconfirmedInput(_)),
        ));
    }

    // ---- can_replace: custom policy -----------------------------------------

    #[test]
    fn test_custom_min_fee_increment() {
        let old_tx = make_tx(0x01, 0x00000001, 50_000);
        let old_entry = make_entry(old_tx.clone(), Amount::from_sat(5_000));
        let old_txid = old_tx.txid();

        let new_tx = make_tx(0x01, 0x00000002, 48_000);
        let conflicts = vec![(old_txid, &old_entry)];

        let policy = RbfPolicy {
            min_fee_increment: Amount::from_sat(5_000),
            ..RbfPolicy::default()
        };

        // 9999 - 5000 = 4999 < 5000 increment
        assert!(matches!(
            can_replace(&new_tx, Amount::from_sat(9_999), &conflicts, &policy),
            Err(RbfError::InsufficientFee { .. }),
        ));

        // 10000 - 5000 = 5000 == min increment -- OK
        assert!(can_replace(&new_tx, Amount::from_sat(10_000), &conflicts, &policy).is_ok());
    }
}
