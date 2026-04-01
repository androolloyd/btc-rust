//! TRUC (Topologically Restricted Until Confirmation) — v3 transaction policy.
//!
//! Transactions with nVersion=3 have special mempool rules designed to make
//! fee bumping via CPFP more predictable:
//!
//! - Max 1 unconfirmed ancestor
//! - Max 1 unconfirmed descendant
//! - Max size 10,000 vbytes for child transactions (those spending unconfirmed v3 parents)
//! - Must signal BIP125 replaceability (at least one input with nSequence < 0xfffffffe)
//!
//! See: <https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki>

use btc_primitives::{Encodable, Transaction};
use thiserror::Error;

/// The nVersion value that triggers TRUC rules.
pub const TRUC_TX_VERSION: i32 = 3;

/// Maximum virtual size (vbytes) of a TRUC child transaction.
pub const TRUC_MAX_CHILD_VSIZE: usize = 10_000;

/// Maximum number of unconfirmed ancestors for a TRUC transaction.
pub const TRUC_MAX_ANCESTORS: usize = 1;

/// Maximum number of unconfirmed descendants for a TRUC transaction.
pub const TRUC_MAX_DESCENDANTS: usize = 1;

/// The nSequence threshold for BIP125 RBF signaling.
const RBF_SEQUENCE_THRESHOLD: u32 = 0xfffffffe;

/// Errors returned when a v3 (TRUC) transaction violates TRUC policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrucError {
    #[error("v3 transaction does not signal BIP125 replaceability (no input with nSequence < 0xfffffffe)")]
    NotSignalingRbf,

    #[error("v3 transaction has {count} unconfirmed ancestors, max allowed is {max}")]
    TooManyAncestors { count: usize, max: usize },

    #[error("v3 transaction has {count} unconfirmed descendants, max allowed is {max}")]
    TooManyDescendants { count: usize, max: usize },

    #[error("v3 child transaction size {size} vbytes exceeds maximum {max} vbytes")]
    ChildTooLarge { size: usize, max: usize },

    #[error("v3 child transaction spends a non-v3 unconfirmed parent {parent_txid}")]
    NonV3Parent { parent_txid: String },
}

/// Returns `true` if a transaction is a v3 (TRUC) transaction.
pub fn is_truc(tx: &Transaction) -> bool {
    tx.version == TRUC_TX_VERSION
}

/// Returns `true` if a transaction signals BIP125 replaceability.
///
/// A transaction signals RBF if at least one of its inputs has an
/// nSequence number strictly less than `0xfffffffe`.
pub fn signals_rbf(tx: &Transaction) -> bool {
    tx.inputs.iter().any(|input| input.sequence < RBF_SEQUENCE_THRESHOLD)
}

/// Returns `true` if the given script is a Pay-to-Anchor (P2A) output.
///
/// P2A outputs are designed for TRUC transactions to enable anyone-can-spend
/// fee-bumping anchors.
pub fn is_p2a_output(tx: &Transaction, output_index: usize) -> bool {
    tx.outputs
        .get(output_index)
        .map_or(false, |o| o.script_pubkey.is_p2a())
}

/// Count P2A outputs in a transaction.
pub fn count_p2a_outputs(tx: &Transaction) -> usize {
    tx.outputs.iter().filter(|o| o.script_pubkey.is_p2a()).count()
}

/// Validate a v3 (TRUC) transaction against TRUC policy rules.
///
/// This should be called when a transaction with nVersion=3 is submitted to
/// the mempool. The caller provides the current ancestor and descendant counts
/// from the mempool graph.
///
/// `is_child` indicates whether this transaction spends any unconfirmed v3
/// parent. When `true`, the child size limit applies.
///
/// Returns `Ok(())` if the transaction passes all TRUC checks.
pub fn validate_truc(
    tx: &Transaction,
    unconfirmed_ancestor_count: usize,
    unconfirmed_descendant_count: usize,
    is_child: bool,
) -> Result<(), TrucError> {
    // Rule 1: Must signal BIP125 replaceability
    if !signals_rbf(tx) {
        return Err(TrucError::NotSignalingRbf);
    }

    // Rule 2: Max 1 unconfirmed ancestor
    if unconfirmed_ancestor_count > TRUC_MAX_ANCESTORS {
        return Err(TrucError::TooManyAncestors {
            count: unconfirmed_ancestor_count,
            max: TRUC_MAX_ANCESTORS,
        });
    }

    // Rule 3: Max 1 unconfirmed descendant
    if unconfirmed_descendant_count > TRUC_MAX_DESCENDANTS {
        return Err(TrucError::TooManyDescendants {
            count: unconfirmed_descendant_count,
            max: TRUC_MAX_DESCENDANTS,
        });
    }

    // Rule 4: Child tx size limit (10,000 vbytes)
    if is_child {
        let tx_vsize = tx.encoded_size(); // approximation (use weight/4 in production)
        if tx_vsize > TRUC_MAX_CHILD_VSIZE {
            return Err(TrucError::ChildTooLarge {
                size: tx_vsize,
                max: TRUC_MAX_CHILD_VSIZE,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{Amount, OutPoint, ScriptBuf, TxHash, TxIn, TxOut};

    /// Build a v3 (TRUC) transaction with configurable sequence number.
    fn make_v3_tx(sequence: u32, output_values: &[i64]) -> Transaction {
        Transaction {
            version: TRUC_TX_VERSION,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence,
            }],
            outputs: output_values
                .iter()
                .map(|&v| TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
                })
                .collect(),
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    /// Build a v2 (non-TRUC) transaction.
    fn make_v2_tx(sequence: u32) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    /// Build a v3 transaction with a P2A output.
    fn make_v3_with_p2a(sequence: u32) -> Transaction {
        Transaction {
            version: TRUC_TX_VERSION,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xcc; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
                },
                TxOut {
                    value: Amount::from_sat(330),
                    script_pubkey: ScriptBuf::p2a(),
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    // ---- is_truc ----

    #[test]
    fn test_is_truc_v3() {
        let tx = make_v3_tx(0, &[50_000]);
        assert!(is_truc(&tx));
    }

    #[test]
    fn test_is_truc_v2() {
        let tx = make_v2_tx(0);
        assert!(!is_truc(&tx));
    }

    #[test]
    fn test_is_truc_v1() {
        let mut tx = make_v2_tx(0);
        tx.version = 1;
        assert!(!is_truc(&tx));
    }

    // ---- signals_rbf ----

    #[test]
    fn test_signals_rbf_low_sequence() {
        let tx = make_v3_tx(0, &[50_000]);
        assert!(signals_rbf(&tx));
    }

    #[test]
    fn test_signals_rbf_max_minus_2() {
        let tx = make_v3_tx(0xfffffffd, &[50_000]);
        assert!(signals_rbf(&tx));
    }

    #[test]
    fn test_not_signals_rbf_max_minus_1() {
        let tx = make_v3_tx(0xfffffffe, &[50_000]);
        assert!(!signals_rbf(&tx));
    }

    #[test]
    fn test_not_signals_rbf_max() {
        let tx = make_v3_tx(0xffffffff, &[50_000]);
        assert!(!signals_rbf(&tx));
    }

    // ---- validate_truc ----

    #[test]
    fn test_truc_valid_parent() {
        let tx = make_v3_tx(0, &[50_000]);
        let result = validate_truc(&tx, 0, 0, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_truc_valid_child() {
        let tx = make_v3_tx(0, &[50_000]);
        let result = validate_truc(&tx, 1, 0, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_truc_rejects_no_rbf() {
        let tx = make_v3_tx(0xffffffff, &[50_000]);
        let result = validate_truc(&tx, 0, 0, false);
        assert_eq!(result, Err(TrucError::NotSignalingRbf));
    }

    #[test]
    fn test_truc_rejects_too_many_ancestors() {
        let tx = make_v3_tx(0, &[50_000]);
        let result = validate_truc(&tx, 2, 0, false);
        assert_eq!(
            result,
            Err(TrucError::TooManyAncestors {
                count: 2,
                max: 1,
            })
        );
    }

    #[test]
    fn test_truc_allows_exactly_one_ancestor() {
        let tx = make_v3_tx(0, &[50_000]);
        let result = validate_truc(&tx, 1, 0, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_truc_rejects_too_many_descendants() {
        let tx = make_v3_tx(0, &[50_000]);
        let result = validate_truc(&tx, 0, 2, false);
        assert_eq!(
            result,
            Err(TrucError::TooManyDescendants {
                count: 2,
                max: 1,
            })
        );
    }

    #[test]
    fn test_truc_allows_exactly_one_descendant() {
        let tx = make_v3_tx(0, &[50_000]);
        let result = validate_truc(&tx, 0, 1, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_truc_child_size_limit() {
        // Create a large v3 child tx (exceeds 10,000 vbytes)
        let large_script = vec![0x00u8; 15_000];
        let tx = Transaction {
            version: TRUC_TX_VERSION,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(large_script),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let result = validate_truc(&tx, 1, 0, true);
        assert!(matches!(result, Err(TrucError::ChildTooLarge { .. })));
    }

    #[test]
    fn test_truc_child_size_limit_not_applied_to_parent() {
        // A large v3 parent tx is OK (size limit only applies to children)
        let large_script = vec![0x00u8; 15_000];
        let tx = Transaction {
            version: TRUC_TX_VERSION,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(large_script),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        // is_child = false => no size limit
        let result = validate_truc(&tx, 0, 0, false);
        assert!(result.is_ok());
    }

    // ---- P2A detection ----

    #[test]
    fn test_p2a_output_detection() {
        let tx = make_v3_with_p2a(0);
        assert!(!is_p2a_output(&tx, 0)); // first output is normal
        assert!(is_p2a_output(&tx, 1));  // second output is P2A
        assert!(!is_p2a_output(&tx, 2)); // out of range
    }

    #[test]
    fn test_count_p2a_outputs() {
        let tx = make_v3_with_p2a(0);
        assert_eq!(count_p2a_outputs(&tx), 1);

        let tx2 = make_v3_tx(0, &[50_000]);
        assert_eq!(count_p2a_outputs(&tx2), 0);
    }

    #[test]
    fn test_p2a_in_v2_tx() {
        // P2A can appear in non-v3 transactions (it's just anyone-can-spend)
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xdd; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(330),
                script_pubkey: ScriptBuf::p2a(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        assert_eq!(count_p2a_outputs(&tx), 1);
        assert!(is_p2a_output(&tx, 0));
    }

    // ---- Error display ----

    #[test]
    fn test_truc_error_display_not_signaling() {
        let err = TrucError::NotSignalingRbf;
        let msg = err.to_string();
        assert!(msg.contains("BIP125"));
    }

    #[test]
    fn test_truc_error_display_ancestors() {
        let err = TrucError::TooManyAncestors { count: 3, max: 1 };
        let msg = err.to_string();
        assert!(msg.contains("3"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn test_truc_error_display_descendants() {
        let err = TrucError::TooManyDescendants { count: 5, max: 1 };
        let msg = err.to_string();
        assert!(msg.contains("5"));
    }

    #[test]
    fn test_truc_error_display_child_too_large() {
        let err = TrucError::ChildTooLarge {
            size: 15_000,
            max: 10_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("15000"));
        assert!(msg.contains("10000"));
    }

    #[test]
    fn test_truc_error_display_non_v3_parent() {
        let err = TrucError::NonV3Parent {
            parent_txid: "abcd1234".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abcd1234"));
    }

    #[test]
    fn test_truc_error_equality() {
        assert_eq!(TrucError::NotSignalingRbf, TrucError::NotSignalingRbf);
        assert_ne!(
            TrucError::TooManyAncestors { count: 2, max: 1 },
            TrucError::TooManyAncestors { count: 3, max: 1 }
        );
    }
}
