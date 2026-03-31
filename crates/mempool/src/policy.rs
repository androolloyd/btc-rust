use btc_primitives::{Amount, Transaction, Encodable};
use thiserror::Error;

/// Errors returned when a transaction violates mempool acceptance policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("transaction size {size} exceeds maximum {max}")]
    TxTooLarge { size: usize, max: usize },

    #[error("transaction fee {fee} is below minimum relay fee {min_fee}")]
    InsufficientFee { fee: i64, min_fee: i64 },

    #[error("output {index} value {value} is below dust limit {dust_limit}")]
    DustOutput {
        index: usize,
        value: i64,
        dust_limit: i64,
    },

    #[error("ancestor count {count} exceeds maximum {max}")]
    TooManyAncestors { count: usize, max: usize },

    #[error("descendant count {count} exceeds maximum {max}")]
    TooManyDescendants { count: usize, max: usize },
}

/// Configurable limits for transaction acceptance into the mempool.
#[derive(Debug, Clone)]
pub struct TxValidationPolicy {
    /// Maximum transaction size in bytes (default: 100,000 = ~100KB).
    pub max_tx_size: usize,
    /// Minimum relay fee in satoshis (default: 1000).
    pub min_relay_fee: Amount,
    /// Maximum number of in-mempool ancestors (default: 25).
    pub max_ancestor_count: usize,
    /// Maximum number of in-mempool descendants (default: 25).
    pub max_descendant_count: usize,
    /// Dust limit in satoshis -- outputs below this are rejected (default: 546).
    pub dust_limit: Amount,
}

impl Default for TxValidationPolicy {
    fn default() -> Self {
        Self {
            max_tx_size: 100_000,
            min_relay_fee: Amount::from_sat(1_000),
            max_ancestor_count: 25,
            max_descendant_count: 25,
            dust_limit: Amount::from_sat(546),
        }
    }
}

/// Validate a transaction against the mempool acceptance policy.
///
/// `fee` is the fee for this transaction (sum of inputs - sum of outputs), provided by the caller
/// since the mempool does not have access to the UTXO set.
///
/// `ancestor_count` and `descendant_count` are the current chain counts for this transaction
/// within the mempool.
pub fn validate_tx_policy(
    tx: &Transaction,
    fee: Amount,
    ancestor_count: usize,
    descendant_count: usize,
    policy: &TxValidationPolicy,
) -> Result<(), PolicyError> {
    // Check transaction size
    let tx_size = tx.encoded_size();
    if tx_size > policy.max_tx_size {
        return Err(PolicyError::TxTooLarge {
            size: tx_size,
            max: policy.max_tx_size,
        });
    }

    // Check minimum relay fee
    if fee.as_sat() < policy.min_relay_fee.as_sat() {
        return Err(PolicyError::InsufficientFee {
            fee: fee.as_sat(),
            min_fee: policy.min_relay_fee.as_sat(),
        });
    }

    // Check for dust outputs (skip OP_RETURN outputs which are provably unspendable)
    for (index, output) in tx.outputs.iter().enumerate() {
        if output.script_pubkey.is_op_return() {
            continue;
        }
        if output.value.as_sat() < policy.dust_limit.as_sat() {
            return Err(PolicyError::DustOutput {
                index,
                value: output.value.as_sat(),
                dust_limit: policy.dust_limit.as_sat(),
            });
        }
    }

    // Check ancestor count
    if ancestor_count > policy.max_ancestor_count {
        return Err(PolicyError::TooManyAncestors {
            count: ancestor_count,
            max: policy.max_ancestor_count,
        });
    }

    // Check descendant count
    if descendant_count > policy.max_descendant_count {
        return Err(PolicyError::TooManyDescendants {
            count: descendant_count,
            max: policy.max_descendant_count,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{OutPoint, ScriptBuf, TxHash, TxIn, TxOut};

    /// Build a simple test transaction with the given number of outputs, each with the given value.
    fn make_tx(output_values: &[i64], script_size: usize) -> Transaction {
        let script_bytes = vec![0x00u8; script_size];
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: 0xffffffff,
            }],
            outputs: output_values
                .iter()
                .map(|&v| TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: ScriptBuf::from_bytes(script_bytes.clone()),
                })
                .collect(),
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_policy_accepts_valid_tx() {
        let tx = make_tx(&[50_000, 50_000], 25);
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(5_000), 0, 0, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_policy_rejects_too_large_tx() {
        // Create a tx with a very large script to exceed max_tx_size
        let tx = make_tx(&[50_000], 200_000);
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(5_000), 0, 0, &policy);
        assert_eq!(
            result,
            Err(PolicyError::TxTooLarge {
                size: tx.encoded_size(),
                max: 100_000,
            })
        );
    }

    #[test]
    fn test_policy_rejects_insufficient_fee() {
        let tx = make_tx(&[50_000], 25);
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(500), 0, 0, &policy);
        assert_eq!(
            result,
            Err(PolicyError::InsufficientFee {
                fee: 500,
                min_fee: 1_000,
            })
        );
    }

    #[test]
    fn test_policy_rejects_dust_output() {
        let tx = make_tx(&[100], 25); // 100 sat < 546 sat dust limit
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(5_000), 0, 0, &policy);
        assert_eq!(
            result,
            Err(PolicyError::DustOutput {
                index: 0,
                value: 100,
                dust_limit: 546,
            })
        );
    }

    #[test]
    fn test_policy_allows_op_return_below_dust() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: 0xffffffff,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
                },
                TxOut {
                    // OP_RETURN output with zero value -- should be allowed
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]),
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        };
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(5_000), 0, 0, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_policy_rejects_too_many_ancestors() {
        let tx = make_tx(&[50_000], 25);
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(5_000), 30, 0, &policy);
        assert_eq!(
            result,
            Err(PolicyError::TooManyAncestors {
                count: 30,
                max: 25,
            })
        );
    }

    #[test]
    fn test_policy_rejects_too_many_descendants() {
        let tx = make_tx(&[50_000], 25);
        let policy = TxValidationPolicy::default();
        let result = validate_tx_policy(&tx, Amount::from_sat(5_000), 0, 30, &policy);
        assert_eq!(
            result,
            Err(PolicyError::TooManyDescendants {
                count: 30,
                max: 25,
            })
        );
    }

    #[test]
    fn test_custom_policy_limits() {
        let tx = make_tx(&[200], 25);
        let policy = TxValidationPolicy {
            dust_limit: Amount::from_sat(100), // Lower dust limit
            min_relay_fee: Amount::from_sat(100),
            ..Default::default()
        };
        let result = validate_tx_policy(&tx, Amount::from_sat(200), 0, 0, &policy);
        assert!(result.is_ok());
    }
}
