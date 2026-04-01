/// Table definitions for the database — reth-style strongly-typed tables
///
/// Each table maps a key type to a value type, both of which must implement
/// Encode/Decode for the storage backend.

/// Block header table: BlockHash -> BlockHeader
pub const TABLE_HEADERS: &str = "Headers";

/// Block height index: u64 -> BlockHash
pub const TABLE_BLOCK_INDEX: &str = "BlockIndex";

/// Transaction table: TxHash -> Transaction
pub const TABLE_TRANSACTIONS: &str = "Transactions";

/// UTXO set: OutPoint -> TxOut
pub const TABLE_UTXOS: &str = "UTXOs";

/// Chain metadata: &str -> Vec<u8>
pub const TABLE_META: &str = "Meta";

/// Transaction block index: TxHash -> (BlockHash, tx_position)
/// Maps a txid to the block that contains it and the tx's position within that block.
pub const TABLE_TX_BLOCK_INDEX: &str = "TxBlockIndex";

/// Address/script index: script_hash(32) + height(8 BE) + tx_position(4 BE) -> AddressIndexValue
/// Maps SHA256(scriptPubKey) to transaction entries affecting that script.
pub const TABLE_ADDRESS_INDEX: &str = "AddressIndex";

pub const META_BEST_HEIGHT: &str = "best_height";
pub const META_BEST_HASH: &str = "best_hash";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_name_constants() {
        assert_eq!(TABLE_HEADERS, "Headers");
        assert_eq!(TABLE_BLOCK_INDEX, "BlockIndex");
        assert_eq!(TABLE_TRANSACTIONS, "Transactions");
        assert_eq!(TABLE_UTXOS, "UTXOs");
        assert_eq!(TABLE_META, "Meta");
        assert_eq!(TABLE_TX_BLOCK_INDEX, "TxBlockIndex");
        assert_eq!(TABLE_ADDRESS_INDEX, "AddressIndex");
    }

    #[test]
    fn test_meta_key_constants() {
        assert_eq!(META_BEST_HEIGHT, "best_height");
        assert_eq!(META_BEST_HASH, "best_hash");
    }
}
