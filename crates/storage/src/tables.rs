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

pub const META_BEST_HEIGHT: &str = "best_height";
pub const META_BEST_HASH: &str = "best_hash";
