//! Electrum protocol method name constants.

// Server methods
pub const METHOD_SERVER_VERSION: &str = "server.version";
pub const METHOD_SERVER_BANNER: &str = "server.banner";
pub const METHOD_SERVER_FEATURES: &str = "server.features";
pub const METHOD_SERVER_PING: &str = "server.ping";

// Blockchain header methods
pub const METHOD_HEADERS_SUBSCRIBE: &str = "blockchain.headers.subscribe";
pub const METHOD_BLOCK_HEADER: &str = "blockchain.block.header";
pub const METHOD_BLOCK_HEADERS: &str = "blockchain.block.headers";

// Scripthash methods
pub const METHOD_SCRIPTHASH_GET_HISTORY: &str = "blockchain.scripthash.get_history";
pub const METHOD_SCRIPTHASH_GET_BALANCE: &str = "blockchain.scripthash.get_balance";
pub const METHOD_SCRIPTHASH_LISTUNSPENT: &str = "blockchain.scripthash.listunspent";
pub const METHOD_SCRIPTHASH_SUBSCRIBE: &str = "blockchain.scripthash.subscribe";
pub const METHOD_SCRIPTHASH_UNSUBSCRIBE: &str = "blockchain.scripthash.unsubscribe";

// Transaction methods
pub const METHOD_TRANSACTION_GET: &str = "blockchain.transaction.get";
pub const METHOD_TRANSACTION_BROADCAST: &str = "blockchain.transaction.broadcast";
pub const METHOD_TRANSACTION_GET_MERKLE: &str = "blockchain.transaction.get_merkle";
pub const METHOD_TRANSACTION_ID_FROM_POS: &str = "blockchain.transaction.id_from_pos";

// Fee estimation
pub const METHOD_ESTIMATEFEE: &str = "blockchain.estimatefee";

pub const METHOD_SCRIPTHASH_GET_MEMPOOL: &str = "blockchain.scripthash.get_mempool";

pub const METHOD_RELAYFEE: &str = "blockchain.relayfee";
pub const METHOD_FEE_HISTOGRAM: &str = "mempool.get_fee_histogram";
