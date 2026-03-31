/// RPC method definitions — Bitcoin Core compatible
///
/// Will implement: getblockchaininfo, getblock, getblockhash,
/// getrawtransaction, sendrawtransaction, getmempoolinfo, etc.

pub const METHOD_GETBLOCKCHAININFO: &str = "getblockchaininfo";
pub const METHOD_GETBLOCK: &str = "getblock";
pub const METHOD_GETBLOCKHASH: &str = "getblockhash";
pub const METHOD_GETBLOCKHEADER: &str = "getblockheader";
pub const METHOD_GETBLOCKCOUNT: &str = "getblockcount";
pub const METHOD_GETRAWTRANSACTION: &str = "getrawtransaction";
pub const METHOD_SENDRAWTRANSACTION: &str = "sendrawtransaction";
pub const METHOD_GETMEMPOOLINFO: &str = "getmempoolinfo";
pub const METHOD_GETPEERINFO: &str = "getpeerinfo";
pub const METHOD_GETNETWORKINFO: &str = "getnetworkinfo";
pub const METHOD_GETBESTBLOCKHASH: &str = "getbestblockhash";
pub const METHOD_ESTIMATEFEE: &str = "estimatefee";
pub const METHOD_STOP: &str = "stop";
