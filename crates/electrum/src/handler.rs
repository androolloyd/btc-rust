//! Electrum protocol request handler and method dispatch.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde_json::Value;
use tracing::info;

use crate::methods::*;
use crate::protocol::{
    ElectrumRequest, ElectrumResponse, METHOD_NOT_FOUND, PARSE_ERROR,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Server identification string.
const SERVER_VERSION: &str = "btc-rust-electrum 0.1.0";

/// Electrum protocol version we support.
const PROTOCOL_VERSION: &str = "1.4";

/// Bitcoin mainnet genesis block hash.
const GENESIS_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// Default server banner.
const DEFAULT_BANNER: &str =
    "Welcome to btc-rust embedded Electrum server. https://github.com/example/btc-rust";

// ---------------------------------------------------------------------------
// Method handler function type
// ---------------------------------------------------------------------------

type MethodFn = Box<dyn Fn(Value) -> Value + Send + Sync>;

// ---------------------------------------------------------------------------
// ElectrumHandler
// ---------------------------------------------------------------------------

/// Central dispatcher for Electrum protocol methods.
///
/// Holds shared chain state and a map of method name -> handler closures.
pub struct ElectrumHandler {
    methods: HashMap<String, MethodFn>,
    // Shared chain state
    chain_height: Arc<AtomicU64>,
    best_hash: Arc<RwLock<String>>,
    /// Per-scripthash subscription status hashes (scripthash -> status).
    scripthash_statuses: Arc<RwLock<HashMap<String, String>>>,
    /// Mock balances for testing: scripthash -> (confirmed, unconfirmed).
    mock_balances: Arc<RwLock<HashMap<String, (u64, u64)>>>,
    /// Mock history for testing: scripthash -> vec of (tx_hash, height).
    mock_history: Arc<RwLock<HashMap<String, Vec<(String, i64)>>>>,
    /// Mock unspent outputs: scripthash -> vec of (tx_hash, tx_pos, value, height).
    mock_unspent: Arc<RwLock<HashMap<String, Vec<(String, u32, u64, u64)>>>>,
    /// Mock raw transactions: txid -> raw_hex.
    mock_transactions: Arc<RwLock<HashMap<String, String>>>,
    /// Mock block headers: height -> 80-byte hex.
    mock_headers: Arc<RwLock<HashMap<u64, String>>>,
}

impl ElectrumHandler {
    /// Create a handler with default genesis state.
    pub fn new() -> Self {
        Self::new_with_state(
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new(GENESIS_HASH.to_string())),
        )
    }

    /// Create a handler with shared state references.
    pub fn new_with_state(
        chain_height: Arc<AtomicU64>,
        best_hash: Arc<RwLock<String>>,
    ) -> Self {
        let scripthash_statuses = Arc::new(RwLock::new(HashMap::new()));
        let mock_balances = Arc::new(RwLock::new(HashMap::new()));
        let mock_history = Arc::new(RwLock::new(HashMap::new()));
        let mock_unspent = Arc::new(RwLock::new(HashMap::new()));
        let mock_transactions = Arc::new(RwLock::new(HashMap::new()));
        let mock_headers = Arc::new(RwLock::new(HashMap::new()));

        let mut handler = ElectrumHandler {
            methods: HashMap::new(),
            chain_height,
            best_hash,
            scripthash_statuses,
            mock_balances,
            mock_history,
            mock_unspent,
            mock_transactions,
            mock_headers,
        };

        handler.register_all_methods();
        handler
    }

    // -----------------------------------------------------------------
    // State mutation helpers (for testing / integration)
    // -----------------------------------------------------------------

    /// Update the chain tip.
    pub fn update_chain_state(&self, height: u64, hash: &str) {
        self.chain_height.store(height, Ordering::SeqCst);
        let mut guard = self.best_hash.write().unwrap();
        *guard = hash.to_string();
    }

    /// Set mock balance for a scripthash.
    pub fn set_mock_balance(&self, scripthash: &str, confirmed: u64, unconfirmed: u64) {
        let mut balances = self.mock_balances.write().unwrap();
        balances.insert(scripthash.to_string(), (confirmed, unconfirmed));
    }

    /// Set mock transaction history for a scripthash.
    pub fn set_mock_history(&self, scripthash: &str, history: Vec<(String, i64)>) {
        let mut h = self.mock_history.write().unwrap();
        h.insert(scripthash.to_string(), history);
    }

    /// Set mock unspent outputs for a scripthash.
    pub fn set_mock_unspent(&self, scripthash: &str, utxos: Vec<(String, u32, u64, u64)>) {
        let mut u = self.mock_unspent.write().unwrap();
        u.insert(scripthash.to_string(), utxos);
    }

    /// Set mock raw transaction data.
    pub fn set_mock_transaction(&self, txid: &str, raw_hex: &str) {
        let mut txns = self.mock_transactions.write().unwrap();
        txns.insert(txid.to_string(), raw_hex.to_string());
    }

    /// Set mock block header hex for a given height.
    pub fn set_mock_header(&self, height: u64, header_hex: &str) {
        let mut headers = self.mock_headers.write().unwrap();
        headers.insert(height, header_hex.to_string());
    }

    // -----------------------------------------------------------------
    // Method registration
    // -----------------------------------------------------------------

    fn register_all_methods(&mut self) {
        // --- server.version ---
        self.register(METHOD_SERVER_VERSION, |_params| {
            serde_json::json!([SERVER_VERSION, PROTOCOL_VERSION])
        });

        // --- server.banner ---
        self.register(METHOD_SERVER_BANNER, |_params| {
            serde_json::json!(DEFAULT_BANNER)
        });

        // --- server.features ---
        {
            let height = self.chain_height.clone();
            let hash = self.best_hash.clone();
            self.register(METHOD_SERVER_FEATURES, move |_params| {
                let h = height.load(Ordering::SeqCst);
                let bh = hash.read().unwrap().clone();
                serde_json::json!({
                    "genesis_hash": GENESIS_HASH,
                    "hosts": {
                        "": {
                            "tcp_port": 50001
                        }
                    },
                    "protocol_max": PROTOCOL_VERSION,
                    "protocol_min": "1.4",
                    "pruning": null,
                    "server_version": SERVER_VERSION,
                    "hash_function": "sha256",
                    "block_height": h,
                    "best_block_hash": bh,
                })
            });
        }

        // --- server.ping ---
        self.register(METHOD_SERVER_PING, |_params| Value::Null);

        // --- blockchain.headers.subscribe ---
        {
            let height = self.chain_height.clone();
            let headers = self.mock_headers.clone();
            self.register(METHOD_HEADERS_SUBSCRIBE, move |_params| {
                let h = height.load(Ordering::SeqCst);
                let header_hex = {
                    let guard = headers.read().unwrap();
                    guard.get(&h).cloned().unwrap_or_else(|| "00".repeat(80))
                };
                serde_json::json!({
                    "height": h,
                    "hex": header_hex,
                })
            });
        }

        // --- blockchain.scripthash.get_history ---
        {
            let history = self.mock_history.clone();
            self.register(METHOD_SCRIPTHASH_GET_HISTORY, move |params| {
                let scripthash = match params_get_str(&params, 0) {
                    Some(s) => s,
                    None => return serde_json::json!([]),
                };
                let guard = history.read().unwrap();
                match guard.get(&scripthash) {
                    Some(entries) => {
                        let arr: Vec<Value> = entries
                            .iter()
                            .map(|(txid, height)| {
                                serde_json::json!({
                                    "tx_hash": txid,
                                    "height": height,
                                })
                            })
                            .collect();
                        Value::Array(arr)
                    }
                    None => serde_json::json!([]),
                }
            });
        }

        // --- blockchain.scripthash.get_balance ---
        {
            let balances = self.mock_balances.clone();
            self.register(METHOD_SCRIPTHASH_GET_BALANCE, move |params| {
                let scripthash = match params_get_str(&params, 0) {
                    Some(s) => s,
                    None => {
                        return serde_json::json!({
                            "confirmed": 0,
                            "unconfirmed": 0,
                        });
                    }
                };
                let guard = balances.read().unwrap();
                let (confirmed, unconfirmed) = guard.get(&scripthash).copied().unwrap_or((0, 0));
                serde_json::json!({
                    "confirmed": confirmed,
                    "unconfirmed": unconfirmed,
                })
            });
        }

        // --- blockchain.scripthash.listunspent ---
        {
            let unspent = self.mock_unspent.clone();
            self.register(METHOD_SCRIPTHASH_LISTUNSPENT, move |params| {
                let scripthash = match params_get_str(&params, 0) {
                    Some(s) => s,
                    None => return serde_json::json!([]),
                };
                let guard = unspent.read().unwrap();
                match guard.get(&scripthash) {
                    Some(utxos) => {
                        let arr: Vec<Value> = utxos
                            .iter()
                            .map(|(txid, pos, value, height)| {
                                serde_json::json!({
                                    "tx_hash": txid,
                                    "tx_pos": pos,
                                    "value": value,
                                    "height": height,
                                })
                            })
                            .collect();
                        Value::Array(arr)
                    }
                    None => serde_json::json!([]),
                }
            });
        }

        // --- blockchain.scripthash.subscribe ---
        {
            let statuses = self.scripthash_statuses.clone();
            let history = self.mock_history.clone();
            self.register(METHOD_SCRIPTHASH_SUBSCRIBE, move |params| {
                let scripthash = match params_get_str(&params, 0) {
                    Some(s) => s,
                    None => return Value::Null,
                };

                // Compute a status hash from the history if available.
                // The Electrum protocol defines status as the SHA-256 of the
                // concatenated "txid:height:" strings for all history entries.
                let status = {
                    let guard = history.read().unwrap();
                    match guard.get(&scripthash) {
                        Some(entries) if !entries.is_empty() => {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            for (txid, height) in entries {
                                hasher.update(format!("{}:{}:", txid, height));
                            }
                            let hash = hasher.finalize();
                            hex::encode(hash)
                        }
                        _ => return Value::Null,
                    }
                };

                // Store the subscription status.
                let mut guard = statuses.write().unwrap();
                guard.insert(scripthash, status.clone());

                serde_json::json!(status)
            });
        }

        // --- blockchain.transaction.get ---
        {
            let transactions = self.mock_transactions.clone();
            self.register(METHOD_TRANSACTION_GET, move |params| {
                let txid = match params_get_str(&params, 0) {
                    Some(s) => s,
                    None => return Value::Null,
                };
                let guard = transactions.read().unwrap();
                match guard.get(&txid) {
                    Some(raw) => serde_json::json!(raw),
                    None => Value::Null,
                }
            });
        }

        // --- blockchain.transaction.broadcast ---
        self.register(METHOD_TRANSACTION_BROADCAST, |params| {
            // In a real implementation, this would decode, validate, and
            // relay the transaction to the mempool. For now, echo back a
            // mock txid (double-SHA-256 of the raw hex bytes).
            let raw_hex = match params_get_str(&params, 0) {
                Some(s) => s,
                None => return Value::Null,
            };
            // Compute a deterministic "txid" from the raw hex for testing.
            use sha2::{Digest, Sha256};
            let bytes = hex::decode(&raw_hex).unwrap_or_default();
            let hash1 = Sha256::digest(&bytes);
            let hash2 = Sha256::digest(&hash1);
            let mut txid_bytes: [u8; 32] = hash2.into();
            txid_bytes.reverse(); // Bitcoin display order
            serde_json::json!(hex::encode(txid_bytes))
        });

        // --- blockchain.estimatefee ---
        self.register(METHOD_ESTIMATEFEE, |params| {
            let _nblocks = params
                .get(0)
                .and_then(|v| v.as_u64())
                .unwrap_or(6);
            // Default fee estimate: 0.0001 BTC/kB (~10 sat/vbyte)
            serde_json::json!(0.0001)
        });

        // --- blockchain.block.header ---
        {
            let headers = self.mock_headers.clone();
            self.register(METHOD_BLOCK_HEADER, move |params| {
                let height = match params.get(0).and_then(|v| v.as_u64()) {
                    Some(h) => h,
                    None => return Value::Null,
                };
                let guard = headers.read().unwrap();
                match guard.get(&height) {
                    Some(hex) => serde_json::json!(hex),
                    None => {
                        // Return a zeroed 80-byte header as placeholder
                        serde_json::json!("00".repeat(80))
                    }
                }
            });
        }

        // --- blockchain.block.headers ---
        {
            let headers = self.mock_headers.clone();
            self.register(METHOD_BLOCK_HEADERS, move |params| {
                let start_height = match params.get(0).and_then(|v| v.as_u64()) {
                    Some(h) => h,
                    None => return Value::Null,
                };
                let count = params
                    .get(1)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1)
                    .min(2016); // Cap at 2016 (one difficulty period)

                let guard = headers.read().unwrap();
                let mut hex_concat = String::new();
                let mut actual_count = 0u64;
                for h in start_height..start_height + count {
                    let header_hex = guard
                        .get(&h)
                        .cloned()
                        .unwrap_or_else(|| "00".repeat(80));
                    hex_concat.push_str(&header_hex);
                    actual_count += 1;
                }

                serde_json::json!({
                    "count": actual_count,
                    "hex": hex_concat,
                    "max": 2016,
                })
            });
        }
    }

    /// Register a method handler. The closure receives `params` and must
    /// return the `result` value.
    fn register<F>(&mut self, method: &str, f: F)
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        self.methods.insert(method.to_string(), Box::new(f));
    }

    // -----------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------

    /// Dispatch a parsed request and return a response.
    pub fn handle(&self, request: &ElectrumRequest) -> ElectrumResponse {
        info!(method = %request.method, "electrum call");

        match self.methods.get(&request.method) {
            Some(handler) => {
                let result = handler(request.params.clone());
                ElectrumResponse::success(request.id.clone(), result)
            }
            None => ElectrumResponse::error(
                request.id.clone(),
                METHOD_NOT_FOUND,
                format!("unknown method: {}", request.method),
            ),
        }
    }

    /// Handle a raw JSON line -- parse, dispatch, serialize.
    pub fn handle_raw(&self, raw: &str) -> String {
        let request: ElectrumRequest = match serde_json::from_str(raw) {
            Ok(r) => r,
            Err(e) => {
                let resp = ElectrumResponse::error(Value::Null, PARSE_ERROR, e.to_string());
                return resp.to_json();
            }
        };

        let resp = self.handle(&request);
        resp.to_json()
    }

    /// Returns a list of all registered method names.
    pub fn method_names(&self) -> Vec<&str> {
        self.methods.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ElectrumHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a string from a params array at the given index.
fn params_get_str(params: &Value, index: usize) -> Option<String> {
    params.get(index).and_then(|v| v.as_str()).map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, params: Value) -> ElectrumRequest {
        ElectrumRequest {
            id: Value::Number(1.into()),
            method: method.to_string(),
            params,
            jsonrpc: None,
        }
    }

    // -- server.version --

    #[test]
    fn test_server_version() {
        let handler = ElectrumHandler::new();
        let req = make_request(METHOD_SERVER_VERSION, serde_json::json!(["Electrum", "1.4"]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr[0], SERVER_VERSION);
        assert_eq!(arr[1], PROTOCOL_VERSION);
    }

    // -- server.banner --

    #[test]
    fn test_server_banner() {
        let handler = ElectrumHandler::new();
        let req = make_request(METHOD_SERVER_BANNER, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let banner = resp.result.unwrap();
        assert!(banner.as_str().unwrap().contains("btc-rust"));
    }

    // -- server.features --

    #[test]
    fn test_server_features() {
        let handler = ElectrumHandler::new();
        let req = make_request(METHOD_SERVER_FEATURES, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let features = resp.result.unwrap();
        assert_eq!(features["genesis_hash"], GENESIS_HASH);
        assert_eq!(features["protocol_max"], PROTOCOL_VERSION);
        assert_eq!(features["hash_function"], "sha256");
        assert_eq!(features["server_version"], SERVER_VERSION);
    }

    // -- server.ping --

    #[test]
    fn test_server_ping() {
        let handler = ElectrumHandler::new();
        let req = make_request(METHOD_SERVER_PING, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result, Some(Value::Null));
    }

    // -- blockchain.headers.subscribe --

    #[test]
    fn test_headers_subscribe() {
        let handler = ElectrumHandler::new();
        handler.update_chain_state(100, "00000000000000aabb");
        let req = make_request(METHOD_HEADERS_SUBSCRIBE, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["height"], 100);
        // hex should be present (placeholder)
        assert!(result["hex"].as_str().unwrap().len() > 0);
    }

    // -- blockchain.scripthash.get_balance --

    #[test]
    fn test_scripthash_get_balance_empty() {
        let handler = ElectrumHandler::new();
        let req = make_request(
            METHOD_SCRIPTHASH_GET_BALANCE,
            serde_json::json!(["abcd1234"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["confirmed"], 0);
        assert_eq!(result["unconfirmed"], 0);
    }

    #[test]
    fn test_scripthash_get_balance_with_mock_data() {
        let handler = ElectrumHandler::new();
        let scripthash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        handler.set_mock_balance(scripthash, 150_000, 25_000);

        let req = make_request(
            METHOD_SCRIPTHASH_GET_BALANCE,
            serde_json::json!([scripthash]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["confirmed"], 150_000);
        assert_eq!(result["unconfirmed"], 25_000);
    }

    // -- blockchain.scripthash.get_history --

    #[test]
    fn test_scripthash_get_history_empty() {
        let handler = ElectrumHandler::new();
        let req = make_request(
            METHOD_SCRIPTHASH_GET_HISTORY,
            serde_json::json!(["deadbeef"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!([]));
    }

    #[test]
    fn test_scripthash_get_history_with_data() {
        let handler = ElectrumHandler::new();
        let sh = "aabbccdd";
        handler.set_mock_history(
            sh,
            vec![
                ("tx1111".to_string(), 100),
                ("tx2222".to_string(), 200),
            ],
        );

        let req = make_request(METHOD_SCRIPTHASH_GET_HISTORY, serde_json::json!([sh]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["tx_hash"], "tx1111");
        assert_eq!(arr[0]["height"], 100);
        assert_eq!(arr[1]["tx_hash"], "tx2222");
        assert_eq!(arr[1]["height"], 200);
    }

    // -- blockchain.scripthash.listunspent --

    #[test]
    fn test_scripthash_listunspent() {
        let handler = ElectrumHandler::new();
        let sh = "aabbccdd";
        handler.set_mock_unspent(
            sh,
            vec![("txid1".to_string(), 0, 50_000, 500)],
        );

        let req = make_request(METHOD_SCRIPTHASH_LISTUNSPENT, serde_json::json!([sh]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["tx_hash"], "txid1");
        assert_eq!(arr[0]["tx_pos"], 0);
        assert_eq!(arr[0]["value"], 50_000);
        assert_eq!(arr[0]["height"], 500);
    }

    // -- blockchain.scripthash.subscribe --

    #[test]
    fn test_scripthash_subscribe_no_history() {
        let handler = ElectrumHandler::new();
        let req = make_request(
            METHOD_SCRIPTHASH_SUBSCRIBE,
            serde_json::json!(["deadbeef"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        // No history => null status
        assert_eq!(resp.result, Some(Value::Null));
    }

    #[test]
    fn test_scripthash_subscribe_with_history() {
        let handler = ElectrumHandler::new();
        let sh = "abcdef01";
        handler.set_mock_history(
            sh,
            vec![("txhash_abc".to_string(), 42)],
        );

        let req = make_request(METHOD_SCRIPTHASH_SUBSCRIBE, serde_json::json!([sh]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let status = resp.result.unwrap();
        // Status should be a hex-encoded SHA-256 hash (64 chars)
        let status_str = status.as_str().unwrap();
        assert_eq!(status_str.len(), 64);
    }

    // -- blockchain.transaction.get --

    #[test]
    fn test_transaction_get() {
        let handler = ElectrumHandler::new();
        let txid = "aaaa";
        let raw_hex = "0100000001abcdef";
        handler.set_mock_transaction(txid, raw_hex);

        let req = make_request(METHOD_TRANSACTION_GET, serde_json::json!([txid]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(raw_hex));
    }

    #[test]
    fn test_transaction_get_unknown() {
        let handler = ElectrumHandler::new();
        let req = make_request(
            METHOD_TRANSACTION_GET,
            serde_json::json!(["nonexistent"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result, Some(Value::Null));
    }

    // -- blockchain.transaction.broadcast --

    #[test]
    fn test_transaction_broadcast() {
        let handler = ElectrumHandler::new();
        let raw_hex = "0100000001aaaa";
        let req = make_request(
            METHOD_TRANSACTION_BROADCAST,
            serde_json::json!([raw_hex]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        // Should return a hex txid (64 chars for sha256d)
        let txid = resp.result.unwrap();
        assert_eq!(txid.as_str().unwrap().len(), 64);
    }

    // -- blockchain.estimatefee --

    #[test]
    fn test_estimatefee() {
        let handler = ElectrumHandler::new();
        let req = make_request(METHOD_ESTIMATEFEE, serde_json::json!([6]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let fee = resp.result.unwrap().as_f64().unwrap();
        assert!(fee > 0.0);
    }

    // -- blockchain.block.header --

    #[test]
    fn test_block_header() {
        let handler = ElectrumHandler::new();
        let header_hex = "aa".repeat(80);
        handler.set_mock_header(0, &header_hex);

        let req = make_request(METHOD_BLOCK_HEADER, serde_json::json!([0]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(header_hex));
    }

    #[test]
    fn test_block_header_placeholder() {
        let handler = ElectrumHandler::new();
        let req = make_request(METHOD_BLOCK_HEADER, serde_json::json!([999]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        // Placeholder should be 80 zero-bytes = 160 hex chars
        let hex = resp.result.unwrap();
        assert_eq!(hex.as_str().unwrap().len(), 160);
    }

    // -- blockchain.block.headers --

    #[test]
    fn test_block_headers_range() {
        let handler = ElectrumHandler::new();
        handler.set_mock_header(0, &"aa".repeat(80));
        handler.set_mock_header(1, &"bb".repeat(80));

        let req = make_request(METHOD_BLOCK_HEADERS, serde_json::json!([0, 2]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["count"], 2);
        assert_eq!(result["max"], 2016);
        // Two 80-byte headers concatenated = 320 hex chars
        assert_eq!(result["hex"].as_str().unwrap().len(), 320);
    }

    // -- unknown method --

    #[test]
    fn test_unknown_method() {
        let handler = ElectrumHandler::new();
        let req = make_request("nonexistent.method", serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, METHOD_NOT_FOUND);
    }

    // -- handle_raw --

    #[test]
    fn test_handle_raw_valid() {
        let handler = ElectrumHandler::new();
        let raw = r#"{"id":1,"method":"server.version","params":["test","1.4"]}"#;
        let resp_str = handler.handle_raw(raw);
        let resp: ElectrumResponse = serde_json::from_str(&resp_str).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result[0], SERVER_VERSION);
    }

    #[test]
    fn test_handle_raw_parse_error() {
        let handler = ElectrumHandler::new();
        let raw = "this is not json";
        let resp_str = handler.handle_raw(raw);
        let resp: ElectrumResponse = serde_json::from_str(&resp_str).unwrap();
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn test_response_id_echoed() {
        let handler = ElectrumHandler::new();
        let req = ElectrumRequest {
            id: Value::String("my-unique-id".to_string()),
            method: METHOD_SERVER_PING.to_string(),
            params: serde_json::json!([]),
            jsonrpc: None,
        };
        let resp = handler.handle(&req);
        assert_eq!(resp.id, Value::String("my-unique-id".to_string()));
    }

    // -- method dispatch enumeration --

    #[test]
    fn test_all_methods_registered() {
        let handler = ElectrumHandler::new();
        let names = handler.method_names();
        let expected = vec![
            METHOD_SERVER_VERSION,
            METHOD_SERVER_BANNER,
            METHOD_SERVER_FEATURES,
            METHOD_SERVER_PING,
            METHOD_HEADERS_SUBSCRIBE,
            METHOD_SCRIPTHASH_GET_HISTORY,
            METHOD_SCRIPTHASH_GET_BALANCE,
            METHOD_SCRIPTHASH_LISTUNSPENT,
            METHOD_SCRIPTHASH_SUBSCRIBE,
            METHOD_TRANSACTION_GET,
            METHOD_TRANSACTION_BROADCAST,
            METHOD_ESTIMATEFEE,
            METHOD_BLOCK_HEADER,
            METHOD_BLOCK_HEADERS,
        ];
        for name in &expected {
            assert!(names.contains(name), "missing method: {}", name);
        }
    }
}
