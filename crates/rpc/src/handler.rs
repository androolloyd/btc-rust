use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;

use btc_primitives::block::Block;
use btc_primitives::encode::Decodable;

use crate::methods::*;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 wire types
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

impl RpcResponse {
    /// Build a success response.
    pub fn success(id: Value, result: Value) -> Self {
        RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Build an error response.
    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

// ---------------------------------------------------------------------------
// Method handler function type
// ---------------------------------------------------------------------------

type MethodFn = Box<dyn Fn(Value) -> RpcResponse + Send + Sync>;

// ---------------------------------------------------------------------------
// RpcHandler
// ---------------------------------------------------------------------------

/// Central dispatcher for JSON-RPC methods.
pub struct RpcHandler {
    methods: HashMap<String, MethodFn>,
    shutdown_flag: Arc<AtomicBool>,
    // Shared state
    chain_height: Arc<AtomicU64>,
    best_hash: Arc<RwLock<String>>,
    network: String,
    peer_count: Arc<AtomicU64>,
    mempool_size: Arc<AtomicU64>,
    mempool_bytes: Arc<AtomicU64>,
    /// Fee deltas for prioritised transactions (txid hex -> satoshi delta).
    priority_deltas: Arc<RwLock<HashMap<String, i64>>>,
}

impl RpcHandler {
    /// Create a handler pre-loaded with all skeleton Bitcoin RPC methods.
    /// Uses default (genesis) state -- suitable for tests.
    pub fn new() -> Self {
        Self::new_with_state(
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string(),
            )),
            "main".to_string(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    /// Create a handler with shared state references.
    ///
    /// # Arguments
    /// * `chain_height` - current best chain height
    /// * `best_hash` - current best block hash (hex string)
    /// * `network` - network name (e.g. "main", "test", "regtest")
    /// * `peer_count` - number of connected peers
    /// * `mempool_size` - number of transactions in the mempool
    /// * `mempool_bytes` - total size of mempool transactions in bytes
    pub fn new_with_state(
        chain_height: Arc<AtomicU64>,
        best_hash: Arc<RwLock<String>>,
        network: String,
        peer_count: Arc<AtomicU64>,
        mempool_size: Arc<AtomicU64>,
        mempool_bytes: Arc<AtomicU64>,
    ) -> Self {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let mut handler = RpcHandler {
            methods: HashMap::new(),
            shutdown_flag: shutdown_flag.clone(),
            chain_height,
            best_hash,
            network,
            peer_count,
            mempool_size,
            mempool_bytes,
            priority_deltas: Arc::new(RwLock::new(HashMap::new())),
        };

        // --- getblockchaininfo ---
        {
            let height = handler.chain_height.clone();
            let hash = handler.best_hash.clone();
            let net = handler.network.clone();
            handler.register(METHOD_GETBLOCKCHAININFO, move |_params| {
                let h = height.load(Ordering::SeqCst);
                let bh = hash.read().unwrap().clone();
                let progress = if h == 0 { 0.0 } else { 1.0 };
                serde_json::json!({
                    "chain": net,
                    "blocks": h,
                    "headers": h,
                    "bestblockhash": bh,
                    "difficulty": 1.0,
                    "mediantime": 1231006505_u64,
                    "verificationprogress": progress,
                    "initialblockdownload": h == 0,
                    "chainwork": "0000000000000000000000000000000000000000000000000000000100010001",
                    "pruned": false,
                    "warnings": ""
                })
            });
        }

        // --- getblockhash ---
        {
            let height = handler.chain_height.clone();
            handler.register(METHOD_GETBLOCKHASH, move |params| {
                let requested = match params.get(0).and_then(|v| v.as_u64()) {
                    Some(h) => h,
                    None => {
                        return serde_json::json!(null);
                    }
                };
                let current = height.load(Ordering::SeqCst);
                if requested > current {
                    return serde_json::json!(null);
                }
                if requested == 0 {
                    serde_json::json!(
                        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                    )
                } else {
                    // For heights we know about but don't have stored, return a zeroed hash.
                    serde_json::json!(
                        "0000000000000000000000000000000000000000000000000000000000000000"
                    )
                }
            });
        }

        // --- getblockheader ---
        handler.register(METHOD_GETBLOCKHEADER, |params| {
            let _hash = params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            serde_json::json!({
                "hash": _hash,
                "confirmations": 1,
                "height": 0,
                "version": 1,
                "versionHex": "00000001",
                "merkleroot": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                "time": 1231006505_u64,
                "mediantime": 1231006505_u64,
                "nonce": 2083236893_u64,
                "bits": "1d00ffff",
                "difficulty": 1.0,
                "chainwork": "0000000000000000000000000000000000000000000000000000000100010001",
                "nTx": 1,
                "previousblockhash": serde_json::Value::Null,
                "nextblockhash": serde_json::Value::Null,
            })
        });

        // --- getblockcount ---
        {
            let height = handler.chain_height.clone();
            handler.register(METHOD_GETBLOCKCOUNT, move |_params| {
                serde_json::json!(height.load(Ordering::SeqCst))
            });
        }

        // --- getpeerinfo ---
        {
            let peers = handler.peer_count.clone();
            handler.register(METHOD_GETPEERINFO, move |_params| {
                let count = peers.load(Ordering::SeqCst);
                let mut arr = Vec::new();
                for i in 0..count {
                    arr.push(serde_json::json!({
                        "id": i,
                        "addr": format!("127.0.0.1:{}", 8333 + i),
                        "services": "0000000000000001",
                        "relaytxes": true,
                        "lastsend": 0,
                        "lastrecv": 0,
                        "conntime": 0,
                        "pingtime": 0.0,
                        "version": 70016,
                        "subver": "/btc-rust:0.1.0/",
                        "inbound": false,
                    }));
                }
                serde_json::json!(arr)
            });
        }

        // --- getmempoolinfo ---
        {
            let mp_size = handler.mempool_size.clone();
            let mp_bytes = handler.mempool_bytes.clone();
            handler.register(METHOD_GETMEMPOOLINFO, move |_params| {
                let size = mp_size.load(Ordering::SeqCst);
                let bytes = mp_bytes.load(Ordering::SeqCst);
                serde_json::json!({
                    "loaded": true,
                    "size": size,
                    "bytes": bytes,
                    "usage": bytes,
                    "maxmempool": 300000000_u64,
                    "mempoolminfee": 0.00001,
                    "minrelaytxfee": 0.00001,
                    "unbroadcastcount": 0
                })
            });
        }

        // --- getbestblockhash ---
        {
            let hash = handler.best_hash.clone();
            handler.register(METHOD_GETBESTBLOCKHASH, move |_params| {
                let bh = hash.read().unwrap().clone();
                serde_json::json!(bh)
            });
        }

        // --- estimatefee ---
        handler.register(METHOD_ESTIMATEFEE, |params| {
            let _nblocks = params.get(0).and_then(|v| v.as_u64()).unwrap_or(6);
            // Return a default fee estimate of 0.00001 BTC/kB (1 sat/vbyte)
            serde_json::json!(0.00001)
        });

        // --- getnetworkinfo ---
        {
            let peers = handler.peer_count.clone();
            let net = handler.network.clone();
            handler.register(METHOD_GETNETWORKINFO, move |_params| {
                let connections = peers.load(Ordering::SeqCst);
                serde_json::json!({
                    "version": 270000,
                    "subversion": "/btc-rust:0.1.0/",
                    "protocolversion": 70016,
                    "localservices": "0000000000000001",
                    "localrelay": true,
                    "timeoffset": 0,
                    "networkactive": true,
                    "connections": connections,
                    "connections_in": 0,
                    "connections_out": connections,
                    "networks": [
                        {
                            "name": net,
                            "limited": false,
                            "reachable": true,
                        }
                    ],
                    "relayfee": 0.00001,
                    "incrementalfee": 0.00001,
                    "warnings": ""
                })
            });
        }

        // --- stop ---
        {
            let stop_flag = shutdown_flag;
            handler.register(METHOD_STOP, move |_params| {
                stop_flag.store(true, Ordering::SeqCst);
                serde_json::json!("Bitcoin server stopping")
            });
        }

        // ---------------------------------------------------------------
        // Mining RPCs
        // ---------------------------------------------------------------

        // --- getblocktemplate ---
        {
            let height = handler.chain_height.clone();
            let hash = handler.best_hash.clone();
            handler.register(METHOD_GETBLOCKTEMPLATE, move |_params| {
                let h = height.load(Ordering::SeqCst);
                let bh = hash.read().unwrap().clone();
                // Difficulty-1 target in compact form
                let bits: u32 = 0x1d00ffff;
                // Expand bits to 256-bit target hex
                let target_hex = compact_bits_to_target_hex(bits);
                let curtime = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0) as u64;
                // Coinbase value: subsidy for next block height (no fees from empty tx list)
                let subsidy = block_subsidy_sats(h + 1);

                serde_json::json!({
                    "version": 536870912_u32,
                    "previousblockhash": bh,
                    "transactions": [],
                    "coinbasevalue": subsidy,
                    "target": target_hex,
                    "mintime": curtime.saturating_sub(600),
                    "curtime": curtime,
                    "height": h + 1,
                    "bits": format!("{:08x}", bits)
                })
            });
        }

        // --- submitblock ---
        handler.register(METHOD_SUBMITBLOCK, |params| {
            let block_hex = match params.get(0).and_then(|v| v.as_str()) {
                Some(h) => h,
                None => {
                    return serde_json::json!("invalid parameter: expected hex string");
                }
            };

            let raw = match hex::decode(block_hex) {
                Ok(b) => b,
                Err(e) => {
                    return serde_json::json!(format!("invalid hex: {}", e));
                }
            };

            let mut cursor = std::io::Cursor::new(&raw[..]);
            match Block::decode(&mut cursor) {
                Ok(block) => {
                    // Basic structural validation
                    if block.transactions.is_empty() {
                        return serde_json::json!("block must have at least one transaction");
                    }
                    if !block.transactions[0].is_coinbase() {
                        return serde_json::json!("first transaction must be coinbase");
                    }
                    // Structural validation passed; full chain validation is not yet wired up.
                    serde_json::json!(null)
                }
                Err(e) => {
                    serde_json::json!(format!("decode error: {}", e))
                }
            }
        });

        // --- getmininginfo ---
        {
            let height = handler.chain_height.clone();
            let net = handler.network.clone();
            handler.register(METHOD_GETMININGINFO, move |_params| {
                let h = height.load(Ordering::SeqCst);
                let bits: u32 = 0x1d00ffff;
                let difficulty = compact_bits_to_difficulty(bits);
                // Simple estimate: difficulty * 2^32 / 600
                let hashps = difficulty * 4_294_967_296.0 / 600.0;
                serde_json::json!({
                    "blocks": h,
                    "difficulty": difficulty,
                    "networkhashps": hashps,
                    "chain": net
                })
            });
        }

        // --- getnetworkhashps ---
        handler.register(METHOD_GETNETWORKHASHPS, |params| {
            let _nblocks = params.get(0).and_then(|v| v.as_i64()).unwrap_or(120);
            let _height = params.get(1).and_then(|v| v.as_i64()).unwrap_or(-1);
            let bits: u32 = 0x1d00ffff;
            let difficulty = compact_bits_to_difficulty(bits);
            // Simple formula: difficulty * 2^32 / target_spacing(600s)
            let hashps = difficulty * 4_294_967_296.0 / 600.0;
            serde_json::json!(hashps)
        });

        // --- prioritisetransaction ---
        {
            let deltas = handler.priority_deltas.clone();
            handler.register(METHOD_PRIORITISETRANSACTION, move |params| {
                let txid = match params.get(0).and_then(|v| v.as_str()) {
                    Some(t) => t.to_string(),
                    None => {
                        return serde_json::json!(false);
                    }
                };
                // params[1] is the dummy value (ignored, for Bitcoin Core compat)
                let fee_delta = match params.get(2).and_then(|v| v.as_i64())
                    .or_else(|| params.get(1).and_then(|v| v.as_i64()))
                {
                    Some(d) => d,
                    None => {
                        return serde_json::json!(false);
                    }
                };
                let mut guard = deltas.write().unwrap();
                let entry = guard.entry(txid).or_insert(0);
                *entry += fee_delta;
                serde_json::json!(true)
            });
        }

        // --- generatetoaddress ---
        {
            let net = handler.network.clone();
            handler.register(METHOD_GENERATETOADDRESS, move |params| {
                if net != "regtest" {
                    return serde_json::json!({
                        "error": "generatetoaddress is only available in regtest mode"
                    });
                }
                let nblocks = match params.get(0).and_then(|v| v.as_u64()) {
                    Some(n) => n,
                    None => {
                        return serde_json::json!(null);
                    }
                };
                let _address = match params.get(1).and_then(|v| v.as_str()) {
                    Some(a) => a.to_string(),
                    None => {
                        return serde_json::json!(null);
                    }
                };
                // In regtest, generate nblocks placeholder hashes.
                // Real block generation requires full chain integration.
                let hashes: Vec<String> = (0..nblocks)
                    .map(|i| format!("{:064x}", i + 1))
                    .collect();
                serde_json::json!(hashes)
            });
        }

        handler
    }

    // -----------------------------------------------------------------
    // State update methods
    // -----------------------------------------------------------------

    /// Update the chain height and best block hash.
    pub fn update_chain_state(&self, height: u64, hash: &str) {
        self.chain_height.store(height, Ordering::SeqCst);
        let mut guard = self.best_hash.write().unwrap();
        *guard = hash.to_string();
    }

    /// Update the connected peer count.
    pub fn update_peer_count(&self, count: u64) {
        self.peer_count.store(count, Ordering::SeqCst);
    }

    /// Update mempool statistics.
    pub fn update_mempool_stats(&self, size: u64, bytes: u64) {
        self.mempool_size.store(size, Ordering::SeqCst);
        self.mempool_bytes.store(bytes, Ordering::SeqCst);
    }

    /// Register a method handler. The closure receives `params` and must
    /// return the `result` value (not the full RpcResponse).
    pub fn register<F>(&mut self, method: &str, f: F)
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        let method_name = method.to_string();
        self.methods.insert(
            method_name.clone(),
            Box::new(move |params| {
                let result = f(params.clone());
                // Build an RpcResponse -- we'll fill in the id at dispatch time,
                // so use a placeholder that gets replaced.
                RpcResponse::success(Value::Null, result)
            }),
        );
    }

    /// Dispatch a parsed request and return a response.
    pub fn handle(&self, request: &RpcRequest) -> RpcResponse {
        info!(method = %request.method, "rpc call");

        if request.jsonrpc != "2.0" {
            return RpcResponse::error(
                request.id.clone(),
                INVALID_REQUEST,
                "only JSON-RPC 2.0 is supported",
            );
        }

        match self.methods.get(&request.method) {
            Some(handler) => {
                let mut resp = handler(request.params.clone());
                resp.id = request.id.clone();
                resp
            }
            None => RpcResponse::error(
                request.id.clone(),
                METHOD_NOT_FOUND,
                format!("method '{}' not found", request.method),
            ),
        }
    }

    /// Handle a raw JSON string -- parse, dispatch, serialize.
    pub fn handle_raw(&self, raw: &str) -> String {
        let request: RpcRequest = match serde_json::from_str(raw) {
            Ok(r) => r,
            Err(e) => {
                let resp = RpcResponse::error(Value::Null, PARSE_ERROR, e.to_string());
                return serde_json::to_string(&resp).unwrap_or_default();
            }
        };

        let resp = self.handle(&request);
        serde_json::to_string(&resp).unwrap_or_default()
    }

    /// Returns true if a `stop` call has been received.
    pub fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::SeqCst)
    }

    /// Get the priority delta for a transaction (for testing/introspection).
    pub fn get_priority_delta(&self, txid: &str) -> Option<i64> {
        let guard = self.priority_deltas.read().unwrap();
        guard.get(txid).copied()
    }
}

impl Default for RpcHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Mining helper functions
// ---------------------------------------------------------------------------

/// Compute block subsidy in satoshis for a given height.
fn block_subsidy_sats(height: u64) -> u64 {
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    50 * 100_000_000u64 >> halvings
}

/// Convert compact bits to floating-point difficulty.
fn compact_bits_to_difficulty(bits: u32) -> f64 {
    let exponent = (bits >> 24) as u32;
    let mantissa = (bits & 0x00ff_ffff) as f64;
    if mantissa == 0.0 {
        return 0.0;
    }
    // difficulty_1_target mantissa / current mantissa * 2^(8*(0x1d - exponent))
    let diff1_mantissa = 0x00ffffu64 as f64;
    let shift = 8 * (0x1d_u32.wrapping_sub(exponent)) as i32;
    diff1_mantissa / mantissa * 2f64.powi(shift)
}

/// Expand compact bits to a 64-hex-char target string (big-endian).
fn compact_bits_to_target_hex(bits: u32) -> String {
    let mut target = [0u8; 32];
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa != 0 && exponent > 0 && (bits & 0x0080_0000) == 0 {
        if exponent <= 3 {
            let m = mantissa >> (8 * (3 - exponent));
            target[31] = (m & 0xff) as u8;
            if exponent >= 2 {
                target[30] = ((m >> 8) & 0xff) as u8;
            }
            if exponent >= 3 {
                target[29] = ((m >> 16) & 0xff) as u8;
            }
        } else {
            let start = 32usize.saturating_sub(exponent);
            if start < 32 {
                target[start] = ((mantissa >> 16) & 0xff) as u8;
            }
            if start + 1 < 32 {
                target[start + 1] = ((mantissa >> 8) & 0xff) as u8;
            }
            if start + 2 < 32 {
                target[start + 2] = (mantissa & 0xff) as u8;
            }
        }
    }
    hex::encode(target)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, params: Value) -> RpcRequest {
        RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: Value::Number(1.into()),
        }
    }

    // -- Serialization / deserialization round-trips --

    #[test]
    fn test_request_deserialization() {
        let json = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;
        let req: RpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "getblockcount");
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, Value::Number(1.into()));
    }

    #[test]
    fn test_response_serialization_success() {
        let resp = RpcResponse::success(Value::Number(1.into()), serde_json::json!(42));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\":42"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_response_serialization_error() {
        let resp = RpcResponse::error(Value::Number(1.into()), METHOD_NOT_FOUND, "not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32601"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_request_serialization_roundtrip() {
        let req = make_request("getblockcount", serde_json::json!([]));
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: RpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.method, "getblockcount");
    }

    // -- Method dispatch --

    #[test]
    fn test_dispatch_getblockchaininfo() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKCHAININFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["chain"], "main");
        assert_eq!(result["blocks"], 0);
    }

    #[test]
    fn test_dispatch_getblockcount() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKCOUNT, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[test]
    fn test_dispatch_getblockhash_genesis() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKHASH, serde_json::json!([0]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let hash = resp.result.unwrap();
        assert_eq!(
            hash,
            serde_json::json!(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            )
        );
    }

    #[test]
    fn test_dispatch_getblockheader() {
        let handler = RpcHandler::new();
        let req = make_request(
            METHOD_GETBLOCKHEADER,
            serde_json::json!([
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            ]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["height"], 0);
    }

    #[test]
    fn test_dispatch_getpeerinfo() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETPEERINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!([]));
    }

    #[test]
    fn test_dispatch_getmempoolinfo() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETMEMPOOLINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["size"], 0);
        assert_eq!(result["loaded"], true);
    }

    #[test]
    fn test_dispatch_stop() {
        let handler = RpcHandler::new();
        assert!(!handler.should_shutdown());
        let req = make_request(METHOD_STOP, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert!(handler.should_shutdown());
    }

    #[test]
    fn test_dispatch_unknown_method() {
        let handler = RpcHandler::new();
        let req = make_request("nonexistent", serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn test_dispatch_invalid_jsonrpc_version() {
        let handler = RpcHandler::new();
        let req = RpcRequest {
            jsonrpc: "1.0".to_string(),
            method: "getblockcount".to_string(),
            params: serde_json::json!([]),
            id: Value::Number(1.into()),
        };
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn test_handle_raw_valid() {
        let handler = RpcHandler::new();
        let raw = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;
        let resp_str = handler.handle_raw(raw);
        let resp: RpcResponse = serde_json::from_str(&resp_str).unwrap();
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[test]
    fn test_handle_raw_parse_error() {
        let handler = RpcHandler::new();
        let raw = "this is not json";
        let resp_str = handler.handle_raw(raw);
        let resp: RpcResponse = serde_json::from_str(&resp_str).unwrap();
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn test_response_id_matches_request() {
        let handler = RpcHandler::new();
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "getblockcount".to_string(),
            params: serde_json::json!([]),
            id: Value::String("my-id-42".to_string()),
        };
        let resp = handler.handle(&req);
        assert_eq!(resp.id, Value::String("my-id-42".to_string()));
    }

    // -- Tests for state-aware methods --

    #[test]
    fn test_new_with_state_custom_values() {
        let handler = RpcHandler::new_with_state(
            Arc::new(AtomicU64::new(100)),
            Arc::new(RwLock::new("aabbccdd".to_string())),
            "regtest".to_string(),
            Arc::new(AtomicU64::new(5)),
            Arc::new(AtomicU64::new(42)),
            Arc::new(AtomicU64::new(9999)),
        );

        // getblockcount should return 100
        let req = make_request(METHOD_GETBLOCKCOUNT, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert_eq!(resp.result.unwrap(), serde_json::json!(100));

        // getblockchaininfo should reflect state
        let req = make_request(METHOD_GETBLOCKCHAININFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["chain"], "regtest");
        assert_eq!(result["blocks"], 100);
        assert_eq!(result["bestblockhash"], "aabbccdd");
        assert_eq!(result["initialblockdownload"], false);
        assert_eq!(result["verificationprogress"], 1.0);
    }

    #[test]
    fn test_update_chain_state() {
        let handler = RpcHandler::new();

        // Initially at height 0
        let req = make_request(METHOD_GETBLOCKCOUNT, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));

        // Update chain state
        handler.update_chain_state(500, "00000000000000000001deadbeef");

        // Should reflect updated height
        let req = make_request(METHOD_GETBLOCKCOUNT, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert_eq!(resp.result.unwrap(), serde_json::json!(500));

        // getblockchaininfo should also reflect
        let req = make_request(METHOD_GETBLOCKCHAININFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["blocks"], 500);
        assert_eq!(result["bestblockhash"], "00000000000000000001deadbeef");
    }

    #[test]
    fn test_update_peer_count() {
        let handler = RpcHandler::new();

        // Initially 0 peers
        let req = make_request(METHOD_GETPEERINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let arr = resp.result.unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 0);

        // Update peer count
        handler.update_peer_count(3);

        let req = make_request(METHOD_GETPEERINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let arr = resp.result.unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 3);

        // getnetworkinfo should reflect connections
        let req = make_request(METHOD_GETNETWORKINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["connections"], 3);
    }

    #[test]
    fn test_update_mempool_stats() {
        let handler = RpcHandler::new();

        // Update mempool
        handler.update_mempool_stats(10, 5000);

        let req = make_request(METHOD_GETMEMPOOLINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["size"], 10);
        assert_eq!(result["bytes"], 5000);
    }

    #[test]
    fn test_getbestblockhash() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBESTBLOCKHASH, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(
            resp.result.unwrap(),
            serde_json::json!(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            )
        );

        // After update
        handler.update_chain_state(1, "0000000000000000deadbeef");
        let req = make_request(METHOD_GETBESTBLOCKHASH, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert_eq!(
            resp.result.unwrap(),
            serde_json::json!("0000000000000000deadbeef")
        );
    }

    #[test]
    fn test_estimatefee() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_ESTIMATEFEE, serde_json::json!([6]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let fee = resp.result.unwrap().as_f64().unwrap();
        assert!(fee > 0.0);
    }

    #[test]
    fn test_getnetworkinfo() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETNETWORKINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["version"], 270000);
        assert_eq!(result["subversion"], "/btc-rust:0.1.0/");
        assert_eq!(result["protocolversion"], 70016);
        assert_eq!(result["connections"], 0);
    }

    #[test]
    fn test_getblockhash_beyond_height_returns_null() {
        let handler = RpcHandler::new();
        // Height 0 is current. Requesting height 1 should return null.
        let req = make_request(METHOD_GETBLOCKHASH, serde_json::json!([1]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_getblockhash_within_range_after_update() {
        let handler = RpcHandler::new();
        handler.update_chain_state(10, "00000000001111");
        // Height 5 is within range
        let req = make_request(METHOD_GETBLOCKHASH, serde_json::json!([5]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        // Non-genesis returns zeroed hash placeholder
        assert_eq!(
            resp.result.unwrap(),
            serde_json::json!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }

    // -- Mining RPC tests --

    #[test]
    fn test_getblocktemplate_returns_valid_json() {
        let handler = RpcHandler::new();
        handler.update_chain_state(810000, "0000000000000000000000000000000000000000000000000000000000abcdef");
        let req = make_request(METHOD_GETBLOCKTEMPLATE, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();

        // Required GBT fields
        assert_eq!(result["version"], 536870912);
        assert_eq!(
            result["previousblockhash"],
            "0000000000000000000000000000000000000000000000000000000000abcdef"
        );
        assert!(result["transactions"].is_array());
        assert!(result["coinbasevalue"].is_number());
        assert!(result["target"].is_string());
        assert!(result["mintime"].is_number());
        assert!(result["curtime"].is_number());
        assert_eq!(result["height"], 810001);
        assert!(result["bits"].is_string());
        // bits should be 8 hex chars
        assert_eq!(result["bits"].as_str().unwrap().len(), 8);
    }

    #[test]
    fn test_submitblock_invalid_hex() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!(["zzzz_not_hex"]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none()); // returns a result, not an RPC-level error
        let result = resp.result.unwrap();
        let msg = result.as_str().unwrap();
        assert!(msg.contains("invalid hex"), "expected hex error, got: {}", msg);
    }

    #[test]
    fn test_submitblock_truncated_data() {
        let handler = RpcHandler::new();
        // Valid hex but not a valid block (too short)
        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!(["aabbccdd"]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let msg = result.as_str().unwrap();
        assert!(msg.contains("decode error"), "expected decode error, got: {}", msg);
    }

    #[test]
    fn test_getmininginfo_returns_required_fields() {
        let handler = RpcHandler::new();
        handler.update_chain_state(810000, "00000000000000000000");
        let req = make_request(METHOD_GETMININGINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();

        assert_eq!(result["blocks"], 810000);
        assert!(result["difficulty"].is_number());
        assert!(result["difficulty"].as_f64().unwrap() > 0.0);
        assert!(result["networkhashps"].is_number());
        assert_eq!(result["chain"], "main");
    }

    #[test]
    fn test_getnetworkhashps_returns_number() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETNETWORKHASHPS, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.is_number());
        assert!(result.as_f64().unwrap() > 0.0);
    }

    #[test]
    fn test_prioritisetransaction_stores_delta() {
        let handler = RpcHandler::new();
        let txid = "aaaa000000000000000000000000000000000000000000000000000000000001";

        // Should return true
        let req = make_request(
            METHOD_PRIORITISETRANSACTION,
            serde_json::json!([txid, 0, 5000]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(true));

        // Verify stored delta
        assert_eq!(handler.get_priority_delta(txid), Some(5000));

        // Apply another delta -- should accumulate
        let req = make_request(
            METHOD_PRIORITISETRANSACTION,
            serde_json::json!([txid, 0, -2000]),
        );
        let resp = handler.handle(&req);
        assert_eq!(resp.result.unwrap(), serde_json::json!(true));
        assert_eq!(handler.get_priority_delta(txid), Some(3000));
    }

    #[test]
    fn test_generatetoaddress_non_regtest_returns_error() {
        // Default handler is "main" network
        let handler = RpcHandler::new();
        let req = make_request(
            METHOD_GENERATETOADDRESS,
            serde_json::json!([1, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        // Should contain an error message, not an array of hashes
        assert!(result["error"].is_string());
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("regtest"),
        );
    }

    #[test]
    fn test_generatetoaddress_regtest_returns_hashes() {
        let handler = RpcHandler::new_with_state(
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new("00".repeat(32))),
            "regtest".to_string(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let req = make_request(
            METHOD_GENERATETOADDRESS,
            serde_json::json!([3, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        // Each entry should be a 64-char hex hash
        for hash in arr {
            assert_eq!(hash.as_str().unwrap().len(), 64);
        }
    }

    // -----------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------

    #[test]
    fn test_default_trait() {
        let handler = RpcHandler::default();
        let req = make_request(METHOD_GETBLOCKCOUNT, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[test]
    fn test_getblockhash_no_params() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKHASH, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        // No height param => null
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_getblockhash_null_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKHASH, serde_json::json!([null]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_getblockheader_no_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKHEADER, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        // hash should be empty string (default)
        assert_eq!(result["hash"], "");
    }

    #[test]
    fn test_estimatefee_no_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_ESTIMATEFEE, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let fee = resp.result.unwrap().as_f64().unwrap();
        assert!(fee > 0.0);
    }

    #[test]
    fn test_estimatefee_null_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_ESTIMATEFEE, serde_json::json!([null]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let fee = resp.result.unwrap().as_f64().unwrap();
        assert_eq!(fee, 0.00001);
    }

    #[test]
    fn test_getnetworkhashps_with_params() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETNETWORKHASHPS, serde_json::json!([240, 100]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let hashps = resp.result.unwrap().as_f64().unwrap();
        assert!(hashps > 0.0);
    }

    #[test]
    fn test_getnetworkhashps_no_params() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETNETWORKHASHPS, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let hashps = resp.result.unwrap().as_f64().unwrap();
        assert!(hashps > 0.0);
    }

    #[test]
    fn test_submitblock_no_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let msg = resp.result.unwrap();
        assert!(msg.as_str().unwrap().contains("invalid parameter"));
    }

    #[test]
    fn test_submitblock_null_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!([null]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let msg = resp.result.unwrap();
        assert!(msg.as_str().unwrap().contains("invalid parameter"));
    }

    #[test]
    fn test_prioritisetransaction_no_params() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_PRIORITISETRANSACTION, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(false));
    }

    #[test]
    fn test_prioritisetransaction_no_fee_delta() {
        let handler = RpcHandler::new();
        let txid = "aaaa000000000000000000000000000000000000000000000000000000000001";
        let req = make_request(
            METHOD_PRIORITISETRANSACTION,
            serde_json::json!([txid]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(false));
    }

    #[test]
    fn test_prioritisetransaction_two_param_form() {
        // When only 2 params: txid and fee_delta (no dummy in between)
        let handler = RpcHandler::new();
        let txid = "bbbb000000000000000000000000000000000000000000000000000000000002";
        let req = make_request(
            METHOD_PRIORITISETRANSACTION,
            serde_json::json!([txid, 7000]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(true));
        assert_eq!(handler.get_priority_delta(txid), Some(7000));
    }

    #[test]
    fn test_get_priority_delta_nonexistent() {
        let handler = RpcHandler::new();
        assert_eq!(handler.get_priority_delta("doesnotexist"), None);
    }

    #[test]
    fn test_generatetoaddress_no_nblocks() {
        let handler = RpcHandler::new_with_state(
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new("00".repeat(32))),
            "regtest".to_string(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let req = make_request(METHOD_GENERATETOADDRESS, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_generatetoaddress_no_address() {
        let handler = RpcHandler::new_with_state(
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new("00".repeat(32))),
            "regtest".to_string(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let req = make_request(METHOD_GENERATETOADDRESS, serde_json::json!([5]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_generatetoaddress_zero_blocks() {
        let handler = RpcHandler::new_with_state(
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new("00".repeat(32))),
            "regtest".to_string(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let req = make_request(
            METHOD_GENERATETOADDRESS,
            serde_json::json!([0, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]),
        );
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result.as_array().unwrap().len(), 0);
    }

    // -- Mining helper function tests --

    #[test]
    fn test_block_subsidy_sats_genesis() {
        assert_eq!(block_subsidy_sats(0), 50 * 100_000_000);
    }

    #[test]
    fn test_block_subsidy_sats_first_halving() {
        assert_eq!(block_subsidy_sats(210_000), 25 * 100_000_000);
    }

    #[test]
    fn test_block_subsidy_sats_second_halving() {
        assert_eq!(block_subsidy_sats(420_000), 1_250_000_000);
    }

    #[test]
    fn test_block_subsidy_sats_after_64_halvings() {
        assert_eq!(block_subsidy_sats(210_000 * 64), 0);
    }

    #[test]
    fn test_block_subsidy_sats_far_future() {
        assert_eq!(block_subsidy_sats(210_000 * 100), 0);
    }

    #[test]
    fn test_compact_bits_to_difficulty_standard() {
        let diff = compact_bits_to_difficulty(0x1d00ffff);
        assert!((diff - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_compact_bits_to_difficulty_zero_mantissa() {
        assert_eq!(compact_bits_to_difficulty(0x1d000000), 0.0);
    }

    #[test]
    fn test_compact_bits_to_difficulty_higher() {
        let diff = compact_bits_to_difficulty(0x1b0404cb);
        assert!(diff > 1.0);
    }

    #[test]
    fn test_compact_bits_to_target_hex_standard() {
        let target = compact_bits_to_target_hex(0x1d00ffff);
        assert_eq!(target.len(), 64);
        // Should contain non-zero bytes
        assert!(target.contains(|c: char| c != '0'));
    }

    #[test]
    fn test_compact_bits_to_target_hex_zero_mantissa() {
        let target = compact_bits_to_target_hex(0x1d000000);
        // Zero mantissa -> all zeros
        assert_eq!(target, "00".repeat(32));
    }

    #[test]
    fn test_compact_bits_to_target_hex_negative_sign() {
        // Bit 0x00800000 is set -- negative sign bit, should produce all zeros
        let target = compact_bits_to_target_hex(0x1d800000);
        assert_eq!(target, "00".repeat(32));
    }

    #[test]
    fn test_compact_bits_to_target_hex_zero_exponent() {
        // Exponent 0 should produce all zeros
        let target = compact_bits_to_target_hex(0x00ffff00);
        assert_eq!(target, "00".repeat(32));
    }

    #[test]
    fn test_compact_bits_to_target_hex_exponent_1() {
        let target = compact_bits_to_target_hex(0x01010000);
        assert_eq!(target.len(), 64);
    }

    #[test]
    fn test_compact_bits_to_target_hex_exponent_2() {
        let target = compact_bits_to_target_hex(0x02010100);
        assert_eq!(target.len(), 64);
    }

    #[test]
    fn test_compact_bits_to_target_hex_exponent_3() {
        let target = compact_bits_to_target_hex(0x03010101);
        assert_eq!(target.len(), 64);
    }

    #[test]
    fn test_compact_bits_to_target_hex_exponent_4() {
        // Exponent 4 -> start at 32 - 4 = 28
        let target = compact_bits_to_target_hex(0x04010203);
        assert_eq!(target.len(), 64);
        // Bytes at positions 28, 29, 30 should contain the mantissa
        let bytes = hex::decode(&target).unwrap();
        assert_eq!(bytes[28], 0x01);
        assert_eq!(bytes[29], 0x02);
        assert_eq!(bytes[30], 0x03);
    }

    #[test]
    fn test_compact_bits_to_target_hex_large_exponent() {
        // Exponent > 32 -> start saturates to 0
        let target = compact_bits_to_target_hex(0x21010203);
        assert_eq!(target.len(), 64);
    }

    #[test]
    fn test_register_custom_method() {
        let mut handler = RpcHandler::new();
        handler.register("custom_method", |_params| {
            serde_json::json!("custom result")
        });
        let req = make_request("custom_method", serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!("custom result"));
    }

    #[test]
    fn test_handle_raw_with_string_id() {
        let handler = RpcHandler::new();
        let raw = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":"my-id"}"#;
        let resp_str = handler.handle_raw(raw);
        let resp: RpcResponse = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp.id, Value::String("my-id".to_string()));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_handle_raw_empty_object() {
        let handler = RpcHandler::new();
        let raw = r#"{}"#;
        let resp_str = handler.handle_raw(raw);
        let resp: RpcResponse = serde_json::from_str(&resp_str).unwrap();
        // Missing required "method" field should cause parse error
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn test_getblockchaininfo_zero_height_progress() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKCHAININFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        // At height 0, progress should be 0.0 and initialblockdownload = true
        assert_eq!(result["verificationprogress"], 0.0);
        assert_eq!(result["initialblockdownload"], true);
    }

    #[test]
    fn test_getblockchaininfo_nonzero_height_progress() {
        let handler = RpcHandler::new();
        handler.update_chain_state(1, "aabb");
        let req = make_request(METHOD_GETBLOCKCHAININFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["verificationprogress"], 1.0);
        assert_eq!(result["initialblockdownload"], false);
    }

    #[test]
    fn test_getpeerinfo_with_multiple_peers() {
        let handler = RpcHandler::new();
        handler.update_peer_count(5);
        let req = make_request(METHOD_GETPEERINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let arr = resp.result.unwrap();
        let peers = arr.as_array().unwrap();
        assert_eq!(peers.len(), 5);
        // Validate fields of first peer
        assert_eq!(peers[0]["id"], 0);
        assert_eq!(peers[0]["inbound"], false);
        assert_eq!(peers[0]["version"], 70016);
        assert!(peers[0]["addr"].as_str().unwrap().contains("127.0.0.1"));
    }

    #[test]
    fn test_getmempoolinfo_all_fields() {
        let handler = RpcHandler::new();
        handler.update_mempool_stats(42, 123456);
        let req = make_request(METHOD_GETMEMPOOLINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["loaded"], true);
        assert_eq!(result["size"], 42);
        assert_eq!(result["bytes"], 123456);
        assert_eq!(result["usage"], 123456);
        assert_eq!(result["maxmempool"], 300000000_u64);
        assert!(result["mempoolminfee"].as_f64().unwrap() > 0.0);
        assert!(result["minrelaytxfee"].as_f64().unwrap() > 0.0);
        assert_eq!(result["unbroadcastcount"], 0);
    }

    #[test]
    fn test_stop_sets_shutdown_flag() {
        let handler = RpcHandler::new();
        assert!(!handler.should_shutdown());
        let req = make_request(METHOD_STOP, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(
            resp.result.unwrap(),
            serde_json::json!("Bitcoin server stopping")
        );
        assert!(handler.should_shutdown());
    }

    #[test]
    fn test_getblocktemplate_coinbase_value() {
        let handler = RpcHandler::new();
        // At height 0, next block is height 1 -> 50 BTC subsidy
        let req = make_request(METHOD_GETBLOCKTEMPLATE, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["coinbasevalue"], 50 * 100_000_000u64);
        assert_eq!(result["height"], 1);
    }

    #[test]
    fn test_getblocktemplate_after_halving() {
        let handler = RpcHandler::new();
        handler.update_chain_state(209_999, "aabb");
        let req = make_request(METHOD_GETBLOCKTEMPLATE, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        // Next block is 210000 (first halving) -> 25 BTC subsidy
        assert_eq!(result["coinbasevalue"], 25 * 100_000_000u64);
    }

    #[test]
    fn test_getmininginfo_all_fields() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETMININGINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["blocks"], 0);
        assert!(result["difficulty"].as_f64().unwrap() > 0.0);
        assert!(result["networkhashps"].as_f64().unwrap() > 0.0);
        assert_eq!(result["chain"], "main");
    }

    #[test]
    fn test_getnetworkinfo_full_fields() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETNETWORKINFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["localservices"], "0000000000000001");
        assert_eq!(result["localrelay"], true);
        assert_eq!(result["timeoffset"], 0);
        assert_eq!(result["networkactive"], true);
        assert_eq!(result["connections_in"], 0);
        assert_eq!(result["connections_out"], 0);
        assert!(result["networks"].is_array());
        assert!(result["relayfee"].as_f64().unwrap() > 0.0);
        assert!(result["incrementalfee"].as_f64().unwrap() > 0.0);
        assert_eq!(result["warnings"], "");
    }

    #[test]
    fn test_rpc_error_data_field_none() {
        let resp = RpcResponse::error(Value::Number(1.into()), INTERNAL_ERROR, "boom");
        let err = resp.error.unwrap();
        assert!(err.data.is_none());
        assert_eq!(err.code, INTERNAL_ERROR);
        assert_eq!(err.message, "boom");
    }

    #[test]
    fn test_rpc_response_success_json_has_correct_jsonrpc() {
        let resp = RpcResponse::success(Value::Number(1.into()), serde_json::json!("ok"));
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn test_rpc_response_error_json_has_correct_jsonrpc() {
        let resp = RpcResponse::error(Value::Null, PARSE_ERROR, "bad");
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn test_handle_raw_malformed_json_array() {
        let handler = RpcHandler::new();
        let raw = r#"[1,2,3]"#;
        let resp_str = handler.handle_raw(raw);
        let resp: RpcResponse = serde_json::from_str(&resp_str).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn test_handle_raw_integer() {
        let handler = RpcHandler::new();
        let raw = "42";
        let resp_str = handler.handle_raw(raw);
        let resp: RpcResponse = serde_json::from_str(&resp_str).unwrap();
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_getblockheader_returns_all_fields() {
        let handler = RpcHandler::new();
        let req = make_request(
            METHOD_GETBLOCKHEADER,
            serde_json::json!(["000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"]),
        );
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(result["confirmations"], 1);
        assert_eq!(result["version"], 1);
        assert_eq!(result["versionHex"], "00000001");
        assert!(result["merkleroot"].is_string());
        assert_eq!(result["time"], 1231006505_u64);
        assert_eq!(result["mediantime"], 1231006505_u64);
        assert_eq!(result["nonce"], 2083236893_u64);
        assert_eq!(result["bits"], "1d00ffff");
        assert_eq!(result["difficulty"], 1.0);
        assert!(result["chainwork"].is_string());
        assert_eq!(result["nTx"], 1);
        assert!(result["previousblockhash"].is_null());
        assert!(result["nextblockhash"].is_null());
    }

    #[test]
    fn test_response_null_id() {
        let handler = RpcHandler::new();
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "getblockcount".to_string(),
            params: serde_json::json!([]),
            id: Value::Null,
        };
        let resp = handler.handle(&req);
        assert!(resp.id.is_null());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_method_not_found_message_contains_method_name() {
        let handler = RpcHandler::new();
        let req = make_request("some_unknown_rpc", serde_json::json!([]));
        let resp = handler.handle(&req);
        let err = resp.error.as_ref().unwrap();
        assert!(err.message.contains("some_unknown_rpc"));
    }

    #[test]
    fn test_getblockchaininfo_fields_comprehensive() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKCHAININFO, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        assert!(result["mediantime"].is_number());
        assert!(result["chainwork"].is_string());
        assert_eq!(result["pruned"], false);
        assert_eq!(result["warnings"], "");
    }

    #[test]
    fn test_getblocktemplate_target_is_64_hex() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKTEMPLATE, serde_json::json!([]));
        let resp = handler.handle(&req);
        let result = resp.result.unwrap();
        let target = result["target"].as_str().unwrap();
        assert_eq!(target.len(), 64);
        // target should be valid hex
        assert!(hex::decode(target).is_ok());
    }

    #[test]
    fn test_submitblock_valid_block_with_coinbase() {
        use btc_primitives::block::{Block, BlockHeader};
        use btc_primitives::compact::CompactTarget;
        use btc_primitives::encode::Encodable;
        use btc_primitives::hash::{BlockHash, TxHash};
        use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::amount::Amount;

        let handler = RpcHandler::new();

        // Build a coinbase transaction (prev_output is all-zeros txid with vout=0xffffffff)
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::ZERO, 0xffffffff),
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        // Encode the block to hex
        let mut buf = Vec::new();
        block.encode(&mut buf).unwrap();
        let block_hex = hex::encode(&buf);

        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!([block_hex]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        // Successful submission returns null
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_submitblock_block_with_no_transactions() {
        use btc_primitives::block::{Block, BlockHeader};
        use btc_primitives::compact::CompactTarget;
        use btc_primitives::encode::Encodable;
        use btc_primitives::hash::{BlockHash, TxHash};

        let handler = RpcHandler::new();

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 0,
            },
            transactions: vec![],
        };

        let mut buf = Vec::new();
        block.encode(&mut buf).unwrap();
        let block_hex = hex::encode(&buf);

        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!([block_hex]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let msg = resp.result.unwrap();
        assert_eq!(msg.as_str().unwrap(), "block must have at least one transaction");
    }

    #[test]
    fn test_submitblock_non_coinbase_first_tx() {
        use btc_primitives::block::{Block, BlockHeader};
        use btc_primitives::compact::CompactTarget;
        use btc_primitives::encode::Encodable;
        use btc_primitives::hash::{BlockHash, TxHash};
        use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
        use btc_primitives::script::ScriptBuf;
        use btc_primitives::amount::Amount;

        let handler = RpcHandler::new();

        // Build a NON-coinbase transaction (normal outpoint, not all-zeros/0xffffffff)
        let non_coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 0,
            },
            transactions: vec![non_coinbase_tx],
        };

        let mut buf = Vec::new();
        block.encode(&mut buf).unwrap();
        let block_hex = hex::encode(&buf);

        let req = make_request(METHOD_SUBMITBLOCK, serde_json::json!([block_hex]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let msg = resp.result.unwrap();
        assert_eq!(msg.as_str().unwrap(), "first transaction must be coinbase");
    }
}
