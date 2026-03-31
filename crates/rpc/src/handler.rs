use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;

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
}

impl Default for RpcHandler {
    fn default() -> Self {
        Self::new()
    }
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
}
