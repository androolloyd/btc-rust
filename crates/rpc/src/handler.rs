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

/// Backend operations return actual validated chain data or an RPC error.
pub trait ChainBackend: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}

pub const CHAIN_METHODS: &[&str] = &[
    METHOD_GETBLOCKCHAININFO,
    METHOD_GETBLOCK,
    METHOD_GETBLOCKHASH,
    METHOD_GETBLOCKHEADER,
    METHOD_GETBLOCKCOUNT,
    METHOD_GETBESTBLOCKHASH,
    METHOD_GETRAWTRANSACTION,
    "gettxout",
    METHOD_GETBLOCKTEMPLATE,
    METHOD_SUBMITBLOCK,
    METHOD_GETMININGINFO,
    METHOD_GETNETWORKHASHPS,
    METHOD_ESTIMATEFEE,
    METHOD_PRIORITISETRANSACTION,
    METHOD_GENERATETOADDRESS,
    "sendrawtransaction",
    "testmempoolaccept",
    "getrawmempool",
    "getmempoolentry",
    "getmempoolinfo",
];

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
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
    shutdown_tx: tokio::sync::watch::Sender<bool>,
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
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let mut handler = RpcHandler {
            methods: HashMap::new(),
            shutdown_flag: shutdown_flag.clone(),
            shutdown_tx: shutdown_tx.clone(),
            chain_height,
            best_hash,
            network,
            peer_count,
            mempool_size,
            mempool_bytes,
        };

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

        // --- getbestblockhash ---
        {
            let hash = handler.best_hash.clone();
            handler.register(METHOD_GETBESTBLOCKHASH, move |_params| {
                let bh = hash.read().unwrap().clone();
                serde_json::json!(bh)
            });
        }

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
                shutdown_tx.send_replace(true);
                serde_json::json!("Bitcoin server stopping")
            });
        }

        // ---------------------------------------------------------------
        // Mining RPCs
        // ---------------------------------------------------------------

        // Chain operations require a backend; never fabricate successful data.
        for method in CHAIN_METHODS {
            if matches!(*method, METHOD_GETBLOCKCOUNT | METHOD_GETBESTBLOCKHASH) {
                continue;
            }
            handler.register_fallible(method, |_| {
                Err(RpcError::new(
                    INTERNAL_ERROR,
                    "validated chain backend unavailable",
                ))
            });
        }

        handler
    }

    /// Install the node's authoritative chain backend for all chain RPCs.
    pub fn with_chain_backend(mut self, backend: Arc<dyn ChainBackend>) -> Self {
        for method in CHAIN_METHODS {
            let backend = Arc::clone(&backend);
            let method = *method;
            self.register_fallible(method, move |params| backend.call(method, params));
        }
        self
    }

    /// Register a method that can return a protocol error.
    pub fn register_fallible<F>(&mut self, method: &str, f: F)
    where
        F: Fn(Value) -> Result<Value, RpcError> + Send + Sync + 'static,
    {
        self.methods.insert(
            method.to_string(),
            Box::new(move |params| match f(params) {
                Ok(value) => RpcResponse::success(Value::Null, value),
                Err(error) => RpcResponse {
                    jsonrpc: "2.0".into(),
                    result: None,
                    error: Some(error),
                    id: Value::Null,
                },
            }),
        );
    }

    pub async fn wait_for_shutdown(&self) {
        let mut receiver = self.shutdown_tx.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.shutdown_tx.send_replace(true);
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
// Mining helper functions
// ---------------------------------------------------------------------------

/// Compute block subsidy in satoshis for a given height.
#[cfg(test)]
fn block_subsidy_sats(height: u64) -> u64 {
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    (50 * 100_000_000u64) >> halvings
}

/// Convert compact bits to floating-point difficulty.
pub fn compact_bits_to_difficulty(bits: u32) -> f64 {
    let exponent = bits >> 24;
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
pub fn compact_bits_to_target_hex(bits: u32) -> String {
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
    fn test_dispatch_getblockcount() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBLOCKCOUNT, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
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
    fn test_dispatch_getmempoolinfo_requires_backend() {
        let handler = RpcHandler::new();
        let resp = handler.handle(&make_request(METHOD_GETMEMPOOLINFO, serde_json::json!([])));
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
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
        handler.update_mempool_stats(10, 5000);
        assert_eq!(handler.mempool_size.load(Ordering::SeqCst), 10);
        assert_eq!(handler.mempool_bytes.load(Ordering::SeqCst), 5000);
        let resp = handler.handle(&make_request(METHOD_GETMEMPOOLINFO, serde_json::json!([])));
        assert!(
            resp.result.is_none(),
            "metrics do not establish a loaded mempool backend"
        );
    }

    #[test]
    fn test_getbestblockhash() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_GETBESTBLOCKHASH, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert_eq!(
            resp.result.unwrap(),
            serde_json::json!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
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
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
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

    // -- Mining RPC tests --

    #[test]
    fn test_prioritisetransaction_cannot_claim_success_without_a_backend() {
        let handler = RpcHandler::new();
        let txid = "aaaa000000000000000000000000000000000000000000000000000000000001";
        for delta in [5000, -2000, i64::MAX] {
            let response = handler.handle(&make_request(
                METHOD_PRIORITISETRANSACTION,
                serde_json::json!([txid, 0, delta]),
            ));
            assert!(response.result.is_none());
            assert_eq!(response.error.unwrap().code, INTERNAL_ERROR);
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
    fn test_estimatefee_no_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_ESTIMATEFEE, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
    }

    #[test]
    fn test_estimatefee_null_param() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_ESTIMATEFEE, serde_json::json!([null]));
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
    }

    #[test]
    fn test_prioritisetransaction_no_params() {
        let handler = RpcHandler::new();
        let req = make_request(METHOD_PRIORITISETRANSACTION, serde_json::json!([]));
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
    }

    #[test]
    fn test_prioritisetransaction_no_fee_delta() {
        let handler = RpcHandler::new();
        let txid = "aaaa000000000000000000000000000000000000000000000000000000000001";
        let req = make_request(METHOD_PRIORITISETRANSACTION, serde_json::json!([txid]));
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
    }

    #[test]
    fn test_prioritisetransaction_two_param_form() {
        let handler = RpcHandler::new();
        let txid = "bbbb000000000000000000000000000000000000000000000000000000000002";
        let req = make_request(
            METHOD_PRIORITISETRANSACTION,
            serde_json::json!([txid, 7000]),
        );
        let resp = handler.handle(&req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
    }

    #[test]
    fn fee_operations_delegate_to_the_actual_backend_without_shadow_state() {
        struct Backend(std::sync::Mutex<Vec<(String, Value)>>);
        impl ChainBackend for Backend {
            fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
                self.0.lock().unwrap().push((method.into(), params));
                Err(RpcError::new(METHOD_NOT_FOUND, "fee backend unavailable"))
            }
        }
        let backend = Arc::new(Backend(std::sync::Mutex::new(Vec::new())));
        let handler = RpcHandler::new().with_chain_backend(backend.clone());
        for method in [METHOD_ESTIMATEFEE, METHOD_PRIORITISETRANSACTION] {
            let response = handler.handle(&make_request(method, serde_json::json!([1])));
            assert!(response.result.is_none());
            assert_eq!(response.error.unwrap().code, METHOD_NOT_FOUND);
        }
        assert_eq!(
            *backend.0.lock().unwrap(),
            vec![
                (METHOD_ESTIMATEFEE.into(), serde_json::json!([1])),
                (METHOD_PRIORITISETRANSACTION.into(), serde_json::json!([1]))
            ]
        );
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
    fn mempool_methods_require_backend_even_with_nonzero_metrics() {
        let handler = RpcHandler::new();
        handler.update_mempool_stats(42, 123456);
        for method in [
            "getmempoolinfo",
            "getrawmempool",
            "getmempoolentry",
            "sendrawtransaction",
            "testmempoolaccept",
        ] {
            let resp = handler.handle(&make_request(method, serde_json::json!([])));
            assert!(resp.result.is_none());
            assert_eq!(resp.error.unwrap().code, INTERNAL_ERROR);
        }
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
    fn chain_operations_require_a_validated_backend() {
        let handler = RpcHandler::new();
        for method in CHAIN_METHODS {
            if matches!(*method, METHOD_GETBLOCKCOUNT | METHOD_GETBESTBLOCKHASH) {
                continue;
            }
            let response = handler.handle(&make_request(method, serde_json::json!([])));
            assert_eq!(response.error.unwrap().code, INTERNAL_ERROR);
            assert!(response.result.is_none());
        }
    }

    #[test]
    fn fallible_method_preserves_error_and_request_id() {
        let mut handler = RpcHandler::new();
        handler.register_fallible("failure", |_| Err(RpcError::new(-8, "invalid height")));
        let response = handler.handle(&make_request("failure", serde_json::json!([])));
        assert_eq!(response.id, serde_json::json!(1));
        assert_eq!(response.error.unwrap().code, -8);
        assert!(response.result.is_none());
    }
}
