//! Electrum protocol wire types.
//!
//! The Electrum protocol uses a JSON-RPC-like format over newline-delimited
//! TCP. It is similar to JSON-RPC 2.0 but has subtle differences:
//! - The `jsonrpc` field is optional (many clients omit it).
//! - The `id` field can be any JSON value (number, string, or null).
//! - Subscription notifications use `method` in the response.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// An Electrum JSON-RPC request.
///
/// Matches the wire format used by Electrum clients:
/// ```json
/// {"id": 0, "method": "server.version", "params": ["Electrum", "1.4"]}
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ElectrumRequest {
    /// Request identifier -- echoed back in the response.
    pub id: Value,

    /// The RPC method name (e.g. "server.version").
    pub method: String,

    /// Method parameters. Defaults to an empty array if omitted.
    #[serde(default = "default_params")]
    pub params: Value,

    /// Optional JSON-RPC version field (most Electrum clients omit this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<String>,
}

fn default_params() -> Value {
    Value::Array(vec![])
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// An Electrum JSON-RPC response.
///
/// ```json
/// {"id": 0, "result": ["ElectrumX 1.16", "1.4"]}
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ElectrumResponse {
    /// Echoed request identifier.
    pub id: Value,

    /// The result on success, absent on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Error object on failure, absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ElectrumError>,

    /// JSON-RPC version (included for compatibility).
    pub jsonrpc: String,
}

/// Electrum protocol error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ElectrumError {
    pub code: i32,
    pub message: String,
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

impl ElectrumResponse {
    /// Build a success response.
    pub fn success(id: Value, result: Value) -> Self {
        ElectrumResponse {
            id,
            result: Some(result),
            error: None,
            jsonrpc: "2.0".to_string(),
        }
    }

    /// Build an error response.
    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        ElectrumResponse {
            id,
            result: None,
            error: Some(ElectrumError {
                code,
                message: message.into(),
            }),
            jsonrpc: "2.0".to_string(),
        }
    }

    /// Serialize to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_parsing_full() {
        let json = r#"{"id":0,"method":"server.version","params":["Electrum","1.4"]}"#;
        let req: ElectrumRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Value::Number(0.into()));
        assert_eq!(req.method, "server.version");
        assert_eq!(req.params, serde_json::json!(["Electrum", "1.4"]));
        assert!(req.jsonrpc.is_none());
    }

    #[test]
    fn test_request_parsing_no_params() {
        let json = r#"{"id":1,"method":"server.banner"}"#;
        let req: ElectrumRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "server.banner");
        assert_eq!(req.params, serde_json::json!([]));
    }

    #[test]
    fn test_request_parsing_with_jsonrpc() {
        let json = r#"{"jsonrpc":"2.0","id":"abc","method":"server.features","params":[]}"#;
        let req: ElectrumRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, Some("2.0".to_string()));
        assert_eq!(req.id, Value::String("abc".to_string()));
    }

    #[test]
    fn test_request_parsing_null_id() {
        let json = r#"{"id":null,"method":"server.version","params":[]}"#;
        let req: ElectrumRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_null());
    }

    #[test]
    fn test_response_serialization_success() {
        let resp = ElectrumResponse::success(
            Value::Number(1.into()),
            serde_json::json!(["btc-rust electrum 0.1.0", "1.4"]),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn test_response_serialization_error() {
        let resp = ElectrumResponse::error(
            Value::Number(2.into()),
            METHOD_NOT_FOUND,
            "unknown method",
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32601"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = ElectrumResponse::success(
            Value::String("test-id".to_string()),
            serde_json::json!(42),
        );
        let json = resp.to_json();
        let parsed: ElectrumResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, Value::String("test-id".to_string()));
        assert_eq!(parsed.result, Some(serde_json::json!(42)));
        assert!(parsed.error.is_none());
    }

    #[test]
    fn test_request_serialization_roundtrip() {
        let req = ElectrumRequest {
            id: Value::Number(5.into()),
            method: "blockchain.transaction.get".to_string(),
            params: serde_json::json!(["aabbccdd"]),
            jsonrpc: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ElectrumRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, "blockchain.transaction.get");
        assert_eq!(parsed.params, serde_json::json!(["aabbccdd"]));
    }

    // -----------------------------------------------------------------
    // Additional coverage tests
    // -----------------------------------------------------------------

    #[test]
    fn test_default_params_function() {
        let val = default_params();
        assert_eq!(val, Value::Array(vec![]));
    }

    #[test]
    fn test_response_success_fields() {
        let resp = ElectrumResponse::success(Value::Number(42.into()), serde_json::json!("ok"));
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, Value::Number(42.into()));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_response_error_fields() {
        let resp = ElectrumResponse::error(Value::Number(7.into()), INTERNAL_ERROR, "broken");
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, Value::Number(7.into()));
        assert!(resp.result.is_none());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, INTERNAL_ERROR);
        assert_eq!(err.message, "broken");
    }

    #[test]
    fn test_response_to_json_success() {
        let resp = ElectrumResponse::success(Value::Number(1.into()), serde_json::json!(true));
        let json = resp.to_json();
        assert!(json.contains("\"result\":true"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_response_to_json_error() {
        let resp = ElectrumResponse::error(Value::Null, PARSE_ERROR, "parse failed");
        let json = resp.to_json();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32700"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_error_roundtrip() {
        let resp = ElectrumResponse::error(
            Value::String("err-id".to_string()),
            INVALID_PARAMS,
            "bad params",
        );
        let json = resp.to_json();
        let parsed: ElectrumResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, Value::String("err-id".to_string()));
        let err = parsed.error.unwrap();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.message, "bad params");
        assert!(parsed.result.is_none());
    }

    #[test]
    fn test_request_with_object_params() {
        let json = r#"{"id":10,"method":"server.version","params":{"client":"test"}}"#;
        let req: ElectrumRequest = serde_json::from_str(json).unwrap();
        assert!(req.params.is_object());
    }

    #[test]
    fn test_request_with_numeric_id() {
        let json = r#"{"id":999,"method":"server.ping","params":[]}"#;
        let req: ElectrumRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Value::Number(999.into()));
    }

    #[test]
    fn test_response_success_null_result() {
        let resp = ElectrumResponse::success(Value::Number(0.into()), Value::Null);
        // Before serialization, result is Some(Null)
        assert_eq!(resp.result, Some(Value::Null));
        assert!(resp.error.is_none());
        // Verify it serializes to valid JSON containing "result":null
        let json = resp.to_json();
        assert!(json.contains("\"result\":null"));
    }

    #[test]
    fn test_error_constants() {
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
    }

    #[test]
    fn test_request_serialization_with_jsonrpc() {
        let req = ElectrumRequest {
            id: Value::Number(1.into()),
            method: "test".to_string(),
            params: serde_json::json!([]),
            jsonrpc: Some("2.0".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn test_request_serialization_without_jsonrpc() {
        let req = ElectrumRequest {
            id: Value::Number(1.into()),
            method: "test".to_string(),
            params: serde_json::json!([]),
            jsonrpc: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        // jsonrpc field should not be present (skip_serializing_if)
        assert!(!json.contains("jsonrpc"));
    }

    #[test]
    fn test_electrum_error_debug() {
        let err = ElectrumError {
            code: -1,
            message: "test error".to_string(),
        };
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("test error"));
    }

    #[test]
    fn test_response_clone() {
        let resp = ElectrumResponse::success(Value::Number(1.into()), serde_json::json!(42));
        let cloned = resp.clone();
        assert_eq!(cloned.id, resp.id);
        assert_eq!(cloned.result, resp.result);
    }

    #[test]
    fn test_request_clone() {
        let req = ElectrumRequest {
            id: Value::Number(1.into()),
            method: "server.ping".to_string(),
            params: serde_json::json!([]),
            jsonrpc: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.method, req.method);
        assert_eq!(cloned.id, req.id);
    }
}
