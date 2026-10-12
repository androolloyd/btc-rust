//! Experimental chain/transaction Electrum dispatch. No fabricated wallet state.
use crate::methods::*;
use crate::protocol::{
    ElectrumError, ElectrumRequest, ElectrumResponse, INTERNAL_ERROR, INVALID_PARAMS,
    INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR,
};
use btc_primitives::BlockHash;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

pub const MAX_BATCH: usize = 128;
pub const MAX_SCRIPT_SUBSCRIPTIONS: usize = 64;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Implementations must query the actual validated chain and admit broadcasts
/// through its verifier. No provider is equivalent to explicit unavailability.
pub trait ElectrumBackend: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, ElectrumError>;
    fn subscribe_headers(&self) -> broadcast::Receiver<BlockHash>;
    /// Coalesced invalidation, published only after durable chain/pool changes.
    fn subscribe_scripts(&self) -> Option<watch::Receiver<u64>> {
        None
    }
    /// One consistent validated snapshot, in the requested script order.
    fn script_statuses(&self, _scripts: &[String]) -> Result<Vec<Value>, ElectrumError> {
        Err(error(
            INTERNAL_ERROR,
            "validated script status provider unavailable",
        ))
    }
}

#[derive(Default)]
pub struct ElectrumHandler {
    backend: Option<Arc<dyn ElectrumBackend>>,
}

/// Subscription ownership belongs to one connection, never to the shared handler.
#[derive(Default)]
pub(crate) struct ScriptSession {
    pub scripts: BTreeMap<String, Value>,
}

pub(crate) struct Dispatch {
    pub output: String,
    pub header: Option<Value>,
    pub close: bool,
}

fn error(code: i32, message: &str) -> ElectrumError {
    ElectrumError {
        code,
        message: message.into(),
    }
}

impl ElectrumHandler {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_backend(mut self, backend: Arc<dyn ElectrumBackend>) -> Self {
        self.backend = Some(backend);
        self
    }
    pub(crate) fn subscribe_headers(&self) -> Option<broadcast::Receiver<BlockHash>> {
        self.backend
            .as_ref()
            .map(|backend| backend.subscribe_headers())
    }
    pub(crate) fn tip(&self) -> Result<Value, ElectrumError> {
        self.call(METHOD_HEADERS_SUBSCRIBE, json!([]))
    }

    pub(crate) fn subscribe_scripts(&self) -> Option<watch::Receiver<u64>> {
        self.backend
            .as_ref()
            .and_then(|provider| provider.subscribe_scripts())
    }
    fn statuses(&self, scripts: &[String]) -> Result<Vec<Value>, ElectrumError> {
        let provider = self.backend.as_ref().ok_or_else(|| {
            error(
                INTERNAL_ERROR,
                "validated script status provider unavailable",
            )
        })?;
        if provider.subscribe_scripts().is_none() {
            return Err(error(
                INTERNAL_ERROR,
                "validated script event provider unavailable",
            ));
        }
        let statuses = provider.script_statuses(scripts)?;
        if statuses.len() != scripts.len()
            || statuses.iter().any(|status| {
                !status.is_null()
                    && status
                        .as_str()
                        .is_none_or(|value| value.len() != 64 || hex::decode(value).is_err())
            })
        {
            return Err(error(
                INTERNAL_ERROR,
                "invalid script status provider response",
            ));
        }
        Ok(statuses)
    }
    pub(crate) fn refresh_scripts(
        &self,
        session: &mut ScriptSession,
    ) -> Result<Vec<Value>, ElectrumError> {
        let scripts: Vec<_> = session.scripts.keys().cloned().collect();
        let statuses = self.statuses(&scripts)?;
        let mut notifications = Vec::new();
        for (script, status) in scripts.into_iter().zip(statuses) {
            if session.scripts.get(&script) != Some(&status) {
                notifications.push(json!({"jsonrpc":"2.0","method":METHOD_SCRIPTHASH_SUBSCRIBE,"params":[script,status]}));
                session.scripts.insert(script, status);
            }
        }
        Ok(notifications)
    }
    fn call(&self, method: &str, params: Value) -> Result<Value, ElectrumError> {
        self.call_session(method, params, None)
    }
    fn call_session(
        &self,
        method: &str,
        params: Value,
        session: Option<&mut ScriptSession>,
    ) -> Result<Value, ElectrumError> {
        let (names, required): (&[&str], usize) = match method {
            METHOD_SERVER_PING | METHOD_SERVER_BANNER | METHOD_HEADERS_SUBSCRIBE => (&[], 0),
            METHOD_BLOCK_HEADER => (&["height", "cp_height"], 1),
            METHOD_BLOCK_HEADERS => (&["start_height", "count", "cp_height"], 2),
            METHOD_TRANSACTION_GET => (&["tx_hash", "verbose"], 1),
            METHOD_TRANSACTION_BROADCAST => (&["raw_tx"], 1),
            METHOD_TRANSACTION_GET_MERKLE => (&["tx_hash", "height"], 2),
            METHOD_SCRIPTHASH_GET_HISTORY | METHOD_SCRIPTHASH_GET_MEMPOOL | METHOD_SCRIPTHASH_GET_BALANCE | METHOD_SCRIPTHASH_LISTUNSPENT | METHOD_SCRIPTHASH_SUBSCRIBE | METHOD_SCRIPTHASH_UNSUBSCRIBE => (&["scripthash"],1),
            // An advertised Electrum version requires *all* its nonoptional
            // methods. Do not claim compatibility before every required method works.
            METHOD_SERVER_VERSION | METHOD_SERVER_FEATURES => return Err(error(METHOD_NOT_FOUND, "complete Electrum protocol negotiation is unavailable; this is an experimental chain/transaction subset")),
            METHOD_ESTIMATEFEE => return Err(error(METHOD_NOT_FOUND, "fee estimator is not implemented")),
            _ => return Err(error(METHOD_NOT_FOUND, "unknown or unsupported Electrum method")),
        };
        let params = match params {
            Value::Array(values) if values.len() >= required && values.len() <= names.len() => {
                Value::Array(values)
            }
            Value::Object(values) => {
                if values.keys().any(|key| !names.contains(&key.as_str())) {
                    return Err(error(INVALID_PARAMS, "unknown named parameter"));
                }
                let mut ordered: Vec<_> = names
                    .iter()
                    .map(|name| values.get(*name).cloned().unwrap_or(Value::Null))
                    .collect();
                while ordered.len() > required && ordered.last() == Some(&Value::Null) {
                    ordered.pop();
                }
                Value::Array(ordered)
            }
            _ => {
                return Err(error(
                    INVALID_PARAMS,
                    "expected supported positional or named parameters",
                ))
            }
        };
        if matches!(
            method,
            METHOD_SCRIPTHASH_SUBSCRIBE | METHOD_SCRIPTHASH_UNSUBSCRIBE
        ) {
            let script = params
                .get(0)
                .and_then(Value::as_str)
                .filter(|value| value.len() == 64 && hex::decode(value).is_ok())
                .ok_or_else(|| error(INVALID_PARAMS, "scripthash must be 32-byte hexadecimal"))?
                .to_ascii_lowercase();
            let session = session.ok_or_else(|| {
                error(
                    INTERNAL_ERROR,
                    "script subscriptions require a live connection",
                )
            })?;
            if method == METHOD_SCRIPTHASH_UNSUBSCRIBE {
                return Ok(json!(session.scripts.remove(&script).is_some()));
            }
            if session.scripts.len() >= MAX_SCRIPT_SUBSCRIPTIONS
                && !session.scripts.contains_key(&script)
            {
                return Err(error(1, "script subscription limit reached"));
            }
            let mut scripts: Vec<_> = session
                .scripts
                .keys()
                .filter(|key| *key != &script)
                .cloned()
                .collect();
            scripts.push(script.clone());
            // Check the entire connection's shared query budget before adding.
            let status = self
                .statuses(&scripts)?
                .pop()
                .ok_or_else(|| error(INTERNAL_ERROR, "script status missing"))?;
            session.scripts.insert(script, status.clone());
            return Ok(status);
        }
        match method {
            METHOD_SERVER_PING => Ok(Value::Null),
            METHOD_SERVER_BANNER => Ok(json!("btc-rust experimental validated chain/transaction service; full protocol negotiation is unavailable")),
            _ => self.backend.as_ref().ok_or_else(|| error(INTERNAL_ERROR, "validated chain provider unavailable"))?.call(method, params),
        }
    }

    pub fn handle(&self, request: &ElectrumRequest) -> ElectrumResponse {
        self.handle_session(request, None)
    }
    fn handle_session(
        &self,
        request: &ElectrumRequest,
        session: Option<&mut ScriptSession>,
    ) -> ElectrumResponse {
        if request.method.len() > 128
            || request
                .jsonrpc
                .as_deref()
                .is_some_and(|v| v != "2.0" && v != "1.0")
        {
            return ElectrumResponse::error(
                request.id.clone(),
                INVALID_REQUEST,
                "invalid RPC version or method",
            );
        }
        match self.call_session(&request.method, request.params.clone(), session) {
            Ok(result) => ElectrumResponse::success(request.id.clone(), result),
            Err(error) => ElectrumResponse::error(request.id.clone(), error.code, error.message),
        }
    }

    fn member(
        &self,
        mut value: Value,
        dispatch: &mut Dispatch,
        session: Option<&mut ScriptSession>,
    ) -> Option<Value> {
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let valid_id = matches!(id, Value::Null | Value::Number(_) | Value::String(_));
        let version2 = value.get("jsonrpc") == Some(&json!("2.0"));
        let notification = value.is_object() && value.get("id").is_none();
        if notification {
            value["id"] = Value::Null;
        }
        let request: Result<ElectrumRequest, _> = serde_json::from_value(value);
        let response = match request {
            Ok(request) if valid_id => {
                let response = self.handle_session(&request, session);
                if request.method == METHOD_HEADERS_SUBSCRIBE && response.error.is_none() {
                    dispatch.header = response.result.clone();
                }
                if request.method == METHOD_SERVER_VERSION {
                    dispatch.close = true;
                }
                // Valid notifications execute but never carry response bytes.
                if notification
                    && response
                        .error
                        .as_ref()
                        .is_none_or(|e| e.code != INVALID_REQUEST)
                {
                    return None;
                }
                response
            }
            _ => ElectrumResponse::error(
                if valid_id { id } else { Value::Null },
                INVALID_REQUEST,
                "invalid Electrum request",
            ),
        };
        // Malformed envelopes have no negotiated legacy context. Emit the
        // standard v2 invalid-request shape with a fresh safe identifier.
        let version2 = version2
            || response
                .error
                .as_ref()
                .is_some_and(|e| e.code == INVALID_REQUEST);
        let mut out = serde_json::to_value(response).expect("RPC response serializes");
        if !version2 {
            out.as_object_mut().unwrap().remove("jsonrpc");
            if out.get("result").is_none() {
                out["result"] = Value::Null;
            }
            if out.get("error").is_none() {
                out["error"] = Value::Null;
            }
        }
        Some(out)
    }

    pub(crate) fn dispatch(&self, line: &str) -> Dispatch {
        self.dispatch_session(line, None)
    }
    pub(crate) fn dispatch_session(
        &self,
        line: &str,
        mut session: Option<&mut ScriptSession>,
    ) -> Dispatch {
        let mut dispatch = Dispatch {
            output: String::new(),
            header: None,
            close: false,
        };
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                dispatch.output =
                    ElectrumResponse::error(Value::Null, PARSE_ERROR, "invalid JSON").to_json();
                return dispatch;
            }
        };
        let batch = value.is_array();
        let members = match value {
            Value::Array(values) if !values.is_empty() && values.len() <= MAX_BATCH => values,
            Value::Array(_) => {
                dispatch.output = ElectrumResponse::error(
                    Value::Null,
                    INVALID_REQUEST,
                    "empty or oversized batch",
                )
                .to_json();
                return dispatch;
            }
            value => vec![value],
        };
        if batch {
            dispatch.output.push('[');
        }
        let mut count = 0;
        for member in members {
            let Some(out) = self.member(member, &mut dispatch, session.as_deref_mut()) else {
                continue;
            };
            let encoded = serde_json::to_string(&out).expect("RPC response serializes");
            if encoded.len() + dispatch.output.len() + 2 > MAX_RESPONSE_BYTES {
                dispatch.output = ElectrumResponse::error(
                    Value::Null,
                    INTERNAL_ERROR,
                    "response exceeds limit; batch operations are not rolled back",
                )
                .to_json();
                dispatch.close = true;
                return dispatch;
            }
            if batch && count > 0 {
                dispatch.output.push(',');
            }
            dispatch.output.push_str(&encoded);
            count += 1;
        }
        if count == 0 {
            dispatch.output.clear();
        } else if batch {
            dispatch.output.push(']');
        }
        dispatch
    }

    pub fn handle_raw(&self, line: &str) -> String {
        self.dispatch(line).output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_provider_never_fabricates_chain_or_broadcast_success() {
        let handler = ElectrumHandler::new();
        for (method, params) in [
            (METHOD_HEADERS_SUBSCRIBE, json!([])),
            (METHOD_BLOCK_HEADER, json!([0])),
            (METHOD_BLOCK_HEADERS, json!([0, 2])),
            (METHOD_TRANSACTION_GET, json!(["00".repeat(32)])),
            (METHOD_TRANSACTION_BROADCAST, json!(["ff"])),
            (METHOD_SCRIPTHASH_GET_BALANCE, json!(["00".repeat(32)])),
            (METHOD_SCRIPTHASH_GET_HISTORY, json!(["00".repeat(32)])),
            (METHOD_SCRIPTHASH_GET_MEMPOOL, json!(["00".repeat(32)])),
            (METHOD_SCRIPTHASH_LISTUNSPENT, json!(["00".repeat(32)])),
            (METHOD_SCRIPTHASH_SUBSCRIBE, json!(["00".repeat(32)])),
            (METHOD_SCRIPTHASH_UNSUBSCRIBE, json!(["00".repeat(32)])),
        ] {
            let response = handler.handle(&ElectrumRequest {
                id: json!(4),
                method: method.into(),
                params,
                jsonrpc: None,
            });
            assert_eq!(response.error.unwrap().code, INTERNAL_ERROR);
            assert!(response.result.is_none());
        }
        for method in [
            METHOD_SERVER_VERSION,
            METHOD_SERVER_FEATURES,
            METHOD_ESTIMATEFEE,
        ] {
            let response: Value = serde_json::from_str(
                &handler.handle_raw(&json!({"id":4,"method":method,"params":[]}).to_string()),
            )
            .unwrap();
            assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
            assert_eq!(response["result"], Value::Null);
        }
    }
    #[test]
    fn wire_ids_named_params_notifications_and_batch_are_bounded() {
        let handler = ElectrumHandler::new();
        let out: Value = serde_json::from_str(&handler.handle_raw(r#"[{"method":"server.ping","jsonrpc":"2.0"},{"id":"x","method":"server.ping","params":{},"jsonrpc":"2.0"},{"id":null,"method":"server.ping"},7]"#)).unwrap();
        assert_eq!(out.as_array().unwrap().len(), 3);
        assert_eq!(out[0], json!({"jsonrpc":"2.0","id":"x","result":null}));
        assert_eq!(out[1], json!({"id":null,"result":null,"error":null}));
        assert_eq!(out[2]["error"]["code"], INVALID_REQUEST);
        assert_eq!(out[2]["jsonrpc"], "2.0");
        assert!(out[2].get("result").is_none());
        assert_eq!(
            handler.handle_raw(r#"{"method":"server.ping","jsonrpc":"2.0"}"#),
            ""
        );
        for raw in [
            r#"{"id":1,"method":"server.ping","params":{"unused":1}}"#,
            r#"{"id":1,"method":"server.ping","params":[1]}"#,
        ] {
            let value: Value = serde_json::from_str(&handler.handle_raw(raw)).unwrap();
            assert_eq!(value["error"]["code"], INVALID_PARAMS);
        }
        let oversized = vec![json!({"id":1,"method":"server.ping"}); MAX_BATCH + 1];
        let value: Value =
            serde_json::from_str(&handler.handle_raw(&json!(oversized).to_string())).unwrap();
        assert_eq!(value["error"]["code"], INVALID_REQUEST);
        for (raw, code) in [
            ("{", PARSE_ERROR),
            ("[]", INVALID_REQUEST),
            ("null", INVALID_REQUEST),
            (r#"{"id":true,"method":"server.ping"}"#, INVALID_REQUEST),
            (
                r#"{"id":1,"method":"server.ping","jsonrpc":"9"}"#,
                INVALID_REQUEST,
            ),
        ] {
            let value: Value = serde_json::from_str(&handler.handle_raw(raw)).unwrap();
            assert_eq!(value["error"]["code"], code);
        }
    }
}
