//! HTTP JSON-RPC envelopes. The typed internal dispatcher remains v2; adapting
//! an envelope never changes which backend runs or substitutes missing data.
use crate::handler::{
    RpcHandler, RpcRequest, RpcResponse, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
    METHOD_NOT_FOUND, PARSE_ERROR,
};
use serde_json::{json, Value};
use std::io::Write;

pub(crate) const MAX_BATCH: usize = 128;
pub(crate) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

struct LimitedBody(Vec<u8>);
impl Write for LimitedBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("RPC response budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn envelope(response: RpcResponse, v2: bool) -> Value {
    if v2 {
        serde_json::to_value(response).expect("RPC response is JSON serializable")
    } else {
        json!({"id": response.id, "result": response.result, "error": response.error})
    }
}

fn legacy_status(code: i32) -> u16 {
    match code {
        INVALID_REQUEST => 400,
        METHOD_NOT_FOUND => 404,
        _ => 500,
    }
}

/// An invalid envelope always gets a reply. Valid v2 notifications execute
/// through the same dispatcher, but neither successes nor RPC errors reply.
fn execute(handler: &RpcHandler, value: Value) -> (u16, Option<Value>) {
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let v2 = value.get("jsonrpc").and_then(Value::as_str) == Some("2.0");
    let invalid = |message| {
        (
            400,
            Some(envelope(
                RpcResponse::error(id.clone(), INVALID_REQUEST, message),
                v2,
            )),
        )
    };
    let Some(object) = value.as_object() else {
        return invalid("request must be an object");
    };
    if !matches!(object.get("jsonrpc"), None | Some(Value::Null))
        && !matches!(
            object.get("jsonrpc").and_then(Value::as_str),
            Some("1.0" | "2.0")
        )
    {
        return invalid("unsupported JSON-RPC version");
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return invalid("method must be a string");
    };
    if method.len() > 128 {
        return invalid("method exceeds length limit");
    }
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    if !params.is_null() && !params.is_array() && !params.is_object() {
        return invalid("params must be an array or object");
    }
    let response = if params.is_object() {
        // The runtime accepts positional arguments. Silently treating named
        // values as absent could perform the wrong mutating operation.
        RpcResponse::error(
            id,
            INVALID_PARAMS,
            "named parameters are not supported; use positional parameters",
        )
    } else {
        handler.handle(&RpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params: if params.is_null() { json!([]) } else { params },
            id,
        })
    };
    if v2 && !object.contains_key("id") {
        return (204, None);
    }
    let status = if v2 {
        200
    } else {
        response
            .error
            .as_ref()
            .map(|e| legacy_status(e.code))
            .unwrap_or(200)
    };
    (status, Some(envelope(response, v2)))
}

fn error_reply(status: u16, code: i32, message: &str) -> Reply {
    let mut body = serde_json::to_vec(&envelope(
        RpcResponse::error(Value::Null, code, message),
        false,
    ))
    .unwrap();
    body.push(b'\n');
    Reply { status, body }
}

pub(crate) fn handle(handler: &RpcHandler, raw: &[u8]) -> Reply {
    let value: Value = match serde_json::from_slice(raw) {
        Ok(value) => value,
        Err(_) => return error_reply(500, PARSE_ERROR, "Parse error"),
    };
    let mut body = LimitedBody(Vec::new());
    let status;
    if let Value::Array(values) = value {
        if values.len() > MAX_BATCH {
            return error_reply(413, INVALID_REQUEST, "RPC batch exceeds operation limit");
        }
        // Core keeps [] for an empty legacy batch. Each member gets fresh
        // envelope state, so malformed members cannot reuse another ID/version.
        body.0.push(b'[');
        let nonempty = !values.is_empty();
        let mut replies = 0;
        for value in values {
            let (_, response) = execute(handler, value);
            if let Some(response) = response {
                if replies > 0 {
                    body.0.push(b',');
                }
                if serde_json::to_writer(&mut body, &response).is_err() {
                    return error_reply(
                        503,
                        INTERNAL_ERROR,
                        "RPC response exceeds budget; query a smaller batch",
                    );
                }
                replies += 1;
            }
        }
        if replies == 0 && nonempty {
            return Reply {
                status: 204,
                body: Vec::new(),
            };
        }
        if body.write_all(b"]\n").is_err() {
            return error_reply(503, INTERNAL_ERROR, "RPC response exceeds budget");
        }
        status = 200;
    } else if value.is_object() {
        let (code, response) = execute(handler, value);
        status = code;
        let Some(response) = response else {
            return Reply {
                status,
                body: Vec::new(),
            };
        };
        if serde_json::to_writer(&mut body, &response).is_err() || body.write_all(b"\n").is_err() {
            return error_reply(503, INTERNAL_ERROR, "RPC response exceeds budget");
        }
    } else {
        return error_reply(500, PARSE_ERROR, "Top-level object parse error");
    }
    Reply {
        status,
        body: body.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn versions_notifications_and_error_statuses_use_real_dispatch() {
        let mut handler = RpcHandler::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        handler.register("count", move |_| {
            json!(observed.fetch_add(1, Ordering::SeqCst))
        });
        for (raw, status, error, v2) in [
            (r#"{"method":"count","id":0}"#, 200, None, false),
            (
                r#"{"jsonrpc":"1.0","method":"missing","id":"legacy"}"#,
                404,
                Some(METHOD_NOT_FOUND),
                false,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"missing","id":null}"#,
                200,
                Some(METHOD_NOT_FOUND),
                true,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"count","params":{},"id":1}"#,
                200,
                Some(INVALID_PARAMS),
                true,
            ),
            (
                r#"{"method":"count","params":{},"id":1}"#,
                500,
                Some(INVALID_PARAMS),
                false,
            ),
        ] {
            let reply = handle(&handler, raw.as_bytes());
            assert_eq!(reply.status, status);
            let value: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(value.get("jsonrpc").is_some(), v2);
            if let Some(code) = error {
                assert_eq!(value["error"]["code"], code);
            }
            if !v2 {
                assert!(value.get("error").is_some() && value.get("result").is_some());
            }
        }
        let reply = handle(
            &handler,
            br#"[{"jsonrpc":"2.0","method":"count"},{"jsonrpc":"2.0","method":"missing"}]"#,
        );
        assert_eq!(reply.status, 204);
        assert!(reply.body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(handle(&handler, b"[]").body, b"[]\n");
        let reply = handle(
            &handler,
            br#"[{"jsonrpc":"2.0","method":"count","id":"a"},true,{"method":"missing","id":"b"}]"#,
        );
        let value: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(value[0]["id"], "a");
        assert_eq!(value[1]["id"], Value::Null);
        assert!(value[1].get("jsonrpc").is_none());
        assert_eq!(value[2]["id"], "b");
        assert_eq!(value[2]["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn batch_and_response_budgets_do_not_fabricate_results() {
        let mut handler = RpcHandler::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        handler.register("count", move |_| {
            json!(observed.fetch_add(1, Ordering::SeqCst))
        });
        let oversized = vec![json!({"jsonrpc":"2.0","method":"count","id":1}); MAX_BATCH + 1];
        assert_eq!(
            handle(&handler, &serde_json::to_vec(&oversized).unwrap()).status,
            413
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        handler.register("large", |_| json!("x".repeat(MAX_RESPONSE_BYTES)));
        let reply = handle(&handler, br#"{"method":"large","id":1}"#);
        assert_eq!(reply.status, 503);
        assert!(reply.body.len() < 1024);
        assert_eq!(
            handle(&handler, br#"{"method":"count","id":2}"#).status,
            200
        );
    }
}
