use serde::Serialize;
use std::io::{self, Write};

/// Output format for CLI responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text (default when TTY)
    Text,
    /// Machine-parseable JSON (default when piped, or --output json)
    Json,
}

impl OutputFormat {
    /// Auto-detect: JSON when stdout is not a TTY, text otherwise
    pub fn auto() -> Self {
        if atty_stdout() {
            OutputFormat::Text
        } else {
            OutputFormat::Json
        }
    }

    pub fn from_str_opt(s: Option<&str>) -> Self {
        match s {
            Some("json") => OutputFormat::Json,
            Some("text") => OutputFormat::Text,
            _ => Self::auto(),
        }
    }
}

/// Check if stdout is a TTY (simplified — no extra dep)
fn atty_stdout() -> bool {
    unsafe { libc_isatty(1) != 0 }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}

#[cfg(not(unix))]
fn libc_isatty(_fd: i32) -> i32 {
    0 // default to JSON on non-unix
}

/// Emit a structured response to stdout
pub fn emit<T: Serialize>(format: OutputFormat, value: &T) {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string(value).expect("serialization failed");
            println!("{}", json);
        }
        OutputFormat::Text => {
            // For text, try to pretty-print
            let json = serde_json::to_value(value).expect("serialization failed");
            print_value_as_text(&json, 0);
        }
    }
}

/// Emit a progress event to stderr (always JSON lines for machine consumption)
pub fn emit_progress(event: &str, data: &serde_json::Value) {
    let msg = serde_json::json!({
        "event": event,
        "data": data,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });
    eprintln!("{}", serde_json::to_string(&msg).unwrap());
}

/// Emit an error and exit.
///
/// Error output always goes to stderr so that stdout remains clean for piping.
/// When JSON format is active, a structured JSON error is also written to stdout
/// so that agents can parse it.
pub fn emit_error(format: OutputFormat, code: i32, message: &str) -> ! {
    match format {
        OutputFormat::Json => {
            // Structured error on stdout for machine consumption
            let err = serde_json::json!({
                "error": {
                    "code": code,
                    "message": message,
                }
            });
            let _ = writeln!(io::stdout(), "{}", serde_json::to_string(&err).unwrap());
            // Also log to stderr for humans watching the terminal
            eprintln!("error: {}", message);
        }
        OutputFormat::Text => {
            eprintln!("error: {}", message);
        }
    }
    std::process::exit(code);
}

fn print_value_as_text(value: &serde_json::Value, indent: usize) {
    let prefix = " ".repeat(indent);
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                match v {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        println!("{}{}:", prefix, k);
                        print_value_as_text(v, indent + 2);
                    }
                    _ => {
                        println!("{}{}: {}", prefix, k, format_scalar(v));
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                print_value_as_text(item, indent);
                println!();
            }
        }
        _ => {
            println!("{}{}", prefix, format_scalar(value));
        }
    }
}

fn format_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        _ => serde_json::to_string(v).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // OutputFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_output_format_from_str_json() {
        assert_eq!(OutputFormat::from_str_opt(Some("json")), OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_text() {
        assert_eq!(OutputFormat::from_str_opt(Some("text")), OutputFormat::Text);
    }

    #[test]
    fn test_output_format_from_str_none_auto() {
        // When piped (test environment) this should be Json
        let f = OutputFormat::from_str_opt(None);
        // In a test env, stdout is NOT a TTY, so auto should be Json
        assert_eq!(f, OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_unknown_auto() {
        let f = OutputFormat::from_str_opt(Some("xml"));
        // Unknown falls through to auto detect
        assert_eq!(f, OutputFormat::auto());
    }

    #[test]
    fn test_output_format_debug() {
        let _ = format!("{:?}", OutputFormat::Json);
        let _ = format!("{:?}", OutputFormat::Text);
    }

    #[test]
    fn test_output_format_clone_eq() {
        let a = OutputFormat::Json;
        let b = a;
        assert_eq!(a, b);

        let c = OutputFormat::Text;
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // format_scalar
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_scalar_string() {
        let v = serde_json::Value::String("hello".into());
        assert_eq!(format_scalar(&v), "hello");
    }

    #[test]
    fn test_format_scalar_number() {
        let v = serde_json::json!(42);
        assert_eq!(format_scalar(&v), "42");
    }

    #[test]
    fn test_format_scalar_float() {
        let v = serde_json::json!(3.14);
        assert_eq!(format_scalar(&v), "3.14");
    }

    #[test]
    fn test_format_scalar_bool_true() {
        let v = serde_json::json!(true);
        assert_eq!(format_scalar(&v), "true");
    }

    #[test]
    fn test_format_scalar_bool_false() {
        let v = serde_json::json!(false);
        assert_eq!(format_scalar(&v), "false");
    }

    #[test]
    fn test_format_scalar_null() {
        let v = serde_json::Value::Null;
        assert_eq!(format_scalar(&v), "null");
    }

    #[test]
    fn test_format_scalar_array() {
        let v = serde_json::json!([1, 2, 3]);
        // Arrays are not scalars, should fall through to JSON serialization
        let result = format_scalar(&v);
        assert!(result.contains("[1,2,3]"));
    }

    #[test]
    fn test_format_scalar_object() {
        let v = serde_json::json!({"a": 1});
        let result = format_scalar(&v);
        assert!(result.contains("\"a\""));
    }

    // -----------------------------------------------------------------------
    // emit (JSON mode)
    // -----------------------------------------------------------------------

    #[test]
    fn test_emit_json_serializes_struct() {
        // emit writes to stdout which we can't easily capture in tests,
        // but we can verify the serialization path doesn't panic
        let status = NodeStatus {
            network: "mainnet".into(),
            chain_height: 100,
            best_block_hash: "0".repeat(64),
            peer_count: 5,
            mempool_size: 10,
            syncing: false,
            sync_progress: 0.5,
            version: "0.1.0".into(),
        };
        // Verify it serializes without error
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["network"], "mainnet");
        assert_eq!(parsed["chain_height"], 100);
        assert_eq!(parsed["peer_count"], 5);
    }

    // -----------------------------------------------------------------------
    // emit_progress
    // -----------------------------------------------------------------------

    #[test]
    fn test_emit_progress_does_not_panic() {
        // emit_progress writes to stderr, just verify it doesn't panic
        emit_progress("test_event", &serde_json::json!({"key": "value"}));
    }

    // -----------------------------------------------------------------------
    // Response types serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_node_status_serialization() {
        let status = NodeStatus {
            network: "testnet".into(),
            chain_height: 42,
            best_block_hash: "abc".into(),
            peer_count: 3,
            mempool_size: 100,
            syncing: true,
            sync_progress: 0.75,
            version: "1.0".into(),
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["network"], "testnet");
        assert_eq!(json["chain_height"], 42);
        assert_eq!(json["syncing"], true);
        assert!((json["sync_progress"].as_f64().unwrap() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_peer_entry_serialization() {
        let peer = PeerEntry {
            addr: "127.0.0.1:8333".into(),
            version: 70016,
            user_agent: "/btc-rust:0.1.0/".into(),
            start_height: 800000,
            inbound: false,
        };
        let json = serde_json::to_value(&peer).unwrap();
        assert_eq!(json["addr"], "127.0.0.1:8333");
        assert_eq!(json["version"], 70016);
        assert_eq!(json["inbound"], false);
        assert_eq!(json["start_height"], 800000);
    }

    #[test]
    fn test_sync_status_serialization() {
        let sync = SyncStatus {
            syncing: true,
            current_height: 500,
            target_height: 1000,
            progress: 0.5,
            stage: "downloading_blocks".into(),
            peers: 8,
        };
        let json = serde_json::to_value(&sync).unwrap();
        assert_eq!(json["syncing"], true);
        assert_eq!(json["current_height"], 500);
        assert_eq!(json["target_height"], 1000);
        assert_eq!(json["stage"], "downloading_blocks");
        assert_eq!(json["peers"], 8);
    }

    // -----------------------------------------------------------------------
    // print_value_as_text (indirect testing via emit)
    // -----------------------------------------------------------------------

    #[test]
    fn test_print_value_as_text_object() {
        // Just verify it doesn't panic
        let v = serde_json::json!({
            "key": "value",
            "number": 42,
            "nested": {"inner": true},
            "array": [1, 2, 3],
        });
        print_value_as_text(&v, 0);
    }

    #[test]
    fn test_print_value_as_text_array() {
        let v = serde_json::json!([1, 2, 3]);
        print_value_as_text(&v, 0);
    }

    #[test]
    fn test_print_value_as_text_scalar() {
        print_value_as_text(&serde_json::json!("hello"), 0);
        print_value_as_text(&serde_json::json!(42), 0);
        print_value_as_text(&serde_json::json!(true), 0);
        print_value_as_text(&serde_json::json!(null), 0);
    }

    #[test]
    fn test_print_value_as_text_with_indent() {
        let v = serde_json::json!({"a": {"b": "c"}});
        print_value_as_text(&v, 4);
    }

    #[test]
    fn test_emit_json_mode() {
        let value = serde_json::json!({"test": true, "count": 42});
        // This writes to stdout. We can't capture it but verify no panic.
        emit(OutputFormat::Json, &value);
    }

    #[test]
    fn test_emit_text_mode() {
        let value = serde_json::json!({"test": true, "count": 42});
        emit(OutputFormat::Text, &value);
    }

    #[test]
    fn test_emit_text_mode_struct() {
        let status = NodeStatus {
            network: "mainnet".into(),
            chain_height: 0,
            best_block_hash: "abc".into(),
            peer_count: 0,
            mempool_size: 0,
            syncing: false,
            sync_progress: 0.0,
            version: "test".into(),
        };
        emit(OutputFormat::Text, &status);
    }

    #[test]
    fn test_emit_json_mode_struct() {
        let status = SyncStatus {
            syncing: true,
            current_height: 100,
            target_height: 200,
            progress: 0.5,
            stage: "downloading".into(),
            peers: 5,
        };
        emit(OutputFormat::Json, &status);
    }

    #[test]
    fn test_emit_text_mode_array() {
        let peers: Vec<PeerEntry> = vec![
            PeerEntry {
                addr: "127.0.0.1:8333".into(),
                version: 70016,
                user_agent: "/test/".into(),
                start_height: 0,
                inbound: false,
            },
        ];
        emit(OutputFormat::Text, &peers);
    }

    #[test]
    fn test_emit_json_mode_empty_array() {
        let peers: Vec<PeerEntry> = vec![];
        emit(OutputFormat::Json, &peers);
    }

    #[test]
    fn test_emit_progress_with_nested_data() {
        emit_progress(
            "block_validated",
            &serde_json::json!({
                "height": 100,
                "hash": "abc",
                "nested": {"inner": true},
            }),
        );
    }

    #[test]
    fn test_output_format_auto_in_test_env() {
        // In a test environment, stdout is typically not a TTY
        let f = OutputFormat::auto();
        assert_eq!(f, OutputFormat::Json);
    }
}

// Standard response types for CLI commands

#[derive(Serialize)]
pub struct NodeStatus {
    pub network: String,
    pub chain_height: u64,
    pub best_block_hash: String,
    pub peer_count: usize,
    pub mempool_size: usize,
    pub syncing: bool,
    pub sync_progress: f64,
    pub version: String,
}

#[derive(Serialize)]
pub struct PeerEntry {
    pub addr: String,
    pub version: u32,
    pub user_agent: String,
    pub start_height: i32,
    pub inbound: bool,
}

#[derive(Serialize)]
pub struct SyncStatus {
    pub syncing: bool,
    pub current_height: u64,
    pub target_height: u64,
    pub progress: f64,
    pub stage: String,
    pub peers: usize,
}
