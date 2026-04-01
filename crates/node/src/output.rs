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
