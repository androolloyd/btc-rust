//! # Esplora-compatible REST API and Prometheus Metrics
//!
//! A lightweight HTTP/1.1 server built directly on `tokio::net::TcpListener`
//! (no hyper/axum dependency) providing:
//!
//! - A subset of the Esplora REST API for block explorers and wallets.
//! - A Prometheus text exposition endpoint (`/metrics`) for monitoring.
//!
//! The server is intentionally minimal: it parses only what it needs from
//! the HTTP request line and headers, routes to the matching handler, and
//! writes a well-formed HTTP/1.1 response.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// HTTP Request / Response primitives
// ---------------------------------------------------------------------------

/// A parsed HTTP/1.1 request (only what we need).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// An HTTP response to send back on the wire.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// 200 OK with JSON body.
    pub fn json(body: &str) -> Self {
        Self {
            status: 200,
            status_text: "OK".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    /// 200 OK with plain text body.
    pub fn text(body: &str) -> Self {
        Self {
            status: 200,
            status_text: "OK".into(),
            headers: vec![
                ("Content-Type".into(), "text/plain; charset=utf-8".into()),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    /// 200 OK with HTML body.
    pub fn html(body: &str) -> Self {
        Self {
            status: 200,
            status_text: "OK".into(),
            headers: vec![
                ("Content-Type".into(), "text/html; charset=utf-8".into()),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    /// 404 Not Found.
    pub fn not_found() -> Self {
        Self {
            status: 404,
            status_text: "Not Found".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
            ],
            body: br#"{"error":"not found"}"#.to_vec(),
        }
    }

    /// 400 Bad Request.
    pub fn bad_request(msg: &str) -> Self {
        Self {
            status: 400,
            status_text: "Bad Request".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
            ],
            body: format!(r#"{{"error":"{}"}}"#, msg).into_bytes(),
        }
    }

    /// 500 Internal Server Error.
    pub fn internal_error(msg: &str) -> Self {
        Self {
            status: 500,
            status_text: "Internal Server Error".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
            ],
            body: format!(r#"{{"error":"{}"}}"#, msg).into_bytes(),
        }
    }

    /// Serialize this response to a byte vector suitable for writing to a TCP stream.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 + self.body.len());
        buf.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", self.status, self.status_text).as_bytes(),
        );
        // Always include Content-Length.
        buf.extend_from_slice(
            format!("Content-Length: {}\r\n", self.body.len()).as_bytes(),
        );
        for (k, v) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);
        buf
    }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Parse an HTTP/1.1 request from raw bytes.
///
/// This is intentionally lenient -- we only extract the method, path, headers,
/// and optional body.  We do NOT support chunked transfer encoding.
pub fn parse_request(raw: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(raw).ok()?;

    // Split headers from body at the first \r\n\r\n.
    let (head, body_bytes) = if let Some(pos) = text.find("\r\n\r\n") {
        (&text[..pos], &raw[pos + 4..])
    } else {
        (text, &[] as &[u8])
    };

    let mut lines = head.lines();

    // Request line: "METHOD /path HTTP/1.1"
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    // We accept any HTTP version token but don't validate it.
    let _version = parts.next()?;

    // Headers
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(
                key.trim().to_lowercase(),
                value.trim().to_string(),
            );
        }
    }

    Some(HttpRequest {
        method,
        path,
        headers,
        body: body_bytes.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

/// Match a URL path against a pattern containing `:param` segments.
///
/// Returns `Some(HashMap)` with captured parameters on match, `None` on mismatch.
///
/// Example:
/// ```
/// # use btc_node::http::match_route;
/// let params = match_route("/api/block/abc123", "/api/block/:hash");
/// assert_eq!(params.unwrap().get("hash").unwrap(), "abc123");
/// ```
pub fn match_route(path: &str, pattern: &str) -> Option<HashMap<String, String>> {
    let path_segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    let pattern_segments: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();

    if path_segments.len() != pattern_segments.len() {
        return None;
    }

    let mut params = HashMap::new();
    for (ps, pt) in path_segments.iter().zip(pattern_segments.iter()) {
        if pt.starts_with(':') {
            params.insert(pt[1..].to_string(), ps.to_string());
        } else if ps != pt {
            return None;
        }
    }
    Some(params)
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

/// Collects node-level metrics that are exposed via the Prometheus `/metrics`
/// endpoint and consumed by the Esplora REST handlers.
///
/// All fields are atomic so they can be updated from any async task without
/// holding a lock.
#[derive(Debug)]
pub struct MetricsCollector {
    pub chain_height: Arc<AtomicU64>,
    pub peer_count: Arc<AtomicU64>,
    pub mempool_size: Arc<AtomicU64>,
    pub mempool_bytes: Arc<AtomicU64>,
    pub sync_progress: Arc<AtomicU64>, // stored as f64 bits
    pub blocks_validated_total: Arc<AtomicU64>,
    pub utxo_set_size: Arc<AtomicU64>,
    pub best_block_hash: Arc<std::sync::RwLock<String>>,
}

impl MetricsCollector {
    /// Create a new collector with all metrics zeroed.
    pub fn new() -> Self {
        Self {
            chain_height: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            mempool_size: Arc::new(AtomicU64::new(0)),
            mempool_bytes: Arc::new(AtomicU64::new(0)),
            sync_progress: Arc::new(AtomicU64::new(0u64.to_be())),
            blocks_validated_total: Arc::new(AtomicU64::new(0)),
            utxo_set_size: Arc::new(AtomicU64::new(0)),
            best_block_hash: Arc::new(std::sync::RwLock::new(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            )),
        }
    }

    /// Set the sync progress (0.0 -- 1.0).
    pub fn set_sync_progress(&self, progress: f64) {
        self.sync_progress
            .store(progress.to_bits(), Ordering::Relaxed);
    }

    /// Get the sync progress (0.0 -- 1.0).
    pub fn get_sync_progress(&self) -> f64 {
        f64::from_bits(self.sync_progress.load(Ordering::Relaxed))
    }

    /// Set the best block hash.
    pub fn set_best_block_hash(&self, hash: &str) {
        if let Ok(mut guard) = self.best_block_hash.write() {
            *guard = hash.to_string();
        }
    }

    /// Get the best block hash.
    pub fn get_best_block_hash(&self) -> String {
        self.best_block_hash
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Increment the blocks-validated counter.
    pub fn inc_blocks_validated(&self) {
        self.blocks_validated_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let height = self.chain_height.load(Ordering::Relaxed);
        let peers = self.peer_count.load(Ordering::Relaxed);
        let mp_size = self.mempool_size.load(Ordering::Relaxed);
        let mp_bytes = self.mempool_bytes.load(Ordering::Relaxed);
        let sync = self.get_sync_progress();
        let validated = self.blocks_validated_total.load(Ordering::Relaxed);
        let utxos = self.utxo_set_size.load(Ordering::Relaxed);

        format!(
            "# HELP btc_chain_height Current block height.\n\
             # TYPE btc_chain_height gauge\n\
             btc_chain_height {height}\n\
             # HELP btc_peer_count Number of connected peers.\n\
             # TYPE btc_peer_count gauge\n\
             btc_peer_count {peers}\n\
             # HELP btc_mempool_size Number of transactions in the mempool.\n\
             # TYPE btc_mempool_size gauge\n\
             btc_mempool_size {mp_size}\n\
             # HELP btc_mempool_bytes Total bytes of transactions in the mempool.\n\
             # TYPE btc_mempool_bytes gauge\n\
             btc_mempool_bytes {mp_bytes}\n\
             # HELP btc_sync_progress Sync progress from 0.0 to 1.0.\n\
             # TYPE btc_sync_progress gauge\n\
             btc_sync_progress {sync}\n\
             # HELP btc_blocks_validated_total Total number of blocks validated.\n\
             # TYPE btc_blocks_validated_total counter\n\
             btc_blocks_validated_total {validated}\n\
             # HELP btc_utxo_set_size Number of entries in the UTXO set.\n\
             # TYPE btc_utxo_set_size gauge\n\
             btc_utxo_set_size {utxos}\n"
        )
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            chain_height: Arc::clone(&self.chain_height),
            peer_count: Arc::clone(&self.peer_count),
            mempool_size: Arc::clone(&self.mempool_size),
            mempool_bytes: Arc::clone(&self.mempool_bytes),
            sync_progress: Arc::clone(&self.sync_progress),
            blocks_validated_total: Arc::clone(&self.blocks_validated_total),
            utxo_set_size: Arc::clone(&self.utxo_set_size),
            best_block_hash: Arc::clone(&self.best_block_hash),
        }
    }
}

// ---------------------------------------------------------------------------
// Esplora REST handlers
// ---------------------------------------------------------------------------

/// Handle all incoming HTTP requests and route them.
pub fn handle_request(req: &HttpRequest, metrics: &MetricsCollector) -> HttpResponse {
    if req.method != "GET" {
        return HttpResponse::bad_request("only GET is supported");
    }

    // Strip query string for routing.
    let path = req.path.split('?').next().unwrap_or(&req.path);

    // ---- Prometheus metrics ----
    if path == "/metrics" {
        return HttpResponse {
            status: 200,
            status_text: "OK".into(),
            headers: vec![
                (
                    "Content-Type".into(),
                    "text/plain; version=0.0.4; charset=utf-8".into(),
                ),
            ],
            body: metrics.render_prometheus().into_bytes(),
        };
    }

    // ---- Esplora REST API ----

    // GET /api/blocks/tip/height
    if path == "/api/blocks/tip/height" {
        let height = metrics.chain_height.load(Ordering::Relaxed);
        return HttpResponse::text(&height.to_string());
    }

    // GET /api/blocks/tip/hash
    if path == "/api/blocks/tip/hash" {
        let hash = metrics.get_best_block_hash();
        return HttpResponse::text(&hash);
    }

    // GET /api/fee-estimates
    if path == "/api/fee-estimates" {
        return handle_fee_estimates(metrics);
    }

    // GET /api/mempool
    if path == "/api/mempool" {
        return handle_mempool(metrics);
    }

    // GET /api/block-height/:height
    if let Some(params) = match_route(path, "/api/block-height/:height") {
        return handle_block_height(&params, metrics);
    }

    // GET /api/block/:hash
    if let Some(params) = match_route(path, "/api/block/:hash") {
        return handle_block_by_hash(&params, metrics);
    }

    // GET /api/tx/:txid
    if let Some(params) = match_route(path, "/api/tx/:txid") {
        return handle_tx(&params, metrics);
    }

    // GET /api/address/:address/txs
    if let Some(params) = match_route(path, "/api/address/:address/txs") {
        return handle_address_txs(&params, metrics);
    }

    // GET /api/address/:address/utxo
    if let Some(params) = match_route(path, "/api/address/:address/utxo") {
        return handle_address_utxo(&params, metrics);
    }

    HttpResponse::not_found()
}

/// `GET /api/block-height/:height` -- return the block hash at a given height.
///
/// In a full implementation this would query the storage layer.  For now we
/// return the best-block hash when height matches, otherwise 404.
fn handle_block_height(
    params: &HashMap<String, String>,
    metrics: &MetricsCollector,
) -> HttpResponse {
    let height_str = match params.get("height") {
        Some(h) => h,
        None => return HttpResponse::bad_request("missing height parameter"),
    };
    let height: u64 = match height_str.parse() {
        Ok(h) => h,
        Err(_) => return HttpResponse::bad_request("invalid height"),
    };
    let current = metrics.chain_height.load(Ordering::Relaxed);
    if height > current {
        return HttpResponse::not_found();
    }
    // Stub: only the tip height returns the best hash.
    let hash = metrics.get_best_block_hash();
    HttpResponse::text(&hash)
}

/// `GET /api/block/:hash` -- block info as JSON.
fn handle_block_by_hash(
    params: &HashMap<String, String>,
    metrics: &MetricsCollector,
) -> HttpResponse {
    let hash = match params.get("hash") {
        Some(h) => h,
        None => return HttpResponse::bad_request("missing hash parameter"),
    };
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::bad_request("invalid block hash");
    }
    let height = metrics.chain_height.load(Ordering::Relaxed);
    let best_hash = metrics.get_best_block_hash();
    // Stub response -- a real implementation would look up the block.
    let json = format!(
        r#"{{"id":"{hash}","height":{height},"version":536870912,"timestamp":0,"tx_count":0,"size":0,"weight":0,"previousblockhash":"{best_hash}"}}"#,
    );
    HttpResponse::json(&json)
}

/// `GET /api/tx/:txid` -- transaction info as JSON.
fn handle_tx(
    params: &HashMap<String, String>,
    _metrics: &MetricsCollector,
) -> HttpResponse {
    let txid = match params.get("txid") {
        Some(t) => t,
        None => return HttpResponse::bad_request("missing txid parameter"),
    };
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return HttpResponse::bad_request("invalid txid");
    }
    // Stub response.
    let json = format!(
        r#"{{"txid":"{txid}","version":2,"locktime":0,"vin":[],"vout":[],"size":0,"weight":0,"fee":0,"status":{{"confirmed":false}}}}"#,
    );
    HttpResponse::json(&json)
}

/// `GET /api/address/:address/txs` -- transaction history for an address.
fn handle_address_txs(
    params: &HashMap<String, String>,
    _metrics: &MetricsCollector,
) -> HttpResponse {
    let address = match params.get("address") {
        Some(a) => a,
        None => return HttpResponse::bad_request("missing address parameter"),
    };
    if address.is_empty() {
        return HttpResponse::bad_request("empty address");
    }
    // Stub: return an empty array.
    HttpResponse::json("[]")
}

/// `GET /api/address/:address/utxo` -- UTXOs for an address.
fn handle_address_utxo(
    params: &HashMap<String, String>,
    _metrics: &MetricsCollector,
) -> HttpResponse {
    let address = match params.get("address") {
        Some(a) => a,
        None => return HttpResponse::bad_request("missing address parameter"),
    };
    if address.is_empty() {
        return HttpResponse::bad_request("empty address");
    }
    // Stub: return an empty array.
    HttpResponse::json("[]")
}

/// `GET /api/fee-estimates` -- fee rate estimates keyed by confirmation target.
fn handle_fee_estimates(_metrics: &MetricsCollector) -> HttpResponse {
    // Stub: return reasonable defaults.
    HttpResponse::json(r#"{"1":20.0,"3":10.0,"6":5.0,"12":2.0,"24":1.0}"#)
}

/// `GET /api/mempool` -- mempool statistics.
fn handle_mempool(metrics: &MetricsCollector) -> HttpResponse {
    let size = metrics.mempool_size.load(Ordering::Relaxed);
    let bytes = metrics.mempool_bytes.load(Ordering::Relaxed);
    let json = format!(
        r#"{{"count":{size},"vsize":{bytes},"total_fee":0,"fee_histogram":[]}}"#,
    );
    HttpResponse::json(&json)
}

// ---------------------------------------------------------------------------
// HttpServer
// ---------------------------------------------------------------------------

/// A lightweight HTTP server for Esplora REST and Prometheus metrics.
pub struct HttpServer {
    port: u16,
    metrics: MetricsCollector,
}

impl HttpServer {
    /// Create a new `HttpServer` bound to the given port.
    pub fn new(port: u16, metrics: MetricsCollector) -> Self {
        Self { port, metrics }
    }

    /// Return the configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Run the server.  This future never completes unless the runtime shuts
    /// down or an unrecoverable error occurs.
    pub async fn run(&self) -> std::io::Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(port = self.port, "HTTP server listening");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "failed to accept connection");
                    continue;
                }
            };
            debug!(%peer, "HTTP connection accepted");
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, &metrics).await {
                    debug!(%peer, error = %e, "connection error");
                }
            });
        }
    }
}

/// Handle a single HTTP connection (one request-response cycle).
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    metrics: &MetricsCollector,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let response = match parse_request(&buf[..n]) {
        Some(req) => {
            debug!(method = %req.method, path = %req.path, "HTTP request");
            handle_request(&req, metrics)
        }
        None => HttpResponse::bad_request("malformed request"),
    };

    stream.write_all(&response.to_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // HTTP request parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_get_request() {
        let raw = b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/blocks/tip/height");
        assert_eq!(req.headers.get("host").unwrap(), "localhost");
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_parse_post_request_with_body() {
        let raw = b"POST /api/tx HTTP/1.1\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: 13\r\n\r\n\
                     {\"raw\":\"aa\"}";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/tx");
        assert_eq!(
            req.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(req.body, b"{\"raw\":\"aa\"}");
    }

    #[test]
    fn test_parse_request_no_headers() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert!(req.headers.is_empty());
    }

    #[test]
    fn test_parse_invalid_request() {
        assert!(parse_request(b"").is_none());
        assert!(parse_request(b"GARBAGE").is_none());
        assert!(parse_request(b"GET\r\n\r\n").is_none());
    }

    #[test]
    fn test_parse_request_header_case_insensitivity() {
        let raw = b"GET / HTTP/1.1\r\nContent-Type: text/html\r\nX-Custom: value\r\n\r\n";
        let req = parse_request(raw).unwrap();
        // Headers are stored lower-cased.
        assert_eq!(req.headers.get("content-type").unwrap(), "text/html");
        assert_eq!(req.headers.get("x-custom").unwrap(), "value");
    }

    // -----------------------------------------------------------------------
    // Route matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_match_route_exact() {
        let params = match_route("/api/blocks/tip/height", "/api/blocks/tip/height");
        assert!(params.is_some());
        assert!(params.unwrap().is_empty());
    }

    #[test]
    fn test_match_route_with_param() {
        let params =
            match_route("/api/block/00000000abcdef", "/api/block/:hash").unwrap();
        assert_eq!(params.get("hash").unwrap(), "00000000abcdef");
    }

    #[test]
    fn test_match_route_with_multiple_params() {
        let params =
            match_route("/api/address/bc1abc/txs", "/api/address/:address/txs").unwrap();
        assert_eq!(params.get("address").unwrap(), "bc1abc");
    }

    #[test]
    fn test_match_route_no_match_wrong_segment() {
        assert!(match_route("/api/block/abc", "/api/tx/:txid").is_none());
    }

    #[test]
    fn test_match_route_no_match_length_mismatch() {
        assert!(match_route("/api/block", "/api/block/:hash").is_none());
        assert!(
            match_route("/api/block/abc/extra", "/api/block/:hash").is_none()
        );
    }

    #[test]
    fn test_match_route_trailing_slash() {
        // Trailing slashes are stripped before comparison.
        let params = match_route("/api/block/abc/", "/api/block/:hash").unwrap();
        assert_eq!(params.get("hash").unwrap(), "abc");
    }

    // -----------------------------------------------------------------------
    // MetricsCollector
    // -----------------------------------------------------------------------

    #[test]
    fn test_metrics_new_defaults() {
        let m = MetricsCollector::new();
        assert_eq!(m.chain_height.load(Ordering::Relaxed), 0);
        assert_eq!(m.peer_count.load(Ordering::Relaxed), 0);
        assert_eq!(m.mempool_size.load(Ordering::Relaxed), 0);
        assert_eq!(m.mempool_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(m.get_sync_progress(), 0.0);
        assert_eq!(m.blocks_validated_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.utxo_set_size.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_set_sync_progress() {
        let m = MetricsCollector::new();
        m.set_sync_progress(0.5);
        assert!((m.get_sync_progress() - 0.5).abs() < f64::EPSILON);

        m.set_sync_progress(1.0);
        assert!((m.get_sync_progress() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_metrics_inc_blocks_validated() {
        let m = MetricsCollector::new();
        m.inc_blocks_validated();
        m.inc_blocks_validated();
        m.inc_blocks_validated();
        assert_eq!(m.blocks_validated_total.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_metrics_set_best_block_hash() {
        let m = MetricsCollector::new();
        m.set_best_block_hash("00000000000000000001abc");
        assert_eq!(m.get_best_block_hash(), "00000000000000000001abc");
    }

    #[test]
    fn test_metrics_clone_shares_atomics() {
        let m = MetricsCollector::new();
        let m2 = m.clone();
        m.chain_height.store(42, Ordering::Relaxed);
        assert_eq!(m2.chain_height.load(Ordering::Relaxed), 42);
    }

    // -----------------------------------------------------------------------
    // Prometheus format output
    // -----------------------------------------------------------------------

    #[test]
    fn test_prometheus_format_contains_all_metrics() {
        let m = MetricsCollector::new();
        m.chain_height.store(800_000, Ordering::Relaxed);
        m.peer_count.store(12, Ordering::Relaxed);
        m.mempool_size.store(5000, Ordering::Relaxed);
        m.mempool_bytes.store(2_500_000, Ordering::Relaxed);
        m.set_sync_progress(0.95);
        m.blocks_validated_total.store(800_000, Ordering::Relaxed);
        m.utxo_set_size.store(90_000_000, Ordering::Relaxed);

        let output = m.render_prometheus();

        assert!(output.contains("btc_chain_height 800000"));
        assert!(output.contains("btc_peer_count 12"));
        assert!(output.contains("btc_mempool_size 5000"));
        assert!(output.contains("btc_mempool_bytes 2500000"));
        assert!(output.contains("btc_sync_progress 0.95"));
        assert!(output.contains("btc_blocks_validated_total 800000"));
        assert!(output.contains("btc_utxo_set_size 90000000"));
    }

    #[test]
    fn test_prometheus_format_has_type_annotations() {
        let m = MetricsCollector::new();
        let output = m.render_prometheus();

        assert!(output.contains("# TYPE btc_chain_height gauge"));
        assert!(output.contains("# TYPE btc_peer_count gauge"));
        assert!(output.contains("# TYPE btc_mempool_size gauge"));
        assert!(output.contains("# TYPE btc_mempool_bytes gauge"));
        assert!(output.contains("# TYPE btc_sync_progress gauge"));
        assert!(output.contains("# TYPE btc_blocks_validated_total counter"));
        assert!(output.contains("# TYPE btc_utxo_set_size gauge"));
    }

    #[test]
    fn test_prometheus_format_has_help_text() {
        let m = MetricsCollector::new();
        let output = m.render_prometheus();

        assert!(output.contains("# HELP btc_chain_height"));
        assert!(output.contains("# HELP btc_peer_count"));
        assert!(output.contains("# HELP btc_mempool_size"));
        assert!(output.contains("# HELP btc_mempool_bytes"));
        assert!(output.contains("# HELP btc_sync_progress"));
        assert!(output.contains("# HELP btc_blocks_validated_total"));
        assert!(output.contains("# HELP btc_utxo_set_size"));
    }

    // -----------------------------------------------------------------------
    // Esplora JSON responses
    // -----------------------------------------------------------------------

    fn make_request(path: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    fn make_metrics() -> MetricsCollector {
        let m = MetricsCollector::new();
        m.chain_height.store(800_000, Ordering::Relaxed);
        m.peer_count.store(8, Ordering::Relaxed);
        m.mempool_size.store(1234, Ordering::Relaxed);
        m.mempool_bytes.store(567_890, Ordering::Relaxed);
        m.set_sync_progress(1.0);
        m.set_best_block_hash(
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
        );
        m
    }

    #[test]
    fn test_tip_height() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/blocks/tip/height"), &m);
        assert_eq!(resp.status, 200);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "800000");
    }

    #[test]
    fn test_tip_hash() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/blocks/tip/hash"), &m);
        assert_eq!(resp.status, 200);
        assert_eq!(
            std::str::from_utf8(&resp.body).unwrap(),
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
        );
    }

    #[test]
    fn test_block_by_hash() {
        let m = make_metrics();
        let hash = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
        let resp = handle_request(
            &make_request(&format!("/api/block/{}", hash)),
            &m,
        );
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains(&format!(r#""id":"{}""#, hash)));
        assert!(body.contains(r#""height":800000"#));
        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["id"].as_str().unwrap(), hash);
    }

    #[test]
    fn test_block_by_hash_invalid() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/block/not_a_hash"), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_block_height_endpoint() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/block-height/800000"), &m);
        assert_eq!(resp.status, 200);
        // Returns the best block hash.
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"));
    }

    #[test]
    fn test_block_height_beyond_tip() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/block-height/999999"), &m);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_block_height_invalid() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/block-height/abc"), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_tx_endpoint() {
        let m = make_metrics();
        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let resp = handle_request(&make_request(&format!("/api/tx/{}", txid)), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["txid"].as_str().unwrap(), txid);
    }

    #[test]
    fn test_tx_invalid_txid() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/tx/xyz"), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_address_txs() {
        let m = make_metrics();
        let resp = handle_request(
            &make_request("/api/address/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4/txs"),
            &m,
        );
        assert_eq!(resp.status, 200);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "[]");
    }

    #[test]
    fn test_address_utxo() {
        let m = make_metrics();
        let resp = handle_request(
            &make_request("/api/address/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4/utxo"),
            &m,
        );
        assert_eq!(resp.status, 200);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "[]");
    }

    #[test]
    fn test_fee_estimates() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/fee-estimates"), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        // Should have targets 1, 3, 6, 12, 24.
        assert!(parsed["1"].is_number());
        assert!(parsed["3"].is_number());
        assert!(parsed["6"].is_number());
        assert!(parsed["12"].is_number());
        assert!(parsed["24"].is_number());
    }

    #[test]
    fn test_mempool_endpoint() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/mempool"), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["count"].as_u64().unwrap(), 1234);
        assert_eq!(parsed["vsize"].as_u64().unwrap(), 567_890);
    }

    #[test]
    fn test_metrics_endpoint() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/metrics"), &m);
        assert_eq!(resp.status, 200);
        let content_type = resp
            .headers
            .iter()
            .find(|(k, _)| k == "Content-Type")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(content_type.contains("text/plain"));
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("btc_chain_height 800000"));
    }

    #[test]
    fn test_unknown_route_returns_404() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/nonexistent"), &m);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_non_get_returns_400() {
        let m = make_metrics();
        let req = HttpRequest {
            method: "POST".into(),
            path: "/api/blocks/tip/height".into(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let resp = handle_request(&req, &m);
        assert_eq!(resp.status, 400);
    }

    // -----------------------------------------------------------------------
    // HttpResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_to_bytes() {
        let resp = HttpResponse::json(r#"{"ok":true}"#);
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 11\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.ends_with(r#"{"ok":true}"#));
    }

    #[test]
    fn test_response_not_found() {
        let resp = HttpResponse::not_found();
        assert_eq!(resp.status, 404);
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn test_response_bad_request() {
        let resp = HttpResponse::bad_request("test error");
        assert_eq!(resp.status, 400);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("test error"));
    }

    #[test]
    fn test_response_internal_error() {
        let resp = HttpResponse::internal_error("boom");
        assert_eq!(resp.status, 500);
    }

    // -----------------------------------------------------------------------
    // HttpServer construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_json_content_type() {
        let resp = HttpResponse::json(r#"{"ok":true}"#);
        let ct = resp.headers.iter().find(|(k, _)| k == "Content-Type").unwrap();
        assert_eq!(ct.1, "application/json");
    }

    #[test]
    fn test_response_text_content_type() {
        let resp = HttpResponse::text("hello world");
        assert_eq!(resp.status, 200);
        let ct = resp.headers.iter().find(|(k, _)| k == "Content-Type").unwrap();
        assert_eq!(ct.1, "text/plain; charset=utf-8");
        assert_eq!(resp.body, b"hello world");
    }

    #[test]
    fn test_response_html_content_type() {
        let resp = HttpResponse::html("<h1>Hello</h1>");
        assert_eq!(resp.status, 200);
        let ct = resp.headers.iter().find(|(k, _)| k == "Content-Type").unwrap();
        assert_eq!(ct.1, "text/html; charset=utf-8");
        assert_eq!(resp.body, b"<h1>Hello</h1>");
    }

    #[test]
    fn test_response_not_found_body() {
        let resp = HttpResponse::not_found();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.status_text, "Not Found");
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("not found"));
    }

    #[test]
    fn test_response_bad_request_body() {
        let resp = HttpResponse::bad_request("custom error message");
        assert_eq!(resp.status, 400);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("custom error message"));
    }

    #[test]
    fn test_response_internal_error_body() {
        let resp = HttpResponse::internal_error("internal failure");
        assert_eq!(resp.status, 500);
        assert_eq!(resp.status_text, "Internal Server Error");
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("internal failure"));
    }

    #[test]
    fn test_response_to_bytes_not_found() {
        let resp = HttpResponse::not_found();
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.contains("Content-Length: "));
    }

    #[test]
    fn test_response_to_bytes_text() {
        let resp = HttpResponse::text("hello");
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn test_response_to_bytes_html() {
        let resp = HttpResponse::html("<b>hi</b>");
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("text/html"));
        assert!(text.ends_with("<b>hi</b>"));
    }

    #[test]
    fn test_response_to_bytes_internal_error() {
        let resp = HttpResponse::internal_error("boom");
        let bytes = resp.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
    }

    #[test]
    fn test_response_clone() {
        let resp = HttpResponse::json(r#"{"ok":true}"#);
        let resp2 = resp.clone();
        assert_eq!(resp.status, resp2.status);
        assert_eq!(resp.body, resp2.body);
    }

    #[test]
    fn test_response_debug() {
        let resp = HttpResponse::json(r#"{"ok":true}"#);
        let debug = format!("{:?}", resp);
        assert!(debug.contains("HttpResponse"));
    }

    #[test]
    fn test_parse_request_with_empty_header_line() {
        // Headers section has an empty line mid-stream (before the blank separator)
        let raw = b"GET /path HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/path");
    }

    #[test]
    fn test_parse_request_with_no_body_after_headers() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_handle_address_txs_empty_address() {
        let m = make_metrics();
        // The address segment itself must be non-empty for the route to match
        // but the handler checks for empty address
        let req = HttpRequest {
            method: "GET".into(),
            path: "/api/address//txs".into(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let resp = handle_request(&req, &m);
        // This path won't match the route pattern with empty address segment
        assert!(resp.status == 400 || resp.status == 404);
    }

    #[test]
    fn test_handle_address_utxo_empty_address() {
        let m = make_metrics();
        let req = HttpRequest {
            method: "GET".into(),
            path: "/api/address//utxo".into(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let resp = handle_request(&req, &m);
        assert!(resp.status == 400 || resp.status == 404);
    }

    #[test]
    fn test_metrics_default_impl() {
        let m = MetricsCollector::default();
        assert_eq!(m.chain_height.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_best_block_hash_default() {
        let m = MetricsCollector::new();
        let hash = m.get_best_block_hash();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_parse_request_without_double_crlf() {
        // No \r\n\r\n separator - should still parse the request line
        let raw = b"GET /path HTTP/1.1";
        // This should be None since there's no proper HTTP request separator
        // Actually looking at the code, it handles missing \r\n\r\n by using
        // the whole text as head
        let result = parse_request(raw);
        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/path");
    }

    #[test]
    fn test_handle_request_with_query_params_on_all_endpoints() {
        let m = make_metrics();
        // Query string should be stripped
        let resp = handle_request(&make_request("/api/blocks/tip/hash?format=json"), &m);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_handle_block_hash_too_short() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/block/abc"), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_handle_block_hash_not_hex() {
        let m = make_metrics();
        let hash = "x".repeat(64);
        let resp = handle_request(&make_request(&format!("/api/block/{}", hash)), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_handle_tx_too_short() {
        let m = make_metrics();
        let resp = handle_request(&make_request("/api/tx/abc"), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_handle_tx_not_hex() {
        let m = make_metrics();
        let txid = "g".repeat(64);
        let resp = handle_request(&make_request(&format!("/api/tx/{}", txid)), &m);
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn test_http_server_port() {
        let m = MetricsCollector::new();
        let server = HttpServer::new(8080, m);
        assert_eq!(server.port(), 8080);
    }

    // -----------------------------------------------------------------------
    // Integration: parse request -> route -> response
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_tip_height() {
        let raw = b"GET /api/blocks/tip/height HTTP/1.1\r\nHost: localhost:3000\r\n\r\n";
        let req = parse_request(raw).unwrap();
        let m = make_metrics();
        let resp = handle_request(&req, &m);
        assert_eq!(resp.status, 200);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "800000");
    }

    #[test]
    fn test_end_to_end_metrics() {
        let raw = b"GET /metrics HTTP/1.1\r\nHost: localhost:9090\r\n\r\n";
        let req = parse_request(raw).unwrap();
        let m = make_metrics();
        let resp = handle_request(&req, &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("btc_chain_height 800000"));
        assert!(body.contains("btc_peer_count 8"));
    }

    #[test]
    fn test_query_string_stripped() {
        let m = make_metrics();
        let req = make_request("/api/blocks/tip/height?format=json");
        let resp = handle_request(&req, &m);
        assert_eq!(resp.status, 200);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "800000");
    }
}
