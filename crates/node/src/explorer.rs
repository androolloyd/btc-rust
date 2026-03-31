//! # Block Explorer
//!
//! A minimal HTML block explorer served directly from the node. It uses the
//! existing Esplora REST API endpoints (served by [`crate::http::HttpServer`])
//! as the data backend and renders a dark-themed UI with search, stats, and
//! block/transaction detail pages.
//!
//! The explorer listens on a configurable port (default 3000) and proxies
//! `/api/*` requests to the Esplora REST handlers so the frontend JavaScript
//! can fetch data without CORS issues.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::http::{parse_request, HttpRequest, HttpResponse, MetricsCollector};

// ---------------------------------------------------------------------------
// HTML Templates
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>btc-rust Explorer</title>
    <style>
        body { font-family: monospace; max-width: 900px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        a { color: #0f9; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .block { border: 1px solid #333; padding: 10px; margin: 5px 0; border-radius: 4px; }
        .tx { border-left: 2px solid #0f9; padding-left: 10px; margin: 5px 0; }
        input { background: #222; color: #fff; border: 1px solid #444; padding: 8px; width: 100%; font-family: monospace; }
        h1 { color: #0f9; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-value { font-size: 24px; color: #0f9; }
        .stat-label { font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <h1>btc-rust explorer</h1>
    <div>
        <input type="text" id="search" placeholder="Search by block hash, txid, or address..." onkeypress="if(event.key==='Enter')search()">
    </div>
    <div id="stats"></div>
    <div id="content"></div>
    <script>
        async function loadStats() {
            const height = await (await fetch('/api/blocks/tip/height')).text();
            const hash = await (await fetch('/api/blocks/tip/hash')).text();
            const mempool = await (await fetch('/api/mempool')).json();
            document.getElementById('stats').innerHTML = `
                <div class="stat"><div class="stat-value">${height}</div><div class="stat-label">Block Height</div></div>
                <div class="stat"><div class="stat-value">${mempool.count || 0}</div><div class="stat-label">Mempool TXs</div></div>
            `;
        }
        async function search() {
            const q = document.getElementById('search').value.trim();
            // Try as block hash, then txid, then height
            if (q.length === 64) {
                // Could be block hash or txid
                let resp = await fetch('/api/block/' + q);
                if (resp.ok) { showBlock(await resp.json()); return; }
                resp = await fetch('/api/tx/' + q);
                if (resp.ok) { showTx(await resp.json()); return; }
            }
            if (/^\d+$/.test(q)) {
                let resp = await fetch('/api/block-height/' + q);
                if (resp.ok) {
                    const hash = await resp.text();
                    let block = await (await fetch('/api/block/' + hash)).json();
                    showBlock(block); return;
                }
            }
            document.getElementById('content').innerHTML = '<p>Not found</p>';
        }
        function showBlock(b) {
            document.getElementById('content').innerHTML = `
                <div class="block">
                    <h3>Block ${b.height || '?'}</h3>
                    <p>Hash: ${b.id || b.hash || '?'}</p>
                    <p>Time: ${new Date((b.timestamp || b.time || 0) * 1000).toISOString()}</p>
                    <p>Transactions: ${b.tx_count || '?'}</p>
                </div>
            `;
        }
        function showTx(t) {
            document.getElementById('content').innerHTML = `
                <div class="tx">
                    <h3>Transaction</h3>
                    <p>TXID: ${t.txid || '?'}</p>
                    <p>Size: ${t.size || '?'} bytes</p>
                </div>
            `;
        }
        loadStats();
    </script>
</body>
</html>"#;

/// HTML template for a block detail page, rendered server-side.
const BLOCK_DETAIL_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Block - btc-rust Explorer</title>
    <style>
        body { font-family: monospace; max-width: 900px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        a { color: #0f9; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .block { border: 1px solid #333; padding: 10px; margin: 5px 0; border-radius: 4px; }
        h1 { color: #0f9; }
        .field { margin: 8px 0; }
        .label { color: #888; }
    </style>
</head>
<body>
    <h1><a href="/">btc-rust explorer</a></h1>
    <div class="block">
        <h2>Block</h2>
        <div class="field"><span class="label">Hash:</span> {{hash}}</div>
    </div>
    <script>
        (async () => {
            const resp = await fetch('/api/block/{{hash}}');
            if (!resp.ok) return;
            const b = await resp.json();
            document.querySelector('.block').innerHTML = `
                <h2>Block ${b.height || '?'}</h2>
                <div class="field"><span class="label">Hash:</span> ${b.id || '?'}</div>
                <div class="field"><span class="label">Height:</span> ${b.height || '?'}</div>
                <div class="field"><span class="label">Time:</span> ${new Date((b.timestamp || 0) * 1000).toISOString()}</div>
                <div class="field"><span class="label">TX Count:</span> ${b.tx_count || '?'}</div>
                <div class="field"><span class="label">Size:</span> ${b.size || '?'} bytes</div>
                <div class="field"><span class="label">Weight:</span> ${b.weight || '?'} WU</div>
                <div class="field"><span class="label">Version:</span> ${b.version || '?'}</div>
                <div class="field"><span class="label">Previous:</span> <a href="/block/${b.previousblockhash}">${b.previousblockhash || '?'}</a></div>
            `;
        })();
    </script>
</body>
</html>"#;

/// HTML template for a transaction detail page, rendered server-side.
const TX_DETAIL_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Transaction - btc-rust Explorer</title>
    <style>
        body { font-family: monospace; max-width: 900px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        a { color: #0f9; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .tx { border-left: 2px solid #0f9; padding-left: 10px; margin: 5px 0; }
        h1 { color: #0f9; }
        .field { margin: 8px 0; }
        .label { color: #888; }
    </style>
</head>
<body>
    <h1><a href="/">btc-rust explorer</a></h1>
    <div class="tx">
        <h2>Transaction</h2>
        <div class="field"><span class="label">TXID:</span> {{txid}}</div>
    </div>
    <script>
        (async () => {
            const resp = await fetch('/api/tx/{{txid}}');
            if (!resp.ok) return;
            const t = await resp.json();
            document.querySelector('.tx').innerHTML = `
                <h2>Transaction</h2>
                <div class="field"><span class="label">TXID:</span> ${t.txid || '?'}</div>
                <div class="field"><span class="label">Size:</span> ${t.size || '?'} bytes</div>
                <div class="field"><span class="label">Weight:</span> ${t.weight || '?'} WU</div>
                <div class="field"><span class="label">Fee:</span> ${t.fee || '?'} sat</div>
                <div class="field"><span class="label">Version:</span> ${t.version || '?'}</div>
                <div class="field"><span class="label">Locktime:</span> ${t.locktime || '?'}</div>
                <div class="field"><span class="label">Status:</span> ${t.status && t.status.confirmed ? 'Confirmed' : 'Unconfirmed'}</div>
            `;
        })();
    </script>
</body>
</html>"#;

// ---------------------------------------------------------------------------
// Route matching for explorer paths
// ---------------------------------------------------------------------------

/// The result of matching an incoming request path against the explorer routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorerRoute {
    /// Serve the index / home page.
    Index,
    /// Serve a block detail page for the given hash.
    BlockDetail(String),
    /// Serve a transaction detail page for the given txid.
    TxDetail(String),
    /// Proxy to the Esplora REST API (path includes the `/api/` prefix).
    Api(String),
}

/// Match an incoming path against the explorer routes.
///
/// Returns `Some(route)` on match, `None` for unknown paths.
pub fn match_explorer_route(path: &str) -> Option<ExplorerRoute> {
    // Strip query string for routing.
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Some(ExplorerRoute::Index);
    }

    // API proxy: anything under /api/
    if path.starts_with("/api/") || path == "/api" {
        return Some(ExplorerRoute::Api(path.to_string()));
    }

    // /metrics passthrough
    if path == "/metrics" {
        return Some(ExplorerRoute::Api(path.to_string()));
    }

    // Block detail: /block/:hash
    if let Some(params) = crate::http::match_route(path, "/block/:hash") {
        if let Some(hash) = params.get("hash") {
            return Some(ExplorerRoute::BlockDetail(hash.clone()));
        }
    }

    // Transaction detail: /tx/:txid
    if let Some(params) = crate::http::match_route(path, "/tx/:txid") {
        if let Some(txid) = params.get("txid") {
            return Some(ExplorerRoute::TxDetail(txid.clone()));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

/// Handle an explorer HTTP request by routing it to the appropriate handler.
///
/// This is public so it can be unit-tested without starting a TCP listener.
pub fn handle_explorer_request(req: &HttpRequest, metrics: &MetricsCollector) -> HttpResponse {
    if req.method != "GET" {
        return HttpResponse::bad_request("only GET is supported");
    }

    let path = req.path.split('?').next().unwrap_or(&req.path);

    match match_explorer_route(path) {
        Some(ExplorerRoute::Index) => HttpResponse::html(INDEX_HTML),
        Some(ExplorerRoute::BlockDetail(hash)) => {
            let html = BLOCK_DETAIL_HTML.replace("{{hash}}", &hash);
            HttpResponse::html(&html)
        }
        Some(ExplorerRoute::TxDetail(txid)) => {
            let html = TX_DETAIL_HTML.replace("{{txid}}", &txid);
            HttpResponse::html(&html)
        }
        Some(ExplorerRoute::Api(_)) => {
            // Proxy to the Esplora REST handlers by reusing the existing
            // handle_request logic from crate::http. We construct a request
            // with the same path and pass it through.
            crate::http::handle_request(req, metrics)
        }
        None => HttpResponse::not_found(),
    }
}

// ---------------------------------------------------------------------------
// ExplorerServer
// ---------------------------------------------------------------------------

/// A lightweight HTTP server that serves the block explorer UI and proxies
/// API requests to the Esplora REST handlers.
pub struct ExplorerServer {
    port: u16,
}

impl ExplorerServer {
    /// Create a new `ExplorerServer` bound to the given port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Return the configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Run the explorer server. This future never completes unless the runtime
    /// shuts down or an unrecoverable error occurs.
    pub async fn run(self, metrics: MetricsCollector) -> std::io::Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(port = self.port, "Explorer server listening");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "failed to accept explorer connection");
                    continue;
                }
            };
            debug!(%peer, "Explorer connection accepted");
            let metrics = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_explorer_connection(stream, &metrics).await {
                    debug!(%peer, error = %e, "explorer connection error");
                }
            });
        }
    }
}

/// Handle a single HTTP connection on the explorer port.
async fn handle_explorer_connection(
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
            debug!(method = %req.method, path = %req.path, "Explorer request");
            handle_explorer_request(&req, metrics)
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
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

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

    fn make_request(path: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // INDEX_HTML validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_html_is_valid() {
        assert!(INDEX_HTML.contains("<!DOCTYPE html>"));
        assert!(INDEX_HTML.contains("<html>"));
        assert!(INDEX_HTML.contains("</html>"));
        assert!(INDEX_HTML.contains("<head>"));
        assert!(INDEX_HTML.contains("</head>"));
        assert!(INDEX_HTML.contains("<body>"));
        assert!(INDEX_HTML.contains("</body>"));
        assert!(INDEX_HTML.contains("<title>btc-rust Explorer</title>"));
        assert!(INDEX_HTML.contains("id=\"search\""));
        assert!(INDEX_HTML.contains("id=\"stats\""));
        assert!(INDEX_HTML.contains("id=\"content\""));
        assert!(INDEX_HTML.contains("loadStats()"));
        assert!(INDEX_HTML.contains("function search()"));
        assert!(INDEX_HTML.contains("/api/blocks/tip/height"));
        assert!(INDEX_HTML.contains("/api/mempool"));
    }

    #[test]
    fn test_block_detail_html_has_template_marker() {
        assert!(BLOCK_DETAIL_HTML.contains("{{hash}}"));
        assert!(BLOCK_DETAIL_HTML.contains("<!DOCTYPE html>"));
        assert!(BLOCK_DETAIL_HTML.contains("/api/block/"));
    }

    #[test]
    fn test_tx_detail_html_has_template_marker() {
        assert!(TX_DETAIL_HTML.contains("{{txid}}"));
        assert!(TX_DETAIL_HTML.contains("<!DOCTYPE html>"));
        assert!(TX_DETAIL_HTML.contains("/api/tx/"));
    }

    // -----------------------------------------------------------------------
    // ExplorerServer construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_explorer_server_construction() {
        let server = ExplorerServer::new(3000);
        assert_eq!(server.port(), 3000);
    }

    #[test]
    fn test_explorer_server_custom_port() {
        let server = ExplorerServer::new(8080);
        assert_eq!(server.port(), 8080);
    }

    // -----------------------------------------------------------------------
    // Route matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_route_index() {
        assert_eq!(match_explorer_route("/"), Some(ExplorerRoute::Index));
        assert_eq!(match_explorer_route(""), Some(ExplorerRoute::Index));
    }

    #[test]
    fn test_route_api_passthrough() {
        assert_eq!(
            match_explorer_route("/api/blocks/tip/height"),
            Some(ExplorerRoute::Api("/api/blocks/tip/height".into()))
        );
        assert_eq!(
            match_explorer_route("/api/mempool"),
            Some(ExplorerRoute::Api("/api/mempool".into()))
        );
        assert_eq!(
            match_explorer_route("/api/block/abc123def456"),
            Some(ExplorerRoute::Api("/api/block/abc123def456".into()))
        );
        assert_eq!(
            match_explorer_route("/api/tx/abc123def456"),
            Some(ExplorerRoute::Api("/api/tx/abc123def456".into()))
        );
    }

    #[test]
    fn test_route_metrics_passthrough() {
        assert_eq!(
            match_explorer_route("/metrics"),
            Some(ExplorerRoute::Api("/metrics".into()))
        );
    }

    #[test]
    fn test_route_block_detail() {
        let hash = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
        assert_eq!(
            match_explorer_route(&format!("/block/{}", hash)),
            Some(ExplorerRoute::BlockDetail(hash.into()))
        );
    }

    #[test]
    fn test_route_tx_detail() {
        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        assert_eq!(
            match_explorer_route(&format!("/tx/{}", txid)),
            Some(ExplorerRoute::TxDetail(txid.into()))
        );
    }

    #[test]
    fn test_route_unknown() {
        assert_eq!(match_explorer_route("/unknown"), None);
        assert_eq!(match_explorer_route("/foo/bar/baz"), None);
    }

    // -----------------------------------------------------------------------
    // Request handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_handle_index_returns_html() {
        let m = make_metrics();
        let resp = handle_explorer_request(&make_request("/"), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("btc-rust explorer"));
        assert!(body.contains("<!DOCTYPE html>"));
        // Check content-type is HTML
        let ct = resp
            .headers
            .iter()
            .find(|(k, _)| k == "Content-Type")
            .map(|(_, v)| v.as_str());
        assert_eq!(ct, Some("text/html; charset=utf-8"));
    }

    #[test]
    fn test_handle_api_proxy() {
        let m = make_metrics();
        let resp = handle_explorer_request(&make_request("/api/blocks/tip/height"), &m);
        assert_eq!(resp.status, 200);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "800000");
    }

    #[test]
    fn test_handle_api_mempool() {
        let m = make_metrics();
        let resp = handle_explorer_request(&make_request("/api/mempool"), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["count"].as_u64().unwrap(), 1234);
    }

    #[test]
    fn test_handle_block_detail_page() {
        let m = make_metrics();
        let hash = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
        let resp = handle_explorer_request(&make_request(&format!("/block/{}", hash)), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains(hash));
        assert!(body.contains("<!DOCTYPE html>"));
        assert!(!body.contains("{{hash}}"));
    }

    #[test]
    fn test_handle_tx_detail_page() {
        let m = make_metrics();
        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let resp = handle_explorer_request(&make_request(&format!("/tx/{}", txid)), &m);
        assert_eq!(resp.status, 200);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains(txid));
        assert!(body.contains("<!DOCTYPE html>"));
        assert!(!body.contains("{{txid}}"));
    }

    #[test]
    fn test_handle_unknown_returns_404() {
        let m = make_metrics();
        let resp = handle_explorer_request(&make_request("/unknown"), &m);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_handle_non_get_returns_400() {
        let m = make_metrics();
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let resp = handle_explorer_request(&req, &m);
        assert_eq!(resp.status, 400);
    }
}
