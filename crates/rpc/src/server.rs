use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::handler::RpcHandler;

/// JSON-RPC server -- provides a Bitcoin Core-compatible RPC interface over
/// newline-delimited JSON on a raw TCP socket.
pub struct RpcServer {
    port: u16,
}

impl RpcServer {
    pub fn new(port: u16) -> Self {
        RpcServer { port }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Default for RpcServer {
    fn default() -> Self {
        Self::new(8332)
    }
}

impl RpcServer {

    /// Start listening for RPC connections.
    ///
    /// This drives the server to completion; it only returns when the
    /// handler's shutdown flag is set (via a `stop` RPC call) or when the
    /// listener encounters a fatal error.
    ///
    /// If the port is already in use (e.g. from a previous run), the error
    /// is logged and the method returns `Ok(())` -- this keeps the RPC
    /// failure non-fatal so the rest of the node can still operate.
    pub async fn run(self, handler: Arc<RpcHandler>) -> eyre::Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(
                    addr = %addr,
                    error = %e,
                    "failed to bind RPC server (port may already be in use) -- RPC disabled"
                );
                return Ok(());
            }
        };
        info!(addr = %addr, "rpc server listening");

        loop {
            if handler.should_shutdown() {
                info!("rpc server shutting down");
                break;
            }

            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!(error = %e, "accept failed");
                    continue;
                }
            };

            info!(peer = %peer, "rpc connection accepted");

            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }

                    let response = handler.handle_raw(&line);
                    let mut out = response.into_bytes();
                    out.push(b'\n');

                    if let Err(e) = writer.write_all(&out).await {
                        error!(error = %e, "write failed");
                        break;
                    }
                }
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn test_server_new() {
        let server = RpcServer::new(18332);
        assert_eq!(server.port(), 18332);
    }

    #[test]
    fn test_server_default() {
        let server = RpcServer::default();
        assert_eq!(server.port(), 8332);
    }

    #[tokio::test]
    async fn test_server_tcp_roundtrip() {
        // Bind to an available port for the test
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(RpcHandler::new());
        let handler_clone = Arc::clone(&handler);

        // Spawn a minimal server loop
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "DONE" {
                    break;
                }
                let response = handler_clone.handle_raw(&line);
                let mut out = response.into_bytes();
                out.push(b'\n');
                writer.write_all(&out).await.unwrap();
            }
        });

        // Connect as a client
        let mut client =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
        let (reader, mut writer) = client.split();

        // Send a valid RPC request
        let req = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        // Read the response
        let mut lines = BufReader::new(reader).lines();
        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"], 0);

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_handles_empty_lines() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(RpcHandler::new());
        let handler_clone = Arc::clone(&handler);

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "DONE" {
                    break;
                }
                let response = handler_clone.handle_raw(&line);
                let mut out = response.into_bytes();
                out.push(b'\n');
                writer.write_all(&out).await.unwrap();
            }
        });

        let mut client =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
        let (reader, mut writer) = client.split();

        // Send empty lines followed by a valid request
        writer.write_all(b"\n\n\n").await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":99}"#;
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        let mut lines = BufReader::new(reader).lines();
        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp["id"], 99);
        assert_eq!(resp["result"], 0);

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_handles_invalid_json() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(RpcHandler::new());
        let handler_clone = Arc::clone(&handler);

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "DONE" {
                    break;
                }
                let response = handler_clone.handle_raw(&line);
                let mut out = response.into_bytes();
                out.push(b'\n');
                writer.write_all(&out).await.unwrap();
            }
        });

        let mut client =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
        let (reader, mut writer) = client.split();

        // Send invalid JSON
        writer.write_all(b"not valid json\n").await.unwrap();

        let mut lines = BufReader::new(reader).lines();
        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert!(resp["error"].is_object());
        assert_eq!(resp["error"]["code"], -32700); // PARSE_ERROR

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_multiple_requests_one_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(RpcHandler::new());
        let handler_clone = Arc::clone(&handler);

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "DONE" {
                    break;
                }
                let response = handler_clone.handle_raw(&line);
                let mut out = response.into_bytes();
                out.push(b'\n');
                writer.write_all(&out).await.unwrap();
            }
        });

        let mut client =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
        let (reader, mut writer) = client.split();

        // Send multiple requests on same connection
        for i in 1..=3 {
            let req = format!(
                r#"{{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":{}}}"#,
                i
            );
            writer
                .write_all(format!("{}\n", req).as_bytes())
                .await
                .unwrap();
        }

        let mut lines = BufReader::new(reader).lines();
        for i in 1..=3 {
            let resp_line = lines.next_line().await.unwrap().unwrap();
            let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
            assert_eq!(resp["id"], i);
            assert_eq!(resp["result"], 0);
        }

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }
}
