//! TCP server for the Electrum protocol.
//!
//! Accepts newline-delimited JSON-RPC over a raw TCP socket, matching the
//! wire format used by Electrum wallets. Each line is parsed as an
//! [`ElectrumRequest`], dispatched through [`ElectrumHandler`], and the
//! resulting [`ElectrumResponse`] is written back followed by a newline.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::handler::ElectrumHandler;

/// Default TCP port for the Electrum protocol (unencrypted).
pub const DEFAULT_PORT: u16 = 50001;

/// Embedded Electrum protocol server.
///
/// Listens on a TCP port and speaks newline-delimited JSON-RPC, compatible
/// with Electrum, Sparrow, Blue Wallet, and other wallets that implement
/// the Electrum protocol.
pub struct ElectrumServer {
    /// TCP port to bind (default: 50001).
    port: u16,
}

impl ElectrumServer {
    /// Create a new server that will listen on the given port.
    pub fn new(port: u16) -> Self {
        ElectrumServer { port }
    }

    /// Returns the configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Start listening for Electrum client connections.
    ///
    /// This drives the server to completion and only returns on fatal error.
    /// If the port is already in use the error is logged and the method
    /// returns `Ok(())` so the rest of the node can keep running.
    pub async fn run(self, handler: Arc<ElectrumHandler>) -> Result<(), std::io::Error> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(
                    addr = %addr,
                    error = %e,
                    "failed to bind electrum server (port may already be in use) -- electrum disabled"
                );
                return Ok(());
            }
        };
        info!(addr = %addr, "electrum server listening");

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!(error = %e, "electrum accept failed");
                    continue;
                }
            };

            info!(peer = %peer, "electrum connection accepted");

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
                        error!(error = %e, "electrum write failed");
                        break;
                    }
                }

                info!(peer = %peer, "electrum connection closed");
            });
        }
    }
}

impl Default for ElectrumServer {
    fn default() -> Self {
        Self::new(DEFAULT_PORT)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_default_port() {
        let server = ElectrumServer::default();
        assert_eq!(server.port(), DEFAULT_PORT);
    }

    #[test]
    fn test_server_custom_port() {
        let server = ElectrumServer::new(60001);
        assert_eq!(server.port(), 60001);
    }

    #[tokio::test]
    async fn test_server_tcp_roundtrip() {
        // Start the server on a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(ElectrumHandler::new());
        let handler_clone = Arc::clone(&handler);

        // Spawn a mini server loop that handles exactly one connection
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
        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        // Send a server.version request
        let req = r#"{"id":1,"method":"server.version","params":["test","1.4"]}"#;
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        // Read response
        let mut lines = BufReader::new(reader).lines();
        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp["id"], 1);
        assert!(resp["result"].is_array());
        assert!(resp["result"][0]
            .as_str()
            .unwrap()
            .contains("btc-rust-electrum"));

        // Shut down
        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }

    #[test]
    fn test_default_port_constant() {
        assert_eq!(DEFAULT_PORT, 50001);
    }

    #[tokio::test]
    async fn test_server_handles_empty_lines() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(ElectrumHandler::new());
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

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        // Send empty lines then a request
        writer.write_all(b"\n\n").await.unwrap();
        let req = r#"{"id":42,"method":"server.ping","params":[]}"#;
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        let mut lines = BufReader::new(reader).lines();
        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp["id"], 42);

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_handles_multiple_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(ElectrumHandler::new());
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

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        // Send multiple requests
        for i in 1..=3 {
            let req = format!(
                r#"{{"id":{},"method":"server.ping","params":[]}}"#,
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
        }

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_handles_invalid_json() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(ElectrumHandler::new());
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

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        writer.write_all(b"garbage data\n").await.unwrap();

        let mut lines = BufReader::new(reader).lines();
        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert!(resp["error"].is_object());
        assert_eq!(resp["error"]["code"], -32700);

        writer.write_all(b"DONE\n").await.unwrap();
        server_handle.await.unwrap();
    }
}
