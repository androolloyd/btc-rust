use std::sync::Arc;

use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info};

use crate::handler::RpcHandler;
pub use crate::http::HttpAuth;

/// Loopback JSON-RPC with authenticated HTTP and legacy newline JSON transport.
pub struct RpcServer {
    port: u16,
    http_auth: Option<HttpAuth>,
}

impl RpcServer {
    pub fn new(port: u16) -> Self {
        RpcServer {
            port,
            http_auth: None,
        }
    }

    /// HTTP is unavailable without credentials; legacy local TCP is retained.
    pub fn with_http_auth(mut self, auth: HttpAuth) -> Self {
        self.http_auth = Some(auth);
        self
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
    /// Bind failures are fatal to RPC startup and are returned to the caller.
    pub async fn run(self, handler: Arc<RpcHandler>) -> eyre::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await?;
        self.run_listener(listener, handler).await
    }

    /// Serve an already-bound listener (also used by real transport tests).
    pub async fn run_listener(
        self,
        listener: TcpListener,
        handler: Arc<RpcHandler>,
    ) -> eyre::Result<()> {
        info!(addr = %listener.local_addr()?, "rpc server listening");
        let mut clients = JoinSet::new();
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        loop {
            tokio::select! {
                biased;
                _ = handler.wait_for_shutdown() => break,
                result = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(error)) = result { error!(%error, "RPC connection task failed"); }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else { drop(stream); continue; };
                    let handler = Arc::clone(&handler);
                    let auth = self.http_auth.clone();
                    clients.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve_connection(stream, handler, auth).await {
                            error!(%error, "RPC connection failed");
                        }
                    });
                }
            }
        }
        // Let the connection handling stop RPC finish writing its response.
        if tokio::time::timeout(Duration::from_secs(1), async {
            while clients.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        }
        Ok(())
    }
}

/// A 4 MW block fits as hex, including its request envelope.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024 + 4096;
pub const MAX_CONNECTIONS: usize = 64;
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(30);

async fn read_request<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    read_line_limited(reader, MAX_REQUEST_BYTES).await
}

pub(crate) async fn read_line_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let consumed = newline.map(|n| n + 1).unwrap_or(available.len());
        if consumed > limit.saturating_sub(line.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RPC request exceeds size limit",
            ));
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    handler: Arc<RpcHandler>,
    auth: Option<HttpAuth>,
) -> eyre::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    // The mode is selected once. A rejected HTTP body can never be reparsed as
    // a legacy request, nor can an HTTP keepalive switch to raw TCP dispatch.
    let first = tokio::select! {
        biased;
        _ = handler.wait_for_shutdown() => return Ok(()),
        result = tokio::time::timeout(IO_TIMEOUT, reader.fill_buf()) => result??.first().copied(),
    };
    if first.is_some_and(|byte| byte.is_ascii_alphabetic()) {
        return crate::http::serve(&mut reader, &mut writer, handler, auth).await;
    }
    loop {
        let line = tokio::select! {
            biased;
            _ = handler.wait_for_shutdown() => return Ok(()),
            result = tokio::time::timeout(Duration::from_secs(30), read_request(&mut reader)) => result??,
        };
        let Some(line) = line else {
            return Ok(());
        };
        let line = std::str::from_utf8(&line)?.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let worker = Arc::clone(&handler);
        let response = tokio::task::spawn_blocking(move || worker.handle_raw(&line)).await?;
        tokio::time::timeout(
            Duration::from_secs(30),
            writer.write_all(format!("{response}\n").as_bytes()),
        )
        .await??;
        if handler.should_shutdown() {
            return Ok(());
        }
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
    async fn real_server_stop_wakes_listener_and_returns_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handler = Arc::new(RpcHandler::new());
        let task = tokio::spawn(RpcServer::new(address.port()).run_listener(listener, handler));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader).lines();
        writer.write_all(b"\n{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}\n{\"jsonrpc\":\"2.0\",\"method\":\"stop\",\"params\":[],\"id\":2}\n").await.unwrap();
        let first: serde_json::Value =
            serde_json::from_str(&reader.next_line().await.unwrap().unwrap()).unwrap();
        let second: serde_json::Value =
            serde_json::from_str(&reader.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(first["result"], 0);
        assert_eq!(second["id"], 2);
        assert_eq!(second["result"], "Bitcoin server stopping");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn bind_failure_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = RpcServer::new(listener.local_addr().unwrap().port())
            .run(Arc::new(RpcHandler::new()))
            .await
            .unwrap_err();
        assert!(error.to_string().to_lowercase().contains("address"));
    }

    #[tokio::test]
    async fn oversized_unterminated_request_is_bounded() {
        let (mut writer, reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let _ = writer.write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1]).await;
        });
        let error = read_request(&mut BufReader::new(reader)).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        task.abort();
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
        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        // Send a valid RPC request
        let req = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;
        writer
            .write_all(format!("{req}\n").as_bytes())
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

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        // Send empty lines followed by a valid request
        writer.write_all(b"\n\n\n").await.unwrap();
        let req = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":99}"#;
        writer
            .write_all(format!("{req}\n").as_bytes())
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

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
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

        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (reader, mut writer) = client.split();

        // Send multiple requests on same connection
        for i in 1..=3 {
            let req =
                format!(r#"{{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":{i}}}"#);
            writer
                .write_all(format!("{req}\n").as_bytes())
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
