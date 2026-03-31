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
