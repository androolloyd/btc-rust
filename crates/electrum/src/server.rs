//! Opt-in loopback Electrum chain/transaction transport with bounded clients.
use crate::handler::{ElectrumHandler, ScriptSession};
use crate::methods::METHOD_HEADERS_SUBSCRIBE;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

pub const DEFAULT_PORT: u16 = 50001;
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024 + 4096;
pub const MAX_CONNECTIONS: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ElectrumServer {
    port: u16,
}
impl Default for ElectrumServer {
    fn default() -> Self {
        Self::new(DEFAULT_PORT)
    }
}
impl ElectrumServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub async fn run(self, handler: Arc<ElectrumHandler>) -> std::io::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await?;
        let (_sender, receiver) = watch::channel(false);
        self.run_listener(listener, handler, receiver).await
    }
    pub async fn run_listener(
        self,
        listener: TcpListener,
        handler: Arc<ElectrumHandler>,
        mut shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        tracing::info!(addr = %listener.local_addr()?, "experimental Electrum chain service listening");
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut clients = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = stopped(&mut shutdown) => break Ok(()),
                result = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(error)) = result { tracing::error!(%error, "Electrum client task failed"); }
                }
                accepted = listener.accept() => {
                    let (stream, _) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let Ok(permit) = permits.clone().try_acquire_owned() else { drop(stream); continue; };
                    let handler = handler.clone(); let receiver = shutdown.clone();
                    clients.spawn(async move { let _permit = permit; if let Err(error) = connection(stream, handler, receiver).await { tracing::debug!(%error, "Electrum client closed"); } });
                }
            }
        };
        clients.abort_all();
        while clients.join_next().await.is_some() {}
        result
    }
}

async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn line<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    // Idle subscriptions survive without allocating. Once the first byte
    // arrives, a partial frame has an actual bounded deadline.
    if reader.fill_buf().await?.is_empty() {
        return Ok(None);
    }
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut value = Vec::new();
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unterminated Electrum frame",
                ));
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| n + 1)
                .unwrap_or(available.len());
            if count > MAX_REQUEST_BYTES.saturating_sub(value.len()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Electrum request exceeds limit",
                ));
            }
            let done = available[count - 1] == b'\n';
            value.extend_from_slice(&available[..count]);
            reader.consume(count);
            if done {
                return Ok(Some(value));
            }
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "partial Electrum frame expired",
        )
    })?
}

async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    output: &str,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    tokio::select! {
        biased;
        _ = stopped(shutdown) => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Electrum stopped")),
        result = tokio::time::timeout(IO_TIMEOUT, async { writer.write_all(output.as_bytes()).await?; writer.write_all(b"\n").await }) => result.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Electrum write expired"))?,
    }
}

struct ReaderTask(tokio::task::JoinHandle<()>);
impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connection(
    stream: TcpStream,
    handler: Arc<ElectrumHandler>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut events = handler.subscribe_headers();
    let mut last_header = None;
    // Capture revisions before any initial snapshot; a commit between the
    // query and first response remains pending and is refreshed afterwards.
    let mut script_events = handler.subscribe_scripts();
    let mut scripts = ScriptSession::default();
    let (sender, mut requests) = mpsc::channel(1);
    // A separate bounded reader retains partially consumed bytes when a
    // header notification arrives. Cancelling a read future would lose them.
    let _reader_task = ReaderTask(tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        loop {
            match line(&mut reader).await {
                Ok(Some(value)) => {
                    if sender.send(Ok(value)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    break;
                }
            }
        }
    }));
    loop {
        tokio::select! {
            _ = stopped(&mut shutdown) => return Ok(()),
            event = async { events.as_mut().unwrap().recv().await }, if events.is_some() && last_header.is_some() => {
                if matches!(event, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "validated header event stream closed"));
                }
                let provider = handler.clone();
                let header = tokio::task::spawn_blocking(move || provider.tip()).await.map_err(std::io::Error::other)?;
                let header = header.map_err(|error| std::io::Error::other(error.message))?;
                if last_header.as_ref() != Some(&header) {
                    let notification = serde_json::json!({"jsonrpc":"2.0", "method":METHOD_HEADERS_SUBSCRIBE, "params":[header]});
                    write(&mut writer, &notification.to_string(), &mut shutdown).await?;
                    last_header = Some(header);
                }
            }
            event = async { script_events.as_mut().unwrap().changed().await }, if script_events.is_some() && !scripts.scripts.is_empty() => {
                if event.is_err() { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof,"validated script event stream closed")); }
                let provider = handler.clone();
                let (result,session) = tokio::task::spawn_blocking(move || { let result = provider.refresh_scripts(&mut scripts); (result,scripts) }).await.map_err(std::io::Error::other)?;
                scripts = session;
                for notification in result.map_err(|error| std::io::Error::other(error.message))? { write(&mut writer,&notification.to_string(),&mut shutdown).await?; }
            }
            request = requests.recv() => {
                let Some(request) = request else { return Ok(()); };
                let request = request?;
                let text = std::str::from_utf8(&request).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData,error))?.trim();
                if text.is_empty() { continue; }
                let text = text.to_owned(); let worker = handler.clone();
                let (result,session) = tokio::task::spawn_blocking(move || { let result = worker.dispatch_session(&text,Some(&mut scripts)); (result,scripts) }).await.map_err(std::io::Error::other)?;
                scripts = session;
                if let Some(header) = result.header { last_header = Some(header); }
                if !result.output.is_empty() { write(&mut writer, &result.output, &mut shutdown).await?; }
                if result.close { return Ok(()); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_listener_returns_errors_and_stops_with_idle_partial_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sender, receiver) = watch::channel(false);
        let task = tokio::spawn(ElectrumServer::new(addr.port()).run_listener(
            listener,
            Arc::new(ElectrumHandler::new()),
            receiver,
        ));
        let stream = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        writer.write_all(b"\n{\"id\":3,\"method\":\"blockchain.transaction.broadcast\",\"params\":[\"ff\"]}\n").await.unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["id"], 3);
        assert_eq!(value["error"]["code"], -32603);
        assert!(value["result"].is_null());
        let _idle = TcpStream::connect(addr).await.unwrap();
        let mut partial = TcpStream::connect(addr).await.unwrap();
        partial.write_all(b"{\"id\":").await.unwrap();
        sender.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reader.read_line(&mut String::new()).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn bind_failure_is_reported_instead_of_disabled_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(ElectrumServer::new(port)
            .run(Arc::new(ElectrumHandler::new()))
            .await
            .is_err());
    }
    #[tokio::test]
    async fn framing_rejects_oversize_and_unterminated_input() {
        let mut bytes = BufReader::new(&b"{\"id\":1}"[..]);
        assert!(line(&mut bytes).await.is_err());
        let large = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let mut bytes = BufReader::new(large.as_slice());
        assert!(line(&mut bytes).await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn partial_frame_has_deadline_while_idle_does_not() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"{").await.unwrap();
        assert_eq!(
            line(&mut reader).await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn closed_provider_events_disconnect_subscribers_instead_of_silencing_updates() {
        // A deliberate event-source fault; the header itself is actual network
        // genesis. This stub is not used as a protocol/validation oracle.
        struct ClosedEvents;
        impl crate::ElectrumBackend for ClosedEvents {
            fn call(
                &self,
                _: &str,
                _: serde_json::Value,
            ) -> Result<serde_json::Value, crate::ElectrumRpcError> {
                let header = btc_consensus::chain::genesis_header(
                    &btc_consensus::validation::ChainParams::from_network(
                        btc_primitives::Network::Regtest,
                    ),
                );
                Ok(
                    serde_json::json!({"height":0,"hex":hex::encode(btc_primitives::encode::encode(&header))}),
                )
            }
            fn subscribe_headers(
                &self,
            ) -> tokio::sync::broadcast::Receiver<btc_primitives::BlockHash> {
                tokio::sync::broadcast::channel(1).1
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = watch::channel(false);
        let handler = Arc::new(ElectrumHandler::new().with_backend(Arc::new(ClosedEvents)));
        let task = tokio::spawn(
            ElectrumServer::new(address.port()).run_listener(listener, handler, receiver),
        );
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"blockchain.headers.subscribe\"}\n",
            )
            .await
            .unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["result"]["height"],
            0
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut String::new()))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        sender.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}

#[cfg(test)]
mod script_fault_tests {
    use super::*;
    use crate::{ElectrumBackend, ElectrumRpcError};
    use serde_json::{json, Value};
    /// Only event delivery is deliberately faulty. Empty history at genesis
    /// has a real null status; this is not a chain/cryptographic oracle.
    struct ClosedScriptEvents;
    impl ElectrumBackend for ClosedScriptEvents {
        fn call(&self, _: &str, _: Value) -> Result<Value, ElectrumRpcError> {
            Err(ElectrumRpcError {
                code: -32601,
                message: "unsupported".into(),
            })
        }
        fn subscribe_headers(&self) -> tokio::sync::broadcast::Receiver<btc_primitives::BlockHash> {
            tokio::sync::broadcast::channel(1).1
        }
        fn subscribe_scripts(&self) -> Option<watch::Receiver<u64>> {
            Some(watch::channel(0).1)
        }
        fn script_statuses(&self, scripts: &[String]) -> Result<Vec<Value>, ElectrumRpcError> {
            Ok(vec![Value::Null; scripts.len()])
        }
    }
    #[tokio::test]
    async fn closed_script_source_disconnects_instead_of_silencing_subscriptions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sender, receiver) = watch::channel(false);
        let handler = Arc::new(ElectrumHandler::new().with_backend(Arc::new(ClosedScriptEvents)));
        let task = tokio::spawn(
            ElectrumServer::new(addr.port()).run_listener(listener, handler, receiver),
        );
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":["00".repeat(32)]})).as_bytes()).await.unwrap();
        let mut client = BufReader::new(client);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap(),
            json!({"jsonrpc":"2.0","id":1,"result":null})
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client.read_line(&mut String::new()))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        sender.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
