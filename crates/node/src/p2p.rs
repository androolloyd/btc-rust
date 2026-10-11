//! Shared inbound/outbound v1/BIP324 sessions serving the committed chain.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use btc_network::message::{GetHeadersMessage, InvItem, InvType, NetworkMessage, VersionMessage};
use btc_network::{Connection, ProtocolVersion};
use btc_primitives::block::Block;
use btc_primitives::hash::{BlockHash, Hash256, TxHash};
use btc_primitives::network::Network;
use btc_rpc::handler::{RpcError, RpcHandler, INTERNAL_ERROR};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinSet;

use crate::chain_backend::NodeChainBackend;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_BLOCKS: usize = 16;
const MAX_BUFFERED_WEIGHT: usize = 16_000_000;

/// Snapshots come from completed handshakes, including actual transport/session.
pub struct PeerTable {
    peers: Mutex<BTreeMap<u64, Value>>,
    next_id: AtomicU64,
    count: Arc<AtomicU64>,
}

pub struct PeerGuard {
    table: Arc<PeerTable>,
    id: u64,
}
impl Drop for PeerGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.table.peers.lock() {
            peers.remove(&self.id);
            self.table.count.store(peers.len() as u64, Ordering::SeqCst);
        }
    }
}

impl PeerTable {
    pub fn new(count: Arc<AtomicU64>) -> Self {
        Self {
            peers: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(0),
            count,
        }
    }
    pub fn register(
        self: &Arc<Self>,
        address: SocketAddr,
        inbound: bool,
        connection: &Connection,
        version: &VersionMessage,
    ) -> eyre::Result<PeerGuard> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| eyre::eyre!("peer table poisoned"))?;
        let mut snapshot = json!({ "id": id, "addr": address.to_string(), "inbound": inbound,
            "version": version.version, "services": format!("{:016x}", version.services),
            "subver": version.user_agent, "relaytxes": version.relay,
            "conntime": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "transport_protocol_type": if connection.is_encrypted() { "v2" } else { "v1" } });
        if let Some(session) = connection.session_id() {
            snapshot["session_id"] = json!(hex::encode(session));
        }
        peers.insert(id, snapshot);
        self.count.store(peers.len() as u64, Ordering::SeqCst);
        Ok(PeerGuard {
            table: self.clone(),
            id,
        })
    }
    pub fn snapshot(&self) -> Result<Value, RpcError> {
        let peers = self
            .peers
            .lock()
            .map_err(|_| RpcError::new(INTERNAL_ERROR, "peer table poisoned"))?;
        Ok(json!(peers.values().collect::<Vec<_>>()))
    }
    pub fn network_info(&self) -> Result<Value, RpcError> {
        let peers = self
            .peers
            .lock()
            .map_err(|_| RpcError::new(INTERNAL_ERROR, "peer table poisoned"))?;
        let inbound = peers
            .values()
            .filter(|peer| peer["inbound"] == true)
            .count();
        Ok(
            json!({ "version": 10000, "subversion": btc_network::protocol::USER_AGENT,
            "protocolversion": ProtocolVersion::CURRENT.0,
            "localrelay": true,
            "localservices": format!("{:016x}", btc_network::protocol::ServiceFlags::node_services().0),
            "connections": peers.len(), "connections_in": inbound, "connections_out": peers.len() - inbound }),
        )
    }
}

pub struct P2pServer;
impl P2pServer {
    pub async fn run(
        listener: TcpListener,
        network: Network,
        backend: Arc<NodeChainBackend>,
        peers: Arc<PeerTable>,
        shutdown: Arc<RpcHandler>,
    ) -> eyre::Result<()> {
        tracing::info!(address = %listener.local_addr()?, "P2P listener ready");
        // Pending handshakes also consume a slot, so silent clients stay bounded.
        let slots = Arc::new(Semaphore::new(32));
        let mut clients = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = shutdown.wait_for_shutdown() => break Ok(()),
                result = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(error)) = result { tracing::warn!(%error, "P2P task failed"); }
                }
                accepted = listener.accept() => {
                    let (stream, address) = match accepted { Ok(value) => value, Err(error) => break Err(error.into()) };
                    let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                    let backend = backend.clone(); let peers = peers.clone(); let shutdown = shutdown.clone();
                    clients.spawn(async move {
                        let _slot = slot;
                        if let Err(error) = serve_peer(stream, address, network, backend, peers, shutdown).await {
                            tracing::debug!(%address, %error, "P2P peer disconnected");
                        }
                    });
                }
            }
        };
        clients.abort_all();
        while clients.join_next().await.is_some() {}
        result
    }
}

async fn send(connection: &mut Connection, message: NetworkMessage) -> eyre::Result<()> {
    tokio::time::timeout(IO_TIMEOUT, connection.send_message(message)).await??;
    Ok(())
}

async fn request_headers(
    connection: &mut Connection,
    backend: &NodeChainBackend,
) -> eyre::Result<()> {
    send(
        connection,
        NetworkMessage::GetHeaders(GetHeadersMessage {
            version: ProtocolVersion::CURRENT.0,
            locator_hashes: backend
                .locator_hashes()
                .map_err(|e| eyre::eyre!(e.message))?,
            stop_hash: BlockHash::ZERO,
        }),
    )
    .await
}

async fn retry_orphans(
    backend: &Arc<NodeChainBackend>,
    orphans: &mut HashMap<TxHash, btc_primitives::Transaction>,
) -> eyre::Result<()> {
    loop {
        let count = orphans.len();
        let ids: Vec<_> = orphans.keys().copied().collect();
        for id in ids {
            let tx = orphans.remove(&id).unwrap();
            let worker = backend.clone();
            let submitted = tx.clone();
            if matches!(
                tokio::task::spawn_blocking(move || worker.submit_transaction(submitted)).await?,
                Err(RpcError { code: -25, .. })
            ) {
                orphans.insert(id, tx);
            }
        }
        if orphans.len() == count {
            break;
        }
    }
    Ok(())
}

async fn serve_peer(
    stream: TcpStream,
    address: SocketAddr,
    network: Network,
    backend: Arc<NodeChainBackend>,
    peers: Arc<PeerTable>,
    shutdown: Arc<RpcHandler>,
) -> eyre::Result<()> {
    let mut connection =
        tokio::time::timeout(IO_TIMEOUT, Connection::accept_inbound(stream, network)).await??;
    let height = i32::try_from(backend.tip()?.0)?;
    let handshake = tokio::time::timeout(
        IO_TIMEOUT,
        connection.perform_inbound_handshake(network, height, true),
    )
    .await??;
    let version = handshake
        .peer_version()
        .ok_or_else(|| eyre::eyre!("missing peer version"))?;
    let _peer = peers.register(address, true, &connection, version)?;
    run_peer_session(&mut connection, backend, Some(shutdown), None, false).await
}

/// Both directions use the same bounded download, validation and committed-data
/// serving path. The outbound manager retains its handshake/IBD peer guard.
pub(crate) async fn run_peer_session(
    connection: &mut Connection,
    backend: Arc<NodeChainBackend>,
    shutdown: Option<Arc<RpcHandler>>,
    sync_state: Option<crate::state::NodeState>,
    announce_tip: bool,
) -> eyre::Result<()> {
    let mut events = backend.subscribe_blocks();
    let mut transactions = backend.subscribe_transactions();
    let relay_transactions = connection.peer_relay();
    let wtxid_relay = connection.peer_wtxid_relay();
    let mut pending_txs = HashSet::new();
    let mut orphan_txs = HashMap::<TxHash, btc_primitives::Transaction>::new();
    send(connection, NetworkMessage::SendHeaders).await?;
    request_headers(connection, &backend).await?;
    // RPC/inbound commits during outbound IBD preceded this subscription. Make
    // our durable tip known immediately, then relay future commit events.
    if announce_tip {
        let hash = backend.tip()?.1;
        send(
            connection,
            NetworkMessage::Inv(vec![InvItem {
                inv_type: InvType::Block,
                hash: Hash256::from_bytes(hash.to_bytes()),
            }]),
        )
        .await?;
    }
    let mut send_headers = false;
    let mut pending = HashSet::new();
    let mut queued: HashMap<BlockHash, Block> = HashMap::new();
    loop {
        let message = tokio::select! {
            biased;
            _ = async {
                if let Some(shutdown) = &shutdown {
                    shutdown.wait_for_shutdown().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => return Ok(()),
            event = transactions.recv(), if relay_transactions => {
                let ids = match event {
                    Ok(id) => vec![id],
                    Err(broadcast::error::RecvError::Lagged(_)) => backend.mempool_transactions().map_err(|e| eyre::eyre!(e.message))?.iter().map(|tx| tx.txid()).collect(),
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let mut items = Vec::new();
                for id in ids {
                    if let Some(tx) = backend.mempool_transaction(id, false).map_err(|e| eyre::eyre!(e.message))? {
                        items.push(InvItem { inv_type: if wtxid_relay { InvType::WtxId } else { InvType::Tx },
                            hash: Hash256::from_bytes(if wtxid_relay { tx.wtxid() } else { tx.txid() }.to_bytes()) });
                    }
                }
                if !items.is_empty() { send(connection, NetworkMessage::Inv(items)).await?; }
                continue;
            }
            event = events.recv() => {
                let hash = match event {
                    Ok(hash) => hash,
                    Err(broadcast::error::RecvError::Lagged(_)) => backend.tip()?.1,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                retry_orphans(&backend, &mut orphan_txs).await?;
                if send_headers {
                    if let Some(header) = backend.header(&hash).map_err(|e| eyre::eyre!(e.message))? {
                        send(connection, NetworkMessage::Headers(vec![header])).await?;
                    }
                } else {
                    send(connection, NetworkMessage::Inv(vec![InvItem { inv_type: InvType::Block, hash: Hash256::from_bytes(hash.to_bytes()) }])).await?;
                }
                continue;
            }
            result = tokio::time::timeout(Duration::from_secs(20 * 60), connection.recv_message()) => result??,
        };
        let is_blocks_request = matches!(&message, NetworkMessage::GetBlocks(_));
        match message {
            NetworkMessage::Ping(nonce) => send(connection, NetworkMessage::Pong(nonce)).await?,
            NetworkMessage::SendHeaders => send_headers = true,
            NetworkMessage::GetHeaders(request) | NetworkMessage::GetBlocks(request) => {
                let is_blocks = is_blocks_request;
                let headers = backend
                    .headers_after(
                        &request.locator_hashes,
                        request.stop_hash,
                        if is_blocks { 500 } else { 2000 },
                    )
                    .map_err(|e| eyre::eyre!(e.message))?;
                if is_blocks {
                    send(
                        connection,
                        NetworkMessage::Inv(
                            headers
                                .into_iter()
                                .map(|header| InvItem {
                                    inv_type: InvType::Block,
                                    hash: Hash256::from_bytes(header.block_hash().to_bytes()),
                                })
                                .collect(),
                        ),
                    )
                    .await?;
                } else {
                    send(connection, NetworkMessage::Headers(headers)).await?;
                }
            }
            NetworkMessage::GetData(items) => {
                let mut missing = Vec::new();
                for item in items {
                    match item.inv_type {
                        InvType::Block | InvType::WitnessBlock => {
                            let block = backend
                                .block(&BlockHash::from_bytes(item.hash.to_bytes()))
                                .map_err(|e| eyre::eyre!(e.message))?;
                            if let Some(mut block) = block {
                                if item.inv_type == InvType::Block {
                                    for tx in &mut block.transactions {
                                        tx.witness.clear();
                                    }
                                }
                                send(connection, NetworkMessage::Block(block)).await?;
                            } else {
                                missing.push(item);
                            }
                        }
                        InvType::Tx | InvType::WitnessTx | InvType::WtxId => {
                            let id = TxHash::from_bytes(item.hash.to_bytes());
                            let transaction = if item.inv_type == InvType::WtxId {
                                backend.mempool_transaction(id, true)
                            } else {
                                backend.transaction(&id)
                            }
                            .map_err(|e| eyre::eyre!(e.message))?;
                            if let Some(mut tx) = transaction {
                                if item.inv_type == InvType::Tx {
                                    tx.witness.clear();
                                }
                                send(connection, NetworkMessage::Tx(tx)).await?;
                            } else {
                                missing.push(item);
                            }
                        }
                        _ => missing.push(item),
                    }
                }
                if !missing.is_empty() {
                    send(connection, NetworkMessage::NotFound(missing)).await?;
                }
            }
            NetworkMessage::Inv(items) => {
                // An inv may advertise only the newest tip after several missed
                // blocks. Fetch the connecting headers before requesting bodies
                // (BIP130); otherwise the tip body looks like an unsupported fork.
                let mut unknown_block = false;
                let mut tx_requests = Vec::new();
                for item in items {
                    if matches!(
                        item.inv_type,
                        InvType::Tx | InvType::WitnessTx | InvType::WtxId
                    ) {
                        let id = TxHash::from_bytes(item.hash.to_bytes());
                        if pending_txs.len() < 128
                            && !pending_txs.contains(&id)
                            && backend
                                .mempool_transaction(id, item.inv_type == InvType::WtxId)
                                .map_err(|e| eyre::eyre!(e.message))?
                                .is_none()
                        {
                            pending_txs.insert(id);
                            tx_requests.push(InvItem {
                                inv_type: if item.inv_type == InvType::WtxId {
                                    InvType::WtxId
                                } else {
                                    InvType::WitnessTx
                                },
                                hash: item.hash,
                            });
                        }
                    }
                    if matches!(item.inv_type, InvType::Block | InvType::WitnessBlock) {
                        let hash = BlockHash::from_bytes(item.hash.to_bytes());
                        if backend
                            .header(&hash)
                            .map_err(|e| eyre::eyre!(e.message))?
                            .is_none()
                            && !pending.contains(&hash)
                            && !queued.contains_key(&hash)
                        {
                            unknown_block = true;
                        }
                    }
                }
                if unknown_block {
                    request_headers(connection, &backend).await?;
                }
                if !tx_requests.is_empty() {
                    send(connection, NetworkMessage::GetData(tx_requests)).await?;
                }
            }
            NetworkMessage::Headers(headers) => {
                if let Some(first) = headers.first() {
                    if backend
                        .header(&first.block_hash())
                        .map_err(|e| eyre::eyre!(e.message))?
                        .is_none()
                        && backend
                            .header(&first.prev_blockhash)
                            .map_err(|e| eyre::eyre!(e.message))?
                            .is_none()
                        && !pending.contains(&first.prev_blockhash)
                        && !queued.contains_key(&first.prev_blockhash)
                    {
                        request_headers(connection, &backend).await?;
                        continue;
                    }
                }
                let mut requests = Vec::new();
                for header in headers {
                    let hash = header.block_hash();
                    if backend
                        .header(&hash)
                        .map_err(|e| eyre::eyre!(e.message))?
                        .is_some()
                        || pending.contains(&hash)
                        || queued.contains_key(&hash)
                    {
                        continue;
                    }
                    if pending.len() >= MAX_PENDING_BLOCKS {
                        break;
                    }
                    btc_consensus::validation::BlockValidator::validate_header(&header)?;
                    pending.insert(hash);
                    requests.push(InvItem {
                        inv_type: InvType::WitnessBlock,
                        hash: Hash256::from_bytes(hash.to_bytes()),
                    });
                }
                if !requests.is_empty() {
                    send(connection, NetworkMessage::GetData(requests)).await?;
                } else if pending.is_empty() && queued.is_empty() {
                    if let Some(state) = &sync_state {
                        state.syncing.store(false, Ordering::SeqCst);
                    }
                }
            }
            NetworkMessage::Block(block) => {
                let hash = block.block_hash();
                if !pending.remove(&hash) {
                    continue;
                }
                // Another peer or RPC may have committed a requested block
                // while its body was in flight. That is not a fork/failure.
                if backend
                    .header(&hash)
                    .map_err(|e| eyre::eyre!(e.message))?
                    .is_none()
                {
                    let weight: usize = queued.values().map(Block::weight).sum();
                    if weight + block.weight() > MAX_BUFFERED_WEIGHT {
                        return Err(eyre::eyre!("pending block buffer limit exceeded"));
                    }
                    queued.insert(hash, block);
                }
                loop {
                    let known = queued
                        .keys()
                        .copied()
                        .filter_map(|hash| match backend.header(&hash) {
                            Ok(Some(_)) => Some(Ok(hash)),
                            Ok(None) => None,
                            Err(error) => Some(Err(eyre::eyre!(error.message))),
                        })
                        .collect::<eyre::Result<Vec<_>>>()?;
                    for hash in known {
                        queued.remove(&hash);
                    }
                    let mut next = None;
                    for (hash, block) in &queued {
                        if backend
                            .header(&block.header.prev_blockhash)
                            .map_err(|e| eyre::eyre!(e.message))?
                            .is_some()
                        {
                            next = Some(*hash);
                            break;
                        }
                    }
                    let Some(next) = next else {
                        break;
                    };
                    let block = queued.remove(&next).unwrap();
                    let worker = backend.clone();
                    let submitted = block.clone();
                    match tokio::task::spawn_blocking(move || worker.submit_block(&submitted))
                        .await?
                    {
                        Ok(_) => {}
                        Err(error) if error.code == -27 => {}
                        Err(error) => return Err(eyre::eyre!(error.message)),
                    }
                }
                if pending.is_empty() {
                    if !queued.is_empty() {
                        return Err(eyre::eyre!("peer supplied blocks with missing ancestry"));
                    }
                    request_headers(connection, &backend).await?;
                }
            }
            NetworkMessage::NotFound(items) => {
                for item in items {
                    pending_txs.remove(&TxHash::from_bytes(item.hash.to_bytes()));
                    if matches!(item.inv_type, InvType::Block | InvType::WitnessBlock)
                        && pending.contains(&BlockHash::from_bytes(item.hash.to_bytes()))
                    {
                        return Err(eyre::eyre!("peer cannot supply a requested block"));
                    }
                }
            }
            NetworkMessage::Version(_) | NetworkMessage::Verack => {
                return Err(eyre::eyre!("duplicate handshake message"))
            }
            NetworkMessage::MemPool if relay_transactions => {
                let items = backend
                    .mempool_transactions()
                    .map_err(|e| eyre::eyre!(e.message))?
                    .iter()
                    .map(|tx| InvItem {
                        inv_type: if wtxid_relay {
                            InvType::WtxId
                        } else {
                            InvType::Tx
                        },
                        hash: Hash256::from_bytes(
                            if wtxid_relay { tx.wtxid() } else { tx.txid() }.to_bytes(),
                        ),
                    })
                    .take(50_000)
                    .collect();
                send(connection, NetworkMessage::Inv(items)).await?;
            }
            NetworkMessage::Tx(tx) => {
                pending_txs.remove(&tx.txid());
                pending_txs.remove(&tx.wtxid());
                let worker = backend.clone();
                let submitted = tx.clone();
                match tokio::task::spawn_blocking(move || worker.submit_transaction(submitted))
                    .await?
                {
                    Ok(_) | Err(RpcError { code: -27, .. }) => {}
                    Err(RpcError { code: -25, .. }) => {
                        if orphan_txs.len() < 64
                            && orphan_txs.values().map(|tx| tx.weight()).sum::<usize>()
                                + tx.weight()
                                <= 4_000_000
                        {
                            let mut parents = Vec::new();
                            for input in &tx.inputs {
                                let id = input.previous_output.txid;
                                if pending_txs.len() < 128 && pending_txs.insert(id) {
                                    parents.push(InvItem {
                                        inv_type: InvType::WitnessTx,
                                        hash: Hash256::from_bytes(id.to_bytes()),
                                    });
                                }
                            }
                            orphan_txs.insert(tx.txid(), tx);
                            if !parents.is_empty() {
                                send(connection, NetworkMessage::GetData(parents)).await?;
                            }
                        }
                    }
                    Err(error) => {
                        tracing::debug!(reason = %error.message, "rejected peer transaction")
                    }
                }
                retry_orphans(&backend, &mut orphan_txs).await?;
            }
            NetworkMessage::WtxidRelay => return Err(eyre::eyre!("late wtxidrelay message")),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::NodeState;
    use btc_rpc::handler::{ChainBackend, RpcRequest};

    async fn receive(connection: &mut Connection) -> NetworkMessage {
        tokio::time::timeout(Duration::from_secs(3), connection.recv_message())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn inbound_transports_serve_committed_blocks_and_publish_peer_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = NodeState::new(Network::Regtest);
        let backend =
            Arc::new(NodeChainBackend::open(&dir.path().join("utxo.redb"), state.clone()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let table = Arc::new(PeerTable::new(state.peer_count.clone()));
        let mut rpc = RpcHandler::new().with_chain_backend(backend.clone());
        let rpc_table = table.clone();
        rpc.register_fallible("getpeerinfo", move |_| rpc_table.snapshot());
        let shutdown = Arc::new(rpc);
        let task = tokio::spawn(P2pServer::run(
            listener,
            Network::Regtest,
            backend.clone(),
            table.clone(),
            shutdown.clone(),
        ));
        for encrypted in [false, true] {
            let mut connection = if encrypted {
                Connection::connect_outbound_v2(address, Network::Regtest)
                    .await
                    .unwrap()
            } else {
                Connection::connect_outbound(address, Network::Regtest)
                    .await
                    .unwrap()
            };
            connection
                .perform_handshake(Network::Regtest, 0)
                .await
                .unwrap();
            assert!(matches!(
                receive(&mut connection).await,
                NetworkMessage::SendHeaders
            ));
            assert!(matches!(
                receive(&mut connection).await,
                NetworkMessage::GetHeaders(_)
            ));
            let response = shutdown.handle(&RpcRequest {
                jsonrpc: "2.0".into(),
                method: "getpeerinfo".into(),
                params: json!([]),
                id: json!(1),
            });
            let peers = response.result.unwrap();
            assert_eq!(peers.as_array().unwrap().len(), 1);
            assert_eq!(
                peers[0]["transport_protocol_type"],
                if encrypted { "v2" } else { "v1" }
            );
            if encrypted {
                assert_eq!(
                    peers[0]["session_id"],
                    hex::encode(connection.session_id().unwrap())
                );
            }
            let hashes = backend
                .call(
                    "generatetoaddress",
                    json!([1, "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]),
                )
                .unwrap();
            assert!(matches!(
                receive(&mut connection).await,
                NetworkMessage::Inv(_)
            ));
            let hash = BlockHash::from_hex(hashes[0].as_str().unwrap()).unwrap();
            connection
                .send_message(NetworkMessage::GetData(vec![InvItem {
                    inv_type: InvType::WitnessBlock,
                    hash: Hash256::from_bytes(hash.to_bytes()),
                }]))
                .await
                .unwrap();
            let NetworkMessage::Block(block) = receive(&mut connection).await else {
                panic!("expected actual block");
            };
            assert_eq!(block.block_hash(), hash);
            assert!(block.header.check_proof_of_work());
            connection
                .send_message(NetworkMessage::Ping(42))
                .await
                .unwrap();
            assert!(matches!(
                receive(&mut connection).await,
                NetworkMessage::Pong(42)
            ));
            drop(connection);
            tokio::time::timeout(Duration::from_secs(2), async {
                while state.peer_count.load(Ordering::SeqCst) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn peer_announcements_use_validation_before_publication() {
        use btc_test::TestNode;
        let dir = tempfile::tempdir().unwrap();
        let state = NodeState::new(Network::Regtest);
        let backend =
            Arc::new(NodeChainBackend::open(&dir.path().join("utxo.redb"), state.clone()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(RpcHandler::new());
        let task = tokio::spawn(P2pServer::run(
            listener,
            Network::Regtest,
            backend.clone(),
            Arc::new(PeerTable::new(state.peer_count.clone())),
            shutdown.clone(),
        ));
        let mut connection = Connection::connect_outbound_v2(address, Network::Regtest)
            .await
            .unwrap();
        connection
            .perform_handshake(Network::Regtest, 0)
            .await
            .unwrap();
        receive(&mut connection).await;
        receive(&mut connection).await;
        let mut miner = TestNode::new();
        let blocks = miner.mine_blocks(2);
        connection
            .send_message(NetworkMessage::Inv(vec![InvItem {
                inv_type: InvType::Block,
                hash: Hash256::from_bytes(blocks[1].block_hash().to_bytes()),
            }]))
            .await
            .unwrap();
        assert!(
            matches!(
                receive(&mut connection).await,
                NetworkMessage::GetHeaders(_)
            ),
            "a tip-only inv must fetch its missing ancestor before requesting bodies"
        );
        connection
            .send_message(NetworkMessage::Headers(
                blocks.iter().map(|b| b.header).collect(),
            ))
            .await
            .unwrap();
        let NetworkMessage::GetData(requests) = receive(&mut connection).await else {
            panic!("expected block request");
        };
        assert_eq!(requests.len(), 2);
        // Reversed body delivery is buffered, then fully validated in order.
        for block in blocks.iter().rev() {
            connection
                .send_message(NetworkMessage::Block(block.clone()))
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while backend.tip().unwrap().0 != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(backend.tip().unwrap().1, blocks[1].block_hash());
        // Commit via another path while this peer's requested body is in flight.
        loop {
            if matches!(
                receive(&mut connection).await,
                NetworkMessage::GetHeaders(_)
            ) {
                break;
            }
        }
        let duplicate = miner.mine_blocks(1).remove(0);
        connection
            .send_message(NetworkMessage::Headers(vec![duplicate.header]))
            .await
            .unwrap();
        loop {
            if matches!(receive(&mut connection).await, NetworkMessage::GetData(_)) {
                break;
            }
        }
        backend.submit_block(&duplicate).unwrap();
        connection
            .send_message(NetworkMessage::Block(duplicate))
            .await
            .unwrap();
        connection
            .send_message(NetworkMessage::Ping(99))
            .await
            .unwrap();
        loop {
            if matches!(receive(&mut connection).await, NetworkMessage::Pong(99)) {
                break;
            }
        }
        assert_eq!(backend.tip().unwrap().0, 3);
        let mut invalid = miner.mine_blocks(1).remove(0);
        invalid.transactions[0].outputs[0].value =
            btc_primitives::amount::Amount::from_sat(5_000_000_001);
        invalid.header.merkle_root = invalid.compute_merkle_root();
        invalid.header.nonce = 0;
        while !invalid.header.check_proof_of_work() {
            invalid.header.nonce += 1;
        }
        connection
            .send_message(NetworkMessage::Headers(vec![invalid.header]))
            .await
            .unwrap();
        loop {
            if matches!(receive(&mut connection).await, NetworkMessage::GetData(_)) {
                break;
            }
        }
        connection
            .send_message(NetworkMessage::Block(invalid.clone()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while connection.recv_message().await.is_ok() {}
        })
        .await
        .unwrap();
        assert_eq!(backend.tip().unwrap().0, 3);
        assert!(backend.block(&invalid.block_hash()).unwrap().is_none());
        shutdown.request_shutdown();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn outbound_sync_relays_after_ibd_and_resumes_after_reconnect() {
        use btc_consensus::{chain::ChainState, validation::ChainParams};
        use btc_network::discovery::PeerManager;
        use tokio::sync::RwLock;
        let dir = tempfile::tempdir().unwrap();
        let remote_state = NodeState::new(Network::Regtest);
        let local_state = NodeState::new(Network::Regtest);
        let remote = Arc::new(
            NodeChainBackend::open(&dir.path().join("remote.redb"), remote_state.clone()).unwrap(),
        );
        let local_path = dir.path().join("local.redb");
        let local = Arc::new(NodeChainBackend::open(&local_path, local_state.clone()).unwrap());
        let mine = |backend: &NodeChainBackend, count| {
            backend
                .call(
                    "generatetoaddress",
                    json!([count, "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]),
                )
                .unwrap()
        };
        mine(&remote, 20);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let remote_shutdown = Arc::new(RpcHandler::new());
        let remote_peers = Arc::new(PeerTable::new(remote_state.peer_count.clone()));
        let server = tokio::spawn(P2pServer::run(
            listener,
            Network::Regtest,
            remote.clone(),
            remote_peers.clone(),
            remote_shutdown.clone(),
        ));
        let local_peers = Arc::new(PeerTable::new(local_state.peer_count.clone()));
        let peer_manager = Arc::new(RwLock::new(PeerManager::new(Network::Regtest)));
        let params = ChainParams::from_network(Network::Regtest);
        let mut manager = crate::sync::SyncManager::with_backend(
            Network::Regtest,
            Arc::new(RwLock::new(ChainState::new(params.clone()))),
            peer_manager.clone(),
            params,
            dir.path().to_path_buf(),
            local.clone(),
        )
        .unwrap();
        manager.set_connect_peers(vec![address]);
        manager.set_peer_table(local_peers.clone());
        manager.set_node_state(local_state.clone());
        let (sender, mut notifications) = broadcast::channel(128);
        manager.set_exex_sender(sender);
        let shutdown = Arc::new(RpcHandler::new().with_chain_backend(local.clone()));
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            manager.run(task_shutdown).await;
        });
        async fn wait_tip(backend: &NodeChainBackend, height: u64) {
            tokio::time::timeout(Duration::from_secs(10), async {
                while backend.tip().unwrap().0 != height {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        wait_tip(&local, 20).await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while local_state.syncing.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(local_peers.snapshot().unwrap()[0]["inbound"], false);
        let first_id = local_peers.snapshot().unwrap()[0]["id"].clone();
        // More than the 16-body window must drain through subsequent locators.
        mine(&remote, 20);
        wait_tip(&local, 40).await;
        assert_eq!(local.tip().unwrap(), remote.tip().unwrap());
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let btc_exex::ExExNotification::BlockCommitted {
                    height: 40,
                    hash,
                    block,
                    ..
                } = notifications.recv().await.unwrap()
                {
                    assert_eq!(hash, local.tip().unwrap().1);
                    assert_eq!(block.block_hash(), hash);
                    break;
                }
            }
        })
        .await
        .unwrap();
        mine(&local, 2);
        wait_tip(&remote, 42).await;
        remote_shutdown.request_shutdown();
        server.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while local_state.peer_count.load(Ordering::SeqCst) != 0
                || peer_manager.read().await.connected_count() != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(peer_manager.read().await.connected_count(), 0);
        // While disconnected RPC can advance our durable tip. The next session
        // must use that tip, not its stale header clone/checkpoint.
        mine(&local, 3);
        let listener = TcpListener::bind(address).await.unwrap();
        let remote_shutdown = Arc::new(RpcHandler::new());
        let server = tokio::spawn(P2pServer::run(
            listener,
            Network::Regtest,
            remote.clone(),
            remote_peers,
            remote_shutdown.clone(),
        ));
        wait_tip(&remote, 45).await;
        assert_ne!(local_peers.snapshot().unwrap()[0]["id"], first_id);
        assert_eq!(local.tip().unwrap(), remote.tip().unwrap());
        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(local_state.peer_count.load(Ordering::SeqCst), 0);
        assert_eq!(peer_manager.read().await.connected_count(), 0);
        remote_shutdown.request_shutdown();
        server.await.unwrap().unwrap();
        let final_tip = local.tip().unwrap();
        drop(shutdown);
        drop(local);
        let reopened =
            NodeChainBackend::open(&local_path, NodeState::new(Network::Regtest)).unwrap();
        assert_eq!(reopened.tip().unwrap(), final_tip);
    }
}
