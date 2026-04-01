//! # ZMQ-Compatible Notifications
//!
//! A TCP-based pub/sub notification system compatible with Bitcoin Core's ZMQ
//! interface. Lightning nodes (LND, CLN, etc.) and Electrum backends rely on
//! this interface to receive real-time block and transaction notifications.
//!
//! Rather than linking against the C libzmq library (supply-chain risk), we
//! implement the notification framing directly over TCP. Each notification is
//! a simple length-prefixed message consisting of:
//!
//!   - **topic** (variable-length string, e.g. `"hashblock"`)
//!   - **body** (variable-length bytes — a 32-byte hash or a full serialized block/tx)
//!   - **sequence** (4-byte little-endian u32 counter, incremented per topic)
//!
//! Subscribers connect to the TCP port and receive a continuous stream of
//! notifications for the topics they subscribed to during the handshake.
//!
//! ## Supported topics (matching Bitcoin Core)
//!
//! | Topic        | Body                          |
//! |-------------|-------------------------------|
//! | `hashblock` | 32-byte block hash            |
//! | `hashtx`    | 32-byte txid                  |
//! | `rawblock`  | Full serialized block         |
//! | `rawtx`     | Full serialized transaction   |
//! | `sequence`  | Block connect/disconnect info |

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use btc_exex::{ExExContext, ExExNotification};
use btc_primitives::encode::Encodable;

// ---------------------------------------------------------------------------
// Topics
// ---------------------------------------------------------------------------

/// The set of notification topics that this publisher supports, matching
/// Bitcoin Core's ZMQ topics.
pub const TOPIC_HASHBLOCK: &str = "hashblock";
pub const TOPIC_HASHTX: &str = "hashtx";
pub const TOPIC_RAWBLOCK: &str = "rawblock";
pub const TOPIC_RAWTX: &str = "rawtx";
pub const TOPIC_SEQUENCE: &str = "sequence";

/// All known topics.
pub const ALL_TOPICS: &[&str] = &[
    TOPIC_HASHBLOCK,
    TOPIC_HASHTX,
    TOPIC_RAWBLOCK,
    TOPIC_RAWTX,
    TOPIC_SEQUENCE,
];

/// Validate that a topic string is one of the known topics.
pub fn is_valid_topic(topic: &str) -> bool {
    ALL_TOPICS.contains(&topic)
}

// ---------------------------------------------------------------------------
// ZmqConfig
// ---------------------------------------------------------------------------

/// Configuration for the ZMQ notification publisher.
#[derive(Debug, Clone)]
pub struct ZmqConfig {
    /// Whether ZMQ notifications are enabled.
    pub enabled: bool,
    /// TCP port to listen on (default: 28332, matching Bitcoin Core).
    pub port: u16,
    /// Which topics to publish. An empty vec means all topics.
    pub topics: Vec<String>,
}

impl Default for ZmqConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 28332,
            topics: Vec::new(),
        }
    }
}

impl ZmqConfig {
    /// Create a new config with all topics enabled on the default port.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a config that enables ZMQ on the given port with all topics.
    pub fn enabled_on(port: u16) -> Self {
        Self {
            enabled: true,
            port,
            topics: Vec::new(),
        }
    }

    /// Return the effective set of topics (all topics if none were explicitly listed).
    pub fn effective_topics(&self) -> HashSet<String> {
        if self.topics.is_empty() {
            ALL_TOPICS.iter().map(|s| (*s).to_string()).collect()
        } else {
            self.topics
                .iter()
                .filter(|t| is_valid_topic(t))
                .cloned()
                .collect()
        }
    }
}

// ---------------------------------------------------------------------------
// ZmqMessage — the wire format for a single notification
// ---------------------------------------------------------------------------

/// A single notification message sent over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZmqMessage {
    /// The topic name (e.g. "hashblock").
    pub topic: String,
    /// The body bytes (hash, serialized block, etc.).
    pub body: Vec<u8>,
    /// Monotonically increasing sequence number (per-topic).
    pub sequence: u32,
}

impl ZmqMessage {
    /// Serialize the message into a length-prefixed wire format.
    ///
    /// Wire format:
    /// ```text
    /// [topic_len: u16 LE] [topic: bytes]
    /// [body_len:  u32 LE] [body:  bytes]
    /// [sequence:  u32 LE]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let topic_bytes = self.topic.as_bytes();
        let total = 2 + topic_bytes.len() + 4 + self.body.len() + 4;
        let mut buf = Vec::with_capacity(total);

        // topic length (u16 LE) + topic
        buf.extend_from_slice(&(topic_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(topic_bytes);

        // body length (u32 LE) + body
        buf.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.body);

        // sequence (u32 LE)
        buf.extend_from_slice(&self.sequence.to_le_bytes());

        buf
    }

    /// Deserialize from the wire format produced by `to_bytes`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let mut pos = 0;

        // topic length
        let topic_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + topic_len > data.len() {
            return None;
        }
        let topic = String::from_utf8(data[pos..pos + topic_len].to_vec()).ok()?;
        pos += topic_len;

        // body length
        if pos + 4 > data.len() {
            return None;
        }
        let body_len = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as usize;
        pos += 4;

        if pos + body_len > data.len() {
            return None;
        }
        let body = data[pos..pos + body_len].to_vec();
        pos += body_len;

        // sequence
        if pos + 4 > data.len() {
            return None;
        }
        let sequence = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);

        Some(Self {
            topic,
            body,
            sequence,
        })
    }
}

// ---------------------------------------------------------------------------
// SequenceCounters
// ---------------------------------------------------------------------------

/// Per-topic monotonic sequence counters.
#[derive(Debug)]
pub struct SequenceCounters {
    counters: HashMap<String, AtomicU32>,
}

impl SequenceCounters {
    /// Create a new set of counters for the given topics.
    pub fn new(topics: &HashSet<String>) -> Self {
        let mut counters = HashMap::new();
        for topic in topics {
            counters.insert(topic.clone(), AtomicU32::new(0));
        }
        Self { counters }
    }

    /// Get and increment the counter for the given topic.
    pub fn next(&self, topic: &str) -> u32 {
        if let Some(counter) = self.counters.get(topic) {
            counter.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Get the current value without incrementing.
    pub fn current(&self, topic: &str) -> u32 {
        if let Some(counter) = self.counters.get(topic) {
            counter.load(Ordering::Relaxed)
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// ZmqPublisher
// ---------------------------------------------------------------------------

/// The ZMQ notification publisher.
///
/// Listens on a TCP port, accepts subscriber connections, and pushes
/// notifications derived from ExEx chain events.
pub struct ZmqPublisher {
    /// TCP port to listen on.
    port: u16,
    /// Set of topics this publisher will emit.
    topics: HashSet<String>,
}

impl ZmqPublisher {
    /// Create a new publisher with the given port and topic set.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            topics: ALL_TOPICS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Create a publisher from a config.
    pub fn from_config(config: &ZmqConfig) -> Self {
        Self {
            port: config.port,
            topics: config.effective_topics(),
        }
    }

    /// Return the port this publisher listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return the set of topics this publisher handles.
    pub fn topics(&self) -> &HashSet<String> {
        &self.topics
    }

    /// Check if a topic is enabled on this publisher.
    pub fn has_topic(&self, topic: &str) -> bool {
        self.topics.contains(topic)
    }

    /// Convert an ExEx notification into zero or more ZMQ messages.
    ///
    /// This is the core mapping from internal chain events to the ZMQ wire
    /// format that downstream consumers (Lightning nodes, etc.) expect.
    pub fn notification_to_messages(
        notification: &ExExNotification,
        topics: &HashSet<String>,
        counters: &SequenceCounters,
    ) -> Vec<ZmqMessage> {
        let mut messages = Vec::new();

        match notification {
            ExExNotification::BlockCommitted {
                hash, block, ..
            } => {
                // hashblock: 32-byte block hash
                if topics.contains(TOPIC_HASHBLOCK) {
                    messages.push(ZmqMessage {
                        topic: TOPIC_HASHBLOCK.to_string(),
                        body: hash.as_bytes().to_vec(),
                        sequence: counters.next(TOPIC_HASHBLOCK),
                    });
                }

                // rawblock: full serialized block
                if topics.contains(TOPIC_RAWBLOCK) {
                    let mut raw = Vec::new();
                    block
                        .encode(&mut raw)
                        .expect("encoding block to vec should not fail");
                    messages.push(ZmqMessage {
                        topic: TOPIC_RAWBLOCK.to_string(),
                        body: raw,
                        sequence: counters.next(TOPIC_RAWBLOCK),
                    });
                }

                // hashtx: 32-byte txid for each transaction in the block
                if topics.contains(TOPIC_HASHTX) {
                    for tx in &block.transactions {
                        messages.push(ZmqMessage {
                            topic: TOPIC_HASHTX.to_string(),
                            body: tx.txid().as_bytes().to_vec(),
                            sequence: counters.next(TOPIC_HASHTX),
                        });
                    }
                }

                // rawtx: full serialized tx for each transaction in the block
                if topics.contains(TOPIC_RAWTX) {
                    for tx in &block.transactions {
                        let mut raw = Vec::new();
                        tx.encode(&mut raw)
                            .expect("encoding tx to vec should not fail");
                        messages.push(ZmqMessage {
                            topic: TOPIC_RAWTX.to_string(),
                            body: raw,
                            sequence: counters.next(TOPIC_RAWTX),
                        });
                    }
                }

                // sequence: block connect notification
                if topics.contains(TOPIC_SEQUENCE) {
                    // Format: 32-byte hash + 1 byte label ('C' = connect)
                    let mut body = Vec::with_capacity(33);
                    body.extend_from_slice(hash.as_bytes());
                    body.push(b'C'); // Connect
                    messages.push(ZmqMessage {
                        topic: TOPIC_SEQUENCE.to_string(),
                        body,
                        sequence: counters.next(TOPIC_SEQUENCE),
                    });
                }
            }

            ExExNotification::BlockReverted { hash, .. } => {
                // sequence: block disconnect notification
                if topics.contains(TOPIC_SEQUENCE) {
                    let mut body = Vec::with_capacity(33);
                    body.extend_from_slice(hash.as_bytes());
                    body.push(b'D'); // Disconnect
                    messages.push(ZmqMessage {
                        topic: TOPIC_SEQUENCE.to_string(),
                        body,
                        sequence: counters.next(TOPIC_SEQUENCE),
                    });
                }
            }

            ExExNotification::ChainReorged {
                reverted,
                committed,
                ..
            } => {
                // Emit disconnect notifications for reverted blocks, then
                // connect notifications for committed blocks (in order).
                if topics.contains(TOPIC_SEQUENCE) {
                    for hash in reverted {
                        let mut body = Vec::with_capacity(33);
                        body.extend_from_slice(hash.as_bytes());
                        body.push(b'D');
                        messages.push(ZmqMessage {
                            topic: TOPIC_SEQUENCE.to_string(),
                            body,
                            sequence: counters.next(TOPIC_SEQUENCE),
                        });
                    }
                    for (_height, hash) in committed {
                        let mut body = Vec::with_capacity(33);
                        body.extend_from_slice(hash.as_bytes());
                        body.push(b'C');
                        messages.push(ZmqMessage {
                            topic: TOPIC_SEQUENCE.to_string(),
                            body,
                            sequence: counters.next(TOPIC_SEQUENCE),
                        });
                    }
                }
            }
        }

        messages
    }

    /// Run the publisher: listen for TCP connections and push notifications
    /// from the ExEx event stream.
    ///
    /// This method runs forever (until the ExEx channel closes or the task is
    /// cancelled). It should be spawned as a tokio task.
    pub async fn run(self, mut ctx: ExExContext) -> eyre::Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(port = self.port, "ZMQ publisher listening");

        let topics = Arc::new(self.topics);
        let counters = Arc::new(SequenceCounters::new(&topics));

        // Internal broadcast for fan-out to connected subscribers.
        let (msg_tx, _) = broadcast::channel::<ZmqMessage>(4096);

        // Spawn the acceptor task — accepts new TCP connections and pipes
        // messages to them.
        let msg_tx_clone = msg_tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!(%addr, "ZMQ subscriber connected");
                        let rx = msg_tx_clone.subscribe();
                        tokio::spawn(handle_subscriber(stream, rx));
                    }
                    Err(e) => {
                        error!(error = %e, "ZMQ accept error");
                    }
                }
            }
        });

        // Main loop: consume ExEx notifications and broadcast ZMQ messages.
        loop {
            match ctx.notifications.recv().await {
                Ok(notification) => {
                    let messages = Self::notification_to_messages(
                        &notification,
                        &topics,
                        &counters,
                    );
                    for msg in messages {
                        debug!(
                            topic = %msg.topic,
                            seq = msg.sequence,
                            body_len = msg.body.len(),
                            "ZMQ publishing"
                        );
                        // Ignore send errors (no subscribers connected).
                        let _ = msg_tx.send(msg);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "ZMQ publisher lagged behind ExEx notifications");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("ZMQ publisher: ExEx channel closed, shutting down");
                    return Ok(());
                }
            }
        }
    }
}

/// Handle a single subscriber TCP connection.
///
/// Reads messages from the internal broadcast channel and writes them to the
/// TCP stream. Exits when the stream errors or the broadcast channel closes.
async fn handle_subscriber(
    mut stream: TcpStream,
    mut rx: broadcast::Receiver<ZmqMessage>,
) {
    loop {
        match rx.recv().await {
            Ok(msg) => {
                let bytes = msg.to_bytes();
                // Write a 4-byte length prefix so the subscriber can frame messages.
                let len = (bytes.len() as u32).to_le_bytes();
                if let Err(e) = stream.write_all(&len).await {
                    debug!(error = %e, "ZMQ subscriber write error (length)");
                    return;
                }
                if let Err(e) = stream.write_all(&bytes).await {
                    debug!(error = %e, "ZMQ subscriber write error (body)");
                    return;
                }
                if let Err(e) = stream.flush().await {
                    debug!(error = %e, "ZMQ subscriber flush error");
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "ZMQ subscriber lagged, some notifications dropped");
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("ZMQ subscriber: broadcast channel closed");
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
    use btc_primitives::amount::Amount;
    use btc_primitives::block::{Block, BlockHeader};
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_test_block() -> Block {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase],
        }
    }

    fn make_utxo_update() -> UtxoSetUpdate {
        let entry = (
            OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            UtxoEntry {
                txout: TxOut {
                    value: Amount::from_sat(1000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
                },
                height: 0,
                is_coinbase: false,
            },
        );
        UtxoSetUpdate {
            created: vec![entry],
            spent: vec![],
        }
    }

    fn all_topics_set() -> HashSet<String> {
        ALL_TOPICS.iter().map(|s| (*s).to_string()).collect()
    }

    // -----------------------------------------------------------------------
    // ZmqPublisher construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_publisher_new() {
        let pub_ = ZmqPublisher::new(28332);
        assert_eq!(pub_.port(), 28332);
        assert_eq!(pub_.topics().len(), ALL_TOPICS.len());
        assert!(pub_.has_topic(TOPIC_HASHBLOCK));
        assert!(pub_.has_topic(TOPIC_HASHTX));
        assert!(pub_.has_topic(TOPIC_RAWBLOCK));
        assert!(pub_.has_topic(TOPIC_RAWTX));
        assert!(pub_.has_topic(TOPIC_SEQUENCE));
    }

    #[test]
    fn test_publisher_from_config_default() {
        let config = ZmqConfig::default();
        let pub_ = ZmqPublisher::from_config(&config);
        assert_eq!(pub_.port(), 28332);
        assert_eq!(pub_.topics().len(), ALL_TOPICS.len());
    }

    #[test]
    fn test_publisher_from_config_specific_topics() {
        let config = ZmqConfig {
            enabled: true,
            port: 29000,
            topics: vec!["hashblock".to_string(), "rawtx".to_string()],
        };
        let pub_ = ZmqPublisher::from_config(&config);
        assert_eq!(pub_.port(), 29000);
        assert_eq!(pub_.topics().len(), 2);
        assert!(pub_.has_topic(TOPIC_HASHBLOCK));
        assert!(pub_.has_topic(TOPIC_RAWTX));
        assert!(!pub_.has_topic(TOPIC_HASHTX));
        assert!(!pub_.has_topic(TOPIC_RAWBLOCK));
        assert!(!pub_.has_topic(TOPIC_SEQUENCE));
    }

    #[test]
    fn test_publisher_from_config_invalid_topics_filtered() {
        let config = ZmqConfig {
            enabled: true,
            port: 29000,
            topics: vec![
                "hashblock".to_string(),
                "bogus".to_string(),
                "rawtx".to_string(),
            ],
        };
        let pub_ = ZmqPublisher::from_config(&config);
        assert_eq!(pub_.topics().len(), 2);
        assert!(pub_.has_topic(TOPIC_HASHBLOCK));
        assert!(pub_.has_topic(TOPIC_RAWTX));
    }

    // -----------------------------------------------------------------------
    // Topic validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_valid_topic() {
        assert!(is_valid_topic("hashblock"));
        assert!(is_valid_topic("hashtx"));
        assert!(is_valid_topic("rawblock"));
        assert!(is_valid_topic("rawtx"));
        assert!(is_valid_topic("sequence"));
        assert!(!is_valid_topic("invalid"));
        assert!(!is_valid_topic(""));
        assert!(!is_valid_topic("HASHBLOCK"));
    }

    // -----------------------------------------------------------------------
    // Topic filtering
    // -----------------------------------------------------------------------

    #[test]
    fn test_topic_filtering_only_hashblock() {
        let topics: HashSet<String> = [TOPIC_HASHBLOCK.to_string()].into_iter().collect();
        let counters = SequenceCounters::new(&topics);

        let block = make_test_block();
        let hash = block.block_hash();
        let notification = ExExNotification::BlockCommitted {
            height: 1,
            hash,
            block,
            utxo_changes: make_utxo_update(),
        };

        let messages =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // Should only produce hashblock, not rawblock/hashtx/rawtx/sequence.
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, TOPIC_HASHBLOCK);
        assert_eq!(messages[0].body, hash.as_bytes().to_vec());
    }

    #[test]
    fn test_topic_filtering_only_sequence() {
        let topics: HashSet<String> = [TOPIC_SEQUENCE.to_string()].into_iter().collect();
        let counters = SequenceCounters::new(&topics);

        let block = make_test_block();
        let hash = block.block_hash();
        let notification = ExExNotification::BlockCommitted {
            height: 1,
            hash,
            block,
            utxo_changes: make_utxo_update(),
        };

        let messages =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, TOPIC_SEQUENCE);
        // Connect notification: 32-byte hash + 'C'
        assert_eq!(messages[0].body.len(), 33);
        assert_eq!(*messages[0].body.last().unwrap(), b'C');
    }

    // -----------------------------------------------------------------------
    // Notification conversion: BlockCommitted
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_committed_produces_all_messages() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);

        let block = make_test_block();
        let hash = block.block_hash();
        let notification = ExExNotification::BlockCommitted {
            height: 42,
            hash,
            block: block.clone(),
            utxo_changes: make_utxo_update(),
        };

        let messages =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // 1 hashblock + 1 rawblock + 1 hashtx (1 tx) + 1 rawtx (1 tx) + 1 sequence = 5
        assert_eq!(messages.len(), 5);

        // Verify topic order: hashblock, rawblock, hashtx, rawtx, sequence
        assert_eq!(messages[0].topic, TOPIC_HASHBLOCK);
        assert_eq!(messages[1].topic, TOPIC_RAWBLOCK);
        assert_eq!(messages[2].topic, TOPIC_HASHTX);
        assert_eq!(messages[3].topic, TOPIC_RAWTX);
        assert_eq!(messages[4].topic, TOPIC_SEQUENCE);

        // hashblock body is the 32-byte block hash
        assert_eq!(messages[0].body.len(), 32);
        assert_eq!(messages[0].body, hash.as_bytes().to_vec());

        // rawblock body should be non-empty and decodable
        assert!(!messages[1].body.is_empty());

        // hashtx body is a 32-byte txid
        assert_eq!(messages[2].body.len(), 32);

        // rawtx body should be non-empty
        assert!(!messages[3].body.is_empty());

        // sequence body: 32-byte hash + 'C'
        assert_eq!(messages[4].body.len(), 33);
        assert_eq!(*messages[4].body.last().unwrap(), b'C');
    }

    // -----------------------------------------------------------------------
    // Notification conversion: BlockReverted
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_reverted_produces_sequence_disconnect() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);

        let hash = BlockHash::from_bytes([0xab; 32]);
        let notification = ExExNotification::BlockReverted { height: 100, hash };

        let messages =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // BlockReverted only produces a sequence disconnect notification.
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, TOPIC_SEQUENCE);
        assert_eq!(messages[0].body.len(), 33);
        assert_eq!(messages[0].body[..32], *hash.as_bytes());
        assert_eq!(*messages[0].body.last().unwrap(), b'D');
    }

    // -----------------------------------------------------------------------
    // Notification conversion: ChainReorged
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_reorg_produces_disconnect_then_connect() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);

        let old_tip = BlockHash::from_bytes([0x01; 32]);
        let new_tip = BlockHash::from_bytes([0x02; 32]);
        let reverted_hash = BlockHash::from_bytes([0x03; 32]);
        let committed_hash = BlockHash::from_bytes([0x04; 32]);

        let notification = ExExNotification::ChainReorged {
            old_tip,
            new_tip,
            fork_height: 50,
            reverted: vec![reverted_hash],
            committed: vec![(51, committed_hash)],
        };

        let messages =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // 1 disconnect + 1 connect = 2 sequence messages
        assert_eq!(messages.len(), 2);

        // First: disconnect of reverted block
        assert_eq!(messages[0].topic, TOPIC_SEQUENCE);
        assert_eq!(messages[0].body[..32], *reverted_hash.as_bytes());
        assert_eq!(*messages[0].body.last().unwrap(), b'D');

        // Second: connect of committed block
        assert_eq!(messages[1].topic, TOPIC_SEQUENCE);
        assert_eq!(messages[1].body[..32], *committed_hash.as_bytes());
        assert_eq!(*messages[1].body.last().unwrap(), b'C');
    }

    // -----------------------------------------------------------------------
    // Sequence numbering
    // -----------------------------------------------------------------------

    #[test]
    fn test_sequence_numbers_increment() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);

        let block = make_test_block();
        let hash = block.block_hash();
        let notification = ExExNotification::BlockCommitted {
            height: 1,
            hash,
            block: block.clone(),
            utxo_changes: make_utxo_update(),
        };

        // First batch
        let messages1 =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // Second batch — sequence numbers should be higher
        let messages2 =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // hashblock: first was 0, second should be 1
        let hb1 = messages1.iter().find(|m| m.topic == TOPIC_HASHBLOCK).unwrap();
        let hb2 = messages2.iter().find(|m| m.topic == TOPIC_HASHBLOCK).unwrap();
        assert_eq!(hb1.sequence, 0);
        assert_eq!(hb2.sequence, 1);

        // rawblock: first was 0, second should be 1
        let rb1 = messages1.iter().find(|m| m.topic == TOPIC_RAWBLOCK).unwrap();
        let rb2 = messages2.iter().find(|m| m.topic == TOPIC_RAWBLOCK).unwrap();
        assert_eq!(rb1.sequence, 0);
        assert_eq!(rb2.sequence, 1);
    }

    #[test]
    fn test_sequence_numbers_independent_per_topic() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);

        // Emit multiple hashblock increments via a loop.
        for _ in 0..5 {
            counters.next(TOPIC_HASHBLOCK);
        }
        // hashblock should be at 5 now
        assert_eq!(counters.current(TOPIC_HASHBLOCK), 5);

        // Other topics should still be at 0
        assert_eq!(counters.current(TOPIC_HASHTX), 0);
        assert_eq!(counters.current(TOPIC_RAWBLOCK), 0);
        assert_eq!(counters.current(TOPIC_RAWTX), 0);
        assert_eq!(counters.current(TOPIC_SEQUENCE), 0);
    }

    #[test]
    fn test_sequence_counter_unknown_topic() {
        let topics: HashSet<String> = [TOPIC_HASHBLOCK.to_string()].into_iter().collect();
        let counters = SequenceCounters::new(&topics);

        // Unknown topic returns 0 and doesn't panic
        assert_eq!(counters.next("bogus"), 0);
        assert_eq!(counters.current("bogus"), 0);
    }

    // -----------------------------------------------------------------------
    // ZmqMessage wire format
    // -----------------------------------------------------------------------

    #[test]
    fn test_zmq_message_roundtrip() {
        let msg = ZmqMessage {
            topic: "hashblock".to_string(),
            body: vec![0xab; 32],
            sequence: 42,
        };

        let bytes = msg.to_bytes();
        let decoded = ZmqMessage::from_bytes(&bytes).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_zmq_message_roundtrip_empty_body() {
        let msg = ZmqMessage {
            topic: "test".to_string(),
            body: vec![],
            sequence: 0,
        };

        let bytes = msg.to_bytes();
        let decoded = ZmqMessage::from_bytes(&bytes).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_zmq_message_roundtrip_large_body() {
        let msg = ZmqMessage {
            topic: "rawblock".to_string(),
            body: vec![0xff; 1_000_000],
            sequence: u32::MAX,
        };

        let bytes = msg.to_bytes();
        let decoded = ZmqMessage::from_bytes(&bytes).expect("should decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_zmq_message_from_bytes_too_short() {
        assert!(ZmqMessage::from_bytes(&[]).is_none());
        assert!(ZmqMessage::from_bytes(&[0x01]).is_none());
    }

    #[test]
    fn test_zmq_message_from_bytes_truncated_topic() {
        // Says topic is 10 bytes but only 2 bytes follow
        let data = [0x0a, 0x00, 0x41, 0x42];
        assert!(ZmqMessage::from_bytes(&data).is_none());
    }

    // -----------------------------------------------------------------------
    // ZmqConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let config = ZmqConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.port, 28332);
        assert!(config.topics.is_empty());
    }

    #[test]
    fn test_config_enabled_on() {
        let config = ZmqConfig::enabled_on(29000);
        assert!(config.enabled);
        assert_eq!(config.port, 29000);
    }

    #[test]
    fn test_config_effective_topics_empty_means_all() {
        let config = ZmqConfig::default();
        let effective = config.effective_topics();
        assert_eq!(effective.len(), ALL_TOPICS.len());
        for topic in ALL_TOPICS {
            assert!(effective.contains(*topic));
        }
    }

    #[test]
    fn test_zmq_config_new() {
        let config = ZmqConfig::new();
        assert!(!config.enabled);
        assert_eq!(config.port, 28332);
    }

    #[test]
    fn test_zmq_config_clone() {
        let config = ZmqConfig::enabled_on(29000);
        let config2 = config.clone();
        assert_eq!(config2.port, 29000);
        assert!(config2.enabled);
    }

    #[test]
    fn test_zmq_config_debug() {
        let config = ZmqConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("ZmqConfig"));
    }

    #[test]
    fn test_publisher_has_topic_false() {
        let config = ZmqConfig {
            enabled: true,
            port: 28332,
            topics: vec!["hashblock".to_string()],
        };
        let pub_ = ZmqPublisher::from_config(&config);
        assert!(!pub_.has_topic(TOPIC_HASHTX));
    }

    #[test]
    fn test_zmq_message_debug() {
        let msg = ZmqMessage {
            topic: "test".to_string(),
            body: vec![0x01],
            sequence: 0,
        };
        let debug = format!("{:?}", msg);
        assert!(debug.contains("ZmqMessage"));
    }

    #[test]
    fn test_zmq_message_clone() {
        let msg = ZmqMessage {
            topic: "hashblock".to_string(),
            body: vec![0xab; 32],
            sequence: 42,
        };
        let msg2 = msg.clone();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_zmq_message_from_bytes_truncated_body() {
        // topic_len=4, topic="test", body_len=100 but not enough bytes
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(b"test");
        data.extend_from_slice(&100u32.to_le_bytes()); // claims 100 body bytes
        data.extend_from_slice(&[0u8; 10]); // only 10 bytes
        assert!(ZmqMessage::from_bytes(&data).is_none());
    }

    #[test]
    fn test_zmq_message_from_bytes_truncated_sequence() {
        // topic + body present but sequence truncated
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(b"test");
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 2]); // 2 byte body
        data.extend_from_slice(&[0u8; 2]); // only 2 of 4 sequence bytes
        assert!(ZmqMessage::from_bytes(&data).is_none());
    }

    #[test]
    fn test_zmq_message_wire_format_details() {
        let msg = ZmqMessage {
            topic: "ab".to_string(),
            body: vec![0x01, 0x02, 0x03],
            sequence: 7,
        };
        let bytes = msg.to_bytes();
        // topic_len: 2 bytes LE = [2, 0]
        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], 0);
        // topic: "ab"
        assert_eq!(&bytes[2..4], b"ab");
        // body_len: 4 bytes LE = [3, 0, 0, 0]
        assert_eq!(bytes[4], 3);
        assert_eq!(bytes[5], 0);
        assert_eq!(bytes[6], 0);
        assert_eq!(bytes[7], 0);
        // body
        assert_eq!(&bytes[8..11], &[1, 2, 3]);
        // sequence: 4 bytes LE = [7, 0, 0, 0]
        assert_eq!(bytes[11], 7);
        assert_eq!(bytes[12], 0);
    }

    #[test]
    fn test_sequence_counters_multiple_increments() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);
        assert_eq!(counters.next(TOPIC_HASHBLOCK), 0);
        assert_eq!(counters.next(TOPIC_HASHBLOCK), 1);
        assert_eq!(counters.next(TOPIC_HASHBLOCK), 2);
        assert_eq!(counters.current(TOPIC_HASHBLOCK), 3);
    }

    #[test]
    fn test_config_effective_topics_filters_invalid() {
        let config = ZmqConfig {
            enabled: true,
            port: 28332,
            topics: vec![
                "hashblock".to_string(),
                "fakeTopic".to_string(),
            ],
        };
        let effective = config.effective_topics();
        assert_eq!(effective.len(), 1);
        assert!(effective.contains("hashblock"));
    }

    // -----------------------------------------------------------------------
    // Integration: block with multiple transactions
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_with_multiple_txs() {
        let topics = all_topics_set();
        let counters = SequenceCounters::new(&topics);

        let tx1 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let tx2 = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![tx1, tx2],
        };

        let hash = block.block_hash();
        let notification = ExExNotification::BlockCommitted {
            height: 10,
            hash,
            block,
            utxo_changes: make_utxo_update(),
        };

        let messages =
            ZmqPublisher::notification_to_messages(&notification, &topics, &counters);

        // 1 hashblock + 1 rawblock + 2 hashtx + 2 rawtx + 1 sequence = 7
        assert_eq!(messages.len(), 7);

        // Count per topic
        let hashblock_count = messages.iter().filter(|m| m.topic == TOPIC_HASHBLOCK).count();
        let rawblock_count = messages.iter().filter(|m| m.topic == TOPIC_RAWBLOCK).count();
        let hashtx_count = messages.iter().filter(|m| m.topic == TOPIC_HASHTX).count();
        let rawtx_count = messages.iter().filter(|m| m.topic == TOPIC_RAWTX).count();
        let sequence_count = messages.iter().filter(|m| m.topic == TOPIC_SEQUENCE).count();

        assert_eq!(hashblock_count, 1);
        assert_eq!(rawblock_count, 1);
        assert_eq!(hashtx_count, 2);
        assert_eq!(rawtx_count, 2);
        assert_eq!(sequence_count, 1);

        // The two hashtx messages should have different txids
        let hashtx_msgs: Vec<_> = messages
            .iter()
            .filter(|m| m.topic == TOPIC_HASHTX)
            .collect();
        assert_ne!(hashtx_msgs[0].body, hashtx_msgs[1].body);

        // The hashtx sequence numbers should be 0 and 1
        assert_eq!(hashtx_msgs[0].sequence, 0);
        assert_eq!(hashtx_msgs[1].sequence, 1);
    }
}
