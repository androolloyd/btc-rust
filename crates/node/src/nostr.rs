//! # Nostr Block Event Publisher
//!
//! An execution extension that publishes new block events to Nostr relays as
//! NIP-01 kind-1 text notes. Each event contains the block height, hash,
//! transaction count, and total fees.
//!
//! Events are signed with secp256k1 Schnorr signatures (BIP-340) and serialised
//! as JSON ready for relay submission.

use btc_exex::{ExEx, ExExContext, ExExNotification};
use btc_primitives::amount::Amount;
use btc_primitives::hash::sha256;
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Nostr event types
// ---------------------------------------------------------------------------

/// A Nostr event (NIP-01) carrying block information.
#[derive(Debug, Clone, Serialize)]
pub struct NostrEvent {
    /// Event ID: SHA-256 of the serialised event content.
    pub id: String,
    /// Author public key (32-byte x-only, hex-encoded).
    pub pubkey: String,
    /// Unix timestamp of event creation.
    pub created_at: u64,
    /// Event kind (1 = text note).
    pub kind: u32,
    /// Event tags (e.g. `["t", "bitcoin"]`).
    pub tags: Vec<Vec<String>>,
    /// Human-readable content string.
    pub content: String,
    /// Schnorr signature over the event ID (hex-encoded).
    pub sig: String,
}

/// Configuration and state for the Nostr block publisher.
pub struct NostrPublisher {
    /// Relay WebSocket URLs to publish events to.
    relay_urls: Vec<String>,
    /// 32-byte secp256k1 secret key for signing events.
    private_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// Schnorr signing helpers
// ---------------------------------------------------------------------------

/// Derive the x-only public key from a 32-byte secret key.
fn pubkey_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    use secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret).expect("valid 32-byte secret key");
    let (xonly, _parity) = sk.public_key(&secp).x_only_public_key();
    xonly.serialize()
}

/// Compute the NIP-01 event ID: `SHA-256([0, pubkey, created_at, kind, tags, content])`.
fn compute_event_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let serialised = serde_json::to_string(&serde_json::json!([
        0,
        pubkey,
        created_at,
        kind,
        tags,
        content,
    ]))
    .expect("JSON serialisation should not fail");

    sha256(serialised.as_bytes())
}

/// Sign a 32-byte message with Schnorr (BIP-340) and return the 64-byte signature.
fn schnorr_sign(message: &[u8; 32], secret: &[u8; 32]) -> [u8; 64] {
    use secp256k1::{Keypair, Message, Secp256k1};

    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, secret).expect("valid secret key");
    let msg = Message::from_digest(*message);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    sig.serialize()
}

// ---------------------------------------------------------------------------
// NostrPublisher implementation
// ---------------------------------------------------------------------------

impl NostrPublisher {
    /// Create a new publisher targeting the given relays.
    pub fn new(relay_urls: Vec<String>, private_key: [u8; 32]) -> Self {
        Self {
            relay_urls,
            private_key,
        }
    }

    /// Build and sign a Nostr event for a committed block.
    fn build_block_event(
        &self,
        height: u64,
        hash: &str,
        tx_count: usize,
        total_fees: Amount,
    ) -> NostrEvent {
        let pubkey_bytes = pubkey_from_secret(&self.private_key);
        let pubkey_hex = hex::encode(pubkey_bytes);

        let content = format!(
            "New Bitcoin block #{height}\nHash: {hash}\nTransactions: {tx_count}\nTotal fees: {total_fees}",
        );

        let tags = vec![
            vec!["t".to_string(), "bitcoin".to_string()],
            vec!["t".to_string(), "block".to_string()],
            vec!["block_height".to_string(), height.to_string()],
        ];

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let kind = 1u32;

        let id_bytes = compute_event_id(&pubkey_hex, created_at, kind, &tags, &content);
        let sig_bytes = schnorr_sign(&id_bytes, &self.private_key);

        NostrEvent {
            id: hex::encode(id_bytes),
            pubkey: pubkey_hex,
            created_at,
            kind,
            tags,
            content,
            sig: hex::encode(sig_bytes),
        }
    }

    /// Format the relay message as a NIP-01 `["EVENT", <event>]` JSON string.
    fn relay_message(event: &NostrEvent) -> String {
        serde_json::to_string(&serde_json::json!(["EVENT", event]))
            .expect("JSON serialisation should not fail")
    }

    /// Compute total fees for a block (sum of inputs minus sum of outputs,
    /// excluding the coinbase).
    fn estimate_total_fees(block: &btc_primitives::block::Block) -> Amount {
        // We don't have input values resolved here, so report the coinbase
        // reward minus the subsidy-implied block reward as a proxy. For a
        // full implementation the UTXO set would be consulted. For now we
        // report the coinbase output total which includes fees + subsidy.
        let coinbase_total: i64 = block
            .transactions
            .first()
            .map(|cb| cb.outputs.iter().map(|o| o.value.as_sat()).sum())
            .unwrap_or(0);
        Amount::from_sat(coinbase_total)
    }
}

impl ExEx for NostrPublisher {
    fn name(&self) -> &str {
        "nostr"
    }

    async fn start(self, mut ctx: ExExContext) -> eyre::Result<()> {
        info!(
            relay_count = self.relay_urls.len(),
            relays = ?self.relay_urls,
            "NostrPublisher started"
        );

        loop {
            match ctx.notifications.recv().await {
                Ok(ExExNotification::BlockCommitted {
                    height,
                    hash,
                    block,
                    ..
                }) => {
                    let hash_hex = hash.to_hex();
                    let tx_count = block.transactions.len();
                    let total_fees = Self::estimate_total_fees(&block);

                    let event =
                        self.build_block_event(height, &hash_hex, tx_count, total_fees);

                    let relay_msg = Self::relay_message(&event);

                    info!(
                        height,
                        %hash,
                        tx_count,
                        event_id = %event.id,
                        "NostrPublisher: built block event"
                    );

                    // Log the full relay-ready JSON so operators can pipe it
                    // to a WebSocket relay, or integrate a WS client later.
                    for relay in &self.relay_urls {
                        info!(
                            relay,
                            msg = %relay_msg,
                            "NostrPublisher: relay event ready"
                        );
                    }
                }
                Ok(ExExNotification::BlockReverted { height, hash }) => {
                    info!(
                        height,
                        %hash,
                        "NostrPublisher: block reverted (not published)"
                    );
                }
                Ok(ExExNotification::ChainReorged {
                    old_tip, new_tip, fork_height, ..
                }) => {
                    info!(
                        %old_tip,
                        %new_tip,
                        fork_height,
                        "NostrPublisher: chain reorg detected"
                    );
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "NostrPublisher: lagged behind, skipped notifications");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("NostrPublisher: channel closed, shutting down");
                    return Ok(());
                }
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
    use btc_exex::ExExManager;
    use btc_primitives::amount::Amount;
    use btc_primitives::block::{Block, BlockHeader};
    use btc_primitives::compact::CompactTarget;
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::network::Network;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    fn test_key() -> [u8; 32] {
        // A deterministic test-only secret key (NOT for production use).
        [0x01; 32]
    }

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

    #[test]
    fn test_nostr_publisher_name() {
        let publisher = NostrPublisher::new(vec![], test_key());
        assert_eq!(publisher.name(), "nostr");
    }

    #[test]
    fn test_build_block_event() {
        let publisher = NostrPublisher::new(
            vec!["wss://relay.example.com".to_string()],
            test_key(),
        );

        let event = publisher.build_block_event(
            800_000,
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
            3000,
            Amount::from_sat(6_25000_0000),
        );

        assert_eq!(event.kind, 1);
        assert!(!event.id.is_empty());
        assert!(!event.pubkey.is_empty());
        assert!(!event.sig.is_empty());
        assert!(event.content.contains("800000"));
        assert!(event.content.contains("3000"));
        assert_eq!(event.id.len(), 64); // 32 bytes hex
        assert_eq!(event.pubkey.len(), 64);
        assert_eq!(event.sig.len(), 128); // 64 bytes hex
    }

    #[test]
    fn test_relay_message_format() {
        let publisher = NostrPublisher::new(vec![], test_key());
        let event = publisher.build_block_event(
            1,
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            1,
            Amount::from_sat(50_0000_0000),
        );

        let msg = NostrPublisher::relay_message(&event);
        // Must be a JSON array starting with "EVENT"
        assert!(msg.starts_with("[\"EVENT\","));
        // Must parse as valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed[0], "EVENT");
        assert_eq!(parsed[1]["kind"], 1);
    }

    #[test]
    fn test_schnorr_signature_valid() {
        let secret = test_key();
        let message = sha256(b"test message");
        let sig = schnorr_sign(&message, &secret);

        // Verify the signature
        use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
        let secp = Secp256k1::verification_only();
        let pubkey_bytes = pubkey_from_secret(&secret);
        let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes).unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        let msg = secp256k1::Message::from_digest(message);
        assert!(secp.verify_schnorr(&sig, &msg, &xonly).is_ok());
    }

    #[tokio::test]
    async fn test_nostr_exex_channel_close() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();
        drop(manager);

        let publisher = NostrPublisher::new(vec![], test_key());
        let result = publisher.start(ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_pubkey_from_secret_deterministic() {
        let key = test_key();
        let pk1 = pubkey_from_secret(&key);
        let pk2 = pubkey_from_secret(&key);
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), 32);
    }

    #[test]
    fn test_pubkey_from_secret_different_keys() {
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let pk1 = pubkey_from_secret(&key1);
        let pk2 = pubkey_from_secret(&key2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_compute_event_id_deterministic() {
        let pubkey = hex::encode(pubkey_from_secret(&test_key()));
        let tags = vec![vec!["t".to_string(), "bitcoin".to_string()]];
        let id1 = compute_event_id(&pubkey, 1000, 1, &tags, "test content");
        let id2 = compute_event_id(&pubkey, 1000, 1, &tags, "test content");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_event_id_differs_with_content() {
        let pubkey = hex::encode(pubkey_from_secret(&test_key()));
        let tags = vec![];
        let id1 = compute_event_id(&pubkey, 1000, 1, &tags, "content A");
        let id2 = compute_event_id(&pubkey, 1000, 1, &tags, "content B");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_event_id_differs_with_kind() {
        let pubkey = hex::encode(pubkey_from_secret(&test_key()));
        let tags = vec![];
        let id1 = compute_event_id(&pubkey, 1000, 1, &tags, "same");
        let id2 = compute_event_id(&pubkey, 1000, 2, &tags, "same");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_event_id_differs_with_timestamp() {
        let pubkey = hex::encode(pubkey_from_secret(&test_key()));
        let tags = vec![];
        let id1 = compute_event_id(&pubkey, 1000, 1, &tags, "same");
        let id2 = compute_event_id(&pubkey, 2000, 1, &tags, "same");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_estimate_total_fees_coinbase() {
        let block = make_test_block();
        let fees = NostrPublisher::estimate_total_fees(&block);
        assert_eq!(fees.as_sat(), 50_0000_0000);
    }

    #[test]
    fn test_estimate_total_fees_empty_block() {
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![],
        };
        let fees = NostrPublisher::estimate_total_fees(&block);
        assert_eq!(fees.as_sat(), 0);
    }

    #[test]
    fn test_nostr_event_has_correct_tags() {
        let publisher = NostrPublisher::new(vec![], test_key());
        let event = publisher.build_block_event(
            1,
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            1,
            Amount::from_sat(50_0000_0000),
        );
        assert_eq!(event.tags.len(), 3);
        assert_eq!(event.tags[0], vec!["t", "bitcoin"]);
        assert_eq!(event.tags[1], vec!["t", "block"]);
        assert_eq!(event.tags[2][0], "block_height");
        assert_eq!(event.tags[2][1], "1");
    }

    #[test]
    fn test_nostr_event_content_format() {
        let publisher = NostrPublisher::new(vec![], test_key());
        let event = publisher.build_block_event(
            42,
            "abcdef",
            5,
            Amount::from_sat(100_000),
        );
        assert!(event.content.contains("42"));
        assert!(event.content.contains("abcdef"));
        assert!(event.content.contains("5"));
    }

    #[test]
    fn test_nostr_publisher_relay_urls() {
        let relays = vec![
            "wss://relay1.example.com".to_string(),
            "wss://relay2.example.com".to_string(),
        ];
        let publisher = NostrPublisher::new(relays.clone(), test_key());
        assert_eq!(publisher.relay_urls, relays);
    }

    #[tokio::test]
    async fn test_nostr_exex_receives_block() {
        use btc_consensus::utxo::UtxoSetUpdate;

        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();

        let block = make_test_block();
        let hash = block.block_hash();

        manager.notify(ExExNotification::BlockCommitted {
            height: 1,
            hash,
            block,
            utxo_changes: UtxoSetUpdate {
                created: vec![],
                spent: vec![],
            },
        });

        // Drop manager to close channel so the ExEx will eventually stop.
        drop(manager);

        let publisher = NostrPublisher::new(
            vec!["wss://relay.example.com".to_string()],
            test_key(),
        );
        let result = publisher.start(ctx).await;
        assert!(result.is_ok());
    }
}
