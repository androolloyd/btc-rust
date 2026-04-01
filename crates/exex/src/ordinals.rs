//! # Ordinals / Inscription Indexing ExEx Plugin
//!
//! An execution extension that passively indexes Ordinals inscriptions from
//! committed blocks. It scans each transaction's taproot witness data for the
//! inscription envelope pattern (`OP_FALSE OP_IF ... OP_ENDIF`) and extracts
//! the content type and body.

use crate::{ExEx, ExExContext, ExExNotification};
use btc_primitives::hash::TxHash;
use btc_primitives::script::Opcode;
use btc_primitives::transaction::Transaction;
use tokio::sync::broadcast;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// InscriptionData
// ---------------------------------------------------------------------------

/// Parsed inscription content extracted from a taproot witness envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InscriptionData {
    /// MIME content type (e.g. "text/plain", "image/png").
    pub content_type: String,
    /// Raw content body bytes.
    pub content_body: Vec<u8>,
    /// The txid of the transaction containing this inscription.
    pub txid: TxHash,
    /// The inscription ID formatted as `<txid>i<index>` where index is the
    /// input index that carried the envelope.
    pub inscription_id: String,
}

// ---------------------------------------------------------------------------
// Envelope parsing
// ---------------------------------------------------------------------------

/// Ordinals inscription envelope marker bytes.
/// The envelope lives inside a tapscript witness item and follows the pattern:
///
/// ```text
/// OP_FALSE (0x00)  OP_IF (0x63)
///   <push "ord">
///   OP_1 (0x51)  <push content-type>
///   OP_0 (0x00)  <push body chunk>*
/// OP_ENDIF (0x68)
/// ```
const OP_FALSE: u8 = Opcode::OP_0 as u8; // 0x00
const OP_IF: u8 = Opcode::OP_IF as u8; // 0x63
const OP_ENDIF: u8 = Opcode::OP_ENDIF as u8; // 0x68

/// Try to extract an inscription from a single witness item (the tapscript).
///
/// Returns `Some(InscriptionData)` if the envelope is found, `None` otherwise.
pub fn parse_inscription_from_witness_item(
    data: &[u8],
    txid: TxHash,
    input_index: usize,
) -> Option<InscriptionData> {
    // We need at least: OP_FALSE OP_IF <push "ord"> ...  OP_ENDIF
    // Scan for the OP_FALSE OP_IF pattern.
    let envelope_start = find_envelope_start(data)?;
    let body_data = &data[envelope_start..];

    // Walk the envelope to extract content-type and body.
    parse_envelope(body_data, txid, input_index)
}

/// Locate the start of an inscription envelope: OP_FALSE (0x00) followed by
/// OP_IF (0x63).
fn find_envelope_start(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    for i in 0..data.len() - 1 {
        if data[i] == OP_FALSE && data[i + 1] == OP_IF {
            return Some(i);
        }
    }
    None
}

/// Read a push-data item starting at `pos` in `data`.
/// Returns `(bytes, new_pos)` or `None` if the data is malformed.
fn read_push(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    if pos >= data.len() {
        return None;
    }
    let opcode = data[pos];
    if opcode == 0 {
        // OP_0 pushes empty bytes
        return Some((&[], pos + 1));
    }
    if (1..=75).contains(&opcode) {
        let len = opcode as usize;
        let end = pos + 1 + len;
        if end > data.len() {
            return None;
        }
        return Some((&data[pos + 1..end], end));
    }
    if opcode == Opcode::OP_PUSHDATA1 as u8 {
        if pos + 2 > data.len() {
            return None;
        }
        let len = data[pos + 1] as usize;
        let end = pos + 2 + len;
        if end > data.len() {
            return None;
        }
        return Some((&data[pos + 2..end], end));
    }
    if opcode == Opcode::OP_PUSHDATA2 as u8 {
        if pos + 3 > data.len() {
            return None;
        }
        let len = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
        let end = pos + 3 + len;
        if end > data.len() {
            return None;
        }
        return Some((&data[pos + 3..end], end));
    }
    None
}

/// Parse the inscription envelope body after the OP_FALSE OP_IF.
/// Expected structure:
///   OP_FALSE OP_IF
///     <push "ord">              — protocol tag
///     OP_1 <push content_type>  — content type field (tag 1)
///     OP_0 <push body>          — body field (tag 0), may repeat
///   OP_ENDIF
fn parse_envelope(data: &[u8], txid: TxHash, input_index: usize) -> Option<InscriptionData> {
    if data.len() < 5 {
        return None;
    }
    // Skip OP_FALSE OP_IF
    let mut pos = 2;

    // Read the "ord" protocol marker
    let (marker, new_pos) = read_push(data, pos)?;
    if marker != b"ord" {
        return None;
    }
    pos = new_pos;

    let mut content_type: Option<String> = None;
    let mut body_parts: Vec<Vec<u8>> = Vec::new();

    // Parse tag/value pairs until OP_ENDIF
    while pos < data.len() {
        let tag_byte = data[pos];

        if tag_byte == OP_ENDIF {
            break;
        }

        // Tag 1 (OP_1 = 0x51): content type
        if tag_byte == Opcode::OP_1 as u8 {
            pos += 1;
            let (ct_data, new_pos) = read_push(data, pos)?;
            content_type = Some(String::from_utf8_lossy(ct_data).into_owned());
            pos = new_pos;
            continue;
        }

        // Tag 0 (OP_0 = 0x00): body chunk
        if tag_byte == OP_FALSE {
            pos += 1;
            let (body_data, new_pos) = read_push(data, pos)?;
            body_parts.push(body_data.to_vec());
            pos = new_pos;
            continue;
        }

        // Unknown tag — try to skip by reading a push
        pos += 1;
        if let Some((_, new_pos)) = read_push(data, pos) {
            pos = new_pos;
        } else {
            break;
        }
    }

    let content_type = content_type.unwrap_or_default();
    let content_body: Vec<u8> = body_parts.into_iter().flatten().collect();
    let inscription_id = format!("{}i{}", txid.to_hex(), input_index);

    Some(InscriptionData {
        content_type,
        content_body,
        txid,
        inscription_id,
    })
}

// ---------------------------------------------------------------------------
// Scan a transaction for inscriptions
// ---------------------------------------------------------------------------

/// Scan all witness items of a transaction for inscription envelopes.
pub fn scan_transaction_for_inscriptions(tx: &Transaction) -> Vec<InscriptionData> {
    let txid = tx.txid();
    let mut inscriptions = Vec::new();

    for (input_idx, witness) in tx.witness.iter().enumerate() {
        for item in witness.iter() {
            if let Some(inscription) =
                parse_inscription_from_witness_item(item, txid, input_idx)
            {
                inscriptions.push(inscription);
            }
        }
    }

    inscriptions
}

// ---------------------------------------------------------------------------
// OrdinalsExEx
// ---------------------------------------------------------------------------

/// Execution extension that indexes Ordinals inscriptions from committed blocks.
///
/// On each `BlockCommitted` notification it scans every transaction's witness
/// data for inscription envelopes and logs each discovery.
pub struct OrdinalsExEx {
    /// Total number of inscriptions discovered so far.
    pub inscription_count: u64,
}

impl OrdinalsExEx {
    pub fn new() -> Self {
        Self {
            inscription_count: 0,
        }
    }
}

impl Default for OrdinalsExEx {
    fn default() -> Self {
        Self::new()
    }
}

impl ExEx for OrdinalsExEx {
    fn name(&self) -> &str {
        "ordinals"
    }

    async fn start(mut self, mut ctx: ExExContext) -> eyre::Result<()> {
        info!(network = %ctx.network, "OrdinalsExEx started");

        loop {
            match ctx.notifications.recv().await {
                Ok(notification) => match &notification {
                    ExExNotification::BlockCommitted {
                        height,
                        hash,
                        block,
                        ..
                    } => {
                        let mut block_inscriptions = 0u64;

                        for tx in &block.transactions {
                            let found = scan_transaction_for_inscriptions(tx);
                            for inscription in &found {
                                self.inscription_count += 1;
                                block_inscriptions += 1;
                                info!(
                                    inscription_id = %inscription.inscription_id,
                                    content_type = %inscription.content_type,
                                    content_len = inscription.content_body.len(),
                                    total_count = self.inscription_count,
                                    "OrdinalsExEx: new inscription found"
                                );
                            }
                        }

                        if block_inscriptions > 0 {
                            info!(
                                height,
                                %hash,
                                block_inscriptions,
                                total_inscriptions = self.inscription_count,
                                "OrdinalsExEx: block processed with inscriptions"
                            );
                        }
                    }
                    ExExNotification::BlockReverted { height, hash } => {
                        info!(
                            height,
                            %hash,
                            "OrdinalsExEx: block reverted (inscription state may be stale)"
                        );
                    }
                    ExExNotification::ChainReorged {
                        old_tip,
                        new_tip,
                        fork_height,
                        ..
                    } => {
                        info!(
                            %old_tip,
                            %new_tip,
                            fork_height,
                            "OrdinalsExEx: chain reorg detected"
                        );
                    }
                },
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "OrdinalsExEx: lagged behind, skipped notifications");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("OrdinalsExEx: channel closed, shutting down");
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
    use crate::ExExManager;
    use btc_primitives::amount::Amount;
    use btc_primitives::hash::TxHash;
    use btc_primitives::network::Network;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

    /// Build a witness item containing an inscription envelope.
    fn make_inscription_witness_item(content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();

        // OP_FALSE OP_IF
        data.push(OP_FALSE);
        data.push(OP_IF);

        // Push "ord" (3 bytes)
        data.push(3u8); // push 3 bytes
        data.extend_from_slice(b"ord");

        // OP_1 (content type tag)
        data.push(Opcode::OP_1 as u8);

        // Push content type
        let ct_bytes = content_type.as_bytes();
        data.push(ct_bytes.len() as u8);
        data.extend_from_slice(ct_bytes);

        // OP_0 (body tag)
        data.push(OP_FALSE);

        // Push body
        if body.len() <= 75 {
            data.push(body.len() as u8);
            data.extend_from_slice(body);
        } else {
            data.push(Opcode::OP_PUSHDATA1 as u8);
            data.push(body.len() as u8);
            data.extend_from_slice(body);
        }

        // OP_ENDIF
        data.push(OP_ENDIF);

        data
    }

    /// Build a test transaction with an inscription in the witness.
    fn make_inscription_tx(content_type: &str, body: &[u8], id_byte: u8) -> Transaction {
        let witness_item = make_inscription_witness_item(content_type, body);
        let witness = Witness::from_items(vec![
            vec![0x01; 64], // fake signature
            witness_item,   // tapscript with inscription
        ]);

        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::p2tr(&[0xaa; 32]),
            }],
            witness: vec![witness],
            lock_time: 0,
        }
    }

    #[test]
    fn test_detect_inscription_in_witness() {
        let tx = make_inscription_tx("text/plain", b"Hello, Ordinals!", 0x01);
        let inscriptions = scan_transaction_for_inscriptions(&tx);

        assert_eq!(inscriptions.len(), 1);
        let insc = &inscriptions[0];
        assert_eq!(insc.content_type, "text/plain");
        assert_eq!(insc.content_body, b"Hello, Ordinals!");
        assert_eq!(insc.txid, tx.txid());
        assert!(insc.inscription_id.ends_with("i0"));
    }

    #[test]
    fn test_extract_image_content_type() {
        let body = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic bytes
        let tx = make_inscription_tx("image/png", &body, 0x02);
        let inscriptions = scan_transaction_for_inscriptions(&tx);

        assert_eq!(inscriptions.len(), 1);
        assert_eq!(inscriptions[0].content_type, "image/png");
        assert_eq!(inscriptions[0].content_body, body);
    }

    #[test]
    fn test_no_inscription_in_regular_witness() {
        let witness = Witness::from_items(vec![
            vec![0x01; 64], // just a signature
            vec![0x02; 33], // just a pubkey
        ]);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x03; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::p2tr(&[0xaa; 32]),
            }],
            witness: vec![witness],
            lock_time: 0,
        };

        let inscriptions = scan_transaction_for_inscriptions(&tx);
        assert!(inscriptions.is_empty());
    }

    #[test]
    fn test_no_inscription_in_legacy_tx() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x04; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00; 10]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let inscriptions = scan_transaction_for_inscriptions(&tx);
        assert!(inscriptions.is_empty());
    }

    #[test]
    fn test_inscription_id_format() {
        let tx = make_inscription_tx("text/plain", b"test", 0x05);
        let inscriptions = scan_transaction_for_inscriptions(&tx);
        let expected_id = format!("{}i0", tx.txid().to_hex());
        assert_eq!(inscriptions[0].inscription_id, expected_id);
    }

    #[test]
    fn test_parse_envelope_missing_ord_marker() {
        // Build a witness item with OP_FALSE OP_IF but wrong marker
        let mut data = Vec::new();
        data.push(OP_FALSE);
        data.push(OP_IF);
        data.push(3u8);
        data.extend_from_slice(b"xyz"); // not "ord"
        data.push(OP_ENDIF);

        let result = parse_inscription_from_witness_item(
            &data,
            TxHash::from_bytes([0xaa; 32]),
            0,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_body_inscription() {
        let tx = make_inscription_tx("text/plain", b"", 0x06);
        let inscriptions = scan_transaction_for_inscriptions(&tx);

        assert_eq!(inscriptions.len(), 1);
        assert_eq!(inscriptions[0].content_type, "text/plain");
        assert!(inscriptions[0].content_body.is_empty());
    }

    #[tokio::test]
    async fn test_ordinals_exex_channel_close() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();
        drop(manager);

        let result = OrdinalsExEx::new().start(ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_ordinals_exex_name() {
        let exex = OrdinalsExEx::new();
        assert_eq!(exex.name(), "ordinals");
    }

    #[test]
    fn test_ordinals_exex_default() {
        let exex = OrdinalsExEx::default();
        assert_eq!(exex.inscription_count, 0);
    }
}
