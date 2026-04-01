//! # Runes Indexing ExEx Plugin
//!
//! An execution extension that passively indexes Runes (BIP-based fungible
//! tokens on Bitcoin) from committed blocks. It scans each transaction's outputs
//! for OP_RETURN scripts carrying the Rune protocol marker (OP_13 = 0x5d) and
//! parses the encoded runestone operations.
//!
//! Runes use a "runestone" protocol where data is embedded in an OP_RETURN
//! output. The runestone format is:
//!
//! ```text
//! OP_RETURN OP_13 <payload>
//! ```
//!
//! The payload encodes operations such as etching new runes, minting existing
//! runes, and transferring rune balances.

use crate::{ExEx, ExExContext, ExExNotification};
use btc_primitives::hash::TxHash;
use btc_primitives::script::Opcode;
use btc_primitives::transaction::Transaction;
use tokio::sync::broadcast;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The Rune protocol marker is OP_13 (0x5d), which identifies an OP_RETURN
/// output as a runestone.
const RUNE_PROTOCOL_MARKER: u8 = Opcode::OP_13 as u8;

/// OP_RETURN opcode value.
const OP_RETURN: u8 = Opcode::OP_RETURN as u8;

// ---------------------------------------------------------------------------
// RuneOperation
// ---------------------------------------------------------------------------

/// Represents the different operations that can be encoded in a runestone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuneOperation {
    /// Etch (create) a new rune with the given properties.
    Etch {
        /// Human-readable name of the rune (e.g. "UNCOMMON*GOODS").
        name: String,
        /// Single character symbol (e.g. '⧉').
        symbol: char,
        /// Total supply to etch.
        supply: u128,
    },

    /// Mint an existing rune by its ID.
    Mint {
        /// The rune ID in "block:tx_index" format.
        rune_id: String,
    },

    /// Transfer a specified amount of a rune.
    Transfer {
        /// The rune ID being transferred.
        rune_id: String,
        /// The amount being transferred.
        amount: u128,
    },
}

// ---------------------------------------------------------------------------
// RuneEntry
// ---------------------------------------------------------------------------

/// A discovered rune entry from an etching transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuneEntry {
    /// Human-readable name of the rune.
    pub name: String,
    /// Single character symbol.
    pub symbol: char,
    /// The rune ID assigned to this rune.
    pub rune_id: String,
    /// The txid of the transaction that etched this rune.
    pub txid: TxHash,
}

// ---------------------------------------------------------------------------
// Runestone parsing
// ---------------------------------------------------------------------------

/// Read a push-data item from the script at position `pos`.
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

/// Decode a LEB128-encoded u128 from the given byte slice.
/// Returns `(value, bytes_consumed)` or `None` if the encoding is invalid.
fn decode_leb128(data: &[u8]) -> Option<(u128, usize)> {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 128 {
            return None;
        }
        let value = (byte & 0x7F) as u128;
        result |= value.checked_shl(shift)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

/// Encode a u128 value as LEB128 bytes.
pub fn encode_leb128(mut value: u128) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if value == 0 {
            break;
        }
    }
    result
}

/// Tag identifiers used in the runestone payload.
///
/// These follow the Runes specification where each field is encoded as a
/// tag-value pair using LEB128 varint encoding.
mod tags {
    /// Tag for the rune name (encoded as a base-26 integer).
    pub const RUNE_NAME: u128 = 2;
    /// Tag for the symbol character.
    pub const SYMBOL: u128 = 3;
    /// Tag for the supply/amount.
    pub const AMOUNT: u128 = 4;
    /// Tag for a mint operation (rune ID encoded as block:tx).
    pub const MINT: u128 = 20;
    /// Tag for the operation type: 0=etch, 1=mint, 2=transfer.
    pub const BODY: u128 = 0;
}

/// Parse a runestone payload (after OP_RETURN OP_13) into a list of rune
/// operations.
///
/// The payload consists of LEB128-encoded tag-value pairs followed by an
/// optional body section with edicts (transfers).
fn parse_runestone_payload(payload: &[u8]) -> Vec<RuneOperation> {
    let mut ops = Vec::new();
    let mut pos = 0;

    // Collect tag-value pairs
    let mut name: Option<String> = None;
    let mut symbol: Option<char> = None;
    let mut supply: Option<u128> = None;
    let mut mint_id: Option<String> = None;

    // Track whether we've entered the body (edicts) section
    let mut in_body = false;

    while pos < payload.len() {
        let (tag, consumed) = match decode_leb128(&payload[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += consumed;

        let (value, consumed) = match decode_leb128(&payload[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += consumed;

        if tag == tags::BODY {
            // The body tag signals the start of edicts.
            // The value here is the first element of the first edict.
            in_body = true;
            // Edicts are encoded as (rune_id_block, rune_id_tx, amount, output)
            // We already consumed (tag=0, value). The value is the rune_id block delta.
            let block = value;
            // Read remaining 3 values: tx_index, amount, output
            let (tx_idx, c1) = match decode_leb128(&payload[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += c1;
            let (amount, c2) = match decode_leb128(&payload[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += c2;
            // output index (we consume it but don't need it for the operation)
            let (_output, c3) = match decode_leb128(&payload[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += c3;

            let rune_id = format!("{}:{}", block, tx_idx);
            ops.push(RuneOperation::Transfer { rune_id, amount });
            continue;
        }

        if in_body {
            // Additional edicts after the first body tag
            let block = tag; // In body mode, the "tag" is actually the block delta
            let tx_idx = value;
            let (amount, c1) = match decode_leb128(&payload[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += c1;
            let (_output, c2) = match decode_leb128(&payload[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += c2;
            let rune_id = format!("{}:{}", block, tx_idx);
            ops.push(RuneOperation::Transfer { rune_id, amount });
            continue;
        }

        match tag {
            tags::RUNE_NAME => {
                // Name is encoded as a base-26 integer; decode back to string
                name = Some(decode_rune_name(value));
            }
            tags::SYMBOL => {
                symbol = char::from_u32(value as u32);
            }
            tags::AMOUNT => {
                supply = Some(value);
            }
            tags::MINT => {
                // value encodes the rune ID as a single integer: block * 1000 + tx_index
                let block = value / 1000;
                let tx = value % 1000;
                mint_id = Some(format!("{}:{}", block, tx));
            }
            _ => {
                // Unknown tag; skip
            }
        }
    }

    // If we collected etch fields, emit an Etch operation
    if let Some(rune_name) = name {
        ops.push(RuneOperation::Etch {
            name: rune_name,
            symbol: symbol.unwrap_or('\u{29C9}'), // default ⧉
            supply: supply.unwrap_or(0),
        });
    }

    // If we collected a mint ID, emit a Mint operation
    if let Some(rune_id) = mint_id {
        ops.push(RuneOperation::Mint { rune_id });
    }

    ops
}

/// Decode a rune name from its bijective base-26 integer encoding.
///
/// Uses bijective numeration where A=1, B=2, ..., Z=26. This avoids
/// ambiguity between e.g. "A" (=1) and "AA" (=27).
fn decode_rune_name(mut value: u128) -> String {
    if value == 0 {
        return "A".to_string();
    }
    let mut chars = Vec::new();
    while value > 0 {
        value -= 1; // convert from 1-based to 0-based for this digit
        let remainder = (value % 26) as u8;
        chars.push((b'A' + remainder) as char);
        value /= 26;
    }
    chars.reverse();
    chars.into_iter().collect()
}

/// Encode a rune name string into its bijective base-26 integer representation.
///
/// Uses bijective numeration where A=1, B=2, ..., Z=26.
pub fn encode_rune_name(name: &str) -> u128 {
    let mut value: u128 = 0;
    for ch in name.chars() {
        let c = ch.to_ascii_uppercase();
        if !c.is_ascii_uppercase() {
            continue;
        }
        value = value * 26 + (c as u128 - b'A' as u128) + 1;
    }
    value
}

/// Scan a transaction's outputs for a runestone (OP_RETURN with OP_13
/// protocol marker) and parse any rune operations found.
///
/// Returns `None` if no runestone output is present, or `Some(ops)` with the
/// parsed operations.
pub fn parse_runestone(tx: &Transaction) -> Option<Vec<RuneOperation>> {
    for output in &tx.outputs {
        let script_bytes = output.script_pubkey.as_bytes();

        // A runestone output starts with OP_RETURN (0x6a) followed by OP_13 (0x5d)
        if script_bytes.len() < 2 {
            continue;
        }
        if script_bytes[0] != OP_RETURN {
            continue;
        }
        if script_bytes[1] != RUNE_PROTOCOL_MARKER {
            continue;
        }

        // The rest of the script is push-data items containing the payload
        let mut payload = Vec::new();
        let mut pos = 2; // skip OP_RETURN and OP_13
        while pos < script_bytes.len() {
            match read_push(script_bytes, pos) {
                Some((data, new_pos)) => {
                    payload.extend_from_slice(data);
                    pos = new_pos;
                }
                None => break,
            }
        }

        if payload.is_empty() {
            continue;
        }

        let ops = parse_runestone_payload(&payload);
        if !ops.is_empty() {
            return Some(ops);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Helper: build a runestone OP_RETURN script
// ---------------------------------------------------------------------------

/// Build an OP_RETURN script containing a runestone with the given LEB128
/// payload bytes.
pub fn build_runestone_script(payload: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(OP_RETURN);
    script.push(RUNE_PROTOCOL_MARKER);
    // Push the payload as a single data push
    if payload.len() <= 75 {
        script.push(payload.len() as u8);
        script.extend_from_slice(payload);
    } else if payload.len() <= 255 {
        script.push(Opcode::OP_PUSHDATA1 as u8);
        script.push(payload.len() as u8);
        script.extend_from_slice(payload);
    } else {
        script.push(Opcode::OP_PUSHDATA2 as u8);
        script.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        script.extend_from_slice(payload);
    }
    script
}

/// Build a LEB128-encoded payload for an Etch operation.
pub fn build_etch_payload(name: &str, symbol: char, supply: u128) -> Vec<u8> {
    let mut payload = Vec::new();
    // Tag: RUNE_NAME
    payload.extend_from_slice(&encode_leb128(tags::RUNE_NAME));
    payload.extend_from_slice(&encode_leb128(encode_rune_name(name)));
    // Tag: SYMBOL
    payload.extend_from_slice(&encode_leb128(tags::SYMBOL));
    payload.extend_from_slice(&encode_leb128(symbol as u128));
    // Tag: AMOUNT (supply)
    payload.extend_from_slice(&encode_leb128(tags::AMOUNT));
    payload.extend_from_slice(&encode_leb128(supply));
    payload
}

/// Build a LEB128-encoded payload for a Mint operation.
pub fn build_mint_payload(block: u128, tx_index: u128) -> Vec<u8> {
    let mut payload = Vec::new();
    // Tag: MINT (encoded as block * 1000 + tx_index)
    payload.extend_from_slice(&encode_leb128(tags::MINT));
    payload.extend_from_slice(&encode_leb128(block * 1000 + tx_index));
    payload
}

/// Build a LEB128-encoded payload for a Transfer edict.
pub fn build_transfer_payload(block: u128, tx_index: u128, amount: u128, output: u128) -> Vec<u8> {
    let mut payload = Vec::new();
    // Body tag starts the edicts section
    payload.extend_from_slice(&encode_leb128(tags::BODY));
    payload.extend_from_slice(&encode_leb128(block));
    payload.extend_from_slice(&encode_leb128(tx_index));
    payload.extend_from_slice(&encode_leb128(amount));
    payload.extend_from_slice(&encode_leb128(output));
    payload
}

// ---------------------------------------------------------------------------
// RunesExEx
// ---------------------------------------------------------------------------

/// Execution extension that indexes Runes from committed blocks.
///
/// On each `BlockCommitted` notification it scans every transaction's outputs
/// for runestone OP_RETURN scripts and parses rune operations (etch, mint,
/// transfer).
pub struct RunesExEx {
    /// Total number of runes discovered (etched) so far.
    pub rune_count: u64,
    /// Total number of rune operations observed.
    pub operation_count: u64,
}

impl RunesExEx {
    pub fn new() -> Self {
        Self {
            rune_count: 0,
            operation_count: 0,
        }
    }
}

impl Default for RunesExEx {
    fn default() -> Self {
        Self::new()
    }
}

impl ExEx for RunesExEx {
    fn name(&self) -> &str {
        "runes"
    }

    async fn start(mut self, mut ctx: ExExContext) -> eyre::Result<()> {
        info!(network = %ctx.network, "RunesExEx started");

        loop {
            match ctx.notifications.recv().await {
                Ok(notification) => match &notification {
                    ExExNotification::BlockCommitted {
                        height,
                        hash,
                        block,
                        ..
                    } => {
                        let mut block_ops = 0u64;

                        for tx in &block.transactions {
                            if let Some(ops) = parse_runestone(tx) {
                                for op in &ops {
                                    self.operation_count += 1;
                                    block_ops += 1;
                                    match op {
                                        RuneOperation::Etch {
                                            name,
                                            symbol,
                                            supply,
                                        } => {
                                            self.rune_count += 1;
                                            info!(
                                                rune_name = %name,
                                                symbol = %symbol,
                                                supply = %supply,
                                                total_runes = self.rune_count,
                                                "RunesExEx: new rune etched"
                                            );
                                        }
                                        RuneOperation::Mint { rune_id } => {
                                            info!(
                                                rune_id = %rune_id,
                                                "RunesExEx: rune mint"
                                            );
                                        }
                                        RuneOperation::Transfer { rune_id, amount } => {
                                            info!(
                                                rune_id = %rune_id,
                                                amount = %amount,
                                                "RunesExEx: rune transfer"
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        if block_ops > 0 {
                            info!(
                                height,
                                %hash,
                                block_operations = block_ops,
                                total_operations = self.operation_count,
                                total_runes = self.rune_count,
                                "RunesExEx: block processed with rune operations"
                            );
                        }
                    }
                    ExExNotification::BlockReverted { height, hash } => {
                        info!(
                            height,
                            %hash,
                            "RunesExEx: block reverted (rune state may be stale)"
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
                            "RunesExEx: chain reorg detected"
                        );
                    }
                },
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "RunesExEx: lagged behind, skipped notifications");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("RunesExEx: channel closed, shutting down");
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
    use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

    /// Build a transaction with a runestone OP_RETURN output.
    fn make_rune_tx(payload: &[u8], id_byte: u8) -> Transaction {
        let script_bytes = build_runestone_script(payload);
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([id_byte; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::p2tr(&[0xaa; 32]),
                },
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(script_bytes),
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_leb128_roundtrip() {
        for value in [0u128, 1, 127, 128, 255, 256, 16384, u128::MAX / 2] {
            let encoded = encode_leb128(value);
            let (decoded, consumed) = decode_leb128(&encoded).unwrap();
            assert_eq!(decoded, value, "LEB128 roundtrip failed for {}", value);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn test_rune_name_roundtrip() {
        for name in ["A", "B", "Z", "AA", "AB", "ZZ", "TEST", "UNCOMMONGOODS"] {
            let encoded = encode_rune_name(name);
            let decoded = decode_rune_name(encoded);
            assert_eq!(decoded, name, "Name roundtrip failed for {}", name);
        }
    }

    #[test]
    fn test_parse_etch_runestone() {
        let payload = build_etch_payload("TEST", '$', 1_000_000);
        let tx = make_rune_tx(&payload, 0x01);

        let ops = parse_runestone(&tx).expect("should find runestone");
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Etch {
                name,
                symbol,
                supply,
            } => {
                assert_eq!(name, "TEST");
                assert_eq!(*symbol, '$');
                assert_eq!(*supply, 1_000_000);
            }
            _ => panic!("expected Etch operation"),
        }
    }

    #[test]
    fn test_parse_mint_runestone() {
        let payload = build_mint_payload(840000, 1);
        let tx = make_rune_tx(&payload, 0x02);

        let ops = parse_runestone(&tx).expect("should find runestone");
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Mint { rune_id } => {
                assert_eq!(rune_id, "840000:1");
            }
            _ => panic!("expected Mint operation"),
        }
    }

    #[test]
    fn test_parse_transfer_runestone() {
        let payload = build_transfer_payload(100, 5, 50000, 0);
        let tx = make_rune_tx(&payload, 0x03);

        let ops = parse_runestone(&tx).expect("should find runestone");
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Transfer { rune_id, amount } => {
                assert_eq!(rune_id, "100:5");
                assert_eq!(*amount, 50000);
            }
            _ => panic!("expected Transfer operation"),
        }
    }

    #[test]
    fn test_no_runestone_in_regular_tx() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x04; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::p2tr(&[0xaa; 32]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        assert!(parse_runestone(&tx).is_none());
    }

    #[test]
    fn test_no_runestone_in_non_rune_op_return() {
        // OP_RETURN with some other data, not OP_13
        let mut script = Vec::new();
        script.push(OP_RETURN);
        script.push(0x04); // push 4 bytes
        script.extend_from_slice(b"test");

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x05; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        assert!(parse_runestone(&tx).is_none());
    }

    #[test]
    fn test_runes_exex_name() {
        let exex = RunesExEx::new();
        assert_eq!(exex.name(), "runes");
    }

    #[test]
    fn test_runes_exex_default() {
        let exex = RunesExEx::default();
        assert_eq!(exex.rune_count, 0);
        assert_eq!(exex.operation_count, 0);
    }

    #[tokio::test]
    async fn test_runes_exex_channel_close() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();
        drop(manager);

        let result = RunesExEx::new().start(ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_etch_with_default_symbol() {
        // Build an etch payload without a symbol tag
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::RUNE_NAME));
        payload.extend_from_slice(&encode_leb128(encode_rune_name("NOSYMBOL")));
        payload.extend_from_slice(&encode_leb128(tags::AMOUNT));
        payload.extend_from_slice(&encode_leb128(100));

        let tx = make_rune_tx(&payload, 0x06);
        let ops = parse_runestone(&tx).expect("should find runestone");
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Etch {
                name,
                symbol,
                supply,
            } => {
                assert_eq!(name, "NOSYMBOL");
                assert_eq!(*symbol, '\u{29C9}'); // default symbol
                assert_eq!(*supply, 100);
            }
            _ => panic!("expected Etch"),
        }
    }

    #[test]
    fn test_empty_payload_no_ops() {
        // OP_RETURN OP_13 but empty payload push (no data)
        let script = vec![OP_RETURN, RUNE_PROTOCOL_MARKER];
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x07; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        assert!(parse_runestone(&tx).is_none());
    }

    #[test]
    fn test_build_runestone_script_structure() {
        let payload = build_etch_payload("AB", 'X', 42);
        let script = build_runestone_script(&payload);

        // Should start with OP_RETURN OP_13
        assert_eq!(script[0], OP_RETURN);
        assert_eq!(script[1], RUNE_PROTOCOL_MARKER);
    }

    // -------------------------------------------------------------------
    // read_push edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_read_push_op_0() {
        // OP_0 pushes empty bytes
        let data = [0x00];
        let (bytes, new_pos) = read_push(&data, 0).unwrap();
        assert!(bytes.is_empty());
        assert_eq!(new_pos, 1);
    }

    #[test]
    fn test_read_push_small_push() {
        // opcode 1..=75 pushes that many bytes
        let data = [0x03, 0xAA, 0xBB, 0xCC];
        let (bytes, new_pos) = read_push(&data, 0).unwrap();
        assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(new_pos, 4);
    }

    #[test]
    fn test_read_push_small_push_truncated() {
        // opcode says 3 bytes but only 2 available
        let data = [0x03, 0xAA, 0xBB];
        assert!(read_push(&data, 0).is_none());
    }

    #[test]
    fn test_read_push_pushdata1() {
        let mut data = vec![Opcode::OP_PUSHDATA1 as u8, 0x04]; // length=4
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let (bytes, new_pos) = read_push(&data, 0).unwrap();
        assert_eq!(bytes, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(new_pos, 6);
    }

    #[test]
    fn test_read_push_pushdata1_truncated_length() {
        // OP_PUSHDATA1 but no length byte
        let data = [Opcode::OP_PUSHDATA1 as u8];
        assert!(read_push(&data, 0).is_none());
    }

    #[test]
    fn test_read_push_pushdata1_truncated_data() {
        // OP_PUSHDATA1 + length 5, but only 3 bytes of data
        let data = [Opcode::OP_PUSHDATA1 as u8, 0x05, 0x01, 0x02, 0x03];
        assert!(read_push(&data, 0).is_none());
    }

    #[test]
    fn test_read_push_pushdata2() {
        let mut data = vec![Opcode::OP_PUSHDATA2 as u8];
        data.extend_from_slice(&3u16.to_le_bytes()); // length=3
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let (bytes, new_pos) = read_push(&data, 0).unwrap();
        assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(new_pos, 6);
    }

    #[test]
    fn test_read_push_pushdata2_truncated_length() {
        // OP_PUSHDATA2 but only 1 length byte (needs 2)
        let data = [Opcode::OP_PUSHDATA2 as u8, 0x00];
        assert!(read_push(&data, 0).is_none());
    }

    #[test]
    fn test_read_push_pushdata2_truncated_data() {
        let mut data = vec![Opcode::OP_PUSHDATA2 as u8];
        data.extend_from_slice(&10u16.to_le_bytes()); // length=10
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes
        assert!(read_push(&data, 0).is_none());
    }

    #[test]
    fn test_read_push_unknown_opcode() {
        // An opcode that is not 0, not 1..75, not PUSHDATA1/2
        // e.g. OP_RETURN (0x6a) which is > 75 and not a pushdata op
        let data = [0x6a];
        assert!(read_push(&data, 0).is_none());
    }

    #[test]
    fn test_read_push_past_end() {
        let data = [0x01, 0x02];
        assert!(read_push(&data, 5).is_none());
    }

    // -------------------------------------------------------------------
    // decode_leb128 edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_decode_leb128_empty() {
        assert!(decode_leb128(&[]).is_none());
    }

    #[test]
    fn test_decode_leb128_zero() {
        let (val, consumed) = decode_leb128(&[0x00]).unwrap();
        assert_eq!(val, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_leb128_unterminated() {
        // All bytes have continuation bit set, never terminates
        let data = vec![0x80; 20]; // 20 bytes, all continuation
        assert!(decode_leb128(&data).is_none());
    }

    #[test]
    fn test_decode_leb128_shift_overflow() {
        // Create a sequence that would shift >= 128 bits
        // Each byte adds 7 bits of shift. 19 bytes = 133 bits of shift.
        // The 19th byte (shift=126) is valid. The 20th (shift=133) would overflow.
        let mut data = vec![0x80; 19]; // 19 continuation bytes
        data.push(0x01); // terminator at shift=133 -- but shift check happens before
        // Actually the check is shift >= 128, which triggers at byte index 19 (shift=133)
        // The 18th byte is index 18, shift = 18*7 = 126. Still ok.
        // The 19th byte is index 19, shift = 19*7 = 133 >= 128 -> None
        assert!(decode_leb128(&data).is_none());
    }

    // -------------------------------------------------------------------
    // encode/decode rune name edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_decode_rune_name_zero() {
        assert_eq!(decode_rune_name(0), "A");
    }

    #[test]
    fn test_encode_rune_name_empty() {
        assert_eq!(encode_rune_name(""), 0);
    }

    #[test]
    fn test_encode_rune_name_non_alpha() {
        // Non-alpha characters should be skipped
        assert_eq!(encode_rune_name("A-B"), encode_rune_name("AB"));
        assert_eq!(encode_rune_name("TEST!@#"), encode_rune_name("TEST"));
    }

    #[test]
    fn test_encode_rune_name_lowercase() {
        // Lowercase is converted to uppercase
        assert_eq!(encode_rune_name("test"), encode_rune_name("TEST"));
    }

    // -------------------------------------------------------------------
    // parse_runestone_payload edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_runestone_payload_empty() {
        let ops = parse_runestone_payload(&[]);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_parse_runestone_payload_unknown_tag() {
        // Build a payload with an unknown tag (e.g. tag=99)
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(99)); // unknown tag
        payload.extend_from_slice(&encode_leb128(42)); // value
        // Also add a known tag so the ops list isn't empty
        payload.extend_from_slice(&encode_leb128(tags::RUNE_NAME));
        payload.extend_from_slice(&encode_leb128(encode_rune_name("TEST")));
        payload.extend_from_slice(&encode_leb128(tags::AMOUNT));
        payload.extend_from_slice(&encode_leb128(100));

        let ops = parse_runestone_payload(&payload);
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Etch { name, .. } => assert_eq!(name, "TEST"),
            _ => panic!("expected Etch"),
        }
    }

    #[test]
    fn test_parse_runestone_payload_etch_without_supply() {
        // Etch with name but no AMOUNT tag -- supply defaults to 0
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::RUNE_NAME));
        payload.extend_from_slice(&encode_leb128(encode_rune_name("NOSUPPLY")));

        let ops = parse_runestone_payload(&payload);
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Etch { name, supply, .. } => {
                assert_eq!(name, "NOSUPPLY");
                assert_eq!(*supply, 0);
            }
            _ => panic!("expected Etch"),
        }
    }

    #[test]
    fn test_parse_runestone_payload_multiple_transfers() {
        // Build a payload with two edicts (transfers) in the body
        let mut payload = Vec::new();
        // First edict via BODY tag
        payload.extend_from_slice(&encode_leb128(tags::BODY)); // tag=0
        payload.extend_from_slice(&encode_leb128(100)); // block
        payload.extend_from_slice(&encode_leb128(5)); // tx_idx
        payload.extend_from_slice(&encode_leb128(1000)); // amount
        payload.extend_from_slice(&encode_leb128(0)); // output

        // Second edict (in body mode, tag=block_delta, value=tx_idx)
        payload.extend_from_slice(&encode_leb128(200)); // block
        payload.extend_from_slice(&encode_leb128(3)); // tx_idx
        payload.extend_from_slice(&encode_leb128(2000)); // amount
        payload.extend_from_slice(&encode_leb128(1)); // output

        let ops = parse_runestone_payload(&payload);
        assert_eq!(ops.len(), 2);
        match &ops[0] {
            RuneOperation::Transfer { rune_id, amount } => {
                assert_eq!(rune_id, "100:5");
                assert_eq!(*amount, 1000);
            }
            _ => panic!("expected Transfer"),
        }
        match &ops[1] {
            RuneOperation::Transfer { rune_id, amount } => {
                assert_eq!(rune_id, "200:3");
                assert_eq!(*amount, 2000);
            }
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn test_parse_runestone_payload_body_truncated_after_block() {
        // Body tag starts but missing tx_idx/amount/output
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::BODY));
        payload.extend_from_slice(&encode_leb128(100)); // block value
        // Missing tx_idx, amount, output -> should break out

        let ops = parse_runestone_payload(&payload);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_parse_runestone_payload_body_truncated_after_tx_idx() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::BODY));
        payload.extend_from_slice(&encode_leb128(100)); // block
        payload.extend_from_slice(&encode_leb128(5)); // tx_idx (consumed as first value)
        // Actually, looking at the code: tag=BODY, value=block=100. Then it reads tx_idx.
        // Wait, let me re-read: tag=0 (BODY), value is consumed. value = block (100).
        // Then reads tx_idx (5). Then needs amount -> truncated.

        let ops = parse_runestone_payload(&payload);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_parse_runestone_payload_body_truncated_after_amount() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::BODY));
        payload.extend_from_slice(&encode_leb128(100)); // block
        payload.extend_from_slice(&encode_leb128(5)); // tx_idx
        payload.extend_from_slice(&encode_leb128(1000)); // amount
        // Missing output -> should break out

        let ops = parse_runestone_payload(&payload);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_parse_runestone_payload_additional_edict_truncated() {
        // First edict succeeds, second edict truncated
        let mut payload = Vec::new();
        // First edict
        payload.extend_from_slice(&encode_leb128(tags::BODY));
        payload.extend_from_slice(&encode_leb128(100));
        payload.extend_from_slice(&encode_leb128(5));
        payload.extend_from_slice(&encode_leb128(1000));
        payload.extend_from_slice(&encode_leb128(0));
        // Second edict -- truncated after block
        payload.extend_from_slice(&encode_leb128(200));
        payload.extend_from_slice(&encode_leb128(3));
        // Missing amount and output

        let ops = parse_runestone_payload(&payload);
        // Only the first edict should be parsed
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            RuneOperation::Transfer { rune_id, amount } => {
                assert_eq!(rune_id, "100:5");
                assert_eq!(*amount, 1000);
            }
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn test_parse_runestone_payload_etch_and_mint_combined() {
        // A payload with both etch fields AND a mint tag
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::RUNE_NAME));
        payload.extend_from_slice(&encode_leb128(encode_rune_name("COMBO")));
        payload.extend_from_slice(&encode_leb128(tags::SYMBOL));
        payload.extend_from_slice(&encode_leb128('$' as u128));
        payload.extend_from_slice(&encode_leb128(tags::AMOUNT));
        payload.extend_from_slice(&encode_leb128(5000));
        payload.extend_from_slice(&encode_leb128(tags::MINT));
        payload.extend_from_slice(&encode_leb128(840000 * 1000 + 1)); // block=840000, tx=1

        let ops = parse_runestone_payload(&payload);
        // Should produce both an Etch and a Mint
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], RuneOperation::Etch { name, .. } if name == "COMBO"));
        assert!(matches!(&ops[1], RuneOperation::Mint { rune_id } if rune_id == "840000:1"));
    }

    // -------------------------------------------------------------------
    // build_runestone_script with larger payloads (OP_PUSHDATA1/2)
    // -------------------------------------------------------------------

    #[test]
    fn test_build_runestone_script_pushdata1() {
        // Payload > 75 bytes but <= 255 bytes -> OP_PUSHDATA1
        let payload = vec![0x42; 100];
        let script = build_runestone_script(&payload);
        assert_eq!(script[0], OP_RETURN);
        assert_eq!(script[1], RUNE_PROTOCOL_MARKER);
        assert_eq!(script[2], Opcode::OP_PUSHDATA1 as u8);
        assert_eq!(script[3], 100u8);
        assert_eq!(&script[4..], &payload[..]);
    }

    #[test]
    fn test_build_runestone_script_pushdata2() {
        // Payload > 255 bytes -> OP_PUSHDATA2
        let payload = vec![0x42; 300];
        let script = build_runestone_script(&payload);
        assert_eq!(script[0], OP_RETURN);
        assert_eq!(script[1], RUNE_PROTOCOL_MARKER);
        assert_eq!(script[2], Opcode::OP_PUSHDATA2 as u8);
        let len = u16::from_le_bytes([script[3], script[4]]);
        assert_eq!(len, 300);
        assert_eq!(&script[5..], &payload[..]);
    }

    // -------------------------------------------------------------------
    // parse_runestone with OP_PUSHDATA1 payloads
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_runestone_with_pushdata1_payload() {
        // Build a script manually with OP_PUSHDATA1
        let etch_payload = build_etch_payload("BIGNAME", 'B', 999);
        // Pad to > 75 bytes
        let mut big_payload = etch_payload.clone();
        // Add unknown tags to pad
        while big_payload.len() <= 75 {
            big_payload.extend_from_slice(&encode_leb128(99)); // unknown tag
            big_payload.extend_from_slice(&encode_leb128(0));  // value
        }

        let mut script = Vec::new();
        script.push(OP_RETURN);
        script.push(RUNE_PROTOCOL_MARKER);
        script.push(Opcode::OP_PUSHDATA1 as u8);
        script.push(big_payload.len() as u8);
        script.extend_from_slice(&big_payload);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xAA; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let ops = parse_runestone(&tx).expect("should find runestone");
        assert!(ops.iter().any(|op| matches!(op, RuneOperation::Etch { name, .. } if name == "BIGNAME")));
    }

    // -------------------------------------------------------------------
    // parse_runestone with too-short scripts
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_runestone_script_too_short() {
        // Script with only 1 byte
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xBB; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(vec![OP_RETURN]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        assert!(parse_runestone(&tx).is_none());
    }

    // -------------------------------------------------------------------
    // RuneEntry struct
    // -------------------------------------------------------------------

    #[test]
    fn test_rune_entry_construction() {
        let entry = RuneEntry {
            name: "TEST".to_string(),
            symbol: '$',
            rune_id: "840000:1".to_string(),
            txid: TxHash::from_bytes([0x01; 32]),
        };
        assert_eq!(entry.name, "TEST");
        assert_eq!(entry.symbol, '$');
        assert_eq!(entry.rune_id, "840000:1");
    }

    // -------------------------------------------------------------------
    // RuneOperation equality
    // -------------------------------------------------------------------

    #[test]
    fn test_rune_operation_equality() {
        let op1 = RuneOperation::Etch {
            name: "A".into(),
            symbol: 'X',
            supply: 100,
        };
        let op2 = op1.clone();
        assert_eq!(op1, op2);

        let op3 = RuneOperation::Mint {
            rune_id: "1:0".into(),
        };
        assert_ne!(op1, op3);
    }

    // -------------------------------------------------------------------
    // RunesExEx: BlockReverted and ChainReorged branches
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_runes_exex_block_reverted() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();

        manager.notify(ExExNotification::BlockReverted {
            height: 10,
            hash: BlockHash::from_bytes([0xcc; 32]),
        });

        drop(manager);
        let result = RunesExEx::new().start(ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_runes_exex_chain_reorged() {
        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();

        manager.notify(ExExNotification::ChainReorged {
            old_tip: BlockHash::from_bytes([0x01; 32]),
            new_tip: BlockHash::from_bytes([0x02; 32]),
            fork_height: 5,
            reverted: vec![BlockHash::from_bytes([0x01; 32])],
            committed: vec![(6, BlockHash::from_bytes([0x02; 32]))],
        });

        drop(manager);
        let result = RunesExEx::new().start(ctx).await;
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // RunesExEx: processes block with rune ops and counts them
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_runes_exex_processes_etch_mint_transfer() {
        use btc_consensus::utxo::{UtxoEntry, UtxoSetUpdate};
        use btc_primitives::block::{Block, BlockHeader};
        use btc_primitives::compact::CompactTarget;
        use btc_primitives::hash::BlockHash;

        let manager = ExExManager::new(Network::Regtest);
        let ctx = manager.subscribe();

        // Three rune txs in one block
        let etch_tx = make_rune_tx(&build_etch_payload("ALPHA", 'A', 1000), 0xE1);
        let mint_tx = make_rune_tx(&build_mint_payload(100, 0), 0xE2);
        let transfer_tx = make_rune_tx(&build_transfer_payload(100, 0, 500, 1), 0xE3);

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1231006505,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![etch_tx, mint_tx, transfer_tx],
        };
        let hash = block.block_hash();

        let utxo_changes = UtxoSetUpdate {
            created: vec![],
            spent: vec![],
        };

        manager.notify(ExExNotification::BlockCommitted {
            height: 1,
            hash,
            block,
            utxo_changes,
        });

        drop(manager);
        let result = RunesExEx::new().start(ctx).await;
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // Malformed LEB128 in payload
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_runestone_payload_malformed_leb128() {
        // A single byte with continuation bit set but nothing after
        let payload = vec![0x80];
        let ops = parse_runestone_payload(&payload);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_parse_runestone_payload_tag_ok_value_malformed() {
        // Valid tag (e.g. 2 for RUNE_NAME), but value is truncated
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_leb128(tags::RUNE_NAME)); // tag = 2
        payload.push(0x80); // start of value, continuation set, but no more bytes
        let ops = parse_runestone_payload(&payload);
        assert!(ops.is_empty());
    }

    // -------------------------------------------------------------------
    // LEB128 edge: large valid value
    // -------------------------------------------------------------------

    #[test]
    fn test_leb128_large_value() {
        let value = u128::MAX / 4;
        let encoded = encode_leb128(value);
        let (decoded, consumed) = decode_leb128(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(consumed, encoded.len());
    }
}
