//! AssumeUTXO snapshot loading.
//!
//! This module provides the ability to load a serialized UTXO set snapshot from
//! disk and populate the persistent storage with it.  This enables fast node
//! bootstrap: the node loads a UTXO snapshot at a known block height and begins
//! syncing from that height immediately.
//!
//! # Snapshot format
//!
//! The snapshot file is a simple binary format:
//!
//! ```text
//! [snapshot_height: u64 LE]
//! [block_hash: 32 bytes]
//! [entry_count: u64 LE]
//! [entries...]
//! ```
//!
//! Each entry is:
//!
//! ```text
//! [txid: 32 bytes]
//! [vout: u32 LE]
//! [height: u64 LE]
//! [is_coinbase: u8 (0 or 1)]
//! [value: i64 LE]
//! [script_len: u32 LE]
//! [script_pubkey: script_len bytes]
//! ```

use std::io::{self, Read, BufReader};
use std::path::Path;

use btc_primitives::amount::Amount;
use btc_primitives::hash::{BlockHash, TxHash};
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, TxOut};
use thiserror::Error;
use tracing::info;

use crate::traits::{Database, DbTxMut, StorageError};

/// A single entry in a UTXO snapshot file.
#[derive(Debug, Clone)]
pub struct UtxoSnapshotEntry {
    /// The outpoint (txid + vout) identifying this UTXO.
    pub outpoint: OutPoint,
    /// The transaction output (value + script_pubkey).
    pub txout: TxOut,
    /// Block height at which this UTXO was created.
    pub height: u64,
    /// Whether the creating transaction was a coinbase.
    pub is_coinbase: bool,
}

/// Metadata from a snapshot file header.
#[derive(Debug, Clone)]
pub struct SnapshotMetadata {
    /// The block height at which the snapshot was taken.
    pub height: u64,
    /// The block hash at the snapshot height.
    pub block_hash: BlockHash,
    /// The number of UTXO entries in the snapshot.
    pub entry_count: u64,
}

/// Errors that can occur when loading a UTXO snapshot.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("snapshot file is too short to contain header")]
    TruncatedHeader,

    #[error("snapshot entry {index} is truncated")]
    TruncatedEntry { index: u64 },

    #[error("snapshot entry {index} has script length {len} exceeding maximum {max}")]
    ScriptTooLarge { index: u64, len: u32, max: u32 },
}

/// Maximum script size in a snapshot entry (consensus limit + margin).
const MAX_SNAPSHOT_SCRIPT_SIZE: u32 = 100_000;

/// Read a `u64` in little-endian from a reader.
fn read_u64_le<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Read a `u32` in little-endian from a reader.
fn read_u32_le<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read an `i64` in little-endian from a reader.
fn read_i64_le<R: Read>(r: &mut R) -> io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

/// Read a 32-byte hash from a reader.
fn read_hash<R: Read>(r: &mut R) -> io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read the snapshot header from a reader.
pub fn read_snapshot_header<R: Read>(reader: &mut R) -> Result<SnapshotMetadata, SnapshotError> {
    let height = read_u64_le(reader).map_err(|_| SnapshotError::TruncatedHeader)?;
    let hash_bytes = read_hash(reader).map_err(|_| SnapshotError::TruncatedHeader)?;
    let entry_count = read_u64_le(reader).map_err(|_| SnapshotError::TruncatedHeader)?;

    Ok(SnapshotMetadata {
        height,
        block_hash: BlockHash::from_bytes(hash_bytes),
        entry_count,
    })
}

/// Read a single UTXO entry from a reader.
pub fn read_snapshot_entry<R: Read>(
    reader: &mut R,
    index: u64,
) -> Result<UtxoSnapshotEntry, SnapshotError> {
    let txid_bytes = read_hash(reader)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;
    let vout = read_u32_le(reader)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;
    let height = read_u64_le(reader)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;

    let mut coinbase_byte = [0u8; 1];
    reader
        .read_exact(&mut coinbase_byte)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;
    let is_coinbase = coinbase_byte[0] != 0;

    let value = read_i64_le(reader)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;
    let script_len = read_u32_le(reader)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;

    if script_len > MAX_SNAPSHOT_SCRIPT_SIZE {
        return Err(SnapshotError::ScriptTooLarge {
            index,
            len: script_len,
            max: MAX_SNAPSHOT_SCRIPT_SIZE,
        });
    }

    let mut script_bytes = vec![0u8; script_len as usize];
    reader
        .read_exact(&mut script_bytes)
        .map_err(|_| SnapshotError::TruncatedEntry { index })?;

    Ok(UtxoSnapshotEntry {
        outpoint: OutPoint::new(TxHash::from_bytes(txid_bytes), vout),
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        },
        height,
        is_coinbase,
    })
}

/// Load a UTXO snapshot from `path` into the given database.
///
/// Returns the snapshot metadata (height, hash, entry count) on success.
/// The database will contain all UTXOs from the snapshot and the best block
/// will be set to the snapshot height and hash.
///
/// # Errors
///
/// Returns `SnapshotError` if the file is missing, truncated, or a database
/// write fails.
pub fn load_utxo_snapshot<DB: Database>(
    path: &Path,
    db: &DB,
) -> Result<SnapshotMetadata, SnapshotError> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    let metadata = read_snapshot_header(&mut reader)?;

    info!(
        height = metadata.height,
        hash = %metadata.block_hash,
        entries = metadata.entry_count,
        "loading UTXO snapshot"
    );

    // Load entries in batches to avoid holding a single huge transaction.
    const BATCH_SIZE: u64 = 10_000;
    let mut loaded: u64 = 0;

    while loaded < metadata.entry_count {
        let batch_end = (loaded + BATCH_SIZE).min(metadata.entry_count);
        let tx = db.tx_mut()?;

        for i in loaded..batch_end {
            let entry = read_snapshot_entry(&mut reader, i)?;
            tx.put_utxo(&entry.outpoint, &entry.txout)?;

            // Also store metadata (height + is_coinbase) under a companion key,
            // matching PersistentUtxoSet's convention.
            let meta_outpoint = OutPoint::new(
                entry.outpoint.txid,
                entry.outpoint.vout | 0x8000_0000,
            );
            let meta_txout = TxOut {
                value: Amount::from_sat(entry.height as i64),
                script_pubkey: ScriptBuf::from_bytes(vec![entry.is_coinbase as u8]),
            };
            tx.put_utxo(&meta_outpoint, &meta_txout)?;
        }

        tx.set_best_block(metadata.height, &metadata.block_hash)?;
        tx.commit()?;

        loaded = batch_end;

        if loaded % 100_000 == 0 || loaded == metadata.entry_count {
            info!(
                loaded,
                total = metadata.entry_count,
                "snapshot loading progress"
            );
        }
    }

    info!(
        height = metadata.height,
        entries = metadata.entry_count,
        "UTXO snapshot loaded successfully"
    );

    Ok(metadata)
}

/// Write a UTXO snapshot entry to a writer (for creating snapshot files).
pub fn write_snapshot_entry<W: io::Write>(
    writer: &mut W,
    entry: &UtxoSnapshotEntry,
) -> io::Result<()> {
    writer.write_all(entry.outpoint.txid.as_bytes())?;
    writer.write_all(&entry.outpoint.vout.to_le_bytes())?;
    writer.write_all(&entry.height.to_le_bytes())?;
    writer.write_all(&[entry.is_coinbase as u8])?;
    writer.write_all(&entry.txout.value.as_sat().to_le_bytes())?;
    let script_bytes = entry.txout.script_pubkey.as_bytes();
    writer.write_all(&(script_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(script_bytes)?;
    Ok(())
}

/// Write a snapshot header to a writer.
pub fn write_snapshot_header<W: io::Write>(
    writer: &mut W,
    metadata: &SnapshotMetadata,
) -> io::Result<()> {
    writer.write_all(&metadata.height.to_le_bytes())?;
    writer.write_all(metadata.block_hash.as_bytes())?;
    writer.write_all(&metadata.entry_count.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_test_entry(vout: u32, height: u64) -> UtxoSnapshotEntry {
        UtxoSnapshotEntry {
            outpoint: OutPoint::new(TxHash::from_bytes([0xaa; 32]), vout),
            txout: TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            },
            height,
            is_coinbase: vout == 0,
        }
    }

    #[test]
    fn test_snapshot_roundtrip_header() {
        let metadata = SnapshotMetadata {
            height: 840_000,
            block_hash: BlockHash::from_bytes([0xbb; 32]),
            entry_count: 42,
        };

        let mut buf = Vec::new();
        write_snapshot_header(&mut buf, &metadata).unwrap();

        let mut cursor = Cursor::new(&buf);
        let read_meta = read_snapshot_header(&mut cursor).unwrap();

        assert_eq!(read_meta.height, 840_000);
        assert_eq!(read_meta.block_hash, BlockHash::from_bytes([0xbb; 32]));
        assert_eq!(read_meta.entry_count, 42);
    }

    #[test]
    fn test_snapshot_roundtrip_entry() {
        let entry = make_test_entry(0, 500_000);

        let mut buf = Vec::new();
        write_snapshot_entry(&mut buf, &entry).unwrap();

        let mut cursor = Cursor::new(&buf);
        let read_entry = read_snapshot_entry(&mut cursor, 0).unwrap();

        assert_eq!(read_entry.outpoint, entry.outpoint);
        assert_eq!(read_entry.txout.value, entry.txout.value);
        assert_eq!(
            read_entry.txout.script_pubkey.as_bytes(),
            entry.txout.script_pubkey.as_bytes()
        );
        assert_eq!(read_entry.height, entry.height);
        assert_eq!(read_entry.is_coinbase, entry.is_coinbase);
    }

    #[test]
    fn test_snapshot_roundtrip_multiple_entries() {
        let entries = vec![
            make_test_entry(0, 100),
            make_test_entry(1, 200),
            make_test_entry(2, 300),
        ];

        let metadata = SnapshotMetadata {
            height: 300,
            block_hash: BlockHash::from_bytes([0xcc; 32]),
            entry_count: entries.len() as u64,
        };

        let mut buf = Vec::new();
        write_snapshot_header(&mut buf, &metadata).unwrap();
        for entry in &entries {
            write_snapshot_entry(&mut buf, entry).unwrap();
        }

        let mut cursor = Cursor::new(&buf);
        let read_meta = read_snapshot_header(&mut cursor).unwrap();
        assert_eq!(read_meta.entry_count, 3);

        for (i, expected) in entries.iter().enumerate() {
            let read_entry = read_snapshot_entry(&mut cursor, i as u64).unwrap();
            assert_eq!(read_entry.outpoint, expected.outpoint);
            assert_eq!(read_entry.height, expected.height);
            assert_eq!(read_entry.is_coinbase, expected.is_coinbase);
        }
    }

    #[test]
    fn test_truncated_header() {
        let buf = vec![0u8; 10]; // too short for header (need 48 bytes)
        let mut cursor = Cursor::new(&buf);
        let result = read_snapshot_header(&mut cursor);
        assert!(matches!(result, Err(SnapshotError::TruncatedHeader)));
    }

    #[test]
    fn test_truncated_entry() {
        let buf = vec![0u8; 10]; // too short for an entry
        let mut cursor = Cursor::new(&buf);
        let result = read_snapshot_entry(&mut cursor, 0);
        assert!(matches!(
            result,
            Err(SnapshotError::TruncatedEntry { index: 0 })
        ));
    }

    #[test]
    fn test_script_too_large() {
        let entry = UtxoSnapshotEntry {
            outpoint: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
            txout: TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00; 10]),
            },
            height: 100,
            is_coinbase: false,
        };

        // Write entry normally but tamper with the script length
        let mut buf = Vec::new();
        buf.extend_from_slice(entry.outpoint.txid.as_bytes()); // txid
        buf.extend_from_slice(&entry.outpoint.vout.to_le_bytes()); // vout
        buf.extend_from_slice(&entry.height.to_le_bytes()); // height
        buf.push(0); // is_coinbase
        buf.extend_from_slice(&entry.txout.value.as_sat().to_le_bytes()); // value
        buf.extend_from_slice(&(MAX_SNAPSHOT_SCRIPT_SIZE + 1).to_le_bytes()); // script_len (too big)

        let mut cursor = Cursor::new(&buf);
        let result = read_snapshot_entry(&mut cursor, 0);
        assert!(matches!(
            result,
            Err(SnapshotError::ScriptTooLarge { index: 0, .. })
        ));
    }

    #[test]
    fn test_snapshot_error_display() {
        let err = SnapshotError::TruncatedHeader;
        assert_eq!(
            err.to_string(),
            "snapshot file is too short to contain header"
        );

        let err = SnapshotError::TruncatedEntry { index: 5 };
        assert!(err.to_string().contains("5"));

        let err = SnapshotError::ScriptTooLarge {
            index: 3,
            len: 200_000,
            max: 100_000,
        };
        assert!(err.to_string().contains("200000"));
    }

    #[test]
    fn test_coinbase_flag_roundtrip() {
        // Non-coinbase
        let entry = UtxoSnapshotEntry {
            outpoint: OutPoint::new(TxHash::from_bytes([0x11; 32]), 1),
            txout: TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00]),
            },
            height: 50,
            is_coinbase: false,
        };
        let mut buf = Vec::new();
        write_snapshot_entry(&mut buf, &entry).unwrap();
        let mut cursor = Cursor::new(&buf);
        let read = read_snapshot_entry(&mut cursor, 0).unwrap();
        assert!(!read.is_coinbase);

        // Coinbase
        let entry2 = UtxoSnapshotEntry {
            is_coinbase: true,
            ..entry
        };
        let mut buf2 = Vec::new();
        write_snapshot_entry(&mut buf2, &entry2).unwrap();
        let mut cursor2 = Cursor::new(&buf2);
        let read2 = read_snapshot_entry(&mut cursor2, 0).unwrap();
        assert!(read2.is_coinbase);
    }
}
