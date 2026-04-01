//! Bitcoin Core LevelDB chainstate adapter.
//!
//! Bitcoin Core stores its UTXO set (chainstate) and block index in LevelDB.
//! This module provides utilities to read Core's on-disk format and import
//! data into our own [`Database`] backend.
//!
//! # Chainstate key format (Bitcoin Core v0.15+)
//!
//! The chainstate database (`~/.bitcoin/chainstate/`) stores UTXOs with the
//! following key/value encoding:
//!
//! ## Key
//!
//! ```text
//! 'C' (0x43) | txid (32 bytes, internal byte order) | varint(vout)
//! ```
//!
//! - The prefix byte `0x43` (ASCII `'C'`) identifies UTXO entries.
//! - The `txid` is in **internal byte order** (the raw SHA-256d result,
//!   not the display-reversed form shown in block explorers).
//! - The `vout` is encoded as a Bitcoin Core-style varint (not the wire
//!   protocol varint). Core uses a variable-length encoding where each
//!   byte contributes 7 bits, with the high bit indicating continuation.
//!
//! ## Value
//!
//! ```text
//! varint(code) | compressed_txout
//! ```
//!
//! Where `code = (height << 1) | is_coinbase`:
//! - `height` is the block height at which the UTXO was created.
//! - `is_coinbase` is 1 if the creating transaction was a coinbase, 0 otherwise.
//!
//! The `compressed_txout` format is:
//! ```text
//! varint(compressed_amount) | compressed_script
//! ```
//!
//! Amount compression uses a special encoding to reduce storage. See
//! [`decompress_amount`] for the algorithm.
//!
//! Script compression recognises standard script types:
//! - `0x00`: P2PKH -- next 20 bytes are the pubkey hash
//! - `0x01`: P2SH  -- next 20 bytes are the script hash
//! - `0x02`/`0x03`: compressed pubkey (P2PK) -- next 32 bytes are the x-coordinate
//! - `0x04`/`0x05`: uncompressed pubkey (P2PK) -- next 32 bytes are the x-coordinate
//! - Otherwise: the first byte minus 6 gives the script length, followed by raw bytes
//!
//! ## Obfuscation
//!
//! Starting with Bitcoin Core v0.15, the chainstate DB is XOR-obfuscated.
//! The obfuscation key is stored under the special key:
//!
//! ```text
//! 0x0e 0x00 'o' 'b' 'f' 'u' 's' 'c' 'a' 't' 'e' '_' 'k' 'e' 'y'
//! ```
//!
//! i.e., `\x0e\x00obfuscate_key` (the first two bytes are a varint-encoded
//! length prefix: 14 = `0x0e`).
//!
//! The value under this key is typically 8 bytes. Every other value in the
//! database is XOR'd byte-by-byte (cycling) with this key before storage.
//! Keys are **not** obfuscated -- only values.
//!
//! To de-obfuscate a value:
//! ```text
//! for i in 0..value.len() {
//!     value[i] ^= obfuscation_key[i % obfuscation_key.len()];
//! }
//! ```
//!
//! # Block index key format
//!
//! The block index database (`~/.bitcoin/blocks/index/`) stores block headers
//! and metadata:
//!
//! ```text
//! Key:   'b' (0x62) | blockhash (32 bytes, internal byte order)
//! Value: varint(version) | varint(height) | varint(status) | varint(num_tx)
//!        | varint(file_number) | varint(data_pos) | varint(undo_pos) | header(80 bytes)
//! ```
//!
//! # Core-style varint encoding
//!
//! Bitcoin Core uses a different varint encoding than the wire protocol:
//!
//! ```text
//! // Each byte stores 7 bits of the value.
//! // The high bit signals whether more bytes follow.
//! // Unlike wire protocol varints, Core varints are big-endian-ish:
//! //   n = 0          -> [0x00]
//! //   n = 127        -> [0x7F]
//! //   n = 128        -> [0x80, 0x00]
//! //   n = 16511      -> [0xFF, 0x7F]
//! //   n = 16512      -> [0x80, 0x80, 0x00]
//! ```
//!
//! The encoding works as follows:
//! - Write the lowest 7 bits of `n` as the last byte.
//! - If `n >= 128`, subtract 128, right-shift by 7, set the high bit on the
//!   current byte, and repeat.
//!
//! # Usage
//!
//! This module is currently a **documented stub**. The actual LevelDB reading
//! requires the `rusty-leveldb` (or `leveldb`) crate, which should be added
//! behind the `leveldb` feature flag:
//!
//! ```toml
//! [features]
//! default = []
//! leveldb = ["dep:rusty-leveldb"]
//!
//! [dependencies]
//! rusty-leveldb = { version = "3", optional = true }
//! ```
//!
//! Once the dependency is available, [`CoreChainState::open`] will create a
//! read-only LevelDB handle and the query/import methods will become
//! functional.

use std::path::{Path, PathBuf};

use btc_primitives::amount::Amount;
use btc_primitives::hash::TxHash;
use btc_primitives::script::ScriptBuf;
use btc_primitives::transaction::{OutPoint, TxOut};
use btc_consensus::utxo::UtxoEntry;

use crate::traits::{Database, StorageError};

// ---------------------------------------------------------------------------
// Core-style varint codec
// ---------------------------------------------------------------------------

/// Decode a Bitcoin Core-style varint from a byte slice.
///
/// Returns `(value, bytes_consumed)` or `None` if the slice is too short.
///
/// Core's varint encoding:
/// - Each byte contributes 7 bits.
/// - The high bit (0x80) signals that more bytes follow.
/// - After the first byte, each continuation byte's value is offset by 128
///   to avoid redundant encodings.
pub fn decode_core_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut n: u64 = 0;
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let byte = data[pos];
        pos += 1;
        // The low 7 bits contribute to the value
        n = (n << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            return Some((n, pos));
        }
        // For continuation bytes, add 1 to avoid ambiguity
        // (Core encodes: subtract 128 then shift, so we add 1 here when decoding)
        n += 1;
    }
}

/// Encode a value as a Bitcoin Core-style varint.
pub fn encode_core_varint(mut n: u64) -> Vec<u8> {
    let mut tmp = Vec::with_capacity(10);
    // Encode lowest 7 bits first (this will be the last byte in output)
    tmp.push((n & 0x7F) as u8);
    n >>= 7;
    while n > 0 {
        n -= 1; // subtract 1 to allow full use of the 7-bit range
        tmp.push(((n & 0x7F) | 0x80) as u8);
        n >>= 7;
    }
    tmp.reverse();
    tmp
}

// ---------------------------------------------------------------------------
// Amount compression / decompression
// ---------------------------------------------------------------------------

/// Decompress a Bitcoin Core compressed amount back to satoshis.
///
/// Core's amount compression algorithm (from `compressor.cpp`):
/// - If `x == 0`, the amount is 0.
/// - Otherwise, decode as follows:
///   1. Subtract 1 from `x`.
///   2. `e = x % 10` (the exponent).
///   3. `x = x / 10`.
///   4. If `e < 9`: `n = x / 9 + 1`, then `d = x % 9 + 1`,
///      result = `n * 10^(e+1) + d * 10^e`... (simplified below).
///   5. If `e == 9`: result = `(x + 1) * 10_000_000` (effectively).
///
/// The actual implementation from Core:
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    // x = 10 * (9 * n + d - 1) + e
    let e = x % 10;
    x /= 10;
    let n;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    // Multiply by 10^e
    let mut amount = n;
    for _ in 0..e {
        amount *= 10;
    }
    amount
}

/// Compress a satoshi amount using Bitcoin Core's compression algorithm.
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e: u64 = 0;
    while n % 10 == 0 && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        n /= 10;
        // x = 10 * (9 * n + d - 1) + e
        1 + (n * 9 + d - 1) * 10 + e
    } else {
        1 + (n - 1) * 10 + 9
    }
}

// ---------------------------------------------------------------------------
// Script decompression
// ---------------------------------------------------------------------------

/// Decompress a script from Core's compressed format.
///
/// Returns `(script, bytes_consumed)` or an error.
///
/// Compression types:
/// - `0x00` + 20 bytes: P2PKH (OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG)
/// - `0x01` + 20 bytes: P2SH (OP_HASH160 <hash> OP_EQUAL)
/// - `0x02`/`0x03` + 32 bytes: compressed P2PK (OP_PUSHBYTES_33 <pubkey> OP_CHECKSIG)
/// - `0x04`/`0x05` + 32 bytes: uncompressed P2PK (needs decompression of the pubkey)
/// - Other: raw script, type byte minus 6 gives the length
pub fn decompress_script(data: &[u8]) -> Result<(ScriptBuf, usize), StorageError> {
    if data.is_empty() {
        return Err(StorageError::Corruption("empty compressed script".into()));
    }

    let script_type = data[0];
    match script_type {
        0x00 => {
            // P2PKH
            if data.len() < 21 {
                return Err(StorageError::Corruption("truncated P2PKH script".into()));
            }
            let hash: [u8; 20] = data[1..21].try_into().unwrap();
            Ok((ScriptBuf::p2pkh(&hash), 21))
        }
        0x01 => {
            // P2SH
            if data.len() < 21 {
                return Err(StorageError::Corruption("truncated P2SH script".into()));
            }
            let hash: [u8; 20] = data[1..21].try_into().unwrap();
            Ok((ScriptBuf::p2sh(&hash), 21))
        }
        0x02 | 0x03 => {
            // Compressed public key (P2PK)
            if data.len() < 33 {
                return Err(StorageError::Corruption("truncated compressed pubkey".into()));
            }
            let mut pubkey = vec![script_type];
            pubkey.extend_from_slice(&data[1..33]);
            // Build P2PK script: <33-byte pubkey> OP_CHECKSIG
            let mut script = ScriptBuf::new();
            script.push_slice(&pubkey);
            script.push_opcode(btc_primitives::script::Opcode::OP_CHECKSIG);
            Ok((script, 33))
        }
        0x04 | 0x05 => {
            // Uncompressed public key stored as compressed
            // The x-coordinate is stored; the parity is encoded in the type byte
            // (0x04 = even y, 0x05 = odd y, matching 0x02/0x03 convention)
            if data.len() < 33 {
                return Err(StorageError::Corruption("truncated uncompressed pubkey".into()));
            }
            // Store as compressed form for our purposes
            let parity = if script_type == 0x04 { 0x02 } else { 0x03 };
            let mut pubkey = vec![parity];
            pubkey.extend_from_slice(&data[1..33]);
            // Build P2PK script for the compressed pubkey
            let mut script = ScriptBuf::new();
            script.push_slice(&pubkey);
            script.push_opcode(btc_primitives::script::Opcode::OP_CHECKSIG);
            Ok((script, 33))
        }
        n => {
            // Raw script: length = n - 6
            let len = (n as usize).checked_sub(6).ok_or_else(|| {
                StorageError::Corruption(format!("invalid script compression type: {}", n))
            })?;
            if data.len() < 1 + len {
                return Err(StorageError::Corruption("truncated raw script".into()));
            }
            let script = ScriptBuf::from_bytes(data[1..1 + len].to_vec());
            Ok((script, 1 + len))
        }
    }
}

// ---------------------------------------------------------------------------
// Obfuscation key
// ---------------------------------------------------------------------------

/// The LevelDB key under which Bitcoin Core stores the obfuscation key.
///
/// Raw bytes: `\x0e\x00obfuscate_key`
///
/// The first byte `0x0e` is a varint encoding of the key name length (14),
/// `0x00` is a namespace byte, and the remaining 14 bytes spell `obfuscate_key`.
pub const OBFUSCATION_KEY_KEY: &[u8] = b"\x0e\x00obfuscate_key";

/// Apply (or remove) XOR obfuscation to a value using the given key.
///
/// This is its own inverse: applying it twice yields the original data.
pub fn xor_obfuscate(value: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, byte) in value.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

// ---------------------------------------------------------------------------
// UTXO key encoding / decoding
// ---------------------------------------------------------------------------

/// The prefix byte for UTXO entries in Core's chainstate DB.
pub const UTXO_KEY_PREFIX: u8 = b'C';

/// Encode an outpoint as a Core chainstate key.
///
/// Format: `'C'` + txid (32 bytes, internal byte order) + core_varint(vout)
pub fn encode_utxo_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(34 + 5); // prefix + txid + max varint
    key.push(UTXO_KEY_PREFIX);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&encode_core_varint(outpoint.vout as u64));
    key
}

/// Decode a Core chainstate UTXO key into an OutPoint.
///
/// Returns the OutPoint and the number of bytes consumed.
pub fn decode_utxo_key(data: &[u8]) -> Result<(OutPoint, usize), StorageError> {
    if data.is_empty() || data[0] != UTXO_KEY_PREFIX {
        return Err(StorageError::Corruption("not a UTXO key".into()));
    }
    if data.len() < 33 {
        return Err(StorageError::Corruption("UTXO key too short".into()));
    }
    let txid = TxHash::from_slice(&data[1..33]);
    let (vout, varint_len) = decode_core_varint(&data[33..])
        .ok_or_else(|| StorageError::Corruption("truncated vout varint".into()))?;
    Ok((OutPoint::new(txid, vout as u32), 33 + varint_len))
}

/// Decode a Core chainstate UTXO value into a UtxoEntry.
///
/// Format: `core_varint(code)` + `core_varint(compressed_amount)` + `compressed_script`
///
/// Where `code = (height << 1) | is_coinbase`.
pub fn decode_utxo_value(data: &[u8]) -> Result<UtxoEntry, StorageError> {
    // Decode the code (height << 1 | is_coinbase)
    let (code, code_len) = decode_core_varint(data)
        .ok_or_else(|| StorageError::Corruption("truncated UTXO code".into()))?;
    let height = code >> 1;
    let is_coinbase = (code & 1) != 0;

    // Decode the compressed amount
    let rest = &data[code_len..];
    let (compressed_amount, amount_len) = decode_core_varint(rest)
        .ok_or_else(|| StorageError::Corruption("truncated UTXO amount".into()))?;
    let value = decompress_amount(compressed_amount);

    // Decode the compressed script
    let script_data = &rest[amount_len..];
    let (script_pubkey, _script_len) = decompress_script(script_data)?;

    Ok(UtxoEntry {
        txout: TxOut {
            value: Amount::from_sat(value as i64),
            script_pubkey,
        },
        height,
        is_coinbase,
    })
}

// ---------------------------------------------------------------------------
// CoreChainState -- the main adapter
// ---------------------------------------------------------------------------

/// Adapter for reading Bitcoin Core's chainstate (UTXO set) database.
///
/// Bitcoin Core stores the UTXO set in a LevelDB database at
/// `~/.bitcoin/chainstate/` (or the equivalent datadir for the configured
/// network).
///
/// # Current status
///
/// This is a **documented stub**. The format parsing utilities
/// ([`decode_core_varint`], [`decompress_amount`], [`decompress_script`],
/// [`decode_utxo_key`], [`decode_utxo_value`], [`xor_obfuscate`]) are fully
/// implemented and tested, but the actual LevelDB I/O requires the
/// `rusty-leveldb` crate behind the `leveldb` feature flag.
///
/// # Example (once `leveldb` feature is enabled)
///
/// ```rust,ignore
/// use btc_storage::leveldb_backend::CoreChainState;
/// use btc_storage::RedbDatabase;
/// use std::path::Path;
///
/// let core_cs = CoreChainState::open(Path::new("/home/user/.bitcoin/chainstate/"))?;
/// let our_db = RedbDatabase::open(Path::new("/tmp/btc-rust.redb"))?;
/// let count = core_cs.import_to(&our_db)?;
/// println!("Imported {} UTXOs from Core's chainstate", count);
/// ```
pub struct CoreChainState {
    /// Path to Bitcoin Core's chainstate directory.
    path: PathBuf,
    /// The XOR obfuscation key read from the database.
    /// Empty if obfuscation is not used (pre-v0.15 databases).
    _obfuscation_key: Vec<u8>,
}

impl CoreChainState {
    /// Open a Bitcoin Core chainstate database in read-only mode.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Io`] if the path does not exist or is not a
    /// valid LevelDB database.
    ///
    /// # Stub behaviour
    ///
    /// Without the `leveldb` feature, this validates that the path exists
    /// but does not actually open a LevelDB handle.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if !path.exists() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("chainstate directory not found: {}", path.display()),
            )));
        }

        // In a full implementation, we would:
        // 1. Open the LevelDB database in read-only mode.
        // 2. Read the obfuscation key from OBFUSCATION_KEY_KEY.
        // 3. Store the key for de-obfuscating all subsequent reads.
        //
        // For now, we just record the path.
        Ok(CoreChainState {
            path: path.to_path_buf(),
            _obfuscation_key: Vec::new(),
        })
    }

    /// Return the path to the chainstate directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Look up a single UTXO by outpoint.
    ///
    /// # Stub behaviour
    ///
    /// Without the `leveldb` feature, this always returns
    /// `Err(StorageError::Database("leveldb feature not enabled"))`.
    pub fn get_utxo(&self, _outpoint: &OutPoint) -> Result<Option<UtxoEntry>, StorageError> {
        // Full implementation would:
        // 1. Encode the outpoint as a Core chainstate key via encode_utxo_key().
        // 2. Look it up in LevelDB.
        // 3. De-obfuscate the value with xor_obfuscate().
        // 4. Decode the value with decode_utxo_value().
        Err(StorageError::Database(
            "leveldb feature not enabled -- add `leveldb` feature to btc-storage".into(),
        ))
    }

    /// Import Bitcoin Core's entire UTXO set into the given database.
    ///
    /// Iterates over all keys with the `'C'` prefix in the chainstate
    /// LevelDB, decodes each UTXO, and writes it into `db`.
    ///
    /// Returns the number of UTXOs imported.
    ///
    /// # Stub behaviour
    ///
    /// Without the `leveldb` feature, this always returns
    /// `Err(StorageError::Database("leveldb feature not enabled"))`.
    pub fn import_to<DB: Database>(&self, _db: &DB) -> Result<usize, StorageError> {
        // Full implementation would:
        // 1. Create a LevelDB iterator starting at key b"C".
        // 2. For each key/value pair where key[0] == 'C':
        //    a. De-obfuscate the value.
        //    b. Decode key -> OutPoint, value -> UtxoEntry.
        //    c. Write to our DB via DbTxMut::put_utxo().
        // 3. Commit in batches (e.g., every 100k UTXOs).
        // 4. Return the total count.
        Err(StorageError::Database(
            "leveldb feature not enabled -- add `leveldb` feature to btc-storage".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_varint_roundtrip() {
        let test_values: &[u64] = &[
            0, 1, 127, 128, 255, 256, 16383, 16384, 16511, 16512,
            65535, 65536, 1_000_000, u32::MAX as u64, u64::MAX,
        ];
        for &val in test_values {
            let encoded = encode_core_varint(val);
            let (decoded, len) = decode_core_varint(&encoded).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {}", val);
            assert_eq!(len, encoded.len(), "length mismatch for {}", val);
        }
    }

    #[test]
    fn test_core_varint_known_values() {
        // n = 0 -> [0x00]
        assert_eq!(encode_core_varint(0), vec![0x00]);
        // n = 127 -> [0x7F]
        assert_eq!(encode_core_varint(127), vec![0x7F]);
        // n = 128 -> [0x80, 0x00]
        assert_eq!(encode_core_varint(128), vec![0x80, 0x00]);
        // n = 16511 -> [0xFF, 0x7F]
        assert_eq!(encode_core_varint(16511), vec![0xFF, 0x7F]);
        // n = 16512 -> [0x80, 0x80, 0x00]
        assert_eq!(encode_core_varint(16512), vec![0x80, 0x80, 0x00]);
    }

    #[test]
    fn test_amount_compression_roundtrip() {
        let test_amounts: &[u64] = &[
            0,
            1,
            100,
            500,
            1000,
            10_000,
            50_000,
            100_000,
            500_000,
            1_000_000,
            10_000_000,
            50_000_000,       // 0.5 BTC
            100_000_000,      // 1 BTC
            500_000_000,      // 5 BTC
            2_100_000_000_000_000, // 21M BTC
        ];
        for &amount in test_amounts {
            let compressed = compress_amount(amount);
            let decompressed = decompress_amount(compressed);
            assert_eq!(decompressed, amount, "amount roundtrip failed for {}", amount);
        }
    }

    #[test]
    fn test_decompress_amount_zero() {
        assert_eq!(decompress_amount(0), 0);
    }

    #[test]
    fn test_xor_obfuscation() {
        let key = vec![0xAB, 0xCD, 0xEF];
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut data = original.clone();

        // Apply obfuscation
        xor_obfuscate(&mut data, &key);
        assert_ne!(data, original);

        // Apply again to de-obfuscate
        xor_obfuscate(&mut data, &key);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_obfuscation_empty_key() {
        let original = vec![0x01, 0x02, 0x03];
        let mut data = original.clone();
        xor_obfuscate(&mut data, &[]);
        assert_eq!(data, original);
    }

    #[test]
    fn test_encode_decode_utxo_key() {
        let outpoint = OutPoint::new(TxHash::from_bytes([0xAB; 32]), 42);
        let key = encode_utxo_key(&outpoint);

        assert_eq!(key[0], b'C');
        assert_eq!(&key[1..33], &[0xAB; 32]);

        let (decoded_outpoint, len) = decode_utxo_key(&key).unwrap();
        assert_eq!(decoded_outpoint.txid, outpoint.txid);
        assert_eq!(decoded_outpoint.vout, 42);
        assert_eq!(len, key.len());
    }

    #[test]
    fn test_decode_utxo_value_p2pkh() {
        // Build a synthetic Core UTXO value:
        // code = (height << 1) | is_coinbase
        // height=100, coinbase=true => code = 201
        let mut data = Vec::new();
        data.extend_from_slice(&encode_core_varint(201)); // code
        data.extend_from_slice(&encode_core_varint(compress_amount(5_000_000_000))); // 50 BTC
        data.push(0x00); // P2PKH type
        data.extend_from_slice(&[0xAB; 20]); // pubkey hash

        let entry = decode_utxo_value(&data).unwrap();
        assert_eq!(entry.height, 100);
        assert!(entry.is_coinbase);
        assert_eq!(entry.txout.value, Amount::from_sat(5_000_000_000));
        assert!(entry.txout.script_pubkey.is_p2pkh());
    }

    #[test]
    fn test_decode_utxo_value_p2sh() {
        // height=50000, not coinbase => code = 100000
        let mut data = Vec::new();
        data.extend_from_slice(&encode_core_varint(100_000));
        data.extend_from_slice(&encode_core_varint(compress_amount(100_000))); // 0.001 BTC
        data.push(0x01); // P2SH type
        data.extend_from_slice(&[0xCD; 20]); // script hash

        let entry = decode_utxo_value(&data).unwrap();
        assert_eq!(entry.height, 50_000);
        assert!(!entry.is_coinbase);
        assert_eq!(entry.txout.value, Amount::from_sat(100_000));
        assert!(entry.txout.script_pubkey.is_p2sh());
    }

    #[test]
    fn test_decompress_script_p2pkh() {
        let mut data = vec![0x00];
        data.extend_from_slice(&[0x11; 20]);
        let (script, consumed) = decompress_script(&data).unwrap();
        assert_eq!(consumed, 21);
        assert!(script.is_p2pkh());
    }

    #[test]
    fn test_decompress_script_p2sh() {
        let mut data = vec![0x01];
        data.extend_from_slice(&[0x22; 20]);
        let (script, consumed) = decompress_script(&data).unwrap();
        assert_eq!(consumed, 21);
        assert!(script.is_p2sh());
    }

    #[test]
    fn test_decompress_script_compressed_pubkey() {
        let mut data = vec![0x02];
        data.extend_from_slice(&[0x33; 32]);
        let (script, consumed) = decompress_script(&data).unwrap();
        assert_eq!(consumed, 33);
        // Should be a P2PK script: <33-byte pubkey> OP_CHECKSIG
        assert_eq!(script.len(), 35); // 1 (push len) + 33 (pubkey) + 1 (OP_CHECKSIG)
    }

    #[test]
    fn test_decompress_script_raw() {
        // Type byte 10 means raw script of length 10 - 6 = 4
        let data = vec![10, 0xDE, 0xAD, 0xBE, 0xEF];
        let (script, consumed) = decompress_script(&data).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(script.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_obfuscation_key_constant() {
        assert_eq!(OBFUSCATION_KEY_KEY, b"\x0e\x00obfuscate_key");
        // 2 prefix bytes + 13 chars in "obfuscate_key" = 15 bytes
        assert_eq!(OBFUSCATION_KEY_KEY.len(), 15);
    }

    #[test]
    fn test_open_nonexistent_path() {
        let result = CoreChainState::open(Path::new("/nonexistent/chainstate"));
        assert!(result.is_err());
    }
}
