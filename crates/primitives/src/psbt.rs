//! Partially Signed Bitcoin Transactions (PSBT) — BIP174 / BIP370 / BIP371
//!
//! PSBT is a standardized format for passing around unsigned or partially-signed
//! transactions between wallets, signers, and finalizers. The binary format uses
//! magic bytes `0x70736274ff` ("psbt" + 0xff separator) followed by key-value
//! maps: one global map, then per-input and per-output maps separated by 0x00.

use crate::amount::Amount;
use crate::encode::{Decodable, Encodable, EncodeError, VarInt};
use crate::hash::TxHash;
use crate::script::ScriptBuf;
use crate::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};
use std::collections::HashSet;
use std::io::{self, Cursor, Read, Write};
use thiserror::Error;

// ---------------------------------------------------------------------------
// PSBT magic
// ---------------------------------------------------------------------------

/// PSBT magic bytes: "psbt" (0x70 0x73 0x62 0x74) followed by 0xff separator.
const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];
/// Resource bound for the in-memory parser, not a Bitcoin consensus limit.
pub const MAX_PSBT_SIZE: usize = 32 * 1024 * 1024;
const MAX_PSBT_MAPS: usize = 100_000;

// ---------------------------------------------------------------------------
// Global key types (BIP174)
// ---------------------------------------------------------------------------

const PSBT_GLOBAL_UNSIGNED_TX: u64 = 0x00;
const PSBT_GLOBAL_XPUB: u64 = 0x01;
const PSBT_GLOBAL_TX_VERSION: u64 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u64 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u64 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u64 = 0x05;
const PSBT_GLOBAL_TX_MODIFIABLE: u64 = 0x06;
const PSBT_GLOBAL_VERSION: u64 = 0xFB;

// ---------------------------------------------------------------------------
// Per-input key types (BIP174 / BIP371)
// ---------------------------------------------------------------------------

const PSBT_IN_NON_WITNESS_UTXO: u64 = 0x00;
const PSBT_IN_WITNESS_UTXO: u64 = 0x01;
const PSBT_IN_PARTIAL_SIG: u64 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u64 = 0x03;
const PSBT_IN_REDEEM_SCRIPT: u64 = 0x04;
const PSBT_IN_WITNESS_SCRIPT: u64 = 0x05;
const PSBT_IN_BIP32_DERIVATION: u64 = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG: u64 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u64 = 0x08;
const PSBT_IN_TAP_KEY_SIG: u64 = 0x13;
const PSBT_IN_TAP_SCRIPT_SIG: u64 = 0x14;
const PSBT_IN_TAP_LEAF_SCRIPT: u64 = 0x15;
const PSBT_IN_TAP_BIP32_DERIVATION: u64 = 0x16;
const PSBT_IN_TAP_INTERNAL_KEY: u64 = 0x17;
const PSBT_IN_TAP_MERKLE_ROOT: u64 = 0x18;

// ---------------------------------------------------------------------------
// Per-output key types (BIP174 / BIP371)
// ---------------------------------------------------------------------------

const PSBT_OUT_REDEEM_SCRIPT: u64 = 0x00;
const PSBT_OUT_WITNESS_SCRIPT: u64 = 0x01;
const PSBT_OUT_BIP32_DERIVATION: u64 = 0x02;
const PSBT_OUT_TAP_INTERNAL_KEY: u64 = 0x05;
const PSBT_OUT_TAP_TREE: u64 = 0x06;
const PSBT_OUT_TAP_BIP32_DERIVATION: u64 = 0x07;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PsbtError {
    #[error("invalid PSBT magic bytes")]
    InvalidMagic,
    #[error("encoding error: {0}")]
    Encode(#[from] EncodeError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("missing unsigned transaction in global map")]
    MissingUnsignedTx,
    #[error("input count mismatch: PSBT has {psbt} but tx has {tx}")]
    InputCountMismatch { psbt: usize, tx: usize },
    #[error("output count mismatch: PSBT has {psbt} but tx has {tx}")]
    OutputCountMismatch { psbt: usize, tx: usize },
    #[error("unsigned transaction must have empty scriptSigs and witnesses")]
    NonEmptyScriptSig,
    #[error("transaction mismatch during merge")]
    TxMismatch,
    #[error("input {index} is not finalized (missing final_script_sig/final_script_witness)")]
    NotFinalized { index: usize },
    #[error("duplicate key: {0:?}")]
    DuplicateKey(Vec<u8>),
    #[error("inconsistent PSBT input {index}: {reason}")]
    InconsistentInput { index: usize, reason: &'static str },
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// KeySource — BIP32 derivation origin
// ---------------------------------------------------------------------------

/// A BIP32 key source: master fingerprint (4 bytes) + derivation path indices.
pub type KeySource = ([u8; 4], Vec<u32>);

/// BIP371 leaf hashes involving a key, followed by its BIP32 origin.
/// An internal key has no leaf hashes. The origin is metadata, not proof of derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapKeySource {
    pub leaf_hashes: Vec<[u8; 32]>,
    pub key_source: KeySource,
}

/// BIP371 input leaf script; the associated map key is its BIP341 control block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapLeafScript {
    pub script: ScriptBuf,
    pub leaf_version: u8,
}

/// One leaf of a complete output Taproot tree, serialized in depth-first order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapTreeLeaf {
    pub depth: u8,
    pub leaf_version: u8,
    pub script: ScriptBuf,
}

// ---------------------------------------------------------------------------
// PsbtInput
// ---------------------------------------------------------------------------

/// Per-input data carried inside a PSBT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PsbtInput {
    pub non_witness_utxo: Option<Transaction>,
    pub witness_utxo: Option<TxOut>,
    /// Partial signatures: pubkey -> signature.
    pub partial_sigs: Vec<(Vec<u8>, Vec<u8>)>,
    pub sighash_type: Option<u32>,
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    pub bip32_derivation: Vec<(Vec<u8>, KeySource)>,
    pub final_script_sig: Option<ScriptBuf>,
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// BIP370 requirements; present only in PSBT v2.
    pub required_time_lock_time: Option<u32>,
    pub required_height_lock_time: Option<u32>,
    // Taproot fields (BIP371)
    pub tap_key_sig: Option<Vec<u8>>,
    pub tap_script_sigs: Vec<(Vec<u8>, Vec<u8>)>,
    pub tap_leaf_scripts: Vec<(Vec<u8>, TapLeafScript)>,
    pub tap_bip32_derivation: Vec<(Vec<u8>, TapKeySource)>,
    pub tap_internal_key: Option<Vec<u8>>,
    pub tap_merkle_root: Option<[u8; 32]>,
    /// Unknown key-value pairs.
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// PsbtOutput
// ---------------------------------------------------------------------------

/// Per-output data carried inside a PSBT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PsbtOutput {
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    pub bip32_derivation: Vec<(Vec<u8>, KeySource)>,
    pub tap_internal_key: Option<Vec<u8>>,
    pub tap_tree: Option<Vec<TapTreeLeaf>>,
    pub tap_bip32_derivation: Vec<(Vec<u8>, TapKeySource)>,
    /// Unknown key-value pairs.
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Psbt
// ---------------------------------------------------------------------------

/// A Partially Signed Bitcoin Transaction (BIP174 / BIP370).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Psbt {
    /// The unsigned transaction that this PSBT wraps.
    pub unsigned_tx: Transaction,
    /// PSBT version (0 for BIP174, 2 for BIP370).
    pub version: u32,
    /// BIP370 fallback when no input specifies a locktime requirement.
    pub fallback_lock_time: Option<u32>,
    /// BIP370 constructor permissions, including undefined bits for forwarding.
    pub tx_modifiable: Option<u8>,
    /// Global extended public keys with derivation info.
    pub xpub: Vec<(Vec<u8>, KeySource)>,
    /// Per-input maps (length must equal `unsigned_tx.inputs.len()`).
    pub inputs: Vec<PsbtInput>,
    /// Per-output maps (length must equal `unsigned_tx.outputs.len()`).
    pub outputs: Vec<PsbtOutput>,
    /// Proprietary key-value pairs in the global map.
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
    /// Unknown global key-value pairs.
    pub unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

// =========================================================================
// Compact-size / key-value helpers
// =========================================================================

/// Write a compact-size length prefix.
fn write_compact_size<W: Write>(writer: &mut W, len: u64) -> Result<usize, PsbtError> {
    Ok(VarInt(len).encode(writer)?)
}

/// Read a compact-size length prefix.
fn read_compact_size<R: Read>(reader: &mut R) -> Result<u64, PsbtError> {
    Ok(VarInt::decode(reader)?.0)
}

/// Write a single PSBT key-value pair.
fn write_kv<W: Write>(writer: &mut W, key: &[u8], value: &[u8]) -> Result<(), PsbtError> {
    write_compact_size(writer, key.len() as u64)?;
    writer.write_all(key)?;
    write_compact_size(writer, value.len() as u64)?;
    writer.write_all(value)?;
    Ok(())
}

/// Read a single PSBT key. Returns `None` when the separator (0x00) is hit.
fn read_key(reader: &mut Cursor<&[u8]>) -> Result<Option<Vec<u8>>, PsbtError> {
    let key_len = read_compact_size(reader)?;
    if key_len == 0 {
        return Ok(None); // separator
    }
    Ok(Some(read_blob(reader, key_len)?))
}

/// Read a PSBT value blob.
fn read_value(reader: &mut Cursor<&[u8]>) -> Result<Vec<u8>, PsbtError> {
    let val_len = read_compact_size(reader)?;
    read_blob(reader, val_len)
}

fn remaining(reader: &Cursor<&[u8]>) -> usize {
    reader
        .get_ref()
        .len()
        .saturating_sub(reader.position() as usize)
}

fn read_blob(reader: &mut Cursor<&[u8]>, len: u64) -> Result<Vec<u8>, PsbtError> {
    if len > remaining(reader) as u64 {
        return Err(PsbtError::Other(
            "PSBT length exceeds remaining bytes".into(),
        ));
    }
    let mut value = vec![0; len as usize];
    reader.read_exact(&mut value)?;
    Ok(value)
}

/// Key type is a canonical CompactSize integer, not necessarily one byte.
fn split_key(key: &[u8]) -> Result<(u64, &[u8]), PsbtError> {
    let mut cursor = Cursor::new(key);
    let kind = read_compact_size(&mut cursor)?;
    Ok((kind, &key[cursor.position() as usize..]))
}

fn singleton(key_data: &[u8]) -> Result<(), PsbtError> {
    if !key_data.is_empty() {
        return Err(PsbtError::Other("singleton PSBT key has key data".into()));
    }
    Ok(())
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], PsbtError> {
    value
        .try_into()
        .map_err(|_| PsbtError::Other(format!("expected {N}-byte PSBT value")))
}

fn v2_only(version: u32) -> Result<(), PsbtError> {
    if version != 2 {
        return Err(PsbtError::Other(
            "BIP370 field is excluded in PSBT v0".into(),
        ));
    }
    Ok(())
}

type Map = Vec<(Vec<u8>, Vec<u8>)>;

fn read_map(r: &mut Cursor<&[u8]>, budget: &mut usize) -> Result<Map, PsbtError> {
    let mut seen = HashSet::new();
    let mut map = Vec::new();
    while let Some(key) = read_key(r)? {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| PsbtError::Other("too many PSBT key-value pairs".into()))?;
        split_key(&key)?;
        if !seen.insert(key.clone()) {
            return Err(PsbtError::DuplicateKey(key));
        }
        map.push((key, read_value(r)?));
    }
    Ok(map)
}

fn public_key_shape(key: &[u8]) -> Result<(), PsbtError> {
    if !((key.len() == 33 && matches!(key[0], 2 | 3)) || (key.len() == 65 && key[0] == 4)) {
        return Err(PsbtError::Other("invalid PSBT public key encoding".into()));
    }
    Ok(())
}

fn tap_signature_shape(signature: &[u8]) -> Result<(), PsbtError> {
    if !matches!(signature.len(), 64 | 65) {
        return Err(PsbtError::Other(
            "Taproot signature must be 64 or 65 bytes".into(),
        ));
    }
    Ok(())
}

fn xonly_public_key(key: &[u8]) -> Result<(), PsbtError> {
    fixed::<32>(key)?;
    secp256k1::XOnlyPublicKey::from_slice(key)
        .map_err(|_| PsbtError::Other("invalid PSBT x-only curve key".into()))?;
    Ok(())
}

/// Check known script commitments without executing the spending script. With a
/// missing P2SH redeem script, the witness-script check must wait for an updater.
fn check_script_commitments(
    script_pubkey: Option<&ScriptBuf>,
    redeem_script: Option<&ScriptBuf>,
    witness_script: Option<&ScriptBuf>,
) -> Result<(), &'static str> {
    if let (Some(output), Some(redeem)) = (script_pubkey, redeem_script) {
        if *output != ScriptBuf::p2sh(&crate::hash::hash160(redeem.as_bytes())) {
            return Err("redeem script does not match output HASH160 commitment");
        }
    }
    if let Some(witness) = witness_script {
        let program = redeem_script.or(script_pubkey);
        if let Some(program) = program {
            if redeem_script.is_none() && program.is_p2sh() {
                return Ok(()); // incomplete metadata: the inner witness program is not known
            }
            if *program != ScriptBuf::p2wsh(&crate::hash::sha256(witness.as_bytes())) {
                return Err("witness script does not match SHA256 witness program");
            }
        }
    }
    Ok(())
}

fn decode_tap_leaf(control: &[u8], value: &[u8]) -> Result<TapLeafScript, PsbtError> {
    // BIP341: 33 + 32*m bytes, with 0 <= m <= 128. Check before slicing.
    if control.len() < 33 || control.len() > 33 + 32 * 128 || (control.len() - 33) % 32 != 0 {
        return Err(PsbtError::Other(
            "invalid Taproot control block length".into(),
        ));
    }
    xonly_public_key(&control[1..33])?;
    let (&leaf_version, script) = value
        .split_last()
        .ok_or_else(|| PsbtError::Other("missing Taproot leaf version".into()))?;
    if leaf_version != control[0] & 0xfe {
        return Err(PsbtError::Other(
            "Taproot leaf/control versions differ".into(),
        ));
    }
    Ok(TapLeafScript {
        script: ScriptBuf::from_bytes(script.to_vec()),
        leaf_version,
    })
}

fn encode_tap_key_source(source: &TapKeySource) -> Vec<u8> {
    let mut value = Vec::new();
    write_compact_size(&mut value, source.leaf_hashes.len() as u64).expect("Vec write");
    for hash in &source.leaf_hashes {
        value.extend_from_slice(hash);
    }
    value.extend_from_slice(&encode_key_source(&source.key_source));
    value
}

fn decode_tap_key_source(value: &[u8]) -> Result<TapKeySource, PsbtError> {
    let mut cursor = Cursor::new(value);
    let count = read_compact_size(&mut cursor)?;
    // Leave the required fingerprint and bound the count before allocating or multiplying.
    let available = remaining(&cursor);
    if available < 4 || count > ((available - 4) / 32) as u64 || count > MAX_PSBT_MAPS as u64 {
        return Err(PsbtError::Other(
            "invalid Taproot derivation hash count".into(),
        ));
    }
    let mut leaf_hashes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut hash = [0; 32];
        cursor.read_exact(&mut hash)?;
        leaf_hashes.push(hash);
    }
    let key_source = decode_key_source(&value[cursor.position() as usize..])?;
    Ok(TapKeySource {
        leaf_hashes,
        key_source,
    })
}

fn encode_tap_tree(tree: &[TapTreeLeaf]) -> Vec<u8> {
    let mut value = Vec::new();
    for leaf in tree {
        value.extend_from_slice(&[leaf.depth, leaf.leaf_version]);
        write_compact_size(&mut value, leaf.script.len() as u64).expect("Vec write");
        value.extend_from_slice(leaf.script.as_bytes());
    }
    value
}

fn decode_tap_tree(value: &[u8]) -> Result<Vec<TapTreeLeaf>, PsbtError> {
    let mut cursor = Cursor::new(value);
    let mut tree = Vec::new();
    // Reduce adjacent completed subtrees. A shallower new leaf cannot precede
    // completion of a deeper left subtree in depth-first order (Core TaprootBuilder).
    let mut depths = Vec::new();
    while remaining(&cursor) > 0 {
        if tree.len() >= MAX_PSBT_MAPS {
            return Err(PsbtError::Other("too many Taproot tree leaves".into()));
        }
        let mut header = [0; 2];
        cursor.read_exact(&mut header)?;
        let [mut depth, leaf_version] = header;
        if depth > 128 || leaf_version & 1 != 0 {
            return Err(PsbtError::Other(
                "invalid Taproot tree depth/version".into(),
            ));
        }
        if depths.last().is_some_and(|previous| *previous > depth) {
            return Err(PsbtError::Other(
                "Taproot tree is not in depth-first order".into(),
            ));
        }
        while depths.last() == Some(&depth) {
            depths.pop();
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| PsbtError::Other("Taproot tree has multiple roots".into()))?;
        }
        depths.push(depth);
        let len = read_compact_size(&mut cursor)?;
        tree.push(TapTreeLeaf {
            depth: header[0],
            leaf_version,
            script: ScriptBuf::from_bytes(read_blob(&mut cursor, len)?),
        });
    }
    if depths != [0] {
        return Err(PsbtError::Other("incomplete Taproot tree".into()));
    }
    Ok(tree)
}

fn determine_lock_time(inputs: &[PsbtInput], fallback: Option<u32>) -> Result<u32, PsbtError> {
    let mut max_height = 0;
    let mut max_time = 0;
    let mut height_possible = true;
    let mut time_possible = true;
    for input in inputs {
        if let Some(height) = input.required_height_lock_time {
            if height == 0 || height >= 500_000_000 {
                return Err(PsbtError::Other("invalid required height locktime".into()));
            }
            max_height = max_height.max(height);
        }
        if let Some(time) = input.required_time_lock_time {
            if time < 500_000_000 {
                return Err(PsbtError::Other("invalid required time locktime".into()));
            }
            max_time = max_time.max(time);
        }
        if input.required_height_lock_time.is_some() || input.required_time_lock_time.is_some() {
            height_possible &= input.required_height_lock_time.is_some();
            time_possible &= input.required_time_lock_time.is_some();
        }
    }
    if max_height == 0 && max_time == 0 {
        Ok(fallback.unwrap_or(0))
    } else if height_possible {
        Ok(max_height)
    } else if time_possible {
        Ok(max_time)
    } else {
        Err(PsbtError::Other(
            "incompatible PSBT input locktime requirements".into(),
        ))
    }
}

/// Build a key from its type byte and optional extra data.
fn make_key(key_type: u64, extra: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + extra.len());
    VarInt(key_type).encode(&mut k).expect("Vec write");
    k.extend_from_slice(extra);
    k
}

/// Serialize a `KeySource` to bytes: 4-byte fingerprint + path of u32-le.
fn encode_key_source(ks: &KeySource) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + ks.1.len() * 4);
    buf.extend_from_slice(&ks.0);
    for &idx in &ks.1 {
        buf.extend_from_slice(&idx.to_le_bytes());
    }
    buf
}

/// Decode a `KeySource` from bytes.
fn decode_key_source(data: &[u8]) -> Result<KeySource, PsbtError> {
    if data.len() < 4 || (data.len() - 4) % 4 != 0 {
        return Err(PsbtError::Other("invalid key source length".into()));
    }
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&data[0..4]);
    let count = (data.len() - 4) / 4;
    let mut path = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * 4;
        let idx = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        path.push(idx);
    }
    Ok((fp, path))
}

/// Serialize a `Transaction` to raw bytes using our `Encodable` trait.
fn tx_to_bytes(tx: &Transaction) -> Vec<u8> {
    crate::encode::encode(tx)
}

/// Deserialize a `Transaction` from raw bytes.
fn tx_from_bytes(data: &[u8]) -> Result<Transaction, PsbtError> {
    Ok(crate::encode::decode(data)?)
}

/// Serialize a `TxOut` to bytes.
fn txout_to_bytes(txo: &TxOut) -> Vec<u8> {
    crate::encode::encode(txo)
}

/// Deserialize a `TxOut` from bytes.
fn txout_from_bytes(data: &[u8]) -> Result<TxOut, PsbtError> {
    Ok(crate::encode::decode(data)?)
}

// =========================================================================
// Psbt impl — construction
// =========================================================================

impl Psbt {
    /// Create a new PSBT from an unsigned transaction.
    ///
    /// The transaction's scriptSigs must be empty and witness data absent.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, PsbtError> {
        // Validate: scriptSigs should be empty
        for inp in &tx.inputs {
            if !inp.script_sig.is_empty() {
                return Err(PsbtError::NonEmptyScriptSig);
            }
        }
        // Validate: no witness data
        if tx.is_segwit() {
            return Err(PsbtError::NonEmptyScriptSig);
        }

        let num_inputs = tx.inputs.len();
        let num_outputs = tx.outputs.len();
        Ok(Psbt {
            unsigned_tx: tx,
            version: 0,
            fallback_lock_time: None,
            tx_modifiable: None,
            xpub: Vec::new(),
            inputs: vec![PsbtInput::default(); num_inputs],
            outputs: vec![PsbtOutput::default(); num_outputs],
            proprietary: Vec::new(),
            unknown: Vec::new(),
        })
    }

    // =====================================================================
    // Serialize
    // =====================================================================

    /// Serialize the PSBT to its binary representation.
    pub fn serialize(&self) -> Vec<u8> {
        self.try_serialize()
            .expect("invalid PSBT model; use try_serialize for fallible serialization")
    }

    /// Serialize after checking counts, version rules, spending data and wire structure.
    pub fn try_serialize(&self) -> Result<Vec<u8>, PsbtError> {
        self.validate_structure()?;
        let mut buf = Vec::new();
        self.serialize_to(&mut buf)?;
        // Also catches duplicate keys introduced through the public collections,
        // including collisions of unknown fields with fields managed here.
        if Self::deserialize(&buf)? != *self {
            return Err(PsbtError::Other(
                "PSBT model contains a managed field in an unknown collection".into(),
            ));
        }
        Ok(buf)
    }

    fn serialize_to<W: Write>(&self, w: &mut W) -> Result<(), PsbtError> {
        // -- Magic --
        w.write_all(&PSBT_MAGIC)?;

        // -- Global map --
        // Unsigned tx (key type 0x00, no key data)
        if self.version == 0 {
            write_kv(
                w,
                &[PSBT_GLOBAL_UNSIGNED_TX as u8],
                &tx_to_bytes(&self.unsigned_tx),
            )?;
        } else {
            write_kv(
                w,
                &[PSBT_GLOBAL_TX_VERSION as u8],
                &self.unsigned_tx.version.to_le_bytes(),
            )?;
            if let Some(locktime) = self.fallback_lock_time {
                write_kv(
                    w,
                    &[PSBT_GLOBAL_FALLBACK_LOCKTIME as u8],
                    &locktime.to_le_bytes(),
                )?;
            }
            write_kv(
                w,
                &[PSBT_GLOBAL_INPUT_COUNT as u8],
                &crate::encode::encode(&VarInt(self.inputs.len() as u64)),
            )?;
            write_kv(
                w,
                &[PSBT_GLOBAL_OUTPUT_COUNT as u8],
                &crate::encode::encode(&VarInt(self.outputs.len() as u64)),
            )?;
            if let Some(flags) = self.tx_modifiable {
                write_kv(w, &[PSBT_GLOBAL_TX_MODIFIABLE as u8], &[flags])?;
            }
        }

        // Xpubs
        for (xpub_data, key_source) in &self.xpub {
            let key = make_key(PSBT_GLOBAL_XPUB, xpub_data);
            let val = encode_key_source(key_source);
            write_kv(w, &key, &val)?;
        }

        // Version (only if non-zero)
        if self.version != 0 {
            let mut val = Vec::with_capacity(4);
            val.extend_from_slice(&self.version.to_le_bytes());
            write_kv(w, &[PSBT_GLOBAL_VERSION as u8], &val)?;
        }

        // Proprietary
        for (key, val) in &self.proprietary {
            write_kv(w, key, val)?;
        }

        // Unknown
        for (key, val) in &self.unknown {
            write_kv(w, key, val)?;
        }

        // Separator
        w.write_all(&[0x00])?;

        // -- Per-input maps --
        for (index, input) in self.inputs.iter().enumerate() {
            if self.version == 2 {
                let txin = &self.unsigned_tx.inputs[index];
                write_kv(w, &[0x0e], txin.previous_output.txid.as_bytes())?;
                write_kv(w, &[0x0f], &txin.previous_output.vout.to_le_bytes())?;
                if txin.sequence != u32::MAX {
                    write_kv(w, &[0x10], &txin.sequence.to_le_bytes())?;
                }
                if let Some(locktime) = input.required_time_lock_time {
                    write_kv(w, &[0x11], &locktime.to_le_bytes())?;
                }
                if let Some(locktime) = input.required_height_lock_time {
                    write_kv(w, &[0x12], &locktime.to_le_bytes())?;
                }
            }
            self.serialize_input(w, input)?;
            w.write_all(&[0x00])?;
        }

        // -- Per-output maps --
        for (index, output) in self.outputs.iter().enumerate() {
            if self.version == 2 {
                let txout = &self.unsigned_tx.outputs[index];
                write_kv(w, &[0x03], &txout.value.as_sat().to_le_bytes())?;
                write_kv(w, &[0x04], txout.script_pubkey.as_bytes())?;
            }
            self.serialize_output(w, output)?;
            w.write_all(&[0x00])?;
        }

        Ok(())
    }

    fn serialize_input<W: Write>(&self, w: &mut W, inp: &PsbtInput) -> Result<(), PsbtError> {
        if let Some(ref tx) = inp.non_witness_utxo {
            write_kv(w, &[PSBT_IN_NON_WITNESS_UTXO as u8], &tx_to_bytes(tx))?;
        }
        if let Some(ref txo) = inp.witness_utxo {
            write_kv(w, &[PSBT_IN_WITNESS_UTXO as u8], &txout_to_bytes(txo))?;
        }
        for (pubkey, sig) in &inp.partial_sigs {
            let key = make_key(PSBT_IN_PARTIAL_SIG, pubkey);
            write_kv(w, &key, sig)?;
        }
        if let Some(sht) = inp.sighash_type {
            write_kv(w, &[PSBT_IN_SIGHASH_TYPE as u8], &sht.to_le_bytes())?;
        }
        if let Some(ref rs) = inp.redeem_script {
            write_kv(w, &[PSBT_IN_REDEEM_SCRIPT as u8], rs.as_bytes())?;
        }
        if let Some(ref ws) = inp.witness_script {
            write_kv(w, &[PSBT_IN_WITNESS_SCRIPT as u8], ws.as_bytes())?;
        }
        for (pubkey, ks) in &inp.bip32_derivation {
            let key = make_key(PSBT_IN_BIP32_DERIVATION, pubkey);
            write_kv(w, &key, &encode_key_source(ks))?;
        }
        if let Some(ref fs) = inp.final_script_sig {
            write_kv(w, &[PSBT_IN_FINAL_SCRIPTSIG as u8], fs.as_bytes())?;
        }
        if let Some(ref fw) = inp.final_script_witness {
            let val = encode_witness_stack(fw);
            write_kv(w, &[PSBT_IN_FINAL_SCRIPTWITNESS as u8], &val)?;
        }
        // Taproot
        if let Some(ref tks) = inp.tap_key_sig {
            write_kv(w, &[PSBT_IN_TAP_KEY_SIG as u8], tks)?;
        }
        for (key_data, sig) in &inp.tap_script_sigs {
            let key = make_key(PSBT_IN_TAP_SCRIPT_SIG, key_data);
            write_kv(w, &key, sig)?;
        }
        for (control, leaf) in &inp.tap_leaf_scripts {
            let mut value = leaf.script.as_bytes().to_vec();
            value.push(leaf.leaf_version);
            write_kv(w, &make_key(PSBT_IN_TAP_LEAF_SCRIPT, control), &value)?;
        }
        for (key, source) in &inp.tap_bip32_derivation {
            write_kv(
                w,
                &make_key(PSBT_IN_TAP_BIP32_DERIVATION, key),
                &encode_tap_key_source(source),
            )?;
        }
        if let Some(ref tik) = inp.tap_internal_key {
            write_kv(w, &[PSBT_IN_TAP_INTERNAL_KEY as u8], tik)?;
        }
        if let Some(ref tmr) = inp.tap_merkle_root {
            write_kv(w, &[PSBT_IN_TAP_MERKLE_ROOT as u8], tmr)?;
        }
        // Unknown
        for (key, val) in &inp.unknown {
            write_kv(w, key, val)?;
        }
        Ok(())
    }

    fn serialize_output<W: Write>(&self, w: &mut W, out: &PsbtOutput) -> Result<(), PsbtError> {
        if let Some(ref rs) = out.redeem_script {
            write_kv(w, &[PSBT_OUT_REDEEM_SCRIPT as u8], rs.as_bytes())?;
        }
        if let Some(ref ws) = out.witness_script {
            write_kv(w, &[PSBT_OUT_WITNESS_SCRIPT as u8], ws.as_bytes())?;
        }
        for (pubkey, ks) in &out.bip32_derivation {
            let key = make_key(PSBT_OUT_BIP32_DERIVATION, pubkey);
            write_kv(w, &key, &encode_key_source(ks))?;
        }
        if let Some(ref tik) = out.tap_internal_key {
            write_kv(w, &[PSBT_OUT_TAP_INTERNAL_KEY as u8], tik)?;
        }
        if let Some(ref tree) = out.tap_tree {
            write_kv(w, &[PSBT_OUT_TAP_TREE as u8], &encode_tap_tree(tree))?;
        }
        for (key, source) in &out.tap_bip32_derivation {
            write_kv(
                w,
                &make_key(PSBT_OUT_TAP_BIP32_DERIVATION, key),
                &encode_tap_key_source(source),
            )?;
        }
        // Unknown
        for (key, val) in &out.unknown {
            write_kv(w, key, val)?;
        }
        Ok(())
    }

    // =====================================================================
    // Deserialize
    // =====================================================================

    /// Decode a bounded, complete PSBT, checking known spending data but not signatures.
    pub fn deserialize(data: &[u8]) -> Result<Self, PsbtError> {
        if data.len() > MAX_PSBT_SIZE {
            return Err(PsbtError::Other("PSBT exceeds parser size limit".into()));
        }
        let mut r = Cursor::new(data);
        let mut magic = [0u8; 5];
        r.read_exact(&mut magic)?;
        if magic != PSBT_MAGIC {
            return Err(PsbtError::InvalidMagic);
        }
        let mut pair_budget = MAX_PSBT_MAPS;
        let mut unsigned_tx = None;
        let mut version = 0;
        let mut tx_version = None;
        let mut fallback_lock_time = None;
        let mut input_count = None;
        let mut output_count = None;
        let mut tx_modifiable = None;
        let mut xpub = Vec::new();
        let mut proprietary = Vec::new();
        let mut unknown = Vec::new();
        for (key, value) in read_map(&mut r, &mut pair_budget)? {
            let (kind, key_data) = split_key(&key)?;
            match kind {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    singleton(key_data)?;
                    unsigned_tx = Some(tx_from_bytes(&value)?);
                }
                PSBT_GLOBAL_XPUB => {
                    if key_data.len() != 78 {
                        return Err(PsbtError::Other("global xpub must be 78 bytes".into()));
                    }
                    xpub.push((key_data.to_vec(), decode_key_source(&value)?));
                }
                PSBT_GLOBAL_VERSION => {
                    singleton(key_data)?;
                    version = u32::from_le_bytes(fixed(&value)?);
                }
                PSBT_GLOBAL_TX_VERSION => {
                    singleton(key_data)?;
                    tx_version = Some(i32::from_le_bytes(fixed(&value)?));
                }
                PSBT_GLOBAL_FALLBACK_LOCKTIME => {
                    singleton(key_data)?;
                    fallback_lock_time = Some(u32::from_le_bytes(fixed(&value)?));
                }
                PSBT_GLOBAL_INPUT_COUNT | PSBT_GLOBAL_OUTPUT_COUNT => {
                    singleton(key_data)?;
                    let count: VarInt = crate::encode::decode(&value)?;
                    let count = usize::try_from(count.0)
                        .map_err(|_| PsbtError::Other("PSBT map count overflow".into()))?;
                    if kind == PSBT_GLOBAL_INPUT_COUNT {
                        input_count = Some(count);
                    } else {
                        output_count = Some(count);
                    }
                }
                PSBT_GLOBAL_TX_MODIFIABLE => {
                    singleton(key_data)?;
                    tx_modifiable = Some(fixed::<1>(&value)?[0]);
                }
                0xfc => proprietary.push((key, value)),
                _ => unknown.push((key, value)),
            }
        }
        let (mut tx, num_inputs, num_outputs) = match version {
            0 => {
                if tx_version.is_some()
                    || fallback_lock_time.is_some()
                    || input_count.is_some()
                    || output_count.is_some()
                    || tx_modifiable.is_some()
                {
                    return Err(PsbtError::Other(
                        "BIP370 global fields are excluded in PSBT v0".into(),
                    ));
                }
                let tx = unsigned_tx.ok_or(PsbtError::MissingUnsignedTx)?;
                let counts = (tx.inputs.len(), tx.outputs.len());
                (tx, counts.0, counts.1)
            }
            2 => {
                if unsigned_tx.is_some() {
                    return Err(PsbtError::Other(
                        "unsigned transaction is excluded in PSBT v2".into(),
                    ));
                }
                let version = tx_version
                    .ok_or_else(|| PsbtError::Other("missing v2 transaction version".into()))?;
                let ni =
                    input_count.ok_or_else(|| PsbtError::Other("missing v2 input count".into()))?;
                let no = output_count
                    .ok_or_else(|| PsbtError::Other("missing v2 output count".into()))?;
                (
                    Transaction {
                        version,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                        witness: Vec::new(),
                        lock_time: 0,
                    },
                    ni,
                    no,
                )
            }
            _ => {
                return Err(PsbtError::Other(format!(
                    "unsupported PSBT version {version}"
                )))
            }
        };
        let count = num_inputs
            .checked_add(num_outputs)
            .ok_or_else(|| PsbtError::Other("PSBT map count overflow".into()))?;
        // Each map requires at least a separator. Bound before capacity allocation.
        if count > MAX_PSBT_MAPS || count > remaining(&r) {
            return Err(PsbtError::Other(
                "PSBT map count exceeds available bytes or resource limit".into(),
            ));
        }
        let mut inputs = Vec::with_capacity(num_inputs);
        let mut outputs = Vec::with_capacity(num_outputs);
        for _ in 0..num_inputs {
            let (input, txin) = Self::deserialize_input(&mut r, version, &mut pair_budget)?;
            inputs.push(input);
            if let Some(txin) = txin {
                tx.inputs.push(txin);
            }
        }
        for _ in 0..num_outputs {
            let (output, txout) = Self::deserialize_output(&mut r, version, &mut pair_budget)?;
            outputs.push(output);
            if let Some(txout) = txout {
                tx.outputs.push(txout);
            }
        }
        if remaining(&r) != 0 {
            return Err(PsbtError::Other("trailing PSBT bytes".into()));
        }
        if version == 2 {
            tx.lock_time = determine_lock_time(&inputs, fallback_lock_time)?;
        }
        let psbt = Psbt {
            unsigned_tx: tx,
            version,
            fallback_lock_time,
            tx_modifiable,
            xpub,
            inputs,
            outputs,
            proprietary,
            unknown,
        };
        psbt.validate_structure()?;
        Ok(psbt)
    }

    fn deserialize_input(
        r: &mut Cursor<&[u8]>,
        version: u32,
        pair_budget: &mut usize,
    ) -> Result<(PsbtInput, Option<TxIn>), PsbtError> {
        let mut inp = PsbtInput::default();
        let mut previous_txid = None;
        let mut output_index = None;
        let mut sequence = u32::MAX;
        for (key, value) in read_map(r, pair_budget)? {
            let (kind, key_data) = split_key(&key)?;
            // All recognized input types except signatures/derivations are singletons.
            if matches!(kind, 0x00 | 0x01 | 0x03..=0x05 | 0x07 | 0x08 | 0x0e..=0x13 | 0x17 | 0x18) {
                singleton(key_data)?;
            }
            match kind {
                PSBT_IN_NON_WITNESS_UTXO => inp.non_witness_utxo = Some(tx_from_bytes(&value)?),
                PSBT_IN_WITNESS_UTXO => inp.witness_utxo = Some(txout_from_bytes(&value)?),
                PSBT_IN_PARTIAL_SIG => {
                    public_key_shape(key_data)?;
                    inp.partial_sigs.push((key_data.to_vec(), value));
                }
                PSBT_IN_SIGHASH_TYPE => inp.sighash_type = Some(u32::from_le_bytes(fixed(&value)?)),
                PSBT_IN_REDEEM_SCRIPT => inp.redeem_script = Some(ScriptBuf::from_bytes(value)),
                PSBT_IN_WITNESS_SCRIPT => inp.witness_script = Some(ScriptBuf::from_bytes(value)),
                PSBT_IN_BIP32_DERIVATION => {
                    public_key_shape(key_data)?;
                    inp.bip32_derivation
                        .push((key_data.to_vec(), decode_key_source(&value)?));
                }
                PSBT_IN_FINAL_SCRIPTSIG => {
                    inp.final_script_sig = Some(ScriptBuf::from_bytes(value))
                }
                PSBT_IN_FINAL_SCRIPTWITNESS => {
                    inp.final_script_witness = Some(decode_witness_stack(&value)?)
                }
                0x0e => {
                    v2_only(version)?;
                    previous_txid = Some(TxHash::from_bytes(fixed(&value)?));
                }
                0x0f => {
                    v2_only(version)?;
                    output_index = Some(u32::from_le_bytes(fixed(&value)?));
                }
                0x10 => {
                    v2_only(version)?;
                    sequence = u32::from_le_bytes(fixed(&value)?);
                }
                0x11 => {
                    v2_only(version)?;
                    inp.required_time_lock_time = Some(u32::from_le_bytes(fixed(&value)?));
                }
                0x12 => {
                    v2_only(version)?;
                    inp.required_height_lock_time = Some(u32::from_le_bytes(fixed(&value)?));
                }
                PSBT_IN_TAP_KEY_SIG => {
                    tap_signature_shape(&value)?;
                    inp.tap_key_sig = Some(value);
                }
                PSBT_IN_TAP_SCRIPT_SIG => {
                    fixed::<64>(key_data)?;
                    xonly_public_key(&key_data[..32])?;
                    tap_signature_shape(&value)?;
                    inp.tap_script_sigs.push((key_data.to_vec(), value));
                }
                PSBT_IN_TAP_LEAF_SCRIPT => {
                    inp.tap_leaf_scripts
                        .push((key_data.to_vec(), decode_tap_leaf(key_data, &value)?));
                }
                PSBT_IN_TAP_BIP32_DERIVATION => {
                    xonly_public_key(key_data)?;
                    inp.tap_bip32_derivation
                        .push((key_data.to_vec(), decode_tap_key_source(&value)?));
                }
                PSBT_IN_TAP_INTERNAL_KEY => {
                    xonly_public_key(&value)?;
                    inp.tap_internal_key = Some(value);
                }
                PSBT_IN_TAP_MERKLE_ROOT => inp.tap_merkle_root = Some(fixed(&value)?),
                _ => inp.unknown.push((key, value)),
            }
        }
        let txin = if version == 2 {
            Some(TxIn {
                previous_output: OutPoint::new(
                    previous_txid
                        .ok_or_else(|| PsbtError::Other("missing v2 previous txid".into()))?,
                    output_index
                        .ok_or_else(|| PsbtError::Other("missing v2 output index".into()))?,
                ),
                script_sig: ScriptBuf::new(),
                sequence,
            })
        } else {
            None
        };
        Ok((inp, txin))
    }

    fn deserialize_output(
        r: &mut Cursor<&[u8]>,
        version: u32,
        pair_budget: &mut usize,
    ) -> Result<(PsbtOutput, Option<TxOut>), PsbtError> {
        let mut out = PsbtOutput::default();
        let mut amount = None;
        let mut script = None;
        for (key, value) in read_map(r, pair_budget)? {
            let (kind, key_data) = split_key(&key)?;
            if matches!(kind, 0x00 | 0x01 | 0x03..=0x06) {
                singleton(key_data)?;
            }
            match kind {
                PSBT_OUT_REDEEM_SCRIPT => out.redeem_script = Some(ScriptBuf::from_bytes(value)),
                PSBT_OUT_WITNESS_SCRIPT => out.witness_script = Some(ScriptBuf::from_bytes(value)),
                PSBT_OUT_BIP32_DERIVATION => {
                    public_key_shape(key_data)?;
                    out.bip32_derivation
                        .push((key_data.to_vec(), decode_key_source(&value)?));
                }
                0x03 => {
                    v2_only(version)?;
                    amount = Some(Amount::from_sat(i64::from_le_bytes(fixed(&value)?)));
                }
                0x04 => {
                    v2_only(version)?;
                    script = Some(ScriptBuf::from_bytes(value));
                }
                PSBT_OUT_TAP_INTERNAL_KEY => {
                    xonly_public_key(&value)?;
                    out.tap_internal_key = Some(value);
                }
                PSBT_OUT_TAP_TREE => out.tap_tree = Some(decode_tap_tree(&value)?),
                PSBT_OUT_TAP_BIP32_DERIVATION => {
                    xonly_public_key(key_data)?;
                    out.tap_bip32_derivation
                        .push((key_data.to_vec(), decode_tap_key_source(&value)?));
                }
                _ => out.unknown.push((key, value)),
            }
        }
        let txout = if version == 2 {
            Some(TxOut {
                value: amount.ok_or_else(|| PsbtError::Other("missing v2 output amount".into()))?,
                script_pubkey: script
                    .ok_or_else(|| PsbtError::Other("missing v2 output script".into()))?,
            })
        } else {
            None
        };
        Ok((out, txout))
    }

    /// Resolve supplied spending data. A full parent is linked to the outpoint's
    /// txid; a witness-only record remains a claim by the updater. Neither proves
    /// confirmation, unspentness, parent consensus validity or a valid signature.
    pub fn input_utxo(&self, index: usize) -> Result<Option<&TxOut>, PsbtError> {
        let error = |reason| PsbtError::InconsistentInput { index, reason };
        let input = self
            .inputs
            .get(index)
            .ok_or_else(|| error("missing input map"))?;
        let txin = self
            .unsigned_tx
            .inputs
            .get(index)
            .ok_or_else(|| error("missing transaction input"))?;
        let parent_output = if let Some(parent) = &input.non_witness_utxo {
            // BIP174/Core require the txid, not the witness transaction hash.
            if parent.txid() != txin.previous_output.txid {
                return Err(error("non-witness UTXO txid differs from outpoint"));
            }
            Some(
                parent
                    .outputs
                    .get(txin.previous_output.vout as usize)
                    .ok_or_else(|| error("previous output index does not exist"))?,
            )
        } else {
            None
        };
        if let (Some(parent), Some(witness)) = (parent_output, input.witness_utxo.as_ref()) {
            if parent != witness {
                return Err(error("witness UTXO differs from referenced parent output"));
            }
        }
        let output = parent_output.or(input.witness_utxo.as_ref());
        if output.is_some_and(|output| {
            output.value.as_sat() < 0 || output.value.as_sat() > Amount::MAX_MONEY.as_sat()
        }) {
            return Err(error("previous output amount is out of range"));
        }
        Ok(output)
    }

    fn validate_structure(&self) -> Result<(), PsbtError> {
        if self.inputs.len() != self.unsigned_tx.inputs.len() {
            return Err(PsbtError::InputCountMismatch {
                psbt: self.inputs.len(),
                tx: self.unsigned_tx.inputs.len(),
            });
        }
        if self.outputs.len() != self.unsigned_tx.outputs.len() {
            return Err(PsbtError::OutputCountMismatch {
                psbt: self.outputs.len(),
                tx: self.unsigned_tx.outputs.len(),
            });
        }
        if self
            .unsigned_tx
            .inputs
            .iter()
            .any(|i| !i.script_sig.is_empty())
            || self.unsigned_tx.is_segwit()
        {
            return Err(PsbtError::NonEmptyScriptSig);
        }
        if self.unsigned_tx.outputs.iter().any(|output| {
            output.value.as_sat() < 0 || output.value.as_sat() > Amount::MAX_MONEY.as_sat()
        }) {
            return Err(PsbtError::Other("PSBT output value out of range".into()));
        }
        for (index, input) in self.inputs.iter().enumerate() {
            let utxo = self.input_utxo(index)?;
            check_script_commitments(
                utxo.map(|output| &output.script_pubkey),
                input.redeem_script.as_ref(),
                input.witness_script.as_ref(),
            )
            .map_err(|reason| PsbtError::InconsistentInput { index, reason })?;
        }
        for (index, output) in self.outputs.iter().enumerate() {
            check_script_commitments(
                Some(&self.unsigned_tx.outputs[index].script_pubkey),
                output.redeem_script.as_ref(),
                output.witness_script.as_ref(),
            )
            .map_err(|reason| {
                PsbtError::Other(format!("inconsistent PSBT output {index}: {reason}"))
            })?;
        }
        match self.version {
            0 => {
                if self.fallback_lock_time.is_some()
                    || self.tx_modifiable.is_some()
                    || self.inputs.iter().any(|i| {
                        i.required_time_lock_time.is_some() || i.required_height_lock_time.is_some()
                    })
                {
                    return Err(PsbtError::Other(
                        "BIP370 fields are excluded in PSBT v0".into(),
                    ));
                }
            }
            2 => {
                if determine_lock_time(&self.inputs, self.fallback_lock_time)?
                    != self.unsigned_tx.lock_time
                {
                    return Err(PsbtError::Other(
                        "v2 fields disagree with transaction locktime".into(),
                    ));
                }
            }
            _ => {
                return Err(PsbtError::Other(format!(
                    "unsupported PSBT version {}",
                    self.version
                )))
            }
        }
        Ok(())
    }

    /// Convert v0/v2 encoding while retaining signatures and unknown metadata.
    /// V2 construction permissions and per-input locktime requirements are
    /// necessarily collapsed into the actual transaction when converting to v0.
    pub fn convert_version(&self, version: u32) -> Result<Self, PsbtError> {
        self.try_serialize()?;
        let mut result = self.clone();
        match version {
            0 => {
                result.fallback_lock_time = None;
                result.tx_modifiable = None;
                for input in &mut result.inputs {
                    input.required_time_lock_time = None;
                    input.required_height_lock_time = None;
                }
            }
            2 if self.version == 0 => {
                result.fallback_lock_time = Some(self.unsigned_tx.lock_time);
                // This conversion commits to the existing transaction. It does
                // not grant permission to modify signed inputs or outputs.
                result.tx_modifiable = Some(0);
            }
            2 => {}
            _ => {
                return Err(PsbtError::Other(format!(
                    "unsupported PSBT version {version}"
                )))
            }
        }
        result.version = version;
        result.try_serialize()?;
        Ok(result)
    }

    /// BIP370 identity uses zero sequences, distinct from the extracted txid.
    pub fn unique_id(&self) -> Result<TxHash, PsbtError> {
        self.validate_structure()?;
        let mut tx = self.unsigned_tx.clone();
        if self.version == 2 {
            for input in &mut tx.inputs {
                input.sequence = 0;
            }
        }
        Ok(tx.txid())
    }

    // =====================================================================
    // Merge (Combiner role)
    // =====================================================================

    /// Merge another PSBT into this one (BIP174 Combiner role).
    ///
    /// The two PSBTs must wrap the same unsigned transaction. Partial
    /// signatures and derivation information are combined; fields already
    /// present in `self` are kept when both PSBTs contain the same key.
    pub fn merge(&mut self, other: &Psbt) -> Result<(), PsbtError> {
        self.try_serialize()?;
        other.try_serialize()?;
        if self.version != other.version
            || self.fallback_lock_time != other.fallback_lock_time
            || self.tx_modifiable != other.tx_modifiable
            || self.inputs.iter().zip(&other.inputs).any(|(a, b)| {
                a.required_time_lock_time != b.required_time_lock_time
                    || a.required_height_lock_time != b.required_height_lock_time
            })
        {
            return Err(PsbtError::Other(
                "convert versions and reconcile v2 construction fields before combining".into(),
            ));
        }
        if self.unsigned_tx != other.unsigned_tx {
            return Err(PsbtError::TxMismatch);
        }

        let mut combined = self.clone();
        // Merge global xpubs
        merge_keyed(&mut combined.xpub, &other.xpub);

        // Merge proprietary
        merge_keyed(&mut combined.proprietary, &other.proprietary);

        // Merge unknown
        merge_keyed(&mut combined.unknown, &other.unknown);

        // Merge inputs
        for (mine, theirs) in combined.inputs.iter_mut().zip(other.inputs.iter()) {
            merge_input(mine, theirs);
        }

        // Merge outputs
        for (mine, theirs) in combined.outputs.iter_mut().zip(other.outputs.iter()) {
            merge_output(mine, theirs);
        }

        combined.try_serialize()?;
        *self = combined;
        Ok(())
    }

    // =====================================================================
    // Finalize
    // =====================================================================

    /// Extract a transaction from fields populated by an external finalizer.
    ///
    /// Each input must have `final_script_sig` and/or `final_script_witness`
    /// populated (the Finalizer role is expected to have filled these in).
    /// This does not verify signatures or whether those scripts spend the UTXOs.
    pub fn finalize(&mut self) -> Result<Transaction, PsbtError> {
        self.try_serialize()?;
        let mut tx = self.unsigned_tx.clone();
        let mut witnesses: Vec<Witness> = Vec::with_capacity(tx.inputs.len());
        let mut has_witness = false;

        for (i, psbt_in) in self.inputs.iter().enumerate() {
            // Apply final_script_sig
            if let Some(ref sig) = psbt_in.final_script_sig {
                tx.inputs[i].script_sig = sig.clone();
            }

            // Apply final_script_witness
            if let Some(ref wit_items) = psbt_in.final_script_witness {
                let witness = Witness::from_items(wit_items.clone());
                has_witness = true;
                witnesses.push(witness);
            } else {
                witnesses.push(Witness::new());
            }

            // At least one of final_script_sig or final_script_witness must exist
            if psbt_in.final_script_sig.is_none() && psbt_in.final_script_witness.is_none() {
                return Err(PsbtError::NotFinalized { index: i });
            }
        }

        if has_witness {
            tx.witness = witnesses;
        }

        Ok(tx)
    }
}

// =========================================================================
// Witness stack encode / decode helpers
// =========================================================================

/// Encode a witness stack to the PSBT value format (same as consensus
/// witness encoding: varint count, then for each item varint-len + data).
fn encode_witness_stack(items: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    VarInt(items.len() as u64).encode(&mut buf).unwrap();
    for item in items {
        VarInt(item.len() as u64).encode(&mut buf).unwrap();
        buf.extend_from_slice(item);
    }
    buf
}

/// Decode a witness stack from PSBT value bytes.
fn decode_witness_stack(data: &[u8]) -> Result<Vec<Vec<u8>>, PsbtError> {
    let mut cursor = Cursor::new(data);
    let count = read_compact_size(&mut cursor)?;
    if count > remaining(&cursor) as u64 || count > MAX_PSBT_MAPS as u64 {
        return Err(PsbtError::Other(
            "witness count exceeds available bytes or resource limit".into(),
        ));
    }
    let count = count as usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(read_value(&mut cursor)?);
    }
    if remaining(&cursor) != 0 {
        return Err(PsbtError::Other("trailing final witness bytes".into()));
    }
    Ok(items)
}

// =========================================================================
// Merge helpers
// =========================================================================

fn merge_keyed<T: Clone>(mine: &mut Vec<(Vec<u8>, T)>, theirs: &[(Vec<u8>, T)]) {
    let mut keys: HashSet<Vec<u8>> = mine.iter().map(|(key, _)| key.clone()).collect();
    for (key, value) in theirs {
        if keys.insert(key.clone()) {
            mine.push((key.clone(), value.clone()));
        }
    }
}

fn merge_input(mine: &mut PsbtInput, theirs: &PsbtInput) {
    if mine.non_witness_utxo.is_none() {
        mine.non_witness_utxo = theirs.non_witness_utxo.clone();
    }
    if mine.witness_utxo.is_none() {
        mine.witness_utxo = theirs.witness_utxo.clone();
    }
    // Merge partial sigs — add any we don't already have
    merge_keyed(&mut mine.partial_sigs, &theirs.partial_sigs);
    if mine.sighash_type.is_none() {
        mine.sighash_type = theirs.sighash_type;
    }
    if mine.redeem_script.is_none() {
        mine.redeem_script = theirs.redeem_script.clone();
    }
    if mine.witness_script.is_none() {
        mine.witness_script = theirs.witness_script.clone();
    }
    merge_keyed(&mut mine.bip32_derivation, &theirs.bip32_derivation);
    if mine.final_script_sig.is_none() {
        mine.final_script_sig = theirs.final_script_sig.clone();
    }
    if mine.final_script_witness.is_none() {
        mine.final_script_witness = theirs.final_script_witness.clone();
    }
    // Taproot
    if mine.tap_key_sig.is_none() {
        mine.tap_key_sig = theirs.tap_key_sig.clone();
    }
    merge_keyed(&mut mine.tap_script_sigs, &theirs.tap_script_sigs);
    merge_keyed(&mut mine.tap_leaf_scripts, &theirs.tap_leaf_scripts);
    merge_keyed(&mut mine.tap_bip32_derivation, &theirs.tap_bip32_derivation);
    if mine.tap_internal_key.is_none() {
        mine.tap_internal_key = theirs.tap_internal_key.clone();
    }
    if mine.tap_merkle_root.is_none() {
        mine.tap_merkle_root = theirs.tap_merkle_root;
    }
    // Unknown
    merge_keyed(&mut mine.unknown, &theirs.unknown);
}

fn merge_output(mine: &mut PsbtOutput, theirs: &PsbtOutput) {
    if mine.redeem_script.is_none() {
        mine.redeem_script = theirs.redeem_script.clone();
    }
    if mine.witness_script.is_none() {
        mine.witness_script = theirs.witness_script.clone();
    }
    merge_keyed(&mut mine.bip32_derivation, &theirs.bip32_derivation);
    if mine.tap_internal_key.is_none() {
        mine.tap_internal_key = theirs.tap_internal_key.clone();
    }
    if mine.tap_tree.is_none() {
        mine.tap_tree = theirs.tap_tree.clone();
    }
    merge_keyed(&mut mine.tap_bip32_derivation, &theirs.tap_bip32_derivation);
    // Unknown
    merge_keyed(&mut mine.unknown, &theirs.unknown);
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn script_psbt() -> Psbt {
        let witness = ScriptBuf::from_bytes(vec![0x51]);
        let redeem = ScriptBuf::p2wsh(&crate::hash::sha256(witness.as_bytes()));
        let mut parent = make_unsigned_tx();
        parent.outputs[0] = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::p2sh(&crate::hash::hash160(redeem.as_bytes())),
        };
        let mut tx = make_unsigned_tx();
        tx.inputs[0].previous_output = OutPoint::new(parent.txid(), 0);
        tx.outputs[0].script_pubkey = parent.outputs[0].script_pubkey.clone();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(parent.outputs[0].clone());
        psbt.inputs[0].non_witness_utxo = Some(parent);
        psbt.inputs[0].redeem_script = Some(redeem.clone());
        psbt.inputs[0].witness_script = Some(witness.clone());
        psbt.outputs[0].redeem_script = Some(redeem);
        psbt.outputs[0].witness_script = Some(witness);
        psbt
    }

    fn unchecked_wire(psbt: &Psbt) -> Vec<u8> {
        let mut bytes = Vec::new();
        psbt.serialize_to(&mut bytes).unwrap();
        bytes
    }

    fn assert_inconsistent_input(psbt: &Psbt) {
        assert!(matches!(
            Psbt::deserialize(&unchecked_wire(psbt)),
            Err(PsbtError::InconsistentInput { .. })
        ));
        assert!(matches!(
            psbt.try_serialize(),
            Err(PsbtError::InconsistentInput { .. })
        ));
        assert!(matches!(
            psbt.convert_version(0),
            Err(PsbtError::InconsistentInput { .. })
        ));
        assert!(matches!(
            psbt.clone().finalize(),
            Err(PsbtError::InconsistentInput { .. })
        ));
    }

    #[test]
    fn published_bip174_utxo_and_script_cases() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip174-utxo.json")).unwrap();
        let cases = fixture["vectors"].as_array().unwrap();
        assert_eq!(cases.len(), 11);
        for case in cases {
            let name = case["case"].as_str().unwrap();
            let parsed = Psbt::deserialize(&hex::decode(case["hex"].as_str().unwrap()).unwrap());
            if case["status"] == "script_mismatch" {
                assert!(
                    matches!(parsed, Err(PsbtError::InconsistentInput { .. })),
                    "{name}: {parsed:?}"
                );
            } else {
                let psbt = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(
                    Psbt::deserialize(&psbt.try_serialize().unwrap()).unwrap(),
                    psbt,
                    "{name}"
                );
                assert_eq!(
                    psbt.convert_version(2).unwrap().convert_version(0).unwrap(),
                    psbt,
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn supplied_parent_must_match_txid_index_and_witness_record() {
        for version in [0, 2] {
            let base = script_psbt().convert_version(version).unwrap();
            assert_eq!(
                base.input_utxo(0).unwrap(),
                base.inputs[0].witness_utxo.as_ref()
            );
            assert!(base.input_utxo(usize::MAX).is_err());
            let mut bad = base.clone();
            bad.unsigned_tx.inputs[0].previous_output.txid = TxHash::from_bytes([0; 32]);
            assert_inconsistent_input(&bad);
            bad = base.clone();
            bad.unsigned_tx.inputs[0].previous_output.vout = u32::MAX;
            assert_inconsistent_input(&bad);
            bad = base.clone();
            bad.inputs[0].non_witness_utxo.as_mut().unwrap().lock_time ^= 1;
            assert_inconsistent_input(&bad);
            bad = base.clone();
            bad.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(100_001);
            assert_inconsistent_input(&bad);
            bad = base.clone();
            bad.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = ScriptBuf::new();
            assert_inconsistent_input(&bad);
            let mut witnessed_parent = base.clone();
            witnessed_parent.inputs[0]
                .non_witness_utxo
                .as_mut()
                .unwrap()
                .witness = vec![Witness::from_items(vec![vec![1]])];
            assert_ne!(
                witnessed_parent.inputs[0]
                    .non_witness_utxo
                    .as_ref()
                    .unwrap()
                    .wtxid(),
                witnessed_parent.unsigned_tx.inputs[0].previous_output.txid
            );
            assert!(witnessed_parent.try_serialize().is_ok());
            let mut missing = base;
            missing.inputs[0].non_witness_utxo = None;
            assert!(missing.try_serialize().is_ok()); // witness-only remains an updater claim
            missing.inputs[0].witness_utxo = None;
            assert_eq!(missing.input_utxo(0).unwrap(), None);
            assert!(missing.try_serialize().is_ok()); // known redeem/witness commitments still agree
        }
    }

    #[test]
    fn supplied_prevout_amounts_are_bounded() {
        let check_amount = |bad: &Psbt| {
            // The wire TxOut decoder already rejects bad amounts. The public
            // in-memory model must also fail before serializing/extracting.
            assert!(matches!(Psbt::deserialize(&unchecked_wire(bad)),
                Err(PsbtError::Encode(EncodeError::InvalidData(message))) if message == "invalid output value"));
            assert!(matches!(
                bad.input_utxo(0),
                Err(PsbtError::InconsistentInput { .. })
            ));
            assert!(matches!(
                bad.try_serialize(),
                Err(PsbtError::InconsistentInput { .. })
            ));
            assert!(matches!(
                bad.clone().finalize(),
                Err(PsbtError::InconsistentInput { .. })
            ));
        };
        for amount in [-1, Amount::MAX_MONEY.as_sat() + 1] {
            let mut bad = script_psbt();
            bad.inputs[0].non_witness_utxo = None;
            bad.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(amount);
            check_amount(&bad);
            let mut bad = script_psbt();
            bad.inputs[0].witness_utxo = None;
            let parent = bad.inputs[0].non_witness_utxo.as_mut().unwrap();
            parent.outputs[0].value = Amount::from_sat(amount);
            bad.unsigned_tx.inputs[0].previous_output.txid = parent.txid();
            check_amount(&bad);
        }
    }

    #[test]
    fn known_redeem_and_witness_commitments_cannot_be_substituted() {
        for version in [0, 2] {
            let base = script_psbt().convert_version(version).unwrap();
            for redeem in [true, false] {
                let mut bad = base.clone();
                let field = if redeem {
                    &mut bad.inputs[0].redeem_script
                } else {
                    &mut bad.inputs[0].witness_script
                };
                *field = Some(ScriptBuf::from_bytes(vec![0x52]));
                assert_inconsistent_input(&bad);
                let mut bad = base.clone();
                let field = if redeem {
                    &mut bad.outputs[0].redeem_script
                } else {
                    &mut bad.outputs[0].witness_script
                };
                *field = Some(ScriptBuf::from_bytes(vec![0x52]));
                assert!(bad.try_serialize().is_err());
                assert!(Psbt::deserialize(&unchecked_wire(&bad)).is_err());
            }
            let mut native = base.clone();
            native.inputs[0].non_witness_utxo = None;
            let redeem = native.inputs[0].redeem_script.take().unwrap();
            native.inputs[0]
                .witness_utxo
                .as_mut()
                .unwrap()
                .script_pubkey = redeem;
            assert!(native.try_serialize().is_ok());
            native.inputs[0].witness_script = Some(ScriptBuf::new());
            assert_inconsistent_input(&native);
            let mut deferred = base.clone();
            deferred.inputs[0].redeem_script = None;
            deferred.inputs[0].witness_script = Some(ScriptBuf::new());
            assert!(deferred.try_serialize().is_ok()); // P2SH hides the missing witness program
            deferred.inputs[0].redeem_script = base.inputs[0].redeem_script.clone();
            assert_inconsistent_input(&deferred);
        }
    }

    #[test]
    fn combining_complementary_spending_data_fails_atomically_on_conflict() {
        let complete = script_psbt();
        let mut parent_only = complete.clone();
        parent_only.inputs[0].witness_utxo = None;
        let mut witness_only = complete.clone();
        witness_only.inputs[0].non_witness_utxo = None;
        witness_only.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(100_001);
        assert!(parent_only.try_serialize().is_ok());
        assert!(witness_only.try_serialize().is_ok());
        for (mut receiver, other) in [
            (parent_only.clone(), witness_only.clone()),
            (witness_only, parent_only),
        ] {
            let before = receiver.clone();
            assert!(matches!(
                receiver.merge(&other),
                Err(PsbtError::InconsistentInput { .. })
            ));
            assert_eq!(receiver, before);
        }
        let mut deferred = complete.clone();
        deferred.inputs[0].redeem_script = None;
        deferred.inputs[0].witness_script = Some(ScriptBuf::new());
        assert!(deferred.try_serialize().is_ok());
        let before = deferred.clone();
        assert!(deferred.merge(&complete).is_err());
        assert_eq!(deferred, before);
    }

    fn test_xonly_key() -> Vec<u8> {
        // Generator point, a real x-only key (secret scalar 1).
        hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
    }

    fn test_tap_sig_key() -> Vec<u8> {
        let mut key = test_xonly_key();
        key.extend_from_slice(&[0x01; 32]);
        key
    }

    #[test]
    fn published_bip371_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip371.json")).unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 17);
        for vector in vectors {
            let name = vector["case"].as_str().unwrap();
            let bytes = hex::decode(vector["hex"].as_str().unwrap()).unwrap();
            let parsed = Psbt::deserialize(&bytes);
            if vector["status"] == "invalid" {
                assert!(parsed.is_err(), "accepted {name}");
                continue;
            }
            let psbt = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                Psbt::deserialize(&psbt.try_serialize().unwrap()).unwrap(),
                psbt,
                "{name}"
            );
            let v2 = psbt.convert_version(2).unwrap();
            let restored = v2.convert_version(0).unwrap();
            assert_eq!(restored, psbt, "{name}");
        }
        // Published script-path input/output examples must be typed, not unknown.
        let valid: Vec<_> = vectors
            .iter()
            .filter(|v| v["status"] == "valid")
            .map(|v| Psbt::deserialize(&hex::decode(v["hex"].as_str().unwrap()).unwrap()).unwrap())
            .collect();
        assert!(valid[0].inputs[0].tap_bip32_derivation[0]
            .1
            .leaf_hashes
            .is_empty());
        assert_eq!(valid[3].inputs[0].tap_leaf_scripts.len(), 3);
        assert_eq!(valid[3].inputs[0].tap_bip32_derivation.len(), 4);
        assert!(valid[3].inputs[0].unknown.is_empty());
        assert_eq!(
            valid[4].outputs[0]
                .tap_tree
                .as_ref()
                .unwrap()
                .iter()
                .map(|l| l.depth)
                .collect::<Vec<_>>(),
            [2, 2, 1]
        );
        assert_eq!(valid[4].outputs[0].tap_bip32_derivation.len(), 4);
        assert!(valid[4].outputs[0].unknown.is_empty());
        assert_eq!(valid[5].inputs[0].tap_script_sigs.len(), 3);
    }

    #[test]
    fn hostile_taproot_records_fail_at_psbt_boundary() {
        let globals = vec![(vec![0], tx_to_bytes(&make_unsigned_tx()))];
        let mut control = vec![0xc0];
        control.extend_from_slice(&test_xonly_key());
        let check_input = |key, value| Psbt::deserialize(&raw_maps(&globals, &[(key, value)], &[]));
        for len in [0, 1, 32, 34, 64, 33 + 32 * 129] {
            let mut bad = control.clone();
            bad.resize(len, 0);
            assert!(check_input(make_key(0x15, &bad), vec![0x51, 0xc0]).is_err());
        }
        assert!(check_input(make_key(0x15, &control), vec![]).is_err());
        for version in [0xc1, 0xc2] {
            assert!(check_input(make_key(0x15, &control), vec![version]).is_err());
        }
        let mut maximum = control.clone();
        maximum.resize(33 + 32 * 128, 0);
        assert!(check_input(make_key(0x15, &maximum), vec![0xc0]).is_ok()); // empty script, valid version
        for kind in [0x14, 0x16] {
            let bad = if kind == 0x14 {
                vec![0xff; 64]
            } else {
                vec![0xff; 32]
            };
            assert!(check_input(make_key(kind, &bad), vec![0; 64]).is_err());
        }
        for value in [vec![0xff; 32], vec![0; 32]] {
            assert!(check_input(vec![0x17], value.clone()).is_err());
            assert!(Psbt::deserialize(&raw_maps(&globals, &[], &[(vec![5], value)])).is_err());
        }
        let mut invalid_control = control.clone();
        invalid_control[1..33].fill(0xff);
        assert!(check_input(make_key(0x15, &invalid_control), vec![0xc0]).is_err());
        let huge = crate::encode::encode(&VarInt(u64::MAX));
        for value in [
            vec![],
            vec![0],
            vec![1, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0],
            vec![0xfd, 0, 0, 0, 0, 0, 0],
            huge,
        ] {
            assert!(check_input(make_key(0x16, &test_xonly_key()), value.clone()).is_err());
            assert!(Psbt::deserialize(&raw_maps(
                &globals,
                &[],
                &[(make_key(7, &test_xonly_key()), value)]
            ))
            .is_err());
        }
        // Keyed input/output derivations and singleton tree reject duplicates/key data.
        let entry = (make_key(0x16, &test_xonly_key()), vec![0; 5]);
        assert!(Psbt::deserialize(&raw_maps(&globals, &[entry.clone(), entry], &[])).is_err());
        assert!(
            Psbt::deserialize(&raw_maps(&globals, &[], &[(vec![6, 0], vec![0, 0xc0, 0])])).is_err()
        );
        for kind in [0x15, 0x16] {
            let mut model = Psbt::from_unsigned_tx(make_unsigned_tx()).unwrap();
            model.inputs[0].unknown.push((vec![kind], vec![]));
            assert!(model.try_serialize().is_err());
            let mut recipient = Psbt::from_unsigned_tx(make_unsigned_tx()).unwrap();
            let before = recipient.clone();
            assert!(recipient.merge(&model).is_err());
            assert_eq!(recipient, before);
        }
    }

    #[test]
    fn taproot_tree_requires_complete_depth_first_topology() {
        let globals = vec![(vec![0], tx_to_bytes(&make_unsigned_tx()))];
        for depths in [
            vec![],
            vec![1],
            vec![0, 0],
            vec![2, 1, 2],
            vec![1, 1, 1],
            vec![129],
            vec![2, 2],
        ] {
            let value: Vec<_> = depths.iter().flat_map(|d| [*d, 0xc0, 0]).collect();
            assert!(
                Psbt::deserialize(&raw_maps(&globals, &[], &[(vec![6], value)])).is_err(),
                "{depths:?}"
            );
        }
        for value in [
            vec![0],
            vec![0, 0xc0],
            vec![0, 0xc0, 2, 0x51],
            vec![0, 0xc1, 0],
            vec![0, 0xc0, 0xfd, 0, 0],
        ] {
            assert!(Psbt::deserialize(&raw_maps(&globals, &[], &[(vec![6], value)])).is_err());
        }
        let mut deepest = (1..128).collect::<Vec<u8>>();
        deepest.extend([128, 128]);
        for depths in [vec![0], vec![1, 1], vec![1, 2, 2], vec![2, 2, 1], deepest] {
            let value: Vec<_> = depths.iter().flat_map(|d| [*d, 0xc0, 0]).collect();
            assert!(
                Psbt::deserialize(&raw_maps(&globals, &[], &[(vec![6], value)])).is_ok(),
                "{depths:?}"
            );
        }
    }
    use crate::amount::Amount;
    use crate::hash::TxHash;
    use crate::transaction::{OutPoint, TxIn};

    #[test]
    fn bip370_published_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip370.json")).unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 47);
        for vector in vectors {
            let bytes = hex::decode(vector["hex"].as_str().unwrap()).unwrap();
            let parsed = Psbt::deserialize(&bytes);
            let name = vector["case"].as_str().unwrap();
            if vector["status"] != "valid" {
                assert!(parsed.is_err(), "accepted {name}");
                continue;
            }
            let psbt = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
            if let Some(locktime) = vector["locktime"].as_u64() {
                assert_eq!(psbt.unsigned_tx.lock_time as u64, locktime, "{name}");
            }
            assert_eq!(
                Psbt::deserialize(&psbt.try_serialize().unwrap()).unwrap(),
                psbt,
                "{name}"
            );
            let v0 = psbt.convert_version(0).unwrap();
            assert_eq!(v0.unsigned_tx, psbt.unsigned_tx, "{name}");
            let v2 = v0.convert_version(2).unwrap();
            assert_eq!(v2.unsigned_tx, psbt.unsigned_tx, "{name}");
            assert_eq!(v2.unique_id().unwrap(), psbt.unique_id().unwrap(), "{name}");
        }
        // Independent unsigned transaction specified by the first valid vector.
        let first = vectors.iter().find(|v| v["status"] == "valid").unwrap();
        let psbt =
            Psbt::deserialize(&hex::decode(first["hex"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(hex::encode(tx_to_bytes(&psbt.unsigned_tx)),
            "02000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000ffffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b000000001600144dd193ac964a56ac1b9e1cca8454fe2f474f851300000000");
    }

    fn raw_maps(
        globals: &[(Vec<u8>, Vec<u8>)],
        inputs: &[(Vec<u8>, Vec<u8>)],
        outputs: &[(Vec<u8>, Vec<u8>)],
    ) -> Vec<u8> {
        let mut bytes = PSBT_MAGIC.to_vec();
        for map in [globals, inputs, outputs] {
            for (key, value) in map {
                write_kv(&mut bytes, key, value).unwrap();
            }
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn strict_map_keys_and_complete_buffers() {
        let global = vec![(vec![0], tx_to_bytes(&make_unsigned_tx()))];
        for map in 0..3 {
            let mut maps = [global.clone(), vec![], vec![]];
            // This multi-byte unknown type must be preserved, and be unique.
            let pair = (make_key(0x100, &[1]), vec![2]);
            maps[map].extend([pair.clone(), pair]);
            assert!(matches!(
                Psbt::deserialize(&raw_maps(&maps[0], &maps[1], &maps[2])),
                Err(PsbtError::DuplicateKey(_))
            ));
        }
        // Singletons with distinct key data may not masquerade as distinct keys.
        let bad_global = vec![(vec![0, 1], tx_to_bytes(&make_unsigned_tx()))];
        assert!(Psbt::deserialize(&raw_maps(&bad_global, &[], &[])).is_err());
        assert!(Psbt::deserialize(&raw_maps(&global, &[(vec![3, 1], vec![1; 4])], &[])).is_err());
        // Noncanonical CompactSize type and truncated type.
        for key in [vec![0xfd, 1, 0], vec![0xfe, 1]] {
            assert!(Psbt::deserialize(&raw_maps(&global, &[(key, vec![])], &[])).is_err());
        }
        let mut psbt = Psbt::from_unsigned_tx(make_unsigned_tx()).unwrap();
        psbt.unknown.push((make_key(0x100, &[0xfc]), vec![1, 2]));
        let mut bytes = psbt.try_serialize().unwrap();
        assert_eq!(Psbt::deserialize(&bytes).unwrap(), psbt);
        bytes.push(0);
        assert!(Psbt::deserialize(&bytes).is_err());
        let mut signed = make_unsigned_tx();
        signed.inputs[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        assert!(matches!(
            Psbt::deserialize(&raw_maps(&[(vec![0], tx_to_bytes(&signed))], &[], &[])),
            Err(PsbtError::NonEmptyScriptSig)
        ));
    }

    #[test]
    fn hostile_lengths_and_counts_are_rejected_before_allocation() {
        let huge = crate::encode::encode(&VarInt(u64::MAX));
        let mut bytes = PSBT_MAGIC.to_vec();
        bytes.extend_from_slice(&huge);
        assert!(Psbt::deserialize(&bytes).is_err());
        bytes = PSBT_MAGIC.to_vec();
        bytes.extend_from_slice(&[1, 0x20]); // unknown key
        bytes.extend_from_slice(&huge);
        assert!(Psbt::deserialize(&bytes).is_err());
        assert!(decode_witness_stack(&huge).is_err());
        let mut witness = vec![1];
        witness.extend_from_slice(&huge);
        assert!(decode_witness_stack(&witness).is_err());
        assert!(decode_witness_stack(&[0, 0]).is_err());
        // Valid v2 metadata but attacker-controlled map counts.
        let mut bytes = PSBT_MAGIC.to_vec();
        for (key, value) in [
            (0xfb, 2u32.to_le_bytes().to_vec()),
            (2, 2i32.to_le_bytes().to_vec()),
            (4, huge),
            (5, vec![0]),
        ] {
            write_kv(&mut bytes, &[key], &value).unwrap();
        }
        bytes.push(0);
        assert!(Psbt::deserialize(&bytes).is_err());
        assert!(Psbt::deserialize(&vec![0; MAX_PSBT_SIZE + 1]).is_err());
    }

    #[test]
    fn malformed_models_fail_atomically() {
        let mut base = Psbt::from_unsigned_tx(make_unsigned_tx()).unwrap();
        let mut other = base.clone();
        other.unknown.push((make_key(0x100, &[]), vec![1]));
        other.inputs.clear();
        let before = base.clone();
        assert!(base.merge(&other).is_err());
        assert_eq!(base, before);
        assert!(other.finalize().is_err());
        other.inputs = vec![PsbtInput::default(); 2];
        assert!(other.finalize().is_err());
        let mut duplicate = base.clone();
        duplicate
            .unknown
            .push((vec![0], tx_to_bytes(&duplicate.unsigned_tx)));
        assert!(duplicate.try_serialize().is_err());
        let mut managed = base.clone();
        managed.inputs[0]
            .unknown
            .push((vec![3], 1u32.to_le_bytes().to_vec()));
        assert!(managed.try_serialize().is_err());
        let v2 = base.convert_version(2).unwrap();
        assert!(base.merge(&v2).is_err());
        assert_eq!(base, before);
        base.version = 1;
        assert!(base.try_serialize().is_err());
    }

    #[test]
    fn merge_resource_failure_preserves_receiver() {
        let mut left = Psbt::from_unsigned_tx(make_unsigned_tx()).unwrap();
        let mut right = left.clone();
        for i in 0..60_000 {
            left.unknown.push((make_key(0x1000 + i, &[]), vec![]));
            right
                .unknown
                .push((make_key(0x1000 + 60_000 + i, &[]), vec![]));
        }
        let before = left.clone();
        assert!(left.merge(&right).is_err());
        assert_eq!(left, before);
    }

    #[test]
    fn v2_empty_creator_and_unique_identifier() {
        let tx = Transaction {
            version: 2,
            inputs: vec![],
            outputs: vec![],
            witness: vec![],
            lock_time: 123,
        };
        let mut creator = Psbt::from_unsigned_tx(tx).unwrap();
        creator.version = 2;
        creator.fallback_lock_time = Some(123);
        creator.tx_modifiable = Some(3);
        assert_eq!(
            Psbt::deserialize(&creator.try_serialize().unwrap()).unwrap(),
            creator
        );
        let mut a = Psbt::from_unsigned_tx(make_unsigned_tx())
            .unwrap()
            .convert_version(2)
            .unwrap();
        let mut b = a.clone();
        b.unsigned_tx.inputs[0].sequence = 1;
        assert_eq!(a.unique_id().unwrap(), b.unique_id().unwrap());
        assert_ne!(a.unsigned_tx.txid(), b.unsigned_tx.txid());
        a.unsigned_tx.lock_time = 1;
        assert!(a.try_serialize().is_err());
    }

    /// Helper: build a minimal unsigned transaction.
    fn make_unsigned_tx() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: 0xfffffffe,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::p2wpkh(&[0u8; 20]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        }
    }

    #[test]
    fn test_from_unsigned_tx() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        assert_eq!(psbt.unsigned_tx, tx);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
        assert_eq!(psbt.version, 0);
    }

    #[test]
    fn test_from_unsigned_tx_rejects_signed() {
        let mut tx = make_unsigned_tx();
        tx.inputs[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x01, 0x02]);
        assert!(Psbt::from_unsigned_tx(tx).is_err());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Add some data to exercise more paths
        psbt.inputs[0].sighash_type = Some(1);
        psbt.inputs[0].partial_sigs.push((
            vec![0x02; 33], // compressed pubkey
            vec![0x30; 72], // DER sig placeholder
        ));
        psbt.inputs[0].bip32_derivation.push((
            vec![0x02; 33],
            (
                [0xDE, 0xAD, 0xBE, 0xEF],
                vec![44 | 0x80000000, 0x80000000, 0],
            ),
        ));
        psbt.outputs[0].bip32_derivation.push((
            vec![0x03; 33],
            (
                [0xCA, 0xFE, 0xBA, 0xBE],
                vec![44 | 0x80000000, 0x80000000, 1],
            ),
        ));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();

        assert_eq!(psbt.unsigned_tx, psbt2.unsigned_tx);
        assert_eq!(psbt.version, psbt2.version);
        assert_eq!(psbt.inputs.len(), psbt2.inputs.len());
        assert_eq!(psbt.outputs.len(), psbt2.outputs.len());
        assert_eq!(psbt.inputs[0].sighash_type, psbt2.inputs[0].sighash_type);
        assert_eq!(psbt.inputs[0].partial_sigs, psbt2.inputs[0].partial_sigs);
        assert_eq!(
            psbt.inputs[0].bip32_derivation,
            psbt2.inputs[0].bip32_derivation
        );
        assert_eq!(
            psbt.outputs[0].bip32_derivation,
            psbt2.outputs[0].bip32_derivation
        );
    }

    #[test]
    fn test_serialize_deserialize_empty_psbt() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt, psbt2);
    }

    #[test]
    fn test_magic_bytes_validation() {
        // Valid PSBT starts with "psbt\xff"
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[0..5], &PSBT_MAGIC);

        // Tamper with magic
        let mut bad = bytes.clone();
        bad[0] = 0x00;
        assert!(matches!(
            Psbt::deserialize(&bad),
            Err(PsbtError::InvalidMagic)
        ));

        // Too short
        assert!(Psbt::deserialize(&[0x70, 0x73]).is_err());
    }

    #[test]
    fn test_merge_partial_sigs() {
        let tx = make_unsigned_tx();
        let mut psbt_a = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt_b = Psbt::from_unsigned_tx(tx).unwrap();

        // Signer A adds their sig
        let pubkey_a = vec![0x02; 33];
        let sig_a = vec![0x30; 72];
        psbt_a.inputs[0]
            .partial_sigs
            .push((pubkey_a.clone(), sig_a.clone()));

        // Signer B adds their sig
        let pubkey_b = vec![0x03; 33];
        let sig_b = vec![0x45; 72];
        psbt_b.inputs[0]
            .partial_sigs
            .push((pubkey_b.clone(), sig_b.clone()));

        // Merge B into A
        psbt_a.merge(&psbt_b).unwrap();

        assert_eq!(psbt_a.inputs[0].partial_sigs.len(), 2);
        assert!(psbt_a.inputs[0]
            .partial_sigs
            .iter()
            .any(|(k, v)| k == &pubkey_a && v == &sig_a));
        assert!(psbt_a.inputs[0]
            .partial_sigs
            .iter()
            .any(|(k, v)| k == &pubkey_b && v == &sig_b));
    }

    #[test]
    fn test_merge_rejects_different_tx() {
        let tx_a = make_unsigned_tx();
        let mut tx_b = make_unsigned_tx();
        tx_b.lock_time = 999;

        let mut psbt_a = Psbt::from_unsigned_tx(tx_a).unwrap();
        let psbt_b = Psbt::from_unsigned_tx(tx_b).unwrap();

        assert!(matches!(psbt_a.merge(&psbt_b), Err(PsbtError::TxMismatch)));
    }

    #[test]
    fn test_merge_idempotent() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        psbt.inputs[0]
            .partial_sigs
            .push((vec![0x02; 33], vec![0xAB; 64]));

        let copy = psbt.clone();
        psbt.merge(&copy).unwrap();

        // Same sig should not be duplicated
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn test_finalize_with_script_sig() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let final_sig = ScriptBuf::from_bytes(vec![
            0x48, // push 72 bytes
            0x30, 0x45, 0x02, 0x21, // DER sig header (placeholder)
        ]);
        psbt.inputs[0].final_script_sig = Some(final_sig.clone());

        let finalized_tx = psbt.finalize().unwrap();
        assert_eq!(finalized_tx.inputs[0].script_sig, final_sig);
    }

    #[test]
    fn test_finalize_with_witness() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let witness_items = vec![vec![0x30; 72], vec![0x02; 33]];
        psbt.inputs[0].final_script_witness = Some(witness_items.clone());

        let finalized_tx = psbt.finalize().unwrap();
        assert!(finalized_tx.is_segwit());
        assert_eq!(finalized_tx.witness.len(), 1);
        assert_eq!(finalized_tx.witness[0].len(), 2);
    }

    #[test]
    fn test_finalize_not_finalized() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        assert!(matches!(
            psbt.finalize(),
            Err(PsbtError::NotFinalized { index: 0 })
        ));
    }

    #[test]
    fn test_roundtrip_with_taproot_fields() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].tap_key_sig = Some(vec![0xAB; 64]);
        psbt.inputs[0].tap_internal_key = Some(test_xonly_key());
        psbt.inputs[0].tap_merkle_root = Some([0xEF; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .push((test_tap_sig_key(), vec![0x02; 65]));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();

        assert_eq!(psbt.inputs[0].tap_key_sig, psbt2.inputs[0].tap_key_sig);
        assert_eq!(
            psbt.inputs[0].tap_internal_key,
            psbt2.inputs[0].tap_internal_key
        );
        assert_eq!(
            psbt.inputs[0].tap_merkle_root,
            psbt2.inputs[0].tap_merkle_root
        );
        assert_eq!(
            psbt.inputs[0].tap_script_sigs,
            psbt2.inputs[0].tap_script_sigs
        );
    }

    #[test]
    fn test_roundtrip_with_witness_utxo() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::p2wpkh(&[0xBB; 20]),
        });

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt.inputs[0].witness_utxo, psbt2.inputs[0].witness_utxo);
    }

    #[test]
    fn test_roundtrip_with_redeem_witness_scripts() {
        let psbt = script_psbt();

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();

        assert_eq!(psbt.inputs[0].redeem_script, psbt2.inputs[0].redeem_script);
        assert_eq!(
            psbt.inputs[0].witness_script,
            psbt2.inputs[0].witness_script
        );
        assert_eq!(
            psbt.outputs[0].redeem_script,
            psbt2.outputs[0].redeem_script
        );
        assert_eq!(
            psbt.outputs[0].witness_script,
            psbt2.outputs[0].witness_script
        );
    }

    #[test]
    fn test_roundtrip_final_scriptwitness() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let wit = vec![vec![0x30; 72], vec![0x02; 33], vec![]];
        psbt.inputs[0].final_script_witness = Some(wit.clone());
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::new()); // also finalize with empty

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(
            psbt.inputs[0].final_script_witness,
            psbt2.inputs[0].final_script_witness
        );
    }

    #[test]
    fn test_version_roundtrip() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.version = 2;

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt2.version, 2);
    }

    #[test]
    fn test_xpub_roundtrip() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let xpub_data = vec![0x04; 78]; // typical xpub is 78 bytes
        let key_source: KeySource = ([0xDE, 0xAD, 0xBE, 0xEF], vec![44 | 0x80000000, 0]);
        psbt.xpub.push((xpub_data.clone(), key_source.clone()));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt2.xpub.len(), 1);
        assert_eq!(psbt2.xpub[0].0, xpub_data);
        assert_eq!(psbt2.xpub[0].1, key_source);
    }

    #[test]
    fn test_merge_bip32_derivation() {
        let tx = make_unsigned_tx();
        let mut psbt_a = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt_b = Psbt::from_unsigned_tx(tx).unwrap();

        psbt_a.inputs[0]
            .bip32_derivation
            .push((vec![0x02; 33], ([0xAA; 4], vec![44 | 0x80000000, 0])));
        psbt_b.inputs[0]
            .bip32_derivation
            .push((vec![0x03; 33], ([0xBB; 4], vec![44 | 0x80000000, 1])));

        psbt_a.merge(&psbt_b).unwrap();
        assert_eq!(psbt_a.inputs[0].bip32_derivation.len(), 2);
    }

    #[test]
    fn test_output_tap_internal_key_roundtrip() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.outputs[0].tap_internal_key = Some(test_xonly_key());

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(
            psbt.outputs[0].tap_internal_key,
            psbt2.outputs[0].tap_internal_key
        );
    }

    // ---- Additional coverage tests ----

    #[test]
    fn test_psbt_error_display() {
        let e1 = PsbtError::InvalidMagic;
        assert!(format!("{e1}").contains("magic"));
        let e2 = PsbtError::MissingUnsignedTx;
        assert!(format!("{e2}").contains("missing"));
        let e3 = PsbtError::InputCountMismatch { psbt: 1, tx: 2 };
        assert!(format!("{e3}").contains("1"));
        let e4 = PsbtError::OutputCountMismatch { psbt: 3, tx: 4 };
        assert!(format!("{e4}").contains("3"));
        let e5 = PsbtError::NonEmptyScriptSig;
        assert!(format!("{e5}").contains("empty"));
        let e6 = PsbtError::TxMismatch;
        assert!(format!("{e6}").contains("mismatch"));
        let e7 = PsbtError::NotFinalized { index: 0 };
        assert!(format!("{e7}").contains("0"));
        let e8 = PsbtError::DuplicateKey(vec![0x01]);
        assert!(format!("{e8}").contains("duplicate"));
        let e9 = PsbtError::Other("custom".into());
        assert!(format!("{e9}").contains("custom"));
    }

    #[test]
    fn test_from_unsigned_tx_rejects_segwit() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: 0xfffffffe,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::p2wpkh(&[0u8; 20]),
            }],
            witness: vec![crate::transaction::Witness::from_items(vec![vec![
                0x30;
                72
            ]])],
            lock_time: 0,
        };
        assert!(Psbt::from_unsigned_tx(tx).is_err());
    }

    #[test]
    fn test_key_source_roundtrip() {
        let ks: KeySource = ([0xDE, 0xAD, 0xBE, 0xEF], vec![44, 0, 0]);
        let encoded = encode_key_source(&ks);
        let decoded = decode_key_source(&encoded).unwrap();
        assert_eq!(decoded, ks);
    }

    #[test]
    fn test_key_source_decode_empty_path() {
        // 4 bytes fingerprint, 0 path elements
        let data = [0x01, 0x02, 0x03, 0x04];
        let (fp, path) = decode_key_source(&data).unwrap();
        assert_eq!(fp, [0x01, 0x02, 0x03, 0x04]);
        assert!(path.is_empty());
    }

    #[test]
    fn test_key_source_decode_invalid_length() {
        // Too short
        let result = decode_key_source(&[0x01, 0x02]);
        assert!(result.is_err());
        // Not aligned (4 + 3 = 7, invalid)
        let result2 = decode_key_source(&[0; 7]);
        assert!(result2.is_err());
    }

    #[test]
    fn test_make_key_helper() {
        let key = make_key(0x02, &[0xAA, 0xBB]);
        assert_eq!(key, vec![0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn test_make_key_no_extra() {
        let key = make_key(0x00, &[]);
        assert_eq!(key, vec![0x00]);
    }

    #[test]
    fn test_witness_stack_roundtrip() {
        let items = vec![vec![0x30; 72], vec![0x02; 33], vec![]];
        let encoded = encode_witness_stack(&items);
        let decoded = decode_witness_stack(&encoded).unwrap();
        assert_eq!(decoded, items);
    }

    #[test]
    fn test_witness_stack_empty() {
        let items: Vec<Vec<u8>> = vec![];
        let encoded = encode_witness_stack(&items);
        let decoded = decode_witness_stack(&encoded).unwrap();
        assert_eq!(decoded, items);
    }

    #[test]
    fn test_merge_with_all_fields_populated() {
        let mut psbt_b = script_psbt();
        let mut psbt_a = Psbt::from_unsigned_tx(psbt_b.unsigned_tx.clone()).unwrap();

        // Fill fields not already covered by the hash-matching spending fixture.
        psbt_b.inputs[0].sighash_type = Some(1);
        psbt_b.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x53]));
        psbt_b.inputs[0].final_script_witness = Some(vec![vec![0x54]]);
        psbt_b.inputs[0].tap_key_sig = Some(vec![0x55; 64]);
        psbt_b.inputs[0].tap_internal_key = Some(test_xonly_key());
        psbt_b.inputs[0].tap_merkle_root = Some([0x57; 32]);
        psbt_b.inputs[0]
            .tap_script_sigs
            .push((test_tap_sig_key(), vec![0x59; 65]));
        let source = TapKeySource {
            leaf_hashes: vec![[0x11; 32]],
            key_source: ([0x12; 4], vec![0x80000056, 0]),
        };
        let mut control = vec![0xc0];
        control.extend(test_xonly_key());
        psbt_b.inputs[0].tap_leaf_scripts.push((
            control,
            TapLeafScript {
                script: ScriptBuf::new(),
                leaf_version: 0xc0,
            },
        ));
        psbt_b.inputs[0]
            .tap_bip32_derivation
            .push((test_xonly_key(), source.clone()));
        psbt_b.inputs[0]
            .unknown
            .push((vec![0xFD, 0x01, 0x01], vec![0x60]));
        psbt_b.outputs[0].tap_internal_key = Some(test_xonly_key());
        psbt_b.outputs[0].tap_tree = Some(vec![TapTreeLeaf {
            depth: 0,
            leaf_version: 0xc0,
            script: ScriptBuf::new(),
        }]);
        psbt_b.outputs[0]
            .tap_bip32_derivation
            .push((test_xonly_key(), source));
        psbt_b.outputs[0]
            .unknown
            .push((vec![0xFD, 0x02, 0x01], vec![0x64]));
        psbt_b.xpub.push((vec![0x04; 78], ([0xAA; 4], vec![44])));
        psbt_b.proprietary.push((vec![0xFC, 0x01], vec![0x70]));
        psbt_b.unknown.push((vec![0xFD, 0x00, 0x01], vec![0x80]));

        psbt_a.merge(&psbt_b).unwrap();

        // Verify all fields were merged
        assert!(psbt_a.inputs[0].non_witness_utxo.is_some());
        assert!(psbt_a.inputs[0].witness_utxo.is_some());
        assert_eq!(psbt_a.inputs[0].sighash_type, Some(1));
        assert!(psbt_a.inputs[0].redeem_script.is_some());
        assert!(psbt_a.inputs[0].witness_script.is_some());
        assert!(psbt_a.inputs[0].final_script_sig.is_some());
        assert!(psbt_a.inputs[0].final_script_witness.is_some());
        assert!(psbt_a.inputs[0].tap_key_sig.is_some());
        assert!(psbt_a.inputs[0].tap_internal_key.is_some());
        assert!(psbt_a.inputs[0].tap_merkle_root.is_some());
        assert_eq!(psbt_a.inputs[0].tap_script_sigs.len(), 1);
        assert_eq!(
            psbt_a.inputs[0].tap_leaf_scripts,
            psbt_b.inputs[0].tap_leaf_scripts
        );
        assert_eq!(
            psbt_a.inputs[0].tap_bip32_derivation,
            psbt_b.inputs[0].tap_bip32_derivation
        );
        assert_eq!(psbt_a.inputs[0].unknown.len(), 1);
        assert!(psbt_a.outputs[0].redeem_script.is_some());
        assert!(psbt_a.outputs[0].witness_script.is_some());
        assert!(psbt_a.outputs[0].tap_internal_key.is_some());
        assert_eq!(psbt_a.outputs[0].tap_tree, psbt_b.outputs[0].tap_tree);
        assert_eq!(
            psbt_a.outputs[0].tap_bip32_derivation,
            psbt_b.outputs[0].tap_bip32_derivation
        );
        assert_eq!(psbt_a.outputs[0].unknown.len(), 1);
        assert_eq!(psbt_a.xpub.len(), 1);
        assert_eq!(psbt_a.proprietary.len(), 1);
        assert_eq!(psbt_a.unknown.len(), 1);
        let once = psbt_a.clone();
        psbt_a.merge(&psbt_b).unwrap();
        assert_eq!(psbt_a, once);
    }

    #[test]
    fn test_merge_does_not_duplicate_existing_fields() {
        let tx = make_unsigned_tx();
        let mut psbt_a = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt_b = Psbt::from_unsigned_tx(tx).unwrap();

        // Both have the same xpub, proprietary, unknown, tap_script_sigs, bip32_derivation
        let common_xpub = (vec![0x04; 78], ([0xAA; 4], vec![44u32]));
        psbt_a.xpub.push(common_xpub.clone());
        psbt_b.xpub.push(common_xpub);

        let common_prop = (vec![0xFC, 0x01], vec![0x70]);
        psbt_a.proprietary.push(common_prop.clone());
        psbt_b.proprietary.push(common_prop);

        let common_unknown = (vec![0xFD, 0x00, 0x01], vec![0x80]);
        psbt_a.unknown.push(common_unknown.clone());
        psbt_b.unknown.push(common_unknown);

        psbt_a.inputs[0]
            .tap_script_sigs
            .push((test_tap_sig_key(), vec![0x02; 65]));
        psbt_b.inputs[0]
            .tap_script_sigs
            .push((test_tap_sig_key(), vec![0x02; 65]));

        psbt_a.outputs[0]
            .bip32_derivation
            .push((vec![0x03; 33], ([0xBB; 4], vec![0])));
        psbt_b.outputs[0]
            .bip32_derivation
            .push((vec![0x03; 33], ([0xBB; 4], vec![0])));

        psbt_a.merge(&psbt_b).unwrap();

        assert_eq!(psbt_a.xpub.len(), 1);
        assert_eq!(psbt_a.proprietary.len(), 1);
        assert_eq!(psbt_a.unknown.len(), 1);
        assert_eq!(psbt_a.inputs[0].tap_script_sigs.len(), 1);
        assert_eq!(psbt_a.outputs[0].bip32_derivation.len(), 1);
    }

    #[test]
    fn test_serialize_with_non_witness_utxo() {
        let mut psbt = script_psbt();
        psbt.inputs[0].witness_utxo = None;

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert!(psbt2.inputs[0].non_witness_utxo.is_some());
    }

    #[test]
    fn test_serialize_with_proprietary_and_unknown() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.proprietary.push((vec![0xFC, 0x01, 0x02], vec![0x03]));
        psbt.unknown.push((vec![0xFD, 0x00, 0x01], vec![0x04]));
        psbt.inputs[0]
            .unknown
            .push((vec![0xFD, 0x01, 0x01], vec![0x05]));
        psbt.outputs[0]
            .unknown
            .push((vec![0xFD, 0x02, 0x01], vec![0x06]));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt2.proprietary.len(), 1);
        // Unknown global keys with type != 0xFC go to unknown
        // 0xFD key type goes to unknown
        assert!(!psbt2.unknown.is_empty() || !psbt2.proprietary.is_empty());
        assert_eq!(psbt2.inputs[0].unknown.len(), 1);
        assert_eq!(psbt2.outputs[0].unknown.len(), 1);
    }

    #[test]
    fn test_finalize_both_sig_and_witness() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x01, 0x02]));
        psbt.inputs[0].final_script_witness = Some(vec![vec![0x30; 72], vec![0x02; 33]]);

        let finalized = psbt.finalize().unwrap();
        assert_eq!(finalized.inputs[0].script_sig.as_bytes(), &[0x01, 0x02]);
        assert!(finalized.is_segwit());
    }

    #[test]
    fn test_deserialize_sighash_invalid_length() {
        // Build a PSBT with an invalid sighash_type length (not 4 bytes)
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let _bytes = psbt.serialize();

        // Manually construct a bad PSBT - insert a bad sighash_type entry
        // This is complex, so instead just test via a fresh construction
        // and verify the error path exists
        let bad_data = vec![0x01, 0x02]; // only 2 bytes, should be 4
        let mut buf = Vec::new();
        buf.extend_from_slice(&PSBT_MAGIC);
        // Write global map with unsigned tx
        let tx_bytes = crate::encode::encode(&psbt.unsigned_tx);
        write_kv(&mut buf, &[PSBT_GLOBAL_UNSIGNED_TX as u8], &tx_bytes).unwrap();
        buf.push(0x00); // global separator
                        // Write input map with bad sighash
        write_kv(&mut buf, &[PSBT_IN_SIGHASH_TYPE as u8], &bad_data).unwrap();
        buf.push(0x00); // input separator
                        // Output separator
        buf.push(0x00);

        let result = Psbt::deserialize(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_bad_tap_merkle_root_length() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&PSBT_MAGIC);
        let tx_bytes = crate::encode::encode(&psbt.unsigned_tx);
        write_kv(&mut buf, &[PSBT_GLOBAL_UNSIGNED_TX as u8], &tx_bytes).unwrap();
        buf.push(0x00);
        // Bad tap_merkle_root (not 32 bytes)
        write_kv(&mut buf, &[PSBT_IN_TAP_MERKLE_ROOT as u8], &[0xAA; 16]).unwrap();
        buf.push(0x00);
        buf.push(0x00);

        let result = Psbt::deserialize(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_bad_version_length() {
        let tx = make_unsigned_tx();
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&PSBT_MAGIC);
        let tx_bytes = crate::encode::encode(&psbt.unsigned_tx);
        write_kv(&mut buf, &[PSBT_GLOBAL_UNSIGNED_TX as u8], &tx_bytes).unwrap();
        // Bad version (3 bytes instead of 4)
        write_kv(&mut buf, &[PSBT_GLOBAL_VERSION as u8], &[0x01, 0x02, 0x03]).unwrap();
        buf.push(0x00);
        buf.push(0x00);
        buf.push(0x00);

        let result = Psbt::deserialize(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_input_count_mismatch() {
        let tx_a = make_unsigned_tx();
        let mut tx_b = make_unsigned_tx();
        tx_b.inputs.push(TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
            script_sig: ScriptBuf::new(),
            sequence: 0xfffffffe,
        });

        let mut psbt_a = Psbt::from_unsigned_tx(tx_a).unwrap();
        let mut psbt_b = Psbt::from_unsigned_tx(tx_b).unwrap();
        // Manually fix so unsigned_tx matches but input counts differ
        psbt_b.unsigned_tx = psbt_a.unsigned_tx.clone();

        let result = psbt_a.merge(&psbt_b);
        assert!(matches!(result, Err(PsbtError::InputCountMismatch { .. })));
    }

    #[test]
    fn test_merge_output_count_mismatch() {
        let tx = make_unsigned_tx();
        let mut psbt_a = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt_b = Psbt::from_unsigned_tx(tx).unwrap();
        // Add extra output to b
        psbt_b.outputs.push(PsbtOutput::default());

        let result = psbt_a.merge(&psbt_b);
        assert!(matches!(result, Err(PsbtError::OutputCountMismatch { .. })));
    }

    #[test]
    fn test_roundtrip_output_redeem_and_witness_scripts() {
        let psbt = script_psbt();

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(
            psbt.outputs[0].redeem_script,
            psbt2.outputs[0].redeem_script
        );
        assert_eq!(
            psbt.outputs[0].witness_script,
            psbt2.outputs[0].witness_script
        );
    }

    #[test]
    fn test_roundtrip_output_bip32_derivation() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.outputs[0].bip32_derivation.push((
            vec![0x02; 33],
            (
                [0xCA, 0xFE, 0xBA, 0xBE],
                vec![44 | 0x80000000, 0x80000000, 1],
            ),
        ));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(
            psbt.outputs[0].bip32_derivation,
            psbt2.outputs[0].bip32_derivation
        );
    }

    #[test]
    fn test_compact_size_helpers() {
        // Test write/read compact size roundtrip
        let mut buf = Vec::new();
        write_compact_size(&mut buf, 42).unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        let val = read_compact_size(&mut cursor).unwrap();
        assert_eq!(val, 42);
    }
}
