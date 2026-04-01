//! Partially Signed Bitcoin Transactions (PSBT) — BIP174 / BIP370 / BIP371
//!
//! PSBT is a standardized format for passing around unsigned or partially-signed
//! transactions between wallets, signers, and finalizers. The binary format uses
//! magic bytes `0x70736274ff` ("psbt" + 0xff separator) followed by key-value
//! maps: one global map, then per-input and per-output maps separated by 0x00.

use crate::encode::{Encodable, Decodable, EncodeError, VarInt};
use crate::script::ScriptBuf;
use crate::transaction::{Transaction, TxOut, Witness};
use std::io::{self, Read, Write, Cursor};
use thiserror::Error;

// ---------------------------------------------------------------------------
// PSBT magic
// ---------------------------------------------------------------------------

/// PSBT magic bytes: "psbt" (0x70 0x73 0x62 0x74) followed by 0xff separator.
const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

// ---------------------------------------------------------------------------
// Global key types (BIP174)
// ---------------------------------------------------------------------------

const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_XPUB: u8 = 0x01;
const PSBT_GLOBAL_VERSION: u8 = 0xFB;

// ---------------------------------------------------------------------------
// Per-input key types (BIP174 / BIP371)
// ---------------------------------------------------------------------------

const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;

// ---------------------------------------------------------------------------
// Per-output key types (BIP174 / BIP371)
// ---------------------------------------------------------------------------

const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;

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
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// KeySource — BIP32 derivation origin
// ---------------------------------------------------------------------------

/// A BIP32 key source: master fingerprint (4 bytes) + derivation path indices.
pub type KeySource = ([u8; 4], Vec<u32>);

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
    // Taproot fields (BIP371)
    pub tap_key_sig: Option<Vec<u8>>,
    pub tap_script_sigs: Vec<(Vec<u8>, Vec<u8>)>,
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
fn read_key<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, PsbtError> {
    let key_len = read_compact_size(reader)?;
    if key_len == 0 {
        return Ok(None); // separator
    }
    let mut key = vec![0u8; key_len as usize];
    reader.read_exact(&mut key)?;
    Ok(Some(key))
}

/// Read a PSBT value blob.
fn read_value<R: Read>(reader: &mut R) -> Result<Vec<u8>, PsbtError> {
    let val_len = read_compact_size(reader)?;
    let mut val = vec![0u8; val_len as usize];
    reader.read_exact(&mut val)?;
    Ok(val)
}

/// Build a key from its type byte and optional extra data.
fn make_key(key_type: u8, extra: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + extra.len());
    k.push(key_type);
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
        let mut buf = Vec::new();
        self.serialize_to(&mut buf).expect("serializing to Vec should not fail");
        buf
    }

    fn serialize_to<W: Write>(&self, w: &mut W) -> Result<(), PsbtError> {
        // -- Magic --
        w.write_all(&PSBT_MAGIC)?;

        // -- Global map --
        // Unsigned tx (key type 0x00, no key data)
        let tx_bytes = tx_to_bytes(&self.unsigned_tx);
        write_kv(w, &[PSBT_GLOBAL_UNSIGNED_TX], &tx_bytes)?;

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
            write_kv(w, &[PSBT_GLOBAL_VERSION], &val)?;
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
        for input in &self.inputs {
            self.serialize_input(w, input)?;
            w.write_all(&[0x00])?;
        }

        // -- Per-output maps --
        for output in &self.outputs {
            self.serialize_output(w, output)?;
            w.write_all(&[0x00])?;
        }

        Ok(())
    }

    fn serialize_input<W: Write>(&self, w: &mut W, inp: &PsbtInput) -> Result<(), PsbtError> {
        if let Some(ref tx) = inp.non_witness_utxo {
            write_kv(w, &[PSBT_IN_NON_WITNESS_UTXO], &tx_to_bytes(tx))?;
        }
        if let Some(ref txo) = inp.witness_utxo {
            write_kv(w, &[PSBT_IN_WITNESS_UTXO], &txout_to_bytes(txo))?;
        }
        for (pubkey, sig) in &inp.partial_sigs {
            let key = make_key(PSBT_IN_PARTIAL_SIG, pubkey);
            write_kv(w, &key, sig)?;
        }
        if let Some(sht) = inp.sighash_type {
            write_kv(w, &[PSBT_IN_SIGHASH_TYPE], &sht.to_le_bytes())?;
        }
        if let Some(ref rs) = inp.redeem_script {
            write_kv(w, &[PSBT_IN_REDEEM_SCRIPT], rs.as_bytes())?;
        }
        if let Some(ref ws) = inp.witness_script {
            write_kv(w, &[PSBT_IN_WITNESS_SCRIPT], ws.as_bytes())?;
        }
        for (pubkey, ks) in &inp.bip32_derivation {
            let key = make_key(PSBT_IN_BIP32_DERIVATION, pubkey);
            write_kv(w, &key, &encode_key_source(ks))?;
        }
        if let Some(ref fs) = inp.final_script_sig {
            write_kv(w, &[PSBT_IN_FINAL_SCRIPTSIG], fs.as_bytes())?;
        }
        if let Some(ref fw) = inp.final_script_witness {
            let val = encode_witness_stack(fw);
            write_kv(w, &[PSBT_IN_FINAL_SCRIPTWITNESS], &val)?;
        }
        // Taproot
        if let Some(ref tks) = inp.tap_key_sig {
            write_kv(w, &[PSBT_IN_TAP_KEY_SIG], tks)?;
        }
        for (key_data, sig) in &inp.tap_script_sigs {
            let key = make_key(PSBT_IN_TAP_SCRIPT_SIG, key_data);
            write_kv(w, &key, sig)?;
        }
        if let Some(ref tik) = inp.tap_internal_key {
            write_kv(w, &[PSBT_IN_TAP_INTERNAL_KEY], tik)?;
        }
        if let Some(ref tmr) = inp.tap_merkle_root {
            write_kv(w, &[PSBT_IN_TAP_MERKLE_ROOT], tmr)?;
        }
        // Unknown
        for (key, val) in &inp.unknown {
            write_kv(w, key, val)?;
        }
        Ok(())
    }

    fn serialize_output<W: Write>(&self, w: &mut W, out: &PsbtOutput) -> Result<(), PsbtError> {
        if let Some(ref rs) = out.redeem_script {
            write_kv(w, &[PSBT_OUT_REDEEM_SCRIPT], rs.as_bytes())?;
        }
        if let Some(ref ws) = out.witness_script {
            write_kv(w, &[PSBT_OUT_WITNESS_SCRIPT], ws.as_bytes())?;
        }
        for (pubkey, ks) in &out.bip32_derivation {
            let key = make_key(PSBT_OUT_BIP32_DERIVATION, pubkey);
            write_kv(w, &key, &encode_key_source(ks))?;
        }
        if let Some(ref tik) = out.tap_internal_key {
            write_kv(w, &[PSBT_OUT_TAP_INTERNAL_KEY], tik)?;
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

    /// Deserialize a PSBT from its binary representation.
    pub fn deserialize(data: &[u8]) -> Result<Self, PsbtError> {
        let mut cursor = Cursor::new(data);
        Self::deserialize_from(&mut cursor)
    }

    fn deserialize_from<R: Read>(r: &mut R) -> Result<Self, PsbtError> {
        // -- Magic --
        let mut magic = [0u8; 5];
        r.read_exact(&mut magic)?;
        if magic != PSBT_MAGIC {
            return Err(PsbtError::InvalidMagic);
        }

        // -- Global map --
        let mut unsigned_tx: Option<Transaction> = None;
        let mut version: u32 = 0;
        let mut xpub: Vec<(Vec<u8>, KeySource)> = Vec::new();
        let mut proprietary: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut unknown: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        loop {
            let key = match read_key(r)? {
                Some(k) => k,
                None => break, // separator
            };
            let value = read_value(r)?;

            if key.is_empty() {
                return Err(PsbtError::Other("empty key in global map".into()));
            }
            let key_type = key[0];
            let key_data = &key[1..];

            match key_type {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    if unsigned_tx.is_some() {
                        return Err(PsbtError::DuplicateKey(key));
                    }
                    unsigned_tx = Some(tx_from_bytes(&value)?);
                }
                PSBT_GLOBAL_XPUB => {
                    let ks = decode_key_source(&value)?;
                    xpub.push((key_data.to_vec(), ks));
                }
                PSBT_GLOBAL_VERSION => {
                    if value.len() != 4 {
                        return Err(PsbtError::Other("invalid PSBT version length".into()));
                    }
                    version = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                }
                _ => {
                    // Proprietary keys start with 0xFC
                    if key_type == 0xFC {
                        proprietary.push((key.clone(), value));
                    } else {
                        unknown.push((key.clone(), value));
                    }
                }
            }
        }

        let tx = unsigned_tx.ok_or(PsbtError::MissingUnsignedTx)?;
        let num_inputs = tx.inputs.len();
        let num_outputs = tx.outputs.len();

        // -- Per-input maps --
        let mut inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(Self::deserialize_input(r)?);
        }

        // -- Per-output maps --
        let mut outputs = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            outputs.push(Self::deserialize_output(r)?);
        }

        Ok(Psbt {
            unsigned_tx: tx,
            version,
            xpub,
            inputs,
            outputs,
            proprietary,
            unknown,
        })
    }

    fn deserialize_input<R: Read>(r: &mut R) -> Result<PsbtInput, PsbtError> {
        let mut inp = PsbtInput::default();

        loop {
            let key = match read_key(r)? {
                Some(k) => k,
                None => break,
            };
            let value = read_value(r)?;

            if key.is_empty() {
                return Err(PsbtError::Other("empty key in input map".into()));
            }
            let key_type = key[0];
            let key_data = &key[1..];

            match key_type {
                PSBT_IN_NON_WITNESS_UTXO => {
                    inp.non_witness_utxo = Some(tx_from_bytes(&value)?);
                }
                PSBT_IN_WITNESS_UTXO => {
                    inp.witness_utxo = Some(txout_from_bytes(&value)?);
                }
                PSBT_IN_PARTIAL_SIG => {
                    inp.partial_sigs.push((key_data.to_vec(), value));
                }
                PSBT_IN_SIGHASH_TYPE => {
                    if value.len() != 4 {
                        return Err(PsbtError::Other("invalid sighash_type length".into()));
                    }
                    inp.sighash_type = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
                PSBT_IN_REDEEM_SCRIPT => {
                    inp.redeem_script = Some(ScriptBuf::from_bytes(value));
                }
                PSBT_IN_WITNESS_SCRIPT => {
                    inp.witness_script = Some(ScriptBuf::from_bytes(value));
                }
                PSBT_IN_BIP32_DERIVATION => {
                    let ks = decode_key_source(&value)?;
                    inp.bip32_derivation.push((key_data.to_vec(), ks));
                }
                PSBT_IN_FINAL_SCRIPTSIG => {
                    inp.final_script_sig = Some(ScriptBuf::from_bytes(value));
                }
                PSBT_IN_FINAL_SCRIPTWITNESS => {
                    inp.final_script_witness = Some(decode_witness_stack(&value)?);
                }
                PSBT_IN_TAP_KEY_SIG => {
                    inp.tap_key_sig = Some(value);
                }
                PSBT_IN_TAP_SCRIPT_SIG => {
                    inp.tap_script_sigs.push((key_data.to_vec(), value));
                }
                PSBT_IN_TAP_INTERNAL_KEY => {
                    inp.tap_internal_key = Some(value);
                }
                PSBT_IN_TAP_MERKLE_ROOT => {
                    if value.len() != 32 {
                        return Err(PsbtError::Other("invalid tap_merkle_root length".into()));
                    }
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&value);
                    inp.tap_merkle_root = Some(root);
                }
                _ => {
                    inp.unknown.push((key.clone(), value));
                }
            }
        }
        Ok(inp)
    }

    fn deserialize_output<R: Read>(r: &mut R) -> Result<PsbtOutput, PsbtError> {
        let mut out = PsbtOutput::default();

        loop {
            let key = match read_key(r)? {
                Some(k) => k,
                None => break,
            };
            let value = read_value(r)?;

            if key.is_empty() {
                return Err(PsbtError::Other("empty key in output map".into()));
            }
            let key_type = key[0];
            let key_data = &key[1..];

            match key_type {
                PSBT_OUT_REDEEM_SCRIPT => {
                    out.redeem_script = Some(ScriptBuf::from_bytes(value));
                }
                PSBT_OUT_WITNESS_SCRIPT => {
                    out.witness_script = Some(ScriptBuf::from_bytes(value));
                }
                PSBT_OUT_BIP32_DERIVATION => {
                    let ks = decode_key_source(&value)?;
                    out.bip32_derivation.push((key_data.to_vec(), ks));
                }
                PSBT_OUT_TAP_INTERNAL_KEY => {
                    out.tap_internal_key = Some(value);
                }
                _ => {
                    out.unknown.push((key.clone(), value));
                }
            }
        }
        Ok(out)
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
        if self.unsigned_tx != other.unsigned_tx {
            return Err(PsbtError::TxMismatch);
        }

        // Merge global xpubs
        for (xpub, ks) in &other.xpub {
            if !self.xpub.iter().any(|(x, _)| x == xpub) {
                self.xpub.push((xpub.clone(), ks.clone()));
            }
        }

        // Merge proprietary
        for (k, v) in &other.proprietary {
            if !self.proprietary.iter().any(|(ek, _)| ek == k) {
                self.proprietary.push((k.clone(), v.clone()));
            }
        }

        // Merge unknown
        for (k, v) in &other.unknown {
            if !self.unknown.iter().any(|(ek, _)| ek == k) {
                self.unknown.push((k.clone(), v.clone()));
            }
        }

        // Merge inputs
        if self.inputs.len() != other.inputs.len() {
            return Err(PsbtError::InputCountMismatch {
                psbt: self.inputs.len(),
                tx: other.inputs.len(),
            });
        }
        for (mine, theirs) in self.inputs.iter_mut().zip(other.inputs.iter()) {
            merge_input(mine, theirs);
        }

        // Merge outputs
        if self.outputs.len() != other.outputs.len() {
            return Err(PsbtError::OutputCountMismatch {
                psbt: self.outputs.len(),
                tx: other.outputs.len(),
            });
        }
        for (mine, theirs) in self.outputs.iter_mut().zip(other.outputs.iter()) {
            merge_output(mine, theirs);
        }

        Ok(())
    }

    // =====================================================================
    // Finalize
    // =====================================================================

    /// Finalize the PSBT and extract a complete, signed `Transaction`.
    ///
    /// Each input must have `final_script_sig` and/or `final_script_witness`
    /// populated (the Finalizer role is expected to have filled these in).
    pub fn finalize(&mut self) -> Result<Transaction, PsbtError> {
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
    let count = read_compact_size(&mut cursor)? as usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_compact_size(&mut cursor)? as usize;
        let mut item = vec![0u8; len];
        cursor.read_exact(&mut item)?;
        items.push(item);
    }
    Ok(items)
}

// =========================================================================
// Merge helpers
// =========================================================================

fn merge_input(mine: &mut PsbtInput, theirs: &PsbtInput) {
    if mine.non_witness_utxo.is_none() {
        mine.non_witness_utxo = theirs.non_witness_utxo.clone();
    }
    if mine.witness_utxo.is_none() {
        mine.witness_utxo = theirs.witness_utxo.clone();
    }
    // Merge partial sigs — add any we don't already have
    for (pk, sig) in &theirs.partial_sigs {
        if !mine.partial_sigs.iter().any(|(k, _)| k == pk) {
            mine.partial_sigs.push((pk.clone(), sig.clone()));
        }
    }
    if mine.sighash_type.is_none() {
        mine.sighash_type = theirs.sighash_type;
    }
    if mine.redeem_script.is_none() {
        mine.redeem_script = theirs.redeem_script.clone();
    }
    if mine.witness_script.is_none() {
        mine.witness_script = theirs.witness_script.clone();
    }
    for (pk, ks) in &theirs.bip32_derivation {
        if !mine.bip32_derivation.iter().any(|(k, _)| k == pk) {
            mine.bip32_derivation.push((pk.clone(), ks.clone()));
        }
    }
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
    for (k, v) in &theirs.tap_script_sigs {
        if !mine.tap_script_sigs.iter().any(|(ek, _)| ek == k) {
            mine.tap_script_sigs.push((k.clone(), v.clone()));
        }
    }
    if mine.tap_internal_key.is_none() {
        mine.tap_internal_key = theirs.tap_internal_key.clone();
    }
    if mine.tap_merkle_root.is_none() {
        mine.tap_merkle_root = theirs.tap_merkle_root;
    }
    // Unknown
    for (k, v) in &theirs.unknown {
        if !mine.unknown.iter().any(|(ek, _)| ek == k) {
            mine.unknown.push((k.clone(), v.clone()));
        }
    }
}

fn merge_output(mine: &mut PsbtOutput, theirs: &PsbtOutput) {
    if mine.redeem_script.is_none() {
        mine.redeem_script = theirs.redeem_script.clone();
    }
    if mine.witness_script.is_none() {
        mine.witness_script = theirs.witness_script.clone();
    }
    for (pk, ks) in &theirs.bip32_derivation {
        if !mine.bip32_derivation.iter().any(|(k, _)| k == pk) {
            mine.bip32_derivation.push((pk.clone(), ks.clone()));
        }
    }
    if mine.tap_internal_key.is_none() {
        mine.tap_internal_key = theirs.tap_internal_key.clone();
    }
    // Unknown
    for (k, v) in &theirs.unknown {
        if !mine.unknown.iter().any(|(ek, _)| ek == k) {
            mine.unknown.push((k.clone(), v.clone()));
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::hash::TxHash;
    use crate::transaction::{OutPoint, TxIn};

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
            ([0xDE, 0xAD, 0xBE, 0xEF], vec![44 | 0x80000000, 0 | 0x80000000, 0]),
        ));
        psbt.outputs[0].bip32_derivation.push((
            vec![0x03; 33],
            ([0xCA, 0xFE, 0xBA, 0xBE], vec![44 | 0x80000000, 0 | 0x80000000, 1]),
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
        assert!(psbt_a.inputs[0].partial_sigs.iter().any(|(k, v)| k == &pubkey_a && v == &sig_a));
        assert!(psbt_a.inputs[0].partial_sigs.iter().any(|(k, v)| k == &pubkey_b && v == &sig_b));
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
        psbt.inputs[0].tap_internal_key = Some(vec![0xCD; 32]);
        psbt.inputs[0].tap_merkle_root = Some([0xEF; 32]);
        psbt.inputs[0]
            .tap_script_sigs
            .push((vec![0x01; 64], vec![0x02; 65]));

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
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let redeem = ScriptBuf::from_bytes(vec![0x51, 0x21, 0x02]);
        let witness_s = ScriptBuf::from_bytes(vec![0x52, 0x21]);

        psbt.inputs[0].redeem_script = Some(redeem.clone());
        psbt.inputs[0].witness_script = Some(witness_s.clone());
        psbt.outputs[0].redeem_script = Some(redeem.clone());
        psbt.outputs[0].witness_script = Some(witness_s.clone());

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

        psbt_a.inputs[0].bip32_derivation.push((
            vec![0x02; 33],
            ([0xAA; 4], vec![44 | 0x80000000, 0]),
        ));
        psbt_b.inputs[0].bip32_derivation.push((
            vec![0x03; 33],
            ([0xBB; 4], vec![44 | 0x80000000, 1]),
        ));

        psbt_a.merge(&psbt_b).unwrap();
        assert_eq!(psbt_a.inputs[0].bip32_derivation.len(), 2);
    }

    #[test]
    fn test_output_tap_internal_key_roundtrip() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.outputs[0].tap_internal_key = Some(vec![0xAA; 32]);

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
        assert!(format!("{}", e1).contains("magic"));
        let e2 = PsbtError::MissingUnsignedTx;
        assert!(format!("{}", e2).contains("missing"));
        let e3 = PsbtError::InputCountMismatch { psbt: 1, tx: 2 };
        assert!(format!("{}", e3).contains("1"));
        let e4 = PsbtError::OutputCountMismatch { psbt: 3, tx: 4 };
        assert!(format!("{}", e4).contains("3"));
        let e5 = PsbtError::NonEmptyScriptSig;
        assert!(format!("{}", e5).contains("empty"));
        let e6 = PsbtError::TxMismatch;
        assert!(format!("{}", e6).contains("mismatch"));
        let e7 = PsbtError::NotFinalized { index: 0 };
        assert!(format!("{}", e7).contains("0"));
        let e8 = PsbtError::DuplicateKey(vec![0x01]);
        assert!(format!("{}", e8).contains("duplicate"));
        let e9 = PsbtError::Other("custom".into());
        assert!(format!("{}", e9).contains("custom"));
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
            witness: vec![crate::transaction::Witness::from_items(vec![vec![0x30; 72]])],
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
        let tx = make_unsigned_tx();
        let mut psbt_a = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let mut psbt_b = Psbt::from_unsigned_tx(tx).unwrap();

        // Fill psbt_b with fields that psbt_a doesn't have
        psbt_b.inputs[0].non_witness_utxo = Some(make_unsigned_tx());
        psbt_b.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::p2wpkh(&[0xBB; 20]),
        });
        psbt_b.inputs[0].sighash_type = Some(1);
        psbt_b.inputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        psbt_b.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x52]));
        psbt_b.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x53]));
        psbt_b.inputs[0].final_script_witness = Some(vec![vec![0x54]]);
        psbt_b.inputs[0].tap_key_sig = Some(vec![0x55; 64]);
        psbt_b.inputs[0].tap_internal_key = Some(vec![0x56; 32]);
        psbt_b.inputs[0].tap_merkle_root = Some([0x57; 32]);
        psbt_b.inputs[0].tap_script_sigs.push((vec![0x58; 64], vec![0x59; 65]));
        psbt_b.inputs[0].unknown.push((vec![0xFE, 0x01], vec![0x60]));
        psbt_b.outputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x61]));
        psbt_b.outputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x62]));
        psbt_b.outputs[0].tap_internal_key = Some(vec![0x63; 32]);
        psbt_b.outputs[0].unknown.push((vec![0xFE, 0x02], vec![0x64]));
        psbt_b.xpub.push((vec![0x04; 78], ([0xAA; 4], vec![44])));
        psbt_b.proprietary.push((vec![0xFC, 0x01], vec![0x70]));
        psbt_b.unknown.push((vec![0xFD, 0x01], vec![0x80]));

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
        assert_eq!(psbt_a.inputs[0].unknown.len(), 1);
        assert!(psbt_a.outputs[0].redeem_script.is_some());
        assert!(psbt_a.outputs[0].witness_script.is_some());
        assert!(psbt_a.outputs[0].tap_internal_key.is_some());
        assert_eq!(psbt_a.outputs[0].unknown.len(), 1);
        assert_eq!(psbt_a.xpub.len(), 1);
        assert_eq!(psbt_a.proprietary.len(), 1);
        assert_eq!(psbt_a.unknown.len(), 1);
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

        let common_unknown = (vec![0xFD, 0x01], vec![0x80]);
        psbt_a.unknown.push(common_unknown.clone());
        psbt_b.unknown.push(common_unknown);

        psbt_a.inputs[0].tap_script_sigs.push((vec![0x01; 64], vec![0x02; 65]));
        psbt_b.inputs[0].tap_script_sigs.push((vec![0x01; 64], vec![0x02; 65]));

        psbt_a.outputs[0].bip32_derivation.push((vec![0x03; 33], ([0xBB; 4], vec![0])));
        psbt_b.outputs[0].bip32_derivation.push((vec![0x03; 33], ([0xBB; 4], vec![0])));

        psbt_a.merge(&psbt_b).unwrap();

        assert_eq!(psbt_a.xpub.len(), 1);
        assert_eq!(psbt_a.proprietary.len(), 1);
        assert_eq!(psbt_a.unknown.len(), 1);
        assert_eq!(psbt_a.inputs[0].tap_script_sigs.len(), 1);
        assert_eq!(psbt_a.outputs[0].bip32_derivation.len(), 1);
    }

    #[test]
    fn test_serialize_with_non_witness_utxo() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(tx);

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert!(psbt2.inputs[0].non_witness_utxo.is_some());
    }

    #[test]
    fn test_serialize_with_proprietary_and_unknown() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.proprietary.push((vec![0xFC, 0x01, 0x02], vec![0x03]));
        psbt.unknown.push((vec![0xFD, 0x01], vec![0x04]));
        psbt.inputs[0].unknown.push((vec![0xFE, 0x01], vec![0x05]));
        psbt.outputs[0].unknown.push((vec![0xFE, 0x02], vec![0x06]));

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
        write_kv(&mut buf, &[PSBT_GLOBAL_UNSIGNED_TX], &tx_bytes).unwrap();
        buf.push(0x00); // global separator
        // Write input map with bad sighash
        write_kv(&mut buf, &[PSBT_IN_SIGHASH_TYPE], &bad_data).unwrap();
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
        write_kv(&mut buf, &[PSBT_GLOBAL_UNSIGNED_TX], &tx_bytes).unwrap();
        buf.push(0x00);
        // Bad tap_merkle_root (not 32 bytes)
        write_kv(&mut buf, &[PSBT_IN_TAP_MERKLE_ROOT], &[0xAA; 16]).unwrap();
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
        write_kv(&mut buf, &[PSBT_GLOBAL_UNSIGNED_TX], &tx_bytes).unwrap();
        // Bad version (3 bytes instead of 4)
        write_kv(&mut buf, &[PSBT_GLOBAL_VERSION], &[0x01, 0x02, 0x03]).unwrap();
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
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.outputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x01, 0x02]));
        psbt.outputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x03, 0x04]));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt.outputs[0].redeem_script, psbt2.outputs[0].redeem_script);
        assert_eq!(psbt.outputs[0].witness_script, psbt2.outputs[0].witness_script);
    }

    #[test]
    fn test_roundtrip_output_bip32_derivation() {
        let tx = make_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.outputs[0].bip32_derivation.push((
            vec![0x02; 33],
            ([0xCA, 0xFE, 0xBA, 0xBE], vec![44 | 0x80000000, 0 | 0x80000000, 1]),
        ));

        let bytes = psbt.serialize();
        let psbt2 = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(psbt.outputs[0].bip32_derivation, psbt2.outputs[0].bip32_derivation);
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
