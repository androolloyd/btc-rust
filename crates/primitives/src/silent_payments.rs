//! Silent Payments (BIP352) — receive Bitcoin without revealing the
//! recipient's address on-chain.
//!
//! This module provides:
//! - `SilentPaymentAddress` — encode / decode with bech32m (`sp1` / `tsp1`).
//! - `derive_output_key` — derive a tweaked output public key for a payment.
//! - `scan_transaction` — scan a transaction for silent payment outputs.
//!
//! The cryptographic operations here are *simplified* relative to the full
//! BIP352 specification (we use tagged SHA-256 hashing in place of the full
//! ECDH + input-aggregation protocol) but the data structures and address
//! encoding match the real spec.

use crate::bech32::{bech32_encode_long, bech32_decode_long, convert_bits, Bech32Variant, Bech32Error};
use crate::hash::sha256;
use crate::network::Network;
use crate::transaction::Transaction;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SilentPaymentError {
    #[error("bech32 error: {0}")]
    Bech32(#[from] Bech32Error),
    #[error("invalid HRP: expected sp or tsp, got {0}")]
    InvalidHrp(String),
    #[error("invalid data length: expected 66 bytes (two compressed pubkeys), got {0}")]
    InvalidDataLength(usize),
    #[error("invalid scan key length: {0}")]
    InvalidScanKeyLength(usize),
    #[error("invalid spend key length: {0}")]
    InvalidSpendKeyLength(usize),
    #[error("wrong bech32 variant (expected bech32m)")]
    WrongVariant,
    #[error("version byte unsupported: {0}")]
    UnsupportedVersion(u8),
    #[error("null output pointer")]
    NullPointer,
}

// ---------------------------------------------------------------------------
// Silent Payment Address
// ---------------------------------------------------------------------------

/// A BIP352 silent payment address consisting of a scan key and a spend key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// Compressed public key used for scanning (33 bytes).
    pub scan_key: [u8; 33],
    /// Compressed public key used for spending (33 bytes).
    pub spend_key: [u8; 33],
    /// Bitcoin network this address belongs to.
    pub network: Network,
}

impl SilentPaymentAddress {
    /// Human-readable part for the given network.
    fn hrp(network: Network) -> &'static str {
        match network {
            Network::Mainnet => "sp",
            _ => "tsp",
        }
    }

    /// Encode to a bech32m string.
    ///
    /// Format: `<hrp>1<version=0><scan_key><spend_key>` encoded as bech32m.
    pub fn encode(&self) -> Result<String, SilentPaymentError> {
        let hrp = Self::hrp(self.network);

        // Payload: version (0) + scan_key (33) + spend_key (33) = 67 bytes
        let mut payload = Vec::with_capacity(67);
        payload.push(0u8); // version 0
        payload.extend_from_slice(&self.scan_key);
        payload.extend_from_slice(&self.spend_key);

        // Convert 8-bit payload to 5-bit groups.
        let data5 = convert_bits(&payload, 8, 5, true)?;

        // BIP352 addresses don't include a witness-version prefix in the
        // 5-bit data the way segwit addresses do. We simply encode the raw
        // 5-bit groups with bech32m.
        let encoded = bech32_encode_long(hrp, &data5, Bech32Variant::Bech32m)?;
        Ok(encoded)
    }

    /// Decode from a bech32m string.
    pub fn decode(s: &str) -> Result<Self, SilentPaymentError> {
        let (hrp, data5, variant) = bech32_decode_long(s)?;

        if variant != Bech32Variant::Bech32m {
            return Err(SilentPaymentError::WrongVariant);
        }

        let network = match hrp.as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            other => return Err(SilentPaymentError::InvalidHrp(other.to_string())),
        };

        // Convert 5-bit groups back to 8-bit bytes.
        let payload = convert_bits(&data5, 5, 8, false)?;

        // payload = version(1) + scan_key(33) + spend_key(33) = 67
        if payload.len() != 67 {
            return Err(SilentPaymentError::InvalidDataLength(payload.len()));
        }

        let version = payload[0];
        if version != 0 {
            return Err(SilentPaymentError::UnsupportedVersion(version));
        }

        let mut scan_key = [0u8; 33];
        let mut spend_key = [0u8; 33];
        scan_key.copy_from_slice(&payload[1..34]);
        spend_key.copy_from_slice(&payload[34..67]);

        Ok(SilentPaymentAddress {
            scan_key,
            spend_key,
            network,
        })
    }
}

// ---------------------------------------------------------------------------
// Tagged hash helper
// ---------------------------------------------------------------------------

/// Compute a BIP340-style tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag);
    let mut preimage = Vec::with_capacity(64 + msg.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(msg);
    sha256(&preimage)
}

// ---------------------------------------------------------------------------
// Key derivation (simplified BIP352)
// ---------------------------------------------------------------------------

/// Derive the tweaked output public key for a specific silent payment.
///
/// This is a *simplified* version of the BIP352 derivation. In a full
/// implementation the sender performs ECDH between the scan secret and the
/// sum of input public keys. Here we approximate with a tagged hash over
/// the provided secrets and outpoints.
///
/// # Arguments
/// * `scan_secret` -- 32-byte scan secret scalar.
/// * `spend_pubkey` -- 33-byte compressed spend public key.
/// * `outpoints` -- serialized outpoints consumed by the transaction
///   (each 36 bytes: txid || vout).
/// * `index` -- output index within this payment (for generating multiple
///   outputs to the same recipient).
///
/// # Returns
/// A 33-byte compressed public key representing the tweaked output key.
pub fn derive_output_key(
    scan_secret: &[u8; 32],
    spend_pubkey: &[u8; 33],
    outpoints: &[u8],
    index: u32,
) -> [u8; 33] {
    // Build the input to the tagged hash:
    //   tagged_hash("BIP0352/Outputs", scan_secret || outpoints || index_le)
    let mut msg = Vec::with_capacity(32 + outpoints.len() + 4);
    msg.extend_from_slice(scan_secret);
    msg.extend_from_slice(outpoints);
    msg.extend_from_slice(&index.to_le_bytes());

    let tweak = tagged_hash(b"BIP0352/Outputs", &msg);

    // In a real implementation we would add the tweak to spend_pubkey on the
    // secp256k1 curve. For this simplified version we combine via tagged
    // hash to produce a deterministic 33-byte "compressed key" result.
    let mut key_input = Vec::with_capacity(33 + 32);
    key_input.extend_from_slice(spend_pubkey);
    key_input.extend_from_slice(&tweak);

    let raw = tagged_hash(b"BIP0352/TweakedKey", &key_input);

    // Construct a pseudo-compressed pubkey: 0x02 prefix + 32 bytes.
    let mut result = [0u8; 33];
    result[0] = 0x02;
    result[1..].copy_from_slice(&raw);
    result
}

/// Scan a transaction for potential silent payment outputs (simplified).
///
/// In a real BIP352 implementation the scanner performs ECDH with each
/// input's public key and checks whether any output matches a derived
/// key. This simplified version computes a deterministic "expected key"
/// from the scan secret and the transaction's outpoints / outputs, then
/// checks each taproot-style output (OP_1 <32 bytes>) for a match.
///
/// # Returns
/// A vec of `(output_index, matched_pubkey)` pairs for outputs that match.
pub fn scan_transaction(
    scan_secret: &[u8; 32],
    spend_pubkey: &[u8; 33],
    tx: &Transaction,
) -> Vec<(u32, [u8; 33])> {
    let mut matches = Vec::new();

    // Collect serialized outpoints from the transaction inputs.
    let mut outpoints_blob = Vec::with_capacity(tx.inputs.len() * 36);
    for inp in &tx.inputs {
        outpoints_blob.extend_from_slice(inp.previous_output.txid.as_bytes());
        outpoints_blob.extend_from_slice(&inp.previous_output.vout.to_le_bytes());
    }

    // Check each output.
    for (idx, out) in tx.outputs.iter().enumerate() {
        let spk = out.script_pubkey.as_bytes();

        // Only consider taproot-style outputs: OP_1 (0x51) <push 32> <32 bytes>.
        if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
            let output_key_bytes = &spk[2..34];

            // Derive the expected key for this output index.
            let expected = derive_output_key(scan_secret, spend_pubkey, &outpoints_blob, idx as u32);

            // Compare x-coordinate (bytes 1..33 of the compressed key).
            if expected[1..] == *output_key_bytes {
                matches.push((idx as u32, expected));
            }
        }
    }

    matches
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use crate::script::ScriptBuf;
    use crate::amount::Amount;
    use crate::hash::TxHash;

    /// Helper: build deterministic test keys.
    fn test_keys() -> ([u8; 33], [u8; 33]) {
        let mut scan = [0u8; 33];
        scan[0] = 0x02;
        for i in 1..33 {
            scan[i] = i as u8;
        }
        let mut spend = [0u8; 33];
        spend[0] = 0x03;
        for i in 1..33 {
            spend[i] = (i as u8).wrapping_add(0x80);
        }
        (scan, spend)
    }

    // --- address encode / decode roundtrip ---

    #[test]
    fn test_address_roundtrip_mainnet() {
        let (scan, spend) = test_keys();
        let addr = SilentPaymentAddress {
            scan_key: scan,
            spend_key: spend,
            network: Network::Mainnet,
        };
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("sp1"), "mainnet address must start with sp1, got {encoded}");
        let decoded = SilentPaymentAddress::decode(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_roundtrip_testnet() {
        let (scan, spend) = test_keys();
        let addr = SilentPaymentAddress {
            scan_key: scan,
            spend_key: spend,
            network: Network::Testnet,
        };
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("tsp1"), "testnet address must start with tsp1, got {encoded}");
        let decoded = SilentPaymentAddress::decode(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_decode_wrong_variant() {
        // Construct a valid bech32 (not bech32m) string -- decoding should fail.
        // We test this indirectly: any random garbage with correct HRP but wrong
        // checksum type should fail.
        let (scan, spend) = test_keys();
        let addr = SilentPaymentAddress {
            scan_key: scan,
            spend_key: spend,
            network: Network::Mainnet,
        };
        let encoded = addr.encode().unwrap();
        // Corrupt the last character to break the checksum.
        let mut corrupted = encoded.clone();
        let last = corrupted.pop().unwrap();
        let replacement = if last == 'q' { 'p' } else { 'q' };
        corrupted.push(replacement);
        assert!(SilentPaymentAddress::decode(&corrupted).is_err());
    }

    #[test]
    fn test_address_decode_invalid_hrp() {
        // Build a bech32m string with wrong HRP.
        use crate::bech32::bech32_encode_long;
        let data5 = convert_bits(&[0u8; 67], 8, 5, true).unwrap();
        let bad = bech32_encode_long("bc", &data5, Bech32Variant::Bech32m).unwrap();
        let err = SilentPaymentAddress::decode(&bad).unwrap_err();
        assert!(matches!(err, SilentPaymentError::InvalidHrp(_)));
    }

    // --- key derivation ---

    #[test]
    fn test_derive_output_key_deterministic() {
        let secret = [0x42u8; 32];
        let (_, spend) = test_keys();
        let outpoints = [0xABu8; 36]; // one dummy outpoint

        let k1 = derive_output_key(&secret, &spend, &outpoints, 0);
        let k2 = derive_output_key(&secret, &spend, &outpoints, 0);
        assert_eq!(k1, k2, "derivation must be deterministic");

        // Prefix should be 0x02 (compressed even).
        assert_eq!(k1[0], 0x02);
    }

    #[test]
    fn test_derive_output_key_different_indices() {
        let secret = [0x42u8; 32];
        let (_, spend) = test_keys();
        let outpoints = [0xABu8; 36];

        let k0 = derive_output_key(&secret, &spend, &outpoints, 0);
        let k1 = derive_output_key(&secret, &spend, &outpoints, 1);
        assert_ne!(k0, k1, "different indices must yield different keys");
    }

    #[test]
    fn test_derive_output_key_different_secrets() {
        let (_, spend) = test_keys();
        let outpoints = [0xABu8; 36];

        let k1 = derive_output_key(&[0x01; 32], &spend, &outpoints, 0);
        let k2 = derive_output_key(&[0x02; 32], &spend, &outpoints, 0);
        assert_ne!(k1, k2, "different secrets must yield different keys");
    }

    // --- scan_transaction ---

    #[test]
    fn test_scan_transaction_no_match() {
        let secret = [0x42u8; 32];
        let (_, spend) = test_keys();

        let p2wpkh_script = {
            let mut v = vec![0x00, 0x14];
            v.extend_from_slice(&[0u8; 20]);
            v
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xBB; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::from_bytes(p2wpkh_script),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let matches = scan_transaction(&secret, &spend, &tx);
        assert!(matches.is_empty(), "should not match non-taproot outputs");
    }

    #[test]
    fn test_address_roundtrip_signet() {
        let (scan, spend) = test_keys();
        let addr = SilentPaymentAddress {
            scan_key: scan,
            spend_key: spend,
            network: Network::Signet,
        };
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("tsp1"), "signet address must start with tsp1, got {encoded}");
        let decoded = SilentPaymentAddress::decode(&encoded).unwrap();
        assert_eq!(decoded.network, Network::Testnet); // signet decodes as testnet HRP "tsp"
    }

    #[test]
    fn test_address_roundtrip_regtest() {
        let (scan, spend) = test_keys();
        let addr = SilentPaymentAddress {
            scan_key: scan,
            spend_key: spend,
            network: Network::Regtest,
        };
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("tsp1"));
    }

    #[test]
    fn test_silent_payment_error_display() {
        let errors: Vec<SilentPaymentError> = vec![
            SilentPaymentError::Bech32(crate::bech32::Bech32Error::InvalidChecksum),
            SilentPaymentError::InvalidHrp("bad".into()),
            SilentPaymentError::InvalidDataLength(10),
            SilentPaymentError::InvalidScanKeyLength(10),
            SilentPaymentError::InvalidSpendKeyLength(10),
            SilentPaymentError::WrongVariant,
            SilentPaymentError::UnsupportedVersion(1),
            SilentPaymentError::NullPointer,
        ];
        for e in errors {
            let s = format!("{}", e);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_derive_output_key_different_outpoints() {
        let secret = [0x42u8; 32];
        let (_, spend) = test_keys();

        let k1 = derive_output_key(&secret, &spend, &[0xAB; 36], 0);
        let k2 = derive_output_key(&secret, &spend, &[0xCD; 36], 0);
        assert_ne!(k1, k2, "different outpoints must yield different keys");
    }

    #[test]
    fn test_scan_transaction_multiple_outputs() {
        let secret = [0x42u8; 32];
        let (_, spend) = test_keys();

        let outpoints_blob = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0xDD; 32]);
            v.extend_from_slice(&0u32.to_le_bytes());
            v
        };

        // Create two taproot outputs, one matching at index 0, one non-matching at index 1
        let derived0 = derive_output_key(&secret, &spend, &outpoints_blob, 0);
        let mut spk0 = vec![0x51, 0x20];
        spk0.extend_from_slice(&derived0[1..]);

        // Second output won't match (random x-coordinate)
        let mut spk1 = vec![0x51, 0x20];
        spk1.extend_from_slice(&[0xFF; 32]);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xDD; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(spk0),
                },
                TxOut {
                    value: Amount::from_sat(5_000),
                    script_pubkey: ScriptBuf::from_bytes(spk1),
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        };

        let matches = scan_transaction(&secret, &spend, &tx);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 0);
    }

    #[test]
    fn test_scan_transaction_with_match() {
        let secret = [0x42u8; 32];
        let (_, spend) = test_keys();

        // Build a transaction whose taproot output contains the derived key.
        let outpoints_blob = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0xCC; 32]); // txid
            v.extend_from_slice(&0u32.to_le_bytes()); // vout
            v
        };

        let derived = derive_output_key(&secret, &spend, &outpoints_blob, 0);
        // Build a taproot scriptPubKey: OP_1 OP_PUSH32 <x-coordinate>
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&derived[1..]); // x-coordinate (32 bytes)

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xCC; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let matches = scan_transaction(&secret, &spend, &tx);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 0); // output index
        assert_eq!(matches[0].1, derived);
    }
}
