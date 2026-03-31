//! Output Descriptors (BIP380-387).
//!
//! Output descriptors are a human-readable language for describing how to
//! derive `scriptPubKey`s for wallet operations. They cover all standard
//! Bitcoin output types (P2PK, P2PKH, P2WPKH, P2SH, P2WSH, P2TR, multisig)
//! and support a checksum for safe copy-pasting.
//!
//! This module provides:
//! - `Descriptor` enum covering all standard descriptor types
//! - Parsing from descriptor strings (`Descriptor::parse`)
//! - Serialization back to descriptor strings (`Descriptor::to_string`)
//! - Simplified `script_pubkey` derivation (pk, pkh, wpkh)
//! - BIP380 descriptor checksum computation (`descriptor_checksum`)

use crate::hash::hash160;
use crate::script::ScriptBuf;
use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum DescriptorError {
    #[error("empty descriptor string")]
    Empty,
    #[error("missing closing parenthesis")]
    MissingCloseParen,
    #[error("unexpected trailing characters: {0}")]
    TrailingCharacters(String),
    #[error("unknown descriptor type: {0}")]
    UnknownType(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid multi threshold: {0}")]
    InvalidThreshold(String),
    #[error("multi threshold {k} exceeds key count {n}")]
    ThresholdTooHigh { k: u32, n: usize },
    #[error("multi requires at least one key")]
    MultiNoKeys,
    #[error("invalid checksum: expected {expected}, got {got}")]
    InvalidChecksum { expected: String, got: String },
    #[error("script_pubkey not supported for this descriptor type")]
    UnsupportedScriptPubkey,
    #[error("invalid hex in raw descriptor: {0}")]
    InvalidHex(String),
}

// ---------------------------------------------------------------------------
// TapTree (for tr descriptors)
// ---------------------------------------------------------------------------

/// A Taproot script tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapTree {
    /// A leaf script.
    Leaf(String),
    /// An internal branch with two children.
    Branch(Box<TapTree>, Box<TapTree>),
}

impl fmt::Display for TapTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Leaf(script) => write!(f, "{}", script),
            TapTree::Branch(left, right) => write!(f, "{{{},{}}}", left, right),
        }
    }
}

// ---------------------------------------------------------------------------
// Descriptor enum
// ---------------------------------------------------------------------------

/// An output descriptor describing how to derive a `scriptPubKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    /// `pk(KEY)` -- Pay to bare public key.
    Pk(String),
    /// `pkh(KEY)` -- Pay to public key hash (P2PKH).
    Pkh(String),
    /// `wpkh(KEY)` -- Pay to witness public key hash (P2WPKH).
    Wpkh(String),
    /// `sh(DESCRIPTOR)` -- Pay to script hash (P2SH) wrapping another descriptor.
    Sh(Box<Descriptor>),
    /// `wsh(DESCRIPTOR)` -- Pay to witness script hash (P2WSH) wrapping another descriptor.
    Wsh(Box<Descriptor>),
    /// `tr(KEY, TREE)` -- Pay to Taproot with an optional script tree.
    Tr(String, Option<Box<TapTree>>),
    /// `multi(k, KEY, KEY, ...)` -- k-of-n bare multisig.
    Multi(u32, Vec<String>),
    /// `sortedmulti(k, KEY, KEY, ...)` -- k-of-n multisig with sorted keys.
    SortedMulti(u32, Vec<String>),
    /// `addr(ADDRESS)` -- A raw address.
    Addr(String),
    /// `raw(HEX)` -- A raw hex scriptPubKey.
    Raw(String),
}

// ---------------------------------------------------------------------------
// Descriptor checksum (BIP380)
// ---------------------------------------------------------------------------

/// The character set used by the descriptor checksum, analogous to bech32.
const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}\
     IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
     ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(c: u64, val: u64) -> u64 {
    let c0 = c >> 35;
    let mut c = ((c & 0x7ffffffff) << 5) ^ val;
    if c0 & 1 != 0 { c ^= 0xf5dee51989; }
    if c0 & 2 != 0 { c ^= 0xa9fdca3312; }
    if c0 & 4 != 0 { c ^= 0x1bab10e32d; }
    if c0 & 8 != 0 { c ^= 0x3706b1677a; }
    if c0 & 16 != 0 { c ^= 0x644d626ffd; }
    c
}

/// Compute the 8-character descriptor checksum as defined in BIP380.
///
/// The checksum is appended to a descriptor string after a `#` separator,
/// e.g. `wpkh(KEY)#checksum`.
pub fn descriptor_checksum(desc: &str) -> Result<String, DescriptorError> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u64 = 0;

    for ch in desc.chars() {
        let pos = INPUT_CHARSET
            .find(ch)
            .ok_or_else(|| DescriptorError::InvalidKey(format!("invalid character '{}' in descriptor", ch)))?
            as u64;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }

    if clscount > 0 {
        c = polymod(c, cls);
    }
    // Finalize: mix in 8 zero values.
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;

    let mut result = String::with_capacity(8);
    for j in 0..8 {
        result.push(CHECKSUM_CHARSET[((c >> (5 * (7 - j))) & 31) as usize] as char);
    }

    Ok(result)
}

/// Verify that a descriptor string with `#checksum` suffix has a valid checksum.
pub fn verify_checksum(desc_with_checksum: &str) -> Result<bool, DescriptorError> {
    if let Some(hash_pos) = desc_with_checksum.rfind('#') {
        let desc = &desc_with_checksum[..hash_pos];
        let provided = &desc_with_checksum[hash_pos + 1..];
        let computed = descriptor_checksum(desc)?;
        Ok(provided == computed)
    } else {
        // No checksum present.
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl Descriptor {
    /// Parse a descriptor from a string.
    ///
    /// Accepts optional `#checksum` suffix. If present, the checksum is verified.
    pub fn parse(s: &str) -> Result<Self, DescriptorError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(DescriptorError::Empty);
        }

        // Strip and verify checksum if present.
        let desc_str = if let Some(hash_pos) = s.rfind('#') {
            let desc_part = &s[..hash_pos];
            let provided_checksum = &s[hash_pos + 1..];
            let computed = descriptor_checksum(desc_part)?;
            if provided_checksum != computed {
                return Err(DescriptorError::InvalidChecksum {
                    expected: computed,
                    got: provided_checksum.to_string(),
                });
            }
            desc_part
        } else {
            s
        };

        Self::parse_inner(desc_str)
    }

    fn parse_inner(s: &str) -> Result<Self, DescriptorError> {
        // Find the descriptor type by looking for the first '('.
        let open_paren = s
            .find('(')
            .ok_or_else(|| DescriptorError::UnknownType(s.to_string()))?;
        let desc_type = &s[..open_paren];

        // Find the matching close paren (handling nesting).
        let args_start = open_paren + 1;
        let close_paren = find_matching_paren(s, open_paren)
            .ok_or(DescriptorError::MissingCloseParen)?;

        // Check for trailing characters after the close paren.
        if close_paren + 1 != s.len() {
            return Err(DescriptorError::TrailingCharacters(
                s[close_paren + 1..].to_string(),
            ));
        }

        let args = &s[args_start..close_paren];

        match desc_type {
            "pk" => Ok(Descriptor::Pk(args.to_string())),
            "pkh" => Ok(Descriptor::Pkh(args.to_string())),
            "wpkh" => Ok(Descriptor::Wpkh(args.to_string())),
            "sh" => {
                let inner = Self::parse_inner(args)?;
                Ok(Descriptor::Sh(Box::new(inner)))
            }
            "wsh" => {
                let inner = Self::parse_inner(args)?;
                Ok(Descriptor::Wsh(Box::new(inner)))
            }
            "tr" => {
                // tr(KEY) or tr(KEY, TREE)
                if let Some(comma_pos) = find_top_level_comma(args) {
                    let key = args[..comma_pos].trim().to_string();
                    let tree_str = args[comma_pos + 1..].trim();
                    let tree = parse_taptree(tree_str)?;
                    Ok(Descriptor::Tr(key, Some(Box::new(tree))))
                } else {
                    Ok(Descriptor::Tr(args.to_string(), None))
                }
            }
            "multi" => {
                let (k, keys) = parse_multi_args(args)?;
                Ok(Descriptor::Multi(k, keys))
            }
            "sortedmulti" => {
                let (k, keys) = parse_multi_args(args)?;
                Ok(Descriptor::SortedMulti(k, keys))
            }
            "addr" => Ok(Descriptor::Addr(args.to_string())),
            "raw" => Ok(Descriptor::Raw(args.to_string())),
            other => Err(DescriptorError::UnknownType(other.to_string())),
        }
    }

    /// Derive the `scriptPubKey` for this descriptor.
    ///
    /// Currently supports: `pk`, `pkh`, `wpkh`, `raw`.
    /// Other types return `DescriptorError::UnsupportedScriptPubkey`.
    pub fn script_pubkey(&self) -> Result<ScriptBuf, DescriptorError> {
        match self {
            Descriptor::Pk(key_hex) => {
                // pk(KEY) -> <KEY> OP_CHECKSIG
                let key_bytes = hex::decode(key_hex)
                    .map_err(|_| DescriptorError::InvalidKey(key_hex.clone()))?;
                let mut script = ScriptBuf::new();
                script.push_slice(&key_bytes);
                script.push_opcode(crate::script::Opcode::OP_CHECKSIG);
                Ok(script)
            }
            Descriptor::Pkh(key_hex) => {
                // pkh(KEY) -> OP_DUP OP_HASH160 <HASH160(KEY)> OP_EQUALVERIFY OP_CHECKSIG
                let key_bytes = hex::decode(key_hex)
                    .map_err(|_| DescriptorError::InvalidKey(key_hex.clone()))?;
                let pkh = hash160(&key_bytes);
                Ok(ScriptBuf::p2pkh(&pkh))
            }
            Descriptor::Wpkh(key_hex) => {
                // wpkh(KEY) -> OP_0 <HASH160(KEY)>
                let key_bytes = hex::decode(key_hex)
                    .map_err(|_| DescriptorError::InvalidKey(key_hex.clone()))?;
                let pkh = hash160(&key_bytes);
                Ok(ScriptBuf::p2wpkh(&pkh))
            }
            Descriptor::Raw(hex_str) => {
                let bytes = hex::decode(hex_str)
                    .map_err(|_| DescriptorError::InvalidHex(hex_str.clone()))?;
                Ok(ScriptBuf::from_bytes(bytes))
            }
            _ => Err(DescriptorError::UnsupportedScriptPubkey),
        }
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Descriptor::Pk(key) => write!(f, "pk({})", key),
            Descriptor::Pkh(key) => write!(f, "pkh({})", key),
            Descriptor::Wpkh(key) => write!(f, "wpkh({})", key),
            Descriptor::Sh(inner) => write!(f, "sh({})", inner),
            Descriptor::Wsh(inner) => write!(f, "wsh({})", inner),
            Descriptor::Tr(key, None) => write!(f, "tr({})", key),
            Descriptor::Tr(key, Some(tree)) => write!(f, "tr({},{})", key, tree),
            Descriptor::Multi(k, keys) => {
                write!(f, "multi({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            Descriptor::SortedMulti(k, keys) => {
                write!(f, "sortedmulti({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            Descriptor::Addr(addr) => write!(f, "addr({})", addr),
            Descriptor::Raw(hex) => write!(f, "raw({})", hex),
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Find the index of the closing parenthesis that matches the opening paren at `open`.
fn find_matching_paren(s: &str, open: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 1;
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'{' => depth += 1,
            b')' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Find the position of the first top-level comma (not nested inside parens/braces).
fn find_top_level_comma(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'{' => depth += 1,
            b')' | b'}' => depth -= 1,
            b',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Split a string by top-level commas.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'{' => depth += 1,
            b')' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Parse the arguments of `multi(k, KEY, KEY, ...)`.
fn parse_multi_args(args: &str) -> Result<(u32, Vec<String>), DescriptorError> {
    let parts = split_top_level_commas(args);
    if parts.len() < 2 {
        return Err(DescriptorError::MultiNoKeys);
    }

    let k: u32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| DescriptorError::InvalidThreshold(parts[0].to_string()))?;

    let keys: Vec<String> = parts[1..].iter().map(|s| s.trim().to_string()).collect();

    if keys.is_empty() {
        return Err(DescriptorError::MultiNoKeys);
    }
    if k as usize > keys.len() {
        return Err(DescriptorError::ThresholdTooHigh {
            k,
            n: keys.len(),
        });
    }

    Ok((k, keys))
}

/// Parse a TapTree from a string like `{leaf,{leaf,leaf}}`.
fn parse_taptree(s: &str) -> Result<TapTree, DescriptorError> {
    let s = s.trim();
    if s.starts_with('{') && s.ends_with('}') {
        let inner = &s[1..s.len() - 1];
        let comma = find_top_level_comma(inner)
            .ok_or_else(|| DescriptorError::InvalidKey("missing comma in taptree branch".to_string()))?;
        let left = parse_taptree(&inner[..comma])?;
        let right = parse_taptree(&inner[comma + 1..])?;
        Ok(TapTree::Branch(Box::new(left), Box::new(right)))
    } else {
        Ok(TapTree::Leaf(s.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Parse/serialize roundtrip tests ----

    #[test]
    fn test_parse_pk() {
        let desc = Descriptor::parse("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)").unwrap();
        assert!(matches!(desc, Descriptor::Pk(_)));
        if let Descriptor::Pk(key) = &desc {
            assert_eq!(key, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        }
    }

    #[test]
    fn test_roundtrip_pk() {
        let input = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
    }

    #[test]
    fn test_roundtrip_pkh() {
        let input = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
    }

    #[test]
    fn test_roundtrip_wpkh() {
        let input = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
    }

    #[test]
    fn test_roundtrip_sh_wpkh() {
        let input = "sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        assert!(matches!(desc, Descriptor::Sh(_)));
        if let Descriptor::Sh(inner) = &desc {
            assert!(matches!(inner.as_ref(), Descriptor::Wpkh(_)));
        }
    }

    #[test]
    fn test_roundtrip_wsh_multi() {
        let input = "wsh(multi(2,key1,key2,key3))";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        assert!(matches!(desc, Descriptor::Wsh(_)));
    }

    #[test]
    fn test_roundtrip_tr_key_only() {
        let input = "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        if let Descriptor::Tr(key, tree) = &desc {
            assert_eq!(key, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
            assert!(tree.is_none());
        } else {
            panic!("expected Tr");
        }
    }

    #[test]
    fn test_roundtrip_tr_with_tree() {
        let input = "tr(internalkey,{leaf1,{leaf2,leaf3}})";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        if let Descriptor::Tr(key, Some(tree)) = &desc {
            assert_eq!(key, "internalkey");
            assert!(matches!(tree.as_ref(), TapTree::Branch(_, _)));
        } else {
            panic!("expected Tr with tree");
        }
    }

    #[test]
    fn test_roundtrip_multi() {
        let input = "multi(2,key1,key2,key3)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        if let Descriptor::Multi(k, keys) = &desc {
            assert_eq!(*k, 2);
            assert_eq!(keys, &["key1", "key2", "key3"]);
        } else {
            panic!("expected Multi");
        }
    }

    #[test]
    fn test_roundtrip_sortedmulti() {
        let input = "sortedmulti(1,keyA,keyB)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        if let Descriptor::SortedMulti(k, keys) = &desc {
            assert_eq!(*k, 1);
            assert_eq!(keys, &["keyA", "keyB"]);
        } else {
            panic!("expected SortedMulti");
        }
    }

    #[test]
    fn test_roundtrip_addr() {
        let input = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
        if let Descriptor::Addr(addr) = &desc {
            assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        } else {
            panic!("expected Addr");
        }
    }

    #[test]
    fn test_roundtrip_raw() {
        let input = "raw(76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac)";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);
    }

    // ---- Checksum tests ----

    #[test]
    fn test_descriptor_checksum_deterministic() {
        let desc = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let c1 = descriptor_checksum(desc).unwrap();
        let c2 = descriptor_checksum(desc).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 8);
    }

    #[test]
    fn test_descriptor_checksum_length() {
        let desc = "pkh(key)";
        let checksum = descriptor_checksum(desc).unwrap();
        assert_eq!(checksum.len(), 8);
        // All characters should be from the checksum charset.
        for ch in checksum.chars() {
            assert!(
                CHECKSUM_CHARSET.contains(&(ch as u8)),
                "unexpected character '{}' in checksum",
                ch
            );
        }
    }

    #[test]
    fn test_descriptor_checksum_different_descriptors() {
        let c1 = descriptor_checksum("pkh(key1)").unwrap();
        let c2 = descriptor_checksum("pkh(key2)").unwrap();
        assert_ne!(c1, c2, "different descriptors should produce different checksums");
    }

    #[test]
    fn test_parse_with_valid_checksum() {
        let desc_str = "pkh(key)";
        let checksum = descriptor_checksum(desc_str).unwrap();
        let with_checksum = format!("{}#{}", desc_str, checksum);
        let desc = Descriptor::parse(&with_checksum).unwrap();
        assert!(matches!(desc, Descriptor::Pkh(_)));
    }

    #[test]
    fn test_parse_with_invalid_checksum() {
        let result = Descriptor::parse("pkh(key)#aaaaaaaa");
        assert!(result.is_err());
        if let Err(DescriptorError::InvalidChecksum { .. }) = result {
            // expected
        } else {
            panic!("expected InvalidChecksum error, got: {:?}", result);
        }
    }

    #[test]
    fn test_verify_checksum_valid() {
        let desc = "wpkh(key)";
        let checksum = descriptor_checksum(desc).unwrap();
        let full = format!("{}#{}", desc, checksum);
        assert!(verify_checksum(&full).unwrap());
    }

    #[test]
    fn test_verify_checksum_invalid() {
        let full = "wpkh(key)#zzzzzzzz";
        assert!(!verify_checksum(full).unwrap());
    }

    #[test]
    fn test_verify_checksum_no_checksum() {
        assert!(verify_checksum("wpkh(key)").unwrap());
    }

    // ---- script_pubkey tests ----

    #[test]
    fn test_pk_script_pubkey() {
        // Compressed public key (33 bytes)
        let key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let desc = Descriptor::Pk(key_hex.to_string());
        let script = desc.script_pubkey().unwrap();
        let bytes = script.as_bytes();
        // Should be: <33-byte push> <pubkey> OP_CHECKSIG(0xac)
        assert_eq!(bytes[0], 33); // push length
        assert_eq!(bytes[bytes.len() - 1], 0xac); // OP_CHECKSIG
        assert_eq!(bytes.len(), 35); // 1 + 33 + 1
    }

    #[test]
    fn test_pkh_script_pubkey() {
        let key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let desc = Descriptor::Pkh(key_hex.to_string());
        let script = desc.script_pubkey().unwrap();
        assert!(script.is_p2pkh());
    }

    #[test]
    fn test_wpkh_script_pubkey() {
        let key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let desc = Descriptor::Wpkh(key_hex.to_string());
        let script = desc.script_pubkey().unwrap();
        assert!(script.is_p2wpkh());
    }

    #[test]
    fn test_raw_script_pubkey() {
        // P2PKH script as raw hex
        let raw_hex = "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac";
        let desc = Descriptor::Raw(raw_hex.to_string());
        let script = desc.script_pubkey().unwrap();
        assert!(script.is_p2pkh());
        assert_eq!(hex::encode(script.as_bytes()), raw_hex);
    }

    #[test]
    fn test_unsupported_script_pubkey() {
        let desc = Descriptor::Addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string());
        let result = desc.script_pubkey();
        assert!(matches!(result, Err(DescriptorError::UnsupportedScriptPubkey)));
    }

    #[test]
    fn test_invalid_key_hex() {
        let desc = Descriptor::Pk("not_valid_hex".to_string());
        let result = desc.script_pubkey();
        assert!(matches!(result, Err(DescriptorError::InvalidKey(_))));
    }

    // ---- Error case tests ----

    #[test]
    fn test_parse_empty() {
        assert!(matches!(Descriptor::parse(""), Err(DescriptorError::Empty)));
    }

    #[test]
    fn test_parse_unknown_type() {
        assert!(matches!(
            Descriptor::parse("unknown(key)"),
            Err(DescriptorError::UnknownType(_))
        ));
    }

    #[test]
    fn test_parse_missing_close_paren() {
        assert!(matches!(
            Descriptor::parse("pkh(key"),
            Err(DescriptorError::MissingCloseParen)
        ));
    }

    #[test]
    fn test_parse_trailing_characters() {
        assert!(matches!(
            Descriptor::parse("pkh(key)extra"),
            Err(DescriptorError::TrailingCharacters(_))
        ));
    }

    #[test]
    fn test_multi_threshold_too_high() {
        assert!(matches!(
            Descriptor::parse("multi(3,key1,key2)"),
            Err(DescriptorError::ThresholdTooHigh { k: 3, n: 2 })
        ));
    }

    #[test]
    fn test_multi_no_keys() {
        assert!(matches!(
            Descriptor::parse("multi(1)"),
            Err(DescriptorError::MultiNoKeys)
        ));
    }

    // ---- Nested descriptor tests ----

    #[test]
    fn test_sh_wsh_multi() {
        let input = "sh(wsh(multi(2,keyA,keyB,keyC)))";
        let desc = Descriptor::parse(input).unwrap();
        assert_eq!(desc.to_string(), input);

        if let Descriptor::Sh(inner) = &desc {
            if let Descriptor::Wsh(inner2) = inner.as_ref() {
                if let Descriptor::Multi(k, keys) = inner2.as_ref() {
                    assert_eq!(*k, 2);
                    assert_eq!(keys.len(), 3);
                } else {
                    panic!("expected Multi inside Wsh");
                }
            } else {
                panic!("expected Wsh inside Sh");
            }
        } else {
            panic!("expected Sh");
        }
    }

    // ---- TapTree tests ----

    #[test]
    fn test_taptree_parse_leaf() {
        let tree = parse_taptree("leaf_script").unwrap();
        assert_eq!(tree, TapTree::Leaf("leaf_script".to_string()));
    }

    #[test]
    fn test_taptree_parse_branch() {
        let tree = parse_taptree("{left,right}").unwrap();
        assert_eq!(
            tree,
            TapTree::Branch(
                Box::new(TapTree::Leaf("left".to_string())),
                Box::new(TapTree::Leaf("right".to_string())),
            )
        );
    }

    #[test]
    fn test_taptree_parse_nested() {
        let tree = parse_taptree("{a,{b,c}}").unwrap();
        assert_eq!(
            tree,
            TapTree::Branch(
                Box::new(TapTree::Leaf("a".to_string())),
                Box::new(TapTree::Branch(
                    Box::new(TapTree::Leaf("b".to_string())),
                    Box::new(TapTree::Leaf("c".to_string())),
                )),
            )
        );
    }

    #[test]
    fn test_taptree_display_roundtrip() {
        let tree = TapTree::Branch(
            Box::new(TapTree::Leaf("a".to_string())),
            Box::new(TapTree::Branch(
                Box::new(TapTree::Leaf("b".to_string())),
                Box::new(TapTree::Leaf("c".to_string())),
            )),
        );
        let s = tree.to_string();
        assert_eq!(s, "{a,{b,c}}");
        let parsed = parse_taptree(&s).unwrap();
        assert_eq!(parsed, tree);
    }
}
