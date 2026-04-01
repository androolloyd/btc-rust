//! BIP32 Hierarchical Deterministic (HD) key derivation.
//!
//! Implements the full BIP32 specification including:
//! - Extended private and public keys with serialization
//! - Child key derivation (hardened and normal)
//! - Derivation path parsing ("m/44'/0'/0'/0/0")
//! - Base58Check encoding/decoding
//! - BIP43/44/49/84/86 standard path constants

use crate::hash::{hash160, sha256d};
use crate::network::Network;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;
use thiserror::Error;

type HmacSha512 = Hmac<Sha512>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Bip32Error {
    #[error("invalid seed length: {0} (expected 16..64 bytes)")]
    InvalidSeedLength(usize),
    #[error("invalid key: derived key is zero or >= curve order")]
    InvalidKey,
    #[error("hardened derivation from public key is not possible")]
    HardenedFromPublic,
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("invalid base58 encoding")]
    InvalidBase58,
    #[error("invalid base58 checksum")]
    InvalidChecksum,
    #[error("invalid serialized key length: expected 78, got {0}")]
    InvalidKeyLength(usize),
    #[error("unknown version bytes: {0:02x}{1:02x}{2:02x}{3:02x}")]
    UnknownVersion(u8, u8, u8, u8),
    #[error("invalid private key marker: expected 0x00, got 0x{0:02x}")]
    InvalidPrivateKeyMarker(u8),
    #[error("secp256k1 error: {0}")]
    Secp256k1(String),
    #[error("invalid child number")]
    InvalidChildNumber,
}

impl From<secp256k1::Error> for Bip32Error {
    fn from(e: secp256k1::Error) -> Self {
        Bip32Error::Secp256k1(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Hardened key offset (2^31)
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

// Version bytes
const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const TPRV_VERSION: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];

// ---------------------------------------------------------------------------
// Base58 (reused from address.rs logic, self-contained here)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &d in digits.iter().rev() {
        result.push(BASE58_ALPHABET[d as usize] as char);
    }

    result
}

fn base58_decode(s: &str) -> Result<Vec<u8>, Bip32Error> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let leading_ones = s.chars().take_while(|&c| c == '1').count();

    let mut bytes: Vec<u8> = Vec::new();
    for ch in s.chars() {
        let val = BASE58_ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or(Bip32Error::InvalidBase58)? as u32;

        let mut carry = val;
        for byte in bytes.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut result = Vec::with_capacity(leading_ones + bytes.len());
    for _ in 0..leading_ones {
        result.push(0);
    }
    result.extend(bytes.iter().rev());

    Ok(result)
}

fn base58check_encode(data: &[u8]) -> String {
    let mut buf = Vec::with_capacity(data.len() + 4);
    buf.extend_from_slice(data);
    let checksum = sha256d(data);
    buf.extend_from_slice(&checksum[..4]);
    base58_encode(&buf)
}

fn base58check_decode(s: &str) -> Result<Vec<u8>, Bip32Error> {
    let data = base58_decode(s)?;
    if data.len() < 5 {
        return Err(Bip32Error::InvalidBase58);
    }

    let (payload, checksum) = data.split_at(data.len() - 4);
    let computed = sha256d(payload);

    if checksum != &computed[..4] {
        return Err(Bip32Error::InvalidChecksum);
    }

    Ok(payload.to_vec())
}

// ---------------------------------------------------------------------------
// Derivation path parsing
// ---------------------------------------------------------------------------

/// A parsed derivation path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildNumber(pub u32);

impl ChildNumber {
    /// Create a normal (non-hardened) child number.
    pub fn normal(index: u32) -> Result<Self, Bip32Error> {
        if index >= HARDENED_OFFSET {
            return Err(Bip32Error::InvalidChildNumber);
        }
        Ok(ChildNumber(index))
    }

    /// Create a hardened child number.
    pub fn hardened(index: u32) -> Result<Self, Bip32Error> {
        if index >= HARDENED_OFFSET {
            return Err(Bip32Error::InvalidChildNumber);
        }
        Ok(ChildNumber(index + HARDENED_OFFSET))
    }

    /// Returns true if this is a hardened derivation.
    pub fn is_hardened(self) -> bool {
        self.0 >= HARDENED_OFFSET
    }

    /// Returns the index without the hardened flag.
    pub fn index(self) -> u32 {
        if self.is_hardened() {
            self.0 - HARDENED_OFFSET
        } else {
            self.0
        }
    }
}

impl std::fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_hardened() {
            write!(f, "{}'", self.index())
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// A BIP32 derivation path (e.g., "m/44'/0'/0'/0/0").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    pub components: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Parse a derivation path string like "m/44'/0'/0'/0/0".
    ///
    /// Supports both `'` and `h` as hardened suffixes.
    pub fn parse(path: &str) -> Result<Self, Bip32Error> {
        let path = path.trim();
        if path.is_empty() || path == "m" || path == "m/" {
            return Ok(DerivationPath {
                components: Vec::new(),
            });
        }

        let stripped = if path.starts_with("m/") {
            &path[2..]
        } else {
            return Err(Bip32Error::InvalidPath(format!(
                "path must start with 'm/', got: {}",
                path
            )));
        };

        let mut components = Vec::new();
        for part in stripped.split('/') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
                (&part[..part.len() - 1], true)
            } else {
                (part, false)
            };

            let index: u32 = num_str.parse().map_err(|_| {
                Bip32Error::InvalidPath(format!("invalid index: {}", part))
            })?;

            let child = if hardened {
                ChildNumber::hardened(index)?
            } else {
                ChildNumber::normal(index)?
            };

            components.push(child);
        }

        Ok(DerivationPath { components })
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m")?;
        for c in &self.components {
            write!(f, "/{}", c)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ExtendedPrivKey
// ---------------------------------------------------------------------------

/// A BIP32 extended private key.
#[derive(Clone)]
pub struct ExtendedPrivKey {
    /// The network this key belongs to.
    pub network: Network,
    /// Depth in the derivation tree (0 for master).
    pub depth: u8,
    /// Fingerprint of the parent key (0x00000000 for master).
    pub parent_fingerprint: [u8; 4],
    /// Child number (0 for master).
    pub child_number: ChildNumber,
    /// Chain code (32 bytes).
    pub chain_code: [u8; 32],
    /// The secret key (32 bytes).
    pub secret_key: SecretKey,
}

impl std::fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPrivKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &hex::encode(self.parent_fingerprint))
            .field("child_number", &self.child_number)
            .field("chain_code", &hex::encode(self.chain_code))
            .field("secret_key", &"[redacted]")
            .finish()
    }
}

impl ExtendedPrivKey {
    /// Generate a master key from a seed (BIP32 master key generation).
    ///
    /// The seed must be between 16 and 64 bytes (128-512 bits).
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self, Bip32Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Bip32Error::InvalidSeedLength(seed.len()));
        }

        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC accepts any key size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let (il, ir) = result.split_at(32);

        let secret_key =
            SecretKey::from_slice(il).map_err(|_| Bip32Error::InvalidKey)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(ExtendedPrivKey {
            network,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber(0),
            chain_code,
            secret_key,
        })
    }

    /// Get the corresponding public key (compressed, 33 bytes).
    pub fn public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.secret_key)
    }

    /// Get the key fingerprint (first 4 bytes of HASH160 of the public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let pubkey = self.public_key();
        let h = hash160(&pubkey.serialize());
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&h[..4]);
        fp
    }

    /// Derive a child private key at the given child number.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Bip32Error> {
        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC accepts any key size");

        if child.is_hardened() {
            // Hardened: HMAC-SHA512(Key = chain_code, Data = 0x00 || ser256(kpar) || ser32(i))
            mac.update(&[0x00]);
            mac.update(&self.secret_key[..]);
        } else {
            // Normal: HMAC-SHA512(Key = chain_code, Data = serP(point(kpar)) || ser32(i))
            let pubkey = self.public_key();
            mac.update(&pubkey.serialize());
        }
        mac.update(&child.0.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let (il, ir) = result.split_at(32);

        // child_key = parse256(IL) + kpar (mod n)
        let tweak = Scalar::from_be_bytes(il.try_into().expect("IL is 32 bytes"))
            .map_err(|_| Bip32Error::InvalidKey)?;
        let child_key = self.secret_key
            .add_tweak(&tweak)
            .map_err(|_| Bip32Error::InvalidKey)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(ExtendedPrivKey {
            network: self.network,
            depth: self.depth.checked_add(1).ok_or_else(|| {
                Bip32Error::InvalidPath("depth overflow".to_string())
            })?,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            chain_code,
            secret_key: child_key,
        })
    }

    /// Derive a key along a full derivation path (e.g., "m/44'/0'/0'/0/0").
    pub fn derive_path(&self, path: &str) -> Result<Self, Bip32Error> {
        let parsed = DerivationPath::parse(path)?;
        let mut key = self.clone();
        for child in &parsed.components {
            key = key.derive_child(*child)?;
        }
        Ok(key)
    }

    /// Derive using a pre-parsed DerivationPath.
    pub fn derive(&self, path: &DerivationPath) -> Result<Self, Bip32Error> {
        let mut key = self.clone();
        for child in &path.components {
            key = key.derive_child(*child)?;
        }
        Ok(key)
    }

    /// Get the corresponding ExtendedPubKey.
    pub fn to_extended_pub_key(&self) -> ExtendedPubKey {
        ExtendedPubKey {
            network: self.network,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            public_key: self.public_key(),
        }
    }

    /// Serialize to 78 bytes (BIP32 format).
    pub fn serialize(&self) -> [u8; 78] {
        let mut buf = [0u8; 78];

        let version = self.network.xprv_version();
        buf[0..4].copy_from_slice(&version);
        buf[4] = self.depth;
        buf[5..9].copy_from_slice(&self.parent_fingerprint);
        buf[9..13].copy_from_slice(&self.child_number.0.to_be_bytes());
        buf[13..45].copy_from_slice(&self.chain_code);
        buf[45] = 0x00; // private key marker
        buf[46..78].copy_from_slice(&self.secret_key[..]);

        buf
    }

    /// Deserialize from 78 bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, Bip32Error> {
        if data.len() != 78 {
            return Err(Bip32Error::InvalidKeyLength(data.len()));
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        let network = if version == XPRV_VERSION {
            Network::Mainnet
        } else if version == TPRV_VERSION {
            Network::Testnet
        } else {
            return Err(Bip32Error::UnknownVersion(
                version[0], version[1], version[2], version[3],
            ));
        };

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        if data[45] != 0x00 {
            return Err(Bip32Error::InvalidPrivateKeyMarker(data[45]));
        }

        let secret_key =
            SecretKey::from_slice(&data[46..78]).map_err(|_| Bip32Error::InvalidKey)?;

        Ok(ExtendedPrivKey {
            network,
            depth,
            parent_fingerprint,
            child_number: ChildNumber(child_number),
            chain_code,
            secret_key,
        })
    }

    /// Encode to base58check (xprv... / tprv...).
    pub fn to_base58(&self) -> String {
        let serialized = self.serialize();
        base58check_encode(&serialized)
    }

    /// Decode from base58check.
    pub fn from_base58(s: &str) -> Result<Self, Bip32Error> {
        let data = base58check_decode(s)?;
        Self::deserialize(&data)
    }
}

// ---------------------------------------------------------------------------
// ExtendedPubKey
// ---------------------------------------------------------------------------

/// A BIP32 extended public key.
#[derive(Debug, Clone)]
pub struct ExtendedPubKey {
    /// The network this key belongs to.
    pub network: Network,
    /// Depth in the derivation tree.
    pub depth: u8,
    /// Fingerprint of the parent key.
    pub parent_fingerprint: [u8; 4],
    /// Child number.
    pub child_number: ChildNumber,
    /// Chain code (32 bytes).
    pub chain_code: [u8; 32],
    /// The compressed public key (33 bytes).
    pub public_key: PublicKey,
}

impl ExtendedPubKey {
    /// Get the key fingerprint (first 4 bytes of HASH160 of the compressed public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let h = hash160(&self.public_key.serialize());
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&h[..4]);
        fp
    }

    /// Derive a child public key at the given (non-hardened) child number.
    ///
    /// Returns an error if the child number is hardened, since public key
    /// derivation cannot produce hardened children.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Bip32Error> {
        if child.is_hardened() {
            return Err(Bip32Error::HardenedFromPublic);
        }

        let secp = Secp256k1::new();

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC accepts any key size");
        mac.update(&self.public_key.serialize());
        mac.update(&child.0.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let (il, ir) = result.split_at(32);

        // Parse IL as a secret key, then compute IL*G + parent_pubkey
        let il_key =
            SecretKey::from_slice(il).map_err(|_| Bip32Error::InvalidKey)?;

        let mut child_pubkey = self.public_key;
        child_pubkey = child_pubkey
            .add_exp_tweak(&secp, &il_key.into())
            .map_err(|_| Bip32Error::InvalidKey)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(ExtendedPubKey {
            network: self.network,
            depth: self.depth.checked_add(1).ok_or_else(|| {
                Bip32Error::InvalidPath("depth overflow".to_string())
            })?,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            chain_code,
            public_key: child_pubkey,
        })
    }

    /// Derive a key along a full derivation path.
    ///
    /// All components must be non-hardened.
    pub fn derive_path(&self, path: &str) -> Result<Self, Bip32Error> {
        let parsed = DerivationPath::parse(path)?;
        let mut key = self.clone();
        for child in &parsed.components {
            key = key.derive_child(*child)?;
        }
        Ok(key)
    }

    /// Derive using a pre-parsed DerivationPath.
    pub fn derive(&self, path: &DerivationPath) -> Result<Self, Bip32Error> {
        let mut key = self.clone();
        for child in &path.components {
            key = key.derive_child(*child)?;
        }
        Ok(key)
    }

    /// Serialize to 78 bytes (BIP32 format).
    pub fn serialize(&self) -> [u8; 78] {
        let mut buf = [0u8; 78];

        let version = self.network.xpub_version();
        buf[0..4].copy_from_slice(&version);
        buf[4] = self.depth;
        buf[5..9].copy_from_slice(&self.parent_fingerprint);
        buf[9..13].copy_from_slice(&self.child_number.0.to_be_bytes());
        buf[13..45].copy_from_slice(&self.chain_code);
        buf[45..78].copy_from_slice(&self.public_key.serialize());

        buf
    }

    /// Deserialize from 78 bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, Bip32Error> {
        if data.len() != 78 {
            return Err(Bip32Error::InvalidKeyLength(data.len()));
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        let network = if version == XPUB_VERSION {
            Network::Mainnet
        } else if version == TPUB_VERSION {
            Network::Testnet
        } else {
            return Err(Bip32Error::UnknownVersion(
                version[0], version[1], version[2], version[3],
            ));
        };

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let public_key =
            PublicKey::from_slice(&data[45..78]).map_err(|_| Bip32Error::InvalidKey)?;

        Ok(ExtendedPubKey {
            network,
            depth,
            parent_fingerprint,
            child_number: ChildNumber(child_number),
            chain_code,
            public_key,
        })
    }

    /// Encode to base58check (xpub... / tpub...).
    pub fn to_base58(&self) -> String {
        let serialized = self.serialize();
        base58check_encode(&serialized)
    }

    /// Decode from base58check.
    pub fn from_base58(s: &str) -> Result<Self, Bip32Error> {
        let data = base58check_decode(s)?;
        Self::deserialize(&data)
    }
}

// ---------------------------------------------------------------------------
// BIP43/44/49/84/86 standard purpose paths
// ---------------------------------------------------------------------------

/// BIP44 purpose path for legacy P2PKH addresses.
pub fn purpose_44() -> &'static str {
    "m/44'"
}

/// BIP49 purpose path for P2SH-wrapped P2WPKH addresses.
pub fn purpose_49() -> &'static str {
    "m/49'"
}

/// BIP84 purpose path for native P2WPKH (bech32) addresses.
pub fn purpose_84() -> &'static str {
    "m/84'"
}

/// BIP86 purpose path for P2TR (Taproot, bech32m) addresses.
pub fn purpose_86() -> &'static str {
    "m/86'"
}

/// Build a full BIP44 derivation path: m/44'/coin'/account'/change/index
pub fn bip44_path(coin: u32, account: u32, change: u32, index: u32) -> String {
    format!("m/44'/{}'/{}'/{}/{}", coin, account, change, index)
}

/// Build a full BIP84 derivation path: m/84'/coin'/account'/change/index
pub fn bip84_path(coin: u32, account: u32, change: u32, index: u32) -> String {
    format!("m/84'/{}'/{}'/{}/{}", coin, account, change, index)
}

/// Build a full BIP86 derivation path: m/86'/coin'/account'/change/index
pub fn bip86_path(coin: u32, account: u32, change: u32, index: u32) -> String {
    format!("m/86'/{}'/{}'/{}/{}", coin, account, change, index)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 Test Vector 1 from the specification
    // Seed: 000102030405060708090a0b0c0d0e0f

    fn test_seed_1() -> Vec<u8> {
        hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()
    }

    fn test_seed_2() -> Vec<u8> {
        hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap()
    }

    // ---- Test Vector 1 ----

    #[test]
    fn test_vector_1_master() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(
            master.to_base58(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );

        let master_pub = master.to_extended_pub_key();
        assert_eq!(
            master_pub.to_base58(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_child(ChildNumber::hardened(0).unwrap()).unwrap();
        assert_eq!(
            child.to_base58(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
        let child_pub = child.to_extended_pub_key();
        assert_eq!(
            child_pub.to_base58(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h_1() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        );
        let child_pub = child.to_extended_pub_key();
        assert_eq!(
            child_pub.to_base58(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h_1_2h() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1/2'").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        );
        let child_pub = child.to_extended_pub_key();
        assert_eq!(
            child_pub.to_base58(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h_1_2h_2() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1/2'/2").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
        );
        let child_pub = child.to_extended_pub_key();
        assert_eq!(
            child_pub.to_base58(),
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h_1_2h_2_1000000000() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        );
        let child_pub = child.to_extended_pub_key();
        assert_eq!(
            child_pub.to_base58(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        );
    }

    // ---- Test Vector 2 ----

    #[test]
    fn test_vector_2_master() {
        let seed = test_seed_2();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(
            master.to_base58(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        );

        let master_pub = master.to_extended_pub_key();
        assert_eq!(
            master_pub.to_base58(),
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        );
    }

    #[test]
    fn test_vector_2_chain_m_0() {
        let seed = test_seed_2();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_child(ChildNumber::normal(0).unwrap()).unwrap();
        assert_eq!(
            child.to_base58(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        );
        let child_pub = child.to_extended_pub_key();
        assert_eq!(
            child_pub.to_base58(),
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        );
    }

    #[test]
    fn test_vector_2_chain_m_0_2147483647h() {
        let seed = test_seed_2();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0/2147483647'").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
        );
    }

    #[test]
    fn test_vector_2_chain_m_0_2147483647h_1() {
        let seed = test_seed_2();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0/2147483647'/1").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
        );
    }

    #[test]
    fn test_vector_2_chain_m_0_2147483647h_1_2147483646h() {
        let seed = test_seed_2();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0/2147483647'/1/2147483646'").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
        );
    }

    #[test]
    fn test_vector_2_chain_m_0_2147483647h_1_2147483646h_2() {
        let seed = test_seed_2();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0/2147483647'/1/2147483646'/2").unwrap();
        assert_eq!(
            child.to_base58(),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
        );
    }

    // ---- Public key derivation consistency ----

    #[test]
    fn test_public_derivation_matches_private() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();

        // Derive m/0' first (hardened, must use private)
        let m_0h = master.derive_child(ChildNumber::hardened(0).unwrap()).unwrap();

        // Then derive m/0'/1 via private and via public
        let m_0h_1_priv = m_0h.derive_child(ChildNumber::normal(1).unwrap()).unwrap();
        let m_0h_pub = m_0h.to_extended_pub_key();
        let m_0h_1_pub = m_0h_pub.derive_child(ChildNumber::normal(1).unwrap()).unwrap();

        // The public keys should match
        assert_eq!(
            m_0h_1_priv.public_key().serialize(),
            m_0h_1_pub.public_key.serialize()
        );

        // The chain codes should also match
        assert_eq!(m_0h_1_priv.chain_code, m_0h_1_pub.chain_code);
    }

    // ---- Base58 roundtrip ----

    #[test]
    fn test_xprv_base58_roundtrip() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let encoded = master.to_base58();
        let decoded = ExtendedPrivKey::from_base58(&encoded).unwrap();
        assert_eq!(decoded.to_base58(), encoded);
        assert_eq!(decoded.depth, master.depth);
        assert_eq!(decoded.chain_code, master.chain_code);
        assert_eq!(decoded.secret_key, master.secret_key);
    }

    #[test]
    fn test_xpub_base58_roundtrip() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let master_pub = master.to_extended_pub_key();
        let encoded = master_pub.to_base58();
        let decoded = ExtendedPubKey::from_base58(&encoded).unwrap();
        assert_eq!(decoded.to_base58(), encoded);
        assert_eq!(decoded.depth, master_pub.depth);
        assert_eq!(decoded.chain_code, master_pub.chain_code);
    }

    // ---- Testnet keys ----

    #[test]
    fn test_testnet_key() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Testnet).unwrap();
        let encoded = master.to_base58();
        assert!(encoded.starts_with("tprv"));

        let master_pub = master.to_extended_pub_key();
        let pub_encoded = master_pub.to_base58();
        assert!(pub_encoded.starts_with("tpub"));

        // Roundtrip
        let decoded = ExtendedPrivKey::from_base58(&encoded).unwrap();
        assert_eq!(decoded.network, Network::Testnet);
        let decoded_pub = ExtendedPubKey::from_base58(&pub_encoded).unwrap();
        assert_eq!(decoded_pub.network, Network::Testnet);
    }

    // ---- Error cases ----

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = vec![0u8; 10]; // too short
        let result = ExtendedPrivKey::from_seed(&short_seed, Network::Mainnet);
        assert!(matches!(result, Err(Bip32Error::InvalidSeedLength(10))));

        let long_seed = vec![0u8; 100]; // too long
        let result = ExtendedPrivKey::from_seed(&long_seed, Network::Mainnet);
        assert!(matches!(result, Err(Bip32Error::InvalidSeedLength(100))));
    }

    #[test]
    fn test_hardened_from_public_fails() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let master_pub = master.to_extended_pub_key();
        let result = master_pub.derive_child(ChildNumber::hardened(0).unwrap());
        assert!(matches!(result, Err(Bip32Error::HardenedFromPublic)));
    }

    #[test]
    fn test_invalid_base58() {
        let result = ExtendedPrivKey::from_base58("not_valid_base58!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base58_checksum() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let mut encoded = master.to_base58();
        // Corrupt the last character
        encoded.pop();
        encoded.push('A');
        let result = ExtendedPrivKey::from_base58(&encoded);
        assert!(result.is_err());
    }

    // ---- Derivation path parsing ----

    #[test]
    fn test_derivation_path_parse() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.components.len(), 5);
        assert!(path.components[0].is_hardened());
        assert_eq!(path.components[0].index(), 44);
        assert!(path.components[1].is_hardened());
        assert_eq!(path.components[1].index(), 0);
        assert!(path.components[2].is_hardened());
        assert_eq!(path.components[2].index(), 0);
        assert!(!path.components[3].is_hardened());
        assert_eq!(path.components[3].index(), 0);
        assert!(!path.components[4].is_hardened());
        assert_eq!(path.components[4].index(), 0);
    }

    #[test]
    fn test_derivation_path_parse_h_suffix() {
        let path = DerivationPath::parse("m/44h/0h/0h").unwrap();
        assert_eq!(path.components.len(), 3);
        for c in &path.components {
            assert!(c.is_hardened());
        }
        assert_eq!(path.components[0].index(), 44);
    }

    #[test]
    fn test_derivation_path_master_only() {
        let path = DerivationPath::parse("m").unwrap();
        assert!(path.components.is_empty());

        let path = DerivationPath::parse("m/").unwrap();
        assert!(path.components.is_empty());
    }

    #[test]
    fn test_derivation_path_invalid() {
        assert!(DerivationPath::parse("44'/0'/0'").is_err()); // missing m/
        assert!(DerivationPath::parse("m/abc").is_err()); // non-numeric
    }

    #[test]
    fn test_derivation_path_display() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    // ---- Purpose path constants ----

    #[test]
    fn test_purpose_paths() {
        assert_eq!(purpose_44(), "m/44'");
        assert_eq!(purpose_49(), "m/49'");
        assert_eq!(purpose_84(), "m/84'");
        assert_eq!(purpose_86(), "m/86'");
    }

    #[test]
    fn test_bip44_path() {
        let path = bip44_path(0, 0, 0, 0);
        assert_eq!(path, "m/44'/0'/0'/0/0");

        let path = bip44_path(0, 0, 1, 5);
        assert_eq!(path, "m/44'/0'/0'/1/5");
    }

    #[test]
    fn test_bip84_path() {
        let path = bip84_path(0, 0, 0, 0);
        assert_eq!(path, "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_bip86_path() {
        let path = bip86_path(0, 0, 0, 0);
        assert_eq!(path, "m/86'/0'/0'/0/0");
    }

    // ---- Fingerprint ----

    #[test]
    fn test_fingerprint() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let fp = master.fingerprint();
        // Master fingerprint for test vector 1
        assert_eq!(fp.len(), 4);
        // It should be non-zero
        assert_ne!(fp, [0; 4]);

        // Child should have parent's fingerprint
        let child = master.derive_child(ChildNumber::hardened(0).unwrap()).unwrap();
        assert_eq!(child.parent_fingerprint, fp);
    }

    // ---- ChildNumber ----

    #[test]
    fn test_child_number() {
        let normal = ChildNumber::normal(42).unwrap();
        assert!(!normal.is_hardened());
        assert_eq!(normal.index(), 42);
        assert_eq!(normal.0, 42);

        let hardened = ChildNumber::hardened(42).unwrap();
        assert!(hardened.is_hardened());
        assert_eq!(hardened.index(), 42);
        assert_eq!(hardened.0, 42 + HARDENED_OFFSET);
    }

    #[test]
    fn test_child_number_display() {
        let normal = ChildNumber::normal(42).unwrap();
        assert_eq!(format!("{}", normal), "42");

        let hardened = ChildNumber::hardened(42).unwrap();
        assert_eq!(format!("{}", hardened), "42'");
    }

    #[test]
    fn test_child_number_overflow() {
        assert!(ChildNumber::normal(HARDENED_OFFSET).is_err());
        assert!(ChildNumber::hardened(HARDENED_OFFSET).is_err());
    }

    // ---- Serialization ----

    #[test]
    fn test_serialize_deserialize_priv() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let serialized = master.serialize();
        assert_eq!(serialized.len(), 78);

        let deserialized = ExtendedPrivKey::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.depth, master.depth);
        assert_eq!(deserialized.chain_code, master.chain_code);
        assert_eq!(deserialized.secret_key, master.secret_key);
        assert_eq!(deserialized.network, Network::Mainnet);
    }

    #[test]
    fn test_serialize_deserialize_pub() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let master_pub = master.to_extended_pub_key();
        let serialized = master_pub.serialize();
        assert_eq!(serialized.len(), 78);

        let deserialized = ExtendedPubKey::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.depth, master_pub.depth);
        assert_eq!(deserialized.chain_code, master_pub.chain_code);
        assert_eq!(
            deserialized.public_key.serialize(),
            master_pub.public_key.serialize()
        );
    }

    #[test]
    fn test_deserialize_wrong_length() {
        let result = ExtendedPrivKey::deserialize(&[0u8; 50]);
        assert!(matches!(result, Err(Bip32Error::InvalidKeyLength(50))));

        let result = ExtendedPubKey::deserialize(&[0u8; 50]);
        assert!(matches!(result, Err(Bip32Error::InvalidKeyLength(50))));
    }

    // ---- Deep derivation ----

    #[test]
    fn test_deep_derivation() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let deep = master.derive_path("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(deep.depth, 5);
        // Verify the key is valid by encoding/decoding
        let encoded = deep.to_base58();
        let decoded = ExtendedPrivKey::from_base58(&encoded).unwrap();
        assert_eq!(decoded.depth, 5);
    }

    // ---- Public key derivation chain ----

    #[test]
    fn test_public_derivation_chain() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();

        // Derive hardened path first via private key
        let account = master.derive_path("m/44'/0'/0'").unwrap();

        // Now derive non-hardened children via both private and public paths
        let account_pub = account.to_extended_pub_key();

        for i in 0..5u32 {
            let child_priv = account
                .derive_child(ChildNumber::normal(0).unwrap())
                .unwrap()
                .derive_child(ChildNumber::normal(i).unwrap())
                .unwrap();

            let child_pub = account_pub
                .derive_child(ChildNumber::normal(0).unwrap())
                .unwrap()
                .derive_child(ChildNumber::normal(i).unwrap())
                .unwrap();

            assert_eq!(
                child_priv.public_key().serialize(),
                child_pub.public_key.serialize(),
                "public keys should match for index {}",
                i
            );
        }
    }

    // ---- Error display ----

    #[test]
    fn test_error_display() {
        let errors: Vec<Bip32Error> = vec![
            Bip32Error::InvalidSeedLength(10),
            Bip32Error::InvalidKey,
            Bip32Error::HardenedFromPublic,
            Bip32Error::InvalidPath("bad".to_string()),
            Bip32Error::InvalidBase58,
            Bip32Error::InvalidChecksum,
            Bip32Error::InvalidKeyLength(50),
            Bip32Error::UnknownVersion(0, 0, 0, 0),
            Bip32Error::InvalidPrivateKeyMarker(0xFF),
            Bip32Error::Secp256k1("err".to_string()),
            Bip32Error::InvalidChildNumber,
        ];
        for e in errors {
            let s = format!("{}", e);
            assert!(!s.is_empty());
        }
    }

    // ---- Debug for ExtendedPrivKey ----

    #[test]
    fn test_extended_priv_key_debug_redacts_secret() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let debug = format!("{:?}", master);
        assert!(debug.contains("[redacted]"));
        // Should not leak the actual secret key bytes
        let secret_hex = hex::encode(&master.secret_key[..]);
        assert!(!debug.contains(&secret_hex));
    }

    // ---- DerivationPath derive method ----

    #[test]
    fn test_derive_with_parsed_path() {
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let path = DerivationPath::parse("m/0'/1").unwrap();

        let child_a = master.derive(&path).unwrap();
        let child_b = master.derive_path("m/0'/1").unwrap();

        assert_eq!(child_a.to_base58(), child_b.to_base58());
    }

    // ---- Minimum seed length ----

    #[test]
    fn test_minimum_seed_length() {
        let seed = vec![0u8; 16]; // minimum 128 bits
        let result = ExtendedPrivKey::from_seed(&seed, Network::Mainnet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_maximum_seed_length() {
        let seed = vec![0u8; 64]; // maximum 512 bits
        let result = ExtendedPrivKey::from_seed(&seed, Network::Mainnet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_base58check_roundtrip_78_bytes() {
        // Verify that base58check encode/decode roundtrips correctly for 78-byte payloads
        let seed = test_seed_1();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1").unwrap();

        let serialized = child.serialize();
        let encoded = base58check_encode(&serialized);
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(decoded, serialized.to_vec());
    }
}
