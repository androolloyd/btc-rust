use crate::hash::{sha256d, hash160};
use crate::network::Network;
use crate::script::ScriptBuf;
use crate::bech32::{self as bech32_mod, Bech32Error};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("invalid base58 character: {0}")]
    InvalidBase58Char(char),
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid address length")]
    InvalidLength,
    #[error("unknown address version: {0}")]
    UnknownVersion(u8),
    #[error("invalid bech32 encoding: {0}")]
    InvalidBech32(#[from] Bech32Error),
}

/// A Bitcoin address
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Pay-to-Public-Key-Hash (legacy, starts with 1 on mainnet)
    P2pkh { hash: [u8; 20], network: Network },
    /// Pay-to-Script-Hash (starts with 3 on mainnet)
    P2sh { hash: [u8; 20], network: Network },
    /// Pay-to-Witness-Public-Key-Hash (bech32, starts with bc1q)
    P2wpkh { hash: [u8; 20], network: Network },
    /// Pay-to-Witness-Script-Hash (bech32, starts with bc1q)
    P2wsh { hash: [u8; 32], network: Network },
    /// Pay-to-Taproot (bech32m, starts with bc1p)
    P2tr { output_key: [u8; 32], network: Network },
}

impl Address {
    /// Create a P2PKH address from a public key
    pub fn p2pkh_from_pubkey(pubkey: &[u8], network: Network) -> Self {
        let hash = hash160(pubkey);
        Address::P2pkh { hash, network }
    }

    /// Get the script_pubkey for this address
    pub fn script_pubkey(&self) -> ScriptBuf {
        match self {
            Address::P2pkh { hash, .. } => ScriptBuf::p2pkh(hash),
            Address::P2sh { hash, .. } => ScriptBuf::p2sh(hash),
            Address::P2wpkh { hash, .. } => ScriptBuf::p2wpkh(hash),
            Address::P2wsh { hash, .. } => ScriptBuf::p2wsh(hash),
            Address::P2tr { output_key, .. } => ScriptBuf::p2tr(output_key),
        }
    }

    /// Get the network for this address
    pub fn network(&self) -> Network {
        match self {
            Address::P2pkh { network, .. }
            | Address::P2sh { network, .. }
            | Address::P2wpkh { network, .. }
            | Address::P2wsh { network, .. }
            | Address::P2tr { network, .. } => *network,
        }
    }

    /// Encode as base58check (for P2PKH and P2SH)
    pub fn to_base58(&self) -> Option<String> {
        match self {
            Address::P2pkh { hash, network } => {
                let version = network.p2pkh_version();
                Some(base58check_encode(version, hash))
            }
            Address::P2sh { hash, network } => {
                let version = network.p2sh_version();
                Some(base58check_encode(version, hash))
            }
            _ => None,
        }
    }

    /// Decode from base58check
    pub fn from_base58(s: &str, network: Network) -> Result<Self, AddressError> {
        let (version, data) = base58check_decode(s)?;
        if data.len() != 20 {
            return Err(AddressError::InvalidLength);
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&data);

        if version == network.p2pkh_version() {
            Ok(Address::P2pkh { hash, network })
        } else if version == network.p2sh_version() {
            Ok(Address::P2sh { hash, network })
        } else {
            Err(AddressError::UnknownVersion(version))
        }
    }

    /// Decode from a bech32/bech32m witness address string.
    pub fn from_bech32(s: &str, network: Network) -> Result<Self, AddressError> {
        let hrp = network.bech32_hrp();
        let (witness_version, program) = bech32_mod::decode_witness_address(s, hrp)?;

        match witness_version {
            0 => {
                if program.len() == 20 {
                    let mut hash = [0u8; 20];
                    hash.copy_from_slice(&program);
                    Ok(Address::P2wpkh { hash, network })
                } else if program.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&program);
                    Ok(Address::P2wsh { hash, network })
                } else {
                    Err(Bech32Error::InvalidV0ProgramLength(program.len()).into())
                }
            }
            1 => {
                if program.len() == 32 {
                    let mut output_key = [0u8; 32];
                    output_key.copy_from_slice(&program);
                    Ok(Address::P2tr { output_key, network })
                } else {
                    Err(Bech32Error::InvalidProgramLength(program.len()).into())
                }
            }
            v => Err(Bech32Error::InvalidWitnessVersion(v).into()),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::P2pkh { .. } | Address::P2sh { .. } => {
                write!(f, "{}", self.to_base58().unwrap())
            }
            Address::P2wpkh { hash, network } => {
                let hrp = network.bech32_hrp();
                let encoded = bech32_mod::encode_witness_address(hrp, 0, hash)
                    .map_err(|_| fmt::Error)?;
                write!(f, "{}", encoded)
            }
            Address::P2wsh { hash, network } => {
                let hrp = network.bech32_hrp();
                let encoded = bech32_mod::encode_witness_address(hrp, 0, hash)
                    .map_err(|_| fmt::Error)?;
                write!(f, "{}", encoded)
            }
            Address::P2tr { output_key, network } => {
                let hrp = network.bech32_hrp();
                let encoded = bech32_mod::encode_witness_address(hrp, 1, output_key)
                    .map_err(|_| fmt::Error)?;
                write!(f, "{}", encoded)
            }
        }
    }
}

// === Base58 implementation (our own, no external dep) ===

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to base58
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

fn base58_decode(s: &str) -> Result<Vec<u8>, AddressError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let leading_ones = s.chars().take_while(|&c| c == '1').count();

    let mut bytes: Vec<u8> = Vec::new();
    for ch in s.chars() {
        let val = BASE58_ALPHABET.iter()
            .position(|&c| c == ch as u8)
            .ok_or(AddressError::InvalidBase58Char(ch))? as u32;

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

fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(version);
    data.extend_from_slice(payload);

    let checksum = sha256d(&data);
    data.extend_from_slice(&checksum[..4]);

    base58_encode(&data)
}

fn base58check_decode(s: &str) -> Result<(u8, Vec<u8>), AddressError> {
    let data = base58_decode(s)?;
    if data.len() < 5 {
        return Err(AddressError::InvalidLength);
    }

    let (payload, checksum) = data.split_at(data.len() - 4);
    let computed_checksum = sha256d(payload);

    if checksum != &computed_checksum[..4] {
        return Err(AddressError::InvalidChecksum);
    }

    let version = payload[0];
    let data = payload[1..].to_vec();
    Ok((version, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58_encode_decode_roundtrip() {
        let data = hex::decode("00010966776006953d5567439e5e39f86a0d273bee").unwrap();
        let encoded = base58_encode(&data);
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_base58check_known_address() {
        // Known mainnet P2PKH address
        let hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let mut h = [0u8; 20];
        h.copy_from_slice(&hash);
        let encoded = base58check_encode(0x00, &h);
        assert_eq!(encoded, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_base58check_decode_address() {
        let (version, data) = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(version, 0x00);
        assert_eq!(hex::encode(data), "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    }

    #[test]
    fn test_base58check_invalid_checksum() {
        let result = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"); // changed last char
        assert!(result.is_err());
    }

    #[test]
    fn test_p2pkh_address_from_base58() {
        let addr = Address::from_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Mainnet).unwrap();
        match addr {
            Address::P2pkh { hash, network } => {
                assert_eq!(network, Network::Mainnet);
                assert_eq!(hex::encode(hash), "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
            }
            _ => panic!("expected P2PKH"),
        }
    }

    #[test]
    fn test_address_script_pubkey() {
        let addr = Address::from_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Mainnet).unwrap();
        let script = addr.script_pubkey();
        assert!(script.is_p2pkh());
    }

    #[test]
    fn test_p2wpkh_display_bech32() {
        let hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut h = [0u8; 20];
        h.copy_from_slice(&hash);
        let addr = Address::P2wpkh { hash: h, network: Network::Mainnet };
        let displayed = addr.to_string();
        assert_eq!(displayed, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_p2wsh_display_bech32() {
        let hash = hex::decode("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262").unwrap();
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        let addr = Address::P2wsh { hash: h, network: Network::Testnet };
        let displayed = addr.to_string();
        // Should be a valid bech32 string, decode it back
        let decoded = Address::from_bech32(&displayed, Network::Testnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_p2tr_display_bech32m() {
        let key = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let addr = Address::P2tr { output_key: k, network: Network::Mainnet };
        let displayed = addr.to_string();
        // Should roundtrip
        let decoded = Address::from_bech32(&displayed, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_from_bech32_p2wpkh() {
        let addr = Address::from_bech32(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Mainnet,
        ).unwrap();
        match addr {
            Address::P2wpkh { hash, network } => {
                assert_eq!(network, Network::Mainnet);
                assert_eq!(hex::encode(hash), "751e76e8199196d454941c45d1b3a323f1433bd6");
            }
            _ => panic!("expected P2WPKH"),
        }
    }

    #[test]
    fn test_from_bech32_p2tr() {
        let addr = Address::from_bech32(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            Network::Mainnet,
        ).unwrap();
        match addr {
            Address::P2tr { output_key, network } => {
                assert_eq!(network, Network::Mainnet);
                assert_eq!(output_key.len(), 32);
            }
            _ => panic!("expected P2TR"),
        }
    }

    #[test]
    fn test_from_bech32_wrong_network() {
        let result = Address::from_bech32(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Testnet, // HRP mismatch: address is "bc" but we expect "tb"
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_address_display_roundtrip_p2wpkh() {
        let hash = [0xab; 20];
        let addr = Address::P2wpkh { hash, network: Network::Mainnet };
        let s = addr.to_string();
        let decoded = Address::from_bech32(&s, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_display_roundtrip_p2wsh() {
        let hash = [0xcd; 32];
        let addr = Address::P2wsh { hash, network: Network::Mainnet };
        let s = addr.to_string();
        let decoded = Address::from_bech32(&s, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_display_roundtrip_p2tr() {
        let key = [0xef; 32];
        let addr = Address::P2tr { output_key: key, network: Network::Mainnet };
        let s = addr.to_string();
        let decoded = Address::from_bech32(&s, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }

    // ---- Additional coverage tests ----

    #[test]
    fn test_p2pkh_from_pubkey() {
        let pubkey = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let addr = Address::p2pkh_from_pubkey(&pubkey, Network::Mainnet);
        match addr {
            Address::P2pkh { network, .. } => assert_eq!(network, Network::Mainnet),
            _ => panic!("expected P2PKH"),
        }
    }

    #[test]
    fn test_address_network() {
        let cases = vec![
            Address::P2pkh { hash: [0; 20], network: Network::Mainnet },
            Address::P2sh { hash: [0; 20], network: Network::Testnet },
            Address::P2wpkh { hash: [0; 20], network: Network::Signet },
            Address::P2wsh { hash: [0; 32], network: Network::Regtest },
            Address::P2tr { output_key: [0; 32], network: Network::Mainnet },
        ];
        let expected = vec![Network::Mainnet, Network::Testnet, Network::Signet, Network::Regtest, Network::Mainnet];
        for (addr, net) in cases.iter().zip(expected.iter()) {
            assert_eq!(addr.network(), *net);
        }
    }

    #[test]
    fn test_script_pubkey_all_types() {
        let addr_p2pkh = Address::P2pkh { hash: [0xab; 20], network: Network::Mainnet };
        assert!(addr_p2pkh.script_pubkey().is_p2pkh());

        let addr_p2sh = Address::P2sh { hash: [0xcd; 20], network: Network::Mainnet };
        assert!(addr_p2sh.script_pubkey().is_p2sh());

        let addr_p2wpkh = Address::P2wpkh { hash: [0xef; 20], network: Network::Mainnet };
        assert!(addr_p2wpkh.script_pubkey().is_p2wpkh());

        let addr_p2wsh = Address::P2wsh { hash: [0x12; 32], network: Network::Mainnet };
        assert!(addr_p2wsh.script_pubkey().is_p2wsh());

        let addr_p2tr = Address::P2tr { output_key: [0x34; 32], network: Network::Mainnet };
        assert!(addr_p2tr.script_pubkey().is_p2tr());
    }

    #[test]
    fn test_to_base58_only_for_legacy() {
        let addr_p2pkh = Address::P2pkh { hash: [0; 20], network: Network::Mainnet };
        assert!(addr_p2pkh.to_base58().is_some());

        let addr_p2sh = Address::P2sh { hash: [0; 20], network: Network::Mainnet };
        assert!(addr_p2sh.to_base58().is_some());

        let addr_p2wpkh = Address::P2wpkh { hash: [0; 20], network: Network::Mainnet };
        assert!(addr_p2wpkh.to_base58().is_none());

        let addr_p2wsh = Address::P2wsh { hash: [0; 32], network: Network::Mainnet };
        assert!(addr_p2wsh.to_base58().is_none());

        let addr_p2tr = Address::P2tr { output_key: [0; 32], network: Network::Mainnet };
        assert!(addr_p2tr.to_base58().is_none());
    }

    #[test]
    fn test_p2sh_base58_roundtrip() {
        let hash = [0xab; 20];
        let addr = Address::P2sh { hash, network: Network::Mainnet };
        let encoded = addr.to_base58().unwrap();
        let decoded = Address::from_base58(&encoded, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_from_base58_unknown_version() {
        // Create a base58check with an unknown version byte
        let encoded = base58check_encode(0xFF, &[0; 20]);
        let result = Address::from_base58(&encoded, Network::Mainnet);
        assert!(matches!(result, Err(AddressError::UnknownVersion(0xFF))));
    }

    #[test]
    fn test_from_base58_invalid_length() {
        // payload != 20 bytes
        let encoded = base58check_encode(0x00, &[0; 10]);
        let result = Address::from_base58(&encoded, Network::Mainnet);
        assert!(matches!(result, Err(AddressError::InvalidLength)));
    }

    #[test]
    fn test_base58_decode_invalid_char() {
        let result = base58_decode("0OIl"); // O, I, l not in base58
        assert!(result.is_err());
    }

    #[test]
    fn test_base58_decode_empty() {
        let result = base58_decode("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_base58_encode_empty() {
        let result = base58_encode(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_base58check_decode_too_short() {
        let result = base58check_decode("111");
        assert!(matches!(result, Err(AddressError::InvalidLength)));
    }

    #[test]
    fn test_base58_leading_zeros() {
        let data = vec![0, 0, 0, 1, 2, 3];
        let encoded = base58_encode(&data);
        assert!(encoded.starts_with("111")); // leading zeros map to '1'
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_display_p2pkh() {
        let hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let mut h = [0u8; 20];
        h.copy_from_slice(&hash);
        let addr = Address::P2pkh { hash: h, network: Network::Mainnet };
        let displayed = addr.to_string();
        assert_eq!(displayed, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_display_p2sh() {
        let hash = [0xab; 20];
        let addr = Address::P2sh { hash, network: Network::Mainnet };
        let displayed = addr.to_string();
        // Should be a valid base58 P2SH address
        let decoded = Address::from_base58(&displayed, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_from_bech32_invalid_checksum() {
        // Invalid checksum should fail
        let result = Address::from_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", Network::Mainnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_testnet_p2pkh_address() {
        let hash = [0; 20];
        let addr = Address::P2pkh { hash, network: Network::Testnet };
        let encoded = addr.to_base58().unwrap();
        // Testnet P2PKH starts with 'm' or 'n'
        let first = encoded.chars().next().unwrap();
        assert!(first == 'm' || first == 'n');
        let decoded = Address::from_base58(&encoded, Network::Testnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_testnet_p2sh_address() {
        let hash = [0; 20];
        let addr = Address::P2sh { hash, network: Network::Testnet };
        let encoded = addr.to_base58().unwrap();
        // Testnet P2SH starts with '2'
        assert!(encoded.starts_with('2'));
        let decoded = Address::from_base58(&encoded, Network::Testnet).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_error_display() {
        let e1 = AddressError::InvalidBase58Char('!');
        assert!(format!("{}", e1).contains("!"));
        let e2 = AddressError::InvalidChecksum;
        assert!(format!("{}", e2).contains("checksum"));
        let e3 = AddressError::InvalidLength;
        assert!(format!("{}", e3).contains("length"));
        let e4 = AddressError::UnknownVersion(0xFF);
        assert!(format!("{}", e4).contains("255"));
    }

    #[test]
    fn test_from_bech32_p2wsh() {
        let hash = [0xcd; 32];
        let addr = Address::P2wsh { hash, network: Network::Mainnet };
        let s = addr.to_string();
        let decoded = Address::from_bech32(&s, Network::Mainnet).unwrap();
        assert_eq!(decoded, addr);
    }
}
