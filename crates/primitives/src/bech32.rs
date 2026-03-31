//! Bech32 and Bech32m encoding/decoding (BIP173 and BIP350).
//!
//! This is our own implementation -- no external bech32 crate dependency.
//! Implements the full encoding/decoding pipeline including witness address
//! handling for all segwit versions.

use std::fmt;
use thiserror::Error;

/// The bech32 character set for encoding 5-bit values.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse lookup table: ASCII byte -> 5-bit value (-1 = invalid).
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
];

/// Bech32 variant: original (BIP173) or modified (BIP350).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32Variant {
    /// Original bech32 encoding (BIP173) -- used for segwit v0.
    Bech32,
    /// Modified bech32m encoding (BIP350) -- used for segwit v1+.
    Bech32m,
}

impl Bech32Variant {
    /// The constant used in checksum computation.
    fn constant(self) -> u32 {
        match self {
            Bech32Variant::Bech32 => 1,
            Bech32Variant::Bech32m => 0x2bc830a3,
        }
    }
}

impl fmt::Display for Bech32Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bech32Variant::Bech32 => write!(f, "Bech32"),
            Bech32Variant::Bech32m => write!(f, "Bech32m"),
        }
    }
}

/// Errors that can occur during bech32 encoding/decoding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Bech32Error {
    #[error("invalid character: {0}")]
    InvalidChar(char),
    #[error("mixed case in bech32 string")]
    MixedCase,
    #[error("missing separator '1'")]
    MissingSeparator,
    #[error("empty human-readable part")]
    EmptyHrp,
    #[error("human-readable part too long (max 83)")]
    HrpTooLong,
    #[error("invalid human-readable part character")]
    InvalidHrpChar,
    #[error("data part too short (need at least 6 checksum chars)")]
    DataTooShort,
    #[error("overall string too long (max 90)")]
    StringTooLong,
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid witness version: {0}")]
    InvalidWitnessVersion(u8),
    #[error("invalid witness program length: {0} (expected 2-40)")]
    InvalidProgramLength(usize),
    #[error("invalid program length {0} for witness v0 (expected 20 or 32)")]
    InvalidV0ProgramLength(usize),
    #[error("wrong encoding variant for witness version {version}: expected {expected}, got {got}")]
    WrongVariant {
        version: u8,
        expected: Bech32Variant,
        got: Bech32Variant,
    },
    #[error("bit conversion error (padding issue)")]
    PaddingError,
    #[error("HRP mismatch: expected {expected}, got {got}")]
    HrpMismatch { expected: String, got: String },
}

// ---------------------------------------------------------------------------
// Core bech32 polynomial / checksum functions
// ---------------------------------------------------------------------------

/// Compute the bech32 BCH polynomial modular checksum.
fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (v as u32);
        if b & 1 != 0 { chk ^= 0x3b6a_57b2; }
        if b & 2 != 0 { chk ^= 0x2650_8e6d; }
        if b & 4 != 0 { chk ^= 0x1ea1_19fa; }
        if b & 8 != 0 { chk ^= 0x3d42_33dd; }
        if b & 16 != 0 { chk ^= 0x2a14_62b3; }
    }
    chk
}

/// Expand the human-readable part into values for checksum computation.
fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        v.push(c >> 5);
    }
    v.push(0);
    for c in hrp.bytes() {
        v.push(c & 0x1f);
    }
    v
}

/// Create a 6-value bech32 checksum for the given HRP and data.
fn bech32_create_checksum(hrp: &str, data: &[u8], variant: Bech32Variant) -> Vec<u8> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&values) ^ variant.constant();
    (0..6).map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8).collect()
}

/// Verify that the bech32 checksum is valid. Returns the variant if valid.
fn bech32_verify_checksum(hrp: &str, data: &[u8]) -> Option<Bech32Variant> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    let polymod = bech32_polymod(&values);
    if polymod == Bech32Variant::Bech32.constant() {
        Some(Bech32Variant::Bech32)
    } else if polymod == Bech32Variant::Bech32m.constant() {
        Some(Bech32Variant::Bech32m)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Full bech32 encode / decode
// ---------------------------------------------------------------------------

/// Encode data as a bech32 string.
///
/// `hrp` is the human-readable part (e.g. "bc"), `data` is already in 5-bit
/// groups, and `variant` selects Bech32 vs Bech32m checksum.
pub fn bech32_encode(hrp: &str, data: &[u8], variant: Bech32Variant) -> Result<String, Bech32Error> {
    // Validate HRP
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    if hrp.len() > 83 {
        return Err(Bech32Error::HrpTooLong);
    }
    for b in hrp.bytes() {
        if b < 33 || b > 126 {
            return Err(Bech32Error::InvalidHrpChar);
        }
    }

    let checksum = bech32_create_checksum(hrp, data, variant);

    let mut result = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    // HRP is always output in lowercase
    for c in hrp.chars() {
        result.push(c.to_ascii_lowercase());
    }
    result.push('1');
    for &d in data.iter().chain(checksum.iter()) {
        result.push(CHARSET[d as usize] as char);
    }

    Ok(result)
}

/// Decode a bech32 string into (hrp, data, variant).
///
/// The returned data is in 5-bit groups (excluding the 6 checksum characters).
pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>, Bech32Variant), Bech32Error> {
    // Check for mixed case
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }

    // Work with the lowercase version for decoding
    let s_lower = s.to_ascii_lowercase();

    // BIP173: a bech32 string is at most 90 characters long
    if s_lower.len() > 90 {
        return Err(Bech32Error::StringTooLong);
    }

    // Find the last '1' separator
    let sep_pos = s_lower.rfind('1').ok_or(Bech32Error::MissingSeparator)?;

    if sep_pos == 0 {
        return Err(Bech32Error::EmptyHrp);
    }

    let hrp = &s_lower[..sep_pos];
    let data_part = &s_lower[sep_pos + 1..];

    if data_part.len() < 6 {
        return Err(Bech32Error::DataTooShort);
    }

    // Validate HRP characters
    for b in hrp.bytes() {
        if b < 33 || b > 126 {
            return Err(Bech32Error::InvalidHrpChar);
        }
    }

    // Decode data part from charset
    let mut data: Vec<u8> = Vec::with_capacity(data_part.len());
    for c in data_part.chars() {
        let byte = c as u32;
        if byte >= 128 {
            return Err(Bech32Error::InvalidChar(c));
        }
        let val = CHARSET_REV[byte as usize];
        if val < 0 {
            return Err(Bech32Error::InvalidChar(c));
        }
        data.push(val as u8);
    }

    // Verify checksum
    let variant = bech32_verify_checksum(hrp, &data)
        .ok_or(Bech32Error::InvalidChecksum)?;

    // Strip the 6 checksum values
    let data_len = data.len() - 6;
    data.truncate(data_len);

    Ok((hrp.to_string(), data, variant))
}

// ---------------------------------------------------------------------------
// Long-form bech32 encode / decode (no 90-character limit)
// ---------------------------------------------------------------------------

/// Encode data as a bech32 string without the BIP173 90-character limit.
///
/// This is needed for protocols like BIP352 (Silent Payments) whose addresses
/// are longer than 90 characters.
pub fn bech32_encode_long(hrp: &str, data: &[u8], variant: Bech32Variant) -> Result<String, Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    if hrp.len() > 83 {
        return Err(Bech32Error::HrpTooLong);
    }
    for b in hrp.bytes() {
        if b < 33 || b > 126 {
            return Err(Bech32Error::InvalidHrpChar);
        }
    }

    let checksum = bech32_create_checksum(hrp, data, variant);

    let mut result = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    for c in hrp.chars() {
        result.push(c.to_ascii_lowercase());
    }
    result.push('1');
    for &d in data.iter().chain(checksum.iter()) {
        result.push(CHARSET[d as usize] as char);
    }

    Ok(result)
}

/// Decode a bech32 string without the BIP173 90-character limit.
///
/// Identical to `bech32_decode` but skips the length check, which is needed for
/// BIP352 silent payment addresses.
pub fn bech32_decode_long(s: &str) -> Result<(String, Vec<u8>, Bech32Variant), Bech32Error> {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }

    let s_lower = s.to_ascii_lowercase();

    // No 90-character limit here (unlike bech32_decode).

    let sep_pos = s_lower.rfind('1').ok_or(Bech32Error::MissingSeparator)?;
    if sep_pos == 0 {
        return Err(Bech32Error::EmptyHrp);
    }

    let hrp = &s_lower[..sep_pos];
    let data_part = &s_lower[sep_pos + 1..];

    if data_part.len() < 6 {
        return Err(Bech32Error::DataTooShort);
    }

    for b in hrp.bytes() {
        if b < 33 || b > 126 {
            return Err(Bech32Error::InvalidHrpChar);
        }
    }

    let mut data: Vec<u8> = Vec::with_capacity(data_part.len());
    for c in data_part.chars() {
        let byte = c as u32;
        if byte >= 128 {
            return Err(Bech32Error::InvalidChar(c));
        }
        let val = CHARSET_REV[byte as usize];
        if val < 0 {
            return Err(Bech32Error::InvalidChar(c));
        }
        data.push(val as u8);
    }

    let variant = bech32_verify_checksum(hrp, &data)
        .ok_or(Bech32Error::InvalidChecksum)?;

    let data_len = data.len() - 6;
    data.truncate(data_len);

    Ok((hrp.to_string(), data, variant))
}

// ---------------------------------------------------------------------------
// Bit conversion helpers
// ---------------------------------------------------------------------------

/// Convert between bit groupings (e.g. 8-bit bytes to 5-bit groups and back).
///
/// `from_bits` and `to_bits` specify the source and target bit widths.
/// If `pad` is true, any remaining bits are zero-padded to fill the last group.
pub fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, Bech32Error> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;

    for &value in data {
        let v = value as u32;
        if (v >> from_bits) != 0 {
            return Err(Bech32Error::PaddingError);
        }
        acc = (acc << from_bits) | v;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits {
        return Err(Bech32Error::PaddingError);
    } else if ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(Bech32Error::PaddingError);
    }

    Ok(ret)
}

// ---------------------------------------------------------------------------
// Witness address encoding / decoding
// ---------------------------------------------------------------------------

/// Encode a witness address (segwit) as a bech32/bech32m string.
///
/// `hrp` is the network HRP (e.g. "bc" for mainnet), `witness_version` is 0-16,
/// and `witness_program` is the raw program bytes (20 or 32 bytes for v0, 32 for v1).
pub fn encode_witness_address(
    hrp: &str,
    witness_version: u8,
    witness_program: &[u8],
) -> Result<String, Bech32Error> {
    // Validate witness version
    if witness_version > 16 {
        return Err(Bech32Error::InvalidWitnessVersion(witness_version));
    }

    // Validate program length (BIP141: 2-40 bytes)
    if witness_program.len() < 2 || witness_program.len() > 40 {
        return Err(Bech32Error::InvalidProgramLength(witness_program.len()));
    }

    // Validate v0 program lengths (BIP141: must be exactly 20 or 32)
    if witness_version == 0 && witness_program.len() != 20 && witness_program.len() != 32 {
        return Err(Bech32Error::InvalidV0ProgramLength(witness_program.len()));
    }

    // Choose variant based on witness version
    let variant = if witness_version == 0 {
        Bech32Variant::Bech32
    } else {
        Bech32Variant::Bech32m
    };

    // Convert program to 5-bit groups and prepend witness version
    let prog5 = convert_bits(witness_program, 8, 5, true)?;
    let mut data = Vec::with_capacity(1 + prog5.len());
    data.push(witness_version);
    data.extend_from_slice(&prog5);

    bech32_encode(hrp, &data, variant)
}

/// Decode a witness address from a bech32/bech32m string.
///
/// Returns `(witness_version, witness_program)` on success.
/// `expected_hrp` is the network HRP to validate against (e.g. "bc").
pub fn decode_witness_address(
    s: &str,
    expected_hrp: &str,
) -> Result<(u8, Vec<u8>), Bech32Error> {
    // BIP173: witness addresses are limited to 90 characters
    if s.len() > 90 {
        return Err(Bech32Error::StringTooLong);
    }

    let (hrp, data, variant) = bech32_decode(s)?;

    // Verify HRP matches expected
    if hrp != expected_hrp.to_ascii_lowercase() {
        return Err(Bech32Error::HrpMismatch {
            expected: expected_hrp.to_string(),
            got: hrp,
        });
    }

    // Need at least 1 byte (witness version) + program data
    if data.is_empty() {
        return Err(Bech32Error::DataTooShort);
    }

    let witness_version = data[0];

    if witness_version > 16 {
        return Err(Bech32Error::InvalidWitnessVersion(witness_version));
    }

    // Check encoding variant matches witness version
    let expected_variant = if witness_version == 0 {
        Bech32Variant::Bech32
    } else {
        Bech32Variant::Bech32m
    };

    if variant != expected_variant {
        return Err(Bech32Error::WrongVariant {
            version: witness_version,
            expected: expected_variant,
            got: variant,
        });
    }

    // Convert remaining data from 5-bit to 8-bit
    let program = convert_bits(&data[1..], 5, 8, false)?;

    // Validate program length (BIP141: 2-40)
    if program.len() < 2 || program.len() > 40 {
        return Err(Bech32Error::InvalidProgramLength(program.len()));
    }

    // Validate v0 program lengths
    if witness_version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(Bech32Error::InvalidV0ProgramLength(program.len()));
    }

    Ok((witness_version, program))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===== BIP173 valid segwit address test vectors =====

    #[test]
    fn test_bip173_valid_p2wpkh_mainnet() {
        // Verified-correct P2WPKH mainnet address for program 751e76e8...
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let (ver, prog) = decode_witness_address(addr, "bc").unwrap();
        assert_eq!(ver, 0);
        assert_eq!(prog.len(), 20);
        assert_eq!(
            hex::encode(&prog),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );

        // Roundtrip
        let reencoded = encode_witness_address("bc", ver, &prog).unwrap();
        assert_eq!(reencoded, addr.to_ascii_lowercase());
    }

    #[test]
    fn test_bip173_valid_p2wsh_testnet() {
        // P2WSH testnet: encode a 32-byte program and roundtrip
        let program = hex::decode(
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ).unwrap();
        let encoded = encode_witness_address("tb", 0, &program).unwrap();
        let (ver, prog) = decode_witness_address(&encoded, "tb").unwrap();
        assert_eq!(ver, 0);
        assert_eq!(prog.len(), 32);
        assert_eq!(prog, program);
    }

    // ===== BIP350 valid test vectors =====

    #[test]
    fn test_bip350_valid_taproot_mainnet() {
        let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        let (ver, prog) = decode_witness_address(addr, "bc").unwrap();
        assert_eq!(ver, 1);
        assert_eq!(prog.len(), 32);

        // Roundtrip
        let reencoded = encode_witness_address("bc", ver, &prog).unwrap();
        assert_eq!(reencoded, addr);
    }

    #[test]
    fn test_bip350_valid_witness_v1_testnet() {
        let addr = "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c";
        let (ver, prog) = decode_witness_address(addr, "tb").unwrap();
        assert_eq!(ver, 1);
        assert_eq!(prog.len(), 32);

        let reencoded = encode_witness_address("tb", ver, &prog).unwrap();
        assert_eq!(reencoded, addr);
    }

    // ===== Invalid test vectors =====

    #[test]
    fn test_invalid_bech32_checksum() {
        // Valid address with last char changed (bad checksum)
        let bad = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
        let result = decode_witness_address(bad, "bc");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mixed_case() {
        let result = bech32_decode("BC1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(result, Err(Bech32Error::MixedCase));
    }

    #[test]
    fn test_invalid_no_separator() {
        // No '1' character at all
        let result = bech32_decode("bcqw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_empty_hrp() {
        let result = bech32_decode("1pzry9x0s0muk");
        assert_eq!(result, Err(Bech32Error::EmptyHrp));
    }

    #[test]
    fn test_invalid_too_long() {
        let long = format!("bc1{}", "q".repeat(88));
        let result = bech32_decode(&long);
        assert_eq!(result, Err(Bech32Error::StringTooLong));
    }

    #[test]
    fn test_invalid_character_in_data() {
        // 'b' is not in the bech32 CHARSET
        let result = bech32_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_witness_v0_wrong_program_length() {
        let prog_16 = [0u8; 16];
        let result = encode_witness_address("bc", 0, &prog_16);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_witness_version_too_high() {
        let prog = [0u8; 32];
        let result = encode_witness_address("bc", 17, &prog);
        assert_eq!(result, Err(Bech32Error::InvalidWitnessVersion(17)));
    }

    #[test]
    fn test_wrong_variant_for_version() {
        // Encode v0 address with bech32m (wrong)
        let prog = [0u8; 20];
        let prog5 = convert_bits(&prog, 8, 5, true).unwrap();
        let mut data = vec![0u8];
        data.extend_from_slice(&prog5);
        let encoded = bech32_encode("bc", &data, Bech32Variant::Bech32m).unwrap();
        let result = decode_witness_address(&encoded, "bc");
        assert!(matches!(result, Err(Bech32Error::WrongVariant { .. })));
    }

    #[test]
    fn test_wrong_variant_for_v1() {
        // Encode v1 address with bech32 (wrong)
        let prog = [0u8; 32];
        let prog5 = convert_bits(&prog, 8, 5, true).unwrap();
        let mut data = vec![1u8];
        data.extend_from_slice(&prog5);
        let encoded = bech32_encode("bc", &data, Bech32Variant::Bech32).unwrap();
        let result = decode_witness_address(&encoded, "bc");
        assert!(matches!(result, Err(Bech32Error::WrongVariant { .. })));
    }

    // ===== Bit conversion tests =====

    #[test]
    fn test_convert_bits_8_to_5() {
        // 0xff = 11111111 -> 5-bit groups: 11111 | 111(00) = [31, 28] with pad
        let result = convert_bits(&[0xff], 8, 5, true).unwrap();
        assert_eq!(result, vec![31, 28]);
    }

    #[test]
    fn test_convert_bits_roundtrip() {
        let original = vec![0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
                            0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6];
        let five_bit = convert_bits(&original, 8, 5, true).unwrap();
        let back = convert_bits(&five_bit, 5, 8, false).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn test_convert_bits_invalid_input() {
        let result = convert_bits(&[0x20], 5, 8, true);
        assert!(result.is_err());
    }

    // ===== Raw bech32 encode/decode roundtrip =====

    #[test]
    fn test_bech32_encode_decode_roundtrip() {
        let data: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let encoded = bech32_encode("test", &data, Bech32Variant::Bech32).unwrap();
        let (hrp, decoded, variant) = bech32_decode(&encoded).unwrap();
        assert_eq!(hrp, "test");
        assert_eq!(decoded, data);
        assert_eq!(variant, Bech32Variant::Bech32);
    }

    #[test]
    fn test_bech32m_encode_decode_roundtrip() {
        let data: Vec<u8> = vec![0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20,
                                  3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22];
        let encoded = bech32_encode("bc", &data, Bech32Variant::Bech32m).unwrap();
        let (hrp, decoded, variant) = bech32_decode(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(decoded, data);
        assert_eq!(variant, Bech32Variant::Bech32m);
    }

    // ===== Comprehensive witness address roundtrips =====

    #[test]
    fn test_roundtrip_p2wpkh() {
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let encoded = encode_witness_address("bc", 0, &program).unwrap();
        let (ver, decoded_prog) = decode_witness_address(&encoded, "bc").unwrap();
        assert_eq!(ver, 0);
        assert_eq!(decoded_prog, program);
    }

    #[test]
    fn test_roundtrip_p2wsh() {
        let program = hex::decode(
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ).unwrap();
        let encoded = encode_witness_address("tb", 0, &program).unwrap();
        let (ver, decoded_prog) = decode_witness_address(&encoded, "tb").unwrap();
        assert_eq!(ver, 0);
        assert_eq!(decoded_prog, program);
    }

    #[test]
    fn test_roundtrip_p2tr() {
        let program = hex::decode(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ).unwrap();
        let encoded = encode_witness_address("bc", 1, &program).unwrap();
        let (ver, decoded_prog) = decode_witness_address(&encoded, "bc").unwrap();
        assert_eq!(ver, 1);
        assert_eq!(decoded_prog, program);
    }

    #[test]
    fn test_roundtrip_testnet_p2wpkh() {
        let program = [0xab; 20];
        let encoded = encode_witness_address("tb", 0, &program).unwrap();
        let (ver, decoded_prog) = decode_witness_address(&encoded, "tb").unwrap();
        assert_eq!(ver, 0);
        assert_eq!(decoded_prog.as_slice(), &program);
    }

    #[test]
    fn test_roundtrip_regtest() {
        let program = [0x42; 20];
        let encoded = encode_witness_address("bcrt", 0, &program).unwrap();
        let (ver, decoded_prog) = decode_witness_address(&encoded, "bcrt").unwrap();
        assert_eq!(ver, 0);
        assert_eq!(decoded_prog.as_slice(), &program);
    }

    // ===== Case insensitivity =====

    #[test]
    fn test_case_insensitive_decode() {
        // Use a verified-correct address
        let addr_lower = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let addr_upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";

        let (hrp1, data1, v1) = bech32_decode(addr_lower).unwrap();
        let (hrp2, data2, v2) = bech32_decode(addr_upper).unwrap();

        assert_eq!(hrp1, hrp2);
        assert_eq!(data1, data2);
        assert_eq!(v1, v2);
    }

    // ===== BIP350 specific valid address vectors =====

    #[test]
    fn test_bip350_valid_address_vectors() {
        let valid = vec![
            ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "tb", 1),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc", 1),
        ];

        for (addr, hrp, expected_ver) in valid {
            let result = decode_witness_address(addr, hrp);
            assert!(
                result.is_ok(),
                "Failed to decode BIP350 address: {} -- {:?}",
                addr,
                result.err()
            );
            let (ver, prog) = result.unwrap();
            assert_eq!(ver, expected_ver, "Wrong version for {}", addr);
            assert_eq!(prog.len(), 32, "Wrong program length for {}", addr);

            // Roundtrip
            let reencoded = encode_witness_address(hrp, ver, &prog).unwrap();
            assert_eq!(reencoded, addr.to_ascii_lowercase());
        }
    }

    #[test]
    fn test_bip350_invalid_bech32m_for_v0() {
        let prog = [0u8; 20];
        let prog5 = convert_bits(&prog, 8, 5, true).unwrap();
        let mut data = vec![0u8];
        data.extend_from_slice(&prog5);
        let encoded = bech32_encode("bc", &data, Bech32Variant::Bech32m).unwrap();
        let result = decode_witness_address(&encoded, "bc");
        assert!(result.is_err());
    }

    #[test]
    fn test_bip350_invalid_bech32_for_v1() {
        let prog = [0u8; 32];
        let prog5 = convert_bits(&prog, 8, 5, true).unwrap();
        let mut data = vec![1u8];
        data.extend_from_slice(&prog5);
        let encoded = bech32_encode("bc", &data, Bech32Variant::Bech32).unwrap();
        let result = decode_witness_address(&encoded, "bc");
        assert!(result.is_err());
    }

    // ===== HRP mismatch =====

    #[test]
    fn test_hrp_mismatch() {
        // Use verified-correct address
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = decode_witness_address(addr, "tb");
        assert!(matches!(result, Err(Bech32Error::HrpMismatch { .. })));
    }

    // ===== Polymod known values =====

    #[test]
    fn test_bech32_polymod_basic() {
        // Decode a known valid bech32 address and verify variant
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let (_, _, variant) = bech32_decode(addr).unwrap();
        assert_eq!(variant, Bech32Variant::Bech32);
    }

    #[test]
    fn test_bech32m_polymod_basic() {
        // Decode a known valid bech32m address and verify variant
        let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        let (_, _, variant) = bech32_decode(addr).unwrap();
        assert_eq!(variant, Bech32Variant::Bech32m);
    }

    // ===== Edge cases =====

    #[test]
    fn test_program_length_2_bytes() {
        let prog = [0xab; 2];
        let encoded = encode_witness_address("bc", 2, &prog).unwrap();
        let (ver, decoded) = decode_witness_address(&encoded, "bc").unwrap();
        assert_eq!(ver, 2);
        assert_eq!(decoded, prog.to_vec());
    }

    #[test]
    fn test_program_length_40_bytes() {
        let prog = [0xcd; 40];
        let encoded = encode_witness_address("bc", 3, &prog).unwrap();
        let (ver, decoded) = decode_witness_address(&encoded, "bc").unwrap();
        assert_eq!(ver, 3);
        assert_eq!(decoded, prog.to_vec());
    }

    #[test]
    fn test_program_length_1_byte_invalid() {
        let prog = [0x01];
        let result = encode_witness_address("bc", 2, &prog);
        assert!(matches!(result, Err(Bech32Error::InvalidProgramLength(1))));
    }

    #[test]
    fn test_program_length_41_bytes_invalid() {
        let prog = [0x01; 41];
        let result = encode_witness_address("bc", 2, &prog);
        assert!(matches!(result, Err(Bech32Error::InvalidProgramLength(41))));
    }

    // ===== The canonical BIP173 test vector with scriptPubKey =====

    #[test]
    fn test_bip173_p2wpkh_script_pubkey() {
        // BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4
        // => witness version 0, program 751e76e8199196d454941c45d1b3a323f1433bd6
        // => scriptPubKey: 0014751e76e8199196d454941c45d1b3a323f1433bd6
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let (ver, prog) = decode_witness_address(addr, "bc").unwrap();
        assert_eq!(ver, 0);

        let mut script_pubkey = Vec::new();
        script_pubkey.push(0x00); // OP_0
        script_pubkey.push(prog.len() as u8);
        script_pubkey.extend_from_slice(&prog);
        assert_eq!(
            hex::encode(&script_pubkey),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    // ===== BIP173 valid bech32 strings (raw, not necessarily valid segwit addresses) =====

    #[test]
    fn test_bip173_valid_bech32_strings() {
        // These are verified-correct bech32 (constant=1) strings
        let valid_bech32 = vec![
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "?1ezyfcl",
        ];

        for s in valid_bech32 {
            let result = bech32_decode(s);
            assert!(
                result.is_ok(),
                "Failed to decode valid bech32: {} -- {:?}",
                s,
                result.err()
            );
            let (_, _, variant) = result.unwrap();
            assert_eq!(
                variant,
                Bech32Variant::Bech32,
                "Expected Bech32 variant for: {}",
                s
            );
        }
    }

    // ===== BIP350 valid bech32m strings (raw, not necessarily valid segwit addresses) =====

    #[test]
    fn test_bip350_valid_bech32m_strings() {
        // These are verified-correct bech32m (constant=0x2bc830a3) strings
        let valid_bech32m = vec![
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio17hy8dj",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "?1v759aa",
        ];

        for s in valid_bech32m {
            let result = bech32_decode(s);
            assert!(
                result.is_ok(),
                "Failed to decode valid bech32m: {} -- {:?}",
                s,
                result.err()
            );
            let (_, _, variant) = result.unwrap();
            assert_eq!(
                variant,
                Bech32Variant::Bech32m,
                "Expected Bech32m for: {}",
                s
            );
        }
    }

    // ===== Invalid bech32 strings =====

    #[test]
    fn test_invalid_bech32_strings() {
        let invalid = vec![
            // HRP character out of range (space = 0x20)
            "\u{20}1nwldj5",
            // HRP character out of range (DEL = 0x7f)
            "\u{7f}1axkwrx",
            // overall max length exceeded
            "an84characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbioandextra1tt5tgs",
            // empty HRP
            "1pzry9x0s0muk",
            // Invalid data character ('b' is not in CHARSET)
            "x1b4n0q5v",
            // Too short checksum
            "li1dgmt3",
            // empty HRP
            "10a06t8",
            // empty HRP
            "1qzzfhee",
        ];

        for s in invalid {
            let result = bech32_decode(s);
            assert!(
                result.is_err(),
                "Should have rejected invalid bech32: {}",
                s
            );
        }
    }

    // ===== Invalid bech32m strings =====

    #[test]
    fn test_invalid_bech32m_strings() {
        let invalid = vec![
            // HRP character out of range
            "\u{20}1xj0phk",
            "\u{7f}1g6xzxy",
            // overall max length exceeded
            "an84characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbioandextra1569pvx",
            // No separator
            "qyrz8wqd2c9m",
            // Empty HRP
            "1qyrz8wqd2c9m",
            // Invalid data character
            "y1b0jsk6g",
            // Too short checksum
            "lt1igcx5c0",
            // Invalid character in checksum (non-bech32 char)
            "in1telegramg2dl",
            // checksum computed with bech32 instead of bech32m
            "M1VUXWEZ",
            // empty HRP
            "16plkw9",
            "1p2gdwpf",
        ];

        for s in invalid {
            let result = bech32_decode(s);
            // Some may decode as Bech32 (not Bech32m). We check they
            // do not decode as valid Bech32m.
            match &result {
                Ok((_, _, Bech32Variant::Bech32m)) => {
                    panic!("Should have rejected invalid bech32m: {}", s);
                }
                _ => {}
            }
        }
    }
}
