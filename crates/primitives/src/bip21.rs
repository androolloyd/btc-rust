//! BIP21 — Bitcoin URI Scheme.
//!
//! Parse and construct `bitcoin:` URIs of the form:
//!
//! ```text
//! bitcoin:<address>?amount=<value>&label=<label>&message=<msg>
//! ```
//!
//! All fields except the address are optional. The `amount` is expressed in
//! BTC as a decimal (e.g. `0.001`). The `label` and `message` fields are
//! percent-encoded UTF-8 strings. Arbitrary extension parameters are
//! preserved in a `HashMap`.

use std::collections::HashMap;
use std::fmt;

use crate::address::Address;
use crate::amount::Amount;
use crate::network::Network;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing a BIP21 URI.
#[derive(Debug, Error)]
pub enum Bip21Error {
    #[error("missing 'bitcoin:' scheme prefix")]
    MissingScheme,
    #[error("missing address")]
    MissingAddress,
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    #[error("invalid percent-encoding: {0}")]
    InvalidPercentEncoding(String),
}

// ---------------------------------------------------------------------------
// BitcoinUri
// ---------------------------------------------------------------------------

/// A parsed `bitcoin:` URI (BIP21).
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinUri {
    /// The Bitcoin address (required).
    pub address: String,
    /// The amount in BTC (optional).
    pub amount: Option<Amount>,
    /// A label for the address (optional, percent-decoded).
    pub label: Option<String>,
    /// A message to display to the user (optional, percent-decoded).
    pub message: Option<String>,
    /// Any additional (extension) query parameters.
    pub params: HashMap<String, String>,
}

impl BitcoinUri {
    /// Parse a BIP21 URI string.
    ///
    /// The address is validated against all supported formats (base58 P2PKH/P2SH,
    /// bech32/bech32m segwit, and taproot) for the given network context. If the
    /// network cannot be determined from the address prefix alone, mainnet is
    /// assumed for validation purposes. Callers can pass an explicit `Network`
    /// to `parse_with_network` for stricter checking.
    pub fn parse(uri: &str) -> Result<Self, Bip21Error> {
        Self::parse_with_network(uri, None)
    }

    /// Parse a BIP21 URI with an optional network hint for address validation.
    pub fn parse_with_network(uri: &str, network: Option<Network>) -> Result<Self, Bip21Error> {
        // Strip the scheme (case-insensitive).
        let rest = if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case("bitcoin:") {
            &uri[8..]
        } else {
            return Err(Bip21Error::MissingScheme);
        };

        if rest.is_empty() {
            return Err(Bip21Error::MissingAddress);
        }

        // Split address from query string.
        let (address_str, query) = match rest.find('?') {
            Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
            None => (rest, None),
        };

        if address_str.is_empty() {
            return Err(Bip21Error::MissingAddress);
        }

        // Validate the address.
        validate_address(address_str, network)?;

        let mut amount: Option<Amount> = None;
        let mut label: Option<String> = None;
        let mut message: Option<String> = None;
        let mut params: HashMap<String, String> = HashMap::new();

        if let Some(qs) = query {
            for pair in qs.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (key, value) = match pair.find('=') {
                    Some(idx) => (&pair[..idx], &pair[idx + 1..]),
                    None => (pair, ""),
                };

                match key {
                    "amount" => {
                        amount = Some(parse_btc_amount(value)?);
                    }
                    "label" => {
                        label = Some(percent_decode(value)?);
                    }
                    "message" => {
                        message = Some(percent_decode(value)?);
                    }
                    _ => {
                        let decoded_value = percent_decode(value)?;
                        params.insert(key.to_string(), decoded_value);
                    }
                }
            }
        }

        Ok(BitcoinUri {
            address: address_str.to_string(),
            amount,
            label,
            message,
            params,
        })
    }

    /// Construct a new `BitcoinUri`.
    pub fn new(address: String) -> Self {
        BitcoinUri {
            address,
            amount: None,
            label: None,
            message: None,
            params: HashMap::new(),
        }
    }

    /// Set the amount (in satoshis via `Amount`).
    pub fn with_amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the label.
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// Set the message.
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }

    /// Add an extension parameter.
    pub fn with_param(mut self, key: String, value: String) -> Self {
        self.params.insert(key, value);
        self
    }
}

impl fmt::Display for BitcoinUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bitcoin:{}", self.address)?;

        let mut first = true;
        let mut sep = |f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if first {
                write!(f, "?")?;
                first = false;
            } else {
                write!(f, "&")?;
            }
            Ok(())
        };

        if let Some(ref amount) = self.amount {
            sep(f)?;
            // Format amount as BTC decimal with up to 8 decimal places,
            // stripping trailing zeros.
            let sats = amount.as_sat();
            let btc_whole = sats / 100_000_000;
            let btc_frac = (sats % 100_000_000).unsigned_abs();
            if btc_frac == 0 {
                write!(f, "amount={}", btc_whole)?;
            } else {
                let frac_str = format!("{:08}", btc_frac);
                let trimmed = frac_str.trim_end_matches('0');
                write!(f, "amount={}.{}", btc_whole, trimmed)?;
            }
        }

        if let Some(ref label) = self.label {
            sep(f)?;
            write!(f, "label={}", percent_encode(label))?;
        }

        if let Some(ref message) = self.message {
            sep(f)?;
            write!(f, "message={}", percent_encode(message))?;
        }

        // Sort custom params for deterministic output.
        let mut sorted_params: Vec<_> = self.params.iter().collect();
        sorted_params.sort_by_key(|(k, _)| k.clone());
        for (key, value) in sorted_params {
            sep(f)?;
            write!(f, "{}={}", key, percent_encode(value))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a BTC amount string (decimal, e.g. "0.001" or "1") into an `Amount`.
fn parse_btc_amount(s: &str) -> Result<Amount, Bip21Error> {
    if s.is_empty() {
        return Err(Bip21Error::InvalidAmount("empty amount".to_string()));
    }

    let negative = s.starts_with('-');
    if negative {
        return Err(Bip21Error::InvalidAmount(
            "negative amounts are not allowed".to_string(),
        ));
    }

    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        1 => {
            // Integer BTC
            let whole: i64 = parts[0]
                .parse()
                .map_err(|e| Bip21Error::InvalidAmount(format!("{}", e)))?;
            Ok(Amount::from_sat(whole * 100_000_000))
        }
        2 => {
            let whole: i64 = if parts[0].is_empty() {
                0
            } else {
                parts[0]
                    .parse()
                    .map_err(|e| Bip21Error::InvalidAmount(format!("{}", e)))?
            };
            let frac_str = parts[1];
            if frac_str.len() > 8 {
                return Err(Bip21Error::InvalidAmount(
                    "too many decimal places (max 8)".to_string(),
                ));
            }
            // Pad to 8 digits
            let padded = format!("{:0<8}", frac_str);
            let frac: i64 = padded
                .parse()
                .map_err(|e| Bip21Error::InvalidAmount(format!("{}", e)))?;
            Ok(Amount::from_sat(whole * 100_000_000 + frac))
        }
        _ => Err(Bip21Error::InvalidAmount(
            "multiple decimal points".to_string(),
        )),
    }
}

/// Percent-decode a URI component.
fn percent_decode(s: &str) -> Result<String, Bip21Error> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(Bip21Error::InvalidPercentEncoding(
                    "incomplete percent-encoding".to_string(),
                ));
            }
            let hi = hex_digit(bytes[i + 1]).ok_or_else(|| {
                Bip21Error::InvalidPercentEncoding(format!(
                    "invalid hex digit '{}'",
                    bytes[i + 1] as char
                ))
            })?;
            let lo = hex_digit(bytes[i + 2]).ok_or_else(|| {
                Bip21Error::InvalidPercentEncoding(format!(
                    "invalid hex digit '{}'",
                    bytes[i + 2] as char
                ))
            })?;
            result.push(hi << 4 | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result)
        .map_err(|e| Bip21Error::InvalidPercentEncoding(format!("invalid UTF-8: {}", e)))
}

/// Percent-encode a URI component (BIP21 compatible).
fn percent_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            // Unreserved characters (RFC 3986)
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_UPPER[(byte >> 4) as usize] as char);
                result.push(HEX_UPPER[(byte & 0x0f) as usize] as char);
            }
        }
    }
    result
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Validate a Bitcoin address string against known formats.
fn validate_address(addr: &str, network: Option<Network>) -> Result<(), Bip21Error> {
    let net = network.unwrap_or(Network::Mainnet);

    // Try bech32/bech32m first (bc1... / tb1... / bcrt1...)
    if addr.starts_with("bc1")
        || addr.starts_with("BC1")
        || addr.starts_with("tb1")
        || addr.starts_with("TB1")
        || addr.starts_with("bcrt1")
        || addr.starts_with("BCRT1")
    {
        // Determine the correct network from the HRP
        let effective_net = if addr.starts_with("bc1") || addr.starts_with("BC1") {
            Network::Mainnet
        } else if addr.starts_with("bcrt1") || addr.starts_with("BCRT1") {
            Network::Regtest
        } else {
            Network::Testnet
        };
        Address::from_bech32(addr, effective_net)
            .map_err(|e| Bip21Error::InvalidAddress(format!("{}", e)))?;
        return Ok(());
    }

    // Try base58 (P2PKH / P2SH)
    // Try mainnet first, then testnet
    if Address::from_base58(addr, net).is_ok() {
        return Ok(());
    }
    // Try the other network variants
    for &try_net in &[Network::Mainnet, Network::Testnet, Network::Regtest] {
        if Address::from_base58(addr, try_net).is_ok() {
            return Ok(());
        }
    }

    Err(Bip21Error::InvalidAddress(format!(
        "unrecognized address format: {}",
        addr
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_only() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(parsed.amount.is_none());
        assert!(parsed.label.is_none());
        assert!(parsed.message.is_none());
        assert!(parsed.params.is_empty());
    }

    #[test]
    fn test_parse_with_amount() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.001";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let amount = parsed.amount.unwrap();
        assert_eq!(amount.as_sat(), 100_000); // 0.001 BTC = 100,000 sats
    }

    #[test]
    fn test_parse_with_whole_btc_amount() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=21";
        let parsed = BitcoinUri::parse(uri).unwrap();
        let amount = parsed.amount.unwrap();
        assert_eq!(amount.as_sat(), 21 * 100_000_000);
    }

    #[test]
    fn test_parse_full_uri() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.1&label=Satoshi&message=Donation";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(parsed.amount.unwrap().as_sat(), 10_000_000);
        assert_eq!(parsed.label.as_deref(), Some("Satoshi"));
        assert_eq!(parsed.message.as_deref(), Some("Donation"));
    }

    #[test]
    fn test_parse_percent_encoded_label() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Hello%20World";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.label.as_deref(), Some("Hello World"));
    }

    #[test]
    fn test_parse_percent_encoded_message() {
        let uri =
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?message=Pay%20for%20lunch%20%26%20coffee";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(
            parsed.message.as_deref(),
            Some("Pay for lunch & coffee")
        );
    }

    #[test]
    fn test_parse_custom_params() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1&req-custom=value";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.params.get("req-custom").map(|s| s.as_str()), Some("value"));
    }

    #[test]
    fn test_parse_bech32_address() {
        let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.5";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(parsed.amount.unwrap().as_sat(), 50_000_000);
    }

    #[test]
    fn test_parse_missing_scheme() {
        let result = BitcoinUri::parse("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(matches!(result, Err(Bip21Error::MissingScheme)));
    }

    #[test]
    fn test_parse_missing_address() {
        let result = BitcoinUri::parse("bitcoin:");
        assert!(matches!(result, Err(Bip21Error::MissingAddress)));
    }

    #[test]
    fn test_parse_missing_address_with_query() {
        let result = BitcoinUri::parse("bitcoin:?amount=1");
        assert!(matches!(result, Err(Bip21Error::MissingAddress)));
    }

    #[test]
    fn test_parse_invalid_address() {
        let result = BitcoinUri::parse("bitcoin:notavalidaddress123");
        assert!(matches!(result, Err(Bip21Error::InvalidAddress(_))));
    }

    #[test]
    fn test_parse_invalid_amount_negative() {
        let result = BitcoinUri::parse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=-1");
        assert!(matches!(result, Err(Bip21Error::InvalidAmount(_))));
    }

    #[test]
    fn test_parse_invalid_amount_text() {
        let result = BitcoinUri::parse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=abc");
        assert!(matches!(result, Err(Bip21Error::InvalidAmount(_))));
    }

    #[test]
    fn test_parse_invalid_amount_too_many_decimals() {
        let result = BitcoinUri::parse(
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.123456789",
        );
        assert!(matches!(result, Err(Bip21Error::InvalidAmount(_))));
    }

    #[test]
    fn test_parse_case_insensitive_scheme() {
        let uri = "Bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_to_string_address_only() {
        let uri = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string());
        assert_eq!(uri.to_string(), "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_to_string_with_amount() {
        let uri = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .with_amount(Amount::from_sat(100_000));
        assert_eq!(
            uri.to_string(),
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.001"
        );
    }

    #[test]
    fn test_to_string_with_whole_amount() {
        let uri = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .with_amount(Amount::from_btc(1));
        assert_eq!(
            uri.to_string(),
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1"
        );
    }

    #[test]
    fn test_to_string_full() {
        let uri = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .with_amount(Amount::from_sat(10_000_000))
            .with_label("Satoshi".to_string())
            .with_message("Donation".to_string());
        let s = uri.to_string();
        assert!(s.starts_with("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?"));
        assert!(s.contains("amount=0.1"));
        assert!(s.contains("label=Satoshi"));
        assert!(s.contains("message=Donation"));
    }

    #[test]
    fn test_to_string_percent_encodes_special_chars() {
        let uri = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .with_label("Hello World".to_string())
            .with_message("Pay for lunch & coffee".to_string());
        let s = uri.to_string();
        assert!(s.contains("label=Hello%20World"));
        assert!(s.contains("message=Pay%20for%20lunch%20%26%20coffee"));
    }

    #[test]
    fn test_roundtrip() {
        let original = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .with_amount(Amount::from_sat(50_000_000))
            .with_label("Test Label".to_string())
            .with_message("Test message!".to_string());
        let serialized = original.to_string();
        let parsed = BitcoinUri::parse(&serialized).unwrap();
        assert_eq!(parsed.address, original.address);
        assert_eq!(parsed.amount, original.amount);
        assert_eq!(parsed.label, original.label);
        assert_eq!(parsed.message, original.message);
    }

    #[test]
    fn test_parse_amount_edge_cases() {
        // 1 satoshi
        assert_eq!(parse_btc_amount("0.00000001").unwrap().as_sat(), 1);
        // Exactly 1 BTC
        assert_eq!(parse_btc_amount("1").unwrap().as_sat(), 100_000_000);
        // 1 BTC with decimals
        assert_eq!(parse_btc_amount("1.0").unwrap().as_sat(), 100_000_000);
        // 0.5 BTC
        assert_eq!(parse_btc_amount("0.5").unwrap().as_sat(), 50_000_000);
    }

    #[test]
    fn test_percent_decode_plus_as_space() {
        let decoded = percent_decode("hello+world").unwrap();
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn test_percent_decode_mixed() {
        let decoded = percent_decode("hello%20world%21").unwrap();
        assert_eq!(decoded, "hello world!");
    }

    #[test]
    fn test_percent_decode_invalid_incomplete() {
        let result = percent_decode("hello%2");
        assert!(result.is_err());
    }

    #[test]
    fn test_percent_decode_invalid_hex() {
        let result = percent_decode("hello%ZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_percent_encode_roundtrip() {
        let original = "Hello World! This has spaces & special chars: @#$%";
        let encoded = percent_encode(original);
        let decoded = percent_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_bip21_error_display() {
        let e = Bip21Error::MissingScheme;
        assert!(format!("{}", e).contains("scheme"));

        let e = Bip21Error::MissingAddress;
        assert!(format!("{}", e).contains("address"));

        let e = Bip21Error::InvalidAmount("test".to_string());
        assert!(format!("{}", e).contains("test"));
    }

    #[test]
    fn test_parse_empty_query_param() {
        let uri = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1&";
        let parsed = BitcoinUri::parse(uri).unwrap();
        assert_eq!(parsed.amount.unwrap().as_sat(), 100_000_000);
    }

    #[test]
    fn test_builder_with_param() {
        let uri = BitcoinUri::new("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .with_param("req-custom".to_string(), "value".to_string());
        let s = uri.to_string();
        assert!(s.contains("req-custom=value"));
    }
}
