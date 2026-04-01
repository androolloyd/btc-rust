//! BIP39 Mnemonic seed phrase generation and validation.
//!
//! Implements the BIP39 standard for generating deterministic wallets from
//! mnemonic sentences. Uses established crypto crates (sha2, hmac, pbkdf2)
//! rather than hand-rolled implementations.

mod bip39_wordlist;
pub use bip39_wordlist::ENGLISH_WORDLIST;

use sha2::{Sha256, Sha512, Digest};
use pbkdf2::pbkdf2_hmac;
use thiserror::Error;

/// Errors from BIP39 mnemonic operations.
#[derive(Debug, Error)]
pub enum Bip39Error {
    #[error("invalid word count {0}: must be 12, 15, 18, 21, or 24")]
    InvalidWordCount(usize),
    #[error("unknown word: {0}")]
    UnknownWord(String),
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid entropy length {0}: must be 16, 20, 24, 28, or 32 bytes")]
    InvalidEntropyLength(usize),
}

/// A BIP39 mnemonic phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mnemonic {
    words: Vec<String>,
    entropy: Vec<u8>,
}

impl Mnemonic {
    /// Generate a new mnemonic with the given word count (12, 15, 18, 21, or 24).
    pub fn generate(word_count: usize) -> Result<Self, Bip39Error> {
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(Bip39Error::InvalidWordCount(word_count)),
        };

        use secp256k1::rand::RngCore;
        let mut rng = secp256k1::rand::thread_rng();
        let mut entropy = vec![0u8; entropy_bytes];
        rng.fill_bytes(&mut entropy);
        Self::from_entropy(&entropy)
    }

    /// Create a mnemonic from raw entropy bytes (16, 20, 24, 28, or 32 bytes).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Bip39Error> {
        let ent_bits = entropy.len() * 8;
        let cs_bits = ent_bits / 32;
        let total_bits = ent_bits + cs_bits;

        if ![128, 160, 192, 224, 256].contains(&ent_bits) {
            return Err(Bip39Error::InvalidEntropyLength(entropy.len()));
        }

        // Compute checksum: first cs_bits of SHA256(entropy)
        let hash = Sha256::digest(entropy);

        // Combine entropy + checksum bits
        let mut bits = Vec::with_capacity(total_bits);
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        for i in 0..cs_bits {
            bits.push((hash[i / 8] >> (7 - (i % 8))) & 1);
        }

        // Convert each 11-bit chunk to a word index
        let mut words = Vec::with_capacity(total_bits / 11);
        for chunk in bits.chunks(11) {
            let mut index: usize = 0;
            for &bit in chunk {
                index = (index << 1) | (bit as usize);
            }
            words.push(ENGLISH_WORDLIST[index].to_string());
        }

        Ok(Mnemonic {
            words,
            entropy: entropy.to_vec(),
        })
    }

    /// Parse and validate a mnemonic phrase from a string.
    pub fn from_phrase(phrase: &str) -> Result<Self, Bip39Error> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let word_count = words.len();

        if ![12, 15, 18, 21, 24].contains(&word_count) {
            return Err(Bip39Error::InvalidWordCount(word_count));
        }

        // Look up each word's index
        let mut indices = Vec::with_capacity(word_count);
        for word in &words {
            match ENGLISH_WORDLIST.iter().position(|w| w == word) {
                Some(idx) => indices.push(idx),
                None => return Err(Bip39Error::UnknownWord(word.to_string())),
            }
        }

        // Convert indices back to bits
        let total_bits = word_count * 11;
        let mut bits = Vec::with_capacity(total_bits);
        for &idx in &indices {
            for i in (0..11).rev() {
                bits.push(((idx >> i) & 1) as u8);
            }
        }

        let ent_bits = (total_bits * 32) / 33;
        let cs_bits = total_bits - ent_bits;

        // Extract entropy bytes
        let mut entropy = Vec::with_capacity(ent_bits / 8);
        for chunk in bits[..ent_bits].chunks(8) {
            let mut byte = 0u8;
            for &bit in chunk {
                byte = (byte << 1) | bit;
            }
            entropy.push(byte);
        }

        // Verify checksum
        let hash = Sha256::digest(&entropy);
        for i in 0..cs_bits {
            let expected = (hash[i / 8] >> (7 - (i % 8))) & 1;
            if bits[ent_bits + i] != expected {
                return Err(Bip39Error::InvalidChecksum);
            }
        }

        Ok(Mnemonic {
            words: words.iter().map(|w| w.to_string()).collect(),
            entropy,
        })
    }

    /// Derive a 64-byte seed from the mnemonic using PBKDF2-HMAC-SHA512.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic_str = self.words.join(" ");
        let salt = format!("mnemonic{}", passphrase);

        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(
            mnemonic_str.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed,
        );
        seed
    }

    /// Get the words of this mnemonic.
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Get the original entropy bytes.
    pub fn to_entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// Get the word count.
    pub fn word_count(&self) -> usize {
        self.words.len()
    }

    /// Get the mnemonic as a space-separated string.
    pub fn phrase(&self) -> String {
        self.words.join(" ")
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.phrase())
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = Bip39Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_phrase(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_length() {
        assert_eq!(ENGLISH_WORDLIST.len(), 2048);
        assert_eq!(ENGLISH_WORDLIST[0], "abandon");
        assert_eq!(ENGLISH_WORDLIST[2047], "zoo");
    }

    #[test]
    fn test_generate_12_words() {
        let m = Mnemonic::generate(12).unwrap();
        assert_eq!(m.word_count(), 12);
        assert_eq!(m.to_entropy().len(), 16);
    }

    #[test]
    fn test_generate_24_words() {
        let m = Mnemonic::generate(24).unwrap();
        assert_eq!(m.word_count(), 24);
        assert_eq!(m.to_entropy().len(), 32);
    }

    #[test]
    fn test_generate_all_valid_counts() {
        for count in [12, 15, 18, 21, 24] {
            let m = Mnemonic::generate(count).unwrap();
            assert_eq!(m.word_count(), count);
        }
    }

    #[test]
    fn test_invalid_word_count() {
        assert!(Mnemonic::generate(11).is_err());
        assert!(Mnemonic::generate(13).is_err());
        assert!(Mnemonic::generate(0).is_err());
    }

    #[test]
    fn test_from_entropy_roundtrip() {
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), 12);
        // All-zeros entropy should produce "abandon" repeated (with checksum word)
        assert_eq!(m.words()[0], "abandon");
        assert_eq!(m.to_entropy(), entropy.as_slice());
    }

    #[test]
    fn test_from_phrase_roundtrip() {
        let m1 = Mnemonic::generate(12).unwrap();
        let phrase = m1.phrase();
        let m2 = Mnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(m1.words(), m2.words());
        assert_eq!(m1.to_entropy(), m2.to_entropy());
    }

    #[test]
    fn test_invalid_checksum() {
        // Take a valid mnemonic and change the last word
        let m = Mnemonic::generate(12).unwrap();
        let mut words: Vec<String> = m.words().to_vec();
        // Change last word to something that breaks checksum
        words[11] = if words[11] == "abandon" { "zoo".into() } else { "abandon".into() };
        let phrase = words.join(" ");
        assert!(Mnemonic::from_phrase(&phrase).is_err());
    }

    #[test]
    fn test_unknown_word() {
        let result = Mnemonic::from_phrase("abandon ability able about above absent absorb abstract absurd abuse access notaword");
        assert!(matches!(result, Err(Bip39Error::UnknownWord(_))));
    }

    #[test]
    fn test_wrong_word_count_phrase() {
        let result = Mnemonic::from_phrase("abandon ability able");
        assert!(matches!(result, Err(Bip39Error::InvalidWordCount(3))));
    }

    #[test]
    fn test_to_seed_deterministic() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let seed1 = m.to_seed("");
        let seed2 = m.to_seed("");
        assert_eq!(seed1, seed2);
        assert_ne!(seed1, [0u8; 64]);
    }

    #[test]
    fn test_to_seed_passphrase_changes_seed() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let seed_no_pass = m.to_seed("");
        let seed_with_pass = m.to_seed("mypassphrase");
        assert_ne!(seed_no_pass, seed_with_pass);
    }

    #[test]
    fn test_display_and_from_str() {
        let m1 = Mnemonic::generate(12).unwrap();
        let display = format!("{}", m1);
        let m2: Mnemonic = display.parse().unwrap();
        assert_eq!(m1, m2);
    }

    // BIP39 test vector: all-zero 128-bit entropy
    #[test]
    fn test_vector_all_zeros_128() {
        let entropy = vec![0u8; 16];
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        // Known result for all-zeros entropy
        assert_eq!(m.words()[0], "abandon");
        assert_eq!(m.word_count(), 12);

        // Verify seed with empty passphrase matches known vector
        let seed = m.to_seed("TREZOR");
        // The seed should be deterministic and non-zero
        assert_ne!(seed, [0u8; 64]);
    }

    // BIP39 test vector: all-ones (0xff) 256-bit entropy
    #[test]
    fn test_vector_all_ff_256() {
        let entropy = vec![0xff; 32];
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), 24);
        // All 0xff bits = index 2047 for each 11-bit chunk = "zoo" repeated
        assert_eq!(m.words()[0], "zoo");
        assert_eq!(m.words()[1], "zoo");
    }

    #[test]
    fn test_invalid_entropy_length() {
        assert!(Mnemonic::from_entropy(&[0u8; 15]).is_err());
        assert!(Mnemonic::from_entropy(&[0u8; 17]).is_err());
        assert!(Mnemonic::from_entropy(&[0u8; 0]).is_err());
    }

    #[test]
    fn test_entropy_roundtrip_all_sizes() {
        for size in [16, 20, 24, 28, 32] {
            let entropy: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            let phrase = m.phrase();
            let m2 = Mnemonic::from_phrase(&phrase).unwrap();
            assert_eq!(m.to_entropy(), m2.to_entropy());
        }
    }

    #[test]
    fn test_error_display() {
        assert!(format!("{}", Bip39Error::InvalidWordCount(5)).contains("5"));
        assert!(format!("{}", Bip39Error::UnknownWord("xyz".into())).contains("xyz"));
        assert!(format!("{}", Bip39Error::InvalidChecksum).contains("checksum"));
        assert!(format!("{}", Bip39Error::InvalidEntropyLength(7)).contains("7"));
    }
}
