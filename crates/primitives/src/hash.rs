use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::fmt;

/// Perform SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Perform double SHA-256 (SHA256d) — Bitcoin's primary hash function
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Perform HASH160 (SHA-256 followed by RIPEMD-160)
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    hasher.finalize().into()
}

macro_rules! define_hash_type {
    ($name:ident, $size:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const ZERO: Self = Self([0u8; $size]);
            pub const LEN: usize = $size;

            pub fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            /// Create from a slice. Panics if slice length != $size.
            pub fn from_slice(slice: &[u8]) -> Self {
                let mut bytes = [0u8; $size];
                bytes.copy_from_slice(slice);
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub fn to_bytes(self) -> [u8; $size] {
                self.0
            }

            /// Parse from hex string (displayed byte order — reversed for Bitcoin hashes)
            pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
                let mut bytes = <[u8; $size]>::default();
                hex::decode_to_slice(s, &mut bytes)?;
                // Bitcoin displays hashes in reversed byte order
                bytes.reverse();
                Ok(Self(bytes))
            }

            /// Convert to hex string (displayed byte order — reversed)
            pub fn to_hex(&self) -> String {
                let mut reversed = self.0;
                reversed.reverse();
                hex::encode(reversed)
            }

            /// Parse from hex in internal byte order (no reversal)
            pub fn from_hex_internal(s: &str) -> Result<Self, hex::FromHexError> {
                let mut bytes = <[u8; $size]>::default();
                hex::decode_to_slice(s, &mut bytes)?;
                Ok(Self(bytes))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_hex())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }
        }
    };
}

define_hash_type!(Hash256, 32, "A 256-bit hash (used for SHA256d results)");
define_hash_type!(BlockHash, 32, "A block hash (SHA256d of block header)");
define_hash_type!(TxHash, 32, "A transaction hash (txid)");
define_hash_type!(Hash160, 20, "A 160-bit hash (HASH160 = RIPEMD160(SHA256(x)))");

impl BlockHash {
    pub fn compute(header_bytes: &[u8]) -> Self {
        Self(sha256d(header_bytes))
    }
}

impl TxHash {
    pub fn compute(tx_bytes: &[u8]) -> Self {
        Self(sha256d(tx_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256d_empty() {
        // SHA256d of empty string — well-known test vector
        let hash = sha256d(b"");
        let expected = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA256("abc") — NIST test vector
        let hash = sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_hash160() {
        // Known HASH160 vector
        let hash = hash160(b"");
        let expected = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_genesis_block_hash() {
        // Bitcoin genesis block header (80 bytes)
        let header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let header_bytes = hex::decode(header_hex).unwrap();
        let hash = BlockHash::compute(&header_bytes);
        // Genesis block hash (display order)
        assert_eq!(
            hash.to_hex(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_hash_hex_roundtrip() {
        let hash_str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash = BlockHash::from_hex(hash_str).unwrap();
        assert_eq!(hash.to_hex(), hash_str);
    }

    #[test]
    fn test_hash_zero() {
        assert_eq!(BlockHash::ZERO.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_hash_from_slice() {
        let bytes = [0xAB; 32];
        let hash = BlockHash::from_slice(&bytes);
        assert_eq!(hash.to_bytes(), bytes);
    }

    #[test]
    fn test_hash_as_bytes() {
        let bytes = [0xCD; 32];
        let hash = BlockHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash_as_ref() {
        let bytes = [0xEF; 32];
        let hash = BlockHash::from_bytes(bytes);
        let r: &[u8] = hash.as_ref();
        assert_eq!(r, &bytes);
    }

    #[test]
    fn test_hash_from_array() {
        let bytes = [0x12; 32];
        let hash: BlockHash = bytes.into();
        assert_eq!(hash.to_bytes(), bytes);
    }

    #[test]
    fn test_hash_debug_display() {
        let hash = BlockHash::from_bytes([0x01; 32]);
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("BlockHash("));
        let display = format!("{}", hash);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_hash_from_hex_internal() {
        let hex_str = "0101010101010101010101010101010101010101010101010101010101010101";
        let hash = BlockHash::from_hex_internal(hex_str).unwrap();
        assert_eq!(hash.to_bytes(), [0x01; 32]);
    }

    #[test]
    fn test_txhash_compute() {
        let data = b"some transaction bytes";
        let hash = TxHash::compute(data);
        assert_ne!(hash, TxHash::ZERO);
    }

    #[test]
    fn test_hash160_type() {
        let hash = Hash160::from_bytes([0xAA; 20]);
        assert_eq!(Hash160::LEN, 20);
        assert_eq!(hash.to_bytes(), [0xAA; 20]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 40);
    }

    #[test]
    fn test_hash256_type() {
        let hash = Hash256::from_bytes([0xBB; 32]);
        assert_eq!(Hash256::LEN, 32);
        assert_eq!(hash.to_bytes(), [0xBB; 32]);
    }

    #[test]
    fn test_hash_equality() {
        let a = TxHash::from_bytes([0x01; 32]);
        let b = TxHash::from_bytes([0x01; 32]);
        let c = TxHash::from_bytes([0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
