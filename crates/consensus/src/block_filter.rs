//! BIP157/158 Compact Block Filters — Golomb-coded set filters for light clients.
//!
//! Implements "basic" block filters (filter type 0x00) that encode scriptPubKeys
//! from a block's transactions into a compact Golomb-coded set. Light clients can
//! query these filters to determine if a block is relevant without downloading
//! the full block data.
//!
//! Reference: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

use btc_primitives::block::Block;
use btc_primitives::encode::{VarInt, Encodable, Decodable};
use btc_primitives::hash::{sha256d, BlockHash};
use btc_primitives::script::Script;

/// Golomb-Rice parameter P for basic filters (BIP158).
/// The remainder of each delta is encoded in P bits.
pub const BASIC_FILTER_P: u8 = 19;

/// BIP158 basic filter false-positive rate parameter.
/// M = 784931, which equals ceil(N * 2^P / N) = 2^P * (M/2^P).
/// More precisely, M = 784931 is the optimal value for P=19.
pub const BASIC_FILTER_M: u64 = 784931;

// ---------------------------------------------------------------------------
// SipHash-2-4 (needed for GCS item hashing, per BIP158)
// ---------------------------------------------------------------------------

/// SipHash-2-4 implementation used for GCS item hashing.
/// BIP158 specifies SipHash with a 128-bit key derived from the block hash.
fn siphash(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    let mut v0: u64 = 0x736f6d6570736575 ^ k0;
    let mut v1: u64 = 0x646f72616e646f6d ^ k1;
    let mut v2: u64 = 0x6c7967656e657261 ^ k0;
    let mut v3: u64 = 0x7465646279746573 ^ k1;

    let chunks = data.len() / 8;
    for i in 0..chunks {
        let m = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Last block: remaining bytes + length
    let remaining = data.len() - chunks * 8;
    let mut last: u64 = (data.len() as u64 & 0xff) << 56;
    for j in 0..remaining {
        last |= (data[chunks * 8 + j] as u64) << (j * 8);
    }

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    // Finalization
    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

// ---------------------------------------------------------------------------
// Bit-level writer / reader for Golomb-Rice coding
// ---------------------------------------------------------------------------

/// A bit-level writer that accumulates bits into a byte buffer.
struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bits_in_current: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            data: Vec::new(),
            current_byte: 0,
            bits_in_current: 0,
        }
    }

    /// Write a single bit (0 or 1).
    fn write_bit(&mut self, bit: bool) {
        self.current_byte = (self.current_byte << 1) | (bit as u8);
        self.bits_in_current += 1;
        if self.bits_in_current == 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bits_in_current = 0;
        }
    }

    /// Write `n` bits from `value` (most significant bit first).
    fn write_bits(&mut self, value: u64, n: u8) {
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    /// Flush remaining bits, padding with zeros on the right.
    fn finish(mut self) -> Vec<u8> {
        if self.bits_in_current > 0 {
            self.current_byte <<= 8 - self.bits_in_current;
            self.data.push(self.current_byte);
        }
        self.data
    }
}

/// A bit-level reader over a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0..8, counts from MSB
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Read a single bit. Returns None at end of data.
    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1 == 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    /// Read `n` bits as a u64 (MSB first).
    fn read_bits(&mut self, n: u8) -> Option<u64> {
        let mut value: u64 = 0;
        for _ in 0..n {
            value = (value << 1) | (self.read_bit()? as u64);
        }
        Some(value)
    }
}

// ---------------------------------------------------------------------------
// Golomb-Rice coding
// ---------------------------------------------------------------------------

/// Golomb-Rice encode a single value into the bit writer.
///
/// The quotient (value >> p) is encoded as a unary number (q ones followed by a zero),
/// and the remainder (value & ((1 << p) - 1)) is encoded in p bits.
fn golomb_encode(writer: &mut BitWriter, value: u64, p: u8) {
    let q = value >> p;
    let r = value & ((1u64 << p) - 1);

    // Unary-encode the quotient: q one-bits then a zero-bit
    for _ in 0..q {
        writer.write_bit(true);
    }
    writer.write_bit(false);

    // Encode the remainder in p bits
    writer.write_bits(r, p);
}

/// Golomb-Rice decode a single value from the bit reader.
///
/// Returns None if the reader runs out of data.
fn golomb_decode(reader: &mut BitReader, p: u8) -> Option<u64> {
    // Read unary-encoded quotient: count one-bits until a zero-bit
    let mut q: u64 = 0;
    loop {
        let bit = reader.read_bit()?;
        if !bit {
            break;
        }
        q += 1;
    }

    // Read the p-bit remainder
    let r = reader.read_bits(p)?;

    Some((q << p) | r)
}

// ---------------------------------------------------------------------------
// GCS (Golomb-Coded Set)
// ---------------------------------------------------------------------------

/// Builder for constructing a Golomb-coded set.
///
/// Items are hashed with SipHash, mapped to a range [0, F) where F = N * M,
/// sorted, delta-encoded, and then Golomb-Rice compressed.
pub struct GcsBuilder {
    items: Vec<u64>,
    key: [u8; 16],
    p: u8,
    m: u64,
}

impl GcsBuilder {
    /// Create a new GCS builder, deriving the SipHash key from the block hash.
    ///
    /// Per BIP158, the key is the first 16 bytes of the block hash (internal byte order).
    pub fn new(block_hash: &BlockHash) -> Self {
        let hash_bytes = block_hash.as_bytes();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash_bytes[..16]);
        GcsBuilder {
            items: Vec::new(),
            key,
            p: BASIC_FILTER_P,
            m: BASIC_FILTER_M,
        }
    }

    /// Create a GCS builder with explicit key and parameters.
    pub fn with_params(key: [u8; 16], p: u8, m: u64) -> Self {
        GcsBuilder {
            items: Vec::new(),
            key,
            p,
            m,
        }
    }

    /// Hash an item and add it to the set.
    ///
    /// The item is hashed with SipHash, then mapped to the range [0, N*M)
    /// using fast modular reduction: (hash * F) >> 64.
    pub fn add_item(&mut self, data: &[u8]) {
        // We defer the range mapping to build() since we need N (total count)
        let h = siphash(&self.key, data);
        self.items.push(h);
    }

    /// Build the GCS filter: sort, deduplicate, delta-encode, Golomb-Rice compress.
    ///
    /// Returns the raw filter bytes (without the N count prefix — the caller
    /// typically stores N as a CompactSize before the filter data).
    pub fn build(&mut self) -> Vec<u8> {
        if self.items.is_empty() {
            return Vec::new();
        }

        // Deduplicate hashes
        self.items.sort_unstable();
        self.items.dedup();

        let n = self.items.len() as u64;
        let f = n * self.m;

        // Map hashes into [0, F) using fast range reduction
        let mut mapped: Vec<u64> = self
            .items
            .iter()
            .map(|&h| fast_range(h, f))
            .collect();
        mapped.sort_unstable();
        mapped.dedup();

        // Delta-encode and Golomb-Rice compress
        let mut writer = BitWriter::new();
        let mut prev = 0u64;
        for val in &mapped {
            let delta = val - prev;
            golomb_encode(&mut writer, delta, self.p);
            prev = *val;
        }

        writer.finish()
    }

    /// Return the number of items added so far (before dedup).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if no items have been added.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Fast modular reduction: maps a 64-bit hash to [0, range) without division.
/// Computes (hash * range) >> 64, which is equivalent to hash % range with
/// near-uniform distribution.
fn fast_range(hash: u64, range: u64) -> u64 {
    ((hash as u128 * range as u128) >> 64) as u64
}

// ---------------------------------------------------------------------------
// GCS matching (query / lookup)
// ---------------------------------------------------------------------------

/// Check if any of the given items match the GCS filter.
///
/// `n` is the number of elements in the filter, `key` is the SipHash key,
/// and `filter_data` is the raw Golomb-Rice encoded data.
pub fn gcs_match_any(
    key: &[u8; 16],
    n: u64,
    m: u64,
    p: u8,
    filter_data: &[u8],
    query_items: &[&[u8]],
) -> bool {
    if n == 0 || query_items.is_empty() || filter_data.is_empty() {
        return false;
    }

    let f = n * m;

    // Hash and map query items to the same range, then sort
    let mut query_hashes: Vec<u64> = query_items
        .iter()
        .map(|item| fast_range(siphash(key, item), f))
        .collect();
    query_hashes.sort_unstable();
    query_hashes.dedup();

    // Walk through the filter and query set simultaneously (merge-intersect)
    let mut reader = BitReader::new(filter_data);
    let mut filter_value: u64 = 0;
    let mut query_idx = 0;
    let mut filter_count = 0;

    loop {
        if query_idx >= query_hashes.len() {
            return false;
        }

        // Advance filter to next value
        if filter_count >= n {
            return false;
        }
        let delta = match golomb_decode(&mut reader, p) {
            Some(d) => d,
            None => return false,
        };
        filter_value += delta;
        filter_count += 1;

        loop {
            if query_idx >= query_hashes.len() {
                return false;
            }
            if query_hashes[query_idx] == filter_value {
                return true;
            }
            if query_hashes[query_idx] > filter_value {
                break;
            }
            // query value < filter value, advance query
            query_idx += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// BIP158 Basic Filter
// ---------------------------------------------------------------------------

/// A BIP158 basic block filter (filter type 0x00).
pub struct BasicFilter {
    /// Filter type identifier (0x00 for basic).
    pub filter_type: u8,
    /// The block hash this filter was built from.
    pub block_hash: BlockHash,
    /// Golomb-coded set data (without the N count prefix).
    pub filter_data: Vec<u8>,
    /// Number of elements in the filter.
    pub n: u32,
    /// Chained filter header: SHA256d(filter_hash || prev_filter_header).
    pub filter_header: [u8; 32],
}

impl BasicFilter {
    /// Check if any of the provided scripts match this filter.
    ///
    /// This is the primary query method for light clients: given a set of
    /// scriptPubKeys the client is interested in, returns true if the filter
    /// indicates a possible match (subject to the GCS false-positive rate).
    pub fn match_any(&self, scripts: &[&[u8]]) -> bool {
        if self.n == 0 || scripts.is_empty() {
            return false;
        }

        let hash_bytes = self.block_hash.as_bytes();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash_bytes[..16]);

        gcs_match_any(
            &key,
            self.n as u64,
            BASIC_FILTER_M,
            BASIC_FILTER_P,
            &self.filter_data,
            scripts,
        )
    }

    /// Serialize the filter as N (CompactSize) || filter_data, matching the
    /// BIP158 wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Encode N as CompactSize (varint)
        VarInt(self.n as u64).encode(&mut out).unwrap();
        out.extend_from_slice(&self.filter_data);
        out
    }

    /// Deserialize a filter from its wire format bytes, given the block hash
    /// and previous filter header.
    pub fn from_bytes(
        block_hash: BlockHash,
        prev_filter_header: &[u8; 32],
        data: &[u8],
    ) -> Option<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let n = VarInt::decode(&mut cursor).ok()?.0;
        let offset = cursor.position() as usize;
        let filter_data = data[offset..].to_vec();

        let filter_bytes = &data[..]; // full serialization for hashing
        let filter_hash = sha256d(filter_bytes);
        let filter_header = compute_filter_header(&filter_hash, prev_filter_header);

        Some(BasicFilter {
            filter_type: 0x00,
            block_hash,
            filter_data,
            n: n as u32,
            filter_header,
        })
    }
}

/// Build a BIP158 "basic" filter (type 0x00) from a block.
///
/// Per BIP158, the basic filter includes:
/// - For each transaction, each output's scriptPubKey (excluding OP_RETURN)
/// - For non-coinbase transactions, each input's previous scriptPubKey
///
/// The `prev_script_pubkeys` parameter provides the scriptPubKeys being spent
/// by each non-coinbase input. The outer Vec is indexed by transaction index
/// (skipping the coinbase at index 0), and the inner Vec is indexed by input index.
///
/// `prev_filter_header` is the filter header of the previous block (all-zeros for genesis).
pub fn build_basic_filter(
    block: &Block,
    prev_script_pubkeys: &[Vec<Vec<u8>>],
    prev_filter_header: &[u8; 32],
) -> BasicFilter {
    let block_hash = block.block_hash();
    let mut builder = GcsBuilder::new(&block_hash);

    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        // Add output scriptPubKeys (skip OP_RETURN)
        for output in &tx.outputs {
            let spk = output.script_pubkey.as_script();
            if !spk.is_empty() && !spk.is_op_return() {
                builder.add_item(spk.as_bytes());
            }
        }

        // For non-coinbase txs, add input previous scriptPubKeys
        if tx_idx > 0 && !tx.is_coinbase() {
            // prev_script_pubkeys is indexed starting from the first non-coinbase tx
            let pspk_idx = tx_idx - 1;
            if pspk_idx < prev_script_pubkeys.len() {
                for spk_bytes in &prev_script_pubkeys[pspk_idx] {
                    if !spk_bytes.is_empty() {
                        let spk = Script::from_bytes(spk_bytes);
                        if !spk.is_op_return() {
                            builder.add_item(spk_bytes);
                        }
                    }
                }
            }
        }
    }

    let n = deduplicated_count(&builder);
    let filter_data = builder.build();

    // Compute filter hash and header
    let serialized = serialize_filter(n, &filter_data);
    let filter_hash = sha256d(&serialized);
    let filter_header = compute_filter_header(&filter_hash, prev_filter_header);

    BasicFilter {
        filter_type: 0x00,
        block_hash,
        filter_data,
        n,
        filter_header,
    }
}

/// Count the number of unique items that will end up in the filter.
/// This peeks into the builder's internal items and deduplicates.
fn deduplicated_count(builder: &GcsBuilder) -> u32 {
    if builder.items.is_empty() {
        return 0;
    }
    let mut sorted = builder.items.clone();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.len() as u32
}

/// Serialize filter as CompactSize(N) || filter_data (BIP158 wire format).
fn serialize_filter(n: u32, filter_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    VarInt(n as u64).encode(&mut out).unwrap();
    out.extend_from_slice(filter_data);
    out
}

// ---------------------------------------------------------------------------
// Filter header chain
// ---------------------------------------------------------------------------

/// Compute a BIP157 filter header.
///
/// filter_header = SHA256d(filter_hash || prev_filter_header)
///
/// This creates a hash chain over filter headers, allowing SPV clients to
/// verify filter integrity by checking against a trusted header chain.
pub fn compute_filter_header(
    filter_hash: &[u8; 32],
    prev_filter_header: &[u8; 32],
) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(filter_hash);
    data[32..].copy_from_slice(prev_filter_header);
    sha256d(&data)
}

// CompactSize encoding/decoding now uses btc_primitives::encode::VarInt

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::block::{Block, BlockHeader};
    use btc_primitives::hash::{BlockHash, TxHash};
    use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::amount::Amount;
    use btc_primitives::compact::CompactTarget;

    #[test]
    fn test_golomb_encode_decode_roundtrip() {
        // Test with various values and P parameters
        for p in [1u8, 5, 10, 15, 19] {
            for &value in &[0u64, 1, 7, 42, 100, 1000, 65535, 1 << 20] {
                let mut writer = BitWriter::new();
                golomb_encode(&mut writer, value, p);
                let data = writer.finish();

                let mut reader = BitReader::new(&data);
                let decoded = golomb_decode(&mut reader, p).unwrap();
                assert_eq!(
                    value, decoded,
                    "roundtrip failed for value={} p={}",
                    value, p
                );
            }
        }
    }

    #[test]
    fn test_golomb_multiple_values_roundtrip() {
        let values = [0u64, 5, 100, 3, 0, 999, 42, 1];
        let p = 19u8;

        let mut writer = BitWriter::new();
        for &v in &values {
            golomb_encode(&mut writer, v, p);
        }
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        for &expected in &values {
            let decoded = golomb_decode(&mut reader, p).unwrap();
            assert_eq!(expected, decoded);
        }
    }

    #[test]
    fn test_bit_writer_reader_roundtrip() {
        let mut writer = BitWriter::new();
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(true);
        writer.write_bits(0b110, 3);
        writer.write_bits(0b0000_0001, 8);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bit(), Some(true));
        assert_eq!(reader.read_bit(), Some(false));
        assert_eq!(reader.read_bit(), Some(true));
        assert_eq!(reader.read_bits(3), Some(0b110));
        assert_eq!(reader.read_bits(8), Some(0b0000_0001));
    }

    #[test]
    fn test_siphash_known_vector() {
        // SipHash-2-4 test vector from the reference implementation
        // Key: 00 01 02 ... 0f, Message: 00 01 02 ... 0e
        let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let msg: Vec<u8> = (0u8..15).collect();
        let h = siphash(&key, &msg);
        // Known SipHash-2-4 result for this input
        assert_eq!(h, 0xa129ca6149be45e5);
    }

    #[test]
    fn test_gcs_construction() {
        let block_hash = BlockHash::from_bytes([0xab; 32]);
        let mut builder = GcsBuilder::new(&block_hash);

        builder.add_item(b"hello");
        builder.add_item(b"world");
        builder.add_item(b"bitcoin");

        assert_eq!(builder.len(), 3);
        let filter = builder.build();
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_gcs_match_positive_and_negative() {
        let block_hash = BlockHash::from_bytes([0xcd; 32]);
        let mut builder = GcsBuilder::new(&block_hash);

        let items: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"delta"];
        for item in &items {
            builder.add_item(item);
        }

        let n = deduplicated_count(&builder);
        let filter_data = builder.build();

        let hash_bytes = block_hash.as_bytes();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash_bytes[..16]);

        // True positive: items that were added should match
        let query: Vec<&[u8]> = vec![b"alpha"];
        assert!(gcs_match_any(
            &key,
            n as u64,
            BASIC_FILTER_M,
            BASIC_FILTER_P,
            &filter_data,
            &query,
        ));

        let query: Vec<&[u8]> = vec![b"gamma"];
        assert!(gcs_match_any(
            &key,
            n as u64,
            BASIC_FILTER_M,
            BASIC_FILTER_P,
            &filter_data,
            &query,
        ));

        // True negative: items not added should (almost certainly) not match
        let query: Vec<&[u8]> = vec![b"omega"];
        assert!(!gcs_match_any(
            &key,
            n as u64,
            BASIC_FILTER_M,
            BASIC_FILTER_P,
            &filter_data,
            &query,
        ));

        let query: Vec<&[u8]> = vec![b"zzzz_not_in_set"];
        assert!(!gcs_match_any(
            &key,
            n as u64,
            BASIC_FILTER_M,
            BASIC_FILTER_P,
            &filter_data,
            &query,
        ));
    }

    #[test]
    fn test_basic_filter_from_block() {
        // Build a minimal block with known outputs
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::p2pkh(&[0x11; 20]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let spending_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(4_000_000_000),
                script_pubkey: ScriptBuf::p2pkh(&[0x22; 20]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0; 32]),
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 0,
            },
            transactions: vec![coinbase_tx, spending_tx],
        };

        // Previous scriptPubKeys for the spending tx's inputs
        let prev_spks = vec![vec![
            ScriptBuf::p2pkh(&[0x33; 20]).as_bytes().to_vec(),
        ]];

        let prev_header = [0u8; 32];
        let filter = build_basic_filter(&block, &prev_spks, &prev_header);

        assert_eq!(filter.filter_type, 0x00);
        assert!(filter.n > 0);
        assert!(!filter.filter_data.is_empty());
        assert_ne!(filter.filter_header, [0u8; 32]);

        // The filter should match the outputs in the block
        let p2pkh_11 = ScriptBuf::p2pkh(&[0x11; 20]);
        let p2pkh_22 = ScriptBuf::p2pkh(&[0x22; 20]);
        let p2pkh_33 = ScriptBuf::p2pkh(&[0x33; 20]);
        assert!(filter.match_any(&[p2pkh_11.as_bytes()]));
        assert!(filter.match_any(&[p2pkh_22.as_bytes()]));
        assert!(filter.match_any(&[p2pkh_33.as_bytes()]));

        // Should not match a script that is not in the block
        let p2pkh_99 = ScriptBuf::p2pkh(&[0x99; 20]);
        assert!(!filter.match_any(&[p2pkh_99.as_bytes()]));
    }

    #[test]
    fn test_filter_header_chain() {
        // Simulate a chain of filter headers
        let genesis_filter_hash = sha256d(b"genesis filter");
        let zero_header = [0u8; 32];

        let header_0 = compute_filter_header(&genesis_filter_hash, &zero_header);
        assert_ne!(header_0, zero_header);

        let block1_filter_hash = sha256d(b"block 1 filter");
        let header_1 = compute_filter_header(&block1_filter_hash, &header_0);
        assert_ne!(header_1, header_0);

        let block2_filter_hash = sha256d(b"block 2 filter");
        let header_2 = compute_filter_header(&block2_filter_hash, &header_1);
        assert_ne!(header_2, header_1);

        // Headers should be deterministic
        let header_2_again = compute_filter_header(&block2_filter_hash, &header_1);
        assert_eq!(header_2, header_2_again);

        // Different prev header should give different result
        let header_2_alt = compute_filter_header(&block2_filter_hash, &header_0);
        assert_ne!(header_2, header_2_alt);
    }

    #[test]
    fn test_empty_filter() {
        // A block with only a coinbase and an OP_RETURN output should produce
        // an empty (or near-empty) filter
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0; 32]),
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        let prev_header = [0u8; 32];
        let filter = build_basic_filter(&block, &[], &prev_header);

        // OP_RETURN is excluded, so the filter should have 0 elements
        assert_eq!(filter.n, 0);
        assert!(filter.filter_data.is_empty());
    }

    #[test]
    fn test_filter_skips_op_return() {
        let coinbase_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04]),
                sequence: 0xffffffff,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(5_000_000_000),
                    script_pubkey: ScriptBuf::p2pkh(&[0x11; 20]),
                },
                TxOut {
                    value: Amount::from_sat(0),
                    // OP_RETURN output
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad]),
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::from_bytes([0; 32]),
                time: 1231006505,
                bits: CompactTarget::from_u32(0x1d00ffff),
                nonce: 0,
            },
            transactions: vec![coinbase_tx],
        };

        let prev_header = [0u8; 32];
        let filter = build_basic_filter(&block, &[], &prev_header);

        // Only the P2PKH output should be in the filter, not the OP_RETURN
        assert_eq!(filter.n, 1);
        let p2pkh = ScriptBuf::p2pkh(&[0x11; 20]);
        assert!(filter.match_any(&[p2pkh.as_bytes()]));
    }

    #[test]
    fn test_compact_size_roundtrip() {
        for &n in &[0u64, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000] {
            let mut buf = Vec::new();
            VarInt(n).encode(&mut buf).unwrap();
            let decoded = VarInt::decode(&mut std::io::Cursor::new(&buf)).unwrap().0;
            assert_eq!(n, decoded, "compact size roundtrip failed for {}", n);
        }
    }

    #[test]
    fn test_fast_range() {
        // fast_range should map values into [0, range)
        assert_eq!(fast_range(0, 100), 0);
        assert_eq!(fast_range(u64::MAX, 100), 99);
        // Midpoint should be roughly range/2
        let mid = fast_range(u64::MAX / 2, 1000);
        assert!(mid >= 450 && mid <= 550, "midpoint was {}", mid);
    }

    // -----------------------------------------------------------------------
    // BIP158 test vectors from testdata/blockfilters.json
    // -----------------------------------------------------------------------

    #[test]
    fn test_bip158_vectors() {
        let test_data = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/blockfilters.json")
        )
        .expect("failed to read blockfilters.json");

        let parsed: serde_json::Value =
            serde_json::from_str(&test_data).expect("failed to parse JSON");
        let arr = parsed.as_array().expect("expected JSON array");

        // Skip the header row (index 0)
        for (test_idx, entry) in arr.iter().enumerate().skip(1) {
            let row = entry.as_array().expect("expected row array");
            let _block_height = row[0].as_u64().expect("block height");
            let block_hash_hex = row[1].as_str().expect("block hash");
            let block_hex = row[2].as_str().expect("block hex");
            let prev_scripts_arr = row[3].as_array().expect("prev scripts array");
            let prev_header_hex = row[4].as_str().expect("prev header");
            let expected_filter_hex = row[5].as_str().expect("expected filter");
            let expected_header_hex = row[6].as_str().expect("expected header");

            // Decode the block
            let block_bytes = hex::decode(block_hex).unwrap();
            let block: Block =
                btc_primitives::encode::decode(&block_bytes).expect("failed to decode block");

            // Verify block hash matches
            let block_hash = block.block_hash();
            assert_eq!(
                block_hash.to_hex(),
                block_hash_hex,
                "block hash mismatch at test {}",
                test_idx
            );

            // Decode previous scriptPubKeys
            // These are provided as a flat list corresponding to all non-coinbase inputs
            // across all non-coinbase transactions, in order.
            let prev_spk_flat: Vec<Vec<u8>> = prev_scripts_arr
                .iter()
                .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
                .collect();

            // Map the flat list to per-transaction groups
            let mut prev_spks: Vec<Vec<Vec<u8>>> = Vec::new();
            let mut flat_idx = 0;
            for tx in block.transactions.iter().skip(1) {
                let mut tx_spks = Vec::new();
                for _ in &tx.inputs {
                    if flat_idx < prev_spk_flat.len() {
                        tx_spks.push(prev_spk_flat[flat_idx].clone());
                        flat_idx += 1;
                    }
                }
                prev_spks.push(tx_spks);
            }

            // Decode previous filter header (hex is in display/reversed byte order)
            let mut prev_header = [0u8; 32];
            hex::decode_to_slice(prev_header_hex, &mut prev_header).unwrap();
            prev_header.reverse();

            // Build the filter
            let filter = build_basic_filter(&block, &prev_spks, &prev_header);

            // Compare filter data (encoded as CompactSize(N) || data)
            let filter_serialized = filter.to_bytes();
            assert_eq!(
                hex::encode(&filter_serialized),
                expected_filter_hex,
                "filter mismatch at test {} (block {})",
                test_idx,
                block_hash_hex,
            );

            // Compare filter header (hex is in display/reversed byte order)
            let mut expected_header = [0u8; 32];
            hex::decode_to_slice(expected_header_hex, &mut expected_header).unwrap();
            expected_header.reverse();

            assert_eq!(
                filter.filter_header, expected_header,
                "filter header mismatch at test {} (block {})",
                test_idx, block_hash_hex,
            );
        }
    }

    #[test]
    fn test_filter_matching_with_real_scripts() {
        // Build a block with real P2PKH and P2WPKH scripts, construct a filter,
        // and verify match_any returns true for scripts in the block and false for
        // scripts not in the block.
        let pkh_a = [0xaa; 20];
        let pkh_b = [0xbb; 20];
        let pkh_c = [0xcc; 20]; // not in block

        let spk_a = ScriptBuf::p2pkh(&pkh_a);
        let spk_b = ScriptBuf::p2wpkh(&pkh_b);
        let spk_c = ScriptBuf::p2pkh(&pkh_c);

        // Build a simple block with a coinbase and one user tx.
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x01]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: spk_a.clone(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let user_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0x11; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x01]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: spk_b.clone(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let txids: Vec<[u8; 32]> = [&coinbase, &user_tx]
            .iter()
            .map(|tx| tx.txid().to_bytes())
            .collect();
        let merkle_root = TxHash::from_bytes(btc_primitives::block::merkle_root(&txids));

        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root,
                time: 1700000000,
                bits: CompactTarget::MAX_TARGET,
                nonce: 0,
            },
            transactions: vec![coinbase, user_tx],
        };

        // For the non-coinbase tx, provide its input's prev scriptPubKey.
        let prev_spks = vec![vec![vec![0x76; 25]]]; // dummy prev script

        let prev_filter_header = [0u8; 32];
        let filter = build_basic_filter(&block, &prev_spks, &prev_filter_header);
        assert!(filter.n > 0, "filter should have elements");

        // match_any should return true for scripts that are in the block.
        assert!(
            filter.match_any(&[spk_a.as_bytes()]),
            "filter should match P2PKH script A (in block)"
        );
        assert!(
            filter.match_any(&[spk_b.as_bytes()]),
            "filter should match P2WPKH script B (in block)"
        );

        // match_any should return false for scripts not in the block
        // (subject to false-positive rate, but with only a few items the
        // probability is negligible).
        assert!(
            !filter.match_any(&[spk_c.as_bytes()]),
            "filter should not match script C (not in block)"
        );

        // Verify match_any with multiple query items.
        assert!(
            filter.match_any(&[spk_a.as_bytes(), spk_c.as_bytes()]),
            "should match when at least one script is in the block"
        );
    }
}
