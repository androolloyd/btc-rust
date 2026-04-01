use crate::encode::{Encodable, Decodable, EncodeError, VarInt, ReadExt, WriteExt};
use crate::hash::TxHash;
use crate::script::ScriptBuf;
use crate::amount::Amount;
use std::io::{Read, Write};

/// A reference to a specific output of a previous transaction, identified by txid and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: TxHash,
    pub vout: u32,
}

impl OutPoint {
    /// Coinbase outpoint — null hash with max index
    pub const COINBASE: OutPoint = OutPoint {
        txid: TxHash::ZERO,
        vout: 0xffffffff,
    };

    pub fn new(txid: TxHash, vout: u32) -> Self {
        OutPoint { txid, vout }
    }

    pub fn is_coinbase(&self) -> bool {
        self.txid == TxHash::ZERO && self.vout == 0xffffffff
    }
}

impl Encodable for OutPoint {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        writer.write_all(self.txid.as_bytes())?;
        writer.write_u32_le(self.vout)?;
        Ok(36)
    }
}

impl Decodable for OutPoint {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let hash = reader.read_hash256()?;
        let vout = reader.read_u32_le()?;
        Ok(OutPoint {
            txid: TxHash::from_bytes(hash),
            vout,
        })
    }
}

/// A transaction input that spends a previous output, with a script signature and sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: ScriptBuf,
    pub sequence: u32,
}

impl TxIn {
    pub const SEQUENCE_FINAL: u32 = 0xffffffff;

    pub fn is_coinbase(&self) -> bool {
        self.previous_output.is_coinbase()
    }
}

impl Encodable for TxIn {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = self.previous_output.encode(writer)?;
        written += self.script_sig.encode(writer)?;
        written += writer.write_u32_le(self.sequence)?;
        Ok(written)
    }
}

impl Decodable for TxIn {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let previous_output = OutPoint::decode(reader)?;
        let script_sig = ScriptBuf::decode(reader)?;
        let sequence = reader.read_u32_le()?;
        Ok(TxIn {
            previous_output,
            script_sig,
            sequence,
        })
    }
}

/// A transaction output specifying an amount and the spending conditions (script).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
}

impl Encodable for TxOut {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = writer.write_i64_le(self.value.as_sat())?;
        written += self.script_pubkey.encode(writer)?;
        Ok(written)
    }
}

impl Decodable for TxOut {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let value = Amount::from_sat(reader.read_i64_le()?);
        // Validate non-negative and within MAX_MONEY
        if value.as_sat() < 0 || !value.is_valid() {
            return Err(EncodeError::InvalidData("invalid output value".into()));
        }
        let script_pubkey = ScriptBuf::decode(reader)?;
        Ok(TxOut { value, script_pubkey })
    }
}

/// Segregated Witness stack items associated with a transaction input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Witness {
    items: Vec<Vec<u8>>,
}

impl Witness {
    pub fn new() -> Self {
        Witness { items: Vec::new() }
    }

    pub fn from_items(items: Vec<Vec<u8>>) -> Self {
        Witness { items }
    }

    pub fn push(&mut self, item: Vec<u8>) {
        self.items.push(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Vec<u8>> {
        self.items.iter()
    }

    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.items.get(index).map(|v| v.as_slice())
    }

    fn encode_items<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = VarInt(self.items.len() as u64).encode(writer)?;
        for item in &self.items {
            let vi = VarInt(item.len() as u64);
            written += vi.encode(writer)?;
            writer.write_all(item)?;
            written += item.len();
        }
        Ok(written)
    }

    fn decode_items<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let count = VarInt::decode(reader)?.0 as usize;
        if count > 100_000 {
            return Err(EncodeError::InvalidData("too many witness items".into()));
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let len = VarInt::decode(reader)?.0 as usize;
            if len > 4_000_000 {
                return Err(EncodeError::InvalidData("witness item too large".into()));
            }
            let data = reader.read_bytes(len)?;
            items.push(data);
        }
        Ok(Witness { items })
    }
}

/// A Bitcoin transaction consisting of inputs, outputs, and optional witness data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub witness: Vec<Witness>,
    pub lock_time: u32,
}

impl Transaction {
    /// Check if this transaction uses segwit
    pub fn is_segwit(&self) -> bool {
        !self.witness.is_empty() && self.witness.iter().any(|w| !w.is_empty())
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase()
    }

    /// Compute the txid (hash of non-witness serialization)
    pub fn txid(&self) -> TxHash {
        let mut buf = Vec::new();
        self.encode_legacy(&mut buf).expect("encoding to vec should not fail");
        TxHash::compute(&buf)
    }

    /// Compute the wtxid (hash of witness serialization)
    pub fn wtxid(&self) -> TxHash {
        if !self.is_segwit() {
            return self.txid();
        }
        let mut buf = Vec::new();
        self.encode_segwit(&mut buf).expect("encoding to vec should not fail");
        TxHash::compute(&buf)
    }

    /// Compute the base (non-witness) serialized size in bytes.
    pub fn base_size(&self) -> usize {
        let mut counter = crate::encode::CountWriter(0);
        self.encode_legacy(&mut counter).expect("counting should not fail");
        counter.0
    }

    /// Compute the total (witness-inclusive) serialized size in bytes.
    pub fn total_size(&self) -> usize {
        let mut counter = crate::encode::CountWriter(0);
        if self.is_segwit() {
            self.encode_segwit(&mut counter).expect("counting should not fail");
        } else {
            self.encode_legacy(&mut counter).expect("counting should not fail");
        }
        counter.0
    }

    /// Compute the BIP141 weight of this transaction.
    /// weight = base_size * 3 + total_size
    pub fn weight(&self) -> usize {
        self.base_size() * 3 + self.total_size()
    }

    /// Encode in legacy (non-witness) format
    fn encode_legacy<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = writer.write_i32_le(self.version)?;
        written += VarInt(self.inputs.len() as u64).encode(writer)?;
        for input in &self.inputs {
            written += input.encode(writer)?;
        }
        written += VarInt(self.outputs.len() as u64).encode(writer)?;
        for output in &self.outputs {
            written += output.encode(writer)?;
        }
        written += writer.write_u32_le(self.lock_time)?;
        Ok(written)
    }

    /// Encode in segwit (witness) format
    fn encode_segwit<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = writer.write_i32_le(self.version)?;
        // Segwit marker and flag
        writer.write_all(&[0x00, 0x01])?;
        written += 2;
        written += VarInt(self.inputs.len() as u64).encode(writer)?;
        for input in &self.inputs {
            written += input.encode(writer)?;
        }
        written += VarInt(self.outputs.len() as u64).encode(writer)?;
        for output in &self.outputs {
            written += output.encode(writer)?;
        }
        // Witness data
        for i in 0..self.inputs.len() {
            let witness = self.witness.get(i).cloned().unwrap_or_default();
            written += witness.encode_items(writer)?;
        }
        written += writer.write_u32_le(self.lock_time)?;
        Ok(written)
    }
}

impl Encodable for Transaction {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        if self.is_segwit() {
            self.encode_segwit(writer)
        } else {
            self.encode_legacy(writer)
        }
    }
}

impl Decodable for Transaction {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let version = reader.read_i32_le()?;

        // Read first varint — could be input count or segwit marker
        let marker = VarInt::decode(reader)?.0;

        if marker == 0 {
            // Segwit format: marker=0, flag=1
            let flag = reader.read_u8()?;
            if flag != 1 {
                return Err(EncodeError::InvalidData(format!("invalid segwit flag: {}", flag)));
            }

            let input_count = VarInt::decode(reader)?.0 as usize;
            if input_count > 100_000 {
                return Err(EncodeError::InvalidData("too many inputs".into()));
            }
            let mut inputs = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                inputs.push(TxIn::decode(reader)?);
            }

            let output_count = VarInt::decode(reader)?.0 as usize;
            if output_count > 100_000 {
                return Err(EncodeError::InvalidData("too many outputs".into()));
            }
            let mut outputs = Vec::with_capacity(output_count);
            for _ in 0..output_count {
                outputs.push(TxOut::decode(reader)?);
            }

            let mut witness = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                witness.push(Witness::decode_items(reader)?);
            }

            let lock_time = reader.read_u32_le()?;

            Ok(Transaction { version, inputs, outputs, witness, lock_time })
        } else {
            // Legacy format: marker was actually the input count
            let input_count = marker as usize;
            if input_count > 100_000 {
                return Err(EncodeError::InvalidData("too many inputs".into()));
            }
            let mut inputs = Vec::with_capacity(input_count);
            for _ in 0..input_count {
                inputs.push(TxIn::decode(reader)?);
            }

            let output_count = VarInt::decode(reader)?.0 as usize;
            if output_count > 100_000 {
                return Err(EncodeError::InvalidData("too many outputs".into()));
            }
            let mut outputs = Vec::with_capacity(output_count);
            for _ in 0..output_count {
                outputs.push(TxOut::decode(reader)?);
            }

            let lock_time = reader.read_u32_le()?;

            Ok(Transaction {
                version,
                inputs,
                outputs,
                witness: Vec::new(),
                lock_time,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode;

    #[test]
    fn test_coinbase_outpoint() {
        assert!(OutPoint::COINBASE.is_coinbase());
        assert!(!OutPoint::new(TxHash::ZERO, 0).is_coinbase());
    }

    #[test]
    fn test_outpoint_roundtrip() {
        let outpoint = OutPoint::new(TxHash::from_bytes([0xab; 32]), 42);
        let encoded = encode::encode(&outpoint);
        assert_eq!(encoded.len(), 36);
        let decoded: OutPoint = encode::decode(&encoded).unwrap();
        assert_eq!(decoded, outpoint);
    }

    #[test]
    fn test_genesis_coinbase_tx() {
        // Bitcoin genesis block coinbase transaction (raw hex)
        let raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043\
             68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f7574\
             20666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967\
             f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec1\
             12de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
        ).unwrap();

        let tx: Transaction = encode::decode(&raw).unwrap();
        assert!(tx.is_coinbase());
        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value.as_sat(), 5_000_000_000); // 50 BTC
        assert_eq!(tx.lock_time, 0);

        // Verify txid
        assert_eq!(
            tx.txid().to_hex(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn test_legacy_tx_roundtrip() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let encoded = encode::encode(&tx);
        let decoded: Transaction = encode::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_negative_txout_value_rejected() {
        // Build a raw TxOut with a negative value
        let mut buf = Vec::new();
        // value: -1 as i64 LE
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        // script_pubkey: empty (varint 0)
        buf.push(0x00);
        let result = encode::decode::<TxOut>(&buf);
        assert!(result.is_err(), "Negative TxOut value should be rejected");
    }

    #[test]
    fn test_txout_value_exceeding_max_money_rejected() {
        // Build a raw TxOut with value exceeding MAX_MONEY
        let excessive = Amount::MAX_MONEY.as_sat() + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&excessive.to_le_bytes());
        buf.push(0x00); // empty script_pubkey
        let result = encode::decode::<TxOut>(&buf);
        assert!(result.is_err(), "TxOut value exceeding MAX_MONEY should be rejected");
    }

    #[test]
    fn test_valid_txout_value_accepted() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(50_000i64).to_le_bytes());
        buf.push(0x00);
        let result = encode::decode::<TxOut>(&buf);
        assert!(result.is_ok(), "Valid TxOut value should be accepted");
        assert_eq!(result.unwrap().value.as_sat(), 50_000);
    }

    #[test]
    fn test_segwit_tx_decode() {
        // A simple segwit transaction (from Bitcoin test vectors)
        // version(4) + marker(1) + flag(1) + vin_count + vin + vout_count + vout + witness + locktime
        let raw = hex::decode(
            "02000000000101000000000000000000000000000000000000000000000000000000000000\
             0000ffffffff03510101ffffffff0200f2052a01000000160014751e76e8199196d454941c\
             45d1b3a323f1433bd60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa3\
             6953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000\
             00000000000000000000000000000000000000000"
        ).unwrap();

        let tx: Transaction = encode::decode(&raw).unwrap();
        assert_eq!(tx.version, 2);
        assert!(tx.is_segwit());
        assert!(tx.is_coinbase());
        assert_eq!(tx.witness.len(), 1);
    }

    #[test]
    fn test_legacy_tx_weight_is_4x_size() {
        // For a legacy (non-witness) transaction, base_size == total_size,
        // so weight = base_size * 3 + total_size = base_size * 4.
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };

        let encoded_len = encode::encode(&tx).len();
        assert_eq!(tx.base_size(), encoded_len);
        assert_eq!(tx.total_size(), encoded_len);
        assert_eq!(tx.weight(), encoded_len * 4);
    }

    #[test]
    fn test_segwit_tx_weight() {
        // Decode a real segwit transaction and verify weight = base * 3 + total.
        let raw = hex::decode(
            "02000000000101000000000000000000000000000000000000000000000000000000000000\
             0000ffffffff03510101ffffffff0200f2052a01000000160014751e76e8199196d454941c\
             45d1b3a323f1433bd60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa3\
             6953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000\
             00000000000000000000000000000000000000000"
        ).unwrap();
        let tx: Transaction = encode::decode(&raw).unwrap();

        let base = tx.base_size();
        let total = tx.total_size();

        // total_size includes marker(1) + flag(1) + witness data, so total > base
        assert!(total > base, "segwit total_size ({}) should exceed base_size ({})", total, base);

        // weight = base_size * 3 + total_size
        assert_eq!(tx.weight(), base * 3 + total);

        // For a segwit tx, weight should be less than total_size * 4
        // (witness data is discounted)
        assert!(tx.weight() < total * 4);
    }

    #[test]
    fn test_witness_basic_operations() {
        let mut w = Witness::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        assert!(w.get(0).is_none());

        w.push(vec![0x01, 0x02]);
        w.push(vec![0x03]);
        assert!(!w.is_empty());
        assert_eq!(w.len(), 2);
        assert_eq!(w.get(0), Some(&[0x01, 0x02][..]));
        assert_eq!(w.get(1), Some(&[0x03][..]));
        assert!(w.get(2).is_none());

        let items: Vec<_> = w.iter().collect();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_witness_from_items() {
        let items = vec![vec![0x01], vec![0x02, 0x03]];
        let w = Witness::from_items(items.clone());
        assert_eq!(w.len(), 2);
        assert_eq!(w.get(0), Some(&[0x01][..]));
    }

    #[test]
    fn test_witness_default() {
        let w = Witness::default();
        assert!(w.is_empty());
    }

    #[test]
    fn test_outpoint_new_and_is_coinbase() {
        let op = OutPoint::new(TxHash::ZERO, 0xffffffff);
        assert!(op.is_coinbase());

        let op2 = OutPoint::new(TxHash::from_bytes([0x01; 32]), 0);
        assert!(!op2.is_coinbase());
    }

    #[test]
    fn test_txin_is_coinbase() {
        let coinbase_in = TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
        };
        assert!(coinbase_in.is_coinbase());

        let normal_in = TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([0x01; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
        };
        assert!(!normal_in.is_coinbase());
    }

    #[test]
    fn test_is_segwit_with_empty_witness_items() {
        // witness vec is non-empty but all items are empty
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
            witness: vec![Witness::new()], // non-empty vec, but witness is empty
            lock_time: 0,
        };
        assert!(!tx.is_segwit()); // should not be segwit since all witnesses are empty
    }

    #[test]
    fn test_wtxid_for_legacy_tx() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0xff]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        // For legacy tx, wtxid == txid
        assert_eq!(tx.wtxid(), tx.txid());
    }

    #[test]
    fn test_weight_matches_manual_calculation() {
        // Construct a segwit tx with known witness data and verify sizes manually.
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0x01, 0x02, 0x03]),
            }],
            witness: vec![Witness::from_items(vec![
                vec![0x30; 72], // mock signature
                vec![0x02; 33], // mock pubkey
            ])],
            lock_time: 0,
        };

        assert!(tx.is_segwit());

        // base_size: version(4) + varint_inputs(1) + outpoint(36) + script_sig_len(1) +
        //            sequence(4) + varint_outputs(1) + value(8) + script_len(1) +
        //            script(5) + locktime(4) = 65
        let base = tx.base_size();
        assert_eq!(base, 65);

        // total_size: version(4) + marker(1) + flag(1) + varint_inputs(1) +
        //             outpoint(36) + script_sig_len(1) + sequence(4) +
        //             varint_outputs(1) + value(8) + script_len(1) + script(5) +
        //             witness: item_count(1) + sig_len(1) + sig(72) + pk_len(1) + pk(33) +
        //             locktime(4) = 175
        let total = tx.total_size();
        assert_eq!(total, 175);

        // weight = 65 * 3 + 175 = 370
        assert_eq!(tx.weight(), 370);
    }
}
