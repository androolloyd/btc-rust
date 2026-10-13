//! Local durable canonical-chain delivery. This is not a Bitcoin wire format.
use crate::traits::{DbTx, StorageError};
use btc_consensus::utxo::UtxoSetUpdate;
#[cfg(feature = "redb")]
use btc_primitives::hash::sha256;
use btc_primitives::{Block, BlockHash};

pub const MAX_EXTENSION_STATE_BYTES: usize = 1024 * 1024;
pub fn bad(message: &str) -> StorageError {
    StorageError::Corruption(message.into())
}
pub fn validate_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(StorageError::Database("invalid extension name".into()));
    }
    Ok(())
}
#[cfg(feature = "redb")]
fn checked<'a>(bytes: &'a [u8], magic: &[u8; 4], length: usize) -> Result<&'a [u8], StorageError> {
    if bytes.len() != length
        || &bytes[..4] != magic
        || sha256(&bytes[..length - 32]) != bytes[length - 32..]
    {
        return Err(bad("invalid ExEx record checksum/format"));
    }
    Ok(&bytes[..length - 32])
}
#[cfg(feature = "redb")]
fn number(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}
#[cfg(feature = "redb")]
fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.extend_from_slice(&sha256(&bytes));
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalTip {
    pub sequence: u64,
    pub height: u64,
    pub hash: BlockHash,
    pub genesis: BlockHash,
    pub bootstrap_height: u64,
}
impl JournalTip {
    pub fn initial(genesis: BlockHash) -> Self {
        Self {
            sequence: 0,
            height: 0,
            hash: genesis,
            genesis,
            bootstrap_height: 0,
        }
    }
    #[cfg(feature = "redb")]
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut b = b"EXJ1".to_vec();
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.extend_from_slice(&self.height.to_be_bytes());
        b.extend_from_slice(self.hash.as_bytes());
        b.extend_from_slice(self.genesis.as_bytes());
        b.extend_from_slice(&self.bootstrap_height.to_be_bytes());
        finish(b)
    }
    #[cfg(feature = "redb")]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let b = checked(bytes, b"EXJ1", 124)?;
        Ok(Self {
            sequence: number(&b[4..12]),
            height: number(&b[12..20]),
            hash: BlockHash::from_slice(&b[20..52]),
            genesis: BlockHash::from_slice(&b[52..84]),
            bootstrap_height: number(&b[84..92]),
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalEntry {
    pub sequence: u64,
    pub connected: bool,
    pub height: u64,
    pub hash: BlockHash,
    pub parent: BlockHash,
}
impl JournalEntry {
    pub fn before(self) -> (u64, BlockHash) {
        if self.connected {
            (self.height - 1, self.parent)
        } else {
            (self.height, self.hash)
        }
    }
    pub fn after(self) -> (u64, BlockHash) {
        if self.connected {
            (self.height, self.hash)
        } else {
            (self.height - 1, self.parent)
        }
    }
    #[cfg(feature = "redb")]
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut b = b"EXE1".to_vec();
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.push(self.connected as u8);
        b.extend_from_slice(&self.height.to_be_bytes());
        b.extend_from_slice(self.hash.as_bytes());
        b.extend_from_slice(self.parent.as_bytes());
        finish(b)
    }
    #[cfg(feature = "redb")]
    pub(crate) fn decode(bytes: &[u8], sequence: u64) -> Result<Self, StorageError> {
        let b = checked(bytes, b"EXE1", 117)?;
        if number(&b[4..12]) != sequence || sequence == 0 || b[12] > 1 || number(&b[13..21]) == 0 {
            return Err(bad("invalid ExEx sequence/kind/height"));
        }
        Ok(Self {
            sequence,
            connected: b[12] == 1,
            height: number(&b[13..21]),
            hash: BlockHash::from_slice(&b[21..53]),
            parent: BlockHash::from_slice(&b[53..85]),
        })
    }
    pub fn resolve(self, reader: &impl DbTx) -> Result<JournalEvent, StorageError> {
        if self.sequence == 0 || self.height == 0 {
            return Err(bad("invalid ExEx event"));
        }
        let block = reader
            .get_block(&self.hash)?
            .ok_or_else(|| bad("missing ExEx actual body"))?;
        if block.block_hash() != self.hash
            || block.header.prev_blockhash != self.parent
            || !block.check_merkle_root()
        {
            return Err(bad("ExEx actual body/ancestry mismatch"));
        }
        btc_consensus::validation::BlockValidator::validate_block(&block)
            .map_err(|e| bad(&format!("invalid ExEx actual body: {e}")))?;
        let raw = reader
            .get_block_undo(&self.hash)?
            .ok_or_else(|| bad("missing ExEx actual undo"))?;
        let undo = crate::undo::decode_undo(self.hash, &raw)?;
        Ok(JournalEvent {
            entry: self,
            block,
            undo,
        })
    }
}
#[derive(Debug)]
pub struct JournalEvent {
    pub entry: JournalEntry,
    pub block: Block,
    pub undo: UtxoSetUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionState {
    pub cursor: JournalTip,
    pub state: Vec<u8>,
}
impl ExtensionState {
    #[cfg(feature = "redb")]
    pub(crate) fn encode(&self, name: &str) -> Result<Vec<u8>, StorageError> {
        validate_name(name)?;
        if self.state.len() > MAX_EXTENSION_STATE_BYTES {
            return Err(StorageError::Database(
                "extension state exceeds bound".into(),
            ));
        }
        let mut b = b"EXS1".to_vec();
        b.extend_from_slice(&self.cursor.encode());
        b.extend_from_slice(&sha256(name.as_bytes()));
        b.extend_from_slice(&(self.state.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.state);
        Ok(finish(b))
    }
    #[cfg(feature = "redb")]
    pub(crate) fn decode(name: &str, bytes: &[u8]) -> Result<Self, StorageError> {
        validate_name(name)?;
        if bytes.len() < 196
            || bytes.len() > 196 + MAX_EXTENSION_STATE_BYTES
            || &bytes[..4] != b"EXS1"
        {
            return Err(bad("invalid extension state length/format"));
        }
        if sha256(&bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
            || sha256(name.as_bytes()) != bytes[128..160]
        {
            return Err(bad("invalid extension state checksum/name"));
        }
        let length = u32::from_be_bytes(bytes[160..164].try_into().unwrap()) as usize;
        if length != bytes.len() - 196 {
            return Err(bad("invalid extension state payload length"));
        }
        Ok(Self {
            cursor: JournalTip::decode(&bytes[4..128])?,
            state: bytes[164..164 + length].to_vec(),
        })
    }
}
