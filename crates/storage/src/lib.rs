pub mod traits;
pub mod provider;
pub mod tables;
pub mod pruning;
pub mod utxo_store;

#[cfg(feature = "redb")]
pub mod redb_backend;

#[cfg(feature = "qmdb")]
pub mod qmdb_backend;

#[cfg(feature = "leveldb")]
pub mod leveldb_backend;

#[cfg(feature = "snapshot")]
pub mod snapshot;

pub use traits::{Database, DbTx, DbTxMut, TxBlockLocation, AddressIndexValue};
pub use provider::BlockchainProvider;
pub use utxo_store::PersistentUtxoSet;

#[cfg(feature = "redb")]
pub use redb_backend::RedbDatabase;

#[cfg(feature = "qmdb")]
pub use qmdb_backend::QmdbDatabase;

#[cfg(feature = "snapshot")]
pub use snapshot::{UtxoSnapshotEntry, load_utxo_snapshot, SnapshotError};
