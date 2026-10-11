pub mod provider;
pub mod pruning;
pub mod tables;
pub mod traits;
pub mod utxo_store;

#[cfg(feature = "redb")]
pub mod redb_backend;

#[cfg(feature = "qmdb")]
pub mod qmdb_backend;

#[cfg(feature = "leveldb")]
pub mod leveldb_backend;

#[cfg(feature = "snapshot")]
pub mod snapshot;

pub use provider::BlockchainProvider;
pub use traits::{AddressIndexValue, Database, DbTx, DbTxMut, TxBlockLocation};
pub use utxo_store::PersistentUtxoSet;

#[cfg(feature = "redb")]
pub use redb_backend::RedbDatabase;

#[cfg(feature = "qmdb")]
pub use qmdb_backend::QmdbDatabase;

#[cfg(feature = "snapshot")]
pub use snapshot::{load_utxo_snapshot, SnapshotError, UtxoSnapshotEntry};
