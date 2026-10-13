//! Supervised consumers of the actual durable journal. State and cursor commit together.
use btc_storage::exex::{bad, ExtensionState, JournalEvent, JournalTip};
use btc_storage::traits::{Database, DbTx, DbTxMut, StorageError};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// A deterministic state transition. Effects belong in the returned state, not
/// external side effects: retries may repeat computation before an atomic commit.
pub trait DurableExtension: Send + Sync + 'static {
    fn name(&self) -> &str;
    /// Check persisted application state even when no new event is pending.
    fn validate_state(&self, previous: Option<&[u8]>) -> Result<(), StorageError>;
    fn apply(&self, event: &JournalEvent, previous: Option<&[u8]>)
        -> Result<Vec<u8>, StorageError>;
}
pub trait DurableStore: Send + Sync + 'static {
    fn step(&self, extension: &dyn DurableExtension) -> Result<bool, StorageError>;
}
pub struct DatabaseStore<D: Database> {
    db: Arc<D>,
}
impl<D: Database> DatabaseStore<D> {
    pub fn new(db: Arc<D>) -> Self {
        Self { db }
    }
}
impl<D: Database> DurableStore for DatabaseStore<D> {
    fn step(&self, extension: &dyn DurableExtension) -> Result<bool, StorageError> {
        let name = extension.name();
        btc_storage::exex::validate_name(name)?;
        let reader = self.db.tx()?;
        let tip = reader
            .exex_journal_tip()?
            .ok_or_else(|| bad("durable ExEx journal unavailable"))?;
        let state = reader.exex_state(name)?;
        let cursor = state
            .as_ref()
            .map(|s| s.cursor)
            .unwrap_or(JournalTip::initial(tip.genesis));
        if cursor.genesis != tip.genesis || cursor.sequence > tip.sequence {
            return Err(bad("extension cursor outside actual journal"));
        }
        extension.validate_state(state.as_ref().map(|s| s.state.as_slice()))?;
        if cursor.sequence == tip.sequence {
            if cursor != tip {
                return Err(bad("extension cursor/tip mismatch"));
            }
            return Ok(false);
        }
        let next = cursor
            .sequence
            .checked_add(1)
            .ok_or_else(|| bad("extension cursor overflow"))?;
        let entry = reader
            .exex_journal_entry(next)?
            .ok_or_else(|| bad("durable extension event missing"))?;
        if entry.before() != (cursor.height, cursor.hash) {
            return Err(bad("extension event ancestry mismatch"));
        }
        let event = entry.resolve(&reader)?;
        drop(reader);
        // Callback work holds no database writer or chain lock.
        let value = extension.apply(&event, state.as_ref().map(|s| s.state.as_slice()))?;
        extension.validate_state(Some(&value))?;
        let write = self.db.tx_mut()?;
        if write.exex_state(name)? != state {
            return Err(bad("concurrent consumer changed this checkpoint"));
        }
        let (height, hash) = entry.after();
        write.set_exex_state(
            name,
            &ExtensionState {
                cursor: JournalTip {
                    sequence: next,
                    height,
                    hash,
                    ..tip
                },
                state: value,
            },
        )?;
        write.commit()?;
        Ok(true)
    }
}

#[derive(Debug, Clone, Default)]
pub struct WorkerStatus {
    pub status: String,
    pub failures: u32,
    pub last_error: Option<String>,
}
pub type Registry = Arc<Mutex<BTreeMap<String, WorkerStatus>>>;
pub struct DurableManager<S: DurableStore> {
    store: Arc<S>,
    wakeup: watch::Receiver<u64>,
    shutdown: watch::Sender<bool>,
    failed: watch::Receiver<Option<String>>,
    failure_sender: watch::Sender<Option<String>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    registry: Registry,
}
impl<S: DurableStore> DurableManager<S> {
    pub fn new(store: Arc<S>, wakeup: watch::Receiver<u64>) -> Self {
        let (shutdown, _) = watch::channel(false);
        let (failure_sender, failed) = watch::channel(None);
        Self {
            store,
            wakeup,
            shutdown,
            failed,
            failure_sender,
            tasks: vec![],
            registry: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    pub fn registry(&self) -> Registry {
        self.registry.clone()
    }
    pub fn register<E: DurableExtension>(&mut self, extension: E) -> eyre::Result<()> {
        eyre::ensure!(!*self.shutdown.borrow(), "extension manager is stopped");
        let name = extension.name().to_owned();
        btc_storage::exex::validate_name(&name)?;
        let runtime = tokio::runtime::Handle::try_current()?;
        {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| eyre::eyre!("extension registry poisoned"))?;
            if registry.len() >= 8 || registry.contains_key(&name) {
                return Err(eyre::eyre!("extension registry full or duplicate name"));
            }
            registry.insert(
                name.clone(),
                WorkerStatus {
                    status: "running".into(),
                    ..WorkerStatus::default()
                },
            );
        }
        let extension: Arc<dyn DurableExtension> = Arc::new(extension);
        let store = self.store.clone();
        let registry = self.registry.clone();
        let mut shutdown = self.shutdown.subscribe();
        let mut wakeup = self.wakeup.clone();
        let failure = self.failure_sender.clone();
        let worker = async move {
            let mut errors = 0u32;
            let mut wakeup_open = true;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                let task_store = store.clone();
                let task_extension = extension.clone();
                let result =
                    tokio::task::spawn_blocking(move || task_store.step(task_extension.as_ref()))
                        .await;
                let result = match result {
                    Ok(result) => result.map_err(|e| e.to_string()),
                    Err(e) => Err(format!("extension worker failed: {e}")),
                };
                match result {
                    Ok(progress) => {
                        errors = 0;
                        if let Ok(mut registry) = registry.lock() {
                            registry.insert(
                                name.clone(),
                                WorkerStatus {
                                    status: "running".into(),
                                    ..WorkerStatus::default()
                                },
                            );
                        }
                        if progress {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        tokio::select! {
                            _ = shutdown.changed() => {},
                            result = wakeup.changed(), if wakeup_open => { wakeup_open = result.is_ok(); },
                            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {},
                        }
                    }
                    Err(error) => {
                        errors += 1;
                        let message: String = error.chars().take(1024).collect();
                        if let Ok(mut registry) = registry.lock() {
                            registry.insert(
                                name.clone(),
                                WorkerStatus {
                                    status: if errors >= 3 { "failed" } else { "retrying" }.into(),
                                    failures: errors,
                                    last_error: Some(message.clone()),
                                },
                            );
                        }
                        if errors >= 3 {
                            let _ = failure.send(Some(format!("{name}: {message}")));
                            return;
                        }
                        tokio::select! {
                            _ = shutdown.changed() => {},
                            _ = tokio::time::sleep(std::time::Duration::from_millis(250u64 << errors)) => {},
                        }
                    }
                }
            }
            if let Ok(mut registry) = registry.lock() {
                if let Some(status) = registry.get_mut(&name) {
                    status.status = "stopped".into();
                }
            }
        };
        self.tasks.push(runtime.spawn(worker));
        Ok(())
    }
    pub async fn wait_failed(&mut self) -> eyre::Error {
        loop {
            if let Some(error) = self.failed.borrow().clone() {
                return eyre::eyre!(error);
            }
            if self.failed.changed().await.is_err() {
                return eyre::eyre!("extension supervisor closed");
            }
        }
    }
    pub async fn shutdown(&mut self) {
        let _ = self.shutdown.send(true);
        for task in &mut self.tasks {
            if tokio::time::timeout(std::time::Duration::from_secs(2), &mut *task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
        self.tasks.clear();
    }
}
impl<S: DurableStore> Drop for DurableManager<S> {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsState {
    pub transactions: u64,
    pub spendable_coins: u64,
}
impl MetricsState {
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != 20 || &bytes[..4] != b"MET1" {
            return Err(bad("invalid durable metrics state"));
        }
        Ok(Self {
            transactions: u64::from_be_bytes(bytes[4..12].try_into().unwrap()),
            spendable_coins: u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
        })
    }
    pub fn coin_counts(event: &JournalEvent) -> (usize, usize) {
        let eligible = |c: &btc_consensus::utxo::UtxoEntry| {
            !c.txout.script_pubkey.is_op_return() && c.txout.script_pubkey.len() <= 10000
        };
        (
            event
                .undo
                .created
                .iter()
                .filter(|(_, c)| eligible(c))
                .count(),
            event.undo.spent.iter().filter(|(_, c)| eligible(c)).count(),
        )
    }
}
pub struct ValidatedMetrics;
impl DurableExtension for ValidatedMetrics {
    fn validate_state(&self, previous: Option<&[u8]>) -> Result<(), StorageError> {
        previous.map(MetricsState::decode).transpose()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "validated-metrics-v1"
    }
    fn apply(
        &self,
        event: &JournalEvent,
        previous: Option<&[u8]>,
    ) -> Result<Vec<u8>, StorageError> {
        let mut state = previous
            .map(MetricsState::decode)
            .transpose()?
            .unwrap_or_default();
        let txs = event.block.transactions.len() as u64;
        let (created, spent) = MetricsState::coin_counts(event);
        let (added, removed) = if event.entry.connected {
            (created, spent)
        } else {
            (spent, created)
        };
        state.transactions = if event.entry.connected {
            state.transactions.checked_add(txs)
        } else {
            state.transactions.checked_sub(txs)
        }
        .ok_or_else(|| bad("durable transaction count overflow/underflow"))?;
        // Same-block creations/spends cancel before subtraction, including undo.
        state.spendable_coins = if added >= removed {
            state.spendable_coins.checked_add((added - removed) as u64)
        } else {
            state.spendable_coins.checked_sub((removed - added) as u64)
        }
        .ok_or_else(|| bad("durable coin count overflow/underflow"))?;
        let mut bytes = b"MET1".to_vec();
        bytes.extend_from_slice(&state.transactions.to_be_bytes());
        bytes.extend_from_slice(&state.spendable_coins.to_be_bytes());
        Ok(bytes)
    }
}
