//! Create a custom Execution Extension that reacts to chain events.
//!
//! Usage: cargo run --example exex_plugin

use btc_exex::{ExEx, ExExContext, ExExManager, ExExNotification};
use btc_primitives::network::Network;

#[allow(dead_code)]
struct MyIndexer {
    block_count: u64,
    tx_count: u64,
}

impl ExEx for MyIndexer {
    fn name(&self) -> &str {
        "my-indexer"
    }

    async fn start(mut self, mut ctx: ExExContext) -> eyre::Result<()> {
        while let Ok(notif) = ctx.notifications.recv().await {
            match notif {
                ExExNotification::BlockCommitted {
                    height, block, ..
                } => {
                    self.block_count += 1;
                    self.tx_count += block.transactions.len() as u64;
                    println!(
                        "Block {}: {} txs (total: {} blocks, {} txs)",
                        height,
                        block.transactions.len(),
                        self.block_count,
                        self.tx_count
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let mut manager = ExExManager::new(Network::Regtest);
    manager.register("my-indexer");

    let _ctx = manager.subscribe();
    println!("ExEx plugin 'my-indexer' registered on regtest.");
    println!("Registered extensions: {:?}", manager.registered_extensions());
    println!("In a real node, connect this to the sync pipeline via ExExManager.");
}
