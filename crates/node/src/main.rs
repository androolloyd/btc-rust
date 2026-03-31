use std::path::PathBuf;

use clap::{Parser, Subcommand};

use btc_node::builder::{DatabaseHandle, NetworkHandle, NodeBuilder, NodeConfig};
use btc_node::output::{self, OutputFormat};
use btc_primitives::Network;
use btc_stages::Pipeline;

#[derive(Parser, Debug)]
#[command(
    name = "btc-node",
    version,
    about = "A Rust Bitcoin full node",
    long_about = "btc-node is a modular Rust Bitcoin full node.\n\n\
                  By default, output is JSON when piped and text when interactive.\n\
                  Use --output json to force JSON output for agent/automation use.\n\
                  Use --interactive for human-friendly interactive mode."
)]
struct Cli {
    /// Network to connect to
    #[arg(long, default_value = "mainnet", global = true)]
    network: String,

    /// Data directory
    #[arg(long, default_value = "~/.btc-rust", global = true)]
    datadir: String,

    /// RPC port
    #[arg(long, global = true)]
    rpc_port: Option<u16>,

    /// P2P port
    #[arg(long, global = true)]
    port: Option<u16>,

    /// Log level
    #[arg(long, default_value = "info", global = true)]
    log_level: String,

    /// Output format: "json" or "text". Auto-detects if omitted (JSON when piped).
    #[arg(long, global = true)]
    output: Option<String>,

    /// Enable interactive mode (human-friendly prompts and progress bars)
    #[arg(long, short = 'i', global = true)]
    interactive: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the node and begin syncing
    Run,

    /// Show current node status
    Status,

    /// Show sync progress
    Sync,

    /// List connected peers
    Peers,

    /// Send an RPC command to a running node
    Rpc {
        /// RPC method name
        method: String,
        /// JSON-encoded parameters (optional)
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Show node configuration
    Config,

    /// Initialize a fresh data directory
    Init,

    /// Show version information
    Version,
}

fn parse_network(s: &str) -> Network {
    match s {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => {
            tracing::warn!(network = %s, "unknown network, defaulting to mainnet");
            Network::Mainnet
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    let format = OutputFormat::from_str_opt(cli.output.as_deref());

    // Log to stderr so stdout stays clean for structured output
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .with_writer(std::io::stderr)
        .init();

    let network = parse_network(&cli.network);

    let mut config = NodeConfig::new(network)
        .with_datadir(&cli.datadir)
        .with_log_level(&cli.log_level);

    if let Some(rpc_port) = cli.rpc_port {
        config = config.with_rpc_port(rpc_port);
    }
    if let Some(p2p_port) = cli.port {
        config = config.with_p2p_port(p2p_port);
    }

    match cli.command {
        Some(Commands::Run) | None => cmd_run(config, format, cli.interactive).await,
        Some(Commands::Status) => cmd_status(config, format),
        Some(Commands::Sync) => cmd_sync(config, format),
        Some(Commands::Peers) => cmd_peers(config, format),
        Some(Commands::Config) => cmd_config(config, format),
        Some(Commands::Init) => cmd_init(config, format),
        Some(Commands::Version) => cmd_version(format),
        Some(Commands::Rpc { method, params }) => cmd_rpc(config, format, &method, &params),
    }
}

async fn cmd_run(
    config: NodeConfig,
    format: OutputFormat,
    interactive: bool,
) -> eyre::Result<()> {
    if interactive {
        eprintln!("Starting btc-node on {} (interactive mode)", config.network);
        eprintln!("Data directory: {}", config.datadir.display());
        eprintln!("P2P port: {}, RPC port: {}", config.p2p_port, config.rpc_port);
        eprintln!();
    }

    output::emit_progress("node_starting", &serde_json::json!({
        "network": config.network.to_string(),
        "datadir": config.datadir.display().to_string(),
        "p2p_port": config.p2p_port,
        "rpc_port": config.rpc_port,
    }));

    let db = DatabaseHandle {
        path: config.datadir.clone(),
    };
    let net = NetworkHandle {
        port: config.p2p_port,
    };
    let pipeline = Pipeline::new();

    let node = NodeBuilder::new(config)
        .with_database(db)
        .with_network(net)
        .with_pipeline(pipeline)
        .build()?;

    node.run().await?;

    Ok(())
}

fn cmd_status(config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let status = output::NodeStatus {
        network: config.network.to_string(),
        chain_height: 0,
        best_block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        peer_count: 0,
        mempool_size: 0,
        syncing: false,
        sync_progress: 0.0,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    output::emit(format, &status);
    Ok(())
}

fn cmd_sync(config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let status = output::SyncStatus {
        syncing: false,
        current_height: 0,
        target_height: 0,
        progress: 0.0,
        stage: "idle".to_string(),
        peers: 0,
    };
    output::emit(format, &status);
    Ok(())
}

fn cmd_peers(_config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let peers: Vec<output::PeerEntry> = vec![];
    output::emit(format, &peers);
    Ok(())
}

fn cmd_config(config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let info = serde_json::json!({
        "network": config.network.to_string(),
        "datadir": config.datadir.display().to_string(),
        "rpc_port": config.rpc_port,
        "p2p_port": config.p2p_port,
        "log_level": config.log_level,
    });
    output::emit(format, &info);
    Ok(())
}

fn cmd_init(config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    // Create data directory if it doesn't exist
    let datadir = &config.datadir;
    if !datadir.exists() {
        std::fs::create_dir_all(datadir)?;
    }

    let result = serde_json::json!({
        "initialized": true,
        "datadir": datadir.display().to_string(),
        "network": config.network.to_string(),
    });
    output::emit(format, &result);
    Ok(())
}

fn cmd_version(format: OutputFormat) -> eyre::Result<()> {
    let info = serde_json::json!({
        "name": "btc-node",
        "version": env!("CARGO_PKG_VERSION"),
        "rust_version": "1.82+",
        "database": "qmdb",
        "features": ["legacy", "segwit", "taproot"],
    });
    output::emit(format, &info);
    Ok(())
}

fn cmd_rpc(
    config: NodeConfig,
    format: OutputFormat,
    method: &str,
    params: &[String],
) -> eyre::Result<()> {
    // Build JSON-RPC request and send to running node
    let params_json: serde_json::Value = if params.is_empty() {
        serde_json::Value::Array(vec![])
    } else {
        // Try to parse each param as JSON, fall back to string
        let parsed: Vec<serde_json::Value> = params
            .iter()
            .map(|p| {
                serde_json::from_str(p).unwrap_or(serde_json::Value::String(p.clone()))
            })
            .collect();
        serde_json::Value::Array(parsed)
    };

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params_json,
        "id": 1,
    });

    // For now, show what would be sent
    // TODO: actually connect to the RPC port and send
    let result = serde_json::json!({
        "request": request,
        "target": format!("127.0.0.1:{}", config.rpc_port),
        "note": "RPC client not yet connected — showing request that would be sent",
    });
    output::emit(format, &result);
    Ok(())
}
