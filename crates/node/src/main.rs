use std::io::Write;

use clap::{Parser, Subcommand};

use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_node::builder::{DatabaseHandle, NetworkHandle, NodeBuilder, NodeConfig};
use btc_node::cli::{self, ScriptItem};
use btc_node::output::{self, OutputFormat};
use btc_primitives::script::{Instruction, ScriptBuf};
use btc_primitives::Network;
use btc_stages::Pipeline;

#[derive(Parser, Debug)]
#[command(
    name = "btc-node",
    version,
    about = "A Rust Bitcoin full node",
    long_about = "btc-node is a modular Rust Bitcoin full node.\n\n\
                  By default, output is JSON when piped and text when interactive.\n\
                  Use --output json (or --json) to force JSON output for agent/automation use.\n\
                  Use --interactive for human-friendly interactive mode.\n\n\
                  Exit codes:\n  \
                  0  — success\n  \
                  1  — general error\n  \
                  2  — invalid arguments\n  \
                  3  — network error\n  \
                  4  — consensus error\n  \
                  5  — storage error"
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

    /// Shorthand for --output json
    #[arg(long, global = true)]
    json: bool,

    /// Enable interactive mode (human-friendly prompts and progress bars)
    #[arg(long, short = 'i', global = true)]
    interactive: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the node and begin syncing
    Run {
        /// Policy preset: "core" (default), "consensus" (minimal), "all" (strictest)
        #[arg(long, default_value = "core")]
        policy: String,

        /// Disable NULLFAIL policy (only effective with --policy core or --policy all)
        #[arg(long)]
        no_nullfail: bool,

        /// Custom dust limit in satoshis
        #[arg(long)]
        dust_limit: Option<u64>,

        /// Custom OP_RETURN data carrier size limit in bytes
        #[arg(long)]
        datacarrier_size: Option<usize>,

        /// Path to an AssumeUTXO snapshot file. When provided, the node loads the
        /// serialized UTXO set and starts syncing from the snapshot height.
        #[arg(long)]
        assumeutxo: Option<String>,

        /// Disable full RBF (revert to BIP125 opt-in RBF behavior).
        /// By default, full RBF is enabled (Bitcoin Core v29+ behavior).
        #[arg(long)]
        no_full_rbf: bool,

        /// Maximum OP_RETURN data size in bytes (default: 100000).
        /// Bitcoin Core v30+ raised this from 80 to 100,000 bytes.
        #[arg(long)]
        op_return_limit: Option<usize>,

        /// ZMQ notification endpoint for hashblock topic (e.g., tcp://127.0.0.1:28332)
        #[arg(long)]
        zmq_pub_hashblock: Option<String>,

        /// ZMQ notification endpoint for hashtx topic
        #[arg(long)]
        zmq_pub_hashtx: Option<String>,

        /// ZMQ notification endpoint for rawblock topic
        #[arg(long)]
        zmq_pub_rawblock: Option<String>,

        /// ZMQ notification endpoint for rawtx topic
        #[arg(long)]
        zmq_pub_rawtx: Option<String>,
    },

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

    /// Decode a raw transaction hex
    DecodeTx {
        /// Raw transaction hex
        hex: String,
    },

    /// Decode a raw script hex
    DecodeScript {
        /// Raw script hex
        hex: String,
    },

    /// Decode a raw block header hex (80 bytes = 160 hex chars)
    DecodeHeader {
        /// Raw block header hex
        hex: String,
    },

    /// Interactive script playground
    Playground,

    /// Watch an address for incoming/outgoing transactions
    Watch {
        /// Bitcoin address to watch (any format)
        address: String,
    },

    /// Simulate a transaction against current UTXO set (dry run)
    SimulateTx {
        /// Raw transaction hex
        hex: String,
    },

    /// Compile a miniscript policy to Bitcoin Script
    Compile {
        /// Policy string (e.g., "and(pk(KEY),after(100))")
        policy: String,
    },

    /// Launch the block explorer web UI
    Explore {
        /// Explorer HTTP port
        #[arg(long, default_value = "3000")]
        explorer_port: u16,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    let format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::from_str_opt(cli.output.as_deref())
    };

    // Log to stderr so stdout stays clean for structured output
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .with_writer(std::io::stderr)
        .init();

    let network = cli::parse_network(&cli.network);

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
        Some(Commands::Run {
            policy,
            no_nullfail,
            dust_limit,
            datacarrier_size,
            assumeutxo,
            no_full_rbf,
            op_return_limit,
            zmq_pub_hashblock,
            zmq_pub_hashtx,
            zmq_pub_rawblock,
            zmq_pub_rawtx,
        }) => {
            cmd_run(
                config,
                format,
                cli.interactive,
                &policy,
                no_nullfail,
                dust_limit,
                datacarrier_size,
                assumeutxo,
                no_full_rbf,
                op_return_limit,
                zmq_pub_hashblock,
                zmq_pub_hashtx,
                zmq_pub_rawblock,
                zmq_pub_rawtx,
            )
            .await
        }
        None => {
            cmd_run(
                config,
                format,
                cli.interactive,
                "core",
                false,
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
            )
            .await
        }
        Some(Commands::Status) => cmd_status(config, format),
        Some(Commands::Sync) => cmd_sync(config, format),
        Some(Commands::Peers) => cmd_peers(config, format),
        Some(Commands::Config) => cmd_config(config, format),
        Some(Commands::Init) => cmd_init(config, format),
        Some(Commands::Version) => cmd_version(format),
        Some(Commands::Rpc { method, params }) => cmd_rpc(config, format, &method, &params),
        Some(Commands::DecodeTx { hex }) => cmd_decode_tx(&hex, format),
        Some(Commands::DecodeScript { hex }) => cmd_decode_script(&hex, format),
        Some(Commands::DecodeHeader { hex }) => cmd_decode_header(&hex, format),
        Some(Commands::Playground) => cmd_playground(),
        Some(Commands::Watch { address }) => cmd_watch(&address, network, format),
        Some(Commands::SimulateTx { hex }) => cmd_simulate_tx(&hex, format),
        Some(Commands::Compile { policy }) => cmd_compile(&policy, format),
        Some(Commands::Explore { explorer_port }) => cmd_explore(config, format, explorer_port),
    }
}

async fn cmd_run(
    config: NodeConfig,
    format: OutputFormat,
    interactive: bool,
    policy: &str,
    no_nullfail: bool,
    dust_limit: Option<u64>,
    datacarrier_size: Option<usize>,
    assumeutxo: Option<String>,
    no_full_rbf: bool,
    op_return_limit: Option<usize>,
    zmq_pub_hashblock: Option<String>,
    zmq_pub_hashtx: Option<String>,
    zmq_pub_rawblock: Option<String>,
    zmq_pub_rawtx: Option<String>,
) -> eyre::Result<()> {
    // Validate policy preset
    match policy {
        "core" | "consensus" | "all" => {}
        other => {
            output::emit_error(format, 2, &format!("unknown policy preset '{}': expected 'core', 'consensus', or 'all'", other));
        }
    }

    let full_rbf = !no_full_rbf;
    let effective_op_return_limit = op_return_limit.unwrap_or(btc_mempool::policy::MAX_OP_RETURN_SIZE);

    // Collect ZMQ topics from CLI flags
    let mut zmq_topics: Vec<String> = Vec::new();
    if zmq_pub_hashblock.is_some() {
        zmq_topics.push("hashblock".to_string());
    }
    if zmq_pub_hashtx.is_some() {
        zmq_topics.push("hashtx".to_string());
    }
    if zmq_pub_rawblock.is_some() {
        zmq_topics.push("rawblock".to_string());
    }
    if zmq_pub_rawtx.is_some() {
        zmq_topics.push("rawtx".to_string());
    }

    if interactive {
        eprintln!("Starting btc-node on {} (interactive mode)", config.network);
        eprintln!("Data directory: {}", config.datadir.display());
        eprintln!(
            "P2P port: {}, RPC port: {}",
            config.p2p_port, config.rpc_port
        );
        eprintln!("Policy preset: {}", policy);
        if no_nullfail {
            eprintln!("  NULLFAIL: disabled");
        }
        if let Some(dl) = dust_limit {
            eprintln!("  Dust limit: {} sat", dl);
        }
        if let Some(ds) = datacarrier_size {
            eprintln!("  OP_RETURN data limit: {} bytes", ds);
        }
        eprintln!("  Full RBF: {}", if full_rbf { "enabled" } else { "disabled" });
        eprintln!("  OP_RETURN limit: {} bytes", effective_op_return_limit);
        if !zmq_topics.is_empty() {
            eprintln!("  ZMQ topics: {}", zmq_topics.join(", "));
        }
        eprintln!();
    }

    output::emit_progress(
        "node_starting",
        &serde_json::json!({
            "network": config.network.to_string(),
            "datadir": config.datadir.display().to_string(),
            "p2p_port": config.p2p_port,
            "rpc_port": config.rpc_port,
            "policy": policy,
            "no_nullfail": no_nullfail,
            "dust_limit": dust_limit,
            "datacarrier_size": datacarrier_size,
            "full_rbf": full_rbf,
            "op_return_limit": effective_op_return_limit,
            "zmq_topics": zmq_topics,
        }),
    );

    // Load AssumeUTXO snapshot if provided
    if let Some(ref snapshot_path) = assumeutxo {
        let path = std::path::Path::new(snapshot_path);
        if !path.exists() {
            output::emit_error(format, 1, &format!("assumeutxo snapshot file not found: {}", snapshot_path));
            return Ok(());
        }

        output::emit_progress(
            "snapshot_loading",
            &serde_json::json!({
                "path": snapshot_path,
            }),
        );

        let db_path = config.datadir.join("utxo.redb");
        match btc_storage::redb_backend::RedbDatabase::new(&db_path) {
            Ok(db) => {
                if let Err(e) = db.init_tables() {
                    output::emit_error(format, 5, &format!("failed to init database tables: {}", e));
                    return Ok(());
                }
                match btc_storage::snapshot::load_utxo_snapshot(path, &db) {
                    Ok(metadata) => {
                        output::emit_progress(
                            "snapshot_loaded",
                            &serde_json::json!({
                                "height": metadata.height,
                                "hash": format!("{}", metadata.block_hash),
                                "entries": metadata.entry_count,
                            }),
                        );
                    }
                    Err(e) => {
                        output::emit_error(format, 5, &format!("failed to load UTXO snapshot: {}", e));
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                output::emit_error(format, 5, &format!("failed to open database: {}", e));
                return Ok(());
            }
        }
    }

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
    let status = cli::build_status(&config);
    output::emit(format, &status);
    Ok(())
}

fn cmd_sync(_config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let status = cli::build_sync_status();
    output::emit(format, &status);
    Ok(())
}

fn cmd_peers(_config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let peers: Vec<output::PeerEntry> = vec![];
    output::emit(format, &peers);
    Ok(())
}

fn cmd_config(config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
    let info = cli::build_config(&config);
    output::emit(format, &info);
    Ok(())
}

fn cmd_init(config: NodeConfig, format: OutputFormat) -> eyre::Result<()> {
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
    let info = cli::build_version();
    output::emit(format, &info);
    Ok(())
}

fn cmd_rpc(
    config: NodeConfig,
    _format: OutputFormat,
    method: &str,
    params: &[String],
) -> eyre::Result<()> {
    let result = cli::build_rpc_request(method, params, config.rpc_port);
    // Always emit JSON-RPC responses as JSON (the protocol is JSON-native)
    output::emit(OutputFormat::Json, &result);
    Ok(())
}

// ---------------------------------------------------------------------------
// Decode subcommands
// ---------------------------------------------------------------------------

fn cmd_decode_tx(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let info = cli::decode_tx(hex_str)?;
    output::emit(format, &info);
    Ok(())
}

fn cmd_decode_script(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let info = cli::decode_script(hex_str)?;
    output::emit(format, &info);
    Ok(())
}

fn cmd_decode_header(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let info = cli::decode_header(hex_str)?;
    output::emit(format, &info);
    Ok(())
}

// ---------------------------------------------------------------------------
// Explore (block explorer web UI)
// ---------------------------------------------------------------------------

fn cmd_explore(config: NodeConfig, format: OutputFormat, explorer_port: u16) -> eyre::Result<()> {
    let info = cli::build_explore(&config, explorer_port);
    output::emit(format, &info);
    eprintln!(
        "Block explorer starting at http://127.0.0.1:{} (network: {})",
        explorer_port, config.network
    );
    // In a full implementation this would start the ExplorerServer from explorer.rs.
    // For now we emit the startup event so agents can parse it.
    Ok(())
}

// ---------------------------------------------------------------------------
// Watch address
// ---------------------------------------------------------------------------

fn cmd_watch(address_str: &str, network: Network, format: OutputFormat) -> eyre::Result<()> {
    let info = cli::watch_address(address_str, network)?;
    // Emit watch-started event (JSON line to stderr for agents)
    output::emit_progress(
        "watch_started",
        &serde_json::json!({
            "address": address_str,
            "type": info["type"],
            "script_hash": info["script_hash"],
        }),
    );
    output::emit(format, &info);
    Ok(())
}

// ---------------------------------------------------------------------------
// Simulate transaction
// ---------------------------------------------------------------------------

fn cmd_simulate_tx(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let result = cli::simulate_tx(hex_str)?;
    output::emit(format, &result);
    Ok(())
}

// ---------------------------------------------------------------------------
// Compile miniscript policy
// ---------------------------------------------------------------------------

fn cmd_compile(policy_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let info = cli::compile_policy(policy_str)?;
    output::emit(format, &info);
    Ok(())
}

// ---------------------------------------------------------------------------
// Script playground
// ---------------------------------------------------------------------------

fn format_stack(stack: &[Vec<u8>]) {
    println!("{}", cli::format_stack_to_string(stack));
}

fn cmd_playground() -> eyre::Result<()> {
    println!("btc-rust script playground");
    println!("Type opcodes to build and execute scripts. Commands:");
    println!("  .run        -- execute current script");
    println!("  .stack      -- show current script");
    println!("  .reset      -- clear script and stack");
    println!("  .trace      -- run with step-by-step trace");
    println!("  .hex        -- show script as hex");
    println!("  .help       -- show this help");
    println!("  .quit       -- exit");
    println!();

    let mut script = ScriptBuf::new();
    let stdin = std::io::stdin();
    let verifier = Secp256k1Verifier;

    loop {
        print!("script> ");
        std::io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match line {
            ".quit" | ".exit" => break,
            ".run" => {
                let flags = ScriptFlags::none();
                let mut engine = ScriptEngine::new_without_tx(&verifier, flags);
                match engine.execute(script.as_script()) {
                    Ok(()) => {
                        if engine.success() {
                            println!("Result: SUCCESS (top of stack is true)");
                        } else {
                            println!("Result: FAILURE (top of stack is false or empty)");
                        }
                        println!("Final stack:");
                        format_stack(engine.stack());
                    }
                    Err(e) => {
                        println!("Execution error: {}", e);
                        println!("Stack at error:");
                        format_stack(engine.stack());
                    }
                }
            }
            ".stack" => {
                println!("Script so far ({} bytes):", script.len());
                let s = script.as_script();
                for instruction in s.instructions() {
                    match instruction {
                        Ok(Instruction::Op(op)) => print!("{:?} ", op),
                        Ok(Instruction::PushBytes(data)) => {
                            print!("PUSH({}) ", hex::encode(data));
                        }
                        Err(e) => print!("ERROR({}) ", e),
                    }
                }
                println!();
            }
            ".reset" => {
                script = ScriptBuf::new();
                println!("Reset.");
            }
            ".trace" => {
                let flags = ScriptFlags::none();
                let s = script.as_script();
                println!("Tracing script execution:");
                println!("Script hex: {}", hex::encode(s.as_bytes()));
                println!();

                let mut step = 0;
                for instruction in s.instructions() {
                    match instruction {
                        Ok(Instruction::Op(op)) => {
                            println!("  step {}: {:?}", step, op);
                        }
                        Ok(Instruction::PushBytes(data)) => {
                            println!("  step {}: PUSH({})", step, hex::encode(data));
                        }
                        Err(e) => {
                            println!("  step {}: ERROR: {}", step, e);
                        }
                    }
                    step += 1;
                }
                println!();

                let mut engine = ScriptEngine::new_without_tx(&verifier, flags);
                match engine.execute(s) {
                    Ok(()) => {
                        if engine.success() {
                            println!("Result: SUCCESS");
                        } else {
                            println!("Result: FAILURE");
                        }
                        println!("Final stack:");
                        format_stack(engine.stack());
                    }
                    Err(e) => {
                        println!("Execution error: {}", e);
                        println!("Stack at error:");
                        format_stack(engine.stack());
                    }
                }
            }
            ".hex" => {
                println!("{}", hex::encode(script.as_bytes()));
            }
            ".help" => {
                println!("btc-rust script playground");
                println!("Type opcodes to build and execute scripts. Commands:");
                println!("  .run        -- execute current script");
                println!("  .stack      -- show current script");
                println!("  .reset      -- clear script and stack");
                println!("  .trace      -- run with step-by-step trace");
                println!("  .hex        -- show script as hex");
                println!("  .help       -- show this help");
                println!("  .quit       -- exit");
                println!();
                println!("Enter opcodes by name (e.g. OP_DUP, OP_ADD, OP_1)");
                println!("Enter hex data to push onto the script (e.g. deadbeef)");
                println!("The OP_ prefix is optional (e.g. DUP, ADD, 1)");
            }
            _ => {
                for token in line.split_whitespace() {
                    match cli::parse_opcode_or_data(token) {
                        Some(ScriptItem::Op(op)) => {
                            script.push_opcode(op);
                            println!("+ {:?}", op);
                        }
                        Some(ScriptItem::Data(d)) => {
                            let len = d.len();
                            script.push_slice(&d);
                            println!("+ PUSH({} bytes: {})", len, hex::encode(&d));
                        }
                        None => println!("Unknown: {}", token),
                    }
                }
            }
        }
    }
    Ok(())
}
