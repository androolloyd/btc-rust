use std::io::Write;

use clap::{Parser, Subcommand};

use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_node::builder::{DatabaseHandle, NetworkHandle, NodeBuilder, NodeConfig};
use btc_node::output::{self, OutputFormat};
use btc_primitives::block::BlockHeader;
use btc_primitives::script::{Instruction, Opcode, Script, ScriptBuf};
use btc_primitives::transaction::Transaction;
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
        Some(Commands::DecodeTx { hex }) => cmd_decode_tx(&hex, format),
        Some(Commands::DecodeScript { hex }) => cmd_decode_script(&hex, format),
        Some(Commands::DecodeHeader { hex }) => cmd_decode_header(&hex, format),
        Some(Commands::Playground) => cmd_playground(),
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
        eprintln!(
            "P2P port: {}, RPC port: {}",
            config.p2p_port, config.rpc_port
        );
        eprintln!();
    }

    output::emit_progress(
        "node_starting",
        &serde_json::json!({
            "network": config.network.to_string(),
            "datadir": config.datadir.display().to_string(),
            "p2p_port": config.p2p_port,
            "rpc_port": config.rpc_port,
        }),
    );

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
    let params_json: serde_json::Value = if params.is_empty() {
        serde_json::Value::Array(vec![])
    } else {
        let parsed: Vec<serde_json::Value> = params
            .iter()
            .map(|p| serde_json::from_str(p).unwrap_or(serde_json::Value::String(p.clone())))
            .collect();
        serde_json::Value::Array(parsed)
    };

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params_json,
        "id": 1,
    });

    let result = serde_json::json!({
        "request": request,
        "target": format!("127.0.0.1:{}", config.rpc_port),
        "note": "RPC client not yet connected \u{2014} showing request that would be sent",
    });
    output::emit(format, &result);
    Ok(())
}

// ---------------------------------------------------------------------------
// Decode subcommands
// ---------------------------------------------------------------------------

fn script_type(script: &Script) -> &str {
    if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2tr() {
        "p2tr"
    } else if script.is_op_return() {
        "op_return"
    } else {
        "unknown"
    }
}

fn cmd_decode_tx(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let bytes = hex::decode(hex_str)?;
    let tx: Transaction = btc_primitives::decode(&bytes)?;
    let info = serde_json::json!({
        "txid": tx.txid().to_hex(),
        "version": tx.version,
        "locktime": tx.lock_time,
        "inputs": tx.inputs.len(),
        "outputs": tx.outputs.len(),
        "is_segwit": tx.is_segwit(),
        "is_coinbase": tx.is_coinbase(),
        "size": bytes.len(),
        "vin": tx.inputs.iter().map(|i| serde_json::json!({
            "txid": i.previous_output.txid.to_hex(),
            "vout": i.previous_output.vout,
            "script_sig_hex": hex::encode(i.script_sig.as_bytes()),
            "sequence": i.sequence,
        })).collect::<Vec<_>>(),
        "vout": tx.outputs.iter().enumerate().map(|(n, o)| serde_json::json!({
            "n": n,
            "value": o.value.as_sat(),
            "value_btc": o.value.as_btc(),
            "script_pubkey_hex": hex::encode(o.script_pubkey.as_bytes()),
            "type": script_type(&o.script_pubkey),
        })).collect::<Vec<_>>(),
    });
    output::emit(format, &info);
    Ok(())
}

fn cmd_decode_script(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let bytes = hex::decode(hex_str)?;
    let script = Script::from_bytes(&bytes);

    let mut ops = Vec::new();
    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::Op(op)) => ops.push(format!("{:?}", op)),
            Ok(Instruction::PushBytes(data)) => {
                ops.push(format!("PUSH({})", hex::encode(data)))
            }
            Err(e) => ops.push(format!("ERROR: {}", e)),
        }
    }

    let info = serde_json::json!({
        "hex": hex_str,
        "size": bytes.len(),
        "type": script_type(script),
        "is_witness_program": script.is_witness_program(),
        "asm": ops.join(" "),
        "opcodes": ops,
    });
    output::emit(format, &info);
    Ok(())
}

fn cmd_decode_header(hex_str: &str, format: OutputFormat) -> eyre::Result<()> {
    let bytes = hex::decode(hex_str)?;
    let header: BlockHeader = btc_primitives::decode(&bytes)?;
    let info = serde_json::json!({
        "hash": header.block_hash().to_hex(),
        "version": header.version,
        "prev_blockhash": header.prev_blockhash.to_hex(),
        "merkle_root": header.merkle_root.to_hex(),
        "time": header.time,
        "bits": format!("{:#010x}", header.bits.to_u32()),
        "nonce": header.nonce,
    });
    output::emit(format, &info);
    Ok(())
}

// ---------------------------------------------------------------------------
// Script playground
// ---------------------------------------------------------------------------

enum ScriptItem {
    Op(Opcode),
    Data(Vec<u8>),
}

fn parse_opcode_or_data(input: &str) -> Option<ScriptItem> {
    let upper = input.to_uppercase();

    let try_names: Vec<String> = if upper.starts_with("OP_") {
        vec![upper.clone()]
    } else {
        vec![format!("OP_{}", upper), upper.clone()]
    };

    for name in &try_names {
        let matched = match name.as_str() {
            "OP_0" | "OP_FALSE" => Some(Opcode::OP_0),
            "OP_1NEGATE" => Some(Opcode::OP_1NEGATE),
            "OP_1" | "OP_TRUE" => Some(Opcode::OP_1),
            "OP_2" => Some(Opcode::OP_2),
            "OP_3" => Some(Opcode::OP_3),
            "OP_4" => Some(Opcode::OP_4),
            "OP_5" => Some(Opcode::OP_5),
            "OP_6" => Some(Opcode::OP_6),
            "OP_7" => Some(Opcode::OP_7),
            "OP_8" => Some(Opcode::OP_8),
            "OP_9" => Some(Opcode::OP_9),
            "OP_10" => Some(Opcode::OP_10),
            "OP_11" => Some(Opcode::OP_11),
            "OP_12" => Some(Opcode::OP_12),
            "OP_13" => Some(Opcode::OP_13),
            "OP_14" => Some(Opcode::OP_14),
            "OP_15" => Some(Opcode::OP_15),
            "OP_16" => Some(Opcode::OP_16),
            "OP_NOP" => Some(Opcode::OP_NOP),
            "OP_IF" => Some(Opcode::OP_IF),
            "OP_NOTIF" => Some(Opcode::OP_NOTIF),
            "OP_ELSE" => Some(Opcode::OP_ELSE),
            "OP_ENDIF" => Some(Opcode::OP_ENDIF),
            "OP_VERIFY" => Some(Opcode::OP_VERIFY),
            "OP_RETURN" => Some(Opcode::OP_RETURN),
            "OP_TOALTSTACK" => Some(Opcode::OP_TOALTSTACK),
            "OP_FROMALTSTACK" => Some(Opcode::OP_FROMALTSTACK),
            "OP_2DROP" => Some(Opcode::OP_2DROP),
            "OP_2DUP" => Some(Opcode::OP_2DUP),
            "OP_3DUP" => Some(Opcode::OP_3DUP),
            "OP_2OVER" => Some(Opcode::OP_2OVER),
            "OP_2ROT" => Some(Opcode::OP_2ROT),
            "OP_2SWAP" => Some(Opcode::OP_2SWAP),
            "OP_IFDUP" => Some(Opcode::OP_IFDUP),
            "OP_DEPTH" => Some(Opcode::OP_DEPTH),
            "OP_DROP" => Some(Opcode::OP_DROP),
            "OP_DUP" => Some(Opcode::OP_DUP),
            "OP_NIP" => Some(Opcode::OP_NIP),
            "OP_OVER" => Some(Opcode::OP_OVER),
            "OP_PICK" => Some(Opcode::OP_PICK),
            "OP_ROLL" => Some(Opcode::OP_ROLL),
            "OP_ROT" => Some(Opcode::OP_ROT),
            "OP_SWAP" => Some(Opcode::OP_SWAP),
            "OP_TUCK" => Some(Opcode::OP_TUCK),
            "OP_SIZE" => Some(Opcode::OP_SIZE),
            "OP_EQUAL" => Some(Opcode::OP_EQUAL),
            "OP_EQUALVERIFY" => Some(Opcode::OP_EQUALVERIFY),
            "OP_1ADD" => Some(Opcode::OP_1ADD),
            "OP_1SUB" => Some(Opcode::OP_1SUB),
            "OP_NEGATE" => Some(Opcode::OP_NEGATE),
            "OP_ABS" => Some(Opcode::OP_ABS),
            "OP_NOT" => Some(Opcode::OP_NOT),
            "OP_0NOTEQUAL" => Some(Opcode::OP_0NOTEQUAL),
            "OP_ADD" => Some(Opcode::OP_ADD),
            "OP_SUB" => Some(Opcode::OP_SUB),
            "OP_BOOLAND" => Some(Opcode::OP_BOOLAND),
            "OP_BOOLOR" => Some(Opcode::OP_BOOLOR),
            "OP_NUMEQUAL" => Some(Opcode::OP_NUMEQUAL),
            "OP_NUMEQUALVERIFY" => Some(Opcode::OP_NUMEQUALVERIFY),
            "OP_NUMNOTEQUAL" => Some(Opcode::OP_NUMNOTEQUAL),
            "OP_LESSTHAN" => Some(Opcode::OP_LESSTHAN),
            "OP_GREATERTHAN" => Some(Opcode::OP_GREATERTHAN),
            "OP_LESSTHANOREQUAL" => Some(Opcode::OP_LESSTHANOREQUAL),
            "OP_GREATERTHANOREQUAL" => Some(Opcode::OP_GREATERTHANOREQUAL),
            "OP_MIN" => Some(Opcode::OP_MIN),
            "OP_MAX" => Some(Opcode::OP_MAX),
            "OP_WITHIN" => Some(Opcode::OP_WITHIN),
            "OP_RIPEMD160" => Some(Opcode::OP_RIPEMD160),
            "OP_SHA1" => Some(Opcode::OP_SHA1),
            "OP_SHA256" => Some(Opcode::OP_SHA256),
            "OP_HASH160" => Some(Opcode::OP_HASH160),
            "OP_HASH256" => Some(Opcode::OP_HASH256),
            "OP_CODESEPARATOR" => Some(Opcode::OP_CODESEPARATOR),
            "OP_CHECKSIG" => Some(Opcode::OP_CHECKSIG),
            "OP_CHECKSIGVERIFY" => Some(Opcode::OP_CHECKSIGVERIFY),
            "OP_CHECKMULTISIG" => Some(Opcode::OP_CHECKMULTISIG),
            "OP_CHECKMULTISIGVERIFY" => Some(Opcode::OP_CHECKMULTISIGVERIFY),
            "OP_NOP1" => Some(Opcode::OP_NOP1),
            "OP_CHECKLOCKTIMEVERIFY" | "OP_CLTV" => Some(Opcode::OP_CHECKLOCKTIMEVERIFY),
            "OP_CHECKSEQUENCEVERIFY" | "OP_CSV" => Some(Opcode::OP_CHECKSEQUENCEVERIFY),
            "OP_NOP4" => Some(Opcode::OP_NOP4),
            "OP_NOP5" => Some(Opcode::OP_NOP5),
            "OP_NOP6" => Some(Opcode::OP_NOP6),
            "OP_NOP7" => Some(Opcode::OP_NOP7),
            "OP_NOP8" => Some(Opcode::OP_NOP8),
            "OP_NOP9" => Some(Opcode::OP_NOP9),
            "OP_NOP10" => Some(Opcode::OP_NOP10),
            "OP_CHECKSIGADD" => Some(Opcode::OP_CHECKSIGADD),
            _ => None,
        };
        if let Some(op) = matched {
            return Some(ScriptItem::Op(op));
        }
    }

    // Try parsing as hex data push
    if let Ok(data) = hex::decode(input) {
        if !data.is_empty() {
            return Some(ScriptItem::Data(data));
        }
    }

    None
}

fn format_stack(stack: &[Vec<u8>]) {
    if stack.is_empty() {
        println!("  (empty)");
    } else {
        for (i, item) in stack.iter().enumerate().rev() {
            let hex_str = hex::encode(item);
            let int_repr = if item.is_empty() {
                " (0)".to_string()
            } else if item.len() <= 4 {
                // Script number encoding: little-endian, sign bit in MSB
                let mut val: i64 = 0;
                for (j, &b) in item.iter().enumerate() {
                    val |= (b as i64) << (j * 8);
                }
                if !item.is_empty() && (item.last().unwrap() & 0x80) != 0 {
                    val = -(val & !(0x80i64 << ((item.len() - 1) * 8)));
                }
                format!(" ({})", val)
            } else {
                String::new()
            };
            println!("  [{}] {}{}", i, hex_str, int_repr);
        }
    }
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
                    match parse_opcode_or_data(token) {
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
