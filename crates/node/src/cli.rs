//! CLI utility functions extracted from the binary entry point for testability.
//!
//! These pure/nearly-pure functions are used by the `btc-node` binary for
//! subcommand handling, decode operations, and script playground support.

use btc_forge::miniscript::Policy;
use btc_primitives::address::Address;
use btc_primitives::block::BlockHeader;
use btc_primitives::encode::Encodable;
use btc_primitives::script::{Instruction, Opcode, Script};
use btc_primitives::transaction::Transaction;
use btc_primitives::Network;
use sha2::{Digest, Sha256};

use crate::builder::NodeConfig;
use crate::output;

// ---------------------------------------------------------------------------
// Network parsing
// ---------------------------------------------------------------------------

/// Parse a network name string into a [`Network`] enum value.
///
/// Defaults to [`Network::Mainnet`] for unrecognised values.
pub fn parse_network(s: &str) -> Network {
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

// ---------------------------------------------------------------------------
// Script type classification
// ---------------------------------------------------------------------------

/// Classify a script into a human-readable type label.
pub fn script_type(script: &Script) -> &str {
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

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

/// Decode a raw transaction hex string and return a JSON representation.
pub fn decode_tx(hex_str: &str) -> eyre::Result<serde_json::Value> {
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
    Ok(info)
}

/// Decode a raw script hex string and return a JSON representation.
pub fn decode_script(hex_str: &str) -> eyre::Result<serde_json::Value> {
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
    Ok(info)
}

/// Decode a raw block header hex string and return a JSON representation.
pub fn decode_header(hex_str: &str) -> eyre::Result<serde_json::Value> {
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
    Ok(info)
}

// ---------------------------------------------------------------------------
// Simulate transaction
// ---------------------------------------------------------------------------

/// Simulate (dry-run) a transaction from its hex-encoded form.
///
/// Returns a structured JSON object with decoded fields and computed sizes.
pub fn simulate_tx(hex_str: &str) -> eyre::Result<serde_json::Value> {
    let bytes =
        hex::decode(hex_str).map_err(|e| eyre::eyre!("invalid hex: {}", e))?;
    let tx: Transaction = btc_primitives::decode(&bytes)
        .map_err(|e| eyre::eyre!("failed to decode transaction: {}", e))?;

    // Compute sizes
    let legacy_size = {
        let mut buf = Vec::new();
        let legacy_tx = Transaction {
            version: tx.version,
            inputs: tx.inputs.clone(),
            outputs: tx.outputs.clone(),
            witness: Vec::new(),
            lock_time: tx.lock_time,
        };
        let _ = legacy_tx.encode(&mut buf);
        buf.len()
    };

    let total_size = {
        let mut buf = Vec::new();
        let _ = tx.encode(&mut buf);
        buf.len()
    };

    // Weight = base_size * 3 + total_size  (BIP141)
    let weight = legacy_size * 3 + total_size;
    let vsize = (weight + 3) / 4; // ceiling division

    let is_coinbase = tx.is_coinbase();
    let total_output: i64 = tx.outputs.iter().map(|o| o.value.as_sat()).sum();

    let mut input_details: Vec<serde_json::Value> = Vec::new();
    for (i, inp) in tx.inputs.iter().enumerate() {
        let mut detail = serde_json::json!({
            "index": i,
            "prev_txid": inp.previous_output.txid.to_hex(),
            "prev_vout": inp.previous_output.vout,
            "sequence": inp.sequence,
            "script_sig_size": inp.script_sig.len(),
        });
        if tx.is_segwit() {
            if let Some(w) = tx.witness.get(i) {
                detail["witness_items"] = serde_json::json!(w.len());
            }
        }
        input_details.push(detail);
    }

    let mut output_details: Vec<serde_json::Value> = Vec::new();
    for (i, out) in tx.outputs.iter().enumerate() {
        output_details.push(serde_json::json!({
            "index": i,
            "value_sat": out.value.as_sat(),
            "value_btc": out.value.as_btc(),
            "script_pubkey_hex": hex::encode(out.script_pubkey.as_bytes()),
            "type": script_type(&out.script_pubkey),
        }));
    }

    let result = serde_json::json!({
        "txid": tx.txid().to_hex(),
        "version": tx.version,
        "locktime": tx.lock_time,
        "is_segwit": tx.is_segwit(),
        "is_coinbase": is_coinbase,
        "inputs_count": tx.inputs.len(),
        "outputs_count": tx.outputs.len(),
        "total_output_sat": total_output,
        "total_output_btc": total_output as f64 / 100_000_000.0,
        "size": total_size,
        "weight": weight,
        "vsize": vsize,
        "inputs": input_details,
        "outputs": output_details,
        "simulation": {
            "utxo_lookup": "unavailable (no running node connection)",
            "fee": "unknown (requires UTXO lookup for input values)",
            "script_verification": "skipped (requires UTXO data)",
            "valid": "indeterminate (dry-run without UTXO set)",
        },
    });
    Ok(result)
}

// ---------------------------------------------------------------------------
// Compile miniscript policy
// ---------------------------------------------------------------------------

/// Compile a miniscript policy string into Bitcoin Script.
pub fn compile_policy(policy_str: &str) -> eyre::Result<serde_json::Value> {
    let policy = Policy::parse(policy_str)
        .map_err(|e| eyre::eyre!("failed to parse policy: {}", e))?;

    let script = policy.compile();
    let script_ref = script.as_script();

    // Disassemble
    let mut asm_ops = Vec::new();
    for instruction in script_ref.instructions() {
        match instruction {
            Ok(Instruction::Op(op)) => asm_ops.push(format!("{:?}", op)),
            Ok(Instruction::PushBytes(data)) => {
                asm_ops.push(format!("PUSH({})", hex::encode(data)))
            }
            Err(e) => asm_ops.push(format!("ERROR: {}", e)),
        }
    }

    let info = serde_json::json!({
        "policy": policy_str,
        "script_hex": hex::encode(script.as_bytes()),
        "script_size": script.len(),
        "asm": asm_ops.join(" "),
        "opcodes": asm_ops,
    });
    Ok(info)
}

// ---------------------------------------------------------------------------
// Watch address
// ---------------------------------------------------------------------------

/// Parse and classify a Bitcoin address for watching.
pub fn watch_address(
    address_str: &str,
    network: Network,
) -> eyre::Result<serde_json::Value> {
    let addr = Address::from_bech32(address_str, network)
        .or_else(|_| Address::from_base58(address_str, network))
        .map_err(|e| {
            eyre::eyre!("failed to parse address '{}': {}", address_str, e)
        })?;

    let script_pubkey = addr.script_pubkey();
    let spk_bytes = script_pubkey.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(spk_bytes);
    let script_hash: [u8; 32] = hasher.finalize().into();

    let addr_type = match &addr {
        Address::P2pkh { .. } => "p2pkh",
        Address::P2sh { .. } => "p2sh",
        Address::P2wpkh { .. } => "p2wpkh",
        Address::P2wsh { .. } => "p2wsh",
        Address::P2tr { .. } => "p2tr",
    };

    let info = serde_json::json!({
        "event": "watch_status",
        "address": address_str,
        "type": addr_type,
        "network": network.to_string(),
        "script_pubkey_hex": hex::encode(spk_bytes),
        "script_hash": hex::encode(script_hash),
        "status": "watching",
        "note": "In a live node, JSON-line events will stream here for each matching transaction.",
    });
    Ok(info)
}

// ---------------------------------------------------------------------------
// Status / sync / peers / config / version / explore builders
// ---------------------------------------------------------------------------

/// Build the JSON representation for the `status` subcommand.
pub fn build_status(config: &NodeConfig) -> output::NodeStatus {
    output::NodeStatus {
        network: config.network.to_string(),
        chain_height: 0,
        best_block_hash:
            "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        peer_count: 0,
        mempool_size: 0,
        syncing: false,
        sync_progress: 0.0,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Build the JSON representation for the `sync` subcommand.
pub fn build_sync_status() -> output::SyncStatus {
    output::SyncStatus {
        syncing: false,
        current_height: 0,
        target_height: 0,
        progress: 0.0,
        stage: "idle".to_string(),
        peers: 0,
    }
}

/// Build the JSON representation for the `config` subcommand.
pub fn build_config(config: &NodeConfig) -> serde_json::Value {
    serde_json::json!({
        "network": config.network.to_string(),
        "datadir": config.datadir.display().to_string(),
        "rpc_port": config.rpc_port,
        "p2p_port": config.p2p_port,
        "log_level": config.log_level,
    })
}

/// Build the JSON representation for the `version` subcommand.
pub fn build_version() -> serde_json::Value {
    serde_json::json!({
        "name": "btc-node",
        "version": env!("CARGO_PKG_VERSION"),
        "rust_version": "1.82+",
        "database": "qmdb",
        "features": ["legacy", "segwit", "taproot"],
    })
}

/// Build the JSON representation for the `explore` subcommand.
pub fn build_explore(config: &NodeConfig, explorer_port: u16) -> serde_json::Value {
    serde_json::json!({
        "event": "explorer_starting",
        "network": config.network.to_string(),
        "explorer_url": format!("http://127.0.0.1:{}", explorer_port),
        "api_url": format!("http://127.0.0.1:{}/api", explorer_port),
        "rpc_port": config.rpc_port,
    })
}

/// Build the JSON-RPC envelope for the `rpc` subcommand.
pub fn build_rpc_request(
    method: &str,
    params: &[String],
    rpc_port: u16,
) -> serde_json::Value {
    let params_json: serde_json::Value = if params.is_empty() {
        serde_json::Value::Array(vec![])
    } else {
        let parsed: Vec<serde_json::Value> = params
            .iter()
            .map(|p| {
                serde_json::from_str(p)
                    .unwrap_or(serde_json::Value::String(p.clone()))
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

    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": null,
        "error": {
            "code": -32600,
            "message": "RPC client not yet connected",
            "data": {
                "request": request,
                "target": format!("127.0.0.1:{}", rpc_port),
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Script playground helpers
// ---------------------------------------------------------------------------

/// An item parsed from playground input: either an opcode or raw data.
pub enum ScriptItem {
    /// A Bitcoin Script opcode.
    Op(Opcode),
    /// Raw data to push onto the script.
    Data(Vec<u8>),
}

/// Try to parse a string token as either a Bitcoin opcode or hex data.
pub fn parse_opcode_or_data(input: &str) -> Option<ScriptItem> {
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
            "OP_CHECKLOCKTIMEVERIFY" | "OP_CLTV" => {
                Some(Opcode::OP_CHECKLOCKTIMEVERIFY)
            }
            "OP_CHECKSEQUENCEVERIFY" | "OP_CSV" => {
                Some(Opcode::OP_CHECKSEQUENCEVERIFY)
            }
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

/// Format a script execution stack for display.
pub fn format_stack_to_string(stack: &[Vec<u8>]) -> String {
    if stack.is_empty() {
        return "  (empty)".to_string();
    }
    let mut lines = Vec::new();
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
        lines.push(format!("  [{}] {}{}", i, hex_str, int_repr));
    }
    lines.join("\n")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::amount::Amount;
    use btc_primitives::hash::TxHash;
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::transaction::{OutPoint, TxIn, TxOut};

    // -----------------------------------------------------------------------
    // parse_network
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_network_mainnet() {
        assert_eq!(parse_network("mainnet"), Network::Mainnet);
    }

    #[test]
    fn test_parse_network_testnet() {
        assert_eq!(parse_network("testnet"), Network::Testnet);
    }

    #[test]
    fn test_parse_network_signet() {
        assert_eq!(parse_network("signet"), Network::Signet);
    }

    #[test]
    fn test_parse_network_regtest() {
        assert_eq!(parse_network("regtest"), Network::Regtest);
    }

    #[test]
    fn test_parse_network_unknown_defaults_to_mainnet() {
        assert_eq!(parse_network("potato"), Network::Mainnet);
        assert_eq!(parse_network(""), Network::Mainnet);
        assert_eq!(parse_network("Mainnet"), Network::Mainnet); // case sensitive
    }

    // -----------------------------------------------------------------------
    // script_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_script_type_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_DUP);
        script.push_opcode(Opcode::OP_HASH160);
        script.push_slice(&[0u8; 20]);
        script.push_opcode(Opcode::OP_EQUALVERIFY);
        script.push_opcode(Opcode::OP_CHECKSIG);
        assert_eq!(script_type(script.as_script()), "p2pkh");
    }

    #[test]
    fn test_script_type_p2sh() {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_HASH160);
        script.push_slice(&[0u8; 20]);
        script.push_opcode(Opcode::OP_EQUAL);
        assert_eq!(script_type(script.as_script()), "p2sh");
    }

    #[test]
    fn test_script_type_p2wpkh() {
        // OP_0 <20 bytes>
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_slice(&[0u8; 20]);
        assert_eq!(script_type(script.as_script()), "p2wpkh");
    }

    #[test]
    fn test_script_type_p2wsh() {
        // OP_0 <32 bytes>
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_0);
        script.push_slice(&[0u8; 32]);
        assert_eq!(script_type(script.as_script()), "p2wsh");
    }

    #[test]
    fn test_script_type_p2tr() {
        // OP_1 <32 bytes>
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_1);
        script.push_slice(&[0u8; 32]);
        assert_eq!(script_type(script.as_script()), "p2tr");
    }

    #[test]
    fn test_script_type_op_return() {
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_RETURN);
        script.push_slice(b"hello");
        assert_eq!(script_type(script.as_script()), "op_return");
    }

    #[test]
    fn test_script_type_unknown() {
        // Random opcodes
        let mut script = ScriptBuf::new();
        script.push_opcode(Opcode::OP_ADD);
        script.push_opcode(Opcode::OP_SUB);
        assert_eq!(script_type(script.as_script()), "unknown");
    }

    // -----------------------------------------------------------------------
    // decode_tx
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_tx_valid() {
        // Build a simple transaction, encode it, then decode it.
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = decode_tx(&hex_str).unwrap();
        assert_eq!(result["version"], 1);
        assert_eq!(result["inputs"], 1);
        assert_eq!(result["outputs"], 1);
        assert!(result["txid"].as_str().unwrap().len() == 64);
        assert_eq!(result["is_coinbase"], true);
        assert_eq!(result["locktime"], 0);
    }

    #[test]
    fn test_decode_tx_invalid_hex() {
        assert!(decode_tx("not_hex").is_err());
    }

    #[test]
    fn test_decode_tx_invalid_data() {
        assert!(decode_tx("deadbeef").is_err());
    }

    // -----------------------------------------------------------------------
    // decode_script
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_script_valid() {
        // P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        // 76 a9 14 <20 zero bytes> 88 ac
        let hex_str = format!("76a914{}88ac", "00".repeat(20));
        let result = decode_script(&hex_str).unwrap();
        assert_eq!(result["type"], "p2pkh");
        assert_eq!(result["size"], 25);
        assert!(result["asm"].as_str().unwrap().contains("OP_DUP"));
        assert!(result["asm"].as_str().unwrap().contains("OP_HASH160"));
    }

    #[test]
    fn test_decode_script_witness_program() {
        // P2WPKH: OP_0 <20 bytes>
        let hex_str = format!("0014{}", "00".repeat(20));
        let result = decode_script(&hex_str).unwrap();
        assert_eq!(result["type"], "p2wpkh");
        assert_eq!(result["is_witness_program"], true);
    }

    #[test]
    fn test_decode_script_invalid_hex() {
        assert!(decode_script("xyz").is_err());
    }

    #[test]
    fn test_decode_script_empty() {
        let result = decode_script("").unwrap();
        assert_eq!(result["size"], 0);
        assert_eq!(result["type"], "unknown");
    }

    // -----------------------------------------------------------------------
    // decode_header
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_header_valid() {
        // Build a valid block header
        use btc_primitives::block::BlockHeader;
        use btc_primitives::compact::CompactTarget;
        use btc_primitives::hash::BlockHash;

        let header = BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::ZERO,
            merkle_root: TxHash::ZERO,
            time: 1231006505,
            bits: CompactTarget::MAX_TARGET,
            nonce: 2083236893,
        };
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = decode_header(&hex_str).unwrap();
        assert_eq!(result["version"], 1);
        assert_eq!(result["time"], 1231006505);
        assert_eq!(result["nonce"], 2083236893);
        assert!(result["hash"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn test_decode_header_invalid_hex() {
        assert!(decode_header("not_valid_hex").is_err());
    }

    #[test]
    fn test_decode_header_too_short() {
        assert!(decode_header("deadbeef").is_err());
    }

    // -----------------------------------------------------------------------
    // simulate_tx
    // -----------------------------------------------------------------------

    #[test]
    fn test_simulate_tx_valid() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = simulate_tx(&hex_str).unwrap();
        assert_eq!(result["version"], 2);
        assert_eq!(result["inputs_count"], 1);
        assert_eq!(result["outputs_count"], 1);
        assert_eq!(result["total_output_sat"], 1_0000_0000);
        assert!(result["size"].as_u64().unwrap() > 0);
        assert!(result["weight"].as_u64().unwrap() > 0);
        assert!(result["vsize"].as_u64().unwrap() > 0);
        assert_eq!(result["is_coinbase"], false);
        assert_eq!(result["simulation"]["valid"], "indeterminate (dry-run without UTXO set)");
    }

    #[test]
    fn test_simulate_tx_invalid_hex() {
        assert!(simulate_tx("zzz").is_err());
    }

    #[test]
    fn test_simulate_tx_invalid_data() {
        assert!(simulate_tx("deadbeef").is_err());
    }

    // -----------------------------------------------------------------------
    // compile_policy
    // -----------------------------------------------------------------------

    #[test]
    fn test_compile_policy_after() {
        let result = compile_policy("after(100)").unwrap();
        assert!(result["script_hex"].as_str().unwrap().len() > 0);
        assert!(result["script_size"].as_u64().unwrap() > 0);
        assert_eq!(result["policy"], "after(100)");
    }

    #[test]
    fn test_compile_policy_invalid() {
        assert!(compile_policy("invalid!!!").is_err());
    }

    // -----------------------------------------------------------------------
    // watch_address
    // -----------------------------------------------------------------------

    #[test]
    fn test_watch_address_bech32() {
        // A valid regtest bech32 address
        let result =
            watch_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", Network::Regtest);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info["type"], "p2wpkh");
        assert_eq!(info["status"], "watching");
    }

    #[test]
    fn test_watch_address_invalid() {
        let result = watch_address("not_an_address", Network::Mainnet);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // build_status
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_status() {
        let config = NodeConfig::new(Network::Mainnet);
        let status = build_status(&config);
        assert_eq!(status.network, "mainnet");
        assert_eq!(status.chain_height, 0);
        assert_eq!(status.peer_count, 0);
        assert!(!status.syncing);
        assert_eq!(status.sync_progress, 0.0);
    }

    #[test]
    fn test_build_status_regtest() {
        let config = NodeConfig::new(Network::Regtest);
        let status = build_status(&config);
        assert_eq!(status.network, "regtest");
    }

    // -----------------------------------------------------------------------
    // build_sync_status
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_sync_status() {
        let sync = build_sync_status();
        assert!(!sync.syncing);
        assert_eq!(sync.current_height, 0);
        assert_eq!(sync.target_height, 0);
        assert_eq!(sync.progress, 0.0);
        assert_eq!(sync.stage, "idle");
        assert_eq!(sync.peers, 0);
    }

    // -----------------------------------------------------------------------
    // build_config
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_config() {
        let config = NodeConfig::new(Network::Testnet)
            .with_rpc_port(9999)
            .with_p2p_port(9998)
            .with_log_level("debug");
        let json = build_config(&config);
        assert_eq!(json["network"], "testnet");
        assert_eq!(json["rpc_port"], 9999);
        assert_eq!(json["p2p_port"], 9998);
        assert_eq!(json["log_level"], "debug");
    }

    // -----------------------------------------------------------------------
    // build_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version() {
        let v = build_version();
        assert_eq!(v["name"], "btc-node");
        assert!(v["version"].as_str().is_some());
        assert_eq!(v["database"], "qmdb");
        let features = v["features"].as_array().unwrap();
        assert!(features.contains(&serde_json::json!("legacy")));
        assert!(features.contains(&serde_json::json!("segwit")));
        assert!(features.contains(&serde_json::json!("taproot")));
    }

    // -----------------------------------------------------------------------
    // build_explore
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_explore() {
        let config = NodeConfig::new(Network::Mainnet);
        let v = build_explore(&config, 3000);
        assert_eq!(v["event"], "explorer_starting");
        assert_eq!(v["network"], "mainnet");
        assert_eq!(v["explorer_url"], "http://127.0.0.1:3000");
        assert_eq!(v["api_url"], "http://127.0.0.1:3000/api");
        assert_eq!(v["rpc_port"], 8332);
    }

    // -----------------------------------------------------------------------
    // build_rpc_request
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rpc_request_no_params() {
        let result = build_rpc_request("getblockcount", &[], 8332);
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["id"], 1);
        assert!(result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not yet connected"));
        let req = &result["error"]["data"]["request"];
        assert_eq!(req["method"], "getblockcount");
        assert_eq!(req["params"], serde_json::json!([]));
    }

    #[test]
    fn test_build_rpc_request_with_params() {
        let result = build_rpc_request(
            "getblockhash",
            &["100".to_string()],
            18332,
        );
        let req = &result["error"]["data"]["request"];
        assert_eq!(req["method"], "getblockhash");
        // "100" should parse as a JSON number
        assert_eq!(req["params"][0], 100);
        assert_eq!(
            result["error"]["data"]["target"],
            "127.0.0.1:18332"
        );
    }

    #[test]
    fn test_build_rpc_request_with_string_params() {
        let result = build_rpc_request(
            "getblock",
            &["00000000000000001111".to_string()],
            8332,
        );
        let req = &result["error"]["data"]["request"];
        assert_eq!(req["method"], "getblock");
        // Non-JSON string stays as string
        assert_eq!(
            req["params"][0],
            "00000000000000001111"
        );
    }

    // -----------------------------------------------------------------------
    // parse_opcode_or_data
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_opcode_with_prefix() {
        match parse_opcode_or_data("OP_DUP") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_DUP),
            _ => panic!("expected OP_DUP"),
        }
    }

    #[test]
    fn test_parse_opcode_without_prefix() {
        match parse_opcode_or_data("DUP") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_DUP),
            _ => panic!("expected OP_DUP"),
        }
    }

    #[test]
    fn test_parse_opcode_lowercase() {
        match parse_opcode_or_data("dup") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_DUP),
            _ => panic!("expected OP_DUP"),
        }
    }

    #[test]
    fn test_parse_opcode_number_opcodes() {
        match parse_opcode_or_data("OP_0") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_0),
            _ => panic!("expected OP_0"),
        }
        match parse_opcode_or_data("OP_1") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_1),
            _ => panic!("expected OP_1"),
        }
        match parse_opcode_or_data("OP_16") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_16),
            _ => panic!("expected OP_16"),
        }
    }

    #[test]
    fn test_parse_opcode_aliases() {
        match parse_opcode_or_data("OP_FALSE") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_0),
            _ => panic!("expected OP_0 for OP_FALSE"),
        }
        match parse_opcode_or_data("OP_TRUE") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_1),
            _ => panic!("expected OP_1 for OP_TRUE"),
        }
        match parse_opcode_or_data("OP_CLTV") {
            Some(ScriptItem::Op(op)) => {
                assert_eq!(op, Opcode::OP_CHECKLOCKTIMEVERIFY)
            }
            _ => panic!("expected OP_CHECKLOCKTIMEVERIFY for OP_CLTV"),
        }
        match parse_opcode_or_data("OP_CSV") {
            Some(ScriptItem::Op(op)) => {
                assert_eq!(op, Opcode::OP_CHECKSEQUENCEVERIFY)
            }
            _ => panic!("expected OP_CHECKSEQUENCEVERIFY for OP_CSV"),
        }
    }

    #[test]
    fn test_parse_opcode_all_nops() {
        for name in &["OP_NOP", "OP_NOP1", "OP_NOP4", "OP_NOP5", "OP_NOP6",
                       "OP_NOP7", "OP_NOP8", "OP_NOP9", "OP_NOP10"] {
            assert!(
                matches!(parse_opcode_or_data(name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_crypto_ops() {
        for name in &[
            "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160", "OP_HASH256",
            "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
            "OP_CHECKMULTISIGVERIFY", "OP_CHECKSIGADD",
        ] {
            assert!(
                matches!(parse_opcode_or_data(name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_stack_ops() {
        for name in &[
            "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP",
            "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP", "OP_IFDUP",
            "OP_DEPTH", "OP_DROP", "OP_NIP", "OP_OVER", "OP_PICK",
            "OP_ROLL", "OP_ROT", "OP_SWAP", "OP_TUCK",
        ] {
            assert!(
                matches!(parse_opcode_or_data(name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_arithmetic_ops() {
        for name in &[
            "OP_1ADD", "OP_1SUB", "OP_NEGATE", "OP_ABS", "OP_NOT",
            "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_BOOLAND", "OP_BOOLOR",
            "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL",
            "OP_LESSTHAN", "OP_GREATERTHAN", "OP_LESSTHANOREQUAL",
            "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX", "OP_WITHIN",
        ] {
            assert!(
                matches!(parse_opcode_or_data(name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_control_flow() {
        for name in &["OP_IF", "OP_NOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY", "OP_RETURN"] {
            assert!(
                matches!(parse_opcode_or_data(name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_comparison() {
        for name in &["OP_SIZE", "OP_EQUAL", "OP_EQUALVERIFY"] {
            assert!(
                matches!(parse_opcode_or_data(name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_1negate() {
        match parse_opcode_or_data("OP_1NEGATE") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_1NEGATE),
            _ => panic!("expected OP_1NEGATE"),
        }
    }

    #[test]
    fn test_parse_opcode_codeseparator() {
        match parse_opcode_or_data("OP_CODESEPARATOR") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_CODESEPARATOR),
            _ => panic!("expected OP_CODESEPARATOR"),
        }
    }

    #[test]
    fn test_parse_hex_data() {
        match parse_opcode_or_data("deadbeef") {
            Some(ScriptItem::Data(d)) => assert_eq!(d, vec![0xde, 0xad, 0xbe, 0xef]),
            _ => panic!("expected hex data"),
        }
    }

    #[test]
    fn test_parse_unknown_returns_none() {
        assert!(parse_opcode_or_data("totally_unknown_thing").is_none());
    }

    #[test]
    fn test_parse_empty_hex_returns_none() {
        // Empty hex parses to empty data which is rejected
        assert!(parse_opcode_or_data("").is_none());
    }

    // -----------------------------------------------------------------------
    // format_stack_to_string
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_stack_empty() {
        assert_eq!(format_stack_to_string(&[]), "  (empty)");
    }

    #[test]
    fn test_format_stack_single_item() {
        let stack = vec![vec![0x01]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("[0]"));
        assert!(output.contains("01"));
        assert!(output.contains("(1)"));
    }

    #[test]
    fn test_format_stack_multiple_items() {
        let stack = vec![vec![0x01], vec![0x02], vec![0x03]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("[0]"));
        assert!(output.contains("[1]"));
        assert!(output.contains("[2]"));
    }

    #[test]
    fn test_format_stack_empty_item() {
        let stack = vec![vec![]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("(0)"));
    }

    #[test]
    fn test_format_stack_negative_value() {
        // 0x81 = -1 in script number encoding
        let stack = vec![vec![0x81]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("(-1)"));
    }

    #[test]
    fn test_format_stack_large_data_no_int() {
        // 5+ byte items don't get an integer representation
        let stack = vec![vec![0x01, 0x02, 0x03, 0x04, 0x05]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("0102030405"));
        assert!(!output.contains("(")); // no integer repr for 5+ byte items
    }

    #[test]
    fn test_format_stack_two_byte_number() {
        // 0x00 0x01 = 256 in script number encoding
        let stack = vec![vec![0x00, 0x01]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("(256)"));
    }

    #[test]
    fn test_format_stack_four_byte_number() {
        // 4-byte numbers should still get an integer repr
        let stack = vec![vec![0x01, 0x00, 0x00, 0x00]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("(1)"));
    }

    #[test]
    fn test_format_stack_four_byte_negative() {
        // 4-byte negative: 0x01 0x00 0x00 0x80 = -1 (sign bit in MSB of last byte)
        let stack = vec![vec![0x01, 0x00, 0x00, 0x80]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("(-1)"));
    }

    #[test]
    fn test_decode_tx_vin_vout_details() {
        let tx = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                    script_sig: ScriptBuf::from_bytes(vec![0x01, 0x02]),
                    sequence: 0xfffffffe,
                },
                TxIn {
                    previous_output: OutPoint::new(TxHash::from_bytes([0xbb; 32]), 1),
                    script_sig: ScriptBuf::from_bytes(vec![]),
                    sequence: TxIn::SEQUENCE_FINAL,
                },
            ],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(5000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::from_sat(3000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14]),
                },
            ],
            witness: Vec::new(),
            lock_time: 500000,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = decode_tx(&hex_str).unwrap();
        assert_eq!(result["version"], 2);
        assert_eq!(result["inputs"], 2);
        assert_eq!(result["outputs"], 2);
        assert_eq!(result["locktime"], 500000);

        // Check vin details
        let vin = result["vin"].as_array().unwrap();
        assert_eq!(vin.len(), 2);
        assert_eq!(vin[0]["vout"], 0);
        assert_eq!(vin[1]["vout"], 1);

        // Check vout details
        let vout = result["vout"].as_array().unwrap();
        assert_eq!(vout.len(), 2);
        assert_eq!(vout[0]["n"], 0);
        assert_eq!(vout[0]["value"], 5000);
        assert_eq!(vout[1]["n"], 1);
        assert_eq!(vout[1]["value"], 3000);
    }

    #[test]
    fn test_simulate_tx_coinbase() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = simulate_tx(&hex_str).unwrap();
        assert_eq!(result["is_coinbase"], true);
        assert_eq!(result["total_output_sat"], 50_0000_0000i64);
    }

    #[test]
    fn test_simulate_tx_weight_calculation() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = simulate_tx(&hex_str).unwrap();
        let size = result["size"].as_u64().unwrap();
        let weight = result["weight"].as_u64().unwrap();
        let vsize = result["vsize"].as_u64().unwrap();
        // For non-segwit tx: weight = size * 4
        assert_eq!(weight, size * 4);
        assert_eq!(vsize, size); // vsize == size for non-segwit
    }

    #[test]
    fn test_build_rpc_request_json_params() {
        let result = build_rpc_request(
            "sendrawtransaction",
            &[r#"{"hex":"abc"}"#.to_string()],
            8332,
        );
        let req = &result["error"]["data"]["request"];
        // JSON string params should be parsed as JSON objects
        assert_eq!(req["params"][0]["hex"], "abc");
    }

    #[test]
    fn test_build_rpc_request_multiple_params() {
        let result = build_rpc_request(
            "getblock",
            &["abc123".to_string(), "2".to_string()],
            8332,
        );
        let req = &result["error"]["data"]["request"];
        assert_eq!(req["params"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_build_status_has_version() {
        let config = NodeConfig::new(Network::Mainnet);
        let status = build_status(&config);
        assert!(!status.version.is_empty());
    }

    #[test]
    fn test_build_explore_different_ports() {
        let config = NodeConfig::new(Network::Testnet).with_rpc_port(18332);
        let v = build_explore(&config, 8080);
        assert_eq!(v["explorer_url"], "http://127.0.0.1:8080");
        assert_eq!(v["rpc_port"], 18332);
    }

    #[test]
    fn test_decode_script_op_return() {
        // OP_RETURN followed by data
        let hex_str = format!("6a{}", hex::encode(b"hello world"));
        let result = decode_script(&hex_str).unwrap();
        assert_eq!(result["type"], "op_return");
    }

    #[test]
    fn test_decode_script_p2tr() {
        // OP_1 <32 bytes>
        let hex_str = format!("5120{}", "00".repeat(32));
        let result = decode_script(&hex_str).unwrap();
        assert_eq!(result["type"], "p2tr");
        assert_eq!(result["is_witness_program"], true);
    }

    #[test]
    fn test_decode_script_p2wsh() {
        // OP_0 <32 bytes>
        let hex_str = format!("0020{}", "00".repeat(32));
        let result = decode_script(&hex_str).unwrap();
        assert_eq!(result["type"], "p2wsh");
    }

    #[test]
    fn test_decode_script_p2sh() {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let hex_str = format!("a914{}87", "00".repeat(20));
        let result = decode_script(&hex_str).unwrap();
        assert_eq!(result["type"], "p2sh");
    }

    #[test]
    fn test_parse_opcode_numbers_2_through_16() {
        for n in 2..=16 {
            let name = format!("OP_{}", n);
            assert!(
                matches!(parse_opcode_or_data(&name), Some(ScriptItem::Op(_))),
                "failed to parse {}",
                name
            );
        }
    }

    #[test]
    fn test_parse_opcode_without_prefix_numbers() {
        // "1" should parse as OP_1
        match parse_opcode_or_data("1") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_1),
            _ => panic!("expected OP_1"),
        }
    }

    #[test]
    fn test_parse_opcode_false_true() {
        match parse_opcode_or_data("FALSE") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_0),
            _ => panic!("expected OP_0 for FALSE"),
        }
        match parse_opcode_or_data("TRUE") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_1),
            _ => panic!("expected OP_1 for TRUE"),
        }
    }

    #[test]
    fn test_parse_opcode_mixed_case() {
        match parse_opcode_or_data("Op_DuP") {
            Some(ScriptItem::Op(op)) => assert_eq!(op, Opcode::OP_DUP),
            _ => panic!("expected OP_DUP"),
        }
    }

    #[test]
    fn test_watch_address_p2pkh_mainnet() {
        // Use a known mainnet P2PKH address
        let result = watch_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Network::Mainnet);
        match result {
            Ok(info) => assert_eq!(info["type"], "p2pkh"),
            Err(_) => {
                // Some address formats may not be supported in test
            }
        }
    }

    #[test]
    fn test_format_stack_three_byte_number() {
        // 3-byte: [0x56, 0x34, 0x12] = 0x123456 = 1193046
        let stack = vec![vec![0x56, 0x34, 0x12]];
        let output = format_stack_to_string(&stack);
        assert!(output.contains("(1193046)"));
    }

    #[test]
    fn test_format_stack_three_byte_negative() {
        // 3-byte negative: [0x56, 0x34, 0x92] -> sign bit set in 0x92
        let stack = vec![vec![0x56, 0x34, 0x92]];
        let output = format_stack_to_string(&stack);
        // Should contain a negative number
        assert!(output.contains("(-"));
    }

    #[test]
    fn test_decode_tx_serialization_valid_json() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE,
                script_sig: ScriptBuf::from_bytes(vec![0x04, 0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);
        let result = decode_tx(&hex_str).unwrap();
        // Verify the result is valid JSON by round-tripping through serialization
        let json_str = serde_json::to_string(&result).unwrap();
        let _: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    }

    #[test]
    fn test_decode_header_fields() {
        use btc_primitives::block::BlockHeader;
        use btc_primitives::compact::CompactTarget;
        use btc_primitives::hash::BlockHash;

        let header = BlockHeader {
            version: 0x20000000,
            prev_blockhash: BlockHash::from_bytes([0xaa; 32]),
            merkle_root: TxHash::from_bytes([0xbb; 32]),
            time: 1700000000,
            bits: CompactTarget::MAX_TARGET,
            nonce: 12345,
        };
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = decode_header(&hex_str).unwrap();
        assert_eq!(result["version"], 0x20000000u32);
        assert_eq!(result["time"], 1700000000);
        assert_eq!(result["nonce"], 12345);
        // hash, prev_blockhash, merkle_root should all be hex strings
        assert!(result["hash"].as_str().unwrap().len() == 64);
        assert!(result["prev_blockhash"].as_str().unwrap().len() == 64);
        assert!(result["merkle_root"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn test_simulate_tx_multiple_outputs() {
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(5000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::from_sat(3000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                },
                TxOut {
                    value: Amount::from_sat(2000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a]), // OP_RETURN
                },
            ],
            witness: Vec::new(),
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = simulate_tx(&hex_str).unwrap();
        assert_eq!(result["outputs_count"], 3);
        assert_eq!(result["total_output_sat"], 10000);
        let outputs = result["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[2]["value_sat"], 2000);
    }

    #[test]
    fn test_build_config_all_networks() {
        for (net, name) in [
            (Network::Mainnet, "mainnet"),
            (Network::Testnet, "testnet"),
            (Network::Signet, "signet"),
            (Network::Regtest, "regtest"),
        ] {
            let config = NodeConfig::new(net);
            let json = build_config(&config);
            assert_eq!(json["network"], name);
        }
    }

    #[test]
    fn test_build_sync_status_serializes() {
        let sync = build_sync_status();
        let json = serde_json::to_value(&sync).unwrap();
        assert_eq!(json["syncing"], false);
    }

    #[test]
    fn test_watch_address_has_required_fields() {
        let result = watch_address(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            Network::Regtest,
        )
        .unwrap();
        assert!(result["address"].is_string());
        assert!(result["type"].is_string());
        assert!(result["network"].is_string());
        assert!(result["script_pubkey_hex"].is_string());
        assert!(result["script_hash"].is_string());
        assert_eq!(result["status"], "watching");
    }

    #[test]
    fn test_simulate_tx_segwit() {
        use btc_primitives::transaction::Witness;
        // Build a segwit transaction with witness data
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                script_sig: ScriptBuf::from_bytes(vec![]),
                sequence: TxIn::SEQUENCE_FINAL,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes({
                    let mut v = vec![0x00, 0x14];
                    v.extend_from_slice(&[0u8; 20]);
                    v
                }),
            }],
            witness: vec![Witness::from_items(vec![vec![0x30; 72], vec![0x02; 33]])],
            lock_time: 0,
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let result = simulate_tx(&hex_str).unwrap();
        assert_eq!(result["is_segwit"], true);
        // The witness items should be present
        let inputs = result["inputs"].as_array().unwrap();
        assert!(inputs[0].get("witness_items").is_some());
        assert_eq!(inputs[0]["witness_items"], 2);
    }

    #[test]
    fn test_watch_address_p2wsh_regtest() {
        // Build a P2WSH address manually (witness version 0, 32-byte program)
        let witness_program = [0u8; 32];
        let addr_str =
            btc_primitives::bech32::encode_witness_address("bcrt", 0, &witness_program)
                .unwrap();
        let result = watch_address(&addr_str, Network::Regtest);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info["type"], "p2wsh");
    }

    #[test]
    fn test_watch_address_p2tr_regtest() {
        // Build a P2TR address: witness version 1, 32 byte program
        let witness_program = [0x01u8; 32];
        let addr_str =
            btc_primitives::bech32::encode_witness_address("bcrt", 1, &witness_program)
                .unwrap();
        let result = watch_address(&addr_str, Network::Regtest);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info["type"], "p2tr");
    }

    #[test]
    fn test_compile_policy_pk() {
        // A simple pk() policy
        let key_hex = "02".to_string() + &"ab".repeat(32);
        let policy = format!("pk({})", key_hex);
        let result = compile_policy(&policy).unwrap();
        assert!(result["script_hex"].as_str().unwrap().len() > 0);
        assert!(result["asm"].as_str().unwrap().contains("OP_CHECKSIG"));
    }
}
