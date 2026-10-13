//! Core-compatible transaction views over actual transactions and block undo.
//! Formatting is descriptive: inferred descriptors carry no wallet ownership.

use std::collections::HashMap;

use btc_consensus::utxo::UtxoEntry;
use btc_primitives::address::Address;
use btc_primitives::bech32::encode_witness_address;
use btc_primitives::descriptor::descriptor_checksum;
use btc_primitives::encode::encode;
use btc_primitives::network::Network;
use btc_primitives::script::{Opcode, Script};
use btc_primitives::transaction::{OutPoint, Transaction};
use btc_rpc::handler::{RpcError, INTERNAL_ERROR};
use serde_json::{json, Value};

fn corrupt(message: &str) -> RpcError {
    RpcError::new(INTERNAL_ERROR, message)
}

/// An amount remains a decimal JSON number, with all eight satoshi places.
fn amount(sat: i64) -> Value {
    serde_json::from_str(&format!("{}.{:08}", sat / 100_000_000, sat % 100_000_000))
        .expect("nonnegative bounded Bitcoin amount")
}

// Unlike ScriptInstructions, retain unknown opcode bytes for OP_UNKNOWN and
// distinguish empty pushes from OP_0. No consensus interpretation is performed.
fn instruction<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let op = *bytes.get(*pos)?;
    *pos += 1;
    let len = match op {
        0..=75 => op as usize,
        76..=78 => {
            let count = 1 << (op - 76);
            let size = bytes.get(*pos..pos.checked_add(count)?)?;
            *pos += count;
            size.iter()
                .enumerate()
                .fold(0usize, |n, (i, b)| n | ((*b as usize) << (8 * i)))
        }
        _ => return Some((op, &[])),
    };
    let data = bytes.get(*pos..pos.checked_add(len)?)?;
    *pos += len;
    Some((op, data))
}

fn script_number(data: &[u8]) -> i64 {
    let value = data
        .iter()
        .enumerate()
        .fold(0i64, |n, (i, b)| n | ((*b as i64) << (8 * i)));
    if data.last().is_some_and(|b| b & 0x80 != 0) {
        -(value & !(0x80 << (8 * (data.len() - 1))))
    } else {
        value
    }
}

// Core's STRICTENC disassembly checks DER structure and the hash type, not the
// scalar values or the signature equation. This helper is never a verifier.
fn signature_suffix(sig: &[u8]) -> Option<&'static str> {
    if !(9..=73).contains(&sig.len())
        || sig[0] != 0x30
        || sig[1] as usize != sig.len() - 3
        || sig[2] != 2
    {
        return None;
    }
    let r = sig[3] as usize;
    if r == 0
        || r + 5 >= sig.len()
        || sig[4] & 0x80 != 0
        || (r > 1 && sig[4] == 0 && sig[5] & 0x80 == 0)
        || sig[r + 4] != 2
    {
        return None;
    }
    let s = sig[r + 5] as usize;
    if s == 0
        || r + s + 7 != sig.len()
        || sig[r + 6] & 0x80 != 0
        || (s > 1 && sig[r + 6] == 0 && sig[r + 7] & 0x80 == 0)
    {
        return None;
    }
    match sig[sig.len() - 1] {
        1 => Some("ALL"),
        2 => Some("NONE"),
        3 => Some("SINGLE"),
        0x81 => Some("ALL|ANYONECANPAY"),
        0x82 => Some("NONE|ANYONECANPAY"),
        0x83 => Some("SINGLE|ANYONECANPAY"),
        _ => None,
    }
}

fn asm(script: &Script, decode_sighash: bool) -> String {
    let bytes = script.as_bytes();
    let mut pos = 0;
    let mut parts = Vec::new();
    while pos < bytes.len() {
        let Some((op, data)) = instruction(bytes, &mut pos) else {
            parts.push("[error]".into());
            break;
        };
        parts.push(match op {
            0..=78 if data.len() <= 4 => script_number(data).to_string(),
            0..=78 => {
                if let Some(suffix) =
                    (decode_sighash && !script.is_op_return() && bytes.len() <= 10_000)
                        .then(|| signature_suffix(data))
                        .flatten()
                {
                    format!("{}[{suffix}]", hex::encode(&data[..data.len() - 1]))
                } else {
                    hex::encode(data)
                }
            }
            79 => "-1".into(),
            81..=96 => (op - 80).to_string(),
            0xff => "OP_INVALIDOPCODE".into(),
            _ => {
                let known = Opcode::from_u8(op);
                if known == Opcode::OP_INVALIDOPCODE {
                    "OP_UNKNOWN".into()
                } else {
                    format!("{known:?}")
                }
            }
        });
    }
    parts.join(" ")
}

fn key_size(key: &[u8]) -> bool {
    matches!(
        (key.first(), key.len()),
        (Some(2 | 3), 33) | (Some(4 | 6 | 7), 65)
    )
}

fn small_number(op: u8, data: &[u8]) -> Option<usize> {
    match op {
        81..=96 => Some((op - 80) as usize),
        1 if data.len() == 1 && (17..=20).contains(&data[0]) => Some(data[0] as usize),
        _ => None,
    }
}

fn multisig(bytes: &[u8]) -> Option<(usize, Vec<&[u8]>)> {
    if bytes.last() != Some(&0xae) {
        return None;
    }
    let mut pos = 0;
    let (op, data) = instruction(bytes, &mut pos)?;
    let required = small_number(op, data)?;
    let mut keys = Vec::new();
    loop {
        let (op, data) = instruction(bytes, &mut pos)?;
        if op <= 78 && key_size(data) {
            keys.push(data);
            if keys.len() > 20 {
                return None;
            }
        } else {
            let count = small_number(op, data)?;
            return (count == keys.len() && required <= count && pos + 1 == bytes.len())
                .then_some((required, keys));
        }
    }
}

pub(crate) fn script_pubkey_json(script: &Script, network: Network) -> Value {
    let bytes = script.as_bytes();
    let mut address = None;
    let mut descriptor = None;
    let kind = if script.is_p2pkh() {
        address = Some(
            Address::P2pkh {
                hash: bytes[3..23].try_into().unwrap(),
                network,
            }
            .to_string(),
        );
        "pubkeyhash"
    } else if script.is_p2sh() {
        address = Some(
            Address::P2sh {
                hash: bytes[2..22].try_into().unwrap(),
                network,
            }
            .to_string(),
        );
        "scripthash"
    } else if script.is_witness_program() {
        let version = if bytes[0] == 0 { 0 } else { bytes[0] - 80 };
        let program = &bytes[2..];
        if version != 0 || matches!(program.len(), 20 | 32) {
            address = Some(
                encode_witness_address(network.bech32_hrp(), version, program)
                    .expect("valid witness program"),
            );
        }
        match (version, program.len()) {
            (0, 20) => "witness_v0_keyhash",
            (0, 32) => "witness_v0_scripthash",
            (0, _) => "nonstandard",
            (1, 32) => {
                if secp256k1::XOnlyPublicKey::from_slice(program).is_ok() {
                    descriptor = Some(format!("rawtr({})", hex::encode(program)));
                }
                "witness_v1_taproot"
            }
            _ if script.is_p2a() => "anchor",
            _ => "witness_unknown",
        }
    } else if matches!(bytes.len(), 35 | 67)
        && bytes[0] as usize == bytes.len() - 2
        && bytes.last() == Some(&0xac)
        && key_size(&bytes[1..bytes.len() - 1])
    {
        let key = &bytes[1..bytes.len() - 1];
        // Core's dummy-provider inference preserves structurally encoded legacy
        // key bytes even if they are not curve points. This is a description of
        // the actual script, never a key-validity or wallet-ownership receipt.
        descriptor = Some(format!("pk({})", hex::encode(key)));
        "pubkey"
    } else if let Some((required, keys)) = multisig(bytes) {
        descriptor = Some(format!(
            "multi({required},{})",
            keys.iter().map(hex::encode).collect::<Vec<_>>().join(",")
        ));
        "multisig"
    } else if script.is_op_return() && {
        let mut pos = 1;
        let mut push_only = true;
        while pos < bytes.len() {
            if instruction(bytes, &mut pos).is_none_or(|(op, _)| op > 96) {
                push_only = false;
                break;
            }
        }
        push_only
    } {
        "nulldata"
    } else {
        "nonstandard"
    };
    let desc = descriptor.unwrap_or_else(|| match &address {
        Some(addr) => format!("addr({addr})"),
        None => format!("raw({})", hex::encode(bytes)),
    });
    let checksum = descriptor_checksum(&desc).expect("generated descriptor alphabet");
    let mut result = json!({"asm": asm(script, false), "desc": format!("{desc}#{checksum}"), "hex": hex::encode(bytes), "type": kind});
    if let Some(address) = address {
        result["address"] = json!(address);
    }
    result
}

pub(crate) fn transaction_json(
    tx: &Transaction,
    network: Network,
    undo: Option<&HashMap<OutPoint, UtxoEntry>>,
    show_prevouts: bool,
) -> Result<Value, RpcError> {
    let undo = undo.filter(|_| !tx.is_coinbase());
    let mut input_sum = 0i64;
    let mut vin = Vec::with_capacity(tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        let mut value = if tx.is_coinbase() {
            json!({"coinbase": hex::encode(input.script_sig.as_bytes())})
        } else {
            json!({"txid": input.previous_output.txid.to_string(), "vout": input.previous_output.vout,
                "scriptSig": {"asm": asm(&input.script_sig, true), "hex": hex::encode(input.script_sig.as_bytes())}})
        };
        value["sequence"] = json!(input.sequence);
        if let Some(witness) = tx.witness.get(i).filter(|w| !w.is_empty()) {
            value["txinwitness"] = json!(witness.iter().map(hex::encode).collect::<Vec<_>>());
        }
        if let Some(undo) = undo {
            let coin = undo
                .get(&input.previous_output)
                .ok_or_else(|| corrupt("transaction input missing from block undo"))?;
            input_sum = input_sum
                .checked_add(coin.txout.value.as_sat())
                .ok_or_else(|| corrupt("undo amount overflow"))?;
            if show_prevouts {
                value["prevout"] = json!({"generated": coin.is_coinbase, "height": coin.height,
                    "value": amount(coin.txout.value.as_sat()), "scriptPubKey": script_pubkey_json(&coin.txout.script_pubkey, network)});
            }
        }
        vin.push(value);
    }
    let vout: Vec<_> = tx.outputs.iter().enumerate().map(|(i, output)| json!({
        "n": i, "value": amount(output.value.as_sat()), "scriptPubKey": script_pubkey_json(&output.script_pubkey, network)
    })).collect();
    let raw = encode(tx);
    let mut result = json!({"txid": tx.txid().to_string(), "hash": tx.wtxid().to_string(),
        "version": tx.version, "size": raw.len(), "vsize": tx.weight().div_ceil(4), "weight": tx.weight(),
        "locktime": tx.lock_time, "vin": vin, "vout": vout, "hex": hex::encode(raw)});
    if undo.is_some() {
        let output_sum = tx
            .outputs
            .iter()
            .try_fold(0i64, |sum, out| sum.checked_add(out.value.as_sat()))
            .ok_or_else(|| corrupt("transaction amount overflow"))?;
        let fee = input_sum
            .checked_sub(output_sum)
            .filter(|fee| (0..=2_100_000_000_000_000).contains(fee))
            .ok_or_else(|| corrupt("invalid transaction fee in block undo"))?;
        result["fee"] = amount(fee);
    }
    Ok(result)
}

pub(crate) fn verbosity(params: &Value, default: i32) -> Result<i32, RpcError> {
    match params.get(1) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(i32::from(*value)),
        Some(value @ Value::Number(_)) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| RpcError::new(-1, "JSON integer out of range")),
        Some(_) => Err(RpcError::new(-3, "verbosity must be a number or boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::script::ScriptBuf;

    #[test]
    fn disassembly_keeps_numeric_unknown_and_malformed_boundaries() {
        for (raw, expected) in [
            ("004f515f607661b1b2baffbc", "0 -1 1 15 16 OP_DUP OP_NOP OP_CHECKLOCKTIMEVERIFY OP_CHECKSEQUENCEVERIFY OP_CHECKSIGADD OP_INVALIDOPCODE OP_UNKNOWN"),
            ("4c000180018004ffffff7f04ffffffff", "0 -0 0 2147483647 -2147483647"),
            ("514e01000000", "1 [error]"),
            ("514d00", "1 [error]"),
            ("514c05ff", "1 [error]"),
        ] {
            let script = ScriptBuf::from_bytes(hex::decode(raw).unwrap());
            // Signed magnitude negative zero is rendered as numeric zero.
            assert_eq!(asm(&script, false), expected.replace("-0", "0"));
        }
    }

    #[test]
    fn signature_disassembly_only_labels_strict_der_and_defined_hash_types() {
        for (hash, suffix) in [
            (1, "ALL"),
            (2, "NONE"),
            (3, "SINGLE"),
            (0x81, "ALL|ANYONECANPAY"),
            (0x82, "NONE|ANYONECANPAY"),
            (0x83, "SINGLE|ANYONECANPAY"),
        ] {
            let mut sig = hex::decode("3006020100020100").unwrap();
            sig.push(hash);
            let mut script = ScriptBuf::new();
            script.push_slice(&sig);
            assert_eq!(asm(&script, true), format!("3006020100020100[{suffix}]"));
            assert_eq!(asm(&script, false), hex::encode(&sig));
            let mut ret = vec![0x6a];
            ret.extend_from_slice(script.as_bytes());
            assert_eq!(
                asm(Script::from_bytes(&ret), true),
                format!("OP_RETURN {}", hex::encode(&sig))
            );
        }
        for raw in [
            "300602010002010080",
            "300602018002010001",
            "30070202000002010001",
            "300602010002010001ff",
        ] {
            let bytes = hex::decode(raw).unwrap();
            assert!(signature_suffix(&bytes).is_none());
        }
    }

    #[test]
    fn inferred_descriptors_preserve_actual_bytes_without_claiming_key_validity() {
        let tr = ScriptBuf::p2tr(&[0xff; 32]);
        let result = script_pubkey_json(&tr, Network::Regtest);
        assert_eq!(result["type"], "witness_v1_taproot");
        assert!(result["desc"].as_str().unwrap().starts_with("addr(bcrt1p"));
        let mut bytes = vec![33, 2];
        bytes.extend([0xff; 32]);
        bytes.push(0xac);
        let result = script_pubkey_json(Script::from_bytes(&bytes), Network::Mainnet);
        assert_eq!(result["type"], "pubkey");
        assert!(result["desc"]
            .as_str()
            .unwrap()
            .starts_with("pk(02ffffffff"));
        assert!(result.get("address").is_none());
        for raw in ["6a4c", "6a76", "00024e73"] {
            assert_eq!(
                script_pubkey_json(
                    Script::from_bytes(&hex::decode(raw).unwrap()),
                    Network::Regtest
                )["type"],
                "nonstandard"
            );
        }
    }

    #[test]
    fn verbosity_does_not_silently_replace_invalid_arguments() {
        for (arg, expected) in [
            (Value::Null, 1),
            (json!(false), 0),
            (json!(true), 1),
            (json!(-1), -1),
            (json!(4), 4),
        ] {
            assert_eq!(verbosity(&json!(["hash", arg]), 1).unwrap(), expected);
        }
        for arg in [
            json!(1.5),
            json!("2"),
            json!({}),
            json!([]),
            json!(2147483648u64),
        ] {
            let expected = if arg.is_number() { -1 } else { -3 };
            assert_eq!(
                verbosity(&json!(["hash", arg]), 1).unwrap_err().code,
                expected
            );
        }
    }
}
