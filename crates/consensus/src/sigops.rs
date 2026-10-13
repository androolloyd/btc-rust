//! Core-compatible static legacy/P2SH/witness-v0 signature-operation costs.
//! Tapscript uses its per-input dynamic budget instead of this block counter.

use crate::script_engine::ScriptFlags;
use btc_primitives::{
    script::{Instruction, Opcode, Script},
    transaction::{Transaction, TxOut, Witness},
};

pub const MAX_BLOCK_SIGOPS_COST: usize = 80_000;
pub const MAX_STANDARD_TX_SIGOPS_COST: usize = 16_000;
pub const MAX_P2SH_SIGOPS: usize = 15;
pub const DEFAULT_BYTES_PER_SIGOP: usize = 20;

/// Count decoded opcodes even in unexecuted branches, stopping at malformed
/// pushes. Push contents and CHECKSIGADD never contribute to this counter.
pub fn script_sigops(script: &Script, accurate: bool) -> usize {
    let mut count = 0usize;
    let mut previous = Opcode::OP_INVALIDOPCODE;
    for instruction in script.instructions() {
        let opcode = match instruction {
            Ok(Instruction::Op(opcode)) => opcode,
            Ok(Instruction::PushBytes(_)) => Opcode::OP_PUSHDATA1,
            Err(_) => break,
        };
        let cost = match opcode {
            Opcode::OP_CHECKSIG | Opcode::OP_CHECKSIGVERIFY => 1,
            Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY => {
                if accurate
                    && (Opcode::OP_1 as u8..=Opcode::OP_16 as u8).contains(&(previous as u8))
                {
                    previous as usize - Opcode::OP_1 as usize + 1
                } else {
                    20
                }
            }
            _ => 0,
        };
        count = count.saturating_add(cost);
        previous = opcode;
    }
    count
}

/// Core GetOp clears data for small integer/reserved opcodes too. This is
/// static counting, not execution or a proof of the redeem-script commitment.
fn last_push(script: &Script) -> Option<&Script> {
    let mut data = &[][..];
    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::PushBytes(bytes)) => data = bytes,
            Ok(Instruction::Op(op)) if op as u8 <= Opcode::OP_16 as u8 => data = &[],
            _ => return None,
        }
    }
    Some(Script::from_bytes(data))
}

pub fn legacy_sigop_cost(tx: &Transaction) -> usize {
    tx.inputs
        .iter()
        .map(|input| script_sigops(input.script_sig.as_script(), false))
        .chain(
            tx.outputs
                .iter()
                .map(|output| script_sigops(output.script_pubkey.as_script(), false)),
        )
        .fold(0usize, usize::saturating_add)
        .saturating_mul(4)
}

pub fn p2sh_sigops(script_sig: &Script, previous: &Script) -> usize {
    if previous.is_p2sh() {
        last_push(script_sig).map_or(0, |script| script_sigops(script, true))
    } else {
        0
    }
}

pub fn input_sigop_cost(
    script_sig: &Script,
    previous: &Script,
    witness: Option<&Witness>,
    flags: &ScriptFlags,
) -> usize {
    let redeem = previous.is_p2sh().then(|| last_push(script_sig)).flatten();
    let mut cost = if flags.verify_p2sh {
        redeem.map_or(0, |script| script_sigops(script, true).saturating_mul(4))
    } else {
        0
    };
    if flags.verify_witness {
        let program = if previous.is_witness_program() {
            Some(previous)
        } else if flags.verify_p2sh {
            redeem.filter(|script| script.is_witness_program())
        } else {
            None
        };
        if let Some(program) = program {
            // Only version zero contributes: Taproot/future versions do not.
            if program.as_bytes()[0] == 0 {
                cost = cost.saturating_add(match program.len() {
                    22 => 1, // P2WPKH costs one even with missing/invalid witness.
                    34 => witness
                        .and_then(|items| items.iter().last())
                        .map_or(0, |script| script_sigops(Script::from_bytes(script), true)),
                    _ => 0,
                });
            }
        }
    }
    cost
}

/// The aligned prevouts must be complete, including for inputs whose scripts
/// ultimately fail execution. Coinbase has no previous-output contribution.
pub fn transaction_sigop_cost(
    tx: &Transaction,
    prevouts: &[TxOut],
    flags: &ScriptFlags,
) -> Result<usize, &'static str> {
    let mut cost = legacy_sigop_cost(tx);
    if tx.is_coinbase() {
        return Ok(cost);
    }
    if prevouts.len() != tx.inputs.len() {
        return Err("signature-operation counting requires every prevout");
    }
    for (index, (input, previous)) in tx.inputs.iter().zip(prevouts).enumerate() {
        cost = cost.saturating_add(input_sigop_cost(
            input.script_sig.as_script(),
            previous.script_pubkey.as_script(),
            tx.witness.get(index),
            flags,
        ));
    }
    Ok(cost)
}

/// Core policy size includes the signature-operation resource cost.
pub fn virtual_size(weight: usize, sigop_cost: usize) -> usize {
    weight
        .max(sigop_cost.saturating_mul(DEFAULT_BYTES_PER_SIGOP))
        .div_ceil(4)
}
