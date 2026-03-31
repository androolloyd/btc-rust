//! Script weight and cost analysis utilities.

use btc_primitives::script::{Instruction, Opcode, Script};

/// Analysis result for a Bitcoin script.
#[derive(Debug, Clone)]
pub struct ScriptAnalysis {
    /// Total size of the script in bytes.
    pub size_bytes: usize,
    /// Number of opcodes (excluding data pushes).
    pub op_count: usize,
    /// Maximum stack depth reached during static analysis.
    pub max_stack_depth: usize,
    /// Whether the script contains any signature-checking opcodes.
    pub has_signature_ops: bool,
    /// Total number of signature operations (sigops).
    pub sigop_count: usize,
    /// Branches found via IF/ELSE/ENDIF analysis.
    pub branches: Vec<ScriptBranch>,
}

/// A branch discovered during script analysis.
#[derive(Debug, Clone)]
pub struct ScriptBranch {
    /// A human-readable description of the branch condition.
    pub condition: String,
    /// Opcodes present in this branch.
    pub ops: Vec<Opcode>,
}

/// Analyze a script and return a [`ScriptAnalysis`].
///
/// This performs static analysis only -- no execution occurs. Stack depth
/// estimation is approximate (it does not follow branches).
pub fn analyze_script(script: &Script) -> ScriptAnalysis {
    let bytes = script.as_bytes();
    let size_bytes = bytes.len();

    let mut op_count: usize = 0;
    let mut sigop_count: usize = 0;
    let mut has_signature_ops = false;
    let mut stack_depth: usize = 0;
    let mut max_stack_depth: usize = 0;

    // Branch tracking state.
    let mut branches: Vec<ScriptBranch> = Vec::new();
    let mut current_branch_ops: Vec<Opcode> = Vec::new();
    let mut in_branch = false;
    let mut branch_depth: usize = 0;
    let mut last_n_keys: usize = 0; // for CHECKMULTISIG sigop counting

    for instr in script.instructions() {
        match instr {
            Ok(Instruction::Op(op)) => {
                op_count += 1;
                current_branch_ops.push(op);

                match op {
                    // Signature operations
                    Opcode::OP_CHECKSIG | Opcode::OP_CHECKSIGVERIFY => {
                        has_signature_ops = true;
                        sigop_count += 1;
                    }
                    Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY => {
                        has_signature_ops = true;
                        // Sigops count = number of public keys in the multisig.
                        // If we can determine it from the preceding OP_N, use that;
                        // otherwise conservatively count 20 (MAX_PUBKEYS_PER_MULTISIG).
                        if last_n_keys > 0 {
                            sigop_count += last_n_keys;
                        } else {
                            sigop_count += 20;
                        }
                    }
                    Opcode::OP_CHECKSIGADD => {
                        has_signature_ops = true;
                        sigop_count += 1;
                    }

                    // Branch tracking
                    Opcode::OP_IF | Opcode::OP_NOTIF => {
                        in_branch = true;
                        branch_depth += 1;
                        // Save current branch and start a new one.
                        if !current_branch_ops.is_empty() {
                            branches.push(ScriptBranch {
                                condition: format!(
                                    "{:?} (depth {})",
                                    op, branch_depth
                                ),
                                ops: std::mem::take(&mut current_branch_ops),
                            });
                        }
                    }
                    Opcode::OP_ELSE => {
                        if in_branch && !current_branch_ops.is_empty() {
                            branches.push(ScriptBranch {
                                condition: format!(
                                    "ELSE (depth {})",
                                    branch_depth
                                ),
                                ops: std::mem::take(&mut current_branch_ops),
                            });
                        }
                    }
                    Opcode::OP_ENDIF => {
                        if branch_depth > 0 {
                            branch_depth -= 1;
                            if branch_depth == 0 {
                                in_branch = false;
                            }
                        }
                        if !current_branch_ops.is_empty() {
                            branches.push(ScriptBranch {
                                condition: format!(
                                    "ENDIF (depth {})",
                                    branch_depth + 1
                                ),
                                ops: std::mem::take(&mut current_branch_ops),
                            });
                        }
                    }

                    // Stack depth estimation (simplified).
                    Opcode::OP_DUP | Opcode::OP_OVER | Opcode::OP_TUCK => {
                        stack_depth += 1;
                    }
                    Opcode::OP_2DUP => {
                        stack_depth += 2;
                    }
                    Opcode::OP_3DUP => {
                        stack_depth += 3;
                    }
                    Opcode::OP_DROP | Opcode::OP_NIP => {
                        stack_depth = stack_depth.saturating_sub(1);
                    }
                    Opcode::OP_2DROP => {
                        stack_depth = stack_depth.saturating_sub(2);
                    }

                    // Number opcodes -- track N for multisig counting.
                    Opcode::OP_1 | Opcode::OP_2 | Opcode::OP_3 | Opcode::OP_4
                    | Opcode::OP_5 | Opcode::OP_6 | Opcode::OP_7 | Opcode::OP_8
                    | Opcode::OP_9 | Opcode::OP_10 | Opcode::OP_11 | Opcode::OP_12
                    | Opcode::OP_13 | Opcode::OP_14 | Opcode::OP_15 | Opcode::OP_16 => {
                        last_n_keys = (op as u8 - Opcode::OP_1 as u8 + 1) as usize;
                        stack_depth += 1;
                    }
                    Opcode::OP_0 => {
                        last_n_keys = 0;
                        stack_depth += 1;
                    }

                    // Arithmetic / comparison ops consume 2, push 1 => net -1
                    Opcode::OP_ADD | Opcode::OP_SUB | Opcode::OP_EQUAL
                    | Opcode::OP_NUMEQUAL | Opcode::OP_BOOLAND | Opcode::OP_BOOLOR
                    | Opcode::OP_LESSTHAN | Opcode::OP_GREATERTHAN
                    | Opcode::OP_MIN | Opcode::OP_MAX => {
                        stack_depth = stack_depth.saturating_sub(1);
                    }

                    _ => {}
                }

                max_stack_depth = max_stack_depth.max(stack_depth);
            }
            Ok(Instruction::PushBytes(data)) => {
                // Data pushes add one item to the stack.
                stack_depth += 1;
                max_stack_depth = max_stack_depth.max(stack_depth);

                // Track data size for potential multisig N detection.
                if data.len() == 1 && data[0] <= 16 {
                    last_n_keys = data[0] as usize;
                }
            }
            Err(_) => break,
        }
    }

    // Flush any remaining branch ops.
    if !current_branch_ops.is_empty() {
        branches.push(ScriptBranch {
            condition: "main".to_string(),
            ops: current_branch_ops,
        });
    }

    ScriptAnalysis {
        size_bytes,
        op_count,
        max_stack_depth,
        has_signature_ops,
        sigop_count,
        branches,
    }
}

/// Estimate the witness weight in weight units for a given set of witness
/// items. Each item contributes its length as a varint plus the item bytes.
pub fn estimate_witness_weight(witness: &[Vec<u8>]) -> usize {
    if witness.is_empty() {
        return 0;
    }
    // Witness count varint.
    let mut weight = varint_size(witness.len());
    for item in witness {
        weight += varint_size(item.len()) + item.len();
    }
    weight
}

/// Size of a compact-size (varint) encoding of `n`.
fn varint_size(n: usize) -> usize {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}
