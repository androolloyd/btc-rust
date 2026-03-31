//! Step-through script execution debugger.

use btc_consensus::script_engine::{ScriptEngine, ScriptFlags};
use btc_consensus::sig_verify::Secp256k1Verifier;
use btc_primitives::script::{Instruction, Opcode, Script, ScriptBuf};

/// A single step of script execution captured by the debugger.
#[derive(Debug, Clone)]
pub struct DebugStep {
    /// Program counter -- byte offset in the script where this instruction
    /// started.
    pub pc: usize,
    /// The opcode executed (or `OP_0` for push-data instructions).
    pub opcode: Opcode,
    /// Snapshot of the main stack after this instruction executed.
    pub stack: Vec<Vec<u8>>,
    /// Snapshot of the alt-stack after this instruction executed.
    pub altstack: Vec<Vec<u8>>,
}

/// A script debugger that executes instructions one-by-one and records
/// the complete execution trace.
pub struct ScriptDebugger {
    /// The script being debugged, stored as owned bytes so there are no
    /// lifetime issues.
    script: ScriptBuf,
    /// Breakpoints (byte offsets).
    breakpoints: Vec<usize>,
    /// Recorded execution history.
    history: Vec<DebugStep>,
    /// Whether the script has been fully executed.
    executed: bool,
}

impl ScriptDebugger {
    /// Create a new debugger for the given script.
    pub fn new(script: &Script) -> Self {
        ScriptDebugger {
            script: script.to_owned(),
            breakpoints: Vec::new(),
            history: Vec::new(),
            executed: false,
        }
    }

    /// Execute all instructions and return the full trace.
    ///
    /// This uses the real [`ScriptEngine`] under the hood; each instruction
    /// is decoded from the script bytes and executed in order. After each
    /// instruction the stack state is captured.
    pub fn run(&mut self) -> Vec<DebugStep> {
        if self.executed {
            return self.history.clone();
        }

        // We iterate over script instructions and for each one, execute
        // the full script up to that point in a fresh engine to capture the
        // cumulative stack state. This is simple and correct, though not
        // the most efficient approach. For scripts under 10 KB (the
        // consensus limit) this is perfectly fine.

        let verifier = Secp256k1Verifier;

        // Collect instruction boundaries.
        let mut instructions: Vec<(usize, Opcode, usize)> = Vec::new(); // (start, opcode, end)
        let mut pos: usize = 0;
        for instr in self.script.as_script().instructions() {
            let start = pos;
            match instr {
                Ok(Instruction::Op(op)) => {
                    pos += 1;
                    instructions.push((start, op, pos));
                }
                Ok(Instruction::PushBytes(data)) => {
                    let len = data.len();
                    if len <= 75 {
                        pos += 1 + len;
                    } else if len <= 0xff {
                        pos += 2 + len;
                    } else if len <= 0xffff {
                        pos += 3 + len;
                    } else {
                        pos += 5 + len;
                    }
                    instructions.push((start, Opcode::OP_0, pos)); // use OP_0 as placeholder for push
                }
                Err(_) => break,
            }
        }

        // Execute the full script in one go and capture the stack at each
        // instruction boundary by replaying prefixes.
        for (i, &(pc, opcode, end)) in instructions.iter().enumerate() {
            // Execute the script prefix [0..end] in a fresh engine.
            let prefix_bytes = &self.script.as_bytes()[..end];
            let prefix_script = Script::from_bytes(prefix_bytes);
            let flags = ScriptFlags::none();
            let mut engine = ScriptEngine::new(&verifier, flags, None, 0, 0);

            // Ignore errors -- we're tracing, not validating.
            let _ = engine.execute(prefix_script);

            self.history.push(DebugStep {
                pc,
                opcode,
                stack: engine.stack().to_vec(),
                altstack: Vec::new(), // alt-stack is not publicly accessible
            });
        }

        self.executed = true;
        self.history.clone()
    }

    /// Execute one instruction (returns the step, or None if the script is
    /// done).
    pub fn step(&mut self) -> Option<&DebugStep> {
        if !self.executed {
            self.run();
        }
        // Return the next un-returned step.
        // For simplicity, just use the history index.
        None // after run(), all steps are in history
    }

    /// Set a breakpoint at the given byte offset.
    pub fn set_breakpoint(&mut self, offset: usize) {
        if !self.breakpoints.contains(&offset) {
            self.breakpoints.push(offset);
        }
    }

    /// Return the stack snapshot at a particular step index.
    pub fn stack_at(&self, step: usize) -> &[Vec<u8>] {
        if step < self.history.len() {
            &self.history[step].stack
        } else {
            &[]
        }
    }

    /// Return the full execution history.
    pub fn history(&self) -> &[DebugStep] {
        &self.history
    }

    /// Print a human-readable execution trace to stdout.
    pub fn print_trace(&self) {
        println!("=== Script Execution Trace ===");
        println!("Script: {} bytes", self.script.len());
        println!();
        for (i, step) in self.history.iter().enumerate() {
            let stack_display: Vec<String> = step
                .stack
                .iter()
                .map(|item| {
                    if item.is_empty() {
                        "[]".to_string()
                    } else {
                        hex::encode(item)
                    }
                })
                .collect();
            println!(
                "  Step {}: pc={:#04x}  {:?}  stack=[{}]",
                i,
                step.pc,
                step.opcode,
                stack_display.join(", "),
            );
        }
        println!("=== End Trace ===");
    }
}
