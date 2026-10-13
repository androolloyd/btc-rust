//! `btc-forge` -- a Foundry-equivalent toolkit for Bitcoin Script development.
//!
//! Provides [`ScriptEnv`] for end-to-end script testing, [`ForgeScript`] for
//! ergonomic script construction, [`ScriptDebugger`] for step-through
//! execution, [`TxBuilder`] for transaction construction, and [`weight`]
//! utilities for script cost analysis.

pub mod debugger;
pub mod miniscript;
pub mod script_builder;
pub mod script_env;
pub mod tx_builder;
pub mod weight;

pub use debugger::{DebugStep, ScriptDebugger};
pub use miniscript::{Miniscript, MiniscriptError, Policy};
pub use script_builder::ForgeScript;
pub use script_env::{Account, ForgeError, FundedUtxo, ScriptEnv, ScriptResult};
pub use tx_builder::TxBuilder;
pub use weight::{analyze_script, estimate_witness_weight, ScriptAnalysis, ScriptBranch};

// Re-export core types for convenience so users do not need to depend on
// lower-level crates directly.
pub use btc_primitives::amount::Amount;
pub use btc_primitives::hash::TxHash;
pub use btc_primitives::script::{Opcode, Script, ScriptBuf};
pub use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

#[cfg(test)]
mod tests;
