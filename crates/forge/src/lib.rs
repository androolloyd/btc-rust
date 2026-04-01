//! `btc-forge` -- a Foundry-equivalent toolkit for Bitcoin Script development.
//!
//! Provides [`ScriptEnv`] for end-to-end script testing, [`ForgeScript`] for
//! ergonomic script construction, [`ScriptDebugger`] for step-through
//! execution, [`TxBuilder`] for transaction construction, and [`weight`]
//! utilities for script cost analysis.

pub mod script_env;
pub mod script_builder;
pub mod debugger;
pub mod tx_builder;
pub mod weight;
pub mod miniscript;

pub use script_env::{ScriptEnv, Account, FundedUtxo, ScriptResult, ForgeError};
pub use script_builder::ForgeScript;
pub use debugger::{ScriptDebugger, DebugStep};
pub use tx_builder::TxBuilder;
pub use weight::{analyze_script, estimate_witness_weight, ScriptAnalysis, ScriptBranch};
pub use miniscript::{Miniscript, Policy, MiniscriptError};

// Re-export core types for convenience so users do not need to depend on
// lower-level crates directly.
pub use btc_primitives::amount::Amount;
pub use btc_primitives::hash::TxHash;
pub use btc_primitives::script::{Opcode, Script, ScriptBuf};
pub use btc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

// Tests are in individual module files and crates/forge/tests/
