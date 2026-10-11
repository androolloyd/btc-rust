pub mod block_filter;
pub mod block_template;
pub mod chain;
pub mod checkpoints;
pub mod opcode_plugin;
pub mod reorg;
pub mod script_engine;
pub mod sig_verify;
pub mod sighash;
pub mod signet;
pub mod utxo;
pub mod validation;
pub mod versionbits;

pub mod taproot;

#[cfg(feature = "segwit")]
pub mod parallel;

#[cfg(feature = "segwit")]
pub mod witness;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use block_template::{build_block_template, BlockTemplate};
pub use chain::ChainState;
pub use checkpoints::Checkpoints;
pub use opcode_plugin::{OpcodeContext, OpcodeExecContext, OpcodePlugin, OpcodeRegistry};
pub use reorg::ReorgManager;
pub use script_engine::ScriptEngine;
pub use sighash::{
    sighash_anyprevout, sighash_legacy, sighash_segwit_v0, sighash_segwit_v0_cached,
    sighash_taproot, SighashCache, SighashType, SIGHASH_ANYPREVOUT, SIGHASH_ANYPREVOUTANYSCRIPT,
};
pub use validation::BlockValidator;

#[cfg(feature = "segwit")]
pub use parallel::{ParallelConfig, ParallelValidator};

#[cfg(feature = "covenants")]
pub use opcode_plugin::{
    covenant_registry, default_check_template_verify_hash, OpCat, OpCheckContractVerify,
    OpCheckSigAnyprevout, OpCheckSigFromStack, OpCheckTemplateVerify, OpInternalKey, OpTxHash,
};

#[cfg(feature = "taproot")]
pub use taproot::{compute_taprootoutput_key, verify_taproot_input, verify_taproot_tweak};

#[cfg(feature = "segwit")]
pub use witness::{verify_input, verify_witness_program, WitnessError};
