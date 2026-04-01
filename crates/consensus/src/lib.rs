pub mod block_filter;
pub mod block_template;
pub mod chain;
pub mod checkpoints;
pub mod reorg;
pub mod script_engine;
pub mod sighash;
pub mod signet;
pub mod validation;
pub mod versionbits;
pub mod sig_verify;
pub mod utxo;
pub mod opcode_plugin;

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
pub use reorg::ReorgManager;
pub use script_engine::ScriptEngine;
pub use sighash::{sighash_legacy, sighash_segwit_v0, sighash_segwit_v0_cached, sighash_taproot, sighash_anyprevout, SighashCache, SighashType, SIGHASH_ANYPREVOUT, SIGHASH_ANYPREVOUTANYSCRIPT};
pub use validation::BlockValidator;
pub use opcode_plugin::{OpcodePlugin, OpcodeRegistry, OpcodeContext, OpcodeExecContext};

#[cfg(feature = "segwit")]
pub use parallel::{ParallelValidator, ParallelConfig};

#[cfg(feature = "covenants")]
pub use opcode_plugin::{OpCheckTemplateVerify, OpCat, OpCheckSigFromStack, OpInternalKey, OpCheckSigAnyprevout, OpTxHash, OpCheckContractVerify, default_check_template_verify_hash, covenant_registry};

#[cfg(feature = "taproot")]
pub use taproot::{verify_taproot_input, verify_taproot_tweak, compute_taprootoutput_key};

#[cfg(feature = "segwit")]
pub use witness::{verify_witness_program, verify_input, WitnessError};
