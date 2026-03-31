//! C-compatible FFI for the consensus library.
//!
//! This module exposes a `libbtcconsensus`-style API that allows C, Go, Python,
//! and other language runtimes to embed our script verification engine.
//!
//! All functions are gated behind `#[cfg(feature = "ffi")]` and use
//! `catch_unwind` to prevent panics from crossing the FFI boundary.

use std::panic::catch_unwind;
use std::slice;

use btc_primitives::encode;
use btc_primitives::script::Script;
use btc_primitives::transaction::Transaction;

use crate::script_engine::{ScriptEngine, ScriptFlags};
use crate::sig_verify::Secp256k1Verifier;
use crate::sighash::{sighash_legacy, SighashType};

// ---------------------------------------------------------------------------
// Flag constants (mirrors Bitcoin Core's bitcoinconsensus.h)
// ---------------------------------------------------------------------------

/// Evaluate P2SH (BIP16) subscripts.
pub const BTC_SCRIPT_FLAGS_VERIFY_P2SH: u32 = 1 << 0;
/// Enforce strict DER signature encoding (BIP66).
pub const BTC_SCRIPT_FLAGS_VERIFY_DERSIG: u32 = 1 << 2;
/// Enforce NULLDUMMY (BIP147).
pub const BTC_SCRIPT_FLAGS_VERIFY_NULLDUMMY: u32 = 1 << 4;
/// Enable CHECKLOCKTIMEVERIFY (BIP65).
pub const BTC_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
/// Enable CHECKSEQUENCEVERIFY (BIP112).
pub const BTC_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
/// Enable witness (BIP141).
pub const BTC_SCRIPT_FLAGS_VERIFY_WITNESS: u32 = 1 << 11;

/// Convenience: all standard rules.
pub const BTC_SCRIPT_FLAGS_VERIFY_ALL: u32 = BTC_SCRIPT_FLAGS_VERIFY_P2SH
    | BTC_SCRIPT_FLAGS_VERIFY_DERSIG
    | BTC_SCRIPT_FLAGS_VERIFY_NULLDUMMY
    | BTC_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY
    | BTC_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY
    | BTC_SCRIPT_FLAGS_VERIFY_WITNESS;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert C-style flag bits into our internal `ScriptFlags`.
fn flags_from_u32(flags: u32) -> ScriptFlags {
    ScriptFlags {
        verify_p2sh: flags & BTC_SCRIPT_FLAGS_VERIFY_P2SH != 0,
        verify_witness: flags & BTC_SCRIPT_FLAGS_VERIFY_WITNESS != 0,
        verify_strictenc: false,
        verify_dersig: flags & BTC_SCRIPT_FLAGS_VERIFY_DERSIG != 0,
        verify_low_s: false,
        verify_nulldummy: flags & BTC_SCRIPT_FLAGS_VERIFY_NULLDUMMY != 0,
        verify_cleanstack: false,
        verify_checklocktimeverify: flags & BTC_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY != 0,
        verify_checksequenceverify: flags & BTC_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY != 0,
        verify_taproot: false,
    }
}

/// Safely reconstruct a byte slice from an FFI pointer + length.
///
/// Returns `None` when the pointer is null **or** the length would overflow
/// the address space.
unsafe fn slice_from_raw(ptr: *const u8, len: u32) -> Option<&'static [u8]> {
    if ptr.is_null() {
        return None;
    }
    let len = len as usize;
    // Guard against absurd lengths that would wrap around the address space.
    if len > isize::MAX as usize {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

/// Verify a script for a transaction input.
///
/// # Arguments
/// * `script_pubkey` / `script_pubkey_len` -- the previous output's scriptPubKey.
/// * `tx_data` / `tx_data_len` -- the spending transaction serialized in
///   Bitcoin consensus format (with or without witness).
/// * `input_index` -- which input of the transaction is being verified.
/// * `flags` -- bitmask of `BTC_SCRIPT_FLAGS_VERIFY_*` constants.
///
/// # Returns
/// `1` on success, `0` on any failure (bad pointers, decode error, script
/// failure, etc.).
#[no_mangle]
pub extern "C" fn btc_verify_script(
    script_pubkey: *const u8,
    script_pubkey_len: u32,
    tx_data: *const u8,
    tx_data_len: u32,
    input_index: u32,
    flags: u32,
) -> i32 {
    let result = catch_unwind(|| {
        // --- pointer validation ---
        let spk = unsafe { slice_from_raw(script_pubkey, script_pubkey_len) };
        let tx_bytes = unsafe { slice_from_raw(tx_data, tx_data_len) };

        let spk = match spk {
            Some(s) => s,
            None => return 0,
        };
        let tx_bytes = match tx_bytes {
            Some(s) => s,
            None => return 0,
        };

        // --- decode the transaction ---
        let tx: Transaction = match encode::decode(tx_bytes) {
            Ok(t) => t,
            Err(_) => return 0,
        };

        let idx = input_index as usize;
        if idx >= tx.inputs.len() {
            return 0;
        }

        // --- build the script engine and run ---
        let verifier = Secp256k1Verifier;
        let script_flags = flags_from_u32(flags);
        let mut engine = ScriptEngine::new(&verifier, script_flags, Some(&tx), idx, 0);

        // Execute the scriptSig first, then the scriptPubKey.
        let script_sig = &tx.inputs[idx].script_sig;
        let pubkey_script = Script::from_bytes(spk);

        if engine.execute(Script::from_bytes(script_sig.as_bytes())).is_err() {
            return 0;
        }
        if engine.execute(pubkey_script).is_err() {
            return 0;
        }

        // After executing both scripts, the top of the stack must be truthy.
        if engine.success() { 1 } else { 0 }
    });

    result.unwrap_or(0)
}

/// Get the library version.
///
/// Currently returns `1`.
#[no_mangle]
pub extern "C" fn btc_consensus_version() -> u32 {
    1
}

/// Compute the sighash for a transaction input.
///
/// The resulting 32-byte hash is written to `output`. The caller must ensure
/// `output` points to at least 32 writable bytes.
///
/// # Returns
/// `1` on success, `0` on failure.
#[no_mangle]
pub extern "C" fn btc_sighash(
    tx_data: *const u8,
    tx_data_len: u32,
    script_code: *const u8,
    script_code_len: u32,
    input_index: u32,
    hash_type: u32,
    output: *mut u8, // 32 bytes
) -> i32 {
    let result = catch_unwind(|| {
        // --- pointer validation ---
        if output.is_null() {
            return 0;
        }

        let tx_bytes = unsafe { slice_from_raw(tx_data, tx_data_len) };
        let sc = unsafe { slice_from_raw(script_code, script_code_len) };

        let tx_bytes = match tx_bytes {
            Some(s) => s,
            None => return 0,
        };
        let sc = match sc {
            Some(s) => s,
            None => return 0,
        };

        // --- decode the transaction ---
        let tx: Transaction = match encode::decode(tx_bytes) {
            Ok(t) => t,
            Err(_) => return 0,
        };

        // --- compute sighash ---
        let sighash_type = SighashType(hash_type);
        let hash = match sighash_legacy(&tx, input_index as usize, sc, sighash_type) {
            Ok(h) => h,
            Err(_) => return 0,
        };

        // --- write result ---
        let out_slice = unsafe { slice::from_raw_parts_mut(output, 32) };
        out_slice.copy_from_slice(&hash);

        1
    });

    result.unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::encode;
    use btc_primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use btc_primitives::script::ScriptBuf;
    use btc_primitives::amount::Amount;
    use btc_primitives::hash::TxHash;

    /// Build a minimal valid transaction for testing.
    fn make_test_tx() -> (Transaction, Vec<u8>) {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(TxHash::from_bytes([0xaa; 32]), 0),
                // scriptSig: OP_TRUE (0x51) -- makes the scriptPubKey succeed
                script_sig: ScriptBuf::from_bytes(vec![0x51]),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            }],
            witness: Vec::new(),
            lock_time: 0,
        };
        let raw = encode::encode(&tx);
        (tx, raw)
    }

    #[test]
    fn test_version() {
        assert_eq!(btc_consensus_version(), 1);
    }

    #[test]
    fn test_verify_script_null_pointers() {
        // Null scriptPubKey pointer should return 0, not crash.
        assert_eq!(
            btc_verify_script(std::ptr::null(), 0, std::ptr::null(), 0, 0, 0),
            0
        );
    }

    #[test]
    fn test_verify_script_empty_tx() {
        let spk: &[u8] = &[0x51]; // OP_TRUE
        assert_eq!(
            btc_verify_script(spk.as_ptr(), spk.len() as u32, std::ptr::null(), 0, 0, 0),
            0
        );
    }

    #[test]
    fn test_verify_script_input_out_of_range() {
        let (_tx, raw) = make_test_tx();
        let spk: &[u8] = &[0x51]; // OP_TRUE
        // input_index = 99 is out of range
        assert_eq!(
            btc_verify_script(
                spk.as_ptr(),
                spk.len() as u32,
                raw.as_ptr(),
                raw.len() as u32,
                99,
                0
            ),
            0
        );
    }

    #[test]
    fn test_verify_script_op_true() {
        let (_tx, raw) = make_test_tx();
        // scriptPubKey = OP_TRUE (0x51): always passes
        let spk: &[u8] = &[0x51];
        let result = btc_verify_script(
            spk.as_ptr(),
            spk.len() as u32,
            raw.as_ptr(),
            raw.len() as u32,
            0,
            0,
        );
        assert_eq!(result, 1);
    }

    #[test]
    fn test_verify_script_op_false() {
        let (_tx, raw) = make_test_tx();
        // scriptPubKey = OP_FALSE (0x00) followed by nothing -- should fail
        let spk: &[u8] = &[0x00];
        let result = btc_verify_script(
            spk.as_ptr(),
            spk.len() as u32,
            raw.as_ptr(),
            raw.len() as u32,
            0,
            0,
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sighash_null_output() {
        let (_tx, raw) = make_test_tx();
        let sc: &[u8] = &[0x51];
        assert_eq!(
            btc_sighash(
                raw.as_ptr(),
                raw.len() as u32,
                sc.as_ptr(),
                sc.len() as u32,
                0,
                1,
                std::ptr::null_mut(),
            ),
            0
        );
    }

    #[test]
    fn test_sighash_null_tx() {
        let sc: &[u8] = &[0x51];
        let mut out = [0u8; 32];
        assert_eq!(
            btc_sighash(
                std::ptr::null(),
                0,
                sc.as_ptr(),
                sc.len() as u32,
                0,
                1,
                out.as_mut_ptr(),
            ),
            0
        );
    }

    #[test]
    fn test_sighash_basic() {
        let (_tx, raw) = make_test_tx();
        let sc: &[u8] = &[0x51]; // OP_TRUE as script code
        let mut out = [0u8; 32];

        let result = btc_sighash(
            raw.as_ptr(),
            raw.len() as u32,
            sc.as_ptr(),
            sc.len() as u32,
            0,
            0x01, // SIGHASH_ALL
            out.as_mut_ptr(),
        );
        assert_eq!(result, 1);

        // The hash should be deterministic -- call again and compare.
        let mut out2 = [0u8; 32];
        let result2 = btc_sighash(
            raw.as_ptr(),
            raw.len() as u32,
            sc.as_ptr(),
            sc.len() as u32,
            0,
            0x01,
            out2.as_mut_ptr(),
        );
        assert_eq!(result2, 1);
        assert_eq!(out, out2, "sighash must be deterministic");
    }

    #[test]
    fn test_sighash_different_hash_types() {
        let (_tx, raw) = make_test_tx();
        let sc: &[u8] = &[0x51];

        let mut out_all = [0u8; 32];
        let mut out_none = [0u8; 32];

        btc_sighash(
            raw.as_ptr(),
            raw.len() as u32,
            sc.as_ptr(),
            sc.len() as u32,
            0,
            0x01, // SIGHASH_ALL
            out_all.as_mut_ptr(),
        );
        btc_sighash(
            raw.as_ptr(),
            raw.len() as u32,
            sc.as_ptr(),
            sc.len() as u32,
            0,
            0x02, // SIGHASH_NONE
            out_none.as_mut_ptr(),
        );

        assert_ne!(out_all, out_none, "different hash types must produce different sighashes");
    }

    #[test]
    fn test_sighash_input_out_of_range() {
        let (_tx, raw) = make_test_tx();
        let sc: &[u8] = &[0x51];
        let mut out = [0u8; 32];

        let result = btc_sighash(
            raw.as_ptr(),
            raw.len() as u32,
            sc.as_ptr(),
            sc.len() as u32,
            99, // out of range
            0x01,
            out.as_mut_ptr(),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn test_verify_script_garbage_tx_data() {
        let spk: &[u8] = &[0x51];
        let garbage: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let result = btc_verify_script(
            spk.as_ptr(),
            spk.len() as u32,
            garbage.as_ptr(),
            garbage.len() as u32,
            0,
            0,
        );
        assert_eq!(result, 0);
    }
}
