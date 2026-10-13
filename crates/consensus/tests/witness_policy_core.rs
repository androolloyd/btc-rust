#![cfg(all(feature = "segwit", feature = "taproot"))]

use btc_consensus::{
    script_engine::ScriptFlags,
    sig_verify::Secp256k1Verifier,
    sighash::{sighash_legacy, sighash_segwit_v0, SighashType},
    witness::verify_input_with_prevouts,
};
use btc_primitives::transaction::{Transaction, TxOut};

#[test]
fn core_witness_key_encoding_and_upgrade_policy_boundaries() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/core29_witness_policy.json")).unwrap();
    let cases = data["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 70);
    for case in cases {
        let tx: Transaction =
            btc_primitives::decode(&hex::decode(case["transaction"].as_str().unwrap()).unwrap())
                .unwrap();
        let previous: TxOut =
            btc_primitives::decode(&hex::decode(case["prevout"].as_str().unwrap()).unwrap())
                .unwrap();
        for (flags, field) in [
            (ScriptFlags::consensus(), "allowed"),
            (ScriptFlags::all(), "interpreter_allowed"),
            (ScriptFlags::core_compliant(), "interpreter_allowed"),
        ] {
            let result = verify_input_with_prevouts(
                &tx,
                0,
                std::slice::from_ref(&previous),
                &Secp256k1Verifier,
                &flags,
            );
            assert_eq!(
                result.is_ok(),
                case[field].as_bool().unwrap(),
                "{} {field}: {result:?}",
                case["name"]
            );
        }
        for row in case["digests"].as_array().unwrap() {
            let code = hex::decode(row["script_code"].as_str().unwrap()).unwrap();
            let digest = if row["witness"].as_bool().unwrap() {
                sighash_segwit_v0(&tx, 0, &code, previous.value.as_sat(), SighashType::ALL).unwrap()
            } else {
                sighash_legacy(&tx, 0, &code, SighashType::ALL).unwrap()
            };
            assert_eq!(hex::encode(digest), row["digest"], "{}", case["name"]);
        }
    }
}
