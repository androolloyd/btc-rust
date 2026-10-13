#![cfg(feature = "segwit")]

use btc_consensus::{
    script_engine::ScriptFlags,
    sig_verify::Secp256k1Verifier,
    sighash::{sighash_legacy, sighash_segwit_v0, SighashType},
    witness::verify_input_with_prevouts,
};
use btc_primitives::transaction::{Transaction, TxOut};

#[test]
fn core_reference_legacy_and_bip143_execution_policy_and_digests() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/core29_scriptcode.json")).unwrap();
    let cases = fixture["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 59);
    for case in cases {
        let tx: Transaction =
            btc_primitives::decode(&hex::decode(case["transaction"].as_str().unwrap()).unwrap())
                .unwrap();
        let previous: TxOut =
            btc_primitives::decode(&hex::decode(case["prevout"].as_str().unwrap()).unwrap())
                .unwrap();
        for (flags, field) in [
            (ScriptFlags::consensus(), "allowed"),
            (ScriptFlags::all(), "policy_allowed"),
        ] {
            let result =
                verify_input_with_prevouts(&tx, 0, &[previous.clone()], &Secp256k1Verifier, &flags);
            assert_eq!(
                result.is_ok(),
                case[field].as_bool().unwrap(),
                "{} {field}: {result:?}",
                case["name"]
            );
        }
        // Isolate CONST_SCRIPTCODE from other policy flags. Legacy separators
        // (even skipped ones) and signature-dependent scriptSigs must fail;
        // the same flag must leave witness-v0 scriptCode untouched.
        let mut flags = ScriptFlags::consensus();
        flags.verify_const_scriptcode = true;
        let result =
            verify_input_with_prevouts(&tx, 0, &[previous.clone()], &Secp256k1Verifier, &flags);
        let witness = tx.is_segwit();
        assert_eq!(
            result.is_ok(),
            witness && case["allowed"].as_bool().unwrap(),
            "{} constant scriptCode: {result:?}",
            case["name"]
        );
        if !witness && case["allowed"].as_bool().unwrap() {
            let message = format!("{result:?}");
            assert!(
                message.contains(
                    if case["name"]
                        .as_str()
                        .unwrap()
                        .starts_with("legacy-finddelete")
                    {
                        "SigFindAndDelete"
                    } else {
                        "ConstScriptCode"
                    }
                ),
                "{}: {message}",
                case["name"]
            );
        }
        for record in case["digests"].as_array().unwrap() {
            let code = hex::decode(record["script_code"].as_str().unwrap()).unwrap();
            let kind = SighashType(record["hash_type"].as_u64().unwrap() as u32);
            let digest = if record["witness"].as_bool().unwrap() {
                sighash_segwit_v0(&tx, 0, &code, previous.value.as_sat(), kind).unwrap()
            } else {
                sighash_legacy(&tx, 0, &code, kind).unwrap()
            };
            assert_eq!(
                hex::encode(digest),
                record["digest"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
