#![cfg(all(feature = "segwit", feature = "taproot"))]

use btc_consensus::{
    script_engine::ScriptFlags,
    sig_verify::Secp256k1Verifier,
    sighash::{sighash_taproot_with_codeseparator, SighashType},
    witness::verify_input_with_prevouts,
};
use btc_primitives::{
    encode::Decodable,
    transaction::{Transaction, TxOut},
};

#[test]
fn core_reference_taproot_execution_and_digest_cases() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/core29_tapscript.json")).unwrap();
    let cases = data["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    for case in cases {
        let bytes = hex::decode(case["transaction"].as_str().unwrap()).unwrap();
        let mut wire = bytes.as_slice();
        let tx = Transaction::decode(&mut wire).unwrap();
        assert!(wire.is_empty());
        let bytes = hex::decode(case["prevout"].as_str().unwrap()).unwrap();
        let mut wire = bytes.as_slice();
        let previous = TxOut::decode(&mut wire).unwrap();
        assert!(wire.is_empty());
        let prevouts = [previous];
        let result = verify_input_with_prevouts(
            &tx,
            0,
            &prevouts,
            &Secp256k1Verifier,
            &ScriptFlags::consensus(),
        );
        assert_eq!(
            result.is_ok(),
            case["allowed"].as_bool().unwrap(),
            "{}: {result:?}",
            case["name"]
        );
        if let Some(expected) = case["digest"].as_str() {
            let annex = case["annex"].as_str().map(|s| hex::decode(s).unwrap());
            let leaf: Option<[u8; 32]> = case["leaf_hash"]
                .as_str()
                .map(|s| hex::decode(s).unwrap().try_into().unwrap());
            let hash_type = case["hash_type"].as_u64().unwrap() as u32;
            let digest = sighash_taproot_with_codeseparator(
                &tx,
                0,
                &prevouts,
                SighashType(hash_type),
                annex.as_deref(),
                leaf.as_ref(),
                case["codesep"].as_i64().unwrap() as u32,
            );
            if matches!(hash_type, 0 | 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
                assert_eq!(hex::encode(digest.unwrap()), expected, "{}", case["name"]);
            } else {
                assert!(digest.is_err(), "{}", case["name"]);
            }
        }
    }
}
