use btc_consensus::{script_engine::ScriptFlags, sigops::*};
use btc_primitives::{
    script::{Opcode, Script, ScriptBuf},
    transaction::{OutPoint, Transaction, TxIn, TxOut, Witness},
    Amount,
};

#[test]
fn independent_core_transaction_and_opcode_counts() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/core29_sigops.json")).unwrap();
    assert_eq!(data["vectors"].as_array().unwrap().len(), 26);
    for row in data["vectors"].as_array().unwrap() {
        let tx: Transaction =
            btc_primitives::decode(&hex::decode(row["transaction"].as_str().unwrap()).unwrap())
                .unwrap();
        let previous: TxOut =
            btc_primitives::decode(&hex::decode(row["prevout"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            transaction_sigop_cost(&tx, &[previous], &ScriptFlags::consensus()).unwrap(),
            row["cost"].as_u64().unwrap() as usize,
            "{}",
            row["name"]
        );
    }
    for row in data["scripts"].as_array().unwrap() {
        let bytes = hex::decode(row["script"].as_str().unwrap()).unwrap();
        for (accurate, field) in [(true, "accurate"), (false, "legacy")] {
            assert_eq!(
                script_sigops(Script::from_bytes(&bytes), accurate),
                row[field].as_u64().unwrap() as usize
            );
        }
    }
}

#[test]
fn core_getsigopcount_and_decode_boundaries() {
    // Core v29 src/test/sigopcount_tests.cpp GetSigOpCount: dummy 20-byte
    // pushes are test data, not purported curve keys or signature equations.
    let mut script = ScriptBuf::new();
    script.push_opcode(Opcode::OP_1);
    script.push_slice(&[0; 20]);
    script.push_slice(&[0; 20]);
    script.push_opcode(Opcode::OP_2);
    script.push_opcode(Opcode::OP_CHECKMULTISIG);
    assert_eq!(script_sigops(script.as_script(), true), 2);
    assert_eq!(script_sigops(script.as_script(), false), 20);
    script.push_opcode(Opcode::OP_IF);
    script.push_opcode(Opcode::OP_CHECKSIG);
    script.push_opcode(Opcode::OP_ENDIF);
    assert_eq!(script_sigops(script.as_script(), true), 3);
    assert_eq!(script_sigops(script.as_script(), false), 21);
    for (bytes, accurate, legacy) in [
        (vec![0x51, 0xae, 0x60, 0xaf, 0xac, 0xad, 0xba], 19, 42),
        (vec![0x52, 1, 0xac, 0xae], 20, 20),
        (vec![0xac, 0x4c, 2, 0xac], 1, 1),
        (vec![0xac, 0x4e, 0xff, 0xff, 0xff, 0xff, 0xae], 1, 1),
        (vec![0xbb, 0xac], 1, 1),
        (vec![0, 0x63, 0x53, 0xaf, 0x68, 0x51], 3, 20),
    ] {
        assert_eq!(script_sigops(Script::from_bytes(&bytes), true), accurate);
        assert_eq!(script_sigops(Script::from_bytes(&bytes), false), legacy);
    }
    for prefix in [vec![0x4c, 0], vec![0x4d, 0, 0], vec![0x4e, 0, 0, 0, 0]] {
        let bytes = [vec![0x52], prefix, vec![0xae]].concat();
        assert_eq!(script_sigops(Script::from_bytes(&bytes), true), 20);
    }
}

#[test]
fn core_prevout_costs_activation_and_coinbase() {
    let code = ScriptBuf::from_bytes(vec![0x52, 0xaf]);
    let mut sig = ScriptBuf::new();
    sig.push_opcode(Opcode::OP_0);
    sig.push_slice(code.as_bytes());
    let p2sh = ScriptBuf::p2sh(&btc_primitives::hash::hash160(code.as_bytes()));
    let witness = Witness::from_items(vec![vec![0xac], code.as_bytes().to_vec()]);
    let wsh = ScriptBuf::p2wsh(&btc_primitives::hash::sha256(code.as_bytes()));
    let wpkh = ScriptBuf::p2wpkh(&[0; 20]);
    let flags = ScriptFlags::consensus();
    assert_eq!(
        input_sigop_cost(sig.as_script(), p2sh.as_script(), None, &flags),
        8
    );
    assert_eq!(
        input_sigop_cost(
            Script::from_bytes(&[]),
            wsh.as_script(),
            Some(&witness),
            &flags
        ),
        2
    );
    assert_eq!(
        input_sigop_cost(Script::from_bytes(&[]), wsh.as_script(), None, &flags),
        0
    );
    assert_eq!(
        input_sigop_cost(Script::from_bytes(&[]), wpkh.as_script(), None, &flags),
        1
    );
    let wrapped = ScriptBuf::p2sh(&btc_primitives::hash::hash160(wsh.as_bytes()));
    let mut wrapped_sig = ScriptBuf::new();
    wrapped_sig.push_slice(wsh.as_bytes());
    assert_eq!(
        input_sigop_cost(
            wrapped_sig.as_script(),
            wrapped.as_script(),
            Some(&witness),
            &flags
        ),
        2
    );
    wrapped_sig.push_opcode(Opcode::OP_1);
    assert_eq!(
        input_sigop_cost(
            wrapped_sig.as_script(),
            wrapped.as_script(),
            Some(&witness),
            &flags
        ),
        0
    );
    assert_eq!(
        input_sigop_cost(
            Script::from_bytes(&[0x61]),
            wrapped.as_script(),
            Some(&witness),
            &flags
        ),
        0
    );
    for previous in [wsh.clone(), p2sh.clone()] {
        assert_eq!(
            input_sigop_cost(
                sig.as_script(),
                previous.as_script(),
                Some(&witness),
                &ScriptFlags::none()
            ),
            0
        );
    }
    let mut future = wsh.as_bytes().to_vec();
    future[0] = 0x51;
    assert_eq!(
        input_sigop_cost(
            sig.as_script(),
            Script::from_bytes(&future),
            Some(&witness),
            &flags
        ),
        0
    );
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::from_bytes(vec![0xad]),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: code,
        }],
        witness: vec![witness],
        lock_time: 0,
    };
    assert_eq!(transaction_sigop_cost(&tx, &[], &flags).unwrap(), 84);
    tx.inputs[0].previous_output.vout = 0;
    assert!(transaction_sigop_cost(&tx, &[], &flags).is_err());
    assert_eq!(virtual_size(401, 0), 101);
    assert_eq!(virtual_size(401, 100), 500);
}
