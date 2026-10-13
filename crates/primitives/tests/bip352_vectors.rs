#![cfg(feature = "silent-payments")]
use btc_primitives::{
    amount::Amount,
    encode::{Decodable, ReadExt, VarInt},
    hash::TxHash,
    network::Network,
    script::ScriptBuf,
    silent_payments::{create_outputs, scan_transaction, SilentPaymentAddress},
    transaction::{OutPoint, Transaction, TxIn, TxOut, Witness},
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;
fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn build(given: &Value) -> (Transaction, Vec<TxOut>, Vec<Option<[u8; 32]>>) {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![],
        outputs: vec![],
        witness: vec![],
        lock_time: 0,
    };
    let mut prevouts = vec![];
    let mut secrets = vec![];
    for v in given["vin"].as_array().unwrap() {
        tx.inputs.push(TxIn {
            previous_output: OutPoint::new(
                TxHash::from_hex(v["txid"].as_str().unwrap()).unwrap(),
                v["vout"].as_u64().unwrap() as u32,
            ),
            script_sig: ScriptBuf::from_bytes(bytes(v["scriptSig"].as_str().unwrap())),
            sequence: u32::MAX,
        });
        let encoded = bytes(v["txinwitness"].as_str().unwrap());
        let mut cursor = std::io::Cursor::new(encoded);
        let mut items = vec![];
        if !cursor.get_ref().is_empty() {
            let n = VarInt::decode(&mut cursor).unwrap().0;
            for _ in 0..n {
                let len = VarInt::decode(&mut cursor).unwrap().0;
                items.push(cursor.read_bytes(len as usize).unwrap());
            }
        }
        tx.witness.push(Witness::from_items(items));
        prevouts.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(bytes(
                v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap(),
            )),
        });
        secrets.push(
            v["private_key"]
                .as_str()
                .map(|s| bytes(s).try_into().unwrap()),
        );
    }
    (tx, prevouts, secrets)
}
#[test]
fn official_bip352_send_and_receive_vectors() {
    let cases: Value =
        serde_json::from_str(include_str!("../../../testdata/bip352_vectors.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let name = case["comment"].as_str().unwrap();
        for sending in case["sending"].as_array().unwrap() {
            let (tx, prevouts, secrets) = build(&sending["given"]);
            let mut recipients = vec![];
            for r in sending["given"]["recipients"].as_array().unwrap() {
                let addr = SilentPaymentAddress::decode(r["address"].as_str().unwrap()).unwrap();
                assert_eq!(
                    addr.scan_key.to_vec(),
                    bytes(r["scan_pub_key"].as_str().unwrap()),
                    "{name}"
                );
                assert_eq!(
                    addr.spend_key.to_vec(),
                    bytes(r["spend_pub_key"].as_str().unwrap()),
                    "{name}"
                );
                for _ in 0..r["count"].as_u64().unwrap_or(1) {
                    recipients.push(addr.clone());
                }
            }
            let result = create_outputs(&tx, &prevouts, &secrets, &recipients);
            let outputs = result.unwrap_or_default();
            let mut actual: Vec<_> = outputs.iter().map(|p| hex::encode(&p[1..])).collect();
            actual.sort();
            assert!(
                sending["expected"]["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| {
                        let mut e: Vec<_> = a
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|s| s.as_str().unwrap().to_string())
                            .collect();
                        e.sort();
                        e == actual
                    }),
                "sender {name}: {actual:?}"
            );
        }
        for receiving in case["receiving"].as_array().unwrap() {
            let (mut tx, prevouts, _) = build(&receiving["given"]);
            for key in receiving["given"]["outputs"].as_array().unwrap() {
                tx.outputs.push(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::p2tr(
                        &bytes(key.as_str().unwrap()).try_into().unwrap(),
                    ),
                });
            }
            let scan: [u8; 32] = bytes(
                receiving["given"]["key_material"]["scan_priv_key"]
                    .as_str()
                    .unwrap(),
            )
            .try_into()
            .unwrap();
            let spend = SecretKey::from_slice(&bytes(
                receiving["given"]["key_material"]["spend_priv_key"]
                    .as_str()
                    .unwrap(),
            ))
            .unwrap();
            let spend_pk = PublicKey::from_secret_key(&Secp256k1::new(), &spend).serialize();
            let labels: Vec<u32> = receiving["given"]["labels"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_u64().unwrap() as u32)
                .collect();
            let found = scan_transaction(&scan, &spend_pk, &tx, &prevouts, &labels).unwrap();
            if let Some(n) = receiving["expected"]["n_outputs"].as_u64() {
                assert_eq!(found.len(), n as usize, "{name}");
                continue;
            }
            let expected = receiving["expected"]["outputs"].as_array().unwrap();
            assert_eq!(found.len(), expected.len(), "receiver {name}");
            for output in found {
                let key = hex::encode(&output.output_key[1..]);
                let e = expected
                    .iter()
                    .find(|e| e["pub_key"] == key)
                    .unwrap_or_else(|| panic!("{name}: unexpected {key}"));
                assert_eq!(
                    hex::encode(output.private_key_tweak),
                    e["priv_key_tweak"].as_str().unwrap(),
                    "{name}"
                );
            }
            let addr = SilentPaymentAddress {
                scan_key: PublicKey::from_secret_key(
                    &Secp256k1::new(),
                    &SecretKey::from_slice(&scan).unwrap(),
                )
                .serialize(),
                spend_key: spend_pk,
                network: Network::Mainnet,
            };
            assert_eq!(
                addr.encode().unwrap(),
                receiving["expected"]["addresses"][0].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
