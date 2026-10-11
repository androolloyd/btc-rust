use btc_primitives::{
    amount::Amount,
    encode::{decode, encode, Decodable, VarInt},
    hash::TxHash,
    script::ScriptBuf,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
#[test]
fn compact_size_must_use_the_shortest_encoding() {
    for bytes in [
        vec![0xfd, 0xfc, 0],
        vec![0xfe, 0xff, 0xff, 0, 0],
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
    ] {
        assert!(decode::<VarInt>(&bytes).is_err());
    }
}
#[test]
fn full_decode_rejects_trailing_bytes_but_stream_decode_is_composable() {
    let bytes = [1, 0, 0, 0, 2, 0, 0, 0];
    assert!(decode::<u32>(&bytes).is_err());
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(u32::decode(&mut reader).unwrap(), 1);
    assert_eq!(u32::decode(&mut reader).unwrap(), 2);
}
#[test]
fn witness_marker_without_witness_is_rejected() {
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(TxHash::from_bytes([1; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::ONE_SAT,
            script_pubkey: ScriptBuf::new(),
        }],
        witness: vec![],
        lock_time: 0,
    };
    let legacy = encode(&tx);
    let mut bytes = legacy[..4].to_vec();
    bytes.extend([0, 1]);
    bytes.extend_from_slice(&legacy[4..legacy.len() - 4]);
    bytes.push(0);
    bytes.extend_from_slice(&legacy[legacy.len() - 4..]);
    assert!(decode::<Transaction>(&bytes).is_err());
}
