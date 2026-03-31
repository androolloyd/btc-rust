#![no_main]

use libfuzzer_sys::fuzz_target;

use btc_network::codec::{decode_payload, encode_payload};
use btc_network::BitcoinCodec;
use btc_primitives::hash::sha256d;
use btc_primitives::network::Network;
use bytes::BytesMut;
use tokio_util::codec::Decoder;

/// All command strings the codec knows about.
const COMMANDS: &[&str] = &[
    "version",
    "verack",
    "ping",
    "pong",
    "inv",
    "getdata",
    "getheaders",
    "getblocks",
    "headers",
    "block",
    "tx",
    "addr",
    "sendheaders",
    "feefilter",
    "notfound",
    "reject",
    "mempool",
];

fuzz_target!(|data: &[u8]| {
    // Guard: need at least 1 byte for command selection + some payload.
    if data.is_empty() {
        return;
    }

    // Limit payload to 256 KB to keep fuzzer iterations fast.
    // Real MAX_PAYLOAD_SIZE is 32 MB but we do not want to allocate that
    // much per fuzzer iteration.
    let max_fuzz_payload: usize = 256 * 1024;

    // --- Strategy 1: raw decode_payload with each known command ---
    // Use the first byte to pick a command, rest is payload.
    let cmd_idx = data[0] as usize % COMMANDS.len();
    let payload = &data[1..];
    if payload.len() <= max_fuzz_payload {
        let _ = decode_payload(COMMANDS[cmd_idx], payload);
    }

    // --- Strategy 2: feed a well-framed message into the BitcoinCodec ---
    // Build a valid 24-byte header around the fuzzed payload so that the
    // codec's Decoder path gets exercised (magic check, checksum verify,
    // length parsing, then payload decode).
    if payload.len() <= max_fuzz_payload {
        let magic = Network::Mainnet.magic();
        let cmd_str = COMMANDS[cmd_idx];

        // Build 12-byte command field.
        let mut command = [0u8; 12];
        let cmd_bytes = cmd_str.as_bytes();
        command[..cmd_bytes.len().min(12)].copy_from_slice(&cmd_bytes[..cmd_bytes.len().min(12)]);

        // Compute correct checksum so the codec does not reject on checksum
        // mismatch -- we want to exercise the payload deserialization.
        let checksum = sha256d(payload);

        let mut buf = BytesMut::with_capacity(24 + payload.len());
        buf.extend_from_slice(&magic);
        buf.extend_from_slice(&command);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&checksum[..4]);
        buf.extend_from_slice(payload);

        let mut codec = BitcoinCodec::new(magic);
        // Must not panic.  Errors are fine.
        let _ = codec.decode(&mut buf);
    }

    // --- Strategy 3: if decode_payload succeeded, verify encode roundtrip ---
    if payload.len() <= max_fuzz_payload {
        if let Ok(msg) = decode_payload(COMMANDS[cmd_idx], payload) {
            // Re-encode must not panic.
            let _ = encode_payload(&msg);
        }
    }
});
