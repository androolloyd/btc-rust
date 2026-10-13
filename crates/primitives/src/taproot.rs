//! BIP341 public commitments, shared by wallet metadata and consensus validation.
//! These functions do not create or verify signatures.

use crate::encode::{Encodable, VarInt};
use crate::hash::sha256;
use secp256k1::{Parity, Scalar, Secp256k1, XOnlyPublicKey};

/// BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message).
pub fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let hash = sha256(tag);
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(&hash);
    preimage.extend_from_slice(&hash);
    preimage.extend_from_slice(message);
    sha256(&preimage)
}

pub fn tap_tweak_hash(internal: &[u8; 32], root: Option<&[u8; 32]>) -> [u8; 32] {
    let mut message = internal.to_vec();
    if let Some(root) = root {
        message.extend_from_slice(root);
    }
    tagged_hash(b"TapTweak", &message)
}

pub fn tap_leaf_hash(version: u8, script: &[u8]) -> [u8; 32] {
    let mut message = vec![version];
    VarInt(script.len() as u64)
        .encode(&mut message)
        .expect("Vec write");
    message.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &message)
}

pub fn tap_branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut message = [0; 64];
    message[..32].copy_from_slice(first);
    message[32..].copy_from_slice(second);
    tagged_hash(b"TapBranch", &message)
}

/// Lift the internal x coordinate, apply the BIP341 scalar tweak and return Q
/// with its y parity (0 = even, 1 = odd). Reject invalid points/tweaks/infinity.
pub fn output_key(
    internal: &[u8; 32],
    root: Option<&[u8; 32]>,
) -> Result<([u8; 32], u8), secp256k1::Error> {
    let internal = XOnlyPublicKey::from_slice(internal)?;
    let tweak = Scalar::from_be_bytes(tap_tweak_hash(&internal.serialize(), root))
        .map_err(|_| secp256k1::Error::InvalidTweak)?;
    let (output, parity) = internal.add_tweak(&Secp256k1::verification_only(), &tweak)?;
    Ok((output.serialize(), u8::from(parity == Parity::Odd)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_bip341_output_keys_and_tweaks() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/bip341-commitments.json")).unwrap();
        let vectors = fixture["scriptPubKey"].as_array().unwrap();
        assert_eq!(vectors.len(), 7);
        for vector in vectors {
            let internal: [u8; 32] =
                hex::decode(vector["given"]["internalPubkey"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
            let root = vector["intermediary"]["merkleRoot"]
                .as_str()
                .map(|root| hex::decode(root).unwrap().try_into().unwrap());
            assert_eq!(
                hex::encode(tap_tweak_hash(&internal, root.as_ref())),
                vector["intermediary"]["tweak"]
            );
            let (key, parity) = output_key(&internal, root.as_ref()).unwrap();
            assert_eq!(hex::encode(key), vector["intermediary"]["tweakedPubkey"]);
            assert_eq!(
                hex::encode(crate::ScriptBuf::p2tr(&key).as_bytes()),
                vector["expected"]["scriptPubKey"]
            );
            if let Some(controls) = vector["expected"]["scriptPathControlBlocks"].as_array() {
                for control in controls {
                    assert_eq!(
                        hex::decode(control.as_str().unwrap()).unwrap()[0] & 1,
                        parity
                    );
                }
            }
        }
        assert!(output_key(&[0xff; 32], None).is_err());
        assert!(output_key(&[0; 32], None).is_err());
    }
}
