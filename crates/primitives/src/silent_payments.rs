//! BIP352 v0 silent-payment addresses, sender derivation and receiver scanning.
//! Prevouts are required: public input keys cannot be recovered from outpoints.
use crate::bech32::{
    bech32_decode_long, bech32_encode_long, convert_bits, Bech32Error, Bech32Variant,
};
use crate::encode::encode;
use crate::hash::{hash160, sha256};
use crate::network::Network;
use crate::script::Instruction;
use crate::transaction::{Transaction, TxOut};
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use thiserror::Error;

pub const MAX_RECIPIENTS_PER_SCAN_KEY: usize = 2323;
const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SilentPaymentError {
    #[error("bech32 error: {0}")]
    Bech32(#[from] Bech32Error),
    #[error("invalid HRP: {0}")]
    InvalidHrp(String),
    #[error("invalid key data length: {0}")]
    InvalidDataLength(usize),
    #[error("wrong bech32 variant")]
    WrongVariant,
    #[error("unsupported address version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid secp256k1 key or scalar")]
    InvalidKey,
    #[error("prevouts or private keys do not match transaction inputs")]
    InputMismatch,
    #[error("no eligible inputs, or aggregate input key is infinity")]
    NoEligibleInputs,
    #[error("transaction spends an unknown witness version")]
    UnknownWitnessVersion,
    #[error("too many recipients sharing a scan key")]
    TooManyRecipients,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    pub scan_key: [u8; 33],
    pub spend_key: [u8; 33],
    pub network: Network,
}
impl SilentPaymentAddress {
    pub fn encode(&self) -> Result<String, SilentPaymentError> {
        PublicKey::from_slice(&self.scan_key).map_err(|_| SilentPaymentError::InvalidKey)?;
        PublicKey::from_slice(&self.spend_key).map_err(|_| SilentPaymentError::InvalidKey)?;
        let mut payload = self.scan_key.to_vec();
        payload.extend_from_slice(&self.spend_key);
        let mut data = vec![0]; // version is one 5-bit value, not an 8-bit byte
        data.extend(convert_bits(&payload, 8, 5, true)?);
        Ok(bech32_encode_long(
            if self.network == Network::Mainnet {
                "sp"
            } else {
                "tsp"
            },
            &data,
            Bech32Variant::Bech32m,
        )?)
    }
    pub fn decode(s: &str) -> Result<Self, SilentPaymentError> {
        if s.len() > 1023 {
            return Err(SilentPaymentError::InvalidDataLength(s.len()));
        }
        let (hrp, data, variant) = bech32_decode_long(s)?;
        if variant != Bech32Variant::Bech32m {
            return Err(SilentPaymentError::WrongVariant);
        }
        let network = match hrp.as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            _ => return Err(SilentPaymentError::InvalidHrp(hrp)),
        };
        let version = *data
            .first()
            .ok_or(SilentPaymentError::InvalidDataLength(0))?;
        if version == 31 {
            return Err(SilentPaymentError::UnsupportedVersion(version));
        }
        let payload = convert_bits(&data[1..], 5, 8, false)?;
        if payload.len() < 66 || (version == 0 && payload.len() != 66) {
            return Err(SilentPaymentError::InvalidDataLength(payload.len()));
        }
        let scan =
            PublicKey::from_slice(&payload[..33]).map_err(|_| SilentPaymentError::InvalidKey)?;
        let spend =
            PublicKey::from_slice(&payload[33..66]).map_err(|_| SilentPaymentError::InvalidKey)?;
        Ok(Self {
            scan_key: scan.serialize(),
            spend_key: spend.serialize(),
            network,
        })
    }
    pub fn with_label(
        &self,
        scan_secret: &[u8; 32],
        label: u32,
    ) -> Result<Self, SilentPaymentError> {
        let mut result = self.clone();
        let tweak = label_tweak(scan_secret, label)?;
        result.spend_key = PublicKey::from_slice(&self.spend_key)
            .map_err(|_| SilentPaymentError::InvalidKey)?
            .add_exp_tweak(&Secp256k1::new(), &tweak)
            .map_err(|_| SilentPaymentError::InvalidKey)?
            .serialize();
        Ok(result)
    }
}
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let h = sha256(tag);
    let mut data = h.to_vec();
    data.extend_from_slice(&h);
    data.extend_from_slice(msg);
    sha256(&data)
}
fn scalar(bytes: [u8; 32]) -> Result<Scalar, SilentPaymentError> {
    if bytes == [0; 32] {
        return Err(SilentPaymentError::InvalidKey);
    }
    Scalar::from_be_bytes(bytes).map_err(|_| SilentPaymentError::InvalidKey)
}
fn label_tweak(scan_secret: &[u8; 32], label: u32) -> Result<Scalar, SilentPaymentError> {
    SecretKey::from_slice(scan_secret).map_err(|_| SilentPaymentError::InvalidKey)?;
    let mut data = scan_secret.to_vec();
    data.extend_from_slice(&label.to_be_bytes());
    scalar(tagged_hash(b"BIP0352/Label", &data))
}
fn output_tweak(shared_secret: &[u8; 33], index: u32) -> Result<Scalar, SilentPaymentError> {
    let mut data = shared_secret.to_vec();
    data.extend_from_slice(&index.to_be_bytes());
    scalar(tagged_hash(b"BIP0352/SharedSecret", &data))
}
/// Derive a real curve point from the serialized ECDH point (not a hash of it).
pub fn derive_output_key(
    shared_secret: &[u8; 33],
    spend_pubkey: &[u8; 33],
    index: u32,
) -> Result<[u8; 33], SilentPaymentError> {
    PublicKey::from_slice(shared_secret).map_err(|_| SilentPaymentError::InvalidKey)?;
    PublicKey::from_slice(spend_pubkey)
        .map_err(|_| SilentPaymentError::InvalidKey)?
        .add_exp_tweak(&Secp256k1::new(), &output_tweak(shared_secret, index)?)
        .map(|p| p.serialize())
        .map_err(|_| SilentPaymentError::InvalidKey)
}
/// Extract the BIP352 eligible public key, including malleated P2PKH scriptSigs.
pub fn eligible_input_key(tx: &Transaction, index: usize, prevout: &TxOut) -> Option<PublicKey> {
    let input = tx.inputs.get(index)?;
    let spk = prevout.script_pubkey.as_bytes();
    let witness = tx.witness.get(index);
    if spk.len() == 34 && spk[..2] == [0x51, 0x20] {
        if let Some(w) = witness {
            let mut n = w.len();
            if n > 1 && w.get(n - 1)?.first() == Some(&0x50) {
                n -= 1;
            }
            if n > 1 {
                let cb = w.get(n - 1)?;
                if cb.len() >= 33 && cb[1..33] == NUMS {
                    return None;
                }
            }
        }
        let mut compressed = [2; 33];
        compressed[1..].copy_from_slice(&spk[2..]);
        return PublicKey::from_slice(&compressed).ok();
    }
    let parse_compressed = |bytes: &[u8]| {
        if bytes.len() == 33 {
            PublicKey::from_slice(bytes).ok()
        } else {
            None
        }
    };
    if spk.len() == 22 && spk[..2] == [0, 20] {
        return parse_compressed(witness?.iter().last()?);
    }
    if prevout.script_pubkey.is_p2sh()
        && input.script_sig.as_bytes().len() == 23
        && input.script_sig.as_bytes()[..3] == [22, 0, 20]
    {
        return parse_compressed(witness?.iter().last()?);
    }
    if prevout.script_pubkey.is_p2pkh() {
        for instruction in input.script_sig.instructions() {
            if let Ok(Instruction::PushBytes(bytes)) = instruction {
                if bytes.len() == 33 && hash160(bytes) == spk[3..23] {
                    return parse_compressed(bytes);
                }
            }
        }
    }
    None
}
fn input_keys(
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Result<Vec<(usize, PublicKey)>, SilentPaymentError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(SilentPaymentError::InputMismatch);
    }
    if prevouts
        .iter()
        .any(|o| o.script_pubkey.is_witness_program() && o.script_pubkey.as_bytes()[0] > 0x51)
    {
        return Err(SilentPaymentError::UnknownWitnessVersion);
    }
    let keys: Vec<_> = prevouts
        .iter()
        .enumerate()
        .filter_map(|(i, o)| eligible_input_key(tx, i, o).map(|k| (i, k)))
        .collect();
    if keys.is_empty() {
        return Err(SilentPaymentError::NoEligibleInputs);
    }
    Ok(keys)
}
fn input_hash(tx: &Transaction, sum: &PublicKey) -> Result<Scalar, SilentPaymentError> {
    let smallest = tx
        .inputs
        .iter()
        .map(|i| encode(&i.previous_output))
        .min()
        .ok_or(SilentPaymentError::NoEligibleInputs)?;
    let mut data = smallest;
    data.extend_from_slice(&sum.serialize());
    scalar(tagged_hash(b"BIP0352/Inputs", &data))
}
/// Create one output per recipient. Repeated recipients share a counter; all
/// generated outputs must remain in the signed transaction. Input private keys
/// are aligned with tx.inputs, and taproot keys must be the tweaked output keys.
pub fn create_outputs(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_secrets: &[Option<[u8; 32]>],
    recipients: &[SilentPaymentAddress],
) -> Result<Vec<[u8; 33]>, SilentPaymentError> {
    if input_secrets.len() != tx.inputs.len() {
        return Err(SilentPaymentError::InputMismatch);
    }
    let keys = input_keys(tx, prevouts)?;
    let secp = Secp256k1::new();
    let mut sum: Option<SecretKey> = None;
    for (i, expected) in keys {
        let mut sk =
            SecretKey::from_slice(&input_secrets[i].ok_or(SilentPaymentError::InputMismatch)?)
                .map_err(|_| SilentPaymentError::InvalidKey)?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        if prevouts[i].script_pubkey.is_p2tr() && pk.x_only_public_key().1 == Parity::Odd {
            sk = sk.negate();
        }
        if PublicKey::from_secret_key(&secp, &sk) != expected {
            return Err(SilentPaymentError::InputMismatch);
        }
        sum = match sum {
            None => Some(sk),
            Some(s) => s.add_tweak(&Scalar::from(sk)).ok(),
        };
    }
    let sum = sum.ok_or(SilentPaymentError::NoEligibleInputs)?;
    let hash = input_hash(tx, &PublicKey::from_secret_key(&secp, &sum))?;
    let shared_scalar = sum
        .mul_tweak(&hash)
        .map_err(|_| SilentPaymentError::InvalidKey)?;
    let mut counters = std::collections::HashMap::<[u8; 33], u32>::new();
    let mut outputs = Vec::new();
    for recipient in recipients {
        let k = counters.entry(recipient.scan_key).or_default();
        if *k as usize >= MAX_RECIPIENTS_PER_SCAN_KEY {
            return Err(SilentPaymentError::TooManyRecipients);
        }
        let shared = PublicKey::from_slice(&recipient.scan_key)
            .map_err(|_| SilentPaymentError::InvalidKey)?
            .mul_tweak(&secp, &Scalar::from(shared_scalar))
            .map_err(|_| SilentPaymentError::InvalidKey)?
            .serialize();
        outputs.push(derive_output_key(&shared, &recipient.spend_key, *k)?);
        *k += 1;
    }
    Ok(outputs)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentMatch {
    pub output_index: u32,
    pub output_key: [u8; 33],
    /// Add this scalar to the spend private key to spend the output.
    pub private_key_tweak: [u8; 32],
    pub label: Option<u32>,
}
/// Scan using eligible input public keys and all spent output scripts. Always
/// includes change label 0, and advances k after a match regardless of its value.
pub fn scan_transaction(
    scan_secret: &[u8; 32],
    spend_pubkey: &[u8; 33],
    tx: &Transaction,
    prevouts: &[TxOut],
    labels: &[u32],
) -> Result<Vec<SilentPaymentMatch>, SilentPaymentError> {
    let keys = match input_keys(tx, prevouts) {
        Ok(k) => k,
        Err(SilentPaymentError::NoEligibleInputs | SilentPaymentError::UnknownWitnessVersion) => {
            return Ok(vec![])
        }
        Err(e) => return Err(e),
    };
    let refs: Vec<_> = keys.iter().map(|(_, k)| k).collect();
    let sum = match PublicKey::combine_keys(&refs) {
        Ok(p) => p,
        Err(_) => return Ok(vec![]),
    };
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(scan_secret).map_err(|_| SilentPaymentError::InvalidKey)?;
    let shared = sum
        .mul_tweak(&secp, &input_hash(tx, &sum)?)
        .and_then(|p| p.mul_tweak(&secp, &Scalar::from(sk)))
        .map_err(|_| SilentPaymentError::InvalidKey)?
        .serialize();
    let spend = PublicKey::from_slice(spend_pubkey).map_err(|_| SilentPaymentError::InvalidKey)?;
    let mut label_keys = vec![(spend, None, None)];
    let mut label_ids = vec![0];
    label_ids.extend_from_slice(labels);
    label_ids.sort_unstable();
    label_ids.dedup();
    for m in label_ids {
        let t = label_tweak(scan_secret, m)?;
        let key = spend
            .add_exp_tweak(&secp, &t)
            .map_err(|_| SilentPaymentError::InvalidKey)?;
        label_keys.push((key, Some(m), Some(t)));
    }
    let mut remaining: Vec<_> = tx
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(i, o)| {
            if o.script_pubkey.is_p2tr() {
                Some((i, o.script_pubkey.as_bytes()[2..].to_vec()))
            } else {
                None
            }
        })
        .collect();
    let mut found = Vec::new();
    for k in 0..MAX_RECIPIENTS_PER_SCAN_KEY as u32 {
        let tweak = output_tweak(&shared, k)?;
        let mut matched = false;
        for (key, label, lt) in &label_keys {
            let expected = key
                .add_exp_tweak(&secp, &tweak)
                .map_err(|_| SilentPaymentError::InvalidKey)?
                .serialize();
            let mut n = 0;
            while n < remaining.len() {
                if remaining[n].1 == expected[1..] {
                    let mut t = SecretKey::from_slice(&tweak.to_be_bytes())
                        .map_err(|_| SilentPaymentError::InvalidKey)?;
                    if let Some(lt) = lt {
                        t = t
                            .add_tweak(lt)
                            .map_err(|_| SilentPaymentError::InvalidKey)?;
                    }
                    found.push(SilentPaymentMatch {
                        output_index: remaining[n].0 as u32,
                        output_key: expected,
                        private_key_tweak: t.secret_bytes(),
                        label: *label,
                    });
                    remaining.remove(n);
                    matched = true;
                } else {
                    n += 1;
                }
            }
        }
        if !matched {
            break;
        }
    }
    found.sort_by_key(|m| m.output_index);
    Ok(found)
}
