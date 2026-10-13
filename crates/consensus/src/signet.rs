//! BIP325 challenge verification using the two virtual transactions.
#[cfg(feature = "segwit")]
use crate::{script_engine::ScriptFlags, sig_verify::Secp256k1Verifier, witness::verify_input};
#[cfg(feature = "segwit")]
use btc_primitives::hash::BlockHash;
use btc_primitives::{
    amount::Amount,
    block::{merkle_root, Block},
    encode::{Decodable, ReadExt, VarInt},
    script::{Instruction, Opcode, ScriptBuf},
    transaction::{OutPoint, Transaction, TxIn, TxOut, Witness},
};
use thiserror::Error;
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];
#[derive(Debug, Error)]
pub enum SignetError {
    #[error("Signet challenge verification requires the SegWit feature")]
    MissingSegwitFeature,
    #[error("block has no transactions")]
    NoTransactions,
    #[error("first transaction is not coinbase")]
    NoCoinbase,
    #[error("BIP141 witness commitment missing")]
    CommitmentNotFound,
    #[error("malformed signet solution")]
    InvalidCommitmentHeader,
    #[error("signet challenge verification failed")]
    ChallengeFailed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignetChallenge {
    pub script: ScriptBuf,
}
impl SignetChallenge {
    pub fn new(script: ScriptBuf) -> Self {
        Self { script }
    }
    pub fn default_signet() -> Self {
        Self::new(ScriptBuf::from_bytes(hex::decode("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae").unwrap()))
    }
}
/// Construct the BIP325 virtual spend with the solution removed from the
/// coinbase commitment. Exposed so custom signet miners can sign the same data.
pub fn signet_transactions(
    block: &Block,
    challenge: &SignetChallenge,
) -> Result<(Transaction, Transaction), SignetError> {
    let mut coinbase = block
        .transactions
        .first()
        .ok_or(SignetError::NoTransactions)?
        .clone();
    if !coinbase.is_coinbase() {
        return Err(SignetError::NoCoinbase);
    }
    let index = coinbase
        .outputs
        .iter()
        .rposition(|o| {
            let s = o.script_pubkey.as_bytes();
            s.len() >= 38 && s[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
        })
        .ok_or(SignetError::CommitmentNotFound)?;
    let mut replacement = ScriptBuf::new();
    let mut solution = None;
    for instruction in coinbase.outputs[index].script_pubkey.instructions() {
        match instruction.map_err(|_| SignetError::InvalidCommitmentHeader)? {
            Instruction::Op(op) => replacement.push_opcode(op),
            Instruction::PushBytes(data) => {
                if solution.is_none() && data.len() > 4 && data[..4] == SIGNET_HEADER {
                    solution = Some(data[4..].to_vec());
                    replacement.push_slice(&SIGNET_HEADER);
                } else {
                    replacement.push_slice(data);
                }
            }
        }
    }
    let mut script_sig = ScriptBuf::new();
    let mut witness = Witness::new();
    if let Some(solution) = solution {
        coinbase.outputs[index].script_pubkey = replacement;
        let mut reader = std::io::Cursor::new(&solution);
        script_sig =
            ScriptBuf::decode(&mut reader).map_err(|_| SignetError::InvalidCommitmentHeader)?;
        let count = VarInt::decode(&mut reader)
            .map_err(|_| SignetError::InvalidCommitmentHeader)?
            .0;
        if count > solution.len() as u64 {
            return Err(SignetError::InvalidCommitmentHeader);
        }
        for _ in 0..count {
            let len = VarInt::decode(&mut reader)
                .map_err(|_| SignetError::InvalidCommitmentHeader)?
                .0;
            if len > solution.len() as u64 {
                return Err(SignetError::InvalidCommitmentHeader);
            }
            witness.push(
                reader
                    .read_bytes(len as usize)
                    .map_err(|_| SignetError::InvalidCommitmentHeader)?,
            );
        }
        if reader.position() != solution.len() as u64 {
            return Err(SignetError::InvalidCommitmentHeader);
        }
    }
    let mut leaves = vec![coinbase.txid().to_bytes()];
    leaves.extend(
        block
            .transactions
            .iter()
            .skip(1)
            .map(|t| t.txid().to_bytes()),
    );
    let mut block_data = block.header.version.to_le_bytes().to_vec();
    block_data.extend_from_slice(block.header.prev_blockhash.as_bytes());
    block_data.extend_from_slice(&merkle_root(&leaves));
    block_data.extend_from_slice(&block.header.time.to_le_bytes());
    let mut spend_sig = ScriptBuf::new();
    spend_sig.push_opcode(Opcode::OP_0);
    spend_sig.push_slice(&block_data);
    let spend = Transaction {
        version: 0,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: spend_sig,
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: challenge.script.clone(),
        }],
        witness: vec![],
    };
    let sign = Transaction {
        version: 0,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(spend.txid(), 0),
            script_sig,
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![Opcode::OP_RETURN as u8]),
        }],
        witness: vec![witness],
    };
    Ok((spend, sign))
}
#[cfg(feature = "segwit")]
pub fn validate_signet_block(
    block: &Block,
    challenge: &SignetChallenge,
) -> Result<(), SignetError> {
    if block.block_hash()
        == BlockHash::from_hex("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
            .unwrap()
    {
        return Ok(());
    }
    let (spend, sign) = signet_transactions(block, challenge)?;
    let flags = ScriptFlags {
        verify_p2sh: true,
        verify_witness: true,
        verify_dersig: true,
        verify_nulldummy: true,
        ..ScriptFlags::none()
    };
    verify_input(&sign, 0, &spend.outputs[0], &Secp256k1Verifier, &flags)
        .map_err(|_| SignetError::ChallengeFailed)
}

#[cfg(not(feature = "segwit"))]
pub fn validate_signet_block(
    _block: &Block,
    _challenge: &SignetChallenge,
) -> Result<(), SignetError> {
    Err(SignetError::MissingSegwitFeature)
}

#[cfg(all(test, feature = "segwit"))]
mod tests {
    use super::*;
    use btc_primitives::hash::TxHash;
    use btc_primitives::{
        block::BlockHeader, compact::CompactTarget, encode::encode, hash::sha256d,
    };
    fn block() -> Block {
        let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment.extend_from_slice(&[0; 32]);
        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::ZERO,
                merkle_root: TxHash::ZERO,
                time: 1598918401,
                bits: CompactTarget::from_u32(0x1e0377ae),
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::COINBASE,
                    script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(commitment),
                }],
                witness: vec![Witness::from_items(vec![vec![0; 32]])],
                lock_time: 0,
            }],
        }
    }
    #[test]
    fn standard_challenge_matches_network_magic() {
        let c = SignetChallenge::default_signet();
        let encoded = encode(&c.script);
        assert_eq!(&sha256d(&encoded)[..4], &[0x0a, 0x03, 0xcf, 0x40]);
    }
    #[test]
    fn trivial_challenge_needs_no_solution() {
        let b = block();
        assert!(validate_signet_block(
            &b,
            &SignetChallenge::new(ScriptBuf::from_bytes(vec![0x51]))
        )
        .is_ok());
        assert!(validate_signet_block(&b, &SignetChallenge::default_signet()).is_err());
    }
    #[test]
    fn real_signature_and_header_tampering() {
        use crate::sighash::{sighash_legacy, SighashType};
        use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut script = ScriptBuf::new();
        script.push_slice(&pk.serialize());
        script.push_opcode(Opcode::OP_CHECKSIG);
        let challenge = SignetChallenge::new(script);
        let mut b = block();
        let mut empty = SIGNET_HEADER.to_vec();
        empty.extend_from_slice(&[0, 0]);
        b.transactions[0].outputs[0]
            .script_pubkey
            .push_slice(&empty);
        let (_, sign) = signet_transactions(&b, &challenge).unwrap();
        let digest =
            sighash_legacy(&sign, 0, challenge.script.as_bytes(), SighashType::ALL).unwrap();
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest(digest), &sk)
            .serialize_der()
            .to_vec();
        signature.push(1);
        let mut sig = ScriptBuf::new();
        sig.push_slice(&signature);
        let mut solution = SIGNET_HEADER.to_vec();
        solution.extend(encode(&sig));
        solution.push(0);
        b.transactions[0].outputs[0].script_pubkey =
            block().transactions[0].outputs[0].script_pubkey.clone();
        b.transactions[0].outputs[0]
            .script_pubkey
            .push_slice(&solution);
        assert!(validate_signet_block(&b, &challenge).is_ok());
        b.header.nonce += 1;
        assert!(validate_signet_block(&b, &challenge).is_ok());
        b.header.time += 1;
        assert!(validate_signet_block(&b, &challenge).is_err());
    }
    #[test]
    fn malformed_solution_rejected() {
        let mut b = block();
        let mut solution = SIGNET_HEADER.to_vec();
        solution.extend([0xfd, 1, 0]);
        b.transactions[0].outputs[0]
            .script_pubkey
            .push_slice(&solution);
        assert!(matches!(
            signet_transactions(&b, &SignetChallenge::default_signet()),
            Err(SignetError::InvalidCommitmentHeader)
        ));
    }
}
