use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigError {
    #[error("invalid signature encoding")]
    InvalidEncoding,
    #[error("invalid public key")]
    InvalidPubKey,
    #[error("signature verification failed")]
    VerifyFailed,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// Signature verification trait — designed to be swappable for post-quantum algorithms
pub trait SignatureVerifier: Send + Sync {
    fn verify_ecdsa(&self, msg_hash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> Result<bool, SigError>;
    fn verify_schnorr(&self, msg_hash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> Result<bool, SigError>;
}

/// Default secp256k1-based verifier (current Bitcoin consensus)
pub struct Secp256k1Verifier;

impl SignatureVerifier for Secp256k1Verifier {
    fn verify_ecdsa(&self, msg_hash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> Result<bool, SigError> {
        let secp = secp256k1::Secp256k1::verification_only();
        let message = secp256k1::Message::from_digest(*msg_hash);
        // Use from_der_lax for consensus compatibility — Bitcoin accepted
        // non-strict DER encodings before BIP66. Strict DER enforcement is
        // checked separately when the DERSIG flag is set.
        let mut signature = secp256k1::ecdsa::Signature::from_der_lax(sig)?;
        // Normalize S value (Bitcoin Core normalizes low-S before verification)
        signature.normalize_s();
        let public_key = secp256k1::PublicKey::from_slice(pubkey)?;
        Ok(secp.verify_ecdsa(&message, &signature, &public_key).is_ok())
    }

    fn verify_schnorr(&self, msg_hash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> Result<bool, SigError> {
        let secp = secp256k1::Secp256k1::verification_only();
        let message = secp256k1::Message::from_digest(*msg_hash);

        if sig.len() != 64 {
            return Err(SigError::InvalidEncoding);
        }
        let signature = secp256k1::schnorr::Signature::from_slice(sig)?;

        if pubkey.len() != 32 {
            return Err(SigError::InvalidPubKey);
        }
        let xonly = secp256k1::XOnlyPublicKey::from_slice(pubkey)?;
        Ok(secp.verify_schnorr(&signature, &message, &xonly).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_trait_object() {
        // Verify the trait is object-safe
        let _verifier: Box<dyn SignatureVerifier> = Box::new(Secp256k1Verifier);
    }

    // ---- Coverage: verify_schnorr invalid lengths ----

    #[test]
    fn test_schnorr_invalid_sig_length() {
        let verifier = Secp256k1Verifier;
        let msg = [0xab; 32];
        let bad_sig = [0u8; 32]; // too short
        let pubkey = [0u8; 32];
        let result = verifier.verify_schnorr(&msg, &bad_sig, &pubkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_schnorr_invalid_pubkey_length() {
        let verifier = Secp256k1Verifier;
        let msg = [0xab; 32];
        let sig = [0u8; 64];
        let bad_pubkey = [0u8; 16]; // too short
        let result = verifier.verify_schnorr(&msg, &sig, &bad_pubkey);
        assert!(result.is_err());
    }
}
