//! Strict WIF private keys. Diagnostics and Debug never include secret material.
use crate::{bip32::base58check_decode, Network};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Clone)]
pub struct WifPrivateKey {
    secret: SecretKey,
    compressed: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid WIF private key: {0}")]
pub struct WifError(&'static str);

impl std::fmt::Debug for WifPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WifPrivateKey")
            .field("compressed", &self.compressed)
            .finish_non_exhaustive()
    }
}

impl WifPrivateKey {
    pub fn from_wif(text: &str, network: Network) -> Result<Self, WifError> {
        if ![51, 52].contains(&text.len()) {
            return Err(WifError("length"));
        }
        let payload = base58check_decode(text).map_err(|_| WifError("encoding or checksum"))?;
        if ![33, 34].contains(&payload.len()) || (payload.len() == 34 && payload[33] != 1) {
            return Err(WifError("compression marker or payload length"));
        }
        let version = if network == Network::Mainnet {
            0x80
        } else {
            0xef
        };
        if payload[0] != version {
            return Err(WifError("version does not match selected network"));
        }
        let secret = SecretKey::from_slice(&payload[1..33]).map_err(|_| WifError("scalar"))?;
        Ok(Self {
            secret,
            compressed: payload.len() == 34,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        let public = PublicKey::from_secret_key(&Secp256k1::new(), &self.secret);
        if self.compressed {
            public.serialize().to_vec()
        } else {
            public.serialize_uncompressed().to_vec()
        }
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }
}
