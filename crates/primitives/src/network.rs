/// Bitcoin network type — compile-time selectable via NodeTypes pattern (reth-style)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    /// Magic bytes for P2P message headers
    pub fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }

    /// Default P2P port
    pub fn default_port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    /// Default RPC port
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Mainnet => 8332,
            Network::Testnet => 18332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
        }
    }

    /// Address version byte for P2PKH
    pub fn p2pkh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Signet | Network::Regtest => 0x6f,
        }
    }

    /// Address version byte for P2SH
    pub fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::Signet | Network::Regtest => 0xc4,
        }
    }

    /// Bech32 human-readable part
    pub fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
            Network::Signet => "tb",
            Network::Regtest => "bcrt",
        }
    }

    /// BIP32 extended private key version bytes
    pub fn xprv_version(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0x04, 0x88, 0xAD, 0xE4],
            _ => [0x04, 0x35, 0x83, 0x94],
        }
    }

    /// BIP32 extended public key version bytes
    pub fn xpub_version(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0x04, 0x88, 0xB2, 0x1E],
            _ => [0x04, 0x35, 0x87, 0xCF],
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Network::Mainnet
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Signet => write!(f, "signet"),
            Network::Regtest => write!(f, "regtest"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_bytes() {
        assert_eq!(Network::Mainnet.magic(), [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(Network::Testnet.magic(), [0x0b, 0x11, 0x09, 0x07]);
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(Network::Mainnet.default_port(), 8333);
        assert_eq!(Network::Mainnet.default_rpc_port(), 8332);
    }

    #[test]
    fn test_address_versions() {
        assert_eq!(Network::Mainnet.p2pkh_version(), 0x00);
        assert_eq!(Network::Testnet.p2pkh_version(), 0x6f);
    }
}
