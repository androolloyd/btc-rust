/// Bitcoin network type — compile-time selectable via NodeTypes pattern (reth-style)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    /// Testnet4 (BIP94) — replacement for testnet3 with proper difficulty adjustment.
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    /// Magic bytes for P2P message headers
    pub fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }

    /// Default P2P port
    pub fn default_port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::Testnet4 => 48333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    /// Default RPC port
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Mainnet => 8332,
            Network::Testnet => 18332,
            Network::Testnet4 => 48332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
        }
    }

    /// Address version byte for P2PKH
    pub fn p2pkh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Testnet4 | Network::Signet | Network::Regtest => 0x6f,
        }
    }

    /// Address version byte for P2SH
    pub fn p2sh_version(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::Testnet4 | Network::Signet | Network::Regtest => 0xc4,
        }
    }

    /// Bech32 human-readable part
    pub fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Testnet4 => "tb",
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
            Network::Testnet4 => write!(f, "testnet4"),
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

    #[test]
    fn test_all_networks_magic() {
        assert_eq!(Network::Signet.magic(), [0x0a, 0x03, 0xcf, 0x40]);
        assert_eq!(Network::Regtest.magic(), [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(Network::Testnet4.magic(), [0x1c, 0x16, 0x3f, 0x28]);
    }

    #[test]
    fn test_all_networks_ports() {
        assert_eq!(Network::Testnet.default_port(), 18333);
        assert_eq!(Network::Testnet4.default_port(), 48333);
        assert_eq!(Network::Signet.default_port(), 38333);
        assert_eq!(Network::Regtest.default_port(), 18444);
        assert_eq!(Network::Testnet.default_rpc_port(), 18332);
        assert_eq!(Network::Testnet4.default_rpc_port(), 48332);
        assert_eq!(Network::Signet.default_rpc_port(), 38332);
        assert_eq!(Network::Regtest.default_rpc_port(), 18443);
    }

    #[test]
    fn test_p2sh_versions() {
        assert_eq!(Network::Mainnet.p2sh_version(), 0x05);
        assert_eq!(Network::Testnet.p2sh_version(), 0xc4);
        assert_eq!(Network::Testnet4.p2sh_version(), 0xc4);
        assert_eq!(Network::Signet.p2sh_version(), 0xc4);
        assert_eq!(Network::Regtest.p2sh_version(), 0xc4);
    }

    #[test]
    fn test_p2pkh_versions_all() {
        assert_eq!(Network::Signet.p2pkh_version(), 0x6f);
        assert_eq!(Network::Testnet4.p2pkh_version(), 0x6f);
        assert_eq!(Network::Regtest.p2pkh_version(), 0x6f);
    }

    #[test]
    fn test_bech32_hrp() {
        assert_eq!(Network::Mainnet.bech32_hrp(), "bc");
        assert_eq!(Network::Testnet.bech32_hrp(), "tb");
        assert_eq!(Network::Testnet4.bech32_hrp(), "tb");
        assert_eq!(Network::Signet.bech32_hrp(), "tb");
        assert_eq!(Network::Regtest.bech32_hrp(), "bcrt");
    }

    #[test]
    fn test_xprv_version() {
        assert_eq!(Network::Mainnet.xprv_version(), [0x04, 0x88, 0xAD, 0xE4]);
        assert_eq!(Network::Testnet.xprv_version(), [0x04, 0x35, 0x83, 0x94]);
        assert_eq!(Network::Signet.xprv_version(), [0x04, 0x35, 0x83, 0x94]);
        assert_eq!(Network::Regtest.xprv_version(), [0x04, 0x35, 0x83, 0x94]);
    }

    #[test]
    fn test_xpub_version() {
        assert_eq!(Network::Mainnet.xpub_version(), [0x04, 0x88, 0xB2, 0x1E]);
        assert_eq!(Network::Testnet.xpub_version(), [0x04, 0x35, 0x87, 0xCF]);
    }

    #[test]
    fn test_network_default() {
        assert_eq!(Network::default(), Network::Mainnet);
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Testnet4.to_string(), "testnet4");
        assert_eq!(Network::Signet.to_string(), "signet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
    }

    #[test]
    fn test_testnet4_properties() {
        let net = Network::Testnet4;
        assert_eq!(net.magic(), [0x1c, 0x16, 0x3f, 0x28]);
        assert_eq!(net.default_port(), 48333);
        assert_eq!(net.default_rpc_port(), 48332);
        assert_eq!(net.p2pkh_version(), 0x6f);
        assert_eq!(net.p2sh_version(), 0xc4);
        assert_eq!(net.bech32_hrp(), "tb");
        assert_eq!(net.xprv_version(), [0x04, 0x35, 0x83, 0x94]);
        assert_eq!(net.xpub_version(), [0x04, 0x35, 0x87, 0xCF]);
    }
}
