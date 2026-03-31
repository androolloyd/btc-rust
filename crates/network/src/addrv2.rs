//! BIP155 addrv2 message format.
//!
//! Extends the Bitcoin P2P `addr` message to support variable-length
//! addresses, enabling Tor v3 (32 bytes), I2P (32 bytes), CJDNS (16
//! bytes), and future network types.
//!
//! See: <https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki>

use btc_primitives::encode::{Decodable, Encodable, EncodeError, ReadExt, VarInt, WriteExt};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Network identifier per BIP155.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NetworkId {
    /// IPv4 -- 4-byte address.
    IPv4 = 0x01,
    /// IPv6 -- 16-byte address.
    IPv6 = 0x02,
    /// Tor v2 (deprecated) -- 10-byte address.
    TorV2 = 0x03,
    /// Tor v3 -- 32-byte address.
    TorV3 = 0x04,
    /// I2P -- 32-byte address.
    I2P = 0x05,
    /// CJDNS -- 16-byte address.
    CJDNS = 0x06,
}

impl NetworkId {
    /// Expected address length in bytes for this network type.
    pub fn addr_len(self) -> usize {
        match self {
            NetworkId::IPv4 => 4,
            NetworkId::IPv6 => 16,
            NetworkId::TorV2 => 10,
            NetworkId::TorV3 => 32,
            NetworkId::I2P => 32,
            NetworkId::CJDNS => 16,
        }
    }

    /// Try to convert a raw `u8` into a `NetworkId`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(NetworkId::IPv4),
            0x02 => Some(NetworkId::IPv6),
            0x03 => Some(NetworkId::TorV2),
            0x04 => Some(NetworkId::TorV3),
            0x05 => Some(NetworkId::I2P),
            0x06 => Some(NetworkId::CJDNS),
            _ => None,
        }
    }
}

impl Encodable for NetworkId {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        writer.write_u8(*self as u8)
    }
}

impl Decodable for NetworkId {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let byte = reader.read_u8()?;
        NetworkId::from_u8(byte).ok_or_else(|| {
            EncodeError::InvalidData(format!("unknown addrv2 network id: 0x{:02x}", byte))
        })
    }
}

/// A single address entry in the addrv2 message (BIP155).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2 {
    /// Timestamp (seconds since Unix epoch) when this address was last seen.
    pub time: u32,
    /// Service flags advertised by this peer (compact-size encoded on wire).
    pub services: u64,
    /// Network identifier.
    pub network_id: NetworkId,
    /// Raw address bytes (length depends on `network_id`).
    pub addr: Vec<u8>,
    /// TCP port (big-endian on wire).
    pub port: u16,
}

impl AddrV2 {
    /// Create an `AddrV2` entry from an IPv4 address.
    pub fn from_ipv4(ip: Ipv4Addr, port: u16, services: u64, time: u32) -> Self {
        AddrV2 {
            time,
            services,
            network_id: NetworkId::IPv4,
            addr: ip.octets().to_vec(),
            port,
        }
    }

    /// Create an `AddrV2` entry from an IPv6 address.
    pub fn from_ipv6(ip: Ipv6Addr, port: u16, services: u64, time: u32) -> Self {
        AddrV2 {
            time,
            services,
            network_id: NetworkId::IPv6,
            addr: ip.octets().to_vec(),
            port,
        }
    }

    /// Try to interpret the address as an IPv4 address.
    pub fn to_ipv4(&self) -> Option<Ipv4Addr> {
        if self.network_id != NetworkId::IPv4 || self.addr.len() != 4 {
            return None;
        }
        Some(Ipv4Addr::new(self.addr[0], self.addr[1], self.addr[2], self.addr[3]))
    }

    /// Try to interpret the address as an IPv6 address.
    pub fn to_ipv6(&self) -> Option<Ipv6Addr> {
        if self.network_id != NetworkId::IPv6 || self.addr.len() != 16 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.addr);
        Some(Ipv6Addr::from(octets))
    }
}

impl Encodable for AddrV2 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = 0;
        // time: uint32
        written += writer.write_u32_le(self.time)?;
        // services: compact size
        written += VarInt(self.services).encode(writer)?;
        // network id: uint8
        written += self.network_id.encode(writer)?;
        // addr: compact-size-prefixed bytes
        written += VarInt(self.addr.len() as u64).encode(writer)?;
        writer.write_all(&self.addr)?;
        written += self.addr.len();
        // port: uint16, big-endian
        writer.write_all(&self.port.to_be_bytes())?;
        written += 2;
        Ok(written)
    }
}

impl Decodable for AddrV2 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let time = reader.read_u32_le()?;
        let services = VarInt::decode(reader)?.0;
        let network_id = NetworkId::decode(reader)?;
        let addr_len = VarInt::decode(reader)?.0 as usize;

        // Validate address length against expected size for known networks.
        let expected = network_id.addr_len();
        if addr_len != expected {
            return Err(EncodeError::InvalidData(format!(
                "addrv2 network {:?} expects {} byte address, got {}",
                network_id, expected, addr_len,
            )));
        }

        let addr = reader.read_bytes(addr_len)?;

        let mut port_bytes = [0u8; 2];
        reader.read_exact(&mut port_bytes)?;
        let port = u16::from_be_bytes(port_bytes);

        Ok(AddrV2 {
            time,
            services,
            network_id,
            addr,
            port,
        })
    }
}

/// An `addrv2` message containing a vector of `AddrV2` entries.
///
/// On the wire this is serialised as a compact-size count followed by the
/// entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2Message {
    pub addrs: Vec<AddrV2>,
}

impl AddrV2Message {
    /// Create a new message from a list of address entries.
    pub fn new(addrs: Vec<AddrV2>) -> Self {
        Self { addrs }
    }

    /// Maximum number of addresses allowed in one addrv2 message (BIP155).
    pub const MAX_ADDRS: usize = 1000;
}

impl Encodable for AddrV2Message {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, EncodeError> {
        let mut written = VarInt(self.addrs.len() as u64).encode(writer)?;
        for entry in &self.addrs {
            written += entry.encode(writer)?;
        }
        Ok(written)
    }
}

impl Decodable for AddrV2Message {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, EncodeError> {
        let count = VarInt::decode(reader)?.0 as usize;
        if count > AddrV2Message::MAX_ADDRS {
            return Err(EncodeError::InvalidData(format!(
                "addrv2 message contains {} addresses, max is {}",
                count,
                AddrV2Message::MAX_ADDRS,
            )));
        }
        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            addrs.push(AddrV2::decode(reader)?);
        }
        Ok(AddrV2Message { addrs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::encode;

    // ---- NetworkId ----------------------------------------------------------

    #[test]
    fn test_network_id_roundtrip() {
        for &nid in &[
            NetworkId::IPv4,
            NetworkId::IPv6,
            NetworkId::TorV2,
            NetworkId::TorV3,
            NetworkId::I2P,
            NetworkId::CJDNS,
        ] {
            let encoded = encode::encode(&nid);
            assert_eq!(encoded.len(), 1);
            let decoded: NetworkId = encode::decode(&encoded).unwrap();
            assert_eq!(decoded, nid);
        }
    }

    #[test]
    fn test_network_id_unknown() {
        let result: Result<NetworkId, _> = encode::decode(&[0xff]);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_id_addr_lengths() {
        assert_eq!(NetworkId::IPv4.addr_len(), 4);
        assert_eq!(NetworkId::IPv6.addr_len(), 16);
        assert_eq!(NetworkId::TorV2.addr_len(), 10);
        assert_eq!(NetworkId::TorV3.addr_len(), 32);
        assert_eq!(NetworkId::I2P.addr_len(), 32);
        assert_eq!(NetworkId::CJDNS.addr_len(), 16);
    }

    // ---- AddrV2 roundtrip per network type ----------------------------------

    fn roundtrip_addrv2(entry: &AddrV2) {
        let encoded = encode::encode(entry);
        let decoded: AddrV2 = encode::decode(&encoded).unwrap();
        assert_eq!(&decoded, entry);
    }

    #[test]
    fn test_addrv2_ipv4_roundtrip() {
        let entry = AddrV2::from_ipv4(
            Ipv4Addr::new(192, 168, 1, 1),
            8333,
            0x0409, // NODE_NETWORK | NODE_WITNESS
            1_700_000_000,
        );
        roundtrip_addrv2(&entry);
        assert_eq!(entry.to_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(entry.to_ipv6(), None);
    }

    #[test]
    fn test_addrv2_ipv6_roundtrip() {
        let entry = AddrV2::from_ipv6(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            8333,
            0x01,
            1_700_000_000,
        );
        roundtrip_addrv2(&entry);
        assert_eq!(
            entry.to_ipv6(),
            Some(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        );
        assert_eq!(entry.to_ipv4(), None);
    }

    #[test]
    fn test_addrv2_torv2_roundtrip() {
        let entry = AddrV2 {
            time: 1_700_000_000,
            services: 0x01,
            network_id: NetworkId::TorV2,
            addr: vec![0xab; 10],
            port: 9050,
        };
        roundtrip_addrv2(&entry);
    }

    #[test]
    fn test_addrv2_torv3_roundtrip() {
        let entry = AddrV2 {
            time: 1_700_000_000,
            services: 0x01,
            network_id: NetworkId::TorV3,
            addr: vec![0xcd; 32],
            port: 9050,
        };
        roundtrip_addrv2(&entry);
    }

    #[test]
    fn test_addrv2_i2p_roundtrip() {
        let entry = AddrV2 {
            time: 1_700_000_000,
            services: 0x01,
            network_id: NetworkId::I2P,
            addr: vec![0xef; 32],
            port: 0,
        };
        roundtrip_addrv2(&entry);
    }

    #[test]
    fn test_addrv2_cjdns_roundtrip() {
        let entry = AddrV2 {
            time: 1_700_000_000,
            services: 0x01,
            network_id: NetworkId::CJDNS,
            addr: vec![0xfc; 16],
            port: 4132,
        };
        roundtrip_addrv2(&entry);
    }

    // ---- Invalid address length ---------------------------------------------

    #[test]
    fn test_addrv2_wrong_addr_len_rejected() {
        // Manually construct an IPv4 entry with 6-byte address (wrong).
        let mut buf = Vec::new();
        buf.extend_from_slice(&1_700_000_000u32.to_le_bytes()); // time
        VarInt(0x01).encode(&mut buf).unwrap(); // services
        buf.push(0x01); // network id = IPv4
        VarInt(6).encode(&mut buf).unwrap(); // addr len = 6 (should be 4)
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // addr
        buf.extend_from_slice(&8333u16.to_be_bytes()); // port

        let result: Result<AddrV2, _> = encode::decode(&buf);
        assert!(result.is_err());
    }

    // ---- AddrV2Message roundtrip --------------------------------------------

    #[test]
    fn test_addrv2_message_roundtrip() {
        let msg = AddrV2Message::new(vec![
            AddrV2::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 8333, 0x01, 1_600_000_000),
            AddrV2 {
                time: 1_650_000_000,
                services: 0x0409,
                network_id: NetworkId::TorV3,
                addr: vec![0x42; 32],
                port: 9050,
            },
            AddrV2::from_ipv6(
                Ipv6Addr::LOCALHOST,
                18333,
                0x01,
                1_700_000_000,
            ),
        ]);

        let encoded = encode::encode(&msg);
        let decoded: AddrV2Message = encode::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.addrs.len(), 3);
    }

    #[test]
    fn test_addrv2_message_empty() {
        let msg = AddrV2Message::new(vec![]);
        let encoded = encode::encode(&msg);
        let decoded: AddrV2Message = encode::decode(&encoded).unwrap();
        assert_eq!(decoded.addrs.len(), 0);
    }

    // ---- IPv4 / IPv6 conversions --------------------------------------------

    #[test]
    fn test_ipv4_conversion() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let entry = AddrV2::from_ipv4(ip, 8333, 0, 0);
        assert_eq!(entry.to_ipv4(), Some(ip));
    }

    #[test]
    fn test_ipv6_conversion() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let entry = AddrV2::from_ipv6(ip, 8333, 0, 0);
        assert_eq!(entry.to_ipv6(), Some(ip));
    }

    #[test]
    fn test_non_ip_returns_none() {
        let entry = AddrV2 {
            time: 0,
            services: 0,
            network_id: NetworkId::TorV3,
            addr: vec![0x00; 32],
            port: 0,
        };
        assert_eq!(entry.to_ipv4(), None);
        assert_eq!(entry.to_ipv6(), None);
    }

    // ---- Port encoding (big-endian) -----------------------------------------

    #[test]
    fn test_port_big_endian() {
        let entry = AddrV2::from_ipv4(Ipv4Addr::new(1, 2, 3, 4), 0x1234, 0, 0);
        let encoded = encode::encode(&entry);
        // The last two bytes should be the port in big-endian.
        let len = encoded.len();
        assert_eq!(encoded[len - 2], 0x12);
        assert_eq!(encoded[len - 1], 0x34);
    }
}
