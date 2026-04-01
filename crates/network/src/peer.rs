use std::net::SocketAddr;
use crate::protocol::{ProtocolVersion, ServiceFlags};

/// State of a peer connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Connected,
    Handshaking,
    Ready,
    Disconnecting,
    Disconnected,
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub state: PeerState,
    pub version: ProtocolVersion,
    pub services: ServiceFlags,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
    pub inbound: bool,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr, inbound: bool) -> Self {
        PeerInfo {
            addr,
            state: PeerState::Connecting,
            version: ProtocolVersion::CURRENT,
            services: ServiceFlags::NONE,
            user_agent: String::new(),
            start_height: 0,
            relay: true,
            inbound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333)
    }

    #[test]
    fn test_peer_info_new_outbound() {
        let addr = test_addr();
        let info = PeerInfo::new(addr, false);
        assert_eq!(info.addr, addr);
        assert_eq!(info.state, PeerState::Connecting);
        assert_eq!(info.version, ProtocolVersion::CURRENT);
        assert_eq!(info.services, ServiceFlags::NONE);
        assert_eq!(info.user_agent, "");
        assert_eq!(info.start_height, 0);
        assert!(info.relay);
        assert!(!info.inbound);
    }

    #[test]
    fn test_peer_info_new_inbound() {
        let addr = test_addr();
        let info = PeerInfo::new(addr, true);
        assert!(info.inbound);
    }

    #[test]
    fn test_peer_state_values() {
        let states = [
            PeerState::Connecting,
            PeerState::Connected,
            PeerState::Handshaking,
            PeerState::Ready,
            PeerState::Disconnecting,
            PeerState::Disconnected,
        ];
        for i in 0..states.len() {
            for j in 0..states.len() {
                if i == j {
                    assert_eq!(states[i], states[j]);
                } else {
                    assert_ne!(states[i], states[j]);
                }
            }
        }
    }

    #[test]
    fn test_peer_state_copy() {
        let state = PeerState::Ready;
        let copy = state;
        assert_eq!(state, copy);
    }

    #[test]
    fn test_peer_info_clone() {
        let addr = test_addr();
        let info = PeerInfo::new(addr, false);
        let cloned = info.clone();
        assert_eq!(cloned.addr, info.addr);
        assert_eq!(cloned.state, info.state);
        assert_eq!(cloned.version, info.version);
        assert_eq!(cloned.services, info.services);
        assert_eq!(cloned.user_agent, info.user_agent);
        assert_eq!(cloned.start_height, info.start_height);
        assert_eq!(cloned.relay, info.relay);
        assert_eq!(cloned.inbound, info.inbound);
    }

    #[test]
    fn test_peer_info_debug() {
        let info = PeerInfo::new(test_addr(), false);
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("Connecting"));
    }
}
