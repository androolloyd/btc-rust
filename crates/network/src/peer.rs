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
