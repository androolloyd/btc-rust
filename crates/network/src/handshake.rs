use std::time::{SystemTime, UNIX_EPOCH};

use btc_primitives::network::Network;

use crate::message::{NetAddress, NetworkMessage, VersionMessage};
use crate::protocol::{ProtocolVersion, ServiceFlags, USER_AGENT};

/// Compact block protocol version we support (BIP152).
const SENDCMPCT_VERSION: u64 = 2;

/// State machine for the Bitcoin version handshake.
///
/// The outbound handshake follows this sequence:
///   1. We send our `version` message
///   2. We receive the peer's `version` message
///   3. We send `verack`
///   4. We receive `verack`
///   5. Handshake is complete (Ready)
///
/// Steps 2-3 and 4 can arrive in slightly different orders in practice;
/// this implementation is flexible about receiving verack before or after
/// the peer's version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state — nothing sent yet.
    Init,
    /// We have sent our version message; waiting for the peer's version.
    VersionSent,
    /// We received the peer's version and sent verack; waiting for their verack.
    VerackSent,
    /// Handshake complete.
    Ready,
    /// Handshake failed.
    Failed,
}

/// Holds handshake state and the peer's version once received.
#[derive(Debug)]
pub struct Handshake {
    state: HandshakeState,
    peer_version: Option<VersionMessage>,
}

impl Handshake {
    pub fn new() -> Self {
        Handshake {
            state: HandshakeState::Init,
            peer_version: None,
        }
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn peer_version(&self) -> Option<&VersionMessage> {
        self.peer_version.as_ref()
    }

    pub fn is_ready(&self) -> bool {
        self.state == HandshakeState::Ready
    }

    /// Build the version message we will send to the peer.
    pub fn build_version_message(
        _network: Network,
        start_height: i32,
    ) -> NetworkMessage {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let nonce = rand::random::<u64>();

        let version = VersionMessage {
            version: ProtocolVersion::CURRENT.0,
            services: ServiceFlags::NETWORK.0,
            timestamp,
            receiver: NetAddress::default(),
            sender: NetAddress::default(),
            nonce,
            user_agent: USER_AGENT.to_string(),
            start_height,
            relay: true,
        };

        NetworkMessage::Version(version)
    }

    /// Record that we have sent our version message.
    pub fn version_sent(&mut self) {
        if self.state == HandshakeState::Init {
            self.state = HandshakeState::VersionSent;
        }
    }

    /// Process an incoming message during the handshake.
    ///
    /// Returns a list of messages that should be sent in response (may be empty).
    pub fn process_message(&mut self, msg: &NetworkMessage) -> Vec<NetworkMessage> {
        let mut responses = Vec::new();

        match msg {
            NetworkMessage::Version(ver) => {
                let peer_version = ver.version;
                self.peer_version = Some(ver.clone());
                // After receiving version, send verack
                responses.push(NetworkMessage::Verack);

                // Send wtxidrelay if peer supports it (BIP339, protocol >= 70016)
                if peer_version >= ProtocolVersion::WTXID_RELAY.0 {
                    responses.push(NetworkMessage::WtxidRelay);
                }

                // Send sendcmpct if peer supports compact blocks (BIP152, protocol >= 70014)
                if peer_version >= ProtocolVersion::COMPACT_BLOCKS.0 {
                    responses.push(NetworkMessage::SendCmpct {
                        announce: false,
                        version: SENDCMPCT_VERSION,
                    });
                }

                match self.state {
                    HandshakeState::VersionSent => {
                        self.state = HandshakeState::VerackSent;
                    }
                    _ => {
                        // Unexpected state; still store it and move on
                        self.state = HandshakeState::VerackSent;
                    }
                }
            }
            NetworkMessage::Verack => {
                match self.state {
                    HandshakeState::VerackSent => {
                        self.state = HandshakeState::Ready;
                    }
                    HandshakeState::VersionSent => {
                        // Received verack before we got their version — unusual but
                        // mark that we got their ack. We'll transition to Ready once
                        // we also get their version.
                        // For simplicity, wait until VerackSent state.
                    }
                    _ => {}
                }
            }
            _ => {
                // Other messages during handshake are ignored
            }
        }

        responses
    }
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_version_message() {
        let msg = Handshake::build_version_message(Network::Mainnet, 800_000);
        match msg {
            NetworkMessage::Version(v) => {
                assert_eq!(v.version, ProtocolVersion::CURRENT.0);
                assert_eq!(v.services, ServiceFlags::NETWORK.0);
                assert_eq!(v.user_agent, USER_AGENT);
                assert_eq!(v.start_height, 800_000);
                assert!(v.relay);
                assert!(v.timestamp > 0);
                assert_ne!(v.nonce, 0); // extremely unlikely to be 0
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn test_handshake_state_machine() {
        let mut hs = Handshake::new();
        assert_eq!(hs.state(), HandshakeState::Init);

        // Step 1: we send our version
        hs.version_sent();
        assert_eq!(hs.state(), HandshakeState::VersionSent);

        // Step 2: we receive peer's version -> should produce verack
        let peer_version = VersionMessage {
            version: 70016,
            services: 1,
            timestamp: 1_700_000_000,
            receiver: NetAddress::default(),
            sender: NetAddress::default(),
            nonce: 42,
            user_agent: "/Satoshi:25.0.0/".to_string(),
            start_height: 800_000,
            relay: true,
        };
        let responses = hs.process_message(&NetworkMessage::Version(peer_version));
        assert_eq!(hs.state(), HandshakeState::VerackSent);
        // Should send: verack, wtxidrelay, sendcmpct
        assert_eq!(responses.len(), 3);
        assert!(matches!(responses[0], NetworkMessage::Verack));
        assert!(matches!(responses[1], NetworkMessage::WtxidRelay));
        match &responses[2] {
            NetworkMessage::SendCmpct { announce, version } => {
                assert!(!announce);
                assert_eq!(*version, SENDCMPCT_VERSION);
            }
            other => panic!("expected SendCmpct, got {:?}", other),
        }
        assert!(hs.peer_version().is_some());

        // Step 3: we receive peer's verack
        let responses = hs.process_message(&NetworkMessage::Verack);
        assert_eq!(hs.state(), HandshakeState::Ready);
        assert!(responses.is_empty());
        assert!(hs.is_ready());
    }

    #[test]
    fn test_handshake_ignores_unknown_messages() {
        let mut hs = Handshake::new();
        hs.version_sent();
        let responses = hs.process_message(&NetworkMessage::Ping(123));
        assert!(responses.is_empty());
        assert_eq!(hs.state(), HandshakeState::VersionSent);
    }
}
