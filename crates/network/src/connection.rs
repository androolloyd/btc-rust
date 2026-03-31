use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use btc_primitives::network::Network;

use crate::codec::BitcoinCodec;
use crate::handshake::{Handshake, HandshakeState};
use crate::message::NetworkMessage;

/// Error type for connection operations.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("connection closed")]
    ConnectionClosed,
}

/// A Bitcoin P2P connection wrapping a framed TCP stream.
pub struct Connection {
    framed: Framed<TcpStream, BitcoinCodec>,
}

impl Connection {
    /// Establish an outbound TCP connection to the given address.
    pub async fn connect_outbound(
        addr: SocketAddr,
        network: Network,
    ) -> Result<Self, ConnectionError> {
        let stream = TcpStream::connect(addr).await?;
        let codec = BitcoinCodec::new(network.magic());
        let framed = Framed::new(stream, codec);
        Ok(Connection { framed })
    }

    /// Wrap an existing TcpStream (e.g., from an accepted inbound connection).
    pub fn from_stream(stream: TcpStream, network: Network) -> Self {
        let codec = BitcoinCodec::new(network.magic());
        let framed = Framed::new(stream, codec);
        Connection { framed }
    }

    /// Send a single message to the peer.
    pub async fn send_message(&mut self, msg: NetworkMessage) -> Result<(), ConnectionError> {
        self.framed.send(msg).await?;
        Ok(())
    }

    /// Receive a single message from the peer.
    /// Returns `ConnectionError::ConnectionClosed` if the stream ends.
    pub async fn recv_message(&mut self) -> Result<NetworkMessage, ConnectionError> {
        match self.framed.next().await {
            Some(Ok(msg)) => Ok(msg),
            Some(Err(e)) => Err(ConnectionError::Io(e)),
            None => Err(ConnectionError::ConnectionClosed),
        }
    }

    /// Perform the version handshake as the outbound (connecting) side.
    ///
    /// Sends our version, waits for the peer's version + verack, sends our verack.
    /// Returns the completed `Handshake` with peer information on success.
    pub async fn perform_handshake(
        &mut self,
        network: Network,
        start_height: i32,
    ) -> Result<Handshake, ConnectionError> {
        let mut hs = Handshake::new();

        // 1. Send our version
        let version_msg = Handshake::build_version_message(network, start_height);
        self.send_message(version_msg).await?;
        hs.version_sent();

        // 2-4. Exchange version/verack until Ready
        loop {
            let msg = self.recv_message().await?;
            let responses = hs.process_message(&msg);

            for resp in responses {
                self.send_message(resp).await?;
            }

            if hs.is_ready() {
                return Ok(hs);
            }

            if hs.state() == HandshakeState::Failed {
                return Err(ConnectionError::HandshakeFailed(
                    "handshake state machine entered failed state".into(),
                ));
            }
        }
    }
}
