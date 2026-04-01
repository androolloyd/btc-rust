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
            Some(Err(e)) => {
                tracing::debug!(error = %e, "message decode/io error");
                Err(ConnectionError::Io(e))
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_connection_error_io() {
        let err = ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_connection_error_handshake_failed() {
        let err = ConnectionError::HandshakeFailed("test failure".into());
        assert!(err.to_string().contains("handshake failed"));
        assert!(err.to_string().contains("test failure"));
    }

    #[test]
    fn test_connection_error_closed() {
        let err = ConnectionError::ConnectionClosed;
        assert!(err.to_string().contains("connection closed"));
    }

    #[tokio::test]
    async fn test_from_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _conn = Connection::from_stream(stream, Network::Mainnet);
        });

        let (stream, _) = listener.accept().await.unwrap();
        let _conn = Connection::from_stream(stream, Network::Mainnet);

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_send_and_recv_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = Connection::from_stream(stream, Network::Mainnet);
            let msg = conn.recv_message().await.unwrap();
            match msg {
                NetworkMessage::Ping(n) => assert_eq!(n, 42),
                other => panic!("expected Ping, got {:?}", other),
            }
            conn.send_message(NetworkMessage::Pong(42)).await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = Connection::from_stream(stream, Network::Mainnet);
        conn.send_message(NetworkMessage::Ping(42)).await.unwrap();
        let response = conn.recv_message().await.unwrap();
        match response {
            NetworkMessage::Pong(n) => assert_eq!(n, 42),
            other => panic!("expected Pong, got {:?}", other),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_recv_on_closed_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream); // Close immediately
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = Connection::from_stream(stream, Network::Mainnet);

        server.await.unwrap();

        let result = conn.recv_message().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_multiple_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = Connection::from_stream(stream, Network::Mainnet);
            let msg1 = conn.recv_message().await.unwrap();
            let msg2 = conn.recv_message().await.unwrap();
            let msg3 = conn.recv_message().await.unwrap();
            assert!(matches!(msg1, NetworkMessage::Verack));
            assert!(matches!(msg2, NetworkMessage::SendHeaders));
            match msg3 {
                NetworkMessage::Ping(n) => assert_eq!(n, 123),
                other => panic!("expected Ping, got {:?}", other),
            }
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = Connection::from_stream(stream, Network::Mainnet);
        conn.send_message(NetworkMessage::Verack).await.unwrap();
        conn.send_message(NetworkMessage::SendHeaders).await.unwrap();
        conn.send_message(NetworkMessage::Ping(123)).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_perform_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Simulated peer on the server side
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = Connection::from_stream(stream, Network::Mainnet);

            // Receive client's version
            let msg = conn.recv_message().await.unwrap();
            assert!(matches!(msg, NetworkMessage::Version(_)));

            // Send our version
            let ver = crate::message::VersionMessage {
                version: 70016,
                services: 1,
                timestamp: 1_700_000_000,
                receiver: crate::message::NetAddress::default(),
                sender: crate::message::NetAddress::default(),
                nonce: 99,
                user_agent: "/test-peer/".to_string(),
                start_height: 800_000,
                relay: true,
            };
            conn.send_message(NetworkMessage::Version(ver)).await.unwrap();

            // Receive wtxidrelay and verack from client
            let msg1 = conn.recv_message().await.unwrap();
            assert!(matches!(msg1, NetworkMessage::WtxidRelay));
            let msg2 = conn.recv_message().await.unwrap();
            assert!(matches!(msg2, NetworkMessage::Verack));

            // Send our verack
            conn.send_message(NetworkMessage::Verack).await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = Connection::from_stream(stream, Network::Mainnet);
        let hs = conn.perform_handshake(Network::Mainnet, 800_000).await.unwrap();
        assert!(hs.is_ready());
        assert!(hs.peer_version().is_some());
        assert_eq!(hs.peer_version().unwrap().user_agent, "/test-peer/");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_outbound_refused() {
        // Try to connect to a port that's not listening
        let result = Connection::connect_outbound(
            "127.0.0.1:1".parse().unwrap(),
            Network::Mainnet,
        )
        .await;
        assert!(result.is_err());
    }
}
