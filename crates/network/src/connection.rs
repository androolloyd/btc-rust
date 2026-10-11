use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
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
    framed: Transport,
}

enum Transport {
    V1(Framed<TcpStream, BitcoinCodec>),
    #[cfg(feature = "v2")]
    V2(Framed<TcpStream, crate::v2codec::V2Codec>),
}

impl Connection {
    /// Detect inbound transport using BIP324's complete v1 version prefix.
    /// Caller sets an overall timeout; consumed v1 bytes remain in the codec.
    pub async fn accept_inbound(
        mut stream: TcpStream,
        network: Network,
    ) -> Result<Self, ConnectionError> {
        let mut expected = network.magic().to_vec();
        expected.extend_from_slice(b"version\0\0\0\0\0");
        let mut prefix = Vec::new();
        for byte in expected {
            let received = stream.read_u8().await?;
            prefix.push(received);
            if received != byte {
                #[cfg(feature = "v2")]
                {
                    let codec =
                        crate::v2codec::handshake_with_prefix(&mut stream, network, false, &prefix)
                            .await?;
                    return Ok(Self {
                        framed: Transport::V2(Framed::new(stream, codec)),
                    });
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConnectionError::HandshakeFailed(
                    "v2 transport unavailable".into(),
                ));
            }
        }
        let mut framed = Framed::new(stream, BitcoinCodec::new(network.magic()));
        framed.read_buffer_mut().extend_from_slice(&prefix);
        Ok(Self {
            framed: Transport::V1(framed),
        })
    }

    pub fn session_id(&self) -> Option<[u8; 32]> {
        match &self.framed {
            Transport::V1(_) => None,
            #[cfg(feature = "v2")]
            Transport::V2(framed) => framed.codec().session_id().copied(),
        }
    }

    /// The accepting side waits for version before sending its version/verack.
    pub async fn perform_inbound_handshake(
        &mut self,
        network: Network,
        start_height: i32,
        relay_transactions: bool,
    ) -> Result<Handshake, ConnectionError> {
        let first = self.recv_message().await?;
        let NetworkMessage::Version(version) = &first else {
            return Err(ConnectionError::HandshakeFailed(
                "first application message must be version".into(),
            ));
        };
        if version.version < crate::protocol::ProtocolVersion::MIN_SUPPORTED.0 {
            return Err(ConnectionError::HandshakeFailed(
                "obsolete protocol version".into(),
            ));
        }
        let mut hs = Handshake::new();
        self.send_message(version_message(network, start_height, relay_transactions))
            .await?;
        hs.version_sent();
        for response in hs.process_message(&first) {
            self.send_message(response).await?;
        }
        loop {
            let message = self.recv_message().await?;
            if matches!(message, NetworkMessage::Version(_)) {
                return Err(ConnectionError::HandshakeFailed("duplicate version".into()));
            }
            for response in hs.process_message(&message) {
                self.send_message(response).await?;
            }
            if hs.is_ready() {
                return Ok(hs);
            }
        }
    }

    /// Establish an outbound TCP connection to the given address.
    pub async fn connect_outbound(
        addr: SocketAddr,
        network: Network,
    ) -> Result<Self, ConnectionError> {
        let stream = TcpStream::connect(addr).await?;
        let codec = BitcoinCodec::new(network.magic());
        let framed = Framed::new(stream, codec);
        Ok(Connection {
            framed: Transport::V1(framed),
        })
    }

    /// Prefer BIP324, reconnecting with v1 when the peer does not support it.
    pub async fn connect_outbound_negotiated(
        addr: SocketAddr,
        network: Network,
    ) -> Result<Self, ConnectionError> {
        #[cfg(feature = "v2")]
        if let Ok(Ok(connection)) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Self::connect_outbound_v2(addr, network),
        )
        .await
        {
            return Ok(connection);
        }
        Self::connect_outbound(addr, network).await
    }
    #[cfg(feature = "v2")]
    pub async fn connect_outbound_v2(
        addr: SocketAddr,
        network: Network,
    ) -> Result<Self, ConnectionError> {
        Self::from_stream_v2(TcpStream::connect(addr).await?, network, true).await
    }
    #[cfg(feature = "v2")]
    pub async fn from_stream_v2(
        mut stream: TcpStream,
        network: Network,
        initiating: bool,
    ) -> Result<Self, ConnectionError> {
        let codec = crate::v2codec::handshake(&mut stream, network, initiating).await?;
        Ok(Self {
            framed: Transport::V2(Framed::new(stream, codec)),
        })
    }
    pub fn is_encrypted(&self) -> bool {
        match &self.framed {
            Transport::V1(_) => false,
            #[cfg(feature = "v2")]
            Transport::V2(_) => true,
        }
    }

    /// Wrap an existing TcpStream (e.g., from an accepted inbound connection).
    pub fn from_stream(stream: TcpStream, network: Network) -> Self {
        let codec = BitcoinCodec::new(network.magic());
        let framed = Framed::new(stream, codec);
        Connection {
            framed: Transport::V1(framed),
        }
    }

    /// Send a single message to the peer.
    pub async fn send_message(&mut self, msg: NetworkMessage) -> Result<(), ConnectionError> {
        match &mut self.framed {
            Transport::V1(framed) => framed.send(msg).await?,
            #[cfg(feature = "v2")]
            Transport::V2(framed) => framed.send(msg).await?,
        }
        Ok(())
    }

    /// Receive a single message from the peer.
    /// Returns `ConnectionError::ConnectionClosed` if the stream ends.
    pub async fn recv_message(&mut self) -> Result<NetworkMessage, ConnectionError> {
        let next = match &mut self.framed {
            Transport::V1(framed) => framed.next().await,
            #[cfg(feature = "v2")]
            Transport::V2(framed) => framed.next().await,
        };
        match next {
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
        self.perform_handshake_with_relay(network, start_height, true)
            .await
    }

    pub async fn perform_handshake_with_relay(
        &mut self,
        network: Network,
        start_height: i32,
        relay_transactions: bool,
    ) -> Result<Handshake, ConnectionError> {
        let mut hs = Handshake::new();

        // 1. Send our version
        let version_msg = version_message(network, start_height, relay_transactions);
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

fn version_message(network: Network, height: i32, relay_transactions: bool) -> NetworkMessage {
    let mut message = Handshake::build_version_message(network, height);
    if let NetworkMessage::Version(version) = &mut message {
        version.relay = relay_transactions;
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn inbound_v1_preserves_fragmented_version_prefix() {
        use tokio::io::AsyncWriteExt;
        use tokio_util::codec::Encoder;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = Connection::accept_inbound(stream, Network::Regtest)
                .await
                .unwrap();
            assert!(!connection.is_encrypted());
            assert!(connection.session_id().is_none());
            assert!(matches!(
                connection.recv_message().await.unwrap(),
                NetworkMessage::Version(_)
            ));
            assert!(matches!(
                connection.recv_message().await.unwrap(),
                NetworkMessage::Ping(42)
            ));
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut bytes = bytes::BytesMut::new();
        let mut codec = BitcoinCodec::new(Network::Regtest.magic());
        codec
            .encode(
                Handshake::build_version_message(Network::Regtest, 0),
                &mut bytes,
            )
            .unwrap();
        codec.encode(NetworkMessage::Ping(42), &mut bytes).unwrap();
        stream.write_all(&bytes[..4]).await.unwrap();
        tokio::task::yield_now().await;
        stream.write_all(&bytes[4..16]).await.unwrap();
        tokio::task::yield_now().await;
        stream.write_all(&bytes[16..]).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn inbound_v2_replies_at_first_mismatching_prefix_byte() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(Connection::accept_inbound(stream, Network::Regtest)
                .await
                .is_err());
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&[0]).await.unwrap();
        let mut reply = [0; 64];
        // Waiting for all 16 prefix bytes would deadlock this exchange.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        drop(stream);
        server.await.unwrap();
    }

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
                other => panic!("expected Ping, got {other:?}"),
            }
            conn.send_message(NetworkMessage::Pong(42)).await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = Connection::from_stream(stream, Network::Mainnet);
        conn.send_message(NetworkMessage::Ping(42)).await.unwrap();
        let response = conn.recv_message().await.unwrap();
        match response {
            NetworkMessage::Pong(n) => assert_eq!(n, 42),
            other => panic!("expected Pong, got {other:?}"),
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
                other => panic!("expected Ping, got {other:?}"),
            }
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = Connection::from_stream(stream, Network::Mainnet);
        conn.send_message(NetworkMessage::Verack).await.unwrap();
        conn.send_message(NetworkMessage::SendHeaders)
            .await
            .unwrap();
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
            conn.send_message(NetworkMessage::Version(ver))
                .await
                .unwrap();

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
        let hs = conn
            .perform_handshake(Network::Mainnet, 800_000)
            .await
            .unwrap();
        assert!(hs.is_ready());
        assert!(hs.peer_version().is_some());
        assert_eq!(hs.peer_version().unwrap().user_agent, "/test-peer/");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_outbound_refused() {
        // Try to connect to a port that's not listening
        let result =
            Connection::connect_outbound("127.0.0.1:1".parse().unwrap(), Network::Mainnet).await;
        assert!(result.is_err());
    }
}
