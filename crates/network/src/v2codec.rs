//! BIP324 transport handshake and framed application messages.
use crate::{
    codec::{decode_payload, encode_payload},
    message::NetworkMessage,
    v2transport::{ChaCha20Poly1305Cipher, V2Command, V2Message, V2Transport, MAX_GARBAGE_LEN},
};
use btc_primitives::network::Network;
use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};
const MAX_PACKET_SIZE: usize = 4_000_000;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Exchange keys, authenticate garbage and receive the transport version.
/// The caller must set a timeout and reconnect for a v1 fallback.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    network: Network,
    initiating: bool,
) -> io::Result<V2Codec> {
    let mut transport = V2Transport::new_encrypted(initiating);
    transport.set_network(network);
    // A responder waits for the first mismatching v1-prefix byte before replying.
    let mut peer = [0; 64];
    if !initiating {
        let mut prefix = network.magic().to_vec();
        prefix.extend_from_slice(b"version\0\0\0\0\0");
        let mut read = 0;
        while read < prefix.len() {
            stream.read_exact(&mut peer[read..read + 1]).await?;
            read += 1;
            if peer[read - 1] != prefix[read - 1] {
                break;
            }
        }
        if read == prefix.len() {
            return Err(invalid("peer requested v1 transport"));
        }
        stream.write_all(transport.our_pubkey()).await?;
        stream.write_all(transport.garbage()).await?;
        stream.flush().await?;
        stream.read_exact(&mut peer[read..]).await?;
    } else {
        stream.write_all(transport.our_pubkey()).await?;
        stream.write_all(transport.garbage()).await?;
        stream.flush().await?;
        stream.read_exact(&mut peer).await?;
    }
    transport.sent_key();
    transport.receive_key(&peer);
    transport.complete_key_exchange();
    stream
        .write_all(
            transport
                .garbage_terminator_send()
                .ok_or_else(|| invalid("key exchange failed"))?,
        )
        .await?;
    let sent_garbage = transport.garbage().to_vec();
    let packet = transport
        .encrypt_packet(&[], &sent_garbage, false)
        .ok_or_else(|| invalid("version encryption failed"))?;
    stream.write_all(&packet).await?;
    stream.flush().await?;
    transport.sent_garbage();
    let mut garbage = Vec::new();
    let mut tail = [0; 16];
    stream.read_exact(&mut tail).await?;
    // Derivation is symmetric: the receiving terminator comes from the transport.
    let terminator = transport
        .garbage_terminator_recv()
        .ok_or_else(|| invalid("missing terminator"))?;
    loop {
        if tail == *terminator {
            break;
        }
        if garbage.len() == MAX_GARBAGE_LEN {
            return Err(invalid("garbage exceeds BIP324 limit"));
        }
        garbage.push(tail[0]);
        tail.copy_within(1.., 0);
        stream.read_exact(&mut tail[15..]).await?;
    }
    let mut aad = garbage;
    loop {
        let mut prefix = [0; 3];
        stream.read_exact(&mut prefix).await?;
        let size = transport
            .packet_length(&prefix)
            .ok_or_else(|| invalid("length decryption failed"))?;
        if size > MAX_PACKET_SIZE {
            return Err(invalid("version packet too large"));
        }
        let mut packet = prefix.to_vec();
        packet.resize(3 + 1 + size + 16, 0);
        stream.read_exact(&mut packet[3..]).await?;
        let (ignore, _version) = transport
            .decrypt_packet(&packet, &aad)
            .ok_or_else(|| invalid("handshake authentication failed"))?;
        aad.clear();
        if !ignore {
            break;
        }
    }
    transport.received_garbage();
    Ok(V2Codec { transport })
}
pub struct V2Codec {
    transport: V2Transport<ChaCha20Poly1305Cipher>,
}
impl V2Codec {
    pub fn session_id(&self) -> Option<&[u8; 32]> {
        self.transport.session_id()
    }
}
impl Decoder for V2Codec {
    type Item = NetworkMessage;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<NetworkMessage>> {
        loop {
            if src.len() < 3 {
                return Ok(None);
            }
            let prefix = src[..3].try_into().unwrap();
            let len = self
                .transport
                .packet_length(&prefix)
                .ok_or_else(|| invalid("invalid cipher state"))?;
            if len > MAX_PACKET_SIZE {
                return Err(invalid("v2 packet too large"));
            }
            let total = 3 + 1 + len + 16;
            if src.len() < total {
                return Ok(None);
            }
            let packet = src.split_to(total);
            let (ignore, data) = self
                .transport
                .decrypt_packet(&packet, &[])
                .ok_or_else(|| invalid("v2 packet authentication failed"))?;
            if ignore {
                continue;
            }
            let message =
                V2Message::decode(&data).ok_or_else(|| invalid("invalid v2 message command"))?;
            return decode_payload(message.command.command_str(), &message.payload)
                .map(Some)
                .map_err(|e| invalid(&e.to_string()));
        }
    }
}
impl Encoder<NetworkMessage> for V2Codec {
    type Error = io::Error;
    fn encode(&mut self, message: NetworkMessage, dst: &mut BytesMut) -> io::Result<()> {
        let command = V2Command::from_str(message.command());
        let payload = encode_payload(&message).map_err(|e| invalid(&e.to_string()))?;
        let msg = match V2Message::from_short(command.clone(), payload.clone()) {
            Some(m) => m,
            None => V2Message::from_extended(command.command_str(), payload),
        };
        let packet = self
            .transport
            .encrypt_message(&msg)
            .ok_or_else(|| invalid("v2 encryption failed"))?;
        dst.extend_from_slice(&packet);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::{Decoder, Encoder};
    #[tokio::test]
    async fn handshake_and_fragmented_messages() {
        let (mut a, mut b) = tokio::io::duplex(65536);
        let (a, b) = tokio::join!(
            handshake(&mut a, Network::Regtest, true),
            handshake(&mut b, Network::Regtest, false)
        );
        let mut a = a.unwrap();
        let mut b = b.unwrap();
        assert_eq!(a.session_id(), b.session_id());
        let mut wire = BytesMut::new();
        a.encode(NetworkMessage::Ping(42), &mut wire).unwrap();
        let mut partial = wire.split_to(4);
        assert!(b.decode(&mut partial).unwrap().is_none());
        partial.extend(wire);
        assert!(matches!(
            b.decode(&mut partial).unwrap(),
            Some(NetworkMessage::Ping(42))
        ));
        assert!(partial.is_empty());
        a.encode(NetworkMessage::Verack, &mut partial).unwrap();
        assert!(matches!(
            b.decode(&mut partial).unwrap(),
            Some(NetworkMessage::Verack)
        ));
    }
    #[tokio::test]
    async fn cross_network_handshake_fails() {
        let (mut a, mut b) = tokio::io::duplex(65536);
        let (a, b) = tokio::join!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                handshake(&mut a, Network::Mainnet, true)
            ),
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                handshake(&mut b, Network::Regtest, false)
            )
        );
        assert!(!matches!(a, Ok(Ok(_))));
        assert!(!matches!(b, Ok(Ok(_))));
    }
}
