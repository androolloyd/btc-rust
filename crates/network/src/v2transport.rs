//! BIP324 v2 P2P encrypted transport protocol.
//!
//! Implements the structure and handshake logic for Bitcoin's v2 encrypted
//! transport as defined in BIP324. This module provides:
//!
//! - ElligatorSwift-based key exchange (ECDH placeholder)
//! - ChaCha20-Poly1305 AEAD encryption via a pluggable trait
//! - Garbage injection for DPI resistance
//! - Short command ID mapping for bandwidth efficiency
//!
//! The actual cryptographic primitives (ECDH, ChaCha20-Poly1305) are
//! abstracted behind traits so they can be supplied without pulling in
//! additional dependencies.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum garbage length in bytes (BIP324 specifies 4095).
pub const MAX_GARBAGE_LEN: usize = 4095;

/// Length of an ElligatorSwift-encoded public key (64 bytes).
pub const ELLIGATOR_SWIFT_KEY_LEN: usize = 64;

/// Length of the garbage terminator (16 bytes, derived from session keys).
pub const GARBAGE_TERMINATOR_LEN: usize = 16;

/// BIP324 network magic used during the handshake.
pub const V2_HANDSHAKE_MAGIC: &[u8] = b"bitcoin_v2_handshake";

// ---------------------------------------------------------------------------
// Encryption trait
// ---------------------------------------------------------------------------

/// Trait abstracting the AEAD cipher used for v2 transport encryption.
///
/// Implementations should provide ChaCha20-Poly1305 as specified by BIP324,
/// but the trait boundary allows testing with a no-op cipher.
pub trait V2Cipher: std::fmt::Debug {
    /// Encrypt `plaintext` in place, appending a 16-byte authentication tag.
    ///
    /// `nonce` is a 96-bit value constructed from the 64-bit message counter
    /// and the direction flag.
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &mut Vec<u8>);

    /// Decrypt and authenticate `ciphertext` (which includes the trailing tag).
    ///
    /// Returns `true` on success and strips the tag, `false` if authentication
    /// fails (in which case the buffer is left in an unspecified state).
    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> bool;
}

/// A no-op cipher that passes data through unchanged. Useful for tests.
#[derive(Debug, Clone)]
pub struct NullCipher;

impl V2Cipher for NullCipher {
    fn encrypt(&self, _key: &[u8; 32], _nonce: &[u8; 12], _aad: &[u8], _plaintext: &mut Vec<u8>) {
        // No-op: plaintext is left as-is.
    }

    fn decrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _ciphertext: &mut Vec<u8>,
    ) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Handshake state
// ---------------------------------------------------------------------------

/// States of the BIP324 v2 handshake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2HandshakeState {
    /// We need to send our ElligatorSwift-encoded public key.
    SendKey,
    /// Waiting for the peer's ElligatorSwift-encoded public key.
    RecvKey,
    /// Key exchange complete, deriving session keys.
    KeyExchange,
    /// Sending garbage + garbage terminator + version packet.
    SendGarbage,
    /// Receiving peer's garbage + garbage terminator + version packet.
    RecvGarbage,
    /// Transport is ready for encrypted messages.
    Ready,
    /// Handshake failed.
    Failed,
}

// ---------------------------------------------------------------------------
// V2 short command IDs (BIP324 Table)
// ---------------------------------------------------------------------------

/// BIP324 short command identifiers.
///
/// The 28 most common Bitcoin P2P commands are assigned single-byte IDs so
/// that the 12-byte ASCII command string does not need to be transmitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Command {
    Addr,
    Block,
    BlockTxn,
    GetData,
    GetBlocks,
    GetHeaders,
    CmpctBlock,
    Headers,
    Inv,
    MemPool,
    MerkleBlock,
    NotFound,
    Ping,
    Pong,
    Reject,
    SendCmpct,
    SendHeaders,
    Tx,
    GetBlockTxn,
    FeeFilter,
    FilterAdd,
    FilterClear,
    FilterLoad,
    GetAddr,
    Verack,
    Version,
    AddrV2,
    SendAddrV2,
    /// An extended (12-byte ASCII) command for messages not covered by the
    /// short-ID table.
    Extended(String),
}

impl V2Command {
    /// Return the BIP324 short command ID, if one exists.
    pub fn short_id(&self) -> Option<u8> {
        match self {
            V2Command::Addr => Some(0),
            V2Command::Block => Some(1),
            V2Command::BlockTxn => Some(2),
            V2Command::GetData => Some(3),
            V2Command::GetBlocks => Some(4),
            V2Command::GetHeaders => Some(5),
            V2Command::CmpctBlock => Some(6),
            V2Command::Headers => Some(7),
            V2Command::Inv => Some(8),
            V2Command::MemPool => Some(9),
            V2Command::MerkleBlock => Some(10),
            V2Command::NotFound => Some(11),
            V2Command::Ping => Some(13),
            V2Command::Pong => Some(14),
            V2Command::Reject => Some(15),
            V2Command::SendCmpct => Some(16),
            V2Command::SendHeaders => Some(17),
            V2Command::Tx => Some(19),
            V2Command::GetBlockTxn => Some(20),
            V2Command::FeeFilter => Some(21),
            V2Command::FilterAdd => Some(22),
            V2Command::FilterClear => Some(23),
            V2Command::FilterLoad => Some(24),
            V2Command::GetAddr => Some(25),
            V2Command::Verack => Some(26),
            V2Command::Version => Some(27),
            V2Command::AddrV2 => Some(28),
            V2Command::SendAddrV2 => Some(29),
            V2Command::Extended(_) => None,
        }
    }

    /// Resolve a short command ID to a `V2Command`.
    pub fn from_short_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(V2Command::Addr),
            1 => Some(V2Command::Block),
            2 => Some(V2Command::BlockTxn),
            3 => Some(V2Command::GetData),
            4 => Some(V2Command::GetBlocks),
            5 => Some(V2Command::GetHeaders),
            6 => Some(V2Command::CmpctBlock),
            7 => Some(V2Command::Headers),
            8 => Some(V2Command::Inv),
            9 => Some(V2Command::MemPool),
            10 => Some(V2Command::MerkleBlock),
            11 => Some(V2Command::NotFound),
            13 => Some(V2Command::Ping),
            14 => Some(V2Command::Pong),
            15 => Some(V2Command::Reject),
            16 => Some(V2Command::SendCmpct),
            17 => Some(V2Command::SendHeaders),
            19 => Some(V2Command::Tx),
            20 => Some(V2Command::GetBlockTxn),
            21 => Some(V2Command::FeeFilter),
            22 => Some(V2Command::FilterAdd),
            23 => Some(V2Command::FilterClear),
            24 => Some(V2Command::FilterLoad),
            25 => Some(V2Command::GetAddr),
            26 => Some(V2Command::Verack),
            27 => Some(V2Command::Version),
            28 => Some(V2Command::AddrV2),
            29 => Some(V2Command::SendAddrV2),
            _ => None,
        }
    }

    /// Return the 12-byte ASCII command string.
    pub fn command_str(&self) -> &str {
        match self {
            V2Command::Addr => "addr",
            V2Command::Block => "block",
            V2Command::BlockTxn => "blocktxn",
            V2Command::GetData => "getdata",
            V2Command::GetBlocks => "getblocks",
            V2Command::GetHeaders => "getheaders",
            V2Command::CmpctBlock => "cmpctblock",
            V2Command::Headers => "headers",
            V2Command::Inv => "inv",
            V2Command::MemPool => "mempool",
            V2Command::MerkleBlock => "merkleblock",
            V2Command::NotFound => "notfound",
            V2Command::Ping => "ping",
            V2Command::Pong => "pong",
            V2Command::Reject => "reject",
            V2Command::SendCmpct => "sendcmpct",
            V2Command::SendHeaders => "sendheaders",
            V2Command::Tx => "tx",
            V2Command::GetBlockTxn => "getblocktxn",
            V2Command::FeeFilter => "feefilter",
            V2Command::FilterAdd => "filteradd",
            V2Command::FilterClear => "filterclear",
            V2Command::FilterLoad => "filterload",
            V2Command::GetAddr => "getaddr",
            V2Command::Verack => "verack",
            V2Command::Version => "version",
            V2Command::AddrV2 => "addrv2",
            V2Command::SendAddrV2 => "sendaddrv2",
            V2Command::Extended(s) => s.as_str(),
        }
    }

    /// Look up a command by its ASCII string name.
    pub fn from_str(s: &str) -> Self {
        match s {
            "addr" => V2Command::Addr,
            "block" => V2Command::Block,
            "blocktxn" => V2Command::BlockTxn,
            "getdata" => V2Command::GetData,
            "getblocks" => V2Command::GetBlocks,
            "getheaders" => V2Command::GetHeaders,
            "cmpctblock" => V2Command::CmpctBlock,
            "headers" => V2Command::Headers,
            "inv" => V2Command::Inv,
            "mempool" => V2Command::MemPool,
            "merkleblock" => V2Command::MerkleBlock,
            "notfound" => V2Command::NotFound,
            "ping" => V2Command::Ping,
            "pong" => V2Command::Pong,
            "reject" => V2Command::Reject,
            "sendcmpct" => V2Command::SendCmpct,
            "sendheaders" => V2Command::SendHeaders,
            "tx" => V2Command::Tx,
            "getblocktxn" => V2Command::GetBlockTxn,
            "feefilter" => V2Command::FeeFilter,
            "filteradd" => V2Command::FilterAdd,
            "filterclear" => V2Command::FilterClear,
            "filterload" => V2Command::FilterLoad,
            "getaddr" => V2Command::GetAddr,
            "verack" => V2Command::Verack,
            "version" => V2Command::Version,
            "addrv2" => V2Command::AddrV2,
            "sendaddrv2" => V2Command::SendAddrV2,
            other => V2Command::Extended(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// V2 message
// ---------------------------------------------------------------------------

/// A decoded BIP324 v2 message.
///
/// The on-wire format is:
///   `[3-byte encrypted length][encrypted header + payload + 16-byte tag]`
///
/// After decryption the header is a single byte:
///   - bit 7 (`0x80`): "ignore" flag — unknown messages with this bit set
///     should be silently skipped (forward compatibility).
///   - bits 0..6: if non-zero this is a short command ID; if zero, a 12-byte
///     ASCII command follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Message {
    /// Raw header byte (flags + optional short command ID).
    pub header: u8,
    /// Resolved command.
    pub command: V2Command,
    /// Message payload.
    pub payload: Vec<u8>,
}

impl V2Message {
    /// `true` if the "ignore" flag (bit 7) is set.
    pub fn is_decoy(&self) -> bool {
        self.header & 0x80 != 0
    }

    /// Create a message from a known short-ID command.
    pub fn from_short(command: V2Command, payload: Vec<u8>) -> Option<Self> {
        let id = command.short_id()?;
        Some(V2Message {
            header: id,
            command,
            payload,
        })
    }

    /// Create a message with a 12-byte extended command.
    pub fn from_extended(command_str: &str, payload: Vec<u8>) -> Self {
        V2Message {
            header: 0,
            command: V2Command::Extended(command_str.to_string()),
            payload,
        }
    }

    /// Encode into the plaintext that goes into the AEAD.
    ///
    /// Format:
    ///   - 1 byte header
    ///   - if header == 0: 12 bytes ASCII command (null-padded)
    ///   - N bytes payload
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.header);
        if self.header == 0 {
            // Extended command: 12-byte null-padded ASCII
            let cmd_bytes = self.command.command_str().as_bytes();
            let mut cmd_buf = [0u8; 12];
            let len = cmd_bytes.len().min(12);
            cmd_buf[..len].copy_from_slice(&cmd_bytes[..len]);
            out.extend_from_slice(&cmd_buf);
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from the plaintext produced by AEAD decryption.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let header = data[0];
        let short_id = header & 0x7f; // mask off ignore flag

        if short_id != 0 {
            // Short command
            let command = V2Command::from_short_id(short_id)?;
            let payload = data[1..].to_vec();
            Some(V2Message {
                header,
                command,
                payload,
            })
        } else {
            // Extended command (header byte is 0x00 or 0x80)
            if data.len() < 13 {
                return None; // need 1 header + 12 command
            }
            let cmd_slice = &data[1..13];
            let end = cmd_slice.iter().position(|&b| b == 0).unwrap_or(12);
            let cmd_str = std::str::from_utf8(&cmd_slice[..end]).ok()?;
            let command = V2Command::from_str(cmd_str);
            let payload = data[13..].to_vec();
            Some(V2Message {
                header,
                command,
                payload,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Session keys
// ---------------------------------------------------------------------------

/// Derived session keys from the ECDH key exchange.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub session_id: [u8; 32],
    pub garbage_terminator_send: [u8; GARBAGE_TERMINATOR_LEN],
    pub garbage_terminator_recv: [u8; GARBAGE_TERMINATOR_LEN],
}

/// Derive session keys from a shared ECDH secret.
///
/// In a real implementation this would use HKDF-SHA256 with the
/// concatenation of the two ElligatorSwift-encoded public keys as salt.
/// Here we use a simplified (but deterministic) derivation based on
/// SHA-256 for structural correctness.
///
/// `initiator` indicates whether we initiated the connection.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    our_pubkey: &[u8; ELLIGATOR_SWIFT_KEY_LEN],
    peer_pubkey: &[u8; ELLIGATOR_SWIFT_KEY_LEN],
    initiator: bool,
) -> SessionKeys {
    // Build salt = SHA256("bitcoin_v2_shared_secret" || initiator_pubkey || responder_pubkey)
    let (init_pk, resp_pk) = if initiator {
        (our_pubkey.as_slice(), peer_pubkey.as_slice())
    } else {
        (peer_pubkey.as_slice(), our_pubkey.as_slice())
    };

    let salt = {
        let mut h = Sha256::new();
        h.update(b"bitcoin_v2_shared_secret");
        h.update(init_pk);
        h.update(resp_pk);
        h.finalize()
    };

    // send_key = SHA256(salt || shared_secret || "send")
    let send_label = if initiator { b"initiator" } else { b"responder" };
    let recv_label = if initiator { b"responder" } else { b"initiator" };

    let send_key = hkdf_extract(&salt, shared_secret, send_label);
    let recv_key = hkdf_extract(&salt, shared_secret, recv_label);

    // session_id = SHA256(salt || shared_secret || "session_id")
    let session_id = hkdf_extract(&salt, shared_secret, b"session_id");

    // garbage terminators
    let gt_send = hkdf_extract(&salt, shared_secret, b"garbage_terminators_send");
    let gt_recv = hkdf_extract(&salt, shared_secret, b"garbage_terminators_recv");

    let mut garbage_terminator_send = [0u8; GARBAGE_TERMINATOR_LEN];
    garbage_terminator_send.copy_from_slice(&gt_send[..GARBAGE_TERMINATOR_LEN]);
    let mut garbage_terminator_recv = [0u8; GARBAGE_TERMINATOR_LEN];
    garbage_terminator_recv.copy_from_slice(&gt_recv[..GARBAGE_TERMINATOR_LEN]);

    SessionKeys {
        send_key,
        recv_key,
        session_id,
        garbage_terminator_send,
        garbage_terminator_recv,
    }
}

/// Simplified HKDF-extract: SHA256(salt || secret || label).
fn hkdf_extract(salt: &[u8], secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(secret);
    h.update(label);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// V2 Transport
// ---------------------------------------------------------------------------

/// Configuration for the v2 transport layer.
#[derive(Debug, Clone)]
pub struct V2TransportConfig {
    /// Whether v2 transport is enabled at all.
    pub enabled: bool,
    /// Prefer v2 over v1 when both are available.
    pub preferred: bool,
}

impl Default for V2TransportConfig {
    fn default() -> Self {
        V2TransportConfig {
            enabled: true,
            preferred: true,
        }
    }
}

/// BIP324 v2 encrypted transport state machine.
///
/// Manages the lifecycle of an encrypted connection: key exchange, garbage
/// injection, and encrypted message framing. The actual AEAD cipher is
/// supplied via the [`V2Cipher`] trait.
#[derive(Debug)]
pub struct V2Transport<C: V2Cipher = NullCipher> {
    state: V2HandshakeState,
    send_key: Option<[u8; 32]>,
    recv_key: Option<[u8; 32]>,
    send_nonce: u64,
    recv_nonce: u64,
    session_id: Option<[u8; 32]>,
    /// Our ElligatorSwift-encoded ephemeral public key.
    our_pubkey: [u8; ELLIGATOR_SWIFT_KEY_LEN],
    /// Peer's ElligatorSwift-encoded ephemeral public key (set during RecvKey).
    peer_pubkey: Option<[u8; ELLIGATOR_SWIFT_KEY_LEN]>,
    /// Our ephemeral private key (32 bytes, used for ECDH — placeholder).
    our_privkey: [u8; 32],
    /// Whether we are the initiator (outbound) side.
    initiator: bool,
    /// Random garbage bytes sent during the handshake.
    garbage: Vec<u8>,
    /// Garbage terminator for our direction.
    garbage_terminator_send: Option<[u8; GARBAGE_TERMINATOR_LEN]>,
    /// Garbage terminator for the peer's direction.
    garbage_terminator_recv: Option<[u8; GARBAGE_TERMINATOR_LEN]>,
    /// The AEAD cipher implementation.
    cipher: C,
}

impl V2Transport<NullCipher> {
    /// Create a new v2 transport with the `NullCipher` (for testing).
    pub fn new_null(initiator: bool) -> Self {
        Self::new(initiator, NullCipher)
    }
}

impl<C: V2Cipher> V2Transport<C> {
    /// Create a new v2 transport.
    pub fn new(initiator: bool, cipher: C) -> Self {
        // Generate ephemeral keypair (placeholder — in a real implementation
        // this would be a secp256k1 keypair encoded via ElligatorSwift).
        let our_privkey: [u8; 32] = rand::random();
        let our_pubkey = Self::derive_public_key(&our_privkey);
        let garbage = Self::generate_garbage();

        V2Transport {
            state: V2HandshakeState::SendKey,
            send_key: None,
            recv_key: None,
            send_nonce: 0,
            recv_nonce: 0,
            session_id: None,
            our_pubkey,
            peer_pubkey: None,
            our_privkey,
            initiator,
            garbage,
            garbage_terminator_send: None,
            garbage_terminator_recv: None,
            cipher,
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> V2HandshakeState {
        self.state
    }

    /// Whether the transport is ready for encrypted messaging.
    pub fn is_ready(&self) -> bool {
        self.state == V2HandshakeState::Ready
    }

    /// The 32-byte session ID, available after key exchange.
    pub fn session_id(&self) -> Option<&[u8; 32]> {
        self.session_id.as_ref()
    }

    /// The ElligatorSwift-encoded public key to send to the peer.
    pub fn our_pubkey(&self) -> &[u8; ELLIGATOR_SWIFT_KEY_LEN] {
        &self.our_pubkey
    }

    /// The garbage bytes we intend to send.
    pub fn garbage(&self) -> &[u8] {
        &self.garbage
    }

    /// The garbage terminator we append after our garbage.
    pub fn garbage_terminator_send(&self) -> Option<&[u8; GARBAGE_TERMINATOR_LEN]> {
        self.garbage_terminator_send.as_ref()
    }

    // -- State transitions ---------------------------------------------------

    /// Advance to `RecvKey` after we have sent our public key.
    pub fn sent_key(&mut self) {
        if self.state == V2HandshakeState::SendKey {
            self.state = V2HandshakeState::RecvKey;
        }
    }

    /// Supply the peer's ElligatorSwift-encoded public key, advancing to
    /// `KeyExchange`.
    pub fn receive_key(&mut self, peer_pubkey: &[u8; ELLIGATOR_SWIFT_KEY_LEN]) {
        if self.state != V2HandshakeState::RecvKey {
            self.state = V2HandshakeState::Failed;
            return;
        }
        self.peer_pubkey = Some(*peer_pubkey);
        self.state = V2HandshakeState::KeyExchange;
    }

    /// Perform key exchange: compute the shared secret and derive session
    /// keys.  Advances to `SendGarbage`.
    pub fn complete_key_exchange(&mut self) {
        if self.state != V2HandshakeState::KeyExchange {
            self.state = V2HandshakeState::Failed;
            return;
        }

        let peer_pk = match self.peer_pubkey {
            Some(pk) => pk,
            None => {
                self.state = V2HandshakeState::Failed;
                return;
            }
        };

        // Compute shared secret (placeholder — real impl uses secp256k1 ECDH
        // on the ElligatorSwift-decoded public keys).
        let shared_secret = Self::compute_ecdh(&self.our_privkey, &peer_pk);

        let keys = derive_session_keys(
            &shared_secret,
            &self.our_pubkey,
            &peer_pk,
            self.initiator,
        );

        self.send_key = Some(keys.send_key);
        self.recv_key = Some(keys.recv_key);
        self.session_id = Some(keys.session_id);
        self.garbage_terminator_send = Some(keys.garbage_terminator_send);
        self.garbage_terminator_recv = Some(keys.garbage_terminator_recv);
        self.state = V2HandshakeState::SendGarbage;
    }

    /// Record that we have sent our garbage + terminator.
    pub fn sent_garbage(&mut self) {
        if self.state == V2HandshakeState::SendGarbage {
            self.state = V2HandshakeState::RecvGarbage;
        }
    }

    /// Record that we have received and validated the peer's garbage.
    pub fn received_garbage(&mut self) {
        if self.state == V2HandshakeState::RecvGarbage {
            self.state = V2HandshakeState::Ready;
        }
    }

    /// Force the handshake into the `Failed` state.
    pub fn fail(&mut self) {
        self.state = V2HandshakeState::Failed;
    }

    // -- Encrypted messaging --------------------------------------------------

    /// Build the nonce for the AEAD from the current counter value.
    fn build_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        // BIP324: first 4 bytes zero, next 8 bytes are the little-endian counter.
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt a `V2Message` for sending.
    ///
    /// Returns the encrypted packet (length prefix + ciphertext + tag),
    /// or `None` if the transport is not in the `Ready` state.
    pub fn encrypt_message(&mut self, msg: &V2Message) -> Option<Vec<u8>> {
        if self.state != V2HandshakeState::Ready {
            return None;
        }
        let send_key = self.send_key?;

        let mut plaintext = msg.encode();
        let nonce = Self::build_nonce(self.send_nonce);
        let contents_len = plaintext.len();

        // Encrypt in place (the cipher will append the 16-byte tag).
        self.cipher.encrypt(&send_key, &nonce, &[], &mut plaintext);

        self.send_nonce = self.send_nonce.wrapping_add(1);

        // Prepend 3-byte little-endian length of the encrypted contents
        // (before encryption the content length, so the peer knows how many
        // bytes to read).
        let mut packet = Vec::with_capacity(3 + plaintext.len());
        let len_bytes = (contents_len as u32).to_le_bytes();
        packet.extend_from_slice(&len_bytes[..3]);
        packet.extend_from_slice(&plaintext);
        Some(packet)
    }

    /// Decrypt a received packet into a `V2Message`.
    ///
    /// `encrypted` should be the ciphertext (without the 3-byte length prefix).
    pub fn decrypt_message(&mut self, encrypted: &[u8]) -> Option<V2Message> {
        if self.state != V2HandshakeState::Ready {
            return None;
        }
        let recv_key = self.recv_key?;
        let nonce = Self::build_nonce(self.recv_nonce);

        let mut buf = encrypted.to_vec();
        if !self.cipher.decrypt(&recv_key, &nonce, &[], &mut buf) {
            return None;
        }

        self.recv_nonce = self.recv_nonce.wrapping_add(1);
        V2Message::decode(&buf)
    }

    // -- Helpers (placeholders for real crypto) --------------------------------

    /// Placeholder: derive a 64-byte "ElligatorSwift-encoded public key"
    /// from a 32-byte private key by double-hashing.
    fn derive_public_key(privkey: &[u8; 32]) -> [u8; ELLIGATOR_SWIFT_KEY_LEN] {
        let h1 = Sha256::digest(privkey);
        let h2 = Sha256::digest(&h1);
        let mut pubkey = [0u8; ELLIGATOR_SWIFT_KEY_LEN];
        pubkey[..32].copy_from_slice(&h1);
        pubkey[32..].copy_from_slice(&h2);
        pubkey
    }

    /// Placeholder: compute a shared secret from our private key and the
    /// peer's ElligatorSwift-encoded public key.  Real code would decode
    /// the ElligatorSwift encoding and perform secp256k1 ECDH.
    fn compute_ecdh(our_privkey: &[u8; 32], peer_pubkey: &[u8; ELLIGATOR_SWIFT_KEY_LEN]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(our_privkey);
        h.update(peer_pubkey);
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Generate random garbage of a random length in `[0, MAX_GARBAGE_LEN]`.
    fn generate_garbage() -> Vec<u8> {
        let len: usize = rand::random::<usize>() % (MAX_GARBAGE_LEN + 1);
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = rand::random();
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Handshake state transitions -----------------------------------------

    #[test]
    fn test_handshake_full_lifecycle() {
        let mut transport = V2Transport::new_null(true);
        assert_eq!(transport.state(), V2HandshakeState::SendKey);

        // Send our public key
        transport.sent_key();
        assert_eq!(transport.state(), V2HandshakeState::RecvKey);

        // Receive peer public key
        let peer_pk = [0xABu8; ELLIGATOR_SWIFT_KEY_LEN];
        transport.receive_key(&peer_pk);
        assert_eq!(transport.state(), V2HandshakeState::KeyExchange);

        // Complete key exchange
        transport.complete_key_exchange();
        assert_eq!(transport.state(), V2HandshakeState::SendGarbage);
        assert!(transport.session_id().is_some());
        assert!(transport.send_key.is_some());
        assert!(transport.recv_key.is_some());
        assert!(transport.garbage_terminator_send().is_some());

        // Send garbage
        transport.sent_garbage();
        assert_eq!(transport.state(), V2HandshakeState::RecvGarbage);

        // Receive garbage
        transport.received_garbage();
        assert_eq!(transport.state(), V2HandshakeState::Ready);
        assert!(transport.is_ready());
    }

    #[test]
    fn test_handshake_state_out_of_order_recv_key_fails() {
        let mut transport = V2Transport::new_null(true);
        assert_eq!(transport.state(), V2HandshakeState::SendKey);

        // Try to receive key before sending ours — must not be in RecvKey
        let peer_pk = [0xABu8; ELLIGATOR_SWIFT_KEY_LEN];
        transport.receive_key(&peer_pk);
        assert_eq!(transport.state(), V2HandshakeState::Failed);
    }

    #[test]
    fn test_handshake_key_exchange_without_peer_key() {
        let mut transport = V2Transport::new_null(true);
        transport.sent_key();
        // Skip receive_key and go straight to key exchange
        transport.state = V2HandshakeState::KeyExchange;
        transport.complete_key_exchange();
        // Should fail since peer_pubkey is None
        assert_eq!(transport.state(), V2HandshakeState::Failed);
    }

    #[test]
    fn test_handshake_fail() {
        let mut transport = V2Transport::new_null(false);
        transport.fail();
        assert_eq!(transport.state(), V2HandshakeState::Failed);
        assert!(!transport.is_ready());
    }

    // -- Short command ID mapping -------------------------------------------

    #[test]
    fn test_short_id_roundtrip() {
        let commands = vec![
            (V2Command::Addr, 0u8),
            (V2Command::Block, 1),
            (V2Command::BlockTxn, 2),
            (V2Command::GetData, 3),
            (V2Command::GetBlocks, 4),
            (V2Command::GetHeaders, 5),
            (V2Command::CmpctBlock, 6),
            (V2Command::Headers, 7),
            (V2Command::Inv, 8),
            (V2Command::MemPool, 9),
            (V2Command::MerkleBlock, 10),
            (V2Command::NotFound, 11),
            (V2Command::Ping, 13),
            (V2Command::Pong, 14),
            (V2Command::Reject, 15),
            (V2Command::SendCmpct, 16),
            (V2Command::SendHeaders, 17),
            (V2Command::Tx, 19),
            (V2Command::GetBlockTxn, 20),
            (V2Command::FeeFilter, 21),
            (V2Command::FilterAdd, 22),
            (V2Command::FilterClear, 23),
            (V2Command::FilterLoad, 24),
            (V2Command::GetAddr, 25),
            (V2Command::Verack, 26),
            (V2Command::Version, 27),
            (V2Command::AddrV2, 28),
            (V2Command::SendAddrV2, 29),
        ];

        for (cmd, expected_id) in &commands {
            assert_eq!(
                cmd.short_id(),
                Some(*expected_id),
                "short_id mismatch for {:?}",
                cmd
            );
            let resolved = V2Command::from_short_id(*expected_id).unwrap();
            assert_eq!(
                &resolved, cmd,
                "from_short_id mismatch for id {}",
                expected_id
            );
        }
    }

    #[test]
    fn test_short_id_gaps_return_none() {
        // IDs 12 and 18 are not assigned in the BIP324 table
        assert!(V2Command::from_short_id(12).is_none());
        assert!(V2Command::from_short_id(18).is_none());
        assert!(V2Command::from_short_id(128).is_none());
        assert!(V2Command::from_short_id(255).is_none());
    }

    #[test]
    fn test_extended_command_has_no_short_id() {
        let cmd = V2Command::Extended("mycustomcmd".to_string());
        assert!(cmd.short_id().is_none());
        assert_eq!(cmd.command_str(), "mycustomcmd");
    }

    #[test]
    fn test_command_str_roundtrip() {
        let known = vec![
            "addr", "block", "blocktxn", "getdata", "getblocks",
            "getheaders", "cmpctblock", "headers", "inv", "mempool",
            "merkleblock", "notfound", "ping", "pong", "reject",
            "sendcmpct", "sendheaders", "tx", "getblocktxn", "feefilter",
            "filteradd", "filterclear", "filterload", "getaddr",
            "verack", "version", "addrv2", "sendaddrv2",
        ];
        for name in known {
            let cmd = V2Command::from_str(name);
            assert!(
                cmd.short_id().is_some(),
                "{} should have a short ID",
                name
            );
            assert_eq!(cmd.command_str(), name);
        }

        // Unknown command -> Extended
        let ext = V2Command::from_str("customxyz");
        assert!(ext.short_id().is_none());
        assert_eq!(ext.command_str(), "customxyz");
    }

    // -- V2Message encoding / decoding --------------------------------------

    #[test]
    fn test_message_short_command_roundtrip() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let msg =
            V2Message::from_short(V2Command::Ping, payload.clone()).unwrap();
        assert_eq!(msg.header, 13); // Ping short ID
        assert!(!msg.is_decoy());

        let encoded = msg.encode();
        // 1 byte header + 4 bytes payload
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 13);
        assert_eq!(&encoded[1..], &payload);

        let decoded = V2Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_message_extended_command_roundtrip() {
        let payload = vec![1, 2, 3];
        let msg = V2Message::from_extended("customcmd", payload.clone());
        assert_eq!(msg.header, 0);
        assert!(!msg.is_decoy());

        let encoded = msg.encode();
        // 1 byte header + 12 byte command + 3 byte payload
        assert_eq!(encoded.len(), 16);
        assert_eq!(encoded[0], 0);
        // Command should be null-padded
        assert_eq!(&encoded[1..10], b"customcmd");
        assert_eq!(encoded[10], 0);
        assert_eq!(encoded[11], 0);
        assert_eq!(encoded[12], 0);
        assert_eq!(&encoded[13..], &payload);

        let decoded = V2Message::decode(&encoded).unwrap();
        assert_eq!(decoded.command, V2Command::Extended("customcmd".to_string()));
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_message_decoy_flag() {
        let mut msg =
            V2Message::from_short(V2Command::Ping, vec![]).unwrap();
        assert!(!msg.is_decoy());

        msg.header |= 0x80; // set decoy flag
        assert!(msg.is_decoy());
    }

    #[test]
    fn test_message_decode_empty_returns_none() {
        assert!(V2Message::decode(&[]).is_none());
    }

    #[test]
    fn test_message_decode_extended_too_short() {
        // Header = 0 means extended, but fewer than 13 bytes total
        assert!(V2Message::decode(&[0, 1, 2]).is_none());
    }

    // -- Garbage bounds -----------------------------------------------------

    #[test]
    fn test_garbage_length_bounds() {
        // Run multiple times to exercise the random path
        for _ in 0..50 {
            let transport = V2Transport::new_null(true);
            assert!(
                transport.garbage().len() <= MAX_GARBAGE_LEN,
                "garbage length {} exceeds maximum {}",
                transport.garbage().len(),
                MAX_GARBAGE_LEN
            );
        }
    }

    // -- Session key derivation determinism ---------------------------------

    #[test]
    fn test_session_key_derivation_deterministic() {
        let secret = [42u8; 32];
        let our_pk = [1u8; ELLIGATOR_SWIFT_KEY_LEN];
        let peer_pk = [2u8; ELLIGATOR_SWIFT_KEY_LEN];

        let keys1 = derive_session_keys(&secret, &our_pk, &peer_pk, true);
        let keys2 = derive_session_keys(&secret, &our_pk, &peer_pk, true);

        assert_eq!(keys1.send_key, keys2.send_key);
        assert_eq!(keys1.recv_key, keys2.recv_key);
        assert_eq!(keys1.session_id, keys2.session_id);
        assert_eq!(
            keys1.garbage_terminator_send,
            keys2.garbage_terminator_send
        );
        assert_eq!(
            keys1.garbage_terminator_recv,
            keys2.garbage_terminator_recv
        );
    }

    #[test]
    fn test_session_key_initiator_responder_differ() {
        let secret = [42u8; 32];
        let our_pk = [1u8; ELLIGATOR_SWIFT_KEY_LEN];
        let peer_pk = [2u8; ELLIGATOR_SWIFT_KEY_LEN];

        let init_keys = derive_session_keys(&secret, &our_pk, &peer_pk, true);
        let resp_keys = derive_session_keys(&secret, &our_pk, &peer_pk, false);

        // Initiator send should differ from responder send (role affects the
        // derivation labels).
        assert_ne!(init_keys.send_key, resp_keys.send_key);
        assert_ne!(init_keys.recv_key, resp_keys.recv_key);
        // session_id uses the same label regardless of role — but the pubkey
        // ordering changes so it will still differ.
        assert_ne!(init_keys.session_id, resp_keys.session_id);
    }

    #[test]
    fn test_session_key_different_secrets_differ() {
        let our_pk = [1u8; ELLIGATOR_SWIFT_KEY_LEN];
        let peer_pk = [2u8; ELLIGATOR_SWIFT_KEY_LEN];

        let keys_a = derive_session_keys(&[0u8; 32], &our_pk, &peer_pk, true);
        let keys_b = derive_session_keys(&[1u8; 32], &our_pk, &peer_pk, true);

        assert_ne!(keys_a.send_key, keys_b.send_key);
        assert_ne!(keys_a.recv_key, keys_b.recv_key);
        assert_ne!(keys_a.session_id, keys_b.session_id);
    }

    // -- Nonce construction --------------------------------------------------

    #[test]
    fn test_nonce_construction() {
        let nonce = V2Transport::<NullCipher>::build_nonce(0);
        assert_eq!(nonce, [0u8; 12]);

        let nonce = V2Transport::<NullCipher>::build_nonce(1);
        let mut expected = [0u8; 12];
        expected[4] = 1;
        assert_eq!(nonce, expected);

        let nonce = V2Transport::<NullCipher>::build_nonce(0x0102030405060708);
        let mut expected = [0u8; 12];
        expected[4..12].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        assert_eq!(nonce, expected);
    }

    // -- Encrypt / decrypt with NullCipher -----------------------------------

    #[test]
    fn test_encrypt_decrypt_null_cipher() {
        let mut transport = V2Transport::new_null(true);

        // Drive through the handshake
        transport.sent_key();
        let peer_pk = [0xABu8; ELLIGATOR_SWIFT_KEY_LEN];
        transport.receive_key(&peer_pk);
        transport.complete_key_exchange();
        transport.sent_garbage();
        transport.received_garbage();
        assert!(transport.is_ready());

        let msg = V2Message::from_short(V2Command::Ping, vec![0x42]).unwrap();
        let packet = transport.encrypt_message(&msg).unwrap();

        // Packet = 3-byte length + plaintext (NullCipher doesn't add a tag)
        assert!(packet.len() >= 3);

        // The length prefix encodes the plaintext length
        let len =
            packet[0] as u32 | (packet[1] as u32) << 8 | (packet[2] as u32) << 16;
        assert_eq!(len as usize, msg.encode().len());

        // Decrypt (strip the 3-byte prefix first, as the caller would)
        let decrypted = transport.decrypt_message(&packet[3..]).unwrap();
        assert_eq!(decrypted.command, V2Command::Ping);
        assert_eq!(decrypted.payload, vec![0x42]);
    }

    #[test]
    fn test_encrypt_before_ready_returns_none() {
        let mut transport = V2Transport::new_null(true);
        let msg = V2Message::from_short(V2Command::Ping, vec![]).unwrap();
        assert!(transport.encrypt_message(&msg).is_none());
    }

    #[test]
    fn test_send_nonce_increments() {
        let mut transport = V2Transport::new_null(true);
        transport.sent_key();
        transport.receive_key(&[0u8; ELLIGATOR_SWIFT_KEY_LEN]);
        transport.complete_key_exchange();
        transport.sent_garbage();
        transport.received_garbage();

        assert_eq!(transport.send_nonce, 0);
        let msg = V2Message::from_short(V2Command::Ping, vec![]).unwrap();
        transport.encrypt_message(&msg);
        assert_eq!(transport.send_nonce, 1);
        transport.encrypt_message(&msg);
        assert_eq!(transport.send_nonce, 2);
    }

    // -- V2TransportConfig ---------------------------------------------------

    #[test]
    fn test_config_defaults() {
        let cfg = V2TransportConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.preferred);
    }

    // --- Config custom values ---

    #[test]
    fn test_config_custom() {
        let cfg = V2TransportConfig {
            enabled: false,
            preferred: false,
        };
        assert!(!cfg.enabled);
        assert!(!cfg.preferred);
    }

    // --- NullCipher ---

    #[test]
    fn test_null_cipher_encrypt_noop() {
        let cipher = NullCipher;
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut data = vec![1, 2, 3, 4];
        cipher.encrypt(&key, &nonce, &[], &mut data);
        // NullCipher should leave data unchanged
        assert_eq!(data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_null_cipher_decrypt_always_succeeds() {
        let cipher = NullCipher;
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut data = vec![5, 6, 7, 8];
        let result = cipher.decrypt(&key, &nonce, &[], &mut data);
        assert!(result);
        assert_eq!(data, vec![5, 6, 7, 8]);
    }

    // --- V2HandshakeState values ---

    #[test]
    fn test_handshake_state_values() {
        let states = [
            V2HandshakeState::SendKey,
            V2HandshakeState::RecvKey,
            V2HandshakeState::KeyExchange,
            V2HandshakeState::SendGarbage,
            V2HandshakeState::RecvGarbage,
            V2HandshakeState::Ready,
            V2HandshakeState::Failed,
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

    // --- V2Transport accessors ---

    #[test]
    fn test_transport_our_pubkey_is_64_bytes() {
        let transport = V2Transport::new_null(true);
        assert_eq!(transport.our_pubkey().len(), ELLIGATOR_SWIFT_KEY_LEN);
    }

    #[test]
    fn test_transport_session_id_none_before_exchange() {
        let transport = V2Transport::new_null(true);
        assert!(transport.session_id().is_none());
    }

    #[test]
    fn test_transport_not_ready_initially() {
        let transport = V2Transport::new_null(true);
        assert!(!transport.is_ready());
    }

    #[test]
    fn test_transport_garbage_terminator_none_before_exchange() {
        let transport = V2Transport::new_null(true);
        assert!(transport.garbage_terminator_send().is_none());
    }

    // --- State transition edge cases ---

    #[test]
    fn test_sent_key_idempotent() {
        let mut transport = V2Transport::new_null(true);
        transport.sent_key();
        assert_eq!(transport.state(), V2HandshakeState::RecvKey);
        // Calling again should be idempotent (not in SendKey state)
        transport.sent_key();
        assert_eq!(transport.state(), V2HandshakeState::RecvKey);
    }

    #[test]
    fn test_sent_garbage_only_from_send_garbage() {
        let mut transport = V2Transport::new_null(true);
        // Not in SendGarbage state
        transport.sent_garbage();
        assert_eq!(transport.state(), V2HandshakeState::SendKey);
    }

    #[test]
    fn test_received_garbage_only_from_recv_garbage() {
        let mut transport = V2Transport::new_null(true);
        // Not in RecvGarbage state
        transport.received_garbage();
        assert_eq!(transport.state(), V2HandshakeState::SendKey);
    }

    #[test]
    fn test_complete_key_exchange_wrong_state() {
        let mut transport = V2Transport::new_null(true);
        // In SendKey, not KeyExchange
        transport.complete_key_exchange();
        assert_eq!(transport.state(), V2HandshakeState::Failed);
    }

    // --- Responder (non-initiator) handshake ---

    #[test]
    fn test_responder_handshake() {
        let mut transport = V2Transport::new_null(false);
        assert_eq!(transport.state(), V2HandshakeState::SendKey);
        assert!(!transport.initiator);

        transport.sent_key();
        let peer_pk = [0xCDu8; ELLIGATOR_SWIFT_KEY_LEN];
        transport.receive_key(&peer_pk);
        transport.complete_key_exchange();
        transport.sent_garbage();
        transport.received_garbage();

        assert!(transport.is_ready());
        assert!(transport.session_id().is_some());
    }

    // --- Decrypt before ready returns None ---

    #[test]
    fn test_decrypt_before_ready_returns_none() {
        let mut transport = V2Transport::new_null(true);
        let result = transport.decrypt_message(&[0x42]);
        assert!(result.is_none());
    }

    // --- Multiple encrypt/decrypt cycles ---

    #[test]
    fn test_multiple_encrypt_decrypt_cycles() {
        let mut transport = V2Transport::new_null(true);
        transport.sent_key();
        transport.receive_key(&[0u8; ELLIGATOR_SWIFT_KEY_LEN]);
        transport.complete_key_exchange();
        transport.sent_garbage();
        transport.received_garbage();

        for i in 0..5u8 {
            let msg = V2Message::from_short(V2Command::Pong, vec![i]).unwrap();
            let packet = transport.encrypt_message(&msg).unwrap();
            let decrypted = transport.decrypt_message(&packet[3..]).unwrap();
            assert_eq!(decrypted.command, V2Command::Pong);
            assert_eq!(decrypted.payload, vec![i]);
        }
        assert_eq!(transport.send_nonce, 5);
        assert_eq!(transport.recv_nonce, 5);
    }

    // --- Encrypt extended command message ---

    #[test]
    fn test_encrypt_decrypt_extended_command() {
        let mut transport = V2Transport::new_null(true);
        transport.sent_key();
        transport.receive_key(&[0x11u8; ELLIGATOR_SWIFT_KEY_LEN]);
        transport.complete_key_exchange();
        transport.sent_garbage();
        transport.received_garbage();

        let msg = V2Message::from_extended("customcmd", vec![0xaa, 0xbb]);
        let packet = transport.encrypt_message(&msg).unwrap();
        let decrypted = transport.decrypt_message(&packet[3..]).unwrap();
        assert_eq!(decrypted.command, V2Command::Extended("customcmd".to_string()));
        assert_eq!(decrypted.payload, vec![0xaa, 0xbb]);
    }

    // --- from_short with extended command returns None ---

    #[test]
    fn test_from_short_extended_returns_none() {
        let cmd = V2Command::Extended("foo".to_string());
        assert!(V2Message::from_short(cmd, vec![]).is_none());
    }

    // --- V2Message decode with ignore flag set but valid short ID ---

    #[test]
    fn test_decode_with_ignore_flag() {
        // header = 0x80 | 13 (Ping short ID) = 0x8D
        let data = vec![0x8D, 0x42];
        let msg = V2Message::decode(&data).unwrap();
        assert!(msg.is_decoy());
        assert_eq!(msg.command, V2Command::Ping);
        assert_eq!(msg.payload, vec![0x42]);
    }

    // --- V2Message decode extended with ignore flag ---

    #[test]
    fn test_decode_extended_with_ignore_flag() {
        // header = 0x80 (ignore flag, short_id = 0 -> extended)
        let mut data = vec![0x80];
        // 12 byte command
        data.extend_from_slice(b"testcmd\0\0\0\0\0");
        data.extend_from_slice(&[0xDE, 0xAD]);
        let msg = V2Message::decode(&data).unwrap();
        assert!(msg.is_decoy());
        assert_eq!(msg.command, V2Command::Extended("testcmd".to_string()));
        assert_eq!(msg.payload, vec![0xDE, 0xAD]);
    }

    // --- V2Message encode for extended with long command ---

    #[test]
    fn test_encode_extended_truncates_long_command() {
        let msg = V2Message::from_extended("verylongcmdname", vec![]);
        let encoded = msg.encode();
        assert_eq!(encoded[0], 0); // header
        // Command truncated to 12 bytes
        assert_eq!(&encoded[1..13], b"verylongcmdn");
        assert_eq!(encoded.len(), 13); // 1 + 12 + 0 payload
    }

    // --- V2Command from_str for all known commands ---

    #[test]
    fn test_from_str_all_known() {
        let mapping = vec![
            ("addr", V2Command::Addr),
            ("block", V2Command::Block),
            ("blocktxn", V2Command::BlockTxn),
            ("getdata", V2Command::GetData),
            ("getblocks", V2Command::GetBlocks),
            ("getheaders", V2Command::GetHeaders),
            ("cmpctblock", V2Command::CmpctBlock),
            ("headers", V2Command::Headers),
            ("inv", V2Command::Inv),
            ("mempool", V2Command::MemPool),
            ("merkleblock", V2Command::MerkleBlock),
            ("notfound", V2Command::NotFound),
            ("ping", V2Command::Ping),
            ("pong", V2Command::Pong),
            ("reject", V2Command::Reject),
            ("sendcmpct", V2Command::SendCmpct),
            ("sendheaders", V2Command::SendHeaders),
            ("tx", V2Command::Tx),
            ("getblocktxn", V2Command::GetBlockTxn),
            ("feefilter", V2Command::FeeFilter),
            ("filteradd", V2Command::FilterAdd),
            ("filterclear", V2Command::FilterClear),
            ("filterload", V2Command::FilterLoad),
            ("getaddr", V2Command::GetAddr),
            ("verack", V2Command::Verack),
            ("version", V2Command::Version),
            ("addrv2", V2Command::AddrV2),
            ("sendaddrv2", V2Command::SendAddrV2),
        ];
        for (name, expected) in mapping {
            let cmd = V2Command::from_str(name);
            assert_eq!(cmd, expected, "from_str mismatch for {}", name);
        }
    }

    // --- V2Command command_str for all known commands ---

    #[test]
    fn test_command_str_all_known() {
        let mapping = vec![
            (V2Command::Addr, "addr"),
            (V2Command::Block, "block"),
            (V2Command::BlockTxn, "blocktxn"),
            (V2Command::GetData, "getdata"),
            (V2Command::GetBlocks, "getblocks"),
            (V2Command::GetHeaders, "getheaders"),
            (V2Command::CmpctBlock, "cmpctblock"),
            (V2Command::Headers, "headers"),
            (V2Command::Inv, "inv"),
            (V2Command::MemPool, "mempool"),
            (V2Command::MerkleBlock, "merkleblock"),
            (V2Command::NotFound, "notfound"),
            (V2Command::Ping, "ping"),
            (V2Command::Pong, "pong"),
            (V2Command::Reject, "reject"),
            (V2Command::SendCmpct, "sendcmpct"),
            (V2Command::SendHeaders, "sendheaders"),
            (V2Command::Tx, "tx"),
            (V2Command::GetBlockTxn, "getblocktxn"),
            (V2Command::FeeFilter, "feefilter"),
            (V2Command::FilterAdd, "filteradd"),
            (V2Command::FilterClear, "filterclear"),
            (V2Command::FilterLoad, "filterload"),
            (V2Command::GetAddr, "getaddr"),
            (V2Command::Verack, "verack"),
            (V2Command::Version, "version"),
            (V2Command::AddrV2, "addrv2"),
            (V2Command::SendAddrV2, "sendaddrv2"),
        ];
        for (cmd, expected_str) in mapping {
            assert_eq!(cmd.command_str(), expected_str);
        }
    }

    // --- V2 handshake magic constant ---

    #[test]
    fn test_v2_handshake_magic() {
        assert_eq!(V2_HANDSHAKE_MAGIC, b"bitcoin_v2_handshake");
    }

    // --- Constants ---

    #[test]
    fn test_constants() {
        assert_eq!(MAX_GARBAGE_LEN, 4095);
        assert_eq!(ELLIGATOR_SWIFT_KEY_LEN, 64);
        assert_eq!(GARBAGE_TERMINATOR_LEN, 16);
    }

    // --- hkdf_extract deterministic ---

    #[test]
    fn test_hkdf_extract_deterministic() {
        let salt = [0xab; 32];
        let secret = [0xcd; 32];
        let label = b"test_label";
        let r1 = hkdf_extract(&salt, &secret, label);
        let r2 = hkdf_extract(&salt, &secret, label);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hkdf_extract_different_labels() {
        let salt = [0; 32];
        let secret = [0; 32];
        let r1 = hkdf_extract(&salt, &secret, b"label_a");
        let r2 = hkdf_extract(&salt, &secret, b"label_b");
        assert_ne!(r1, r2);
    }

    // --- Session keys fields populated after key exchange ---

    #[test]
    fn test_session_keys_fields() {
        let secret = [0x42; 32];
        let our_pk = [0x01; ELLIGATOR_SWIFT_KEY_LEN];
        let peer_pk = [0x02; ELLIGATOR_SWIFT_KEY_LEN];
        let keys = derive_session_keys(&secret, &our_pk, &peer_pk, true);

        // All fields should be non-zero (extremely unlikely to be all zeros)
        assert_ne!(keys.send_key, [0; 32]);
        assert_ne!(keys.recv_key, [0; 32]);
        assert_ne!(keys.session_id, [0; 32]);
        // send_key and recv_key should be different
        assert_ne!(keys.send_key, keys.recv_key);
    }

    // --- V2Message from_short with empty payload ---

    #[test]
    fn test_from_short_empty_payload() {
        let msg = V2Message::from_short(V2Command::Verack, vec![]).unwrap();
        assert_eq!(msg.header, 26); // Verack short ID
        assert_eq!(msg.command, V2Command::Verack);
        assert!(msg.payload.is_empty());
    }

    // --- V2Message extended with known command ---

    #[test]
    fn test_decode_extended_known_command() {
        // Extended command that happens to be a known name
        let mut data = vec![0x00]; // header = 0
        data.extend_from_slice(b"version\0\0\0\0\0"); // 12 bytes
        data.push(0xAA); // payload
        let msg = V2Message::decode(&data).unwrap();
        assert_eq!(msg.command, V2Command::Version);
        assert_eq!(msg.payload, vec![0xAA]);
    }

    // --- Recv nonce increments ---

    #[test]
    fn test_recv_nonce_increments() {
        let mut transport = V2Transport::new_null(true);
        transport.sent_key();
        transport.receive_key(&[0u8; ELLIGATOR_SWIFT_KEY_LEN]);
        transport.complete_key_exchange();
        transport.sent_garbage();
        transport.received_garbage();

        assert_eq!(transport.recv_nonce, 0);
        let msg = V2Message::from_short(V2Command::Ping, vec![]).unwrap();
        let packet = transport.encrypt_message(&msg).unwrap();
        transport.decrypt_message(&packet[3..]);
        assert_eq!(transport.recv_nonce, 1);
    }

    // --- Nonce wrapping ---

    #[test]
    fn test_nonce_wrapping() {
        let nonce = V2Transport::<NullCipher>::build_nonce(u64::MAX);
        let mut expected = [0u8; 12];
        expected[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(nonce, expected);
    }

    // --- Two transports with different initiator flags derive different keys ---

    #[test]
    fn test_two_transports_different_roles() {
        let mut init = V2Transport::new_null(true);
        let mut resp = V2Transport::new_null(false);

        // They should have different pubkeys (random)
        // but both start in SendKey state
        assert_eq!(init.state(), V2HandshakeState::SendKey);
        assert_eq!(resp.state(), V2HandshakeState::SendKey);

        init.sent_key();
        resp.sent_key();

        // Exchange keys
        let init_pk = *init.our_pubkey();
        let resp_pk = *resp.our_pubkey();

        init.receive_key(&resp_pk);
        resp.receive_key(&init_pk);

        init.complete_key_exchange();
        resp.complete_key_exchange();

        // Both should be in SendGarbage state
        assert_eq!(init.state(), V2HandshakeState::SendGarbage);
        assert_eq!(resp.state(), V2HandshakeState::SendGarbage);
    }
}
