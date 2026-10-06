use std::fmt;

use crate::crypto::{aead::AeadCipher, kdf::SessionKeys};
use crate::protocol::{AntiReplayFilter, PacketFrame, PacketType, DEFAULT_REPLAY_WINDOW_SIZE};

pub const DEFAULT_REKEY_PACKET_THRESHOLD: u64 = 1_000_000;
pub const SESSION_ID_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_SIZE]);

impl Default for SessionId {
    fn default() -> Self {
        Self::generate()
    }
}

impl SessionId {
    pub fn new(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; SESSION_ID_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != SESSION_ID_SIZE * 2 {
            return Err(format!(
                "Invalid hex length for SessionId: expected {} characters, got {}",
                SESSION_ID_SIZE * 2,
                hex.len()
            ));
        }

        let mut bytes = [0u8; SESSION_ID_SIZE];
        for i in 0..SESSION_ID_SIZE {
            let byte_str = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|e| format!("Invalid hex byte '{}': {}", byte_str, e))?;
        }

        Ok(Self(bytes))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; SESSION_ID_SIZE]> for SessionId {
    fn as_ref(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Client,
    Server,
}

impl fmt::Display for SessionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionRole::Client => write!(f, "Client"),
            SessionRole::Server => write!(f, "Server"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Uninitialized,
    Handshaking,
    Established,
    Rekeying,
    Closed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Uninitialized => write!(f, "Uninitialized"),
            SessionState::Handshaking => write!(f, "Handshaking"),
            SessionState::Established => write!(f, "Established"),
            SessionState::Rekeying => write!(f, "Rekeying"),
            SessionState::Closed => write!(f, "Closed"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionMetrics {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub replays_dropped: u64,
    pub rekeys_completed: u64,
}

pub struct Session {
    session_id: SessionId,
    role: SessionRole,
    state: SessionState,
    tx_seq: u64,
    rx_filter: AntiReplayFilter,
    tx_cipher: Option<AeadCipher>,
    rx_cipher: Option<AeadCipher>,
    rekey_threshold: u64,
    metrics: SessionMetrics,
}

impl Session {
    pub fn new(role: SessionRole) -> Self {
        Self::with_session_id(role, SessionId::generate())
    }

    pub fn with_session_id(role: SessionRole, session_id: SessionId) -> Self {
        Self {
            session_id,
            role,
            state: SessionState::Uninitialized,
            tx_seq: 0,
            rx_filter: AntiReplayFilter::new(DEFAULT_REPLAY_WINDOW_SIZE),
            tx_cipher: None,
            rx_cipher: None,
            rekey_threshold: DEFAULT_REKEY_PACKET_THRESHOLD,
            metrics: SessionMetrics::default(),
        }
    }

    pub fn new_client() -> Self {
        Self::new(SessionRole::Client)
    }

    pub fn new_server() -> Self {
        Self::new(SessionRole::Server)
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }


    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state == SessionState::Closed
    }

    pub fn tx_seq(&self) -> u64 {
        self.tx_seq
    }

    pub fn metrics(&self) -> &SessionMetrics {
        &self.metrics
    }

    pub fn reset_metrics(&mut self) {
        self.metrics = SessionMetrics::default();
    }

    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    pub fn set_rekey_threshold(&mut self, threshold: u64) {
        self.rekey_threshold = threshold;
    }

    pub fn rekey_threshold(&self) -> u64 {
        self.rekey_threshold
    }

    pub fn establish(&mut self, keys: &SessionKeys) -> Result<(), String> {
        if self.state == SessionState::Closed {
            return Err("Cannot establish a closed session".to_string());
        }

        let (tx_key, rx_key) = match self.role {
            SessionRole::Client => (keys.client_write_key(), keys.server_write_key()),
            SessionRole::Server => (keys.server_write_key(), keys.client_write_key()),
        };

        self.tx_cipher = Some(AeadCipher::new(tx_key));
        self.rx_cipher = Some(AeadCipher::new(rx_key));
        self.state = SessionState::Established;
        self.tx_seq = 0;
        self.rx_filter.reset();

        Ok(())
    }

    pub fn encrypt_packet(&mut self, packet_type: PacketType, plaintext: &[u8]) -> Result<PacketFrame, String> {
        if self.state != SessionState::Established {
            return Err(format!("Cannot encrypt packet in state: {}", self.state));
        }

        let cipher = self.tx_cipher.as_ref().ok_or("TX cipher uninitialized")?;
        self.tx_seq += 1;
        let seq = self.tx_seq;

        let aad = format!("seq={}", seq);
        let ciphertext = cipher.encrypt(seq, aad.as_bytes(), plaintext)?;

        self.metrics.tx_packets += 1;
        self.metrics.tx_bytes += plaintext.len() as u64;

        PacketFrame::new(packet_type, seq, ciphertext)
    }

    pub fn decrypt_packet(&mut self, frame: &PacketFrame) -> Result<Vec<u8>, String> {
        if self.state != SessionState::Established {
            return Err(format!("Cannot decrypt packet in state: {}", self.state));
        }

        let cipher = self.rx_cipher.as_ref().ok_or("RX cipher uninitialized")?;

        if !self.rx_filter.check_and_update(frame.seq()) {
            self.metrics.replays_dropped += 1;
            return Err(format!(
                "Anti-replay check failed for sequence number {}",
                frame.seq()
            ));
        }

        let aad = format!("seq={}", frame.seq());
        let plaintext = cipher.decrypt(frame.seq(), aad.as_bytes(), &frame.payload)?;

        self.metrics.rx_packets += 1;
        self.metrics.rx_bytes += plaintext.len() as u64;

        Ok(plaintext)
    }

    pub fn create_ping(&mut self, timestamp: u64) -> Result<PacketFrame, String> {
        self.encrypt_packet(PacketType::Ping, &timestamp.to_be_bytes())
    }

    pub fn handle_ping(&mut self, frame: &PacketFrame) -> Result<u64, String> {
        if frame.packet_type() != PacketType::Ping {
            return Err(format!("Expected Ping packet, received: {}", frame.packet_type()));
        }

        let decrypted = self.decrypt_packet(frame)?;
        if decrypted.len() != 8 {
            return Err(format!("Invalid ping payload size: {} bytes (expected 8)", decrypted.len()));
        }

        Ok(u64::from_be_bytes(decrypted[..8].try_into().unwrap()))
    }

    pub fn is_rekey_needed(&self) -> bool {
        self.tx_seq >= self.rekey_threshold
    }

    pub fn trigger_rekey(&mut self) -> Result<(), String> {
        if self.state != SessionState::Established {
            return Err(format!("Cannot trigger rekey from state: {}", self.state));
        }
        self.state = SessionState::Rekeying;
        Ok(())
    }

    pub fn complete_rekey(&mut self, keys: &SessionKeys) -> Result<(), String> {
        if self.state != SessionState::Rekeying {
            return Err(format!("Cannot complete rekey in state: {}", self.state));
        }

        let (tx_key, rx_key) = match self.role {
            SessionRole::Client => (keys.client_write_key(), keys.server_write_key()),
            SessionRole::Server => (keys.server_write_key(), keys.client_write_key()),
        };

        self.tx_cipher = Some(AeadCipher::new(tx_key));
        self.rx_cipher = Some(AeadCipher::new(rx_key));
        self.state = SessionState::Established;
        self.tx_seq = 0;
        self.rx_filter.reset();
        self.metrics.rekeys_completed += 1;

        Ok(())
    }

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        self.tx_cipher = None;
        self.rx_cipher = None;
        self.rx_filter.reset();
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::SessionKeys;

    #[test]
    fn test_session_creation_and_defaults() {
        let client = Session::new_client();
        assert_eq!(client.role(), SessionRole::Client);
        assert_eq!(client.state(), SessionState::Uninitialized);
        assert!(!client.is_established());
        assert!(!client.is_closed());
        assert_eq!(client.tx_seq(), 0);

        let server = Session::new_server();
        assert_eq!(server.role(), SessionRole::Server);
        assert_eq!(server.state(), SessionState::Uninitialized);
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(SessionRole::Client.to_string(), "Client");
        assert_eq!(SessionRole::Server.to_string(), "Server");

        assert_eq!(SessionState::Uninitialized.to_string(), "Uninitialized");
        assert_eq!(SessionState::Handshaking.to_string(), "Handshaking");
        assert_eq!(SessionState::Established.to_string(), "Established");
        assert_eq!(SessionState::Rekeying.to_string(), "Rekeying");
        assert_eq!(SessionState::Closed.to_string(), "Closed");
    }

    #[test]
    fn test_session_establish() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        assert!(client.establish(&keys).is_ok());
        assert!(server.establish(&keys).is_ok());

        assert!(client.is_established());
        assert!(server.is_established());
    }

    #[test]
    fn test_session_encrypt_decrypt_bidirectional() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let keys = SessionKeys::new([11u8; 32], [22u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        // Client -> Server
        let client_msg = b"client-payload-123";
        let frame = client.encrypt_packet(PacketType::Data, client_msg).unwrap();
        assert_eq!(frame.seq(), 1);

        let decrypted = server.decrypt_packet(&frame).unwrap();
        assert_eq!(client_msg.to_vec(), decrypted);

        // Server -> Client
        let server_msg = b"server-payload-response";
        let resp_frame = server.encrypt_packet(PacketType::Data, server_msg).unwrap();
        assert_eq!(resp_frame.seq(), 1);

        let decrypted_resp = client.decrypt_packet(&resp_frame).unwrap();
        assert_eq!(server_msg.to_vec(), decrypted_resp);
    }

    #[test]
    fn test_session_replay_rejection() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let keys = SessionKeys::new([33u8; 32], [44u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        let frame = client.encrypt_packet(PacketType::Data, b"data").unwrap();
        assert!(server.decrypt_packet(&frame).is_ok());

        // Replay same frame fails anti-replay check
        assert!(server.decrypt_packet(&frame).is_err());
    }

    #[test]
    fn test_session_unestablished_operations_fail() {
        let mut client = Session::new_client();
        let err = client.encrypt_packet(PacketType::Data, b"test");
        assert!(err.is_err());

        let frame = PacketFrame::new(PacketType::Data, 1, vec![1, 2, 3]).unwrap();
        let err_dec = client.decrypt_packet(&frame);
        assert!(err_dec.is_err());
    }

    #[test]
    fn test_session_rekeying_lifecycle() {
        let mut client = Session::new_client();
        let initial_keys = SessionKeys::new([55u8; 32], [66u8; 32]);
        client.establish(&initial_keys).unwrap();

        client.set_rekey_threshold(2);
        assert_eq!(client.rekey_threshold(), 2);
        assert!(!client.is_rekey_needed());

        client.encrypt_packet(PacketType::Data, b"msg1").unwrap();
        assert!(!client.is_rekey_needed());

        client.encrypt_packet(PacketType::Data, b"msg2").unwrap();
        assert!(client.is_rekey_needed());

        // Trigger rekey
        assert!(client.trigger_rekey().is_ok());
        assert_eq!(client.state(), SessionState::Rekeying);
        assert!(!client.is_established());

        // Complete rekey
        let rekeyed_keys = SessionKeys::new([77u8; 32], [88u8; 32]);
        assert!(client.complete_rekey(&rekeyed_keys).is_ok());
        assert!(client.is_established());
        assert_eq!(client.tx_seq(), 0);
        assert!(!client.is_rekey_needed());
    }

    #[test]
    fn test_session_close_lifecycle() {
        let mut client = Session::new_client();
        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        client.establish(&keys).unwrap();
        assert!(client.is_established());

        client.close();
        assert!(client.is_closed());
        assert!(!client.is_established());

        // Operations fail after close
        assert!(client.encrypt_packet(PacketType::Data, b"data").is_err());
        assert!(client.trigger_rekey().is_err());
        assert!(client.establish(&keys).is_err());
    }

    #[test]
    fn test_session_metrics_tracking() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();
        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        let payload = b"metrics-test-data";
        let frame = client.encrypt_packet(PacketType::Data, payload).unwrap();
        assert_eq!(client.metrics().tx_packets, 1);
        assert_eq!(client.metrics().tx_bytes, payload.len() as u64);

        let _ = server.decrypt_packet(&frame).unwrap();
        assert_eq!(server.metrics().rx_packets, 1);
        assert_eq!(server.metrics().rx_bytes, payload.len() as u64);

        // Test replay metric increment
        let _ = server.decrypt_packet(&frame);
        assert_eq!(server.metrics().replays_dropped, 1);

        // Test rekey metric increment
        client.trigger_rekey().unwrap();
        let new_keys = SessionKeys::new([3u8; 32], [4u8; 32]);
        client.complete_rekey(&new_keys).unwrap();
        assert_eq!(client.metrics().rekeys_completed, 1);

        client.reset_metrics();
        assert_eq!(client.metrics().tx_packets, 0);
        assert_eq!(client.metrics().tx_bytes, 0);
    }

    #[test]
    fn test_session_ping_roundtrip() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();
        let keys = SessionKeys::new([10u8; 32], [20u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        let timestamp = 1727784000;
        let ping_frame = client.create_ping(timestamp).unwrap();
        assert!(ping_frame.is_ping());

        let received_timestamp = server.handle_ping(&ping_frame).unwrap();
        assert_eq!(received_timestamp, timestamp);
    }

    #[test]
    fn test_session_ping_validation_errors() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();
        let keys = SessionKeys::new([10u8; 32], [20u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        // Data frame passed to handle_ping fails
        let data_frame = client.encrypt_packet(PacketType::Data, b"not-a-ping").unwrap();
        assert!(server.handle_ping(&data_frame).is_err());

        // Ping frame with invalid length fails
        let bad_ping_frame = client.encrypt_packet(PacketType::Ping, b"short").unwrap();
        assert!(server.handle_ping(&bad_ping_frame).is_err());
    }

    #[test]
    fn test_session_id_lifecycle() {
        let sid = SessionId::generate();
        assert_eq!(sid.as_bytes().len(), SESSION_ID_SIZE);

        let hex = sid.to_hex();
        assert_eq!(hex.len(), SESSION_ID_SIZE * 2);
        assert_eq!(sid.to_string(), hex);

        let parsed = SessionId::from_hex(&hex).unwrap();
        assert_eq!(sid, parsed);

        // Invalid hex fails
        assert!(SessionId::from_hex("invalid").is_err());
        assert!(SessionId::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());

        // Custom session ID initialization
        let custom_sid = SessionId::new([0xab; SESSION_ID_SIZE]);
        let session = Session::with_session_id(SessionRole::Client, custom_sid);
        assert_eq!(session.session_id(), &custom_sid);

        // AsRef checks
        let slice: &[u8] = custom_sid.as_ref();
        assert_eq!(slice, &[0xab; SESSION_ID_SIZE]);
        let array_ref: &[u8; SESSION_ID_SIZE] = custom_sid.as_ref();
        assert_eq!(array_ref, &[0xab; SESSION_ID_SIZE]);
    }
}




