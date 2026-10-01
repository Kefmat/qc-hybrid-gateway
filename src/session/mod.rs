use std::fmt;

use crate::crypto::{aead::AeadCipher, kdf::SessionKeys};
use crate::protocol::{AntiReplayFilter, DEFAULT_REPLAY_WINDOW_SIZE};

pub const DEFAULT_REKEY_PACKET_THRESHOLD: u64 = 1_000_000;

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

pub struct Session {
    role: SessionRole,
    state: SessionState,
    tx_seq: u64,
    rx_filter: AntiReplayFilter,
    tx_cipher: Option<AeadCipher>,
    rx_cipher: Option<AeadCipher>,
    rekey_threshold: u64,
}

impl Session {
    pub fn new(role: SessionRole) -> Self {
        Self {
            role,
            state: SessionState::Uninitialized,
            tx_seq: 0,
            rx_filter: AntiReplayFilter::new(DEFAULT_REPLAY_WINDOW_SIZE),
            tx_cipher: None,
            rx_cipher: None,
            rekey_threshold: DEFAULT_REKEY_PACKET_THRESHOLD,
        }
    }

    pub fn new_client() -> Self {
        Self::new(SessionRole::Client)
    }

    pub fn new_server() -> Self {
        Self::new(SessionRole::Server)
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
}
