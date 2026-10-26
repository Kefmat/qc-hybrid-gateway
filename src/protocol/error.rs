use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    Framing,
    Replay,
    Crypto,
    State,
}

impl ErrorKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::Framing => "Framing",
            ErrorKind::Replay => "Replay",
            ErrorKind::Crypto => "Crypto",
            ErrorKind::State => "State",
        }
    }

    pub const fn is_framing(&self) -> bool {
        matches!(self, ErrorKind::Framing)
    }

    pub const fn is_replay(&self) -> bool {
        matches!(self, ErrorKind::Replay)
    }

    pub const fn is_crypto(&self) -> bool {
        matches!(self, ErrorKind::Crypto)
    }

    pub const fn is_state(&self) -> bool {
        matches!(self, ErrorKind::State)
    }
}

impl AsRef<str> for ErrorKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ErrorKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Framing" => Ok(ErrorKind::Framing),
            "Replay" => Ok(ErrorKind::Replay),
            "Crypto" => Ok(ErrorKind::Crypto),
            "State" => Ok(ErrorKind::State),
            _ => Err(format!("Unknown error kind: '{}'", s)),
        }
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Buffer too short: expected at least {expected} bytes, received {actual} bytes")]
    BufferTooShort { expected: usize, actual: usize },

    #[error("Unsupported protocol version: {0}")]
    InvalidVersion(u8),

    #[error("Unknown packet type identifier: 0x{0:02x}")]
    UnknownPacketType(u8),

    #[error("Payload length {payload_len} exceeds maximum frame limit {max_limit}")]
    FrameTooLarge { payload_len: usize, max_limit: usize },

    #[error("Payload truncated: header specified {expected} bytes, but buffer has {actual} bytes")]
    PayloadTruncated { expected: usize, actual: usize },

    #[error("Anti-replay validation failed for sequence {0}")]
    ReplayDetected(u64),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid session state: {0}")]
    InvalidState(String),
}

impl ProtocolError {
    pub const fn kind(&self) -> ErrorKind {
        match self {
            ProtocolError::BufferTooShort { .. }
            | ProtocolError::InvalidVersion(_)
            | ProtocolError::UnknownPacketType(_)
            | ProtocolError::FrameTooLarge { .. }
            | ProtocolError::PayloadTruncated { .. } => ErrorKind::Framing,
            ProtocolError::ReplayDetected(_) => ErrorKind::Replay,
            ProtocolError::CryptoError(_) => ErrorKind::Crypto,
            ProtocolError::InvalidState(_) => ErrorKind::State,
        }
    }

    pub fn buffer_too_short(expected: usize, actual: usize) -> Self {
        Self::BufferTooShort { expected, actual }
    }

    pub fn invalid_version(version: u8) -> Self {
        Self::InvalidVersion(version)
    }

    pub fn unknown_packet_type(packet_type: u8) -> Self {
        Self::UnknownPacketType(packet_type)
    }

    pub fn frame_too_large(payload_len: usize, max_limit: usize) -> Self {
        Self::FrameTooLarge {
            payload_len,
            max_limit,
        }
    }

    pub fn payload_truncated(expected: usize, actual: usize) -> Self {
        Self::PayloadTruncated { expected, actual }
    }

    pub fn replay_detected(seq: u64) -> Self {
        Self::ReplayDetected(seq)
    }

    pub fn crypto_error(msg: impl Into<String>) -> Self {
        Self::CryptoError(msg.into())
    }

    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::InvalidState(msg.into())
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(self, ProtocolError::ReplayDetected(_))
    }

    pub const fn is_framing_error(&self) -> bool {
        matches!(self.kind(), ErrorKind::Framing)
    }

    pub const fn is_replay(&self) -> bool {
        matches!(self.kind(), ErrorKind::Replay)
    }

    pub const fn is_crypto_error(&self) -> bool {
        matches!(self.kind(), ErrorKind::Crypto)
    }

    pub const fn is_state_error(&self) -> bool {
        matches!(self.kind(), ErrorKind::State)
    }
}

impl From<ProtocolError> for std::io::Error {
    fn from(err: ProtocolError) -> Self {
        let io_kind = match err.kind() {
            ErrorKind::Framing => std::io::ErrorKind::InvalidData,
            ErrorKind::Replay => std::io::ErrorKind::ConnectionAborted,
            ErrorKind::Crypto => std::io::ErrorKind::InvalidInput,
            ErrorKind::State => std::io::ErrorKind::NotConnected,
        };
        std::io::Error::new(io_kind, err.to_string())
    }
}

impl From<&ProtocolError> for std::io::Error {
    fn from(err: &ProtocolError) -> Self {
        let io_kind = match err.kind() {
            ErrorKind::Framing => std::io::ErrorKind::InvalidData,
            ErrorKind::Replay => std::io::ErrorKind::ConnectionAborted,
            ErrorKind::Crypto => std::io::ErrorKind::InvalidInput,
            ErrorKind::State => std::io::ErrorKind::NotConnected,
        };
        std::io::Error::new(io_kind, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_error_formatting() {
        let err = ProtocolError::BufferTooShort { expected: 14, actual: 5 };
        assert_eq!(err.to_string(), "Buffer too short: expected at least 14 bytes, received 5 bytes");

        let err = ProtocolError::InvalidVersion(2);
        assert_eq!(err.to_string(), "Unsupported protocol version: 2");

        let err = ProtocolError::UnknownPacketType(0xFF);
        assert_eq!(err.to_string(), "Unknown packet type identifier: 0xff");

        let err = ProtocolError::FrameTooLarge { payload_len: 70000, max_limit: 65536 };
        assert_eq!(err.to_string(), "Payload length 70000 exceeds maximum frame limit 65536");

        let err = ProtocolError::PayloadTruncated { expected: 100, actual: 50 };
        assert_eq!(err.to_string(), "Payload truncated: header specified 100 bytes, but buffer has 50 bytes");

        let err = ProtocolError::ReplayDetected(42);
        assert_eq!(err.to_string(), "Anti-replay validation failed for sequence 42");

        let err = ProtocolError::CryptoError("tag mismatch".to_string());
        assert_eq!(err.to_string(), "Cryptographic operation failed: tag mismatch");

        let err = ProtocolError::InvalidState("Closed".to_string());
        assert_eq!(err.to_string(), "Invalid session state: Closed");
    }

    #[test]
    fn test_protocol_error_predicates() {
        let err_buf = ProtocolError::BufferTooShort { expected: 10, actual: 2 };
        assert!(err_buf.is_framing_error());
        assert!(!err_buf.is_replay());
        assert!(!err_buf.is_crypto_error());
        assert!(!err_buf.is_state_error());

        let err_ver = ProtocolError::InvalidVersion(9);
        assert!(err_ver.is_framing_error());

        let err_type = ProtocolError::UnknownPacketType(0xEE);
        assert!(err_type.is_framing_error());

        let err_large = ProtocolError::FrameTooLarge { payload_len: 100000, max_limit: 65536 };
        assert!(err_large.is_framing_error());

        let err_trunc = ProtocolError::PayloadTruncated { expected: 50, actual: 10 };
        assert!(err_trunc.is_framing_error());

        let err_replay = ProtocolError::ReplayDetected(99);
        assert!(err_replay.is_replay());
        assert!(!err_replay.is_framing_error());

        let err_crypto = ProtocolError::CryptoError("auth failure".into());
        assert!(err_crypto.is_crypto_error());
        assert!(!err_crypto.is_framing_error());

        let err_state = ProtocolError::InvalidState("Uninitialized".into());
        assert!(err_state.is_state_error());
        assert!(!err_state.is_framing_error());
    }

    #[test]
    fn test_error_kind_display() {
        assert_eq!(ErrorKind::Framing.to_string(), "Framing");
        assert_eq!(ErrorKind::Replay.to_string(), "Replay");
        assert_eq!(ErrorKind::Crypto.to_string(), "Crypto");
        assert_eq!(ErrorKind::State.to_string(), "State");
    }

    #[test]
    fn test_error_kind_methods_and_as_ref() {
        assert_eq!(ErrorKind::Framing.as_str(), "Framing");
        assert_eq!(ErrorKind::Replay.as_str(), "Replay");
        assert_eq!(ErrorKind::Crypto.as_str(), "Crypto");
        assert_eq!(ErrorKind::State.as_str(), "State");

        assert!(ErrorKind::Framing.is_framing());
        assert!(!ErrorKind::Framing.is_replay());
        assert!(ErrorKind::Replay.is_replay());
        assert!(!ErrorKind::Replay.is_crypto());
        assert!(ErrorKind::Crypto.is_crypto());
        assert!(!ErrorKind::Crypto.is_state());
        assert!(ErrorKind::State.is_state());
        assert!(!ErrorKind::State.is_framing());

        assert_eq!(ErrorKind::Framing.as_ref(), "Framing");
        assert_eq!(ErrorKind::State.as_ref(), "State");

        assert_eq!("Framing".parse::<ErrorKind>().unwrap(), ErrorKind::Framing);
        assert_eq!("Replay".parse::<ErrorKind>().unwrap(), ErrorKind::Replay);
        assert_eq!("Crypto".parse::<ErrorKind>().unwrap(), ErrorKind::Crypto);
        assert_eq!("State".parse::<ErrorKind>().unwrap(), ErrorKind::State);
        assert!("UnknownKind".parse::<ErrorKind>().is_err());
    }

    #[test]
    fn test_protocol_error_constructors_and_kind() {
        let err_buf = ProtocolError::buffer_too_short(20, 5);
        assert_eq!(err_buf.kind(), ErrorKind::Framing);
        assert!(!err_buf.is_recoverable());

        let err_ver = ProtocolError::invalid_version(3);
        assert_eq!(err_ver.kind(), ErrorKind::Framing);

        let err_type = ProtocolError::unknown_packet_type(0xAB);
        assert_eq!(err_type.kind(), ErrorKind::Framing);

        let err_large = ProtocolError::frame_too_large(1000, 500);
        assert_eq!(err_large.kind(), ErrorKind::Framing);

        let err_trunc = ProtocolError::payload_truncated(100, 20);
        assert_eq!(err_trunc.kind(), ErrorKind::Framing);

        let err_replay = ProtocolError::replay_detected(42);
        assert_eq!(err_replay.kind(), ErrorKind::Replay);
        assert!(err_replay.is_recoverable());

        let err_crypto = ProtocolError::crypto_error("decrypt failed");
        assert_eq!(err_crypto.kind(), ErrorKind::Crypto);
        assert!(!err_crypto.is_recoverable());

        let err_state = ProtocolError::invalid_state("closed");
        assert_eq!(err_state.kind(), ErrorKind::State);
        assert!(!err_state.is_recoverable());

        // Test std::io::Error conversions
        let io_buf: std::io::Error = err_buf.into();
        assert_eq!(io_buf.kind(), std::io::ErrorKind::InvalidData);

        let io_replay: std::io::Error = (&err_replay).into();
        assert_eq!(io_replay.kind(), std::io::ErrorKind::ConnectionAborted);

        let io_crypto: std::io::Error = err_crypto.into();
        assert_eq!(io_crypto.kind(), std::io::ErrorKind::InvalidInput);

        let io_state: std::io::Error = (&err_state).into();
        assert_eq!(io_state.kind(), std::io::ErrorKind::NotConnected);
    }
}

