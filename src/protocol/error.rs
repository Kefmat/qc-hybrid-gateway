use thiserror::Error;

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
    pub const fn is_framing_error(&self) -> bool {
        matches!(
            self,
            ProtocolError::BufferTooShort { .. }
                | ProtocolError::InvalidVersion(_)
                | ProtocolError::UnknownPacketType(_)
                | ProtocolError::FrameTooLarge { .. }
                | ProtocolError::PayloadTruncated { .. }
        )
    }

    pub const fn is_replay(&self) -> bool {
        matches!(self, ProtocolError::ReplayDetected(_))
    }

    pub const fn is_crypto_error(&self) -> bool {
        matches!(self, ProtocolError::CryptoError(_))
    }

    pub const fn is_state_error(&self) -> bool {
        matches!(self, ProtocolError::InvalidState(_))
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
}

