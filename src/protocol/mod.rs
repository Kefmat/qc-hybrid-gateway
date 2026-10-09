use std::collections::HashSet;
use std::fmt;

pub mod codec;
pub mod error;
pub mod handshake;
pub use codec::FrameDecoder;
pub use error::ProtocolError;
pub use handshake::{HandshakeInit, HandshakeResponse, HANDSHAKE_NONCE_SIZE};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_SIZE: usize = 65536;
pub const HEADER_SIZE: usize = 14; // version (1) + type (1) + seq (8) + payload_len (4)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Data = 0x03,
    Ping = 0x04,
}

impl PacketType {
    pub const fn is_handshake(&self) -> bool {
        matches!(self, PacketType::HandshakeInit | PacketType::HandshakeResp)
    }

    pub const fn is_data(&self) -> bool {
        matches!(self, PacketType::Data)
    }

    pub const fn is_ping(&self) -> bool {
        matches!(self, PacketType::Ping)
    }
}

impl fmt::Display for PacketType {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::HandshakeInit => write!(f, "HandshakeInit"),
            PacketType::HandshakeResp => write!(f, "HandshakeResp"),
            PacketType::Data => write!(f, "Data"),
            PacketType::Ping => write!(f, "Ping"),
        }
    }
}

impl TryFrom<u8> for PacketType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::HandshakeInit),
            0x02 => Ok(PacketType::HandshakeResp),
            0x03 => Ok(PacketType::Data),
            0x04 => Ok(PacketType::Ping),
            _ => Err(format!("Unknown packet type: 0x{:02x}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub seq: u64,
    pub payload_len: u32,
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Data,
            seq: 0,
            payload_len: 0,
        }
    }
}

impl PacketHeader {
    pub fn new(packet_type: PacketType, seq: u64, payload_len: u32) -> Result<Self, String> {

        if payload_len as usize > MAX_FRAME_SIZE {
            return Err(format!(
                "Payload length {} exceeds maximum frame size {}",
                payload_len, MAX_FRAME_SIZE
            ));
        }

        Ok(Self {
            version: PROTOCOL_VERSION,
            packet_type,
            seq,
            payload_len,
        })
    }

    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2..10].copy_from_slice(&self.seq.to_be_bytes());
        buf[10..14].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_SIZE {
            return Err("Header buffer too short".to_string());
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(format!("Unsupported protocol version: {}", version));
        }

        let packet_type = PacketType::try_from(bytes[1])?;
        let seq = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[10..14].try_into().unwrap());

        if payload_len as usize > MAX_FRAME_SIZE {
            return Err(format!(
                "Decoded payload length {} exceeds maximum frame size {}",
                payload_len, MAX_FRAME_SIZE
            ));
        }

        Ok(Self {
            version,
            packet_type,
            seq,
            payload_len,
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        self.encode()
    }

    pub fn total_frame_len(&self) -> usize {
        HEADER_SIZE + self.payload_len as usize
    }

    pub const fn is_valid_version(&self) -> bool {
        self.version == PROTOCOL_VERSION
    }

    pub const fn is_handshake(&self) -> bool {
        self.packet_type.is_handshake()
    }

    pub const fn is_data(&self) -> bool {
        self.packet_type.is_data()
    }

    pub const fn is_ping(&self) -> bool {
        self.packet_type.is_ping()
    }
}

impl TryFrom<&[u8]> for PacketHeader {
    type Error = String;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(slice)
    }
}

impl TryFrom<[u8; HEADER_SIZE]> for PacketHeader {
    type Error = String;

    fn try_from(bytes: [u8; HEADER_SIZE]) -> Result<Self, Self::Error> {
        Self::decode(&bytes)
    }
}

impl fmt::Display for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PacketHeader(v{}, {}, seq={}, len={})",
            self.version, self.packet_type, self.seq, self.payload_len
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl PacketFrame {
    pub fn new(packet_type: PacketType, seq: u64, payload: Vec<u8>) -> Result<Self, String> {
        let header = PacketHeader::new(packet_type, seq, payload.len() as u32)?;
        Ok(Self { header, payload })
    }

    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    pub fn version(&self) -> u8 {
        self.header.version
    }

    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    pub const fn is_handshake(&self) -> bool {
        self.header.is_handshake()
    }

    pub const fn is_data(&self) -> bool {
        self.header.is_data()
    }

    pub const fn is_ping(&self) -> bool {
        self.header.is_ping()
    }

    pub fn seq(&self) -> u64 {
        self.header.seq
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn total_len(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let header = PacketHeader::decode(bytes)?;
        let payload_len = header.payload_len as usize;

        if bytes.len() < HEADER_SIZE + payload_len {
            return Err("Packet payload truncated".to_string());
        }

        let payload = bytes[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();

        Ok(Self { header, payload })
    }
}

impl fmt::Display for PacketFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PacketFrame({}, seq={}, len={})",
            self.header.packet_type, self.header.seq, self.payload.len()
        )
    }
}


pub const DEFAULT_REPLAY_WINDOW_SIZE: u64 = 64;

#[derive(Debug, Clone)]
pub struct AntiReplayFilter {
    window_size: u64,
    highest_seq: u64,
    seen: HashSet<u64>,
}

impl Default for AntiReplayFilter {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW_SIZE)
    }
}

impl AntiReplayFilter {
    pub fn new(window_size: u64) -> Self {
        Self {
            window_size,
            highest_seq: 0,
            seen: HashSet::new(),
        }
    }

    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    pub fn highest_seq(&self) -> u64 {
        self.highest_seq
    }

    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    pub fn reset(&mut self) {
        self.highest_seq = 0;
        self.seen.clear();
    }

    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq > self.highest_seq {
            let cutoff = seq.saturating_sub(self.window_size);
            self.seen.retain(|&s| s >= cutoff);
            self.highest_seq = seq;
            self.seen.insert(seq);
            true
        } else if seq + self.window_size > self.highest_seq {
            if self.seen.contains(&seq) {
                false // Replay detected
            } else {
                self.seen.insert(seq);
                true
            }
        } else {
            false // Too old
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_frame_roundtrip() {
        let frame = PacketFrame::new(PacketType::Data, 100, b"secure-pqc-payload".to_vec()).unwrap();
        let encoded = frame.encode();
        let decoded = PacketFrame::decode(&encoded).expect("failed to decode frame");

        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_packet_header_encode_decode() {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::HandshakeInit,
            seq: 12345,
            payload_len: 256,
        };
        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = PacketHeader::decode(&encoded).expect("failed to decode header");
        assert_eq!(header, decoded);

        // Test decode failure on invalid version
        let mut bad_version = encoded;
        bad_version[0] = 99;
        assert!(PacketHeader::decode(&bad_version).is_err());
    }

    #[test]
    fn test_packet_header_new_and_size_validation() {
        let valid_header = PacketHeader::new(PacketType::Data, 1, 1024);
        assert!(valid_header.is_ok());

        let oversized_header = PacketHeader::new(PacketType::Data, 1, (MAX_FRAME_SIZE + 1) as u32);
        assert!(oversized_header.is_err());
    }

    #[test]
    fn test_packet_type_predicates() {
        assert!(PacketType::HandshakeInit.is_handshake());
        assert!(PacketType::HandshakeResp.is_handshake());
        assert!(!PacketType::Data.is_handshake());
        assert!(PacketType::Data.is_data());
        assert!(!PacketType::Ping.is_data());
        assert!(PacketType::Ping.is_ping());

        let frame = PacketFrame::new(PacketType::HandshakeInit, 1, vec![]).unwrap();
        assert!(frame.is_handshake());
        assert!(!frame.is_data());
        assert!(!frame.is_ping());
    }

    #[test]
    fn test_packet_header_default() {
        let header = PacketHeader::default();
        assert_eq!(header.version, PROTOCOL_VERSION);

        assert_eq!(header.packet_type, PacketType::Data);
        assert_eq!(header.seq, 0);
        assert_eq!(header.payload_len, 0);
    }

    #[test]
    fn test_packet_frame_accessors() {
        let frame = PacketFrame::new(PacketType::Data, 77, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(frame.packet_type(), PacketType::Data);
        assert_eq!(frame.version(), PROTOCOL_VERSION);
        assert_eq!(frame.header().seq, 77);
        assert_eq!(frame.seq(), 77);
        assert_eq!(frame.payload_len(), 4);
        assert_eq!(frame.payload(), &[1, 2, 3, 4]);
        assert_eq!(frame.total_len(), HEADER_SIZE + 4);
        assert!(!frame.is_empty());
        assert_eq!(frame.clone().into_payload(), vec![1, 2, 3, 4]);

        let empty_frame = PacketFrame::new(PacketType::Ping, 88, vec![]).unwrap();
        assert_eq!(empty_frame.payload_len(), 0);
        assert_eq!(empty_frame.payload(), &[] as &[u8]);
        assert_eq!(empty_frame.total_len(), HEADER_SIZE);
        assert!(empty_frame.is_empty());
        assert_eq!(empty_frame.into_payload(), Vec::<u8>::new());
    }

    #[test]
    fn test_packet_frame_truncated() {
        let frame = PacketFrame::new(PacketType::Ping, 1, b"ping".to_vec()).unwrap();
        let mut encoded = frame.encode();
        encoded.pop(); // remove one byte

        assert!(PacketFrame::decode(&encoded).is_err());
    }

    #[test]
    fn test_invalid_packet_type() {
        let mut bytes = vec![PROTOCOL_VERSION, 0x99];
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());

        assert!(PacketFrame::decode(&bytes).is_err());
    }

    #[test]
    fn test_packet_frame_oversized_payload() {
        let oversized = vec![0u8; MAX_FRAME_SIZE + 1];
        let result = PacketFrame::new(PacketType::Data, 1, oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_anti_replay_filter_detailed() {
        let mut filter = AntiReplayFilter::new(10);
        // Initial accept
        assert!(filter.check_and_update(10));
        // Duplicate within window rejected
        assert!(!filter.check_and_update(10));
        // Out of order within window accepted
        assert!(filter.check_and_update(5));
        // Duplicate of out of order rejected
        assert!(!filter.check_and_update(5));
        // Packets outside window rejected
        assert!(!filter.check_and_update(0));
        // Sequence advance and window pruning
        assert!(filter.check_and_update(30));
        assert!(!filter.check_and_update(10)); // now out of window
        assert!(filter.check_and_update(25)); // within new window (30 - 10 = 20)
    }

    #[test]
    fn test_display_implementations() {
        assert_eq!(PacketType::HandshakeInit.to_string(), "HandshakeInit");
        assert_eq!(PacketType::Data.to_string(), "Data");

        let header = PacketHeader {
            version: 1,
            packet_type: PacketType::Data,
            seq: 42,
            payload_len: 128,
        };
        assert_eq!(
            header.to_string(),
            "PacketHeader(v1, Data, seq=42, len=128)"
        );

        let frame = PacketFrame::new(PacketType::Data, 42, vec![1, 2, 3]).unwrap();
        assert_eq!(frame.to_string(), "PacketFrame(Data, seq=42, len=3)");
    }

    #[test]
    fn test_anti_replay_filter_default_and_accessors() {
        let mut filter = AntiReplayFilter::default();
        assert_eq!(filter.window_size(), DEFAULT_REPLAY_WINDOW_SIZE);
        assert_eq!(filter.highest_seq(), 0);
        assert_eq!(filter.seen_count(), 0);

        filter.check_and_update(100);
        assert_eq!(filter.highest_seq(), 100);
        assert_eq!(filter.seen_count(), 1);

        filter.reset();
        assert_eq!(filter.highest_seq(), 0);
        assert_eq!(filter.seen_count(), 0);
        // Can re-accept sequences starting fresh
        assert!(filter.check_and_update(100));
    }

    #[test]
    fn test_packet_header_conversions_and_helpers() {
        let header = PacketHeader::new(PacketType::Data, 55, 300).unwrap();
        assert!(header.is_valid_version());
        assert_eq!(header.total_frame_len(), HEADER_SIZE + 300);
        assert_eq!(header.to_bytes(), header.encode());

        let bytes = header.to_bytes();
        let parsed_from_slice: PacketHeader = bytes.as_slice().try_into().expect("TryFrom slice failed");
        assert_eq!(header, parsed_from_slice);

        let parsed_from_array: PacketHeader = bytes.try_into().expect("TryFrom array failed");
        assert_eq!(header, parsed_from_array);
    }
}




