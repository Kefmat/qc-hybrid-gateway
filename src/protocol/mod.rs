use std::collections::HashSet;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl PacketFrame {
    pub fn new(packet_type: PacketType, seq: u64, payload: Vec<u8>) -> Result<Self, String> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(format!("Payload exceeds maximum frame size: {}", MAX_FRAME_SIZE));
        }

        Ok(Self {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type,
                seq,
                payload_len: payload.len() as u32,
            },
            payload,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.push(self.header.version);
        buf.push(self.header.packet_type as u8);
        buf.extend_from_slice(&self.header.seq.to_be_bytes());
        buf.extend_from_slice(&self.header.payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_SIZE {
            return Err("Packet too short for header".to_string());
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(format!("Unsupported protocol version: {}", version));
        }

        let packet_type = PacketType::try_from(bytes[1])?;
        let seq = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize;

        if bytes.len() < HEADER_SIZE + payload_len {
            return Err("Packet payload truncated".to_string());
        }

        let payload = bytes[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();

        Ok(Self {
            header: PacketHeader {
                version,
                packet_type,
                seq,
                payload_len: payload_len as u32,
            },
            payload,
        })
    }
}

pub struct AntiReplayFilter {
    window_size: u64,
    highest_seq: u64,
    seen: HashSet<u64>,
}

impl AntiReplayFilter {
    pub fn new(window_size: u64) -> Self {
        Self {
            window_size,
            highest_seq: 0,
            seen: HashSet::new(),
        }
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
}

