use bytes::{Buf, BytesMut};
use crate::protocol::{PacketFrame, PacketHeader, HEADER_SIZE, MAX_FRAME_SIZE};

#[derive(Debug, Clone)]
pub struct FrameDecoder {
    buffer: BytesMut,
    max_frame_size: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(MAX_FRAME_SIZE),
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(max_frame_size),
            max_frame_size,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn decode_frame(&mut self) -> Result<Option<PacketFrame>, String> {
        if self.buffer.len() < HEADER_SIZE {
            return Ok(None);
        }

        let header = PacketHeader::decode(&self.buffer[..HEADER_SIZE])?;
        let payload_len = header.payload_len as usize;

        if payload_len > self.max_frame_size {
            return Err(format!(
                "Frame payload {} exceeds maximum configured limit {}",
                payload_len, self.max_frame_size
            ));
        }

        let total_frame_len = HEADER_SIZE + payload_len;
        if self.buffer.len() < total_frame_len {
            return Ok(None);
        }

        // Consume the frame
        self.buffer.advance(HEADER_SIZE);
        let payload = self.buffer.split_to(payload_len).to_vec();

        Ok(Some(PacketFrame { header, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PacketType;

    #[test]
    fn test_codec_single_frame_roundtrip() {
        let mut decoder = FrameDecoder::default();
        let frame = PacketFrame::new(PacketType::Data, 42, b"stream-payload".to_vec()).unwrap();
        let wire_bytes = frame.encode();

        decoder.feed(&wire_bytes);
        let decoded = decoder.decode_frame().expect("decoding failed").expect("frame missing");
        assert_eq!(frame, decoded);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_codec_chunked_streaming_input() {
        let mut decoder = FrameDecoder::new();
        let frame = PacketFrame::new(PacketType::Ping, 1, b"heartbeat".to_vec()).unwrap();
        let wire_bytes = frame.encode();

        // Feed byte by byte
        for (i, byte) in wire_bytes.iter().enumerate() {
            decoder.feed(&[*byte]);
            if i + 1 < wire_bytes.len() {
                assert_eq!(decoder.decode_frame().unwrap(), None);
            }
        }

        let decoded = decoder.decode_frame().unwrap().expect("frame should be ready");
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_codec_multiple_frames_in_buffer() {
        let mut decoder = FrameDecoder::new();
        let frame1 = PacketFrame::new(PacketType::Data, 1, b"frame-one".to_vec()).unwrap();
        let frame2 = PacketFrame::new(PacketType::Data, 2, b"frame-two".to_vec()).unwrap();

        let mut combined = frame1.encode();
        combined.extend_from_slice(&frame2.encode());

        decoder.feed(&combined);
        assert_eq!(decoder.buffer_len(), combined.len());

        let dec1 = decoder.decode_frame().unwrap().expect("frame 1 missing");
        assert_eq!(frame1, dec1);

        let dec2 = decoder.decode_frame().unwrap().expect("frame 2 missing");
        assert_eq!(frame2, dec2);

        assert!(decoder.decode_frame().unwrap().is_none());
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_codec_oversized_frame_rejected() {
        let mut decoder = FrameDecoder::with_max_frame_size(10);
        let frame = PacketFrame::new(PacketType::Data, 1, vec![0u8; 100]).unwrap();
        decoder.feed(&frame.encode());

        assert!(decoder.decode_frame().is_err());
    }

    #[test]
    fn test_codec_clear() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(b"some-incomplete-bytes");
        assert!(!decoder.is_empty());
        decoder.clear();
        assert!(decoder.is_empty());
        assert_eq!(decoder.buffer_len(), 0);
    }
}
