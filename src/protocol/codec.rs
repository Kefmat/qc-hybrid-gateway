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

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    pub fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
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

    pub fn decode_all(&mut self) -> Result<Vec<PacketFrame>, String> {
        let mut frames = Vec::new();
        while let Some(frame) = self.decode_frame()? {
            frames.push(frame);
        }
        Ok(frames)
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

    #[test]
    fn test_codec_capacity_and_max_frame_size() {
        let mut decoder = FrameDecoder::with_max_frame_size(2048);
        assert_eq!(decoder.max_frame_size(), 2048);
        assert!(decoder.capacity() >= 2048);
        decoder.reserve(512);
        assert!(decoder.capacity() >= 2048);
    }

    #[test]
    fn test_codec_buffer_accessor() {
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.buffer(), &[] as &[u8]);
        decoder.feed(b"raw-data-in-buffer");
        assert_eq!(decoder.buffer(), b"raw-data-in-buffer");
    }

    #[test]
    fn test_codec_decode_all() {
        let mut decoder = FrameDecoder::new();
        let frame1 = PacketFrame::new(PacketType::Data, 10, b"frame-1".to_vec()).unwrap();
        let frame2 = PacketFrame::new(PacketType::Data, 11, b"frame-2".to_vec()).unwrap();
        let frame3 = PacketFrame::new(PacketType::Ping, 12, b"frame-3".to_vec()).unwrap();

        let mut data = frame1.encode();
        data.extend_from_slice(&frame2.encode());
        data.extend_from_slice(&frame3.encode());

        decoder.feed(&data);
        let frames = decoder.decode_all().expect("decode_all failed");
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], frame1);
        assert_eq!(frames[1], frame2);
        assert_eq!(frames[2], frame3);
        assert!(decoder.is_empty());
    }
}
