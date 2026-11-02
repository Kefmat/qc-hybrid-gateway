use std::fmt;
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

    /// Feeds an already encoded `PacketFrame` directly into the decoder buffer.
    pub fn feed_frame(&mut self, frame: &PacketFrame) {
        self.feed(&frame.encode());
    }

    /// Feeds multiple packet frames sequentially into the decoder buffer.
    pub fn feed_all(&mut self, frames: &[PacketFrame]) {
        for frame in frames {
            self.feed_frame(frame);
        }
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

    /// Clears the buffer and resets its capacity to `max_frame_size`.
    pub fn reset(&mut self) {
        self.buffer = BytesMut::with_capacity(self.max_frame_size);
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn next_frame_length(&self) -> Option<usize> {
        if self.buffer.len() < HEADER_SIZE {
            return None;
        }
        let header = PacketHeader::decode(&self.buffer[..HEADER_SIZE]).ok()?;
        Some(HEADER_SIZE + header.payload_len as usize)
    }

    /// Returns the number of additional bytes needed to complete decoding the pending frame,
    /// or `None` if not even the header (`HEADER_SIZE` bytes) has been received yet.
    pub fn remaining_bytes_needed(&self) -> Option<usize> {
        self.next_frame_length()
            .map(|len| len.saturating_sub(self.buffer.len()))
    }

    /// Peeks at the packet header of the next frame in the buffer without consuming bytes.
    /// Returns `None` if fewer than `HEADER_SIZE` bytes are buffered or if the header fails validation.
    pub fn peek_header(&self) -> Option<PacketHeader> {
        if self.buffer.len() < HEADER_SIZE {
            return None;
        }
        PacketHeader::decode(&self.buffer[..HEADER_SIZE]).ok()
    }

    /// Peeks at the packet type of the next frame in the buffer without consuming bytes.
    /// Returns `None` if the header is not yet available or invalid.
    pub fn peek_packet_type(&self) -> Option<crate::protocol::PacketType> {
        self.peek_header().map(|h| h.packet_type)
    }

    pub fn has_pending_frame(&self) -> bool {
        match self.next_frame_length() {
            Some(len) => self.buffer.len() >= len,
            None => false,
        }
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

        if self.buffer.is_empty() {
            self.reclaim_unused_capacity();
        }

        Ok(Some(PacketFrame { header, payload }))
    }

    /// Reclaims buffer capacity and resets position when all bytes have been drained.
    pub fn reclaim_unused_capacity(&mut self) {
        if self.buffer.is_empty() {
            self.buffer.clear();
        }
    }

    /// Compacts oversized internal buffer allocations if empty to prevent memory leakage.
    pub fn compact(&mut self) {
        if self.buffer.is_empty() && self.buffer.capacity() > self.max_frame_size * 2 {
            self.buffer = BytesMut::with_capacity(self.max_frame_size);
        }
    }

    /// Checks whether the internal buffer has reached or exceeded max frame size.
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.max_frame_size
    }

    /// Returns the number of bytes that can be appended before reaching `max_frame_size`.
    pub fn available_capacity(&self) -> usize {
        self.max_frame_size.saturating_sub(self.buffer.len())
    }

    pub fn decode_all(&mut self) -> Result<Vec<PacketFrame>, String> {
        let mut frames = Vec::new();
        while let Some(frame) = self.decode_frame()? {
            frames.push(frame);
        }
        self.reclaim_unused_capacity();
        Ok(frames)
    }

    /// Returns a short diagnostic summary of the decoder buffer state.
    pub fn summary(&self) -> String {
        format!(
            "FrameDecoder(len={}, cap={}, max={})",
            self.buffer_len(),
            self.capacity(),
            self.max_frame_size
        )
    }

    /// Returns a streaming iterator that yields frames as they become available.
    pub fn iter_frames(&mut self) -> FrameIter<'_> {
        FrameIter { decoder: self }
    }
}

impl fmt::Display for FrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Streaming iterator that drains and yields decoded frames from a `FrameDecoder`.
pub struct FrameIter<'a> {
    decoder: &'a mut FrameDecoder,
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = Result<PacketFrame, String>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.decoder.decode_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl AsRef<[u8]> for FrameDecoder {
    fn as_ref(&self) -> &[u8] {
        self.buffer()
    }
}

impl std::io::Write for FrameDecoder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.feed(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> Extend<&'a [u8]> for FrameDecoder {
    fn extend<T: IntoIterator<Item = &'a [u8]>>(&mut self, iter: T) {
        for chunk in iter {
            self.feed(chunk);
        }
    }
}

impl Extend<u8> for FrameDecoder {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.buffer.extend(iter);
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

    #[test]
    fn test_codec_pending_and_next_frame_length() {
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.next_frame_length(), None);
        assert!(!decoder.has_pending_frame());

        let frame = PacketFrame::new(PacketType::Data, 7, b"payload123".to_vec()).unwrap();
        let encoded = frame.encode();

        // Feed only header
        decoder.feed(&encoded[..HEADER_SIZE]);
        assert_eq!(decoder.next_frame_length(), Some(encoded.len()));
        assert!(!decoder.has_pending_frame());

        // Feed the rest
        decoder.feed(&encoded[HEADER_SIZE..]);
        assert_eq!(decoder.next_frame_length(), Some(encoded.len()));
        assert!(decoder.has_pending_frame());

        let decoded = decoder.decode_frame().unwrap().unwrap();
        assert_eq!(frame, decoded);
        assert_eq!(decoder.next_frame_length(), None);
        assert!(!decoder.has_pending_frame());
    }

    #[test]
    fn test_codec_peek_header_and_type() {
        let mut decoder = FrameDecoder::new();
        assert!(decoder.peek_header().is_none());
        assert!(decoder.peek_packet_type().is_none());

        let frame = PacketFrame::new(PacketType::Ping, 101, b"pingdata".to_vec()).unwrap();
        decoder.feed_frame(&frame);

        let header = decoder.peek_header().expect("peek_header should return header");
        assert_eq!(header.packet_type, PacketType::Ping);
        assert_eq!(header.seq, 101);
        assert_eq!(header.payload_len, 8);
        assert_eq!(decoder.peek_packet_type(), Some(PacketType::Ping));

        // Ensure peeking didn't consume any data
        assert_eq!(decoder.buffer_len(), frame.total_len());
        let decoded = decoder.decode_frame().unwrap().expect("should still decode");
        assert_eq!(decoded, frame);
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_codec_feed_frame_and_reset() {
        let mut decoder = FrameDecoder::new();
        decoder.reserve(1000);
        assert!(decoder.capacity() >= 1000);

        let frame = PacketFrame::new(PacketType::Data, 1, b"test".to_vec()).unwrap();
        let encoded = frame.encode();

        assert_eq!(decoder.remaining_bytes_needed(), None);

        // Feed only header
        decoder.feed(&encoded[..HEADER_SIZE]);
        assert_eq!(decoder.remaining_bytes_needed(), Some(4));

        // Feed remaining payload
        decoder.feed(&encoded[HEADER_SIZE..]);
        assert_eq!(decoder.remaining_bytes_needed(), Some(0));

        let decoded = decoder.decode_frame().unwrap().unwrap();
        assert_eq!(decoded, frame);

        decoder.feed(b"leftover-bytes");
        assert!(!decoder.is_empty());
        decoder.reset();
        assert!(decoder.is_empty());
        assert_eq!(decoder.buffer_len(), 0);
    }

    #[test]
    fn test_codec_buffer_compaction_and_reclaim() {
        let mut decoder = FrameDecoder::with_max_frame_size(512);
        let frame = PacketFrame::new(PacketType::Data, 7, b"buffer-opt".to_vec()).unwrap();
        decoder.feed_frame(&frame);
        assert!(!decoder.is_empty());

        let decoded = decoder.decode_frame().unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert!(decoder.is_empty());

        decoder.reserve(2000);
        assert!(decoder.capacity() >= 2000);
        decoder.compact();
        assert_eq!(decoder.capacity(), 512);
    }

    #[test]
    fn test_codec_io_write_extend_and_traits() {
        use std::io::Write;

        let mut decoder = FrameDecoder::with_max_frame_size(100);
        assert!(!decoder.is_full());
        assert_eq!(decoder.available_capacity(), 100);

        // Test std::io::Write
        let written = decoder.write(b"streaming-").unwrap();
        assert_eq!(written, 10);
        assert_eq!(decoder.buffer_len(), 10);
        assert_eq!(decoder.available_capacity(), 90);
        decoder.flush().unwrap();

        // Test AsRef<[u8]>
        assert_eq!(decoder.as_ref(), b"streaming-");

        // Test Extend<&[u8]>
        decoder.extend(vec![&b"chunk1"[..], &b"-chunk2"[..]]);
        assert_eq!(decoder.as_ref(), b"streaming-chunk1-chunk2");

        // Test Extend<u8>
        decoder.extend(vec![b'!', b'!']);
        assert_eq!(decoder.as_ref(), b"streaming-chunk1-chunk2!!");

        // Test is_full and available_capacity saturation
        decoder.feed(&vec![0u8; 100]);
        assert!(decoder.is_full());
        assert_eq!(decoder.available_capacity(), 0);
    }

    #[test]
    fn test_codec_iterator_display_and_feed_all() {
        let mut decoder = FrameDecoder::with_max_frame_size(1024);
        let summary_str = decoder.summary();
        assert!(summary_str.contains("FrameDecoder(len=0, cap="));
        assert!(summary_str.contains("max=1024)"));
        assert_eq!(format!("{}", decoder), summary_str);

        let frames = vec![
            PacketFrame::data(1, b"first-frame".to_vec()).unwrap(),
            PacketFrame::ping(2, 42).unwrap(),
            PacketFrame::data(3, b"third-frame".to_vec()).unwrap(),
        ];

        decoder.feed_all(&frames);
        assert!(!decoder.is_empty());

        let decoded: Result<Vec<PacketFrame>, String> = decoder.iter_frames().collect();
        let decoded_frames = decoded.expect("iter_frames failed");
        assert_eq!(decoded_frames.len(), 3);
        assert_eq!(decoded_frames, frames);
        assert!(decoder.is_empty());
    }
}
