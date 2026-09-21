use std::collections::HashSet;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_SIZE: usize = 65536;

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
