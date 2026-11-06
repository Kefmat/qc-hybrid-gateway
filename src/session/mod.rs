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

impl From<[u8; SESSION_ID_SIZE]> for SessionId {
    fn from(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8; SESSION_ID_SIZE]> for SessionId {
    fn from(bytes: &[u8; SESSION_ID_SIZE]) -> Self {
        Self::new(*bytes)
    }
}

impl TryFrom<&[u8]> for SessionId {
    type Error = String;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != SESSION_ID_SIZE {
            return Err(format!(
                "Invalid byte slice length for SessionId: expected {}, got {}",
                SESSION_ID_SIZE,
                slice.len()
            ));
        }
        let mut bytes = [0u8; SESSION_ID_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl std::str::FromStr for SessionId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl From<SessionId> for [u8; SESSION_ID_SIZE] {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

impl From<&SessionId> for [u8; SESSION_ID_SIZE] {
    fn from(id: &SessionId) -> Self {
        id.0
    }
}

impl From<SessionId> for Vec<u8> {
    fn from(id: SessionId) -> Self {
        id.0.to_vec()
    }
}

impl From<&SessionId> for Vec<u8> {
    fn from(id: &SessionId) -> Self {
        id.0.to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Client,
    Server,
}

impl SessionRole {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SessionRole::Client => "Client",
            SessionRole::Server => "Server",
        }
    }

    pub const fn is_client(&self) -> bool {
        matches!(self, SessionRole::Client)
    }

    pub const fn is_server(&self) -> bool {
        matches!(self, SessionRole::Server)
    }

    pub const fn peer_role(&self) -> Self {
        match self {
            SessionRole::Client => SessionRole::Server,
            SessionRole::Server => SessionRole::Client,
        }
    }

    pub const fn is_peer_of(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (SessionRole::Client, SessionRole::Server) | (SessionRole::Server, SessionRole::Client)
        )
    }

    /// Returns a slice of all possible `SessionRole` variants.
    pub const fn all() -> &'static [SessionRole] {
        &[SessionRole::Client, SessionRole::Server]
    }
}

impl AsRef<str> for SessionRole {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SessionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SessionRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Client" => Ok(SessionRole::Client),
            "Server" => Ok(SessionRole::Server),
            _ => Err(format!("Unknown session role: '{}'", s)),
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

impl SessionState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SessionState::Uninitialized => "Uninitialized",
            SessionState::Handshaking => "Handshaking",
            SessionState::Established => "Established",
            SessionState::Rekeying => "Rekeying",
            SessionState::Closed => "Closed",
        }
    }

    pub const fn is_uninitialized(&self) -> bool {
        matches!(self, SessionState::Uninitialized)
    }

    pub const fn is_handshaking(&self) -> bool {
        matches!(self, SessionState::Handshaking)
    }

    pub const fn is_established(&self) -> bool {
        matches!(self, SessionState::Established)
    }

    pub const fn is_rekeying(&self) -> bool {
        matches!(self, SessionState::Rekeying)
    }

    pub const fn is_closed(&self) -> bool {
        matches!(self, SessionState::Closed)
    }

    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            SessionState::Handshaking | SessionState::Established | SessionState::Rekeying
        )
    }

    pub const fn is_terminal(&self) -> bool {
        matches!(self, SessionState::Closed)
    }

    pub const fn can_transition_to(&self, target: &SessionState) -> bool {
        match (*self, *target) {
            (SessionState::Uninitialized, SessionState::Handshaking) => true,
            (SessionState::Uninitialized, SessionState::Established) => true,
            (SessionState::Handshaking, SessionState::Established) => true,
            (SessionState::Handshaking, SessionState::Closed) => true,
            (SessionState::Established, SessionState::Rekeying) => true,
            (SessionState::Established, SessionState::Closed) => true,
            (SessionState::Rekeying, SessionState::Established) => true,
            (SessionState::Rekeying, SessionState::Closed) => true,
            (SessionState::Closed, _) => false,
            _ => false,
        }
    }

    /// Returns a slice of all possible `SessionState` variants.
    pub const fn all() -> &'static [SessionState] {
        &[
            SessionState::Uninitialized,
            SessionState::Handshaking,
            SessionState::Established,
            SessionState::Rekeying,
            SessionState::Closed,
        ]
    }
}

impl AsRef<str> for SessionState {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SessionState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Uninitialized" => Ok(SessionState::Uninitialized),
            "Handshaking" => Ok(SessionState::Handshaking),
            "Established" => Ok(SessionState::Established),
            "Rekeying" => Ok(SessionState::Rekeying),
            "Closed" => Ok(SessionState::Closed),
            _ => Err(format!("Unknown session state: '{}'", s)),
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
    pub pings_sent: u64,
    pub pongs_received: u64,
    pub last_rtt_ms: Option<u64>,
}

impl SessionMetrics {
    pub fn total_packets(&self) -> u64 {
        self.tx_packets.saturating_add(self.rx_packets)
    }

    pub fn total_bytes(&self) -> u64 {
        self.tx_bytes.saturating_add(self.rx_bytes)
    }

    pub fn has_dropped_packets(&self) -> bool {
        self.replays_dropped > 0
    }

    pub fn average_packet_size(&self) -> Option<usize> {
        let total_pkts = self.total_packets();
        self.total_bytes()
            .checked_div(total_pkts)
            .map(|avg| avg as usize)
    }

    pub fn has_traffic(&self) -> bool {
        self.total_packets() > 0
    }

    pub fn is_empty(&self) -> bool {
        self.total_packets() == 0
    }

    pub fn combine(&mut self, other: &SessionMetrics) {
        self.tx_packets = self.tx_packets.saturating_add(other.tx_packets);
        self.rx_packets = self.rx_packets.saturating_add(other.rx_packets);
        self.tx_bytes = self.tx_bytes.saturating_add(other.tx_bytes);
        self.rx_bytes = self.rx_bytes.saturating_add(other.rx_bytes);
        self.replays_dropped = self.replays_dropped.saturating_add(other.replays_dropped);
        self.rekeys_completed = self.rekeys_completed.saturating_add(other.rekeys_completed);
        self.pings_sent = self.pings_sent.saturating_add(other.pings_sent);
        self.pongs_received = self.pongs_received.saturating_add(other.pongs_received);
        if other.last_rtt_ms.is_some() {
            self.last_rtt_ms = other.last_rtt_ms;
        }
    }

    pub fn to_json(&self) -> String {
        let rtt_val = match self.last_rtt_ms {
            Some(ms) => ms.to_string(),
            None => "null".to_string(),
        };
        format!(
            r#"{{"tx_packets":{},"rx_packets":{},"tx_bytes":{},"rx_bytes":{},"replays_dropped":{},"rekeys_completed":{},"pings_sent":{},"pongs_received":{},"last_rtt_ms":{},"total_packets":{},"total_bytes":{}}}"#,
            self.tx_packets,
            self.rx_packets,
            self.tx_bytes,
            self.rx_bytes,
            self.replays_dropped,
            self.rekeys_completed,
            self.pings_sent,
            self.pongs_received,
            rtt_val,
            self.total_packets(),
            self.total_bytes(),
        )
    }

    pub fn to_report(&self) -> String {
        let avg_str = match self.average_packet_size() {
            Some(avg) => format!("{} bytes", avg),
            None => "N/A".to_string(),
        };
        let rtt_str = match self.last_rtt_ms {
            Some(rtt) => format!("{} ms", rtt),
            None => "N/A".to_string(),
        };
        format!(
            "Session Telemetry Report:\n  - TX: {} packets ({} bytes)\n  - RX: {} packets ({} bytes)\n  - Replays Dropped: {}\n  - Rekeys Completed: {}\n  - Pings Sent / Pongs Received: {} / {}\n  - Last RTT: {}\n  - Average Packet Size: {}",
            self.tx_packets,
            self.tx_bytes,
            self.rx_packets,
            self.rx_bytes,
            self.replays_dropped,
            self.rekeys_completed,
            self.pings_sent,
            self.pongs_received,
            rtt_str,
            avg_str
        )
    }

    /// Resets all counters and RTT telemetry back to default zero values.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Computes the ratio of dropped replay packets over total inbound attempts (rx_packets + replays_dropped).
    pub fn replay_drop_ratio(&self) -> f64 {
        let total_rx = self.rx_packets.saturating_add(self.replays_dropped);
        if total_rx == 0 {
            0.0
        } else {
            self.replays_dropped as f64 / total_rx as f64
        }
    }

    /// Returns whether an RTT measurement has been recorded.
    pub fn has_active_rtt(&self) -> bool {
        self.last_rtt_ms.is_some()
    }

    /// Returns the most recent round-trip time in milliseconds, if available.
    pub fn rtt_ms(&self) -> Option<u64> {
        self.last_rtt_ms
    }
}

impl std::ops::Add for SessionMetrics {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.combine(&rhs);
        self
    }
}

impl std::ops::Add<&SessionMetrics> for SessionMetrics {
    type Output = Self;

    fn add(mut self, rhs: &SessionMetrics) -> Self::Output {
        self.combine(rhs);
        self
    }
}

impl std::ops::Add<&SessionMetrics> for &SessionMetrics {
    type Output = SessionMetrics;

    fn add(self, rhs: &SessionMetrics) -> Self::Output {
        let mut res = self.clone();
        res.combine(rhs);
        res
    }
}

impl std::ops::AddAssign for SessionMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.combine(&rhs);
    }
}

impl std::ops::AddAssign<&SessionMetrics> for SessionMetrics {
    fn add_assign(&mut self, rhs: &SessionMetrics) {
        self.combine(rhs);
    }
}

impl fmt::Display for SessionMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rtt_str = match self.last_rtt_ms {
            Some(rtt) => format!("{}ms", rtt),
            None => "none".to_string(),
        };
        write!(
            f,
            "SessionMetrics(tx_pkts={}, rx_pkts={}, tx_bytes={}, rx_bytes={}, dropped={}, rekeys={}, pings={}, pongs={}, rtt={})",
            self.tx_packets,
            self.rx_packets,
            self.tx_bytes,
            self.rx_bytes,
            self.replays_dropped,
            self.rekeys_completed,
            self.pings_sent,
            self.pongs_received,
            rtt_str
        )
    }
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

    pub fn peer_role(&self) -> SessionRole {
        self.role.peer_role()
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn is_uninitialized(&self) -> bool {
        self.state == SessionState::Uninitialized
    }

    pub fn is_handshaking(&self) -> bool {
        self.state == SessionState::Handshaking
    }

    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    pub fn is_rekeying(&self) -> bool {
        self.state == SessionState::Rekeying
    }

    pub fn is_closed(&self) -> bool {
        self.state == SessionState::Closed
    }

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn can_transmit(&self) -> bool {
        self.state == SessionState::Established && self.tx_cipher.is_some()
    }

    pub fn can_receive(&self) -> bool {
        self.state == SessionState::Established && self.rx_cipher.is_some()
    }

    pub fn remaining_rekey_quota(&self) -> u64 {
        self.rekey_threshold.saturating_sub(self.tx_seq)
    }

    /// Returns the number of transmissions remaining before reaching the rekey threshold.
    pub fn remaining_tx_until_rekey(&self) -> u64 {
        self.remaining_rekey_quota()
    }

    /// Checks whether the transmission sequence counter has reached or exceeded the rekey threshold.
    pub fn rekey_threshold_reached(&self) -> bool {
        self.tx_seq >= self.rekey_threshold
    }

    pub fn is_rekey_imminent(&self, margin: u64) -> bool {
        self.remaining_rekey_quota() <= margin
    }

    pub fn rekey_progress_ratio(&self) -> f64 {
        if self.rekey_threshold == 0 {
            1.0
        } else {
            (self.tx_seq as f64 / self.rekey_threshold as f64).min(1.0)
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Session({}, role={}, state={}, tx_seq={})",
            self.session_id, self.role, self.state, self.tx_seq
        )
    }

    pub fn tx_seq(&self) -> u64 {
        self.tx_seq
    }

    pub fn rx_filter(&self) -> &AntiReplayFilter {
        &self.rx_filter
    }

    pub fn rx_seen_count(&self) -> usize {
        self.rx_filter.seen_count()
    }

    /// Checks if a received sequence number would be accepted by the anti-replay filter without mutating filter state.
    pub fn would_accept_rx(&self, seq: u64) -> bool {
        self.rx_filter.would_accept(seq)
    }

    /// Checks if a received sequence number is a replay of an already observed packet within the sliding window.
    pub fn is_rx_replay(&self, seq: u64) -> bool {
        self.rx_filter.is_replay(seq)
    }

    /// Returns the minimum sequence number that can still be accepted by the sliding window.
    pub fn min_valid_rx_seq(&self) -> u64 {
        self.rx_filter.min_valid_seq()
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

    pub fn encrypt_packet(
        &mut self,
        packet_type: PacketType,
        plaintext: &[u8],
    ) -> Result<PacketFrame, String> {
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

    /// Encrypts an application data payload and returns an authenticated `PacketFrame` of type `PacketType::Data`.
    pub fn encrypt_data(&mut self, plaintext: &[u8]) -> Result<PacketFrame, String> {
        self.encrypt_packet(PacketType::Data, plaintext)
    }

    /// Decrypts an application data packet frame, validating that the frame is of type `PacketType::Data`.
    pub fn decrypt_data(&mut self, frame: &PacketFrame) -> Result<Vec<u8>, String> {
        if frame.packet_type() != PacketType::Data {
            return Err(format!(
                "Expected Data packet, received: {}",
                frame.packet_type()
            ));
        }
        self.decrypt_packet(frame)
    }

    pub fn create_ping(&mut self, timestamp: u64) -> Result<PacketFrame, String> {
        let frame = self.encrypt_packet(PacketType::Ping, &timestamp.to_be_bytes())?;
        self.metrics.pings_sent += 1;
        Ok(frame)
    }

    pub fn handle_ping(&mut self, frame: &PacketFrame) -> Result<u64, String> {
        if frame.packet_type() != PacketType::Ping {
            return Err(format!(
                "Expected Ping packet, received: {}",
                frame.packet_type()
            ));
        }

        let decrypted = self.decrypt_packet(frame)?;
        if decrypted.len() != 8 {
            return Err(format!(
                "Invalid ping payload size: {} bytes (expected 8)",
                decrypted.len()
            ));
        }

        Ok(u64::from_be_bytes(decrypted[..8].try_into().unwrap()))
    }

    pub fn create_pong(&mut self, timestamp: u64) -> Result<PacketFrame, String> {
        self.encrypt_packet(PacketType::Pong, &timestamp.to_be_bytes())
    }

    pub fn handle_pong(
        &mut self,
        frame: &PacketFrame,
        current_timestamp: u64,
    ) -> Result<u64, String> {
        if frame.packet_type() != PacketType::Pong {
            return Err(format!(
                "Expected Pong packet, received: {}",
                frame.packet_type()
            ));
        }

        let decrypted = self.decrypt_packet(frame)?;
        if decrypted.len() != 8 {
            return Err(format!(
                "Invalid pong payload size: {} bytes (expected 8)",
                decrypted.len()
            ));
        }

        let sent_time = u64::from_be_bytes(decrypted[..8].try_into().unwrap());
        let rtt = current_timestamp.saturating_sub(sent_time);
        self.metrics.pongs_received += 1;
        self.metrics.last_rtt_ms = Some(rtt);

        Ok(rtt)
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

    /// Advances the session keys by one symmetric ratchet step and immediately re-keys
    /// the session ciphers in place, enforcing forward secrecy without asymmetric roundtrips.
    pub fn ratchet_rekey(&mut self, keys: &mut SessionKeys) -> Result<(), String> {
        if !matches!(
            self.state,
            SessionState::Established | SessionState::Rekeying
        ) {
            return Err(format!("Cannot ratchet rekey in state: {}", self.state));
        }

        keys.ratchet();

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

    /// Advances the session keys by one symmetric ratchet step bound with an external salt
    /// and immediately re-keys the session ciphers in place.
    pub fn ratchet_rekey_with_salt(
        &mut self,
        keys: &mut SessionKeys,
        salt: &[u8],
    ) -> Result<(), String> {
        if !matches!(
            self.state,
            SessionState::Established | SessionState::Rekeying
        ) {
            return Err(format!("Cannot ratchet rekey in state: {}", self.state));
        }

        keys.ratchet_with_salt(salt);

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

    pub fn terminate(&mut self) {
        self.close();
    }

    pub fn can_transition_to(&self, target: &SessionState) -> bool {
        self.state.can_transition_to(target)
    }

    pub fn is_rekey_in_progress(&self) -> bool {
        self.state == SessionState::Rekeying
    }

    pub fn telemetry_report(&self) -> String {
        format!(
            "Session ID: {} [{} | {}]\n{}",
            self.session_id,
            self.role,
            self.state,
            self.metrics.to_report()
        )
    }

    pub fn is_peer_role(&self, other_role: SessionRole) -> bool {
        self.role.is_peer_of(&other_role)
    }

    pub fn is_ciphers_initialized(&self) -> bool {
        self.tx_cipher.is_some() && self.rx_cipher.is_some()
    }

    pub fn telemetry_json(&self) -> String {
        format!(
            r#"{{"session_id":"{}","role":"{}","state":"{}","metrics":{}}}"#,
            self.session_id,
            self.role,
            self.state,
            self.metrics.to_json()
        )
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("role", &self.role)
            .field("state", &self.state)
            .field("tx_seq", &self.tx_seq)
            .field("rx_filter", &self.rx_filter)
            .field("has_tx_cipher", &self.tx_cipher.is_some())
            .field("has_rx_cipher", &self.rx_cipher.is_some())
            .field("rekey_threshold", &self.rekey_threshold)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
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
        assert!(client.is_uninitialized());
        assert!(!client.is_handshaking());
        assert!(!client.is_rekeying());
        assert!(!client.is_established());
        assert!(!client.is_closed());
        assert!(!client.can_transmit());
        assert_eq!(client.tx_seq(), 0);

        let server = Session::new_server();
        assert_eq!(server.role(), SessionRole::Server);
        assert_eq!(server.state(), SessionState::Uninitialized);
        assert!(server.is_uninitialized());
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(SessionRole::Client.as_str(), "Client");
        assert_eq!(SessionRole::Server.as_str(), "Server");
        assert_eq!(SessionRole::Client.as_ref(), "Client");
        assert_eq!(SessionRole::Server.as_ref(), "Server");
        assert_eq!(SessionRole::Client.to_string(), "Client");
        assert_eq!(SessionRole::Server.to_string(), "Server");

        assert_eq!(SessionState::Uninitialized.as_str(), "Uninitialized");
        assert_eq!(SessionState::Handshaking.as_str(), "Handshaking");
        assert_eq!(SessionState::Established.as_str(), "Established");
        assert_eq!(SessionState::Rekeying.as_str(), "Rekeying");
        assert_eq!(SessionState::Closed.as_str(), "Closed");
        assert_eq!(SessionState::Established.as_ref(), "Established");

        assert_eq!(SessionState::Uninitialized.to_string(), "Uninitialized");
        assert_eq!(SessionState::Handshaking.to_string(), "Handshaking");
        assert_eq!(SessionState::Established.to_string(), "Established");
        assert_eq!(SessionState::Rekeying.to_string(), "Rekeying");
        assert_eq!(SessionState::Closed.to_string(), "Closed");

        assert!(SessionState::Uninitialized.is_uninitialized());
        assert!(!SessionState::Uninitialized.is_handshaking());
        assert!(SessionState::Handshaking.is_handshaking());
        assert!(!SessionState::Handshaking.is_established());
        assert!(SessionState::Established.is_established());
        assert!(!SessionState::Established.is_rekeying());
        assert!(SessionState::Rekeying.is_rekeying());
        assert!(!SessionState::Rekeying.is_closed());
        assert!(SessionState::Closed.is_closed());
        assert!(!SessionState::Closed.is_uninitialized());

        assert!(!SessionState::Uninitialized.is_active());
        assert!(SessionState::Handshaking.is_active());
        assert!(SessionState::Established.is_active());
        assert!(SessionState::Rekeying.is_active());
        assert!(!SessionState::Closed.is_active());

        assert!(!SessionState::Uninitialized.is_terminal());
        assert!(!SessionState::Established.is_terminal());
        assert!(SessionState::Closed.is_terminal());

        assert!(SessionState::Uninitialized.can_transition_to(&SessionState::Handshaking));
        assert!(SessionState::Handshaking.can_transition_to(&SessionState::Established));
        assert!(SessionState::Established.can_transition_to(&SessionState::Rekeying));
        assert!(SessionState::Rekeying.can_transition_to(&SessionState::Established));
        assert!(SessionState::Established.can_transition_to(&SessionState::Closed));
        assert!(!SessionState::Closed.can_transition_to(&SessionState::Established));

        let mut session = Session::new_client();
        assert!(session.can_transition_to(&SessionState::Handshaking));
        assert!(!session.is_rekey_in_progress());
        session.terminate();
        assert!(session.is_closed());

        // FromStr parsing
        assert_eq!(
            "Client".parse::<SessionRole>().unwrap(),
            SessionRole::Client
        );
        assert_eq!(
            "Server".parse::<SessionRole>().unwrap(),
            SessionRole::Server
        );
        assert!("InvalidRole".parse::<SessionRole>().is_err());

        assert_eq!(
            "Uninitialized".parse::<SessionState>().unwrap(),
            SessionState::Uninitialized
        );
        assert_eq!(
            "Handshaking".parse::<SessionState>().unwrap(),
            SessionState::Handshaking
        );
        assert_eq!(
            "Established".parse::<SessionState>().unwrap(),
            SessionState::Established
        );
        assert_eq!(
            "Rekeying".parse::<SessionState>().unwrap(),
            SessionState::Rekeying
        );
        assert_eq!(
            "Closed".parse::<SessionState>().unwrap(),
            SessionState::Closed
        );
        assert!("InvalidState".parse::<SessionState>().is_err());
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
        assert!(client.can_transmit());
        assert!(server.can_transmit());
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
        assert!(server.metrics().has_dropped_packets());

        // Test aggregate query helpers
        assert_eq!(client.metrics().total_packets(), 1);
        assert_eq!(client.metrics().total_bytes(), payload.len() as u64);
        assert!(!client.metrics().has_dropped_packets());

        // Test rekey metric increment
        client.trigger_rekey().unwrap();
        let new_keys = SessionKeys::new([3u8; 32], [4u8; 32]);
        client.complete_rekey(&new_keys).unwrap();
        assert_eq!(client.metrics().rekeys_completed, 1);

        client.reset_metrics();
        assert_eq!(client.metrics().tx_packets, 0);
        assert_eq!(client.metrics().tx_bytes, 0);
        assert_eq!(client.metrics().total_packets(), 0);
        assert_eq!(client.metrics().total_bytes(), 0);
        assert!(!client.metrics().has_dropped_packets());
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
        assert!(ping_frame.is_heartbeat());
        assert_eq!(client.metrics().pings_sent, 1);

        let received_timestamp = server.handle_ping(&ping_frame).unwrap();
        assert_eq!(received_timestamp, timestamp);

        // Server responds with Pong
        let pong_frame = server.create_pong(received_timestamp).unwrap();
        assert!(pong_frame.is_pong());
        assert!(pong_frame.is_heartbeat());

        // Client processes Pong and calculates RTT
        let current_time = timestamp + 12; // 12ms later
        let rtt = client.handle_pong(&pong_frame, current_time).unwrap();
        assert_eq!(rtt, 12);
        assert_eq!(client.metrics().pongs_received, 1);
        assert_eq!(client.metrics().last_rtt_ms, Some(12));
    }

    #[test]
    fn test_session_pong_validation_errors() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();
        let keys = SessionKeys::new([10u8; 32], [20u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        let data_frame = client
            .encrypt_packet(PacketType::Data, b"not-a-pong")
            .unwrap();
        assert!(server.handle_pong(&data_frame, 100).is_err());

        let bad_pong_frame = client.encrypt_packet(PacketType::Pong, b"short").unwrap();
        assert!(server.handle_pong(&bad_pong_frame, 100).is_err());
    }

    #[test]
    fn test_session_ping_validation_errors() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();
        let keys = SessionKeys::new([10u8; 32], [20u8; 32]);
        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        // Data frame passed to handle_ping fails
        let data_frame = client
            .encrypt_packet(PacketType::Data, b"not-a-ping")
            .unwrap();
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

        // From / TryFrom checks
        let from_arr: SessionId = [0xcd; SESSION_ID_SIZE].into();
        assert_eq!(from_arr.as_bytes(), &[0xcd; SESSION_ID_SIZE]);
        let from_arr_ref: SessionId = (&[0xef; SESSION_ID_SIZE]).into();
        assert_eq!(from_arr_ref.as_bytes(), &[0xef; SESSION_ID_SIZE]);

        let try_from_valid: SessionId = (&[0x12; SESSION_ID_SIZE][..]).try_into().unwrap();
        assert_eq!(try_from_valid.as_bytes(), &[0x12; SESSION_ID_SIZE]);
        let try_from_invalid: Result<SessionId, _> = (&[0x12; 8][..]).try_into();
        assert!(try_from_invalid.is_err());

        // FromStr parsing
        let from_str: SessionId = hex.parse().unwrap();
        assert_eq!(sid, from_str);
        assert!("invalid-hex".parse::<SessionId>().is_err());

        // Into array / Vec conversions
        let id_arr: [u8; SESSION_ID_SIZE] = sid.into();
        assert_eq!(id_arr, *sid.as_bytes());
        let id_arr_ref: [u8; SESSION_ID_SIZE] = (&sid).into();
        assert_eq!(id_arr_ref, *sid.as_bytes());
        let id_vec: Vec<u8> = sid.into();
        assert_eq!(id_vec, sid.as_bytes().to_vec());
        let id_vec_ref: Vec<u8> = (&sid).into();
        assert_eq!(id_vec_ref, sid.as_bytes().to_vec());
    }

    #[test]
    fn test_session_rx_filter_accessors() {
        let mut server = Session::new_server();
        let mut client = Session::new_client();
        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        server.establish(&keys).unwrap();
        client.establish(&keys).unwrap();

        assert_eq!(server.rx_seen_count(), 0);
        assert_eq!(server.rx_filter().window_size(), DEFAULT_REPLAY_WINDOW_SIZE);

        let frame = client
            .encrypt_packet(PacketType::Data, b"test-payload")
            .unwrap();
        server.decrypt_packet(&frame).unwrap();

        assert_eq!(server.rx_seen_count(), 1);
        assert_eq!(server.rx_filter().highest_seq(), 1);
    }

    #[test]
    fn test_session_role_methods() {
        let client = SessionRole::Client;
        let server = SessionRole::Server;

        assert!(client.is_client());
        assert!(!client.is_server());
        assert_eq!(client.peer_role(), SessionRole::Server);

        assert!(server.is_server());
        assert!(!server.is_client());
        assert_eq!(server.peer_role(), SessionRole::Client);
    }

    #[test]
    fn test_session_metrics_display() {
        let metrics = SessionMetrics {
            tx_packets: 10,
            rx_packets: 20,
            tx_bytes: 1000,
            rx_bytes: 2000,
            replays_dropped: 2,
            rekeys_completed: 1,
            pings_sent: 3,
            pongs_received: 3,
            last_rtt_ms: Some(15),
        };
        let s = metrics.to_string();
        assert_eq!(
            s,
            "SessionMetrics(tx_pkts=10, rx_pkts=20, tx_bytes=1000, rx_bytes=2000, dropped=2, rekeys=1, pings=3, pongs=3, rtt=15ms)"
        );
        assert_eq!(metrics.average_packet_size(), Some(100)); // (1000 + 2000) / (10 + 20) = 100

        let empty_metrics = SessionMetrics::default();
        assert_eq!(empty_metrics.average_packet_size(), None);
        assert_eq!(
            empty_metrics.to_string(),
            "SessionMetrics(tx_pkts=0, rx_pkts=0, tx_bytes=0, rx_bytes=0, dropped=0, rekeys=0, pings=0, pongs=0, rtt=none)"
        );

        let json = metrics.to_json();
        assert!(json.contains("\"tx_packets\":10"));
        assert!(json.contains("\"rx_packets\":20"));
        assert!(json.contains("\"rekeys_completed\":1"));
        assert!(json.contains("\"pings_sent\":3"));
        assert!(json.contains("\"pongs_received\":3"));
        assert!(json.contains("\"last_rtt_ms\":15"));

        let report = metrics.to_report();
        assert!(report.contains("Session Telemetry Report"));
        assert!(report.contains("TX: 10 packets"));
        assert!(report.contains("Pings Sent / Pongs Received: 3 / 3"));
        assert!(report.contains("Last RTT: 15 ms"));
        assert!(report.contains("Average Packet Size: 100 bytes"));

        let mut session = Session::new_client();
        session.metrics = metrics;
        let s_report = session.telemetry_report();
        assert!(s_report.contains("Client"));
        let s_json = session.telemetry_json();
        assert!(s_json.contains("\"role\":\"Client\""));
        assert!(s_json.contains("\"metrics\":"));
    }

    #[test]
    fn test_session_can_receive_and_quota() {
        let mut client = Session::new_client();
        assert!(!client.can_receive());
        assert!(!client.can_transmit());

        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        client.establish(&keys).unwrap();
        assert!(client.can_receive());
        assert!(client.can_transmit());

        client.set_rekey_threshold(100);
        assert_eq!(client.remaining_rekey_quota(), 100);

        client.encrypt_packet(PacketType::Data, b"data1").unwrap();
        assert_eq!(client.remaining_rekey_quota(), 99);

        client.close();
        assert!(!client.can_receive());
        assert!(!client.can_transmit());
    }

    #[test]
    fn test_session_delegation_helpers() {
        let mut client = Session::new_client();
        assert_eq!(client.peer_role(), SessionRole::Server);
        assert!(!client.is_active());
        assert!(!client.is_terminal());

        let server = Session::new_server();
        assert_eq!(server.peer_role(), SessionRole::Client);

        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        client.establish(&keys).unwrap();
        assert!(client.is_active());
        assert!(!client.is_terminal());

        client.trigger_rekey().unwrap();
        assert!(client.is_active());
        assert!(!client.is_terminal());

        client.close();
        assert!(!client.is_active());
        assert!(client.is_terminal());
    }

    #[test]
    fn test_session_metrics_is_empty() {
        let mut metrics = SessionMetrics::default();
        assert!(metrics.is_empty());
        assert!(!metrics.has_traffic());

        metrics.tx_packets = 1;
        assert!(!metrics.is_empty());
        assert!(metrics.has_traffic());
    }

    #[test]
    fn test_session_metrics_combine_and_ops() {
        let m1 = SessionMetrics {
            tx_packets: 10,
            rx_packets: 5,
            tx_bytes: 500,
            rx_bytes: 250,
            replays_dropped: 1,
            rekeys_completed: 1,
            pings_sent: 2,
            pongs_received: 1,
            last_rtt_ms: Some(10),
        };
        let m2 = SessionMetrics {
            tx_packets: 20,
            rx_packets: 15,
            tx_bytes: 1000,
            rx_bytes: 750,
            replays_dropped: 2,
            rekeys_completed: 1,
            pings_sent: 1,
            pongs_received: 2,
            last_rtt_ms: Some(25),
        };

        let mut combined = m1.clone();
        combined.combine(&m2);
        assert_eq!(combined.tx_packets, 30);
        assert_eq!(combined.rx_packets, 20);
        assert_eq!(combined.tx_bytes, 1500);
        assert_eq!(combined.rx_bytes, 1000);
        assert_eq!(combined.replays_dropped, 3);
        assert_eq!(combined.rekeys_completed, 2);
        assert_eq!(combined.pings_sent, 3);
        assert_eq!(combined.pongs_received, 3);
        assert_eq!(combined.last_rtt_ms, Some(25));

        // Test std::ops::Add
        let added = m1.clone() + m2.clone();
        assert_eq!(added, combined);

        let added_ref = &m1 + &m2;
        assert_eq!(added_ref, combined);

        let added_mixed = m1.clone() + &m2;
        assert_eq!(added_mixed, combined);

        // Test std::ops::AddAssign
        let mut assign_test = m1.clone();
        assign_test += m2.clone();
        assert_eq!(assign_test, combined);

        let mut assign_ref_test = m1;
        assign_ref_test += &m2;
        assert_eq!(assign_ref_test, combined);
    }

    #[test]
    fn test_session_rekey_imminent_and_summary() {
        let mut client = Session::new_client();
        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        client.establish(&keys).unwrap();

        client.set_rekey_threshold(10);
        assert_eq!(client.remaining_rekey_quota(), 10);
        assert_eq!(client.rekey_progress_ratio(), 0.0);
        assert!(!client.is_rekey_imminent(2));

        for _ in 0..8 {
            client.encrypt_packet(PacketType::Data, b"pkt").unwrap();
        }

        assert_eq!(client.tx_seq(), 8);
        assert_eq!(client.remaining_rekey_quota(), 2);
        assert_eq!(client.rekey_progress_ratio(), 0.8);
        assert!(client.is_rekey_imminent(2));
        assert!(client.is_rekey_imminent(5));

        let summary = client.summary();
        assert!(summary.contains("Session("));
        assert!(summary.contains("role=Client"));
        assert!(summary.contains("state=Established"));
        assert!(summary.contains("tx_seq=8"));
    }

    #[test]
    fn test_session_ratchet_rekey_lifecycle_and_forward_secrecy() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let mut client_keys = SessionKeys::new([0x33u8; 32], [0x44u8; 32]);
        let mut server_keys = SessionKeys::new([0x33u8; 32], [0x44u8; 32]);

        client.establish(&client_keys).unwrap();
        server.establish(&server_keys).unwrap();

        // Send packet under generation 0
        let frame0 = client
            .encrypt_packet(PacketType::Data, b"pre-ratchet-secret")
            .unwrap();
        let decrypted0 = server.decrypt_packet(&frame0).unwrap();
        assert_eq!(decrypted0, b"pre-ratchet-secret");

        // Ratchet both sessions
        assert!(client.ratchet_rekey(&mut client_keys).is_ok());
        assert!(server.ratchet_rekey(&mut server_keys).is_ok());

        assert_eq!(client.state(), SessionState::Established);
        assert_eq!(server.state(), SessionState::Established);
        assert_eq!(client.tx_seq(), 0);
        assert_eq!(client.metrics().rekeys_completed, 1);
        assert_eq!(server.metrics().rekeys_completed, 1);

        // Send packet under generation 1
        let frame1 = client
            .encrypt_packet(PacketType::Data, b"post-ratchet-secret")
            .unwrap();
        let decrypted1 = server.decrypt_packet(&frame1).unwrap();
        assert_eq!(decrypted1, b"post-ratchet-secret");

        // Forward secrecy check: old ciphertext frame0 cannot be decrypted by server after ratchet
        assert!(server.decrypt_packet(&frame0).is_err());
    }

    #[test]
    fn test_session_ratchet_rekey_with_salt() {
        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let mut client_keys = SessionKeys::new([0x55u8; 32], [0x66u8; 32]);
        let mut server_keys = SessionKeys::new([0x55u8; 32], [0x66u8; 32]);

        client.establish(&client_keys).unwrap();
        server.establish(&server_keys).unwrap();

        let salt = b"custom-session-salt-v1";
        client
            .ratchet_rekey_with_salt(&mut client_keys, salt)
            .unwrap();
        server
            .ratchet_rekey_with_salt(&mut server_keys, salt)
            .unwrap();

        let frame = client
            .encrypt_packet(PacketType::Data, b"salted-ratchet-message")
            .unwrap();
        let decrypted = server.decrypt_packet(&frame).unwrap();
        assert_eq!(decrypted, b"salted-ratchet-message");
    }

    #[test]
    fn test_session_ratchet_rekey_invalid_state() {
        let mut uninit_session = Session::new_client();
        let mut keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        assert!(uninit_session.ratchet_rekey(&mut keys).is_err());

        let mut closed_session = Session::new_client();
        closed_session.establish(&keys).unwrap();
        closed_session.close();
        assert!(closed_session.ratchet_rekey(&mut keys).is_err());
        assert!(closed_session
            .ratchet_rekey_with_salt(&mut keys, b"salt")
            .is_err());
    }

    #[test]
    fn test_session_role_peer_relations() {
        assert!(SessionRole::Client.is_peer_of(&SessionRole::Server));
        assert!(SessionRole::Server.is_peer_of(&SessionRole::Client));
        assert!(!SessionRole::Client.is_peer_of(&SessionRole::Client));
        assert!(!SessionRole::Server.is_peer_of(&SessionRole::Server));

        let client = Session::new_client();
        assert!(client.is_peer_role(SessionRole::Server));
        assert!(!client.is_peer_role(SessionRole::Client));
    }

    #[test]
    fn test_session_debug_display_and_ciphers() {
        let mut client = Session::new_client();
        assert!(!client.is_ciphers_initialized());

        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("Session"));
        assert!(debug_str.contains("role: Client"));
        assert!(debug_str.contains("has_tx_cipher: false"));

        let display_str = format!("{}", client);
        assert_eq!(display_str, client.summary());

        let keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        client.establish(&keys).unwrap();
        assert!(client.is_ciphers_initialized());

        let debug_established = format!("{:?}", client);
        assert!(debug_established.contains("has_tx_cipher: true"));
        assert!(debug_established.contains("has_rx_cipher: true"));
    }

    #[test]
    fn test_session_data_helpers_and_replay_delegation() {
        let keys = SessionKeys::new([0x33u8; 32], [0x44u8; 32]);
        let mut client = Session::new_client();
        let mut server = Session::new_server();

        client.establish(&keys).unwrap();
        server.establish(&keys).unwrap();

        // Anti-replay delegation queries before traffic
        assert!(server.would_accept_rx(1));
        assert!(!server.is_rx_replay(1));
        assert_eq!(server.min_valid_rx_seq(), 0);

        // Encrypt and decrypt data
        let payload = b"streamlined application message";
        let frame = client.encrypt_data(payload).expect("encrypt_data failed");
        assert_eq!(frame.packet_type(), PacketType::Data);
        assert_eq!(frame.seq(), 1);

        assert!(server.would_accept_rx(1));
        let decrypted = server.decrypt_data(&frame).expect("decrypt_data failed");
        assert_eq!(decrypted, payload);

        // After processing, seq 1 should be recognized as replay and not accepted
        assert!(!server.would_accept_rx(1));
        assert!(server.is_rx_replay(1));

        // Replaying same frame must fail
        assert!(server.decrypt_data(&frame).is_err());

        // Decrypt data rejects non-data frames
        let ping_frame = client.create_ping(123456).expect("create_ping failed");
        let err = server.decrypt_data(&ping_frame);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Expected Data packet"));
    }

    #[test]
    fn test_session_variants_metrics_and_rekey_checks() {
        assert_eq!(
            SessionRole::all(),
            &[SessionRole::Client, SessionRole::Server]
        );
        assert_eq!(
            SessionState::all(),
            &[
                SessionState::Uninitialized,
                SessionState::Handshaking,
                SessionState::Established,
                SessionState::Rekeying,
                SessionState::Closed,
            ]
        );

        let mut metrics = SessionMetrics {
            tx_packets: 10,
            rx_packets: 8,
            tx_bytes: 100,
            rx_bytes: 80,
            replays_dropped: 2,
            rekeys_completed: 1,
            pings_sent: 1,
            pongs_received: 1,
            last_rtt_ms: Some(15),
        };

        assert!(metrics.has_active_rtt());
        assert_eq!(metrics.rtt_ms(), Some(15));
        // total_rx = 8 + 2 = 10, replays_dropped = 2 => ratio = 0.2
        assert!((metrics.replay_drop_ratio() - 0.2).abs() < 1e-6);

        metrics.reset();
        assert_eq!(metrics.total_packets(), 0);
        assert!(!metrics.has_active_rtt());
        assert_eq!(metrics.replay_drop_ratio(), 0.0);

        let mut session = Session::new_client();
        session.set_rekey_threshold(5);
        assert_eq!(session.remaining_tx_until_rekey(), 5);
        assert!(!session.rekey_threshold_reached());

        session.tx_seq = 5;
        assert_eq!(session.remaining_tx_until_rekey(), 0);
        assert!(session.rekey_threshold_reached());
    }
}
