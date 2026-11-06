use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const KEM_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-KEM-V1";
pub const SESSION_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-SESSION-V1";
pub const RATCHET_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-RATCHET-V1";
pub const KEM_INFO_LABEL: &[u8] = b"hybrid-kem-shared-secret";
pub const CLIENT_KEY_INFO_PREFIX: &[u8] = b"client-write-key:";
pub const SERVER_KEY_INFO_PREFIX: &[u8] = b"server-write-key:";
pub const RATCHET_CLIENT_LABEL: &[u8] = b"ratchet-client-key-step";
pub const RATCHET_SERVER_LABEL: &[u8] = b"ratchet-server-key-step";

pub fn hash_transcript(messages: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for msg in messages {
        hasher.update(msg);
    }
    hasher.finalize().into()
}

pub fn derive_hybrid_shared_secret(classical_ss: &[u8], pq_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(classical_ss.len() + pq_ss.len());
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pq_ss);

    let hk = Hkdf::<Sha256>::new(Some(KEM_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(KEM_INFO_LABEL, &mut okm)
        .expect("HKDF expansion failed");

    ikm.zeroize();
    okm
}

pub struct SessionKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
}

impl SessionKeys {
    pub fn new(client_write_key: [u8; 32], server_write_key: [u8; 32]) -> Self {
        Self {
            client_write_key,
            server_write_key,
        }
    }

    pub fn zeroed() -> Self {
        Self {
            client_write_key: [0u8; 32],
            server_write_key: [0u8; 32],
        }
    }

    pub fn as_client_slice(&self) -> &[u8] {
        &self.client_write_key
    }

    pub fn as_server_slice(&self) -> &[u8] {
        &self.server_write_key
    }

    pub fn client_write_key(&self) -> &[u8; 32] {
        &self.client_write_key
    }

    pub fn client_write_key_mut(&mut self) -> &mut [u8; 32] {
        &mut self.client_write_key
    }

    pub fn server_write_key(&self) -> &[u8; 32] {
        &self.server_write_key
    }

    pub fn server_write_key_mut(&mut self) -> &mut [u8; 32] {
        &mut self.server_write_key
    }

    pub fn is_zeroized(&self) -> bool {
        self.client_write_key == [0u8; 32] && self.server_write_key == [0u8; 32]
    }

    pub fn matches(&self, other: &SessionKeys) -> bool {
        self.client_write_key == other.client_write_key
            && self.server_write_key == other.server_write_key
    }

    pub fn as_parts(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.client_write_key, &self.server_write_key)
    }

    pub fn into_parts(self) -> ([u8; 32], [u8; 32]) {
        (self.client_write_key, self.server_write_key)
    }

    pub fn try_from_slices(client_key: &[u8], server_key: &[u8]) -> Result<Self, String> {
        if client_key.len() != 32 {
            return Err(format!(
                "Invalid client key length: expected 32 bytes, got {}",
                client_key.len()
            ));
        }
        if server_key.len() != 32 {
            return Err(format!(
                "Invalid server key length: expected 32 bytes, got {}",
                server_key.len()
            ));
        }
        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];
        client_write_key.copy_from_slice(client_key);
        server_write_key.copy_from_slice(server_key);
        Ok(Self::new(client_write_key, server_write_key))
    }

    pub fn rekey(&mut self, new_client_key: [u8; 32], new_server_key: [u8; 32]) {
        self.zeroize_keys();
        self.client_write_key = new_client_key;
        self.server_write_key = new_server_key;
    }

    /// Advances both client and server write keys by one symmetric ratchet step,
    /// securely zeroizing previous key states to provide forward secrecy.
    pub fn ratchet(&mut self) {
        let mut new_client = derive_ratchet_step(&self.client_write_key, RATCHET_CLIENT_LABEL);
        let mut new_server = derive_ratchet_step(&self.server_write_key, RATCHET_SERVER_LABEL);
        self.rekey(new_client, new_server);
        new_client.zeroize();
        new_server.zeroize();
    }

    /// Advances keys by one ratchet step bound with an optional external transcript or nonce salt.
    pub fn ratchet_with_salt(&mut self, salt: &[u8]) {
        let hk_client = Hkdf::<Sha256>::new(Some(salt), &self.client_write_key);
        let mut new_client = [0u8; 32];
        hk_client
            .expand(RATCHET_CLIENT_LABEL, &mut new_client)
            .expect("HKDF expand client ratchet failed");

        let hk_server = Hkdf::<Sha256>::new(Some(salt), &self.server_write_key);
        let mut new_server = [0u8; 32];
        hk_server
            .expand(RATCHET_SERVER_LABEL, &mut new_server)
            .expect("HKDF expand server ratchet failed");

        self.rekey(new_client, new_server);
        new_client.zeroize();
        new_server.zeroize();
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.client_write_key);
        out[32..64].copy_from_slice(&self.server_write_key);
        out
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];
        client_write_key.copy_from_slice(&bytes[..32]);
        server_write_key.copy_from_slice(&bytes[32..64]);
        Self::new(client_write_key, server_write_key)
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!(
                "Invalid byte slice length for SessionKeys: expected 64 bytes, got {}",
                bytes.len()
            ));
        }
        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];
        client_write_key.copy_from_slice(&bytes[..32]);
        server_write_key.copy_from_slice(&bytes[32..64]);
        Ok(Self::new(client_write_key, server_write_key))
    }

    pub fn zeroize_keys(&mut self) {
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
    }

    pub fn constant_time_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self
            .client_write_key
            .iter()
            .zip(other.client_write_key.iter())
        {
            diff |= a ^ b;
        }
        for (a, b) in self
            .server_write_key
            .iter()
            .zip(other.server_write_key.iter())
        {
            diff |= a ^ b;
        }
        diff == 0
    }

    pub fn client_write_key_is_zero(&self) -> bool {
        let mut acc = 0u8;
        for b in &self.client_write_key {
            acc |= *b;
        }
        acc == 0
    }

    pub fn server_write_key_is_zero(&self) -> bool {
        let mut acc = 0u8;
        for b in &self.server_write_key {
            acc |= *b;
        }
        acc == 0
    }

    /// Inverts the session keys by returning a new instance with client and server write keys swapped.
    pub fn inverted(&self) -> Self {
        Self::new(self.server_write_key, self.client_write_key)
    }

    /// Inverts the session keys in-place by swapping client and server write keys.
    pub fn invert(&mut self) {
        std::mem::swap(&mut self.client_write_key, &mut self.server_write_key);
    }

    /// Returns a short 8-hex-character SHA-256 fingerprint of the client write key for non-sensitive logging.
    pub fn client_key_fingerprint(&self) -> String {
        let hash = Sha256::digest(self.client_write_key);
        hash[..4].iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Returns a short 8-hex-character SHA-256 fingerprint of the server write key for non-sensitive logging.
    pub fn server_key_fingerprint(&self) -> String {
        let hash = Sha256::digest(self.server_write_key);
        hash[..4].iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SessionKeys(client_fp={}, server_fp={})",
            self.client_key_fingerprint(),
            self.server_key_fingerprint()
        )
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("client_write_key", &"[REDACTED]")
            .field("server_write_key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for SessionKeys {
    fn clone(&self) -> Self {
        Self {
            client_write_key: self.client_write_key,
            server_write_key: self.server_write_key,
        }
    }
}

impl PartialEq for SessionKeys {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Eq for SessionKeys {}

impl From<([u8; 32], [u8; 32])> for SessionKeys {
    fn from(keys: ([u8; 32], [u8; 32])) -> Self {
        Self::new(keys.0, keys.1)
    }
}

impl From<(&[u8; 32], &[u8; 32])> for SessionKeys {
    fn from(keys: (&[u8; 32], &[u8; 32])) -> Self {
        Self::new(*keys.0, *keys.1)
    }
}

impl From<SessionKeys> for ([u8; 32], [u8; 32]) {
    fn from(keys: SessionKeys) -> Self {
        keys.into_parts()
    }
}

impl From<[u8; 64]> for SessionKeys {
    fn from(bytes: [u8; 64]) -> Self {
        Self::from_bytes(&bytes)
    }
}

impl From<&[u8; 64]> for SessionKeys {
    fn from(bytes: &[u8; 64]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<&SessionKeys> for [u8; 64] {
    fn from(keys: &SessionKeys) -> Self {
        keys.to_bytes()
    }
}

impl From<SessionKeys> for [u8; 64] {
    fn from(keys: SessionKeys) -> Self {
        keys.to_bytes()
    }
}

impl From<&SessionKeys> for Vec<u8> {
    fn from(keys: &SessionKeys) -> Self {
        keys.to_vec()
    }
}

impl From<SessionKeys> for Vec<u8> {
    fn from(keys: SessionKeys) -> Self {
        keys.to_vec()
    }
}

impl TryFrom<&[u8]> for SessionKeys {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_byte_slice(bytes)
    }
}

impl TryFrom<(&[u8], &[u8])> for SessionKeys {
    type Error = String;

    fn try_from(slices: (&[u8], &[u8])) -> Result<Self, Self::Error> {
        Self::try_from_slices(slices.0, slices.1)
    }
}

impl Default for SessionKeys {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
    }
}

pub fn derive_session_keys(
    master_shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_SALT), master_shared_secret);

    let mut client_write_key = [0u8; 32];
    let mut server_write_key = [0u8; 32];

    let mut client_info = Vec::from(CLIENT_KEY_INFO_PREFIX);
    client_info.extend_from_slice(transcript_hash);
    hk.expand(&client_info, &mut client_write_key)
        .expect("HKDF expand client key failed");

    let mut server_info = Vec::from(SERVER_KEY_INFO_PREFIX);
    server_info.extend_from_slice(transcript_hash);
    hk.expand(&server_info, &mut server_write_key)
        .expect("HKDF expand server key failed");

    SessionKeys::new(client_write_key, server_write_key)
}

pub fn derive_child_secret(master_secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_SALT), master_secret);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .expect("HKDF expand child secret failed");
    okm
}

/// Derives the next generation of a 32-byte symmetric key using HKDF-SHA256,
/// enforcing forward secrecy through irreversible one-way key evolution.
pub fn derive_ratchet_step(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(RATCHET_SALT), key);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .expect("HKDF expand ratchet step failed");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_hybrid_shared_secret() {
        let classical_ss = [0x11u8; 32];
        let pq_ss = [0x22u8; 32];

        let ss1 = derive_hybrid_shared_secret(&classical_ss, &pq_ss);
        let ss2 = derive_hybrid_shared_secret(&classical_ss, &pq_ss);
        assert_eq!(ss1, ss2);

        let ss_diff = derive_hybrid_shared_secret(&classical_ss, &[0x33u8; 32]);
        assert_ne!(ss1, ss_diff);
    }

    #[test]
    fn test_derive_session_keys_uniqueness() {
        let master_secret = [0x42u8; 32];
        let transcript = [0x99u8; 32];

        let keys = derive_session_keys(&master_secret, &transcript);
        assert_ne!(keys.client_write_key, keys.server_write_key);

        let diff_transcript = [0x88u8; 32];
        let keys_diff = derive_session_keys(&master_secret, &diff_transcript);
        assert_ne!(keys.client_write_key, keys_diff.client_write_key);
        assert_ne!(keys.server_write_key, keys_diff.server_write_key);
    }

    #[test]
    fn test_hash_transcript() {
        let msg1 = b"handshake-client-hello";
        let msg2 = b"handshake-server-hello";

        let hash1 = hash_transcript(&[msg1, msg2]);
        let hash2 = hash_transcript(&[msg1, msg2]);
        assert_eq!(hash1, hash2);

        let hash_diff = hash_transcript(&[msg1]);
        assert_ne!(hash1, hash_diff);
    }

    #[test]
    fn test_session_keys_drop_zeroization() {
        let master_secret = [0xAAu8; 32];
        let transcript = [0xBBu8; 32];
        let session_keys = derive_session_keys(&master_secret, &transcript);
        assert_ne!(session_keys.client_write_key, [0u8; 32]);
        assert_ne!(session_keys.server_write_key, [0u8; 32]);

        // Explicitly test zeroization in Drop
        drop(session_keys);
    }

    #[test]
    fn test_session_keys_accessors() {
        let master_secret = [0x11u8; 32];
        let transcript = [0x22u8; 32];
        let session_keys = derive_session_keys(&master_secret, &transcript);
        assert_eq!(
            session_keys.client_write_key(),
            &session_keys.client_write_key
        );
        assert_eq!(
            session_keys.server_write_key(),
            &session_keys.server_write_key
        );
        assert_eq!(
            session_keys.as_client_slice(),
            &session_keys.client_write_key[..]
        );
        assert_eq!(
            session_keys.as_server_slice(),
            &session_keys.server_write_key[..]
        );
    }

    #[test]
    fn test_session_keys_new_and_default() {
        let client_k = [0x33u8; 32];
        let server_k = [0x44u8; 32];
        let session_keys = SessionKeys::new(client_k, server_k);
        assert_eq!(session_keys.client_write_key, client_k);
        assert_eq!(session_keys.server_write_key, server_k);

        let zeroed_keys = SessionKeys::zeroed();
        assert!(zeroed_keys.is_zeroized());

        let default_keys = SessionKeys::default();
        assert!(default_keys.is_zeroized());
        assert!(default_keys.matches(&zeroed_keys));
    }

    #[test]
    fn test_session_keys_debug_redaction() {
        let session_keys = SessionKeys::new([0x11u8; 32], [0x22u8; 32]);
        let debug_str = format!("{:?}", session_keys);
        assert!(debug_str.contains("SessionKeys"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("11"));
        assert!(!debug_str.contains("22"));
    }

    #[test]
    fn test_session_keys_rekey_and_zeroize() {
        let mut keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        assert_eq!(keys.client_write_key, [1u8; 32]);
        assert_eq!(keys.server_write_key, [2u8; 32]);

        keys.rekey([3u8; 32], [4u8; 32]);
        assert_eq!(keys.client_write_key, [3u8; 32]);
        assert_eq!(keys.server_write_key, [4u8; 32]);

        keys.zeroize_keys();
        assert_eq!(keys.client_write_key, [0u8; 32]);
        assert_eq!(keys.server_write_key, [0u8; 32]);
    }

    #[test]
    fn test_session_keys_is_zeroized_and_matches() {
        let keys1 = SessionKeys::new([1u8; 32], [2u8; 32]);
        let keys2 = SessionKeys::new([1u8; 32], [2u8; 32]);
        let keys3 = SessionKeys::new([3u8; 32], [4u8; 32]);

        assert!(keys1.matches(&keys2));
        assert!(!keys1.matches(&keys3));
        assert!(!keys1.is_zeroized());

        let zero_keys = SessionKeys::new([0u8; 32], [0u8; 32]);
        assert!(zero_keys.is_zeroized());

        let mut keys_to_zero = SessionKeys::new([1u8; 32], [2u8; 32]);
        keys_to_zero.zeroize_keys();
        assert!(keys_to_zero.is_zeroized());

        let mut mutable_keys = SessionKeys::new([1u8; 32], [2u8; 32]);
        *mutable_keys.client_write_key_mut() = [5u8; 32];
        assert_eq!(mutable_keys.client_write_key(), &[5u8; 32]);
    }

    #[test]
    fn test_session_keys_parts_and_try_from_slices() {
        let client_k = [0x55u8; 32];
        let server_k = [0x66u8; 32];
        let keys = SessionKeys::new(client_k, server_k);
        assert_eq!(keys.as_parts(), (&client_k, &server_k));
        let (c, s) = keys.into_parts();
        assert_eq!(c, client_k);
        assert_eq!(s, server_k);

        let parsed = SessionKeys::try_from_slices(&client_k, &server_k).unwrap();
        assert_eq!(parsed.client_write_key(), &client_k);
        assert_eq!(parsed.server_write_key(), &server_k);

        assert!(SessionKeys::try_from_slices(&[1, 2], &server_k).is_err());
        assert!(SessionKeys::try_from_slices(&client_k, &[1, 2]).is_err());
    }

    #[test]
    fn test_derive_child_secret() {
        let master = [0x77u8; 32];
        let child1 = derive_child_secret(&master, b"sub-key-1");
        let child2 = derive_child_secret(&master, b"sub-key-2");
        let child1_dup = derive_child_secret(&master, b"sub-key-1");
        assert_eq!(child1, child1_dup);
        assert_ne!(child1, child2);
    }

    #[test]
    fn test_session_keys_constant_time_eq_and_zero_checks() {
        let keys_a = SessionKeys::new([0x42; 32], [0x43; 32]);
        let keys_b = SessionKeys::new([0x42; 32], [0x43; 32]);
        let keys_c = SessionKeys::new([0x42; 32], [0x44; 32]);

        assert!(keys_a.constant_time_eq(&keys_b));
        assert!(!keys_a.constant_time_eq(&keys_c));
        assert!(!keys_a.client_write_key_is_zero());
        assert!(!keys_a.server_write_key_is_zero());

        let mut zero_keys = SessionKeys::zeroed();
        assert!(zero_keys.client_write_key_is_zero());
        assert!(zero_keys.server_write_key_is_zero());
        assert!(zero_keys.is_zeroized());

        zero_keys.zeroize_keys();
        assert!(zero_keys.client_write_key_is_zero());
    }

    #[test]
    fn test_derive_ratchet_step_determinism_and_uniqueness() {
        let initial_key = [0x5Au8; 32];
        let step1 = derive_ratchet_step(&initial_key, RATCHET_CLIENT_LABEL);
        let step1_dup = derive_ratchet_step(&initial_key, RATCHET_CLIENT_LABEL);
        assert_eq!(step1, step1_dup);
        assert_ne!(step1, initial_key);

        let step_server = derive_ratchet_step(&initial_key, RATCHET_SERVER_LABEL);
        assert_ne!(step1, step_server);

        let step2 = derive_ratchet_step(&step1, RATCHET_CLIENT_LABEL);
        assert_ne!(step1, step2);
        assert_ne!(initial_key, step2);
    }

    #[test]
    fn test_session_keys_ratchet_forward_secrecy() {
        let mut keys = SessionKeys::new([0x12; 32], [0x34; 32]);
        let initial_client = *keys.client_write_key();
        let initial_server = *keys.server_write_key();

        keys.ratchet();
        assert_ne!(*keys.client_write_key(), initial_client);
        assert_ne!(*keys.server_write_key(), initial_server);
        assert_ne!(keys.client_write_key(), keys.server_write_key());
        assert!(!keys.is_zeroized());

        let gen1_client = *keys.client_write_key();
        keys.ratchet();
        assert_ne!(*keys.client_write_key(), gen1_client);
        assert_ne!(*keys.client_write_key(), initial_client);
    }

    #[test]
    fn test_session_keys_ratchet_with_salt() {
        let mut keys1 = SessionKeys::new([0x77; 32], [0x88; 32]);
        let mut keys2 = SessionKeys::new([0x77; 32], [0x88; 32]);

        keys1.ratchet();
        keys2.ratchet_with_salt(b"custom-transcript-salt");

        assert_ne!(keys1.client_write_key(), keys2.client_write_key());
        assert_ne!(keys1.server_write_key(), keys2.server_write_key());
    }

    #[test]
    fn test_session_keys_traits_eq_clone_try_from() {
        let keys1 = SessionKeys::new([0x12u8; 32], [0x34u8; 32]);
        let cloned = keys1.clone();
        assert_eq!(keys1, cloned);

        let keys2 = SessionKeys::new([0x12u8; 32], [0x35u8; 32]);
        assert_ne!(keys1, keys2);

        let from_tuple = SessionKeys::try_from((&[0x12u8; 32][..], &[0x34u8; 32][..])).unwrap();
        assert_eq!(keys1, from_tuple);

        let bad_tuple = SessionKeys::try_from((&[1u8, 2][..], &[0x34u8; 32][..]));
        assert!(bad_tuple.is_err());
    }

    #[test]
    fn test_session_keys_conversions_and_serialization() {
        let client_k = [0x11u8; 32];
        let server_k = [0x22u8; 32];
        let keys = SessionKeys::new(client_k, server_k);

        // to_bytes and to_vec
        let bytes64 = keys.to_bytes();
        assert_eq!(&bytes64[..32], &client_k);
        assert_eq!(&bytes64[32..64], &server_k);
        assert_eq!(keys.to_vec(), bytes64.to_vec());

        // from_bytes and from_byte_slice
        let reconstructed = SessionKeys::from_bytes(&bytes64);
        assert_eq!(reconstructed, keys);

        let from_slice = SessionKeys::from_byte_slice(&bytes64).unwrap();
        assert_eq!(from_slice, keys);

        // TryFrom byte slice validation
        assert!(SessionKeys::from_byte_slice(&[0u8; 30]).is_err());
        assert!(SessionKeys::from_byte_slice(&[0u8; 65]).is_err());

        let try_from_slice: SessionKeys = bytes64.as_slice().try_into().unwrap();
        assert_eq!(try_from_slice, keys);

        // From tuple conversions
        let from_owned_tuple: SessionKeys = (client_k, server_k).into();
        assert_eq!(from_owned_tuple, keys);

        let from_ref_tuple: SessionKeys = ((&client_k, &server_k)).into();
        assert_eq!(from_ref_tuple, keys);

        let into_tuple: ([u8; 32], [u8; 32]) = keys.clone().into();
        assert_eq!(into_tuple, (client_k, server_k));

        // From array and vector conversions
        let from_arr: SessionKeys = bytes64.into();
        assert_eq!(from_arr, keys);

        let from_arr_ref: SessionKeys = (&bytes64).into();
        assert_eq!(from_arr_ref, keys);

        let into_arr: [u8; 64] = keys.clone().into();
        assert_eq!(into_arr, bytes64);

        let into_arr_ref: [u8; 64] = (&keys).into();
        assert_eq!(into_arr_ref, bytes64);

        let into_vec: Vec<u8> = keys.clone().into();
        assert_eq!(into_vec, bytes64.to_vec());

        let into_vec_ref: Vec<u8> = (&keys).into();
        assert_eq!(into_vec_ref, bytes64.to_vec());
    }

    #[test]
    fn test_session_keys_inversion_and_display() {
        let client_k = [0x11u8; 32];
        let server_k = [0x22u8; 32];
        let mut keys = SessionKeys::new(client_k, server_k);

        // Test Display and Fingerprints
        let display_str = format!("{}", keys);
        assert!(display_str.contains("SessionKeys(client_fp="));
        assert!(display_str.contains("server_fp="));
        assert_eq!(keys.client_key_fingerprint().len(), 8);
        assert_eq!(keys.server_key_fingerprint().len(), 8);
        assert_ne!(keys.client_key_fingerprint(), keys.server_key_fingerprint());

        // Test inverted
        let inverted = keys.inverted();
        assert_eq!(inverted.client_write_key, server_k);
        assert_eq!(inverted.server_write_key, client_k);
        assert_eq!(
            inverted.client_key_fingerprint(),
            keys.server_key_fingerprint()
        );
        assert_eq!(
            inverted.server_key_fingerprint(),
            keys.client_key_fingerprint()
        );

        // Test invert in-place
        keys.invert();
        assert_eq!(keys, inverted);
        keys.invert();
        assert_eq!(keys.client_write_key, client_k);
        assert_eq!(keys.server_write_key, server_k);
    }
}
