use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const KEM_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-KEM-V1";
const SESSION_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-SESSION-V1";

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
    hk.expand(b"hybrid-kem-shared-secret", &mut okm)
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

    pub fn client_write_key(&self) -> &[u8; 32] {
        &self.client_write_key
    }

    pub fn server_write_key(&self) -> &[u8; 32] {
        &self.server_write_key
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
    }
}

pub fn derive_session_keys(master_shared_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_SALT), master_shared_secret);

    let mut client_write_key = [0u8; 32];
    let mut server_write_key = [0u8; 32];

    let mut client_info = Vec::from(b"client-write-key:");
    client_info.extend_from_slice(transcript_hash);
    hk.expand(&client_info, &mut client_write_key)
        .expect("HKDF expand client key failed");

    let mut server_info = Vec::from(b"server-write-key:");
    server_info.extend_from_slice(transcript_hash);
    hk.expand(&server_info, &mut server_write_key)
        .expect("HKDF expand server key failed");

    SessionKeys::new(client_write_key, server_write_key)
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
        assert_eq!(session_keys.client_write_key(), &session_keys.client_write_key);
        assert_eq!(session_keys.server_write_key(), &session_keys.server_write_key);
    }

    #[test]
    fn test_session_keys_new() {
        let client_k = [0x33u8; 32];
        let server_k = [0x44u8; 32];
        let session_keys = SessionKeys::new(client_k, server_k);
        assert_eq!(session_keys.client_write_key, client_k);
        assert_eq!(session_keys.server_write_key, server_k);
    }
}





