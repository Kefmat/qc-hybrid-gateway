use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const KEM_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-KEM-V1";
const SESSION_SALT: &[u8] = b"PQC-HYBRID-GATEWAY-SESSION-V1";

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

    SessionKeys {
        client_write_key,
        server_write_key,
    }
}
