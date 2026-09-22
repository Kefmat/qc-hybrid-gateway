use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub fn format_nonce(nonce_counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
    nonce_bytes
}

pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
}

impl AeadCipher {
    pub fn new(key_bytes: &[u8; KEY_SIZE]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    pub fn encrypt(&self, nonce_counter: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_bytes = format_nonce(nonce_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("AEAD encryption error: {:?}", e))
    }

    pub fn decrypt(&self, nonce_counter: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_bytes = format_nonce(nonce_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("AEAD decryption/auth tag error: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_nonce() {
        let nonce = format_nonce(42);
        assert_eq!(&nonce[0..4], &[0, 0, 0, 0]);
        assert_eq!(&nonce[4..12], &42u64.to_be_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_empty_payload() {
        let key = [0x42u8; 32];
        let cipher = AeadCipher::new(&key);
        let encrypted = cipher.encrypt(1, b"header", b"").expect("encryption failed");
        assert_eq!(encrypted.len(), TAG_SIZE);

        let decrypted = cipher.decrypt(1, b"header", &encrypted).expect("decryption failed");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aad_mismatch_fails_decryption() {
        let key = [0x55u8; 32];
        let cipher = AeadCipher::new(&key);
        let encrypted = cipher.encrypt(10, b"correct-aad", b"secret").unwrap();

        let err = cipher.decrypt(10, b"wrong-aad", &encrypted);
        assert!(err.is_err());
    }
}
