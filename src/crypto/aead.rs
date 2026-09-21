use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
}

impl AeadCipher {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    pub fn encrypt(&self, nonce_counter: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
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
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
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
