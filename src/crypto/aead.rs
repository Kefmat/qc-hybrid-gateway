use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// Formats a 64-bit sequence counter into a 96-bit (12-byte) big-endian nonce.
pub fn format_nonce(nonce_counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
    nonce_bytes
}

/// ChaCha20-Poly1305 authenticated symmetric cipher engine.
pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
}

impl AeadCipher {
    /// Returns the cipher key size in bytes (32).
    pub const fn key_size() -> usize {
        KEY_SIZE
    }

    /// Returns the AEAD authentication tag size in bytes (16).
    pub const fn tag_size() -> usize {
        TAG_SIZE
    }

    /// Returns the nonce size in bytes (12).
    pub const fn nonce_size() -> usize {
        NONCE_SIZE
    }

    /// Checks whether a given key length in bytes is valid for ChaCha20-Poly1305 (32 bytes).
    pub const fn is_valid_key_len(len: usize) -> bool {
        len == KEY_SIZE
    }

    /// Checks whether a given nonce length in bytes is valid for ChaCha20-Poly1305 (12 bytes).
    pub const fn is_valid_nonce_len(len: usize) -> bool {
        len == NONCE_SIZE
    }

    /// Checks whether a given tag length in bytes is valid for ChaCha20-Poly1305 (16 bytes).
    pub const fn is_valid_tag_len(len: usize) -> bool {
        len == TAG_SIZE
    }

    /// Computes the expected ciphertext length for a given plaintext length including the authentication tag.
    pub const fn ciphertext_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_SIZE
    }

    /// Computes the plaintext length for a given ciphertext length, returning `None` if the ciphertext is shorter than the authentication tag.
    pub const fn plaintext_len(ciphertext_len: usize) -> Option<usize> {
        if ciphertext_len >= TAG_SIZE {
            Some(ciphertext_len - TAG_SIZE)
        } else {
            None
        }
    }

    /// Creates a new cipher instance initialized with a 32-byte key.
    pub fn new(key_bytes: &[u8; KEY_SIZE]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    /// Creates a new cipher instance from a byte slice, validating that its length matches KEY_SIZE.
    pub fn from_slice(key_bytes: &[u8]) -> Result<Self, String> {
        if key_bytes.len() != KEY_SIZE {
            return Err(format!(
                "Invalid AEAD key length: expected {} bytes, got {}",
                KEY_SIZE,
                key_bytes.len()
            ));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(key_bytes);
        Ok(Self::new(&key))
    }

    /// Re-keys the cipher instance with a new 32-byte key.
    pub fn rekey(&mut self, new_key_bytes: &[u8; KEY_SIZE]) {
        let key = Key::from_slice(new_key_bytes);
        self.cipher = ChaCha20Poly1305::new(key);
    }

    /// Re-keys the cipher instance from a byte slice, validating that its length matches KEY_SIZE.
    pub fn rekey_from_slice(&mut self, new_key_bytes: &[u8]) -> Result<(), String> {
        if new_key_bytes.len() != KEY_SIZE {
            return Err(format!(
                "Invalid AEAD key length for rekey: expected {} bytes, got {}",
                KEY_SIZE,
                new_key_bytes.len()
            ));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(new_key_bytes);
        self.rekey(&key);
        Ok(())
    }




    /// Encrypts plaintext with associated data (AAD) using sequence counter based nonce.
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

    /// Decrypts ciphertext and verifies authentication tag with associated data (AAD).
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

impl From<&[u8; KEY_SIZE]> for AeadCipher {
    fn from(key: &[u8; KEY_SIZE]) -> Self {
        Self::new(key)
    }
}

impl From<[u8; KEY_SIZE]> for AeadCipher {
    fn from(key: [u8; KEY_SIZE]) -> Self {
        Self::new(&key)
    }
}

impl TryFrom<&[u8]> for AeadCipher {
    type Error = String;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

impl std::fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadCipher")
            .field("algorithm", &"ChaCha20Poly1305")
            .field("key_size", &KEY_SIZE)
            .field("tag_size", &TAG_SIZE)
            .field("nonce_size", &NONCE_SIZE)
            .finish()
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

    #[test]
    fn test_ciphertext_truncation_fails_decryption() {
        let key = [0x77u8; 32];
        let cipher = AeadCipher::new(&key);
        let encrypted = cipher.encrypt(5, b"aad", b"secret message payload").unwrap();

        let truncated = &encrypted[..encrypted.len() - 1];
        assert!(cipher.decrypt(5, b"aad", truncated).is_err());
    }

    #[test]
    fn test_nonce_sequence_counters_distinct() {
        let n1 = format_nonce(1);
        let n2 = format_nonce(2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_aead_cipher_size_constants() {
        assert_eq!(AeadCipher::key_size(), 32);
        assert_eq!(AeadCipher::tag_size(), 16);
        assert_eq!(AeadCipher::nonce_size(), 12);
        assert!(AeadCipher::is_valid_key_len(32));
        assert!(!AeadCipher::is_valid_key_len(16));
        assert!(AeadCipher::is_valid_nonce_len(12));
        assert!(!AeadCipher::is_valid_nonce_len(8));
        assert!(AeadCipher::is_valid_tag_len(16));
        assert!(!AeadCipher::is_valid_tag_len(32));
    }

    #[test]
    fn test_aead_cipher_from_slice() {
        let key_bytes = [0x55u8; 32];
        let cipher = AeadCipher::from_slice(&key_bytes);
        assert!(cipher.is_ok());

        let bad_key = [0x55u8; 16];
        let bad_cipher = AeadCipher::from_slice(&bad_key);
        assert!(bad_cipher.is_err());
    }

    #[test]
    fn test_aead_cipher_rekey() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let mut cipher = AeadCipher::new(&key1);

        let plaintext = b"rekey-test-payload";
        let aad = b"rekey-aad";
        let ct1 = cipher.encrypt(1, aad, plaintext).unwrap();

        // After rekeying, cipher should decrypt with key2 and fail to decrypt with key1 ciphertext
        cipher.rekey(&key2);
        assert!(cipher.decrypt(1, aad, &ct1).is_err());

        let ct2 = cipher.encrypt(1, aad, plaintext).unwrap();
        let decrypted = cipher.decrypt(1, aad, &ct2).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aead_cipher_from_and_try_from() {
        let key = [0x33u8; KEY_SIZE];
        let cipher_ref: AeadCipher = (&key).into();
        let cipher_val: AeadCipher = key.into();

        let ct = cipher_ref.encrypt(1, b"aad", b"hello").unwrap();
        let pt = cipher_val.decrypt(1, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello");

        let cipher_try: AeadCipher = key.as_slice().try_into().expect("TryFrom failed");
        let pt2 = cipher_try.decrypt(1, b"aad", &ct).unwrap();
        assert_eq!(pt2, b"hello");
    }

    #[test]
    fn test_aead_cipher_debug() {
        let key = [0x42u8; KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let debug_str = format!("{:?}", cipher);
        assert!(debug_str.contains("AeadCipher"));
        assert!(debug_str.contains("ChaCha20Poly1305"));
        assert!(debug_str.contains("tag_size: 16"));
    }

    #[test]
    fn test_aead_cipher_length_helpers() {
        assert_eq!(AeadCipher::ciphertext_len(0), TAG_SIZE);
        assert_eq!(AeadCipher::ciphertext_len(100), 100 + TAG_SIZE);

        assert_eq!(AeadCipher::plaintext_len(TAG_SIZE), Some(0));
        assert_eq!(AeadCipher::plaintext_len(TAG_SIZE + 50), Some(50));
        assert_eq!(AeadCipher::plaintext_len(TAG_SIZE - 1), None);
        assert_eq!(AeadCipher::plaintext_len(0), None);
    }

    #[test]
    fn test_aead_rekey_from_slice() {
        let key1 = [0x11u8; KEY_SIZE];
        let key2 = [0x22u8; KEY_SIZE];
        let mut cipher = AeadCipher::new(&key1);

        assert!(cipher.rekey_from_slice(&key2).is_ok());

        let bad_key = [0x33u8; 20];
        assert!(cipher.rekey_from_slice(&bad_key).is_err());
    }

    #[test]
    fn test_aead_corrupted_tag_fails() {
        let key = [0x88u8; KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let mut ct = cipher.encrypt(42, b"associated-data", b"payload to protect").unwrap();

        // Mutate the final tag byte
        let last_idx = ct.len() - 1;
        ct[last_idx] ^= 0x01;
        assert!(cipher.decrypt(42, b"associated-data", &ct).is_err());

        // Mutate the first tag byte (at ct.len() - TAG_SIZE)
        ct[last_idx] ^= 0x01; // restore
        let first_tag_idx = ct.len() - TAG_SIZE;
        ct[first_tag_idx] ^= 0x55;
        assert!(cipher.decrypt(42, b"associated-data", &ct).is_err());
    }

    #[test]
    fn test_aead_nonce_sequence_boundaries() {
        let n_zero = format_nonce(0);
        let n_max = format_nonce(u64::MAX);
        assert_ne!(n_zero, n_max);
        assert_eq!(n_zero.as_slice()[0..4], [0, 0, 0, 0]);
        assert_eq!(n_max.as_slice()[0..4], [0, 0, 0, 0]);
        assert_eq!(&n_max.as_slice()[4..12], &u64::MAX.to_be_bytes());

        let key = [0x99u8; KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let ct_seq1 = cipher.encrypt(1, b"aad", b"hello").unwrap();
        // Trying to decrypt with seq 2 must fail even with exact same payload and aad
        assert!(cipher.decrypt(2, b"aad", &ct_seq1).is_err());
    }
}




