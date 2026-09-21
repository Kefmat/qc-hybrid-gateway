pub mod crypto;
pub mod protocol;

pub use crypto::kem::{HybridKemKeyPair, HybridKemPublicKey, HybridKemSecretKey, HybridKemCiphertext};
pub use crypto::sig::{HybridSigKeyPair, HybridSigPublicKey, HybridSigSecretKey, HybridSignature};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::{decapsulate_hybrid, encapsulate_hybrid};
    use crate::crypto::sig::{sign_hybrid, verify_hybrid};
    use crate::crypto::aead::AeadCipher;
    use crate::crypto::kdf::derive_session_keys;
    use crate::protocol::AntiReplayFilter;

    #[test]
    fn test_hybrid_kem_exchange() {
        let receiver = HybridKemKeyPair::generate();
        let (ciphertext, sender_ss) = encapsulate_hybrid(&receiver.public_key);
        let receiver_ss = decapsulate_hybrid(&ciphertext, &receiver.secret_key);
        assert_eq!(sender_ss, receiver_ss);
    }

    #[test]
    fn test_hybrid_signature_lifecycle() {
        let signer = HybridSigKeyPair::generate();
        let payload = b"critical-zero-trust-payload";
        let signature = sign_hybrid(payload, &signer.secret_key);

        assert!(verify_hybrid(payload, &signature, &signer.public_key));
        assert!(!verify_hybrid(b"corrupted-payload", &signature, &signer.public_key));
    }

    #[test]
    fn test_aead_framing_and_tampering() {
        let master_secret = [0x77u8; 32];
        let transcript = [0x99u8; 32];
        let session = derive_session_keys(&master_secret, &transcript);

        let sender = AeadCipher::new(&session.client_write_key);
        let receiver = AeadCipher::new(&session.client_write_key);

        let plaintext = b"Hello Post-Quantum Encrypted World";
        let aad = b"seq=1";
        let ciphertext = sender.encrypt(1, aad, plaintext).unwrap();

        let decrypted = receiver.decrypt(1, aad, &ciphertext).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);

        // Tamper test
        let mut tampered = ciphertext.clone();
        tampered[2] ^= 0x01;
        assert!(receiver.decrypt(1, aad, &tampered).is_err());
    }

    #[test]
    fn test_anti_replay_window() {
        let mut filter = AntiReplayFilter::new(32);
        assert!(filter.check_and_update(1));
        assert!(filter.check_and_update(2));
        assert!(!filter.check_and_update(1));
        assert!(filter.check_and_update(50));
        assert!(!filter.check_and_update(5));
    }
}
