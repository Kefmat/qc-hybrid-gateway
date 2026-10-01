pub mod crypto;
pub mod protocol;
pub mod session;

pub use crypto::aead::AeadCipher;
pub use crypto::kdf::{derive_hybrid_shared_secret, derive_session_keys, hash_transcript, SessionKeys};
pub use crypto::kem::{HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridKemSecretKey};
pub use crypto::sig::{HybridSigKeyPair, HybridSigPublicKey, HybridSigSecretKey, HybridSignature};
pub use protocol::{AntiReplayFilter, HandshakeInit, HandshakeResponse, PacketFrame, PacketHeader, PacketType};
pub use session::{Session, SessionRole, SessionState};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::{decapsulate_hybrid, encapsulate_hybrid};
    use crate::crypto::sig::{sign_hybrid, verify_hybrid};

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
        let transcript = hash_transcript(&[b"client-handshake-init", b"server-handshake-resp"]);
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

    #[test]
    fn test_end_to_end_protocol_pipeline() {
        // 1. Setup Server Identities
        let server_kem = HybridKemKeyPair::generate();
        let server_sig = HybridSigKeyPair::generate();

        // 2. Client initiates handshake (encapsulation)
        let (kem_ct, client_ss) = encapsulate_hybrid(&server_kem.public_key);
        let client_hello_payload = kem_ct.to_bytes();
        let client_hello_frame = PacketFrame::new(PacketType::HandshakeInit, 1, client_hello_payload.clone()).unwrap();

        // 3. Server decapsulates and signs response
        let server_ss = decapsulate_hybrid(&kem_ct, &server_kem.secret_key);
        assert_eq!(client_ss, server_ss);

        let server_sig_data = sign_hybrid(&client_hello_payload, &server_sig.secret_key);
        let server_resp_frame = PacketFrame::new(PacketType::HandshakeResp, 1, server_sig_data.to_bytes()).unwrap();

        // 4. Client verifies server identity
        let decoded_sig = HybridSignature::from_bytes(&server_resp_frame.payload).unwrap();
        assert!(verify_hybrid(&client_hello_payload, &decoded_sig, &server_sig.public_key));

        // 5. Both derive matching session keys bound to transcript
        let transcript = hash_transcript(&[&client_hello_frame.encode(), &server_resp_frame.encode()]);
        let client_session = derive_session_keys(&client_ss, &transcript);
        let server_session = derive_session_keys(&server_ss, &transcript);

        assert_eq!(client_session.client_write_key(), server_session.client_write_key());
        assert_eq!(client_session.server_write_key(), server_session.server_write_key());

        // 6. Client encrypts and sends Data packet
        let client_cipher = AeadCipher::new(client_session.client_write_key());
        let server_rx_cipher = AeadCipher::new(server_session.client_write_key());

        let plaintext = b"post-quantum-secure-tunnel-payload";
        let encrypted_payload = client_cipher.encrypt(1, b"seq=1", plaintext).unwrap();
        let data_frame = PacketFrame::new(PacketType::Data, 1, encrypted_payload).unwrap();

        // 7. Server anti-replay and decryption
        let mut server_replay_filter = AntiReplayFilter::default();
        assert!(server_replay_filter.check_and_update(data_frame.seq()));

        let decoded_frame = PacketFrame::decode(&data_frame.encode()).unwrap();
        assert!(decoded_frame.is_data());
        let decrypted = server_rx_cipher.decrypt(decoded_frame.seq(), b"seq=1", &decoded_frame.payload).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}

