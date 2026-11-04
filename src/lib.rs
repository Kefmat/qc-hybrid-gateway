pub mod crypto;
pub mod protocol;
pub mod session;
pub mod transport;

pub use crypto::aead::AeadCipher;
pub use crypto::kdf::{
    derive_hybrid_shared_secret, derive_ratchet_step, derive_session_keys, hash_transcript,
    SessionKeys,
};
pub use crypto::kem::{HybridKemCiphertext, HybridKemKeyPair, HybridKemPublicKey, HybridKemSecretKey};
pub use crypto::sig::{HybridSigKeyPair, HybridSigPublicKey, HybridSigSecretKey, HybridSignature};
pub use protocol::{
    AntiReplayFilter, FrameDecoder, HandshakeInit, HandshakeResponse, PacketFrame, PacketHeader,
    PacketType, ProtocolError,
};
pub use session::{Session, SessionId, SessionMetrics, SessionRole, SessionState, SESSION_ID_SIZE};
pub use transport::{EstablishedClientConnection, TunnelClient, TunnelConfig, TunnelServer};

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

    #[test]
    fn test_full_session_tunnel_with_streaming_codec_and_rekey() {
        // Setup identities
        let client_sig = HybridSigKeyPair::generate();
        let server_sig = HybridSigKeyPair::generate();

        // 1. Client initiates HandshakeInit
        let client_ephemeral_kem = HybridKemKeyPair::generate();
        let client_nonce = [1u8; 16];
        let init_msg = HandshakeInit::create(client_ephemeral_kem.public_key, client_nonce, &client_sig.secret_key);
        assert!(init_msg.verify(&client_sig.public_key));

        // 2. Server encapsulates against client's ephemeral KEM key
        let (kem_ct, server_shared_secret) = encapsulate_hybrid(&init_msg.ephemeral_pk);
        let server_nonce = [2u8; 16];
        let resp_msg = HandshakeResponse::create(kem_ct.clone(), server_nonce, &server_sig.secret_key);
        assert!(resp_msg.verify(&server_sig.public_key));

        // 3. Client decapsulates
        let client_shared_secret = decapsulate_hybrid(&resp_msg.ciphertext, &client_ephemeral_kem.secret_key);
        assert_eq!(client_shared_secret, server_shared_secret);

        // 4. Derive initial session keys
        let transcript = hash_transcript(&[&init_msg.to_bytes(), &resp_msg.to_bytes()]);
        let client_keys = derive_session_keys(&client_shared_secret, &transcript);
        let server_keys = derive_session_keys(&server_shared_secret, &transcript);

        // 5. Establish Sessions
        let mut client_session = Session::new_client();
        let mut server_session = Session::new_server();
        client_session.establish(&client_keys).unwrap();
        server_session.establish(&server_keys).unwrap();

        // 6. Streaming traffic with FrameDecoder
        let mut server_decoder = FrameDecoder::new();
        let mut client_decoder = FrameDecoder::new();

        let packet1 = client_session.encrypt_packet(PacketType::Data, b"message-one").unwrap();
        let packet2 = client_session.encrypt_packet(PacketType::Ping, b"ping").unwrap();

        let mut stream_bytes = packet1.encode();
        stream_bytes.extend_from_slice(&packet2.encode());

        server_decoder.feed(&stream_bytes);
        let rx_frame1 = server_decoder.decode_frame().unwrap().unwrap();
        let rx_frame2 = server_decoder.decode_frame().unwrap().unwrap();

        let pt1 = server_session.decrypt_packet(&rx_frame1).unwrap();
        let pt2 = server_session.decrypt_packet(&rx_frame2).unwrap();
        assert_eq!(pt1, b"message-one");
        assert_eq!(pt2, b"ping");

        // 7. Server responds to client
        let server_resp = server_session.encrypt_packet(PacketType::Data, b"response-ack").unwrap();
        client_decoder.feed(&server_resp.encode());
        let rx_resp = client_decoder.decode_frame().unwrap().unwrap();
        let pt_resp = client_session.decrypt_packet(&rx_resp).unwrap();
        assert_eq!(pt_resp, b"response-ack");

        // 8. Rekeying transition
        client_session.trigger_rekey().unwrap();
        server_session.trigger_rekey().unwrap();

        let new_transcript = hash_transcript(&[&transcript, b"rekey-rotation"]);
        let new_client_keys = derive_session_keys(&client_shared_secret, &new_transcript);
        let new_server_keys = derive_session_keys(&server_shared_secret, &new_transcript);

        client_session.complete_rekey(&new_client_keys).unwrap();
        server_session.complete_rekey(&new_server_keys).unwrap();

        let post_rekey_pkt = client_session.encrypt_packet(PacketType::Data, b"post-rekey-data").unwrap();
        server_decoder.feed(&post_rekey_pkt.encode());
        let rx_post_rekey = server_decoder.decode_frame().unwrap().unwrap();
        let pt_rekey = server_session.decrypt_packet(&rx_post_rekey).unwrap();
        assert_eq!(pt_rekey, b"post-rekey-data");

        // 9. Teardown
        client_session.close();
        server_session.close();
        assert!(client_session.is_closed());
        assert!(server_session.is_closed());
    }

    #[test]
    fn test_rapid_rekeying_stress_and_out_of_order_packets() {
        let master_secret = [0xAAu8; 32];
        let mut transcript = hash_transcript(&[b"initial-session-transcript"]);

        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let initial_keys = derive_session_keys(&master_secret, &transcript);
        client.establish(&initial_keys).unwrap();
        server.establish(&initial_keys).unwrap();

        // Perform 3 consecutive rapid rekeys
        for round in 1..=3 {
            let data_msg = format!("round-{}-data", round);
            let frame = client.encrypt_packet(PacketType::Data, data_msg.as_bytes()).unwrap();
            let decrypted = server.decrypt_packet(&frame).unwrap();
            assert_eq!(decrypted, data_msg.as_bytes());

            client.trigger_rekey().unwrap();
            server.trigger_rekey().unwrap();

            transcript = hash_transcript(&[&transcript, format!("rotation-{}", round).as_bytes()]);
            let keys = derive_session_keys(&master_secret, &transcript);

            client.complete_rekey(&keys).unwrap();
            server.complete_rekey(&keys).unwrap();
            assert_eq!(client.metrics().rekeys_completed, round);
            assert_eq!(server.metrics().rekeys_completed, round);
        }

        // Out-of-order frame delivery test
        let p1 = client.encrypt_packet(PacketType::Data, b"pkt-1").unwrap();
        let p2 = client.encrypt_packet(PacketType::Data, b"pkt-2").unwrap();
        let p3 = client.encrypt_packet(PacketType::Data, b"pkt-3").unwrap();

        // Deliver out of order: p2 then p1 (within window), then p3
        assert_eq!(server.decrypt_packet(&p2).unwrap(), b"pkt-2");
        assert_eq!(server.decrypt_packet(&p1).unwrap(), b"pkt-1");
        assert_eq!(server.decrypt_packet(&p3).unwrap(), b"pkt-3");

        // Duplicate replay of p2 must fail
        assert!(server.decrypt_packet(&p2).is_err());
        assert_eq!(server.metrics().replays_dropped, 1);
    }

    #[test]
    fn test_session_continuous_ratchet_forward_secrecy() {
        let master_secret = [0x55u8; 32];
        let transcript = hash_transcript(&[b"test-ratchet-session-transcript"]);

        let mut client = Session::new_client();
        let mut server = Session::new_server();

        let mut client_keys = derive_session_keys(&master_secret, &transcript);
        let mut server_keys = derive_session_keys(&master_secret, &transcript);

        client.establish(&client_keys).unwrap();
        server.establish(&server_keys).unwrap();

        let mut previous_frames = Vec::new();

        // Perform 4 consecutive ratchet evolutions
        for generation in 1..=4 {
            let message = format!("generation-{}-payload", generation);
            let frame = client.encrypt_packet(PacketType::Data, message.as_bytes()).unwrap();
            let decrypted = server.decrypt_packet(&frame).unwrap();
            assert_eq!(decrypted, message.as_bytes());

            previous_frames.push(frame);

            // Ratchet both endpoints forward
            client.ratchet_rekey(&mut client_keys).unwrap();
            server.ratchet_rekey(&mut server_keys).unwrap();

            assert_eq!(client.metrics().rekeys_completed, generation as u64);
            assert_eq!(server.metrics().rekeys_completed, generation as u64);
        }

        // Verify communication continues seamlessly after multiple ratchets
        let final_msg = b"seamless-continuity-after-multiple-ratchets";
        let frame_final = client.encrypt_packet(PacketType::Data, final_msg).unwrap();
        let decrypted_final = server.decrypt_packet(&frame_final).unwrap();
        assert_eq!(decrypted_final, final_msg);

        // Forward secrecy check: old ciphertexts encrypted under previous key generations
        // cannot be decrypted by an auditor session initialized with current (ratcheted) keys.
        let mut ratcheted_auditor = Session::new_server();
        ratcheted_auditor.establish(&server_keys).unwrap();
        for old_frame in &previous_frames {
            assert!(
                ratcheted_auditor.decrypt_packet(old_frame).is_err(),
                "Old frame from previous ratchet generation was decrypted by ratcheted session!"
            );
        }
    }

    #[test]
    fn test_hybrid_gateway_type_conversions_debug_and_filtering() {
        // 1. Generate keypairs and inspect safe Debug representations (no private key exposure)
        let kem_keys = HybridKemKeyPair::generate();
        let sig_keys = HybridSigKeyPair::generate();

        let kem_debug = format!("{:?}", kem_keys);
        assert!(kem_debug.contains("[REDACTED]"));
        assert!(kem_debug.contains("HybridKemKeyPair"));

        let sig_debug = format!("{:?}", sig_keys);
        assert!(sig_debug.contains("[REDACTED]"));
        assert!(sig_debug.contains("HybridSigKeyPair"));

        // 2. Test Display formatting for public types
        let (ct, sender_ss) = encapsulate_hybrid(&kem_keys.public_key);
        let pk_display = format!("{}", kem_keys.public_key);
        assert!(pk_display.starts_with("HybridKemPublicKey("));
        let ct_display = format!("{}", ct);
        assert!(ct_display.starts_with("HybridKemCiphertext("));

        let sig = sign_hybrid(b"integration-display-test", &sig_keys.secret_key);
        let sig_display = format!("{}", sig);
        assert!(sig_display.starts_with("HybridSignature("));
        let sig_pk_display = format!("{}", sig_keys.public_key);
        assert!(sig_pk_display.starts_with("HybridSigPublicKey("));

        // 3. Session peer role and ciphers checking
        let mut client = Session::new_client();
        let server = Session::new_server();
        assert!(client.is_peer_role(server.role()));
        assert!(server.is_peer_role(client.role()));
        assert!(!client.is_ciphers_initialized());

        let transcript = hash_transcript(&[&ct.to_bytes()]);
        let session_keys = derive_session_keys(&sender_ss, &transcript);
        client.establish(&session_keys).unwrap();
        assert!(client.is_ciphers_initialized());

        // 4. Test pre-filtering with AntiReplayFilter::would_accept and is_replay
        let mut filter = AntiReplayFilter::new(32);
        let frame1 = client.encrypt_packet(PacketType::Data, b"stream-msg-1").unwrap();
        assert!(filter.would_accept(frame1.seq()));
        assert!(!filter.is_replay(frame1.seq()));
        assert!(filter.check_and_update(frame1.seq()));
        assert!(!filter.would_accept(frame1.seq()));
        assert!(filter.is_replay(frame1.seq()));

        // Display check for Session and AntiReplayFilter
        let session_display = format!("{}", client);
        assert!(session_display.contains("Session("));
        let filter_display = format!("{}", filter);
        assert!(filter_display.contains("AntiReplayFilter(window=32"));
    }
}



