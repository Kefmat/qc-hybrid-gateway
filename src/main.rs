use clap::{Parser, Subcommand};
use pqc_hybrid_gateway::crypto::{
    aead::AeadCipher,
    kdf::{derive_session_keys, hash_transcript},
    kem::{decapsulate_hybrid, encapsulate_hybrid, HybridKemKeyPair},
    sig::{sign_hybrid, verify_hybrid, HybridSigKeyPair},
};
use pqc_hybrid_gateway::protocol::{
    AntiReplayFilter, FrameDecoder, HandshakeInit, HandshakeResponse, PacketType,
};
use pqc_hybrid_gateway::session::Session;
use std::time::Instant;


#[derive(Parser)]
#[command(
    name = "pqc-hybrid-gateway",
    about = "Post-Quantum Hybrid Cryptographic Gateway (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519, ChaCha20-Poly1305)",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Post-Quantum and classical hybrid keypairs
    Keygen,
    /// Run cryptographic verification tests (KEM, Signatures, AEAD, Anti-Replay)
    Verify,
    /// Run cryptographic performance benchmarks
    Bench,
    /// Simulate full Post-Quantum hybrid encrypted tunnel between client and server
    Tunnel,
}


fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            println!("--- Generating Post-Quantum Hybrid Keys ---");
            let kem_keys = HybridKemKeyPair::generate();
            let sig_keys = HybridSigKeyPair::generate();

            println!("[+] Hybrid KEM Keypair generated:");
            println!("    - Classical (X25519 Public Key): {} bytes", kem_keys.public_key.x25519_pk.len());
            println!("    - Post-Quantum (ML-KEM-768 Public Key): {} bytes", std::mem::size_of_val(&kem_keys.public_key.kyber_pk));

            println!("[+] Hybrid Signature Keypair generated:");
            println!("    - Classical (Ed25519 Public Key): {} bytes", sig_keys.public_key.ed25519_pk.len());
            println!("    - Post-Quantum (ML-DSA-65 Public Key): {} bytes", std::mem::size_of_val(&sig_keys.public_key.dilithium_pk));
        }
        Commands::Verify => {
            println!("--- Running Cryptographic Verification Suite ---");

            // 1. Hybrid KEM verification
            print!("[TEST 1/5] Hybrid KEM (ML-KEM-768 + X25519) Key Exchange... ");
            let receiver_keys = HybridKemKeyPair::generate();
            let (ciphertext, sender_shared_secret) = encapsulate_hybrid(&receiver_keys.public_key);
            let receiver_shared_secret = decapsulate_hybrid(&ciphertext, &receiver_keys.secret_key);

            assert_eq!(sender_shared_secret, receiver_shared_secret, "KEM shared secret mismatch");
            println!("PASSED");

            // 2. Hybrid Signature verification
            print!("[TEST 2/5] Hybrid Signature (ML-DSA-65 + Ed25519) Sign & Verify... ");
            let signer_keys = HybridSigKeyPair::generate();
            let message = b"CRITICAL_AUTH_PAYLOAD_POST_QUANTUM_SECURE";
            let signature = sign_hybrid(message, &signer_keys.secret_key);

            let valid = verify_hybrid(message, &signature, &signer_keys.public_key);
            assert!(valid, "Signature validation failed");

            // Tamper test
            let tampered_msg = b"CRITICAL_AUTH_PAYLOAD_POST_QUANTUM_TAMPERED";
            assert!(!verify_hybrid(tampered_msg, &signature, &signer_keys.public_key), "Tampered message passed verification");
            println!("PASSED");

            // 3. AEAD & Transcript Key Derivation
            print!("[TEST 3/5] AEAD Session Derivation & Tamper Resistance... ");
            let transcript_hash = hash_transcript(&[b"client-init-key-exchange", b"server-resp-key-exchange"]);
            let session_keys = derive_session_keys(&sender_shared_secret, &transcript_hash);
            let client_cipher = AeadCipher::new(&session_keys.client_write_key);
            let server_cipher = AeadCipher::new(&session_keys.client_write_key);

            let plaintext = b"Confidential Tunnel Traffic";
            let aad = b"header-metadata-seq-1";
            let encrypted = client_cipher.encrypt(1, aad, plaintext).expect("Encryption failed");

            let decrypted = server_cipher.decrypt(1, aad, &encrypted).expect("Decryption failed");
            assert_eq!(plaintext.to_vec(), decrypted, "Plaintext mismatch");

            // Tamper ciphertext
            let mut bad_encrypted = encrypted.clone();
            bad_encrypted[0] ^= 0xFF;
            assert!(server_cipher.decrypt(1, aad, &bad_encrypted).is_err(), "Corrupted ciphertext was accepted");
            println!("PASSED");

            // 4. Anti-Replay Filter
            print!("[TEST 4/5] Anti-Replay Sliding Window Filter... ");
            let mut filter = AntiReplayFilter::new(64);
            assert!(filter.check_and_update(1));
            assert!(filter.check_and_update(2));
            assert!(!filter.check_and_update(1), "Replayed packet seq 1 accepted");
            assert!(filter.check_and_update(100));
            assert!(!filter.check_and_update(10), "Outdated packet accepted");
            println!("PASSED");

            // 5. Wire Frame Encoding/Decoding
            print!("[TEST 5/5] Wire Frame Serialization & Framing... ");
            let frame = pqc_hybrid_gateway::protocol::PacketFrame::new(
                pqc_hybrid_gateway::protocol::PacketType::Data,
                42,
                encrypted,
            ).expect("Frame creation failed");
            let encoded = frame.encode();
            let decoded = pqc_hybrid_gateway::protocol::PacketFrame::decode(&encoded).expect("Frame decode failed");
            assert_eq!(frame, decoded, "Decoded frame mismatch");
            println!("PASSED");

            println!("\nAll cryptographic security verifications completed successfully.");
        }
        Commands::Bench => {
            println!("--- Benchmarking Post-Quantum Hybrid Operations ---");
            let iterations = 1000;

            // KEM Keygen
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = HybridKemKeyPair::generate();
            }
            let kem_keygen_dur = start.elapsed();
            println!("Hybrid KEM KeyGen:       {:?} per op", kem_keygen_dur / iterations);

            // KEM Encapsulate
            let receiver = HybridKemKeyPair::generate();
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = encapsulate_hybrid(&receiver.public_key);
            }
            let kem_encap_dur = start.elapsed();
            println!("Hybrid KEM Encapsulate:  {:?} per op", kem_encap_dur / iterations);

            // KEM Decapsulate
            let (ct, _) = encapsulate_hybrid(&receiver.public_key);
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = decapsulate_hybrid(&ct, &receiver.secret_key);
            }
            let kem_decap_dur = start.elapsed();
            println!("Hybrid KEM Decapsulate:  {:?} per op", kem_decap_dur / iterations);

            // Signature Sign
            let signer = HybridSigKeyPair::generate();
            let msg = b"benchmark payload";
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = sign_hybrid(msg, &signer.secret_key);
            }
            let sig_sign_dur = start.elapsed();
            println!("Hybrid Sig Sign:         {:?} per op", sig_sign_dur / iterations);

            // Signature Verify
            let sig = sign_hybrid(msg, &signer.secret_key);
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = verify_hybrid(msg, &sig, &signer.public_key);
            }
            let sig_verify_dur = start.elapsed();
            println!("Hybrid Sig Verify:       {:?} per op", sig_verify_dur / iterations);

            // AEAD ChaCha20-Poly1305 (1 KB payload)
            let key = [0x42u8; 32];
            let cipher = AeadCipher::new(&key);
            let payload_1kb = vec![0x37u8; 1024];
            let aad = b"seq-benchmark";
            let aead_iters = 10_000;

            let start = Instant::now();
            for i in 0..aead_iters {
                let _ = cipher.encrypt(i as u64, aad, &payload_1kb);
            }
            let aead_enc_dur = start.elapsed();
            println!("AEAD Encrypt (1KB):      {:?} per op", aead_enc_dur / aead_iters);

            let encrypted_1kb = cipher.encrypt(1, aad, &payload_1kb).unwrap();
            let start = Instant::now();
            for _ in 0..aead_iters {
                let _ = cipher.decrypt(1, aad, &encrypted_1kb);
            }
            let aead_dec_dur = start.elapsed();
            println!("AEAD Decrypt (1KB):      {:?} per op", aead_dec_dur / aead_iters);
        }
        Commands::Tunnel => {
            println!("=== Post-Quantum Hybrid Gateway: Tunnel Simulation ===");

            // 1. Setup Identities
            println!("[Step 1] Initializing client and server long-term cryptographic identities...");
            let client_sig = HybridSigKeyPair::generate();
            let server_sig = HybridSigKeyPair::generate();

            // 2. Handshake Phase
            println!("[Step 2] Performing ML-KEM-768 / X25519 authenticated key exchange...");
            let client_ephemeral_kem = HybridKemKeyPair::generate();
            let client_nonce = [0x55u8; 16];
            let init_msg = HandshakeInit::create(client_ephemeral_kem.public_key, client_nonce, &client_sig.secret_key);

            let (kem_ct, server_shared_secret) = encapsulate_hybrid(&init_msg.ephemeral_pk);
            let server_nonce = [0xAAu8; 16];
            let resp_msg = HandshakeResponse::create(kem_ct.clone(), server_nonce, &server_sig.secret_key);

            assert!(resp_msg.verify(&server_sig.public_key), "Server handshake verification failed");
            let client_shared_secret = decapsulate_hybrid(&resp_msg.ciphertext, &client_ephemeral_kem.secret_key);
            assert_eq!(client_shared_secret, server_shared_secret, "KEM shared secret mismatch");

            // 3. Derive Session Keys
            let transcript = hash_transcript(&[&init_msg.to_bytes(), &resp_msg.to_bytes()]);
            let client_keys = derive_session_keys(&client_shared_secret, &transcript);
            let server_keys = derive_session_keys(&server_shared_secret, &transcript);

            let mut client_session = Session::new_client();
            let mut server_session = Session::new_server();
            client_session.establish(&client_keys).expect("Client session establish failed");
            server_session.establish(&server_keys).expect("Server session establish failed");

            println!("[+] Handshake complete. Tunnel session active.");
            println!("    - Session ID: {}", client_session.session_id());
            println!("    - Client Role: {}, Server Role: {}", client_session.role(), server_session.role());

            // 4. Bidirectional Stream Framing & Traffic
            println!("[Step 3] Streaming bidirectional application data over ChaCha20-Poly1305...");
            let mut client_decoder = FrameDecoder::new();
            let mut server_decoder = FrameDecoder::new();

            let messages = [
                "GET /api/v1/quantum-secure-telemetry HTTP/1.1",
                "Host: pqc-gateway.internal",
                "User-Agent: pqc-tunnel-client/0.1.0",
                "Authorization: Bearer PQC-HYBRID-TOKEN-OK",
            ];

            for msg in &messages {
                let frame = client_session.encrypt_packet(PacketType::Data, msg.as_bytes()).unwrap();
                server_decoder.feed(&frame.encode());
                let rx_frame = server_decoder.decode_frame().unwrap().unwrap();
                let decrypted = server_session.decrypt_packet(&rx_frame).unwrap();
                println!("    [Client -> Server] (seq={}): {}", rx_frame.seq(), String::from_utf8_lossy(&decrypted));
            }

            // Server responds
            let server_reply = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPost-Quantum Encrypted Tunnel Active";
            let resp_frame = server_session.encrypt_packet(PacketType::Data, server_reply).unwrap();
            client_decoder.feed(&resp_frame.encode());
            let rx_resp_frame = client_decoder.decode_frame().unwrap().unwrap();
            let decrypted_resp = client_session.decrypt_packet(&rx_resp_frame).unwrap();
            println!("    [Server -> Client] (seq={}): {}", rx_resp_frame.seq(), String::from_utf8_lossy(&decrypted_resp));

            // 5. Keepalive Ping/Pong
            println!("[Step 4] Sending keepalive ping frame...");
            let ping_frame = client_session.create_ping(123456789).unwrap();
            server_decoder.feed(&ping_frame.encode());
            let rx_ping = server_decoder.decode_frame().unwrap().unwrap();
            let ping_ts = server_session.handle_ping(&rx_ping).unwrap();
            println!("    [+] Server received verified ping with timestamp: {}", ping_ts);

            // 6. Graceful Teardown & Metrics
            client_session.close();
            server_session.close();
            println!("[Step 5] Tunnel session closed gracefully.");
            println!("    - Client Metrics: TX Packets={}, TX Bytes={}, RX Packets={}, RX Bytes={}",
                client_session.metrics().tx_packets, client_session.metrics().tx_bytes,
                client_session.metrics().rx_packets, client_session.metrics().rx_bytes
            );
            println!("    - Server Metrics: TX Packets={}, TX Bytes={}, RX Packets={}, RX Bytes={}",
                server_session.metrics().tx_packets, server_session.metrics().tx_bytes,
                server_session.metrics().rx_packets, server_session.metrics().rx_bytes
            );
            println!("=== Tunnel Simulation Succeeded ===");
        }
    }
}


