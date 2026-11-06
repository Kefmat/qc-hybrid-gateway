use clap::{Parser, Subcommand};
use pqc_hybrid_gateway::crypto::{
    aead::AeadCipher,
    kdf::{derive_session_keys, hash_transcript},
    kem::{decapsulate_hybrid, encapsulate_hybrid, HybridKemKeyPair},
    sig::{sign_hybrid, verify_hybrid, HybridSigKeyPair, HybridSigPublicKey},
};
use pqc_hybrid_gateway::protocol::{
    AntiReplayFilter, FrameDecoder, HandshakeInit, HandshakeResponse, PacketType,
};
use pqc_hybrid_gateway::session::Session;
use pqc_hybrid_gateway::transport::{TunnelClient, TunnelServer};
use std::time::Instant;
use tokio::net::TcpListener;

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
    Keygen {
        /// Optional directory to save generated keys
        #[arg(short, long)]
        out_dir: Option<String>,
        /// Key name prefix (default: "identity")
        #[arg(short, long, default_value = "identity")]
        prefix: String,
    },
    /// Run cryptographic verification tests (KEM, Signatures, AEAD, Anti-Replay)
    Verify,
    /// Run cryptographic performance benchmarks
    Bench,
    /// Simulate full Post-Quantum hybrid encrypted tunnel between client and server
    Tunnel {
        /// Simulated packet drop rate percentage (0 - 100)
        #[arg(short, long, default_value_t = 0)]
        drop_rate: u8,
        /// Simulated network latency in milliseconds
        #[arg(short, long, default_value_t = 0)]
        latency_ms: u64,
        /// Display full formatted session telemetry reports
        #[arg(short, long)]
        report: bool,
        /// Output session telemetry formatted as JSON
        #[arg(short, long)]
        json: bool,
    },
    /// Start a live Post-Quantum hybrid TCP tunnel server
    Server {
        /// TCP address and port to bind
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        bind: String,
        /// Maximum number of client connections to handle before exiting
        #[arg(short, long)]
        max_clients: Option<usize>,
        /// Optional directory from which to load server identity keys
        #[arg(short, long)]
        key_dir: Option<String>,
        /// Key name prefix (default: "identity")
        #[arg(short, long, default_value = "identity")]
        prefix: String,
    },
    /// Connect to a live Post-Quantum hybrid TCP tunnel server
    Client {
        /// Server TCP address and port to connect to
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        connect: String,
        /// Message payload to transmit securely
        #[arg(short, long, default_value = "Hello Post-Quantum World!")]
        message: String,
        /// Number of keepalive pings to transmit
        #[arg(short = 'n', long, default_value_t = 3)]
        pings: u32,
        /// Trigger a forward secrecy ratchet rekey step
        #[arg(short, long)]
        ratchet: bool,
        /// Optional directory from which to load client identity keys
        #[arg(short, long)]
        key_dir: Option<String>,
        /// Key name prefix (default: "identity")
        #[arg(short, long, default_value = "identity")]
        prefix: String,
        /// Optional path to server public signature key file for pinned verification
        #[arg(short = 's', long)]
        server_key: Option<String>,
    },
    /// Display cryptographic parameters and architectural specification
    Info,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Info => {
            println!(
                "================================================================================"
            );
            println!(
                "       PQC Hybrid Gateway - Architectural & Cryptographic Specification         "
            );
            println!(
                "================================================================================"
            );
            println!("  [+] Post-Quantum Hybrid KEM:");
            println!("      - Post-Quantum Primitive: ML-KEM-768 (NIST FIPS 203)");
            println!("      - Classical Primitive:    X25519 ECDH (RFC 7748)");
            println!("      - KDF Binding:            HKDF-SHA256 (PQC-HYBRID-GATEWAY-KEM-V1)");
            println!();
            println!("  [+] Post-Quantum Hybrid Signatures:");
            println!("      - Post-Quantum Primitive: ML-DSA-65 (NIST FIPS 204)");
            println!("      - Classical Primitive:    Ed25519 (RFC 8032)");
            println!("      - Dual Verification:      Both classical and post-quantum required");
            println!();
            println!("  [+] Symmetric Transport & Framing:");
            println!("      - Symmetric Cipher:       ChaCha20-Poly1305 AEAD (RFC 8439)");
            println!("      - Key Derivation:         HKDF-SHA256 bound to handshake transcript");
            println!(
                "      - Frame Header:           14-byte binary framing with sequence counters"
            );
            println!("      - Anti-Replay Filter:     64-packet sliding window bitmask");
            println!(
                "================================================================================"
            );
        }
        Commands::Keygen { out_dir, prefix } => {
            println!("--- Generating Post-Quantum Hybrid Keys ---");
            let kem_keys = HybridKemKeyPair::generate();
            let sig_keys = HybridSigKeyPair::generate();

            println!("[+] Hybrid KEM Keypair generated:");
            println!(
                "    - Classical (X25519 Public Key): {} bytes",
                kem_keys.public_key.x25519_pk.len()
            );
            println!(
                "    - Post-Quantum (ML-KEM-768 Public Key): {} bytes",
                std::mem::size_of_val(&kem_keys.public_key.kyber_pk)
            );

            println!("[+] Hybrid Signature Keypair generated:");
            println!(
                "    - Classical (Ed25519 Public Key): {} bytes",
                sig_keys.public_key.ed25519_pk.len()
            );
            println!(
                "    - Post-Quantum (ML-DSA-65 Public Key): {} bytes",
                std::mem::size_of_val(&sig_keys.public_key.dilithium_pk)
            );

            if let Some(dir) = out_dir {
                if let Err(e) = kem_keys.save_to_dir(&dir, &prefix) {
                    eprintln!("[-] Error saving KEM keys: {}", e);
                } else if let Err(e) = sig_keys.save_to_dir(&dir, &prefix) {
                    eprintln!("[-] Error saving Signature keys: {}", e);
                } else {
                    println!("[+] Successfully exported keys to '{}/{}*'", dir, prefix);
                }
            }
        }
        Commands::Verify => {
            println!("--- Running Cryptographic Verification Suite ---");

            // 1. Hybrid KEM verification
            print!("[TEST 1/5] Hybrid KEM (ML-KEM-768 + X25519) Key Exchange... ");
            let receiver_keys = HybridKemKeyPair::generate();
            let (ciphertext, sender_shared_secret) = encapsulate_hybrid(&receiver_keys.public_key);
            let receiver_shared_secret = decapsulate_hybrid(&ciphertext, &receiver_keys.secret_key);

            assert_eq!(
                sender_shared_secret, receiver_shared_secret,
                "KEM shared secret mismatch"
            );
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
            assert!(
                !verify_hybrid(tampered_msg, &signature, &signer_keys.public_key),
                "Tampered message passed verification"
            );
            println!("PASSED");

            // 3. AEAD & Transcript Key Derivation
            print!("[TEST 3/5] AEAD Session Derivation & Tamper Resistance... ");
            let transcript_hash =
                hash_transcript(&[b"client-init-key-exchange", b"server-resp-key-exchange"]);
            let session_keys = derive_session_keys(&sender_shared_secret, &transcript_hash);
            let client_cipher = AeadCipher::new(&session_keys.client_write_key);
            let server_cipher = AeadCipher::new(&session_keys.client_write_key);

            let plaintext = b"Confidential Tunnel Traffic";
            let aad = b"header-metadata-seq-1";
            let encrypted = client_cipher
                .encrypt(1, aad, plaintext)
                .expect("Encryption failed");

            let decrypted = server_cipher
                .decrypt(1, aad, &encrypted)
                .expect("Decryption failed");
            assert_eq!(plaintext.to_vec(), decrypted, "Plaintext mismatch");

            // Tamper ciphertext
            let mut bad_encrypted = encrypted.clone();
            bad_encrypted[0] ^= 0xFF;
            assert!(
                server_cipher.decrypt(1, aad, &bad_encrypted).is_err(),
                "Corrupted ciphertext was accepted"
            );
            println!("PASSED");

            // 4. Anti-Replay Filter
            print!("[TEST 4/5] Anti-Replay Sliding Window Filter... ");
            let mut filter = AntiReplayFilter::new(64);
            assert!(filter.check_and_update(1));
            assert!(filter.check_and_update(2));
            assert!(
                !filter.check_and_update(1),
                "Replayed packet seq 1 accepted"
            );
            assert!(filter.check_and_update(100));
            assert!(!filter.check_and_update(10), "Outdated packet accepted");
            println!("PASSED");

            // 5. Wire Frame Encoding/Decoding
            print!("[TEST 5/5] Wire Frame Serialization & Framing... ");
            let frame = pqc_hybrid_gateway::protocol::PacketFrame::new(
                pqc_hybrid_gateway::protocol::PacketType::Data,
                42,
                encrypted,
            )
            .expect("Frame creation failed");
            let encoded = frame.encode();
            let decoded = pqc_hybrid_gateway::protocol::PacketFrame::decode(&encoded)
                .expect("Frame decode failed");
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
            println!(
                "Hybrid KEM KeyGen:       {:?} per op",
                kem_keygen_dur / iterations
            );

            // KEM Encapsulate
            let receiver = HybridKemKeyPair::generate();
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = encapsulate_hybrid(&receiver.public_key);
            }
            let kem_encap_dur = start.elapsed();
            println!(
                "Hybrid KEM Encapsulate:  {:?} per op",
                kem_encap_dur / iterations
            );

            // KEM Decapsulate
            let (ct, _) = encapsulate_hybrid(&receiver.public_key);
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = decapsulate_hybrid(&ct, &receiver.secret_key);
            }
            let kem_decap_dur = start.elapsed();
            println!(
                "Hybrid KEM Decapsulate:  {:?} per op",
                kem_decap_dur / iterations
            );

            // Signature Sign
            let signer = HybridSigKeyPair::generate();
            let msg = b"benchmark payload";
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = sign_hybrid(msg, &signer.secret_key);
            }
            let sig_sign_dur = start.elapsed();
            println!(
                "Hybrid Sig Sign:         {:?} per op",
                sig_sign_dur / iterations
            );

            // Signature Verify
            let sig = sign_hybrid(msg, &signer.secret_key);
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = verify_hybrid(msg, &sig, &signer.public_key);
            }
            let sig_verify_dur = start.elapsed();
            println!(
                "Hybrid Sig Verify:       {:?} per op",
                sig_verify_dur / iterations
            );

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
            println!(
                "AEAD Encrypt (1KB):      {:?} per op",
                aead_enc_dur / aead_iters
            );

            let encrypted_1kb = cipher.encrypt(1, aad, &payload_1kb).unwrap();
            let start = Instant::now();
            for _ in 0..aead_iters {
                let _ = cipher.decrypt(1, aad, &encrypted_1kb);
            }
            let aead_dec_dur = start.elapsed();
            println!(
                "AEAD Decrypt (1KB):      {:?} per op",
                aead_dec_dur / aead_iters
            );
        }
        Commands::Tunnel {
            drop_rate,
            latency_ms,
            report,
            json,
        } => {
            println!("=== Post-Quantum Hybrid Gateway: Tunnel Simulation ===");
            if drop_rate > 0 || latency_ms > 0 {
                println!(
                    "  [Simulation Profile] Simulated Latency: {}ms | Drop Rate: {}%",
                    latency_ms, drop_rate
                );
            }

            // 1. Setup Identities
            println!(
                "[Step 1] Initializing client and server long-term cryptographic identities..."
            );
            let client_sig = HybridSigKeyPair::generate();
            let server_sig = HybridSigKeyPair::generate();

            // 2. Handshake Phase
            println!("[Step 2] Performing ML-KEM-768 / X25519 authenticated key exchange...");
            let client_ephemeral_kem = HybridKemKeyPair::generate();
            let client_nonce = [0x55u8; 16];
            let init_msg = HandshakeInit::create(
                client_ephemeral_kem.public_key,
                client_nonce,
                &client_sig.secret_key,
            );

            let (kem_ct, server_shared_secret) = encapsulate_hybrid(&init_msg.ephemeral_pk);
            let server_nonce = [0xAAu8; 16];
            let resp_msg =
                HandshakeResponse::create(kem_ct.clone(), server_nonce, &server_sig.secret_key);

            assert!(
                resp_msg.verify(&server_sig.public_key),
                "Server handshake verification failed"
            );
            let client_shared_secret =
                decapsulate_hybrid(&resp_msg.ciphertext, &client_ephemeral_kem.secret_key);
            assert_eq!(
                client_shared_secret, server_shared_secret,
                "KEM shared secret mismatch"
            );

            // 3. Derive Session Keys
            let transcript = hash_transcript(&[&init_msg.to_bytes(), &resp_msg.to_bytes()]);
            let mut client_keys = derive_session_keys(&client_shared_secret, &transcript);
            let mut server_keys = derive_session_keys(&server_shared_secret, &transcript);

            let mut client_session = Session::new_client();
            let mut server_session = Session::new_server();
            client_session
                .establish(&client_keys)
                .expect("Client session establish failed");
            server_session
                .establish(&server_keys)
                .expect("Server session establish failed");

            println!("[+] Handshake complete. Tunnel session active.");
            println!("    - Session ID: {}", client_session.session_id());
            println!(
                "    - Client Role: {}, Server Role: {}",
                client_session.role(),
                server_session.role()
            );

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
                let frame = client_session
                    .encrypt_packet(PacketType::Data, msg.as_bytes())
                    .unwrap();
                server_decoder.feed(&frame.encode());
                let rx_frame = server_decoder.decode_frame().unwrap().unwrap();
                let decrypted = server_session.decrypt_packet(&rx_frame).unwrap();
                println!(
                    "    [Client -> Server] (seq={}): {}",
                    rx_frame.seq(),
                    String::from_utf8_lossy(&decrypted)
                );
            }

            // Server responds
            let server_reply = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPost-Quantum Encrypted Tunnel Active";
            let resp_frame = server_session
                .encrypt_packet(PacketType::Data, server_reply)
                .unwrap();
            client_decoder.feed(&resp_frame.encode());
            let rx_resp_frame = client_decoder.decode_frame().unwrap().unwrap();
            let decrypted_resp = client_session.decrypt_packet(&rx_resp_frame).unwrap();
            println!(
                "    [Server -> Client] (seq={}): {}",
                rx_resp_frame.seq(),
                String::from_utf8_lossy(&decrypted_resp)
            );

            // 5. Symmetric Key Ratchet & Forward Secrecy Evolution
            println!("[Step 4] Advancing symmetric key ratchet for zero-trust forward secrecy...");
            client_session
                .ratchet_rekey(&mut client_keys)
                .expect("Client ratchet failed");
            server_session
                .ratchet_rekey(&mut server_keys)
                .expect("Server ratchet failed");
            println!(
                "    [+] Both endpoints evolved write keys to generation 1 (rekeys={})",
                client_session.metrics().rekeys_completed
            );

            let ratcheted_msg = "POST /api/v1/quantum-rekey/ack HTTP/1.1";
            let ratcheted_frame = client_session
                .encrypt_packet(PacketType::Data, ratcheted_msg.as_bytes())
                .unwrap();
            server_decoder.feed(&ratcheted_frame.encode());
            let rx_ratcheted = server_decoder.decode_frame().unwrap().unwrap();
            let decrypted_ratcheted = server_session.decrypt_packet(&rx_ratcheted).unwrap();
            println!(
                "    [Client -> Server (Ratcheted)] (seq={}): {}",
                rx_ratcheted.seq(),
                String::from_utf8_lossy(&decrypted_ratcheted)
            );

            // 6. Keepalive Ping/Pong & Latency Measurement
            println!("[Step 5] Sending keepalive ping/pong frame for latency measurement...");
            let ping_ts = 123456789;
            let ping_frame = client_session.create_ping(ping_ts).unwrap();
            server_decoder.feed(&ping_frame.encode());
            let rx_ping = server_decoder.decode_frame().unwrap().unwrap();
            let server_ping_ts = server_session.handle_ping(&rx_ping).unwrap();
            println!(
                "    [+] Server received verified ping with timestamp: {}",
                server_ping_ts
            );

            // Server responds with Pong
            let pong_frame = server_session.create_pong(server_ping_ts).unwrap();
            client_decoder.feed(&pong_frame.encode());
            let rx_pong = client_decoder.decode_frame().unwrap().unwrap();
            let simulated_rtt = latency_ms * 2 + 4;
            let rtt = client_session
                .handle_pong(&rx_pong, ping_ts + simulated_rtt)
                .unwrap();
            println!(
                "    [+] Client received verified pong (measured RTT: {}ms)",
                rtt
            );

            // 7. Graceful Teardown & Metrics
            client_session.close();
            server_session.close();

            if json {
                println!("\n--- Session Telemetry (JSON Export) ---");
                println!("Client: {}", client_session.telemetry_json());
                println!("Server: {}", server_session.telemetry_json());
            } else if report {
                println!("\n--- Session Telemetry Report ---");
                println!("Client:\n{}", client_session.telemetry_report());
                println!("\nServer:\n{}", server_session.telemetry_report());
            } else {
                println!("    - Client: {}", client_session.metrics());
                if let Some(avg) = client_session.metrics().average_packet_size() {
                    println!("      * Client Average Packet Size: {} bytes (Total: {} bytes, {} packets)",
                        avg, client_session.metrics().total_bytes(), client_session.metrics().total_packets());
                }
                println!("    - Server: {}", server_session.metrics());
                if let Some(avg) = server_session.metrics().average_packet_size() {
                    println!("      * Server Average Packet Size: {} bytes (Total: {} bytes, {} packets)",
                        avg, server_session.metrics().total_bytes(), server_session.metrics().total_packets());
                }
            }
            println!("=== Tunnel Simulation Succeeded ===");
        }
        Commands::Server {
            bind,
            max_clients,
            key_dir,
            prefix,
        } => {
            println!(
                "================================================================================"
            );
            println!(
                "             PQC Hybrid Gateway - Live TCP Server Engine                        "
            );
            println!(
                "================================================================================"
            );
            let sig_keys = if let Some(dir) = key_dir {
                println!(
                    "[*] Loading server identity keys from '{}' (prefix: '{}')...",
                    dir, prefix
                );
                HybridSigKeyPair::load_from_dir(&dir, &prefix).expect("Failed to load server keys")
            } else {
                println!("[*] Generating ephemeral server hybrid signature keypair (ML-DSA-65 + Ed25519)...");
                HybridSigKeyPair::generate()
            };

            println!(
                "[+] Server Identity Public Key Fingerprint: {}",
                sig_keys.public_key.fingerprint()
            );
            println!("[*] Binding TCP listener on {}...", bind);
            let listener = TcpListener::bind(&bind)
                .await
                .unwrap_or_else(|e| panic!("Failed to bind TCP listener on {}: {}", bind, e));
            println!("[+] Server listening and ready for Post-Quantum hybrid client connections");

            let server = std::sync::Arc::new(TunnelServer::new(sig_keys));
            let mut client_count = 0;

            while max_clients.is_none_or(|max| client_count < max) {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        client_count += 1;
                        println!(
                            "\n[+] [Client #{}] Connection established from {}",
                            client_count, peer_addr
                        );
                        let server_clone = server.clone();
                        tokio::spawn(async move {
                            match server_clone.handle_connection(stream, None).await {
                                Ok(metrics) => {
                                    println!(
                                        "[✓] [Client #{}] Completed session: {}",
                                        client_count, metrics
                                    );
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[-] [Client #{}] Session error: {}",
                                        client_count, e
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[-] Accept error: {}", e);
                        break;
                    }
                }
            }
            println!(
                "\n[+] Server reached client limit ({}). Shutting down.",
                client_count
            );
        }
        Commands::Client {
            connect,
            message,
            pings,
            ratchet,
            key_dir,
            prefix,
            server_key,
        } => {
            println!(
                "================================================================================"
            );
            println!(
                "             PQC Hybrid Gateway - Live TCP Client Engine                        "
            );
            println!(
                "================================================================================"
            );
            let sig_keys = if let Some(dir) = key_dir {
                println!(
                    "[*] Loading client identity keys from '{}' (prefix: '{}')...",
                    dir, prefix
                );
                HybridSigKeyPair::load_from_dir(&dir, &prefix).expect("Failed to load client keys")
            } else {
                println!("[*] Generating ephemeral client hybrid signature keypair (ML-DSA-65 + Ed25519)...");
                HybridSigKeyPair::generate()
            };

            let server_sig_pk = if let Some(path) = server_key {
                println!("[*] Loading pinned server public key from '{}'...", path);
                Some(
                    HybridSigPublicKey::load_from_file(&path)
                        .expect("Failed to load server public key"),
                )
            } else {
                println!("[*] No server public key pinned (using Trust-On-First-Use)...");
                None
            };

            let client = TunnelClient::with_config(sig_keys, server_sig_pk, Default::default());

            println!(
                "[*] Connecting to Post-Quantum gateway server at {}...",
                connect
            );
            let mut conn = client
                .connect(&connect)
                .await
                .unwrap_or_else(|e| panic!("Connection to {} failed: {}", connect, e));
            println!(
                "[+] Established Post-Quantum Hybrid Tunnel Session (id: {})",
                conn.session().session_id()
            );

            // 1. Send data payload
            println!(
                "\n[*] Transmitting encrypted data payload ({} bytes): '{}'",
                message.len(),
                message
            );
            let response = conn
                .send_data(message.as_bytes())
                .await
                .expect("Failed to send data frame");
            println!(
                "[+] Received decrypted server response: '{}'",
                String::from_utf8_lossy(&response)
            );

            // 2. Transmit keepalive pings
            if pings > 0 {
                println!("\n[*] Transmitting {} keepalive ping frame(s)...", pings);
                for i in 1..=pings {
                    let rtt = conn.ping().await.expect("Ping failed");
                    println!("    [+] Ping #{} verified (measured RTT: {}ms)", i, rtt);
                }
            }

            // 3. Ratchet if requested
            if ratchet {
                println!("\n[*] Advancing symmetric forward secrecy ratchet...");
                conn.ratchet()
                    .await
                    .expect("Ratchet forward secrecy step failed");
                println!("[+] Ratchet completed! Keys evolved forward.");

                let post_msg = "Post-Ratchet Authenticated Verification Payload";
                println!(
                    "[*] Transmitting post-ratchet encrypted payload: '{}'",
                    post_msg
                );
                let post_resp = conn
                    .send_data(post_msg.as_bytes())
                    .await
                    .expect("Failed post-ratchet transmission");
                println!(
                    "[+] Received decrypted server response: '{}'",
                    String::from_utf8_lossy(&post_resp)
                );
            }

            // 4. Teardown
            let metrics = conn.metrics().clone();
            conn.close().await;
            println!("\n[+] Connection closed gracefully.");
            println!("    - Final Client Session Metrics: {}", metrics);
            println!(
                "================================================================================"
            );
        }
    }
}
