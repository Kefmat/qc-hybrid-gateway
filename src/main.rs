use clap::{Parser, Subcommand};
use pqc_hybrid_gateway::crypto::{
    aead::AeadCipher,
    kdf::derive_session_keys,
    kem::{decapsulate_hybrid, encapsulate_hybrid, HybridKemKeyPair},
    sig::{sign_hybrid, verify_hybrid, HybridSigKeyPair},
};
use pqc_hybrid_gateway::protocol::AntiReplayFilter;
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
            print!("[TEST 1/4] Hybrid KEM (ML-KEM-768 + X25519) Key Exchange... ");
            let receiver_keys = HybridKemKeyPair::generate();
            let (ciphertext, sender_shared_secret) = encapsulate_hybrid(&receiver_keys.public_key);
            let receiver_shared_secret = decapsulate_hybrid(&ciphertext, &receiver_keys.secret_key);

            assert_eq!(sender_shared_secret, receiver_shared_secret, "KEM shared secret mismatch");
            println!("PASSED");

            // 2. Hybrid Signature verification
            print!("[TEST 2/4] Hybrid Signature (ML-DSA-65 + Ed25519) Sign & Verify... ");
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
            print!("[TEST 3/4] AEAD Session Derivation & Tamper Resistance... ");
            let transcript_hash = [0x42u8; 32];
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
            print!("[TEST 4/4] Anti-Replay Sliding Window Filter... ");
            let mut filter = AntiReplayFilter::new(64);
            assert!(filter.check_and_update(1));
            assert!(filter.check_and_update(2));
            assert!(!filter.check_and_update(1), "Replayed packet seq 1 accepted");
            assert!(filter.check_and_update(100));
            assert!(!filter.check_and_update(10), "Outdated packet accepted");
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
        }
    }
}
