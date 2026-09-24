# PQC Hybrid Gateway (`pqc-hybrid-gateway`)

A high-performance Post-Quantum Hybrid Cryptographic Gateway and Secure Tunnel engine written in Rust.

The gateway combines NIST-standardized Post-Quantum Cryptography (PQC) algorithms with battle-tested classical primitives in a dual-layer hybrid architecture, ensuring forward security against cryptographically relevant quantum computers (CRQCs) while maintaining classical compliance.

---

## Architectural Scope & Cryptographic Design

### 1. Hybrid Key Encapsulation (KEM)
* **Post-Quantum Primitive**: **ML-KEM-768** (NIST FIPS 203 / Kyber-768)
* **Classical Primitive**: **X25519 ECDH** (RFC 7748)
* **Key Derivation**: Ephemeral shared secrets from both mechanisms are concatenated and passed through **HKDF-SHA256** (`PQC-HYBRID-GATEWAY-KEM-V1`), ensuring the resulting master secret remains secure as long as *at least one* primitive remains unbroken.

### 2. Hybrid Signatures & Identity Provenance
* **Post-Quantum Primitive**: **ML-DSA-65** (NIST FIPS 204 / Dilithium3)
* **Classical Primitive**: **Ed25519** (RFC 8032)
* **Verification Semantics**: Dual-signature verification requiring both the Ed25519 and ML-DSA-65 signatures to validate successfully against the composite public key.

### 3. Symmetric Transport & Framing
* **Cipher**: **ChaCha20-Poly1305 AEAD** (RFC 8439)
* **Session Derivation**: Separate client-to-server and server-to-client unidirectional write keys derived from the master secret bound to the handshake transcript hash.
* **Wire Protocol Framing**: Versioned binary framing (`PacketFrame`, `PacketType`) with sequence indexing and payload bounds.
* **Anti-Replay Defense**: Sliding-window bitmask filter detecting replayed and out-of-order packets.
* **Memory Safety**: Automatic secret key zeroization on drop (`zeroize`).

---

## Directory Structure

```text
pqc-hybrid-gateway/
├── Cargo.toml
├── README.md
├── .gitignore
└── src/
    ├── lib.rs              # Core library exports and unit test suite
    ├── main.rs             # CLI interface (keygen, verify, bench)
    ├── crypto/
    │   ├── mod.rs          # Crypto subsystem declarations
    │   ├── kem.rs          # ML-KEM-768 + X25519 Hybrid Key Encapsulation
    │   ├── sig.rs          # ML-DSA-65 + Ed25519 Hybrid Signatures
    │   ├── aead.rs         # ChaCha20-Poly1305 Authenticated Encryption
    │   └── kdf.rs          # HKDF-SHA256 Transcript Binding & Session Derivation
    └── protocol/
        └── mod.rs          # Wire framing (PacketFrame) and sliding-window anti-replay filter
```

---

## Building and Running

### Prerequisites
* Rust toolchain (1.75+ recommended)
* Cargo package manager

### Run Unit Tests
```bash
cargo test
```

### Run Cryptographic Verification Suite
Runs full end-to-end verification of KEM exchange, signature validation, AEAD tamper detection, anti-replay protection, and wire framing:
```bash
cargo run -- verify
```

### Key Generation
Generate a sample pair of Hybrid KEM and Hybrid Signature public/private keys:
```bash
cargo run -- keygen
```

### Micro-benchmarks
Benchmark the cryptographic primitives (KEM Keygen/Encap/Decap, Signature Sign/Verify, ChaCha20-Poly1305 AEAD Encrypt/Decrypt) locally:
```bash
cargo run --release -- bench
```

---

## Security & Implementation Notes

- **Zeroization**: All private keys (`HybridKemSecretKey`, `HybridSigSecretKey`, `SessionKeys`) automatically zeroize underlying memory on drop.
- **Transcript Binding**: All derived session keys are strictly bound to ephemeral exchange transcripts via HKDF-SHA256.
- **Anti-Replay Window**: Uses configurable sliding-window bitmask verification (default window: 64 packets) to prevent packet replay attacks.

