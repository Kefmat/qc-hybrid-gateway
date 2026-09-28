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
* **Wire Protocol Framing**: Versioned binary framing (`PacketHeader`, `PacketFrame`, `PacketType`) with sequence indexing and payload bounds.
* **Anti-Replay Defense**: Sliding-window bitmask filter detecting replayed and out-of-order packets.
* **Memory Safety**: Automatic secret key zeroization on drop (`zeroize`).

---

## Cryptographic Parameters Summary

| Component | Classical Primitive | Post-Quantum Primitive | Combined Public Key | Ciphertext / Signature |
|:---|:---|:---|:---|:---|
| **Key Encapsulation** | X25519 (32 B) | ML-KEM-768 (1184 B) | 1216 bytes | 1120 bytes |
| **Digital Signatures** | Ed25519 (32 B) | ML-DSA-65 (1952 B) | 1984 bytes | 3357 bytes |
| **Symmetric AEAD** | ChaCha20-Poly1305 (32 B key, 12 B nonce, 16 B tag) | N/A (Quantum-resistant 256-bit key) | N/A | Variable + 16 B tag |

---

## Wire Protocol Frame Format

All network communication uses a fixed 14-byte binary header followed by the variable-length payload:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |  Packet Type  |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                    Sequence Number (64 bits)                  |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |       Payload Length (32 bits)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Data...                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Length | Type | Description |
|:---|:---|:---|:---|:---|
| `version` | 0 | 1 byte | `u8` | Protocol version (`0x01`) |
| `packet_type` | 1 | 1 byte | `u8` | `0x01` (HandshakeInit), `0x02` (HandshakeResp), `0x03` (Data), `0x04` (Ping) |
| `seq` | 2..10 | 8 bytes | `u64` (big-endian) | Monotonically increasing sequence counter |
| `payload_len` | 10..14 | 4 bytes | `u32` (big-endian) | Payload length in bytes (max 65536 bytes) |
| `payload` | 14.. | Variable | `[u8]` | Encrypted ciphertext or raw handshake payload |

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
        └── mod.rs          # Wire framing (PacketHeader, PacketFrame) and anti-replay filter
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


