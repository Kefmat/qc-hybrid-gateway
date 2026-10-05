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
* **Stream Codec**: Incremental buffer frame parser (`FrameDecoder`) supporting chunked streaming and multi-frame processing.
* **Session State Machine**: Comprehensive lifecycle tracking (`Session`, `SessionRole`, `SessionState`) with sequence counters and rekey triggers.
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

## Session State Machine & Lifecycle

The `Session` engine manages tunnel state transitions across the connection lifecycle:

```text
+-------------------+
|   Uninitialized   |
+---------+---------+
          | (establish)
          v
+-------------------+       trigger_rekey()      +-------------------+
|    Established    | -------------------------> |     Rekeying      |
| (encrypt/decrypt) | <------------------------- | (complete_rekey)  |
+---------+---------+                            +-------------------+
          |
          | close()
          v
+-------------------+
|      Closed       |
+-------------------+
```

- **Uninitialized**: Session allocated with defined role (`Client` or `Server`), ciphers unset.
- **Established**: Keys established, sequence numbers active, anti-replay active, data encryption/decryption permitted.
- **Rekeying**: Transition state during key rotation before completing with new `SessionKeys`.
- **Closed**: Terminated session with ciphers zeroized and wiped from memory.

---

## Directory Structure

```text
pqc-hybrid-gateway/
├── Cargo.toml
├── README.md
├── .gitignore
└── src/
    ├── lib.rs              # Core library exports and integration test suite
    ├── main.rs             # CLI interface (keygen, verify, bench)
    ├── crypto/
    │   ├── mod.rs          # Crypto subsystem declarations
    │   ├── kem.rs          # ML-KEM-768 + X25519 Hybrid Key Encapsulation
    │   ├── sig.rs          # ML-DSA-65 + Ed25519 Hybrid Signatures
    │   ├── aead.rs         # ChaCha20-Poly1305 Authenticated Encryption
    │   └── kdf.rs          # HKDF-SHA256 Transcript Binding & Session Derivation
    ├── protocol/
    │   ├── mod.rs          # Wire framing (PacketHeader, PacketFrame) and anti-replay filter
    │   ├── handshake.rs    # HandshakeInit and HandshakeResponse messages
    │   └── codec.rs        # FrameDecoder stream codec helper
    └── session/
        └── mod.rs          # Session state machine, rekeying, and bidirectional traffic
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

### Interactive Tunnel Simulation
Simulate a complete end-to-end client-server handshake, streaming frame exchange, keepalive ping/pong, and telemetry reporting:
```bash
cargo run -- tunnel
```

### Micro-benchmarks
Benchmark the cryptographic primitives (KEM Keygen/Encap/Decap, Signature Sign/Verify, ChaCha20-Poly1305 AEAD Encrypt/Decrypt) locally:
```bash
cargo run --release -- bench
```


---

## Protocol Handshake & Transport Lifecycle

1. **Client Initiation**: The client generates an ephemeral hybrid KEM keypair and transmits a signed `HandshakeInit` message with a nonce.
2. **Server Authentication**: The server encapsulates a shared secret against the client's public key, signs the ciphertext and nonce with its composite identity key (`ML-DSA-65` + `Ed25519`), and returns a `HandshakeResponse`.
3. **Transcript Hash & Key Derivation**: Both peers compute `SHA-256` over the handshake transcript and derive unidirectional AEAD session write keys via `HKDF-SHA256`.
4. **Encrypted Transport**: Application data is packaged into `Data` frames, encrypted using `ChaCha20-Poly1305` with sequential nonce counters and validated against sliding-window anti-replay filters.
5. **Periodic Rekeying**: Upon reaching threshold packet counts, sessions transition through `Rekeying` to rotate session keys without dropping connectivity.

---

## Security & Implementation Notes

- **Zeroization**: All private keys (`HybridKemSecretKey`, `HybridSigSecretKey`, `SessionKeys`) automatically zeroize underlying memory on drop.
- **Transcript Binding**: All derived session keys are strictly bound to ephemeral exchange transcripts via HKDF-SHA256.
- **Anti-Replay Window**: Uses configurable sliding-window bitmask verification (default window: 64 packets) to prevent packet replay attacks.
- **Memory Safety & Invariants**: All frame lengths and header fields are strictly bounded by `MAX_FRAME_SIZE` (64 KB) with checked constructors.
