use pqcrypto_kyber::kyber768::{
    decapsulate, encapsulate, keypair, Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::kdf::derive_hybrid_shared_secret;

pub const X25519_KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct HybridKemPublicKey {
    pub x25519_pk: [u8; X25519_KEY_SIZE],
    pub kyber_pk: KyberPublicKey,
}

impl PartialEq for HybridKemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.x25519_pk == other.x25519_pk && self.kyber_pk.as_bytes() == other.kyber_pk.as_bytes()
    }
}

impl Eq for HybridKemPublicKey {}

impl std::fmt::Debug for HybridKemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKemPublicKey")
            .field("x25519_pk", &self.x25519_pk)
            .field("kyber_pk_len", &self.kyber_pk.as_bytes().len())
            .finish()
    }
}

impl HybridKemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(X25519_KEY_SIZE + self.kyber_pk.as_bytes().len());
        bytes.extend_from_slice(&self.x25519_pk);
        bytes.extend_from_slice(self.kyber_pk.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < X25519_KEY_SIZE {
            return Err("Byte slice too short for HybridKemPublicKey".to_string());
        }
        let mut x25519_pk = [0u8; X25519_KEY_SIZE];
        x25519_pk.copy_from_slice(&bytes[..X25519_KEY_SIZE]);

        let kyber_pk = KyberPublicKey::from_bytes(&bytes[32..])
            .map_err(|e| format!("Failed to parse Kyber public key: {:?}", e))?;

        Ok(Self {
            x25519_pk,
            kyber_pk,
        })
    }
}

pub struct HybridKemSecretKey {
    pub x25519_sk: [u8; X25519_KEY_SIZE],
    pub kyber_sk: KyberSecretKey,
}

impl Drop for HybridKemSecretKey {
    fn drop(&mut self) {
        self.x25519_sk.zeroize();
    }
}

pub struct HybridKemKeyPair {
    pub public_key: HybridKemPublicKey,
    pub secret_key: HybridKemSecretKey,
}

#[derive(Clone)]
pub struct HybridKemCiphertext {
    pub x25519_ephemeral_pk: [u8; X25519_KEY_SIZE],
    pub kyber_ct: KyberCiphertext,
}

impl PartialEq for HybridKemCiphertext {
    fn eq(&self, other: &Self) -> bool {
        self.x25519_ephemeral_pk == other.x25519_ephemeral_pk
            && self.kyber_ct.as_bytes() == other.kyber_ct.as_bytes()
    }
}

impl Eq for HybridKemCiphertext {}

impl std::fmt::Debug for HybridKemCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKemCiphertext")
            .field("x25519_ephemeral_pk", &self.x25519_ephemeral_pk)
            .field("kyber_ct_len", &self.kyber_ct.as_bytes().len())
            .finish()
    }
}




impl HybridKemCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(X25519_KEY_SIZE + self.kyber_ct.as_bytes().len());
        bytes.extend_from_slice(&self.x25519_ephemeral_pk);
        bytes.extend_from_slice(self.kyber_ct.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < X25519_KEY_SIZE {
            return Err("Byte slice too short for HybridKemCiphertext".to_string());
        }
        let mut x25519_ephemeral_pk = [0u8; X25519_KEY_SIZE];
        x25519_ephemeral_pk.copy_from_slice(&bytes[..X25519_KEY_SIZE]);

        let kyber_ct = KyberCiphertext::from_bytes(&bytes[32..])
            .map_err(|e| format!("Failed to parse Kyber ciphertext: {:?}", e))?;

        Ok(Self {
            x25519_ephemeral_pk,
            kyber_ct,
        })
    }
}

impl HybridKemKeyPair {
    pub fn generate() -> Self {
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let (kyber_pk, kyber_sk) = keypair();

        Self {
            public_key: HybridKemPublicKey {
                x25519_pk: *x25519_pk.as_bytes(),
                kyber_pk,
            },
            secret_key: HybridKemSecretKey {
                x25519_sk: x25519_sk.to_bytes(),
                kyber_sk,
            },
        }
    }
}

/// Encapsulates a hybrid shared secret using peer's ML-KEM-768 and X25519 public keys.
/// Returns the composite ciphertext and a 32-byte master shared secret derived via HKDF-SHA256.
pub fn encapsulate_hybrid(
    peer_pk: &HybridKemPublicKey,
) -> (HybridKemCiphertext, [u8; 32]) {
    let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);

    let peer_x25519_pk = X25519PublicKey::from(peer_pk.x25519_pk);
    let classical_ss = ephemeral_sk.diffie_hellman(&peer_x25519_pk);

    let (kyber_ss, kyber_ct) = encapsulate(&peer_pk.kyber_pk);

    let hybrid_ss = derive_hybrid_shared_secret(classical_ss.as_bytes(), kyber_ss.as_bytes());

    let ciphertext = HybridKemCiphertext {
        x25519_ephemeral_pk: *ephemeral_pk.as_bytes(),
        kyber_ct,
    };

    (ciphertext, hybrid_ss)
}

/// Decapsulates a composite ciphertext using the recipient's ML-KEM-768 and X25519 secret keys.
/// Returns the matching 32-byte master shared secret.
pub fn decapsulate_hybrid(
    ciphertext: &HybridKemCiphertext,
    sk: &HybridKemSecretKey,
) -> [u8; 32] {
    let static_sk = StaticSecret::from(sk.x25519_sk);
    let ephemeral_pk = X25519PublicKey::from(ciphertext.x25519_ephemeral_pk);
    let classical_ss = static_sk.diffie_hellman(&ephemeral_pk);

    let kyber_ss = decapsulate(&ciphertext.kyber_ct, &sk.kyber_sk);

    derive_hybrid_shared_secret(classical_ss.as_bytes(), kyber_ss.as_bytes())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_serialization() {
        let pair = HybridKemKeyPair::generate();
        let bytes = pair.public_key.to_bytes();
        let decoded = HybridKemPublicKey::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(pair.public_key, decoded);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let pair = HybridKemKeyPair::generate();
        let (ct, _) = encapsulate_hybrid(&pair.public_key);
        let bytes = ct.to_bytes();
        let decoded = HybridKemCiphertext::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(ct, decoded);
    }

    #[test]
    fn test_deserialization_truncated_inputs() {
        let short_bytes = [0u8; 16];
        assert!(HybridKemPublicKey::from_bytes(&short_bytes).is_err());
        assert!(HybridKemCiphertext::from_bytes(&short_bytes).is_err());
    }
}


