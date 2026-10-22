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
    pub fn x25519_pk(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.x25519_pk
    }

    pub fn kyber_pk(&self) -> &KyberPublicKey {
        &self.kyber_pk
    }

    pub fn kyber_pk_bytes(&self) -> &[u8] {
        self.kyber_pk.as_bytes()
    }

    pub fn as_parts(&self) -> (&[u8; X25519_KEY_SIZE], &KyberPublicKey) {
        (&self.x25519_pk, &self.kyber_pk)
    }

    pub fn into_parts(self) -> ([u8; X25519_KEY_SIZE], KyberPublicKey) {
        (self.x25519_pk, self.kyber_pk)
    }

    pub fn encoded_len(&self) -> usize {
        X25519_KEY_SIZE + self.kyber_pk.as_bytes().len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
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

impl TryFrom<&[u8]> for HybridKemPublicKey {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<&HybridKemPublicKey> for Vec<u8> {
    fn from(pk: &HybridKemPublicKey) -> Self {
        pk.to_bytes()
    }
}

impl From<HybridKemPublicKey> for Vec<u8> {
    fn from(pk: HybridKemPublicKey) -> Self {
        pk.to_bytes()
    }
}

pub struct HybridKemSecretKey {
    pub x25519_sk: [u8; X25519_KEY_SIZE],
    pub kyber_sk: KyberSecretKey,
}

impl HybridKemSecretKey {
    pub fn x25519_sk(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.x25519_sk
    }

    pub fn kyber_sk(&self) -> &KyberSecretKey {
        &self.kyber_sk
    }
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
    pub fn x25519_ephemeral_pk(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.x25519_ephemeral_pk
    }

    pub fn kyber_ct(&self) -> &KyberCiphertext {
        &self.kyber_ct
    }

    pub fn kyber_ct_bytes(&self) -> &[u8] {
        self.kyber_ct.as_bytes()
    }

    pub fn as_parts(&self) -> (&[u8; X25519_KEY_SIZE], &KyberCiphertext) {
        (&self.x25519_ephemeral_pk, &self.kyber_ct)
    }

    pub fn into_parts(self) -> ([u8; X25519_KEY_SIZE], KyberCiphertext) {
        (self.x25519_ephemeral_pk, self.kyber_ct)
    }

    pub fn encoded_len(&self) -> usize {
        X25519_KEY_SIZE + self.kyber_ct.as_bytes().len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
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

impl TryFrom<&[u8]> for HybridKemCiphertext {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<&HybridKemCiphertext> for Vec<u8> {
    fn from(ct: &HybridKemCiphertext) -> Self {
        ct.to_bytes()
    }
}

impl From<HybridKemCiphertext> for Vec<u8> {
    fn from(ct: HybridKemCiphertext) -> Self {
        ct.to_bytes()
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

    pub fn public_key(&self) -> &HybridKemPublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &HybridKemSecretKey {
        &self.secret_key
    }

    pub fn as_parts(&self) -> (&HybridKemPublicKey, &HybridKemSecretKey) {
        (&self.public_key, &self.secret_key)
    }

    pub fn into_parts(self) -> (HybridKemPublicKey, HybridKemSecretKey) {
        (self.public_key, self.secret_key)
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
    use pqcrypto_traits::kem::SecretKey as _;

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

    #[test]
    fn test_kem_public_key_accessors() {
        let pair = HybridKemKeyPair::generate();
        assert_eq!(pair.public_key.x25519_pk(), &pair.public_key.x25519_pk);
        assert_eq!(pair.public_key.kyber_pk().as_bytes(), pair.public_key.kyber_pk.as_bytes());
    }

    #[test]
    fn test_kem_ciphertext_accessors() {
        let pair = HybridKemKeyPair::generate();
        let (ct, _) = encapsulate_hybrid(&pair.public_key);
        assert_eq!(ct.x25519_ephemeral_pk(), &ct.x25519_ephemeral_pk);
        assert_eq!(ct.kyber_ct().as_bytes(), ct.kyber_ct.as_bytes());
    }

    #[test]
    fn test_kem_encoded_lengths() {
        let pair = HybridKemKeyPair::generate();
        assert_eq!(pair.public_key.encoded_len(), pair.public_key.to_bytes().len());

        let (ct, _) = encapsulate_hybrid(&pair.public_key);
        assert_eq!(ct.encoded_len(), ct.to_bytes().len());
    }

    #[test]
    fn test_kem_try_from() {
        let pair = HybridKemKeyPair::generate();
        let pk_bytes = pair.public_key.to_bytes();
        let pk: HybridKemPublicKey = pk_bytes.as_slice().try_into().expect("TryFrom pk failed");
        assert_eq!(pk, pair.public_key);

        let (ct, _) = encapsulate_hybrid(&pair.public_key);
        let ct_bytes = ct.to_bytes();
        let decoded_ct: HybridKemCiphertext = ct_bytes.as_slice().try_into().expect("TryFrom ct failed");
        assert_eq!(decoded_ct, ct);
    }

    #[test]
    fn test_kem_secret_key_accessors() {
        let pair = HybridKemKeyPair::generate();
        assert_eq!(pair.secret_key.x25519_sk(), &pair.secret_key.x25519_sk);
        assert_eq!(pair.secret_key.kyber_sk().as_bytes(), pair.secret_key.kyber_sk.as_bytes());
    }

    #[test]
    fn test_kem_from_into_vec() {
        let pair = HybridKemKeyPair::generate();
        let pk_ref_vec: Vec<u8> = (&pair.public_key).into();
        assert_eq!(pk_ref_vec, pair.public_key.to_bytes());

        let pk_owned = pair.public_key.clone();
        let pk_vec: Vec<u8> = pk_owned.into();
        assert_eq!(pk_vec, pair.public_key.to_bytes());

        let (ct, _) = encapsulate_hybrid(&pair.public_key);
        let ct_ref_vec: Vec<u8> = (&ct).into();
        assert_eq!(ct_ref_vec, ct.to_bytes());

        let ct_owned = ct.clone();
        let ct_vec: Vec<u8> = ct_owned.into();
        assert_eq!(ct_vec, ct.to_bytes());
    }

    #[test]
    fn test_kem_keypair_and_parts() {
        let pair = HybridKemKeyPair::generate();
        assert_eq!(pair.public_key().x25519_pk(), pair.public_key.x25519_pk());
        assert_eq!(pair.public_key().kyber_pk_bytes(), pair.public_key.kyber_pk.as_bytes());
        assert_eq!(pair.secret_key().x25519_sk(), pair.secret_key.x25519_sk());

        let (ct, _) = encapsulate_hybrid(pair.public_key());
        assert_eq!(ct.kyber_ct_bytes(), ct.kyber_ct.as_bytes());

        let (x_ct, kyber_ct) = ct.into_parts();
        assert_eq!(x_ct.len(), X25519_KEY_SIZE);
        assert!(!kyber_ct.as_bytes().is_empty());

        let (pk, sk) = pair.into_parts();
        let (x_pk, kyber_pk) = pk.into_parts();
        assert_eq!(x_pk.len(), X25519_KEY_SIZE);
        assert_eq!(kyber_pk.as_bytes().len(), 1184); // Kyber768 public key size
        assert_eq!(sk.x25519_sk().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_kem_as_parts_accessors() {
        let pair = HybridKemKeyPair::generate();
        let (pk_ref, sk_ref) = pair.as_parts();
        assert_eq!(pk_ref.x25519_pk(), pair.public_key().x25519_pk());
        assert_eq!(sk_ref.x25519_sk(), pair.secret_key().x25519_sk());

        let (x_pk, kyber_pk) = pair.public_key().as_parts();
        assert_eq!(x_pk, pair.public_key().x25519_pk());
        assert_eq!(kyber_pk.as_bytes(), pair.public_key().kyber_pk_bytes());

        let (ct, _) = encapsulate_hybrid(pair.public_key());
        let (x_ephem, kyber_ct) = ct.as_parts();
        assert_eq!(x_ephem, ct.x25519_ephemeral_pk());
        assert_eq!(kyber_ct.as_bytes(), ct.kyber_ct_bytes());
    }
}




