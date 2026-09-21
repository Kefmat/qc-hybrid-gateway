use pqcrypto_kyber::kyber768::{
    decapsulate, encapsulate, keypair, Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::SharedSecret as _;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::kdf::derive_hybrid_shared_secret;

#[derive(Clone)]
pub struct HybridKemPublicKey {
    pub x25519_pk: [u8; 32],
    pub kyber_pk: KyberPublicKey,
}

pub struct HybridKemSecretKey {
    pub x25519_sk: [u8; 32],
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
    pub x25519_ephemeral_pk: [u8; 32],
    pub kyber_ct: KyberCiphertext,
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
