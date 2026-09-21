use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use pqcrypto_dilithium::dilithium3::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature as DilithiumSignature,
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use rand::rngs::OsRng;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct HybridSigPublicKey {
    pub ed25519_pk: [u8; 32],
    pub dilithium_pk: DilithiumPublicKey,
}

pub struct HybridSigSecretKey {
    pub ed25519_sk: [u8; 32],
    pub dilithium_sk: DilithiumSecretKey,
}

impl Drop for HybridSigSecretKey {
    fn drop(&mut self) {
        self.ed25519_sk.zeroize();
    }
}

pub struct HybridSigKeyPair {
    pub public_key: HybridSigPublicKey,
    pub secret_key: HybridSigSecretKey,
}

#[derive(Clone)]
pub struct HybridSignature {
    pub ed25519_sig: [u8; 64],
    pub dilithium_sig: DilithiumSignature,
}

impl HybridSigKeyPair {
    pub fn generate() -> Self {
        let mut ed_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut ed_bytes);
        let ed_signing_key = Ed25519SigningKey::from_bytes(&ed_bytes);
        let ed_verifying_key = ed_signing_key.verifying_key();

        let (dilithium_pk, dilithium_sk) = keypair();

        Self {
            public_key: HybridSigPublicKey {
                ed25519_pk: *ed_verifying_key.as_bytes(),
                dilithium_pk,
            },
            secret_key: HybridSigSecretKey {
                ed25519_sk: ed_bytes,
                dilithium_sk,
            },
        }
    }
}

pub fn sign_hybrid(message: &[u8], sk: &HybridSigSecretKey) -> HybridSignature {
    let ed_signing_key = Ed25519SigningKey::from_bytes(&sk.ed25519_sk);
    let ed_sig = ed_signing_key.sign(message);

    let dilithium_sig = detached_sign(message, &sk.dilithium_sk);

    HybridSignature {
        ed25519_sig: ed_sig.to_bytes(),
        dilithium_sig,
    }
}

pub fn verify_hybrid(
    message: &[u8],
    signature: &HybridSignature,
    pk: &HybridSigPublicKey,
) -> bool {
    let Ok(ed_verifying_key) = Ed25519VerifyingKey::from_bytes(&pk.ed25519_pk) else {
        return false;
    };
    let ed_sig = Ed25519Signature::from_bytes(&signature.ed25519_sig);

    if ed_verifying_key.verify(message, &ed_sig).is_err() {
        return false;
    }

    verify_detached_signature(&signature.dilithium_sig, message, &pk.dilithium_pk).is_ok()
}
