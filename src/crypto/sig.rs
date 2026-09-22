use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use pqcrypto_dilithium::dilithium3::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature as DilithiumSignature,
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use rand::rngs::OsRng;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct HybridSigPublicKey {
    pub ed25519_pk: [u8; 32],
    pub dilithium_pk: DilithiumPublicKey,
}

impl HybridSigPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + self.dilithium_pk.as_bytes().len());
        bytes.extend_from_slice(&self.ed25519_pk);
        bytes.extend_from_slice(self.dilithium_pk.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 32 {
            return Err("Byte slice too short for HybridSigPublicKey".to_string());
        }
        let mut ed25519_pk = [0u8; 32];
        ed25519_pk.copy_from_slice(&bytes[..32]);

        let dilithium_pk = DilithiumPublicKey::from_bytes(&bytes[32..])
            .map_err(|e| format!("Failed to parse Dilithium public key: {:?}", e))?;

        Ok(Self {
            ed25519_pk,
            dilithium_pk,
        })
    }
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

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.dilithium_sig.as_bytes().len());
        bytes.extend_from_slice(&self.ed25519_sig);
        bytes.extend_from_slice(self.dilithium_sig.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 64 {
            return Err("Byte slice too short for HybridSignature".to_string());
        }
        let mut ed25519_sig = [0u8; 64];
        ed25519_sig.copy_from_slice(&bytes[..64]);

        let dilithium_sig = DilithiumSignature::from_bytes(&bytes[64..])
            .map_err(|e| format!("Failed to parse Dilithium signature: {:?}", e))?;

        Ok(Self {
            ed25519_sig,
            dilithium_sig,
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_serialization() {
        let pair = HybridSigKeyPair::generate();
        let bytes = pair.public_key.to_bytes();
        let decoded = HybridSigPublicKey::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(pair.public_key.ed25519_pk, decoded.ed25519_pk);
        assert_eq!(pair.public_key.dilithium_pk.as_bytes(), decoded.dilithium_pk.as_bytes());
    }

    #[test]
    fn test_signature_serialization_and_verification() {
        let pair = HybridSigKeyPair::generate();
        let msg = b"serialize-and-verify-this";
        let signature = sign_hybrid(msg, &pair.secret_key);
        let bytes = signature.to_bytes();
        let decoded_sig = HybridSignature::from_bytes(&bytes).expect("signature decode failed");

        assert!(verify_hybrid(msg, &decoded_sig, &pair.public_key));
    }
}
