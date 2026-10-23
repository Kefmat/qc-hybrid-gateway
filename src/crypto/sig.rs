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

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

#[derive(Clone)]
pub struct HybridSigPublicKey {
    pub ed25519_pk: [u8; ED25519_PUBLIC_KEY_SIZE],
    pub dilithium_pk: DilithiumPublicKey,
}

impl PartialEq for HybridSigPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ed25519_pk == other.ed25519_pk && self.dilithium_pk.as_bytes() == other.dilithium_pk.as_bytes()
    }
}

impl Eq for HybridSigPublicKey {}

impl std::fmt::Debug for HybridSigPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigPublicKey")
            .field("ed25519_pk", &self.ed25519_pk)
            .field("dilithium_pk_len", &self.dilithium_pk.as_bytes().len())
            .finish()
    }
}

impl HybridSigPublicKey {
    pub fn ed25519_pk(&self) -> &[u8; ED25519_PUBLIC_KEY_SIZE] {
        &self.ed25519_pk
    }

    pub fn dilithium_pk(&self) -> &DilithiumPublicKey {
        &self.dilithium_pk
    }

    pub fn dilithium_pk_bytes(&self) -> &[u8] {
        self.dilithium_pk.as_bytes()
    }

    pub fn as_parts(&self) -> (&[u8; ED25519_PUBLIC_KEY_SIZE], &DilithiumPublicKey) {
        (&self.ed25519_pk, &self.dilithium_pk)
    }

    pub fn into_parts(self) -> ([u8; ED25519_PUBLIC_KEY_SIZE], DilithiumPublicKey) {
        (self.ed25519_pk, self.dilithium_pk)
    }

    pub fn encoded_len(&self) -> usize {
        ED25519_PUBLIC_KEY_SIZE + self.dilithium_pk.as_bytes().len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.ed25519_pk);
        bytes.extend_from_slice(self.dilithium_pk.as_bytes());
        bytes
    }



    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < ED25519_PUBLIC_KEY_SIZE {
            return Err("Byte slice too short for HybridSigPublicKey".to_string());
        }
        let mut ed25519_pk = [0u8; ED25519_PUBLIC_KEY_SIZE];
        ed25519_pk.copy_from_slice(&bytes[..ED25519_PUBLIC_KEY_SIZE]);

        let dilithium_pk = DilithiumPublicKey::from_bytes(&bytes[ED25519_PUBLIC_KEY_SIZE..])
            .map_err(|e| format!("Failed to parse Dilithium public key: {:?}", e))?;

        Ok(Self {
            ed25519_pk,
            dilithium_pk,
        })
    }
}

impl TryFrom<&[u8]> for HybridSigPublicKey {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<&HybridSigPublicKey> for Vec<u8> {
    fn from(pk: &HybridSigPublicKey) -> Self {
        pk.to_bytes()
    }
}

impl From<HybridSigPublicKey> for Vec<u8> {
    fn from(pk: HybridSigPublicKey) -> Self {
        pk.to_bytes()
    }
}

pub struct HybridSigSecretKey {
    pub ed25519_sk: [u8; ED25519_PUBLIC_KEY_SIZE],
    pub dilithium_sk: DilithiumSecretKey,
}

impl HybridSigSecretKey {
    pub fn ed25519_sk(&self) -> &[u8; ED25519_PUBLIC_KEY_SIZE] {
        &self.ed25519_sk
    }

    pub fn dilithium_sk(&self) -> &DilithiumSecretKey {
        &self.dilithium_sk
    }
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
    pub ed25519_sig: [u8; ED25519_SIGNATURE_SIZE],
    pub dilithium_sig: DilithiumSignature,
}

impl PartialEq for HybridSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ed25519_sig == other.ed25519_sig
            && self.dilithium_sig.as_bytes() == other.dilithium_sig.as_bytes()
    }
}

impl Eq for HybridSignature {}

impl std::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSignature")
            .field("ed25519_sig_len", &self.ed25519_sig.len())
            .field("dilithium_sig_len", &self.dilithium_sig.as_bytes().len())
            .finish()
    }
}




impl HybridSignature {
    pub fn ed25519_sig(&self) -> &[u8; ED25519_SIGNATURE_SIZE] {
        &self.ed25519_sig
    }

    pub fn dilithium_sig(&self) -> &DilithiumSignature {
        &self.dilithium_sig
    }

    pub fn dilithium_sig_bytes(&self) -> &[u8] {
        self.dilithium_sig.as_bytes()
    }

    pub fn as_parts(&self) -> (&[u8; ED25519_SIGNATURE_SIZE], &DilithiumSignature) {
        (&self.ed25519_sig, &self.dilithium_sig)
    }

    pub fn into_parts(self) -> ([u8; ED25519_SIGNATURE_SIZE], DilithiumSignature) {
        (self.ed25519_sig, self.dilithium_sig)
    }

    pub fn encoded_len(&self) -> usize {
        ED25519_SIGNATURE_SIZE + self.dilithium_sig.as_bytes().len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.ed25519_sig);
        bytes.extend_from_slice(self.dilithium_sig.as_bytes());
        bytes
    }



    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < ED25519_SIGNATURE_SIZE {
            return Err("Byte slice too short for HybridSignature".to_string());
        }
        let mut ed25519_sig = [0u8; ED25519_SIGNATURE_SIZE];
        ed25519_sig.copy_from_slice(&bytes[..ED25519_SIGNATURE_SIZE]);

        let dilithium_sig = DilithiumSignature::from_bytes(&bytes[ED25519_SIGNATURE_SIZE..])
            .map_err(|e| format!("Failed to parse Dilithium signature: {:?}", e))?;

        Ok(Self {
            ed25519_sig,
            dilithium_sig,
        })
    }
}

impl TryFrom<&[u8]> for HybridSignature {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<&HybridSignature> for Vec<u8> {
    fn from(sig: &HybridSignature) -> Self {
        sig.to_bytes()
    }
}

impl From<HybridSignature> for Vec<u8> {
    fn from(sig: HybridSignature) -> Self {
        sig.to_bytes()
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

    pub fn public_key(&self) -> &HybridSigPublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &HybridSigSecretKey {
        &self.secret_key
    }

    pub fn as_parts(&self) -> (&HybridSigPublicKey, &HybridSigSecretKey) {
        (&self.public_key, &self.secret_key)
    }

    pub fn into_parts(self) -> (HybridSigPublicKey, HybridSigSecretKey) {
        (self.public_key, self.secret_key)
    }
}

/// Generates a dual hybrid signature (Ed25519 + ML-DSA-65) over the provided message.
pub fn sign_hybrid(message: &[u8], sk: &HybridSigSecretKey) -> HybridSignature {
    let ed_signing_key = Ed25519SigningKey::from_bytes(&sk.ed25519_sk);
    let ed_sig = ed_signing_key.sign(message);

    let dilithium_sig = detached_sign(message, &sk.dilithium_sk);

    HybridSignature {
        ed25519_sig: ed_sig.to_bytes(),
        dilithium_sig,
    }
}

/// Verifies that both the Ed25519 and ML-DSA-65 signatures are valid for the given message.
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
    use pqcrypto_traits::sign::SecretKey as _;

    #[test]
    fn test_public_key_serialization() {
        let pair = HybridSigKeyPair::generate();
        let bytes = pair.public_key.to_bytes();
        let decoded = HybridSigPublicKey::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(pair.public_key, decoded);
    }

    #[test]
    fn test_signature_serialization_and_verification() {
        let pair = HybridSigKeyPair::generate();
        let msg = b"serialize-and-verify-this";
        let signature = sign_hybrid(msg, &pair.secret_key);
        let bytes = signature.to_bytes();
        let decoded_sig = HybridSignature::from_bytes(&bytes).expect("signature decode failed");

        assert_eq!(signature, decoded_sig);
        assert!(verify_hybrid(msg, &decoded_sig, &pair.public_key));
    }

    #[test]
    fn test_deserialization_truncated_inputs() {
        let short_pk_bytes = [0u8; 16];
        assert!(HybridSigPublicKey::from_bytes(&short_pk_bytes).is_err());

        let short_sig_bytes = [0u8; 32];
        assert!(HybridSignature::from_bytes(&short_sig_bytes).is_err());
    }

    #[test]
    fn test_sig_public_key_accessors() {
        let pair = HybridSigKeyPair::generate();
        assert_eq!(pair.public_key.ed25519_pk(), &pair.public_key.ed25519_pk);
        assert_eq!(pair.public_key.dilithium_pk().as_bytes(), pair.public_key.dilithium_pk.as_bytes());
    }

    #[test]
    fn test_sig_signature_accessors() {
        let pair = HybridSigKeyPair::generate();
        let sig = sign_hybrid(b"test-accessors", &pair.secret_key);
        assert_eq!(sig.ed25519_sig(), &sig.ed25519_sig);
        assert_eq!(sig.dilithium_sig().as_bytes(), sig.dilithium_sig.as_bytes());
    }

    #[test]
    fn test_sig_encoded_lengths() {
        let pair = HybridSigKeyPair::generate();
        assert_eq!(pair.public_key.encoded_len(), pair.public_key.to_bytes().len());

        let sig = sign_hybrid(b"message", &pair.secret_key);
        assert_eq!(sig.encoded_len(), sig.to_bytes().len());
    }

    #[test]
    fn test_sig_try_from() {
        let pair = HybridSigKeyPair::generate();
        let pk_bytes = pair.public_key.to_bytes();
        let pk: HybridSigPublicKey = pk_bytes.as_slice().try_into().expect("TryFrom pk failed");
        assert_eq!(pk, pair.public_key);

        let sig = sign_hybrid(b"try-from-signature-test", &pair.secret_key);
        let sig_bytes = sig.to_bytes();
        let decoded_sig: HybridSignature = sig_bytes.as_slice().try_into().expect("TryFrom sig failed");
        assert_eq!(decoded_sig, sig);
    }

    #[test]
    fn test_sig_secret_key_accessors() {
        let pair = HybridSigKeyPair::generate();
        assert_eq!(pair.secret_key.ed25519_sk(), &pair.secret_key.ed25519_sk);
        assert_eq!(pair.secret_key.dilithium_sk().as_bytes(), pair.secret_key.dilithium_sk.as_bytes());
    }

    #[test]
    fn test_sig_from_into_vec() {
        let pair = HybridSigKeyPair::generate();
        let pk_ref_vec: Vec<u8> = (&pair.public_key).into();
        assert_eq!(pk_ref_vec, pair.public_key.to_bytes());

        let pk_owned = pair.public_key.clone();
        let pk_vec: Vec<u8> = pk_owned.into();
        assert_eq!(pk_vec, pair.public_key.to_bytes());

        let sig = sign_hybrid(b"test-into-vec-signature", &pair.secret_key);
        let sig_ref_vec: Vec<u8> = (&sig).into();
        assert_eq!(sig_ref_vec, sig.to_bytes());

        let sig_owned = sig.clone();
        let sig_vec: Vec<u8> = sig_owned.into();
        assert_eq!(sig_vec, sig.to_bytes());
    }

    #[test]
    fn test_sig_keypair_and_parts() {
        let pair = HybridSigKeyPair::generate();
        assert_eq!(pair.public_key().ed25519_pk(), pair.public_key.ed25519_pk());
        assert_eq!(pair.public_key().dilithium_pk_bytes(), pair.public_key.dilithium_pk.as_bytes());
        assert_eq!(pair.secret_key().ed25519_sk(), pair.secret_key.ed25519_sk());

        let sig = sign_hybrid(b"test-parts-payload", pair.secret_key());
        assert_eq!(sig.dilithium_sig_bytes(), sig.dilithium_sig.as_bytes());

        let (ed_sig, dilithium_sig) = sig.into_parts();
        assert_eq!(ed_sig.len(), ED25519_SIGNATURE_SIZE);
        assert!(!dilithium_sig.as_bytes().is_empty());

        let (pk, sk) = pair.into_parts();
        let (ed_pk, dilithium_pk) = pk.into_parts();
        assert_eq!(ed_pk.len(), ED25519_PUBLIC_KEY_SIZE);
        assert!(!dilithium_pk.as_bytes().is_empty());
        assert_eq!(sk.ed25519_sk().len(), ED25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sig_as_parts_accessors() {
        let pair = HybridSigKeyPair::generate();
        let (pk_ref, sk_ref) = pair.as_parts();
        assert_eq!(pk_ref.ed25519_pk(), pair.public_key().ed25519_pk());
        assert_eq!(sk_ref.ed25519_sk(), pair.secret_key().ed25519_sk());

        let (ed_pk, dilithium_pk) = pair.public_key().as_parts();
        assert_eq!(ed_pk, pair.public_key().ed25519_pk());
        assert_eq!(dilithium_pk.as_bytes(), pair.public_key().dilithium_pk_bytes());

        let sig = sign_hybrid(b"test-as-parts-sig", pair.secret_key());
        let (ed_sig, dilithium_sig) = sig.as_parts();
        assert_eq!(ed_sig, sig.ed25519_sig());
        assert_eq!(dilithium_sig.as_bytes(), sig.dilithium_sig_bytes());
    }
}




