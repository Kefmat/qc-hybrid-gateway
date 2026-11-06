use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use pqcrypto_dilithium::dilithium3::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature as DilithiumSignature,
    PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
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
        self.ed25519_pk == other.ed25519_pk
            && self.dilithium_pk.as_bytes() == other.dilithium_pk.as_bytes()
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

impl std::fmt::Display for HybridSigPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HybridSigPublicKey(ed25519={}B, dilithium={}B)",
            self.ed25519_pk.len(),
            self.dilithium_pk.as_bytes().len()
        )
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

    /// Returns the hex string representation of the Ed25519 public key.
    pub fn ed25519_pk_hex(&self) -> String {
        self.ed25519_pk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Returns an 8-hex-character SHA-256 fingerprint of the serialized hybrid public key.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.to_bytes());
        digest[..4].iter().map(|b| format!("{:02x}", b)).collect()
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

    /// Saves the serialized public key to disk at the specified path.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        std::fs::write(path, self.to_bytes())
    }

    /// Loads and deserializes a public key from disk.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read signature public key file: {}", e))?;
        Self::from_bytes(&bytes)
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

    pub fn dilithium_sk_bytes(&self) -> &[u8] {
        self.dilithium_sk.as_bytes()
    }

    pub fn as_parts(&self) -> (&[u8; ED25519_PUBLIC_KEY_SIZE], &DilithiumSecretKey) {
        (&self.ed25519_sk, &self.dilithium_sk)
    }

    pub fn into_parts(self) -> ([u8; ED25519_PUBLIC_KEY_SIZE], DilithiumSecretKey) {
        (self.ed25519_sk, self.dilithium_sk)
    }

    pub fn encoded_len(&self) -> usize {
        ED25519_PUBLIC_KEY_SIZE + self.dilithium_sk.as_bytes().len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.ed25519_sk);
        bytes.extend_from_slice(self.dilithium_sk.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < ED25519_PUBLIC_KEY_SIZE {
            return Err("Byte slice too short for HybridSigSecretKey".to_string());
        }
        let mut ed25519_sk = [0u8; ED25519_PUBLIC_KEY_SIZE];
        ed25519_sk.copy_from_slice(&bytes[..ED25519_PUBLIC_KEY_SIZE]);

        let dilithium_sk = DilithiumSecretKey::from_bytes(&bytes[ED25519_PUBLIC_KEY_SIZE..])
            .map_err(|e| format!("Failed to parse Dilithium secret key: {:?}", e))?;

        Ok(Self {
            ed25519_sk,
            dilithium_sk,
        })
    }

    /// Saves the serialized secret key to disk at the specified path.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        std::fs::write(path, self.to_bytes())
    }

    /// Loads and deserializes a secret key from disk.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read signature secret key file: {}", e))?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for HybridSigSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigSecretKey")
            .field("ed25519_sk", &"[REDACTED]")
            .field("dilithium_sk_len", &self.dilithium_sk.as_bytes().len())
            .finish()
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

impl std::fmt::Debug for HybridSigKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &self.secret_key)
            .finish()
    }
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

impl std::fmt::Display for HybridSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HybridSignature(ed25519={}B, dilithium={}B)",
            self.ed25519_sig.len(),
            self.dilithium_sig.as_bytes().len()
        )
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

    /// Returns the hex string representation of the Ed25519 signature.
    pub fn ed25519_sig_hex(&self) -> String {
        self.ed25519_sig
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Returns an 8-hex-character SHA-256 fingerprint of the serialized hybrid signature.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.to_bytes());
        digest[..4].iter().map(|b| format!("{:02x}", b)).collect()
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

    /// Saves both public and secret keys to the specified directory with given prefix.
    pub fn save_to_dir(
        &self,
        dir: impl AsRef<std::path::Path>,
        prefix: &str,
    ) -> Result<(), std::io::Error> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        self.public_key
            .save_to_file(dir.join(format!("{}.sig.pub", prefix)))?;
        self.secret_key
            .save_to_file(dir.join(format!("{}.sig.key", prefix)))?;
        Ok(())
    }

    /// Loads both public and secret keys from the specified directory with given prefix.
    pub fn load_from_dir(dir: impl AsRef<std::path::Path>, prefix: &str) -> Result<Self, String> {
        let dir = dir.as_ref();
        let public_key =
            HybridSigPublicKey::load_from_file(dir.join(format!("{}.sig.pub", prefix)))?;
        let secret_key =
            HybridSigSecretKey::load_from_file(dir.join(format!("{}.sig.key", prefix)))?;
        Ok(Self {
            public_key,
            secret_key,
        })
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
pub fn verify_hybrid(message: &[u8], signature: &HybridSignature, pk: &HybridSigPublicKey) -> bool {
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
        assert_eq!(
            pair.public_key.dilithium_pk().as_bytes(),
            pair.public_key.dilithium_pk.as_bytes()
        );
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
        assert_eq!(
            pair.public_key.encoded_len(),
            pair.public_key.to_bytes().len()
        );

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
        let decoded_sig: HybridSignature =
            sig_bytes.as_slice().try_into().expect("TryFrom sig failed");
        assert_eq!(decoded_sig, sig);
    }

    #[test]
    fn test_sig_secret_key_accessors() {
        let pair = HybridSigKeyPair::generate();
        assert_eq!(pair.secret_key.ed25519_sk(), &pair.secret_key.ed25519_sk);
        assert_eq!(
            pair.secret_key.dilithium_sk().as_bytes(),
            pair.secret_key.dilithium_sk.as_bytes()
        );
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
        assert_eq!(
            pair.public_key().dilithium_pk_bytes(),
            pair.public_key.dilithium_pk.as_bytes()
        );
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
        assert_eq!(
            dilithium_pk.as_bytes(),
            pair.public_key().dilithium_pk_bytes()
        );

        let sig = sign_hybrid(b"test-as-parts-sig", pair.secret_key());
        let (ed_sig, dilithium_sig) = sig.as_parts();
        assert_eq!(ed_sig, sig.ed25519_sig());
        assert_eq!(dilithium_sig.as_bytes(), sig.dilithium_sig_bytes());
    }

    #[test]
    fn test_sig_secret_key_parts_and_bytes() {
        let pair = HybridSigKeyPair::generate();
        let sk = pair.secret_key();
        assert!(!sk.dilithium_sk_bytes().is_empty());

        let (ed_sk, dilithium_sk) = sk.as_parts();
        assert_eq!(ed_sk, sk.ed25519_sk());
        assert_eq!(dilithium_sk.as_bytes(), sk.dilithium_sk_bytes());

        let (pk, sk_owned) = pair.into_parts();
        assert_eq!(pk.encoded_len(), 1984);
        let (ed_sk_owned, dilithium_sk_owned) = sk_owned.into_parts();
        assert_eq!(ed_sk_owned.len(), ED25519_PUBLIC_KEY_SIZE);
        assert!(!dilithium_sk_owned.as_bytes().is_empty());
    }

    #[test]
    fn test_sig_debug_redaction_and_display() {
        let pair = HybridSigKeyPair::generate();
        let sk_debug = format!("{:?}", pair.secret_key());
        assert!(sk_debug.contains("HybridSigSecretKey"));
        assert!(sk_debug.contains("[REDACTED]"));
        assert!(sk_debug.contains("dilithium_sk_len"));

        let pair_debug = format!("{:?}", pair);
        assert!(pair_debug.contains("HybridSigKeyPair"));
        assert!(pair_debug.contains("[REDACTED]"));

        let pk_display = format!("{}", pair.public_key());
        assert!(pk_display.contains("HybridSigPublicKey(ed25519=32B, dilithium=1952B)"));

        let sig = sign_hybrid(b"display-test-msg", pair.secret_key());
        let sig_display = format!("{}", sig);
        let expected_sig_str = format!(
            "HybridSignature(ed25519=64B, dilithium={}B)",
            sig.dilithium_sig_bytes().len()
        );
        assert_eq!(sig_display, expected_sig_str);
    }

    #[test]
    fn test_sig_hex_and_fingerprints() {
        let pair = HybridSigKeyPair::generate();
        let pk = pair.public_key();

        let pk_hex = pk.ed25519_pk_hex();
        assert_eq!(pk_hex.len(), 64);
        assert_eq!(pk.fingerprint().len(), 8);

        let sig = sign_hybrid(b"hex-and-fingerprint-test", pair.secret_key());
        let sig_hex = sig.ed25519_sig_hex();
        assert_eq!(sig_hex.len(), 128); // 64 bytes = 128 hex chars
        assert_eq!(sig.fingerprint().len(), 8);
    }

    #[test]
    fn test_sig_key_persistence_and_file_io() {
        let temp_dir = std::env::temp_dir().join(format!("pqc_sig_test_{}", rand::random::<u64>()));
        let pair = HybridSigKeyPair::generate();

        pair.save_to_dir(&temp_dir, "test_sig")
            .expect("save_to_dir failed");
        let loaded =
            HybridSigKeyPair::load_from_dir(&temp_dir, "test_sig").expect("load_from_dir failed");

        assert_eq!(pair.public_key().to_bytes(), loaded.public_key().to_bytes());
        assert_eq!(pair.secret_key().to_bytes(), loaded.secret_key().to_bytes());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
