use crate::crypto::{
    kem::{HybridKemCiphertext, HybridKemPublicKey},
    sig::{sign_hybrid, verify_hybrid, HybridSigPublicKey, HybridSigSecretKey, HybridSignature},
};

pub const HANDSHAKE_NONCE_SIZE: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeInit {
    pub ephemeral_pk: HybridKemPublicKey,
    pub nonce: [u8; HANDSHAKE_NONCE_SIZE],
    pub signature: HybridSignature,
}

impl HandshakeInit {
    pub fn new(
        ephemeral_pk: HybridKemPublicKey,
        nonce: [u8; HANDSHAKE_NONCE_SIZE],
        signature: HybridSignature,
    ) -> Self {
        Self {
            ephemeral_pk,
            nonce,
            signature,
        }
    }

    pub fn create(
        ephemeral_pk: HybridKemPublicKey,
        nonce: [u8; HANDSHAKE_NONCE_SIZE],
        signer_sk: &HybridSigSecretKey,
    ) -> Self {
        let mut signed_data = ephemeral_pk.to_bytes();
        signed_data.extend_from_slice(&nonce);
        let signature = sign_hybrid(&signed_data, signer_sk);
        Self {
            ephemeral_pk,
            nonce,
            signature,
        }
    }

    pub fn verify(&self, signer_pk: &HybridSigPublicKey) -> bool {
        let mut signed_data = self.ephemeral_pk.to_bytes();
        signed_data.extend_from_slice(&self.nonce);
        verify_hybrid(&signed_data, &self.signature, signer_pk)
    }

    pub fn encoded_len(&self) -> usize {
        4 + self.ephemeral_pk.encoded_len() + HANDSHAKE_NONCE_SIZE + 4 + self.signature.encoded_len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_bytes = self.ephemeral_pk.to_bytes();
        let sig_bytes = self.signature.to_bytes();
        let mut buf = Vec::with_capacity(self.encoded_len());

        buf.extend_from_slice(&(pk_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&pk_bytes);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&sig_bytes);

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Buffer too short for HandshakeInit pk length".to_string());
        }

        let pk_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let offset1 = 4 + pk_len;
        if bytes.len() < offset1 + HANDSHAKE_NONCE_SIZE + 4 {
            return Err("Buffer too short for HandshakeInit nonce and sig header".to_string());
        }

        let ephemeral_pk = HybridKemPublicKey::from_bytes(&bytes[4..offset1])?;

        let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset1..offset1 + HANDSHAKE_NONCE_SIZE]);

        let offset2 = offset1 + HANDSHAKE_NONCE_SIZE;
        let sig_len = u32::from_be_bytes(bytes[offset2..offset2 + 4].try_into().unwrap()) as usize;
        let offset3 = offset2 + 4 + sig_len;

        if bytes.len() < offset3 {
            return Err("Buffer too short for HandshakeInit signature payload".to_string());
        }

        let signature = HybridSignature::from_bytes(&bytes[offset2 + 4..offset3])?;

        Ok(Self {
            ephemeral_pk,
            nonce,
            signature,
        })
    }
}

impl TryFrom<&[u8]> for HandshakeInit {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub ciphertext: HybridKemCiphertext,
    pub nonce: [u8; HANDSHAKE_NONCE_SIZE],
    pub signature: HybridSignature,
}

impl HandshakeResponse {
    pub fn new(
        ciphertext: HybridKemCiphertext,
        nonce: [u8; HANDSHAKE_NONCE_SIZE],
        signature: HybridSignature,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            signature,
        }
    }

    pub fn create(
        ciphertext: HybridKemCiphertext,
        nonce: [u8; HANDSHAKE_NONCE_SIZE],
        signer_sk: &HybridSigSecretKey,
    ) -> Self {
        let mut signed_data = ciphertext.to_bytes();
        signed_data.extend_from_slice(&nonce);
        let signature = sign_hybrid(&signed_data, signer_sk);
        Self {
            ciphertext,
            nonce,
            signature,
        }
    }

    pub fn verify(&self, signer_pk: &HybridSigPublicKey) -> bool {
        let mut signed_data = self.ciphertext.to_bytes();
        signed_data.extend_from_slice(&self.nonce);
        verify_hybrid(&signed_data, &self.signature, signer_pk)
    }

    pub fn encoded_len(&self) -> usize {
        4 + self.ciphertext.encoded_len() + HANDSHAKE_NONCE_SIZE + 4 + self.signature.encoded_len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_bytes = self.ciphertext.to_bytes();
        let sig_bytes = self.signature.to_bytes();
        let mut buf = Vec::with_capacity(self.encoded_len());

        buf.extend_from_slice(&(ct_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&ct_bytes);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&sig_bytes);

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Buffer too short for HandshakeResponse ciphertext length".to_string());
        }

        let ct_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let offset1 = 4 + ct_len;
        if bytes.len() < offset1 + HANDSHAKE_NONCE_SIZE + 4 {
            return Err("Buffer too short for HandshakeResponse nonce and sig header".to_string());
        }

        let ciphertext = HybridKemCiphertext::from_bytes(&bytes[4..offset1])?;

        let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset1..offset1 + HANDSHAKE_NONCE_SIZE]);

        let offset2 = offset1 + HANDSHAKE_NONCE_SIZE;
        let sig_len = u32::from_be_bytes(bytes[offset2..offset2 + 4].try_into().unwrap()) as usize;
        let offset3 = offset2 + 4 + sig_len;

        if bytes.len() < offset3 {
            return Err("Buffer too short for HandshakeResponse signature payload".to_string());
        }

        let signature = HybridSignature::from_bytes(&bytes[offset2 + 4..offset3])?;

        Ok(Self {
            ciphertext,
            nonce,
            signature,
        })
    }
}

impl TryFrom<&[u8]> for HandshakeResponse {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        kem::{encapsulate_hybrid, HybridKemKeyPair},
        sig::HybridSigKeyPair,
    };

    #[test]
    fn test_handshake_init_roundtrip_and_verify() {
        let kem_keys = HybridKemKeyPair::generate();
        let sig_keys = HybridSigKeyPair::generate();
        let nonce = [7u8; HANDSHAKE_NONCE_SIZE];

        let init = HandshakeInit::create(kem_keys.public_key, nonce, &sig_keys.secret_key);
        assert!(init.verify(&sig_keys.public_key));

        let encoded = init.to_bytes();
        assert_eq!(encoded.len(), init.encoded_len());

        let decoded = HandshakeInit::from_bytes(&encoded).expect("failed to decode HandshakeInit");
        assert_eq!(init, decoded);
        assert!(decoded.verify(&sig_keys.public_key));

        // Wrong public key fails verification
        let other_sig_keys = HybridSigKeyPair::generate();
        assert!(!decoded.verify(&other_sig_keys.public_key));
    }

    #[test]
    fn test_handshake_response_roundtrip_and_verify() {
        let kem_keys = HybridKemKeyPair::generate();
        let sig_keys = HybridSigKeyPair::generate();
        let (ct, _) = encapsulate_hybrid(&kem_keys.public_key);
        let nonce = [9u8; HANDSHAKE_NONCE_SIZE];

        let resp = HandshakeResponse::create(ct, nonce, &sig_keys.secret_key);
        assert!(resp.verify(&sig_keys.public_key));

        let encoded = resp.to_bytes();
        assert_eq!(encoded.len(), resp.encoded_len());

        let decoded = HandshakeResponse::from_bytes(&encoded).expect("failed to decode HandshakeResponse");
        assert_eq!(resp, decoded);
        assert!(decoded.verify(&sig_keys.public_key));

        // Wrong public key fails verification
        let other_sig_keys = HybridSigKeyPair::generate();
        assert!(!decoded.verify(&other_sig_keys.public_key));
    }

    #[test]
    fn test_handshake_decode_truncated_errors() {
        let short = [0u8; 3];
        assert!(HandshakeInit::from_bytes(&short).is_err());
        assert!(HandshakeResponse::from_bytes(&short).is_err());
    }

    #[test]
    fn test_handshake_try_from() {
        let kem_keys = HybridKemKeyPair::generate();
        let sig_keys = HybridSigKeyPair::generate();
        let nonce = [1u8; HANDSHAKE_NONCE_SIZE];

        let init = HandshakeInit::create(kem_keys.public_key.clone(), nonce, &sig_keys.secret_key);
        let init_bytes = init.to_bytes();
        let decoded_init: HandshakeInit = init_bytes.as_slice().try_into().expect("TryFrom HandshakeInit failed");
        assert_eq!(init, decoded_init);

        let (ct, _) = encapsulate_hybrid(&kem_keys.public_key);
        let resp = HandshakeResponse::create(ct, nonce, &sig_keys.secret_key);
        let resp_bytes = resp.to_bytes();
        let decoded_resp: HandshakeResponse = resp_bytes.as_slice().try_into().expect("TryFrom HandshakeResponse failed");
        assert_eq!(resp, decoded_resp);
    }
}

