use crate::crypto::{
    kem::{HybridKemCiphertext, HybridKemPublicKey},
    sig::HybridSignature,
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
