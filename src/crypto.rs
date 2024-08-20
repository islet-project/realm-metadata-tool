use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature,
    },
    elliptic_curve::generic_array::GenericArray,
    EncodedPoint,
};
use sec1::point::Coordinates;
use std::fs;
use std::path::PathBuf;

#[cfg(test)]
use rand_core::OsRng;

use crate::error::Result;

pub const PUBLIC_KEY_SIZE: usize = p384::U384::BYTES * 2;
pub const SIGNATURE_SIZE: usize = p384::U384::BYTES * 2;

#[derive(Clone, Debug)]
pub struct MetadataPrivateKey(p384::SecretKey);

#[derive(Clone)]
pub struct MetadataSigningKey(p384::ecdsa::SigningKey);

pub struct MetadataPublicKey(p384::PublicKey);

#[derive(Clone, Debug, PartialEq)]
pub struct MetadataVerifyingKey(p384::ecdsa::VerifyingKey);
pub struct MetadataSignature(p384::ecdsa::Signature);

impl MetadataPrivateKey {
    pub fn from_pem_file(path: &PathBuf) -> Result<Self> {
        let pem = fs::read_to_string(path)?;
        let key = p384::SecretKey::from_sec1_pem(&pem)?;

        Ok(MetadataPrivateKey(key))
    }
}

impl From<MetadataPrivateKey> for MetadataSigningKey {
    fn from(value: MetadataPrivateKey) -> Self {
        MetadataSigningKey(value.0.clone().into())
    }
}

impl From<MetadataPrivateKey> for MetadataPublicKey {
    fn from(value: MetadataPrivateKey) -> Self {
        MetadataPublicKey(value.0.public_key())
    }
}

impl MetadataSigningKey {
    #[cfg(test)]
    pub fn random() -> Self {
        MetadataSigningKey(p384::ecdsa::SigningKey::random(&mut OsRng))
    }

    pub fn sign(&self, data: &[u8]) -> Result<MetadataSignature> {
        let signature: Signature = self.0.sign(data);
        Ok(MetadataSignature(signature))
    }
}

impl From<MetadataSigningKey> for MetadataPrivateKey {
    fn from(value: MetadataSigningKey) -> Self {
        MetadataPrivateKey(value.0.clone().into())
    }
}

impl From<MetadataSigningKey> for MetadataVerifyingKey {
    fn from(value: MetadataSigningKey) -> Self {
        MetadataVerifyingKey(*value.0.verifying_key())
    }
}

impl MetadataPublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        let verifying_key = p384::ecdsa::VerifyingKey::from(&self.0);
        let point = verifying_key.to_encoded_point(false);

        let mut v: Vec<u8> = vec![0; PUBLIC_KEY_SIZE];
        match point.coordinates() {
            Coordinates::Uncompressed { x, y } => {
                v[0..PUBLIC_KEY_SIZE / 2].copy_from_slice(x);
                v[PUBLIC_KEY_SIZE / 2..PUBLIC_KEY_SIZE].copy_from_slice(y);
            }
            _ => panic!("Invalid type of Coordinates, they should be of Uncompressed type!"),
        };
        v
    }
}

impl From<MetadataPublicKey> for MetadataVerifyingKey {
    fn from(value: MetadataPublicKey) -> Self {
        MetadataVerifyingKey(value.0.into())
    }
}

impl MetadataVerifyingKey {
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let point = EncodedPoint::from_untagged_bytes(GenericArray::from_slice(data));
        Ok(Self(p384::ecdsa::VerifyingKey::from_encoded_point(&point)?))
    }

    pub fn verify(&self, signature: &MetadataSignature, data: &[u8]) -> Result<bool> {
        self.0.verify(data, &signature.0)?;
        Ok(true)
    }
}

impl From<MetadataVerifyingKey> for MetadataPublicKey {
    fn from(value: MetadataVerifyingKey) -> Self {
        MetadataPublicKey(value.0.into())
    }
}

impl MetadataSignature {
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Self(Signature::from_slice(data)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
