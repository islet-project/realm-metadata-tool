use p384::ecdsa::{signature::Signer, Signature};
use std::fs;
use std::path::PathBuf;

use crate::error::Result;

pub fn load_private_key(path: &PathBuf) -> Result<p384::SecretKey> {
    let pem = fs::read_to_string(path)?;
    let key = p384::SecretKey::from_sec1_pem(&pem)?;

    Ok(key)
}

pub fn derive_public_key(private_key: &p384::SecretKey) -> p384::PublicKey {
    private_key.public_key()
}

pub fn sign(data: &[u8], private_key: &p384::SecretKey) -> Result<Signature> {
    let signing_key = p384::ecdsa::SigningKey::from(private_key);
    let signature: Signature = signing_key.sign(data);
    Ok(signature)
}
