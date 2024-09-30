use std::path::PathBuf;

use crate::crypto::MetadataPrivateKey;
use crate::crypto::MetadataPublicKey;
use crate::error::Result;
use crate::manifest::Manifest;
use crate::metadata::{Metadata, SignedMetadata};

pub fn create_metadata_file(manifest: &PathBuf, key: &PathBuf, output: &PathBuf) -> Result<()> {
    let manifest = Manifest::from_yaml(manifest)?;
    let mut metadata = Metadata::from_manifest(&manifest)?;
    let private_key = MetadataPrivateKey::from_pem_file(key)?;
    let public_key: MetadataPublicKey = private_key.clone().into();
    metadata.set_public_key(&public_key);

    metadata.sign(&private_key)?.to_file(output)
}

pub fn verify_metadata_file(input: &PathBuf) -> Result<bool> {
    SignedMetadata::from_file(input)?.verify()
}

pub fn dump_metadata_file(input: &PathBuf, print_hexdump: bool) -> Result<()> {
    let signed_metadata = SignedMetadata::from_file(input)?;
    println!("{}", signed_metadata);
    if print_hexdump {
        println!("-- hexdump --");
        signed_metadata.hexdump()?;
    }
    Ok(())
}
