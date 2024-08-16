use std::path::PathBuf;

use crate::crypto;
use crate::error::Result;
use crate::manifest::Manifest;
use crate::metadata::{Metadata, SignedMetadata};

pub fn create_metadata_file(manifest: &PathBuf, key: &PathBuf, output: &PathBuf) -> Result<()> {
    let manifest = Manifest::from_yaml(manifest)?;
    let mut metadata = Metadata::from_manifest(&manifest)?;
    let private_key = crypto::load_private_key(key)?;
    let public_key = crypto::derive_public_key(&private_key);
    metadata.set_public_key(&public_key);

    metadata.sign(&private_key)?.write(output)
}

pub fn verify_metadata_file(input: &PathBuf) -> Result<bool> {
    SignedMetadata::from_file(input)?.verify()
}

pub fn dump_metadata_file(input: &PathBuf, print_hexdump: bool) -> Result<()> {
    let signed_metadata = SignedMetadata::from_file(input)?;
    println!("{}", signed_metadata);
    if print_hexdump {
        signed_metadata.hexdump()?;
    }
    Ok(())
}
