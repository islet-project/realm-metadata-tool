use array_init::array_init;
use core::fmt::Display;
use hexdump::hexdump;
use semver::Version;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use crate::{
    crypto::{
        self, MetadataPrivateKey, MetadataPublicKey, MetadataSignature, MetadataSigningKey, MetadataVerifyingKey
    },
    error::Result,
    manifest::{HashAlgorithm, Manifest},
    utils,
};

const FMT_VERSION: u64 = 1;
const REALM_ID_SIZE: usize = 128;
const RIM_SIZE_SHA256: usize = 32;
const RIM_SIZE_SHA512: usize = 64;
const RIM_SIZE: usize = {
    const fn max(a: usize, b: usize) -> usize {
        if a > b {
            a
        } else {
            b
        }
    }
    max(RIM_SIZE_SHA256, RIM_SIZE_SHA512)
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Metadata {
    fmt_version: u64,
    #[serde(with = "BigArray")]
    realm_id: [u8; REALM_ID_SIZE],
    #[serde(with = "BigArray")]
    rim: [u8; RIM_SIZE],
    hash_algo: u64,
    version_major: u64,
    version_minor: u64,
    version_patch: u64,
    security_version_number: u64,
    #[serde(with = "BigArray")]
    public_key: [u8; crypto::PUBLIC_KEY_SIZE],
}

impl Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "fmt:        {}", self.fmt_version)?;
        writeln!(f, "realm_id:   '{}'", utils::arr_to_string(&self.realm_id))?;
        writeln!(f, "rim:        {}", utils::arr_to_hex(&self.rim))?;
        writeln!(
            f,
            "hash_algo:  {}",
            HashAlgorithm::try_from(self.hash_algo).unwrap()
        )?;
        writeln!(
            f,
            "version:    {}.{}.{}",
            self.version_major, self.version_minor, self.version_patch
        )?;
        writeln!(f, "svn:        {}", self.security_version_number)?;
        writeln!(f, "public_key: {}", utils::arr_to_hex(&self.public_key))
    }
}

impl Metadata {
    pub fn from_manifest(manifest: &Manifest) -> Result<Self> {
        let ver = Version::parse(manifest.version.as_str())?;

        let mut metadata = Metadata {
            fmt_version: FMT_VERSION,
            realm_id: array_init(|_| 0),
            rim: array_init(|_| 0),
            hash_algo: manifest.hash_algo.clone().into(),
            version_major: ver.major,
            version_minor: ver.minor,
            version_patch: ver.patch,
            security_version_number: manifest.svn,
            public_key: array_init(|_| 0),
        };

        let realm_id_bytes = manifest.realm_id.as_bytes();
        metadata.realm_id[0..realm_id_bytes.len()].copy_from_slice(realm_id_bytes);
        match manifest.hash_algo {
            HashAlgorithm::SHA256 => {
                hex::decode_to_slice(manifest.rim.as_bytes(), &mut metadata.rim[0..32])?
            }
            HashAlgorithm::SHA512 => {
                hex::decode_to_slice(manifest.rim.as_bytes(), &mut metadata.rim[0..64])?
            }
        };
        Ok(metadata)
    }

    pub fn set_public_key(&mut self, public_key: &MetadataPublicKey) {
        self.public_key
            .copy_from_slice(public_key.to_vec().as_slice());
    }

    pub fn get_verifying_key(&self) -> Result<MetadataVerifyingKey> {
        MetadataVerifyingKey::from_slice(&self.public_key)
    }

    pub fn sign(&self, private_key: &MetadataPrivateKey) -> Result<SignedMetadata> {
        let encoded = utils::serialize(self)?;
        let signing_key: MetadataSigningKey = private_key.clone().into();
        let signature = signing_key.sign(encoded.as_slice())?;

        let mut signed_metadata = SignedMetadata {
            metadata: self.clone(),
            signature: array_init(|_| 0),
        };

        signed_metadata
            .signature
            .copy_from_slice(signature.to_vec().as_slice());

        Ok(signed_metadata)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedMetadata {
    metadata: Metadata,
    #[serde(with = "BigArray")]
    signature: [u8; crypto::SIGNATURE_SIZE],
}

impl Display for SignedMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}signature:  {}",
            self.metadata,
            utils::arr_to_hex(&self.signature)
        )
    }
}

impl SignedMetadata {
    pub fn to_file(&self, path: &PathBuf) -> Result<()> {
        let encoded = utils::serialize(self)?;

        let mut file = File::create(path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let metadata = fs::metadata(path)?;
        let mut buffer = vec![0; metadata.len() as usize];
        let mut f = File::open(path)?;
        f.read_exact(&mut buffer)?;

        utils::deserialize(&buffer)
    }

    pub fn get_signature(&self) -> Result<MetadataSignature> {
        MetadataSignature::from_slice(&self.signature)
    }

    pub fn verify(&self) -> Result<bool> {
        let verifying_key = self.metadata.get_verifying_key()?;
        let encoded = utils::serialize(&self.metadata)?;
        let signature = self.get_signature()?;

        verifying_key.verify(&signature, encoded.as_slice())?;

        Ok(true)
    }

    pub fn hexdump(&self) -> Result<()> {
        println!("====");
        hexdump(&utils::serialize(self)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crypto::MetadataSigningKey;

    const METADATA_SIZE: usize = 0x150;
    const SIGNED_METADATA_SIZE: usize = METADATA_SIZE + crypto::SIGNATURE_SIZE;

    fn get_template_metadata() -> Metadata {
        Metadata {
            fmt_version: FMT_VERSION,
            realm_id: array_init(|_| 0),
            rim: array_init(|_| 0),
            hash_algo: 1,
            version_major: 1,
            version_minor: 2,
            version_patch: 3,
            security_version_number: 100,
            public_key: array_init(|_| 0),
        }
    }

    #[test]
    fn check_the_size_of_metadata() {
        let metadata = get_template_metadata();
        assert_eq!(utils::serialize(&metadata).unwrap().len(), METADATA_SIZE);
    }

    #[test]
    fn check_the_size_of_signed_metadata() {
        let signed_metadata = SignedMetadata {
            metadata: get_template_metadata(),
            signature: array_init(|_| 0),
        };

        assert_eq!(
            utils::serialize(&signed_metadata).unwrap().len(),
            SIGNED_METADATA_SIZE
        );
    }

    #[test]
    fn public_key_is_properly_encoded() {
        let signing_key = MetadataSigningKey::random();
        let verifying_key: MetadataVerifyingKey = signing_key.into();
        let public_key: MetadataPublicKey = verifying_key.clone().into();
        let mut metadata = get_template_metadata();
        metadata.set_public_key(&public_key);

        let extracted_verifying_key = metadata.get_verifying_key().unwrap();
        assert_eq!(verifying_key, extracted_verifying_key);
    }

    #[test]
    fn signature_is_valid() {
        let signing_key = MetadataSigningKey::random();
        let private_key: MetadataPrivateKey = signing_key.clone().into();
        let verifying_key: MetadataVerifyingKey = signing_key.into();
        let public_key: MetadataPublicKey = verifying_key.into();

        let mut metadata = get_template_metadata();
        metadata.set_public_key(&public_key);

        let signed_metadata = metadata.sign(&private_key).unwrap();
        assert!(signed_metadata.verify().unwrap());
    }
}
