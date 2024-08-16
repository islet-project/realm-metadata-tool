use array_init::array_init;
use core::fmt::Display;
use hexdump::hexdump;
use p384::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::generic_array::GenericArray,
    EncodedPoint,
};
use sec1::point::Coordinates;
use semver::Version;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use crate::{
    crypto,
    error::Result,
    manifest::{HashAlgorithm, Manifest},
    utils,
};

const FMT_VERSION: u64 = 1;
const REALM_ID_SIZE: usize = 128;
const RIM_SIZE: usize = 64;
const PUBLIC_KEY_SIZE: usize = 96;
const SIGNATURE_SIZE: usize = 96;

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
    public_key: [u8; PUBLIC_KEY_SIZE],
}

impl Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "fmt:        {}", self.fmt_version)?;
        writeln!(f, "realm_id:   '{}'", utils::arr_to_string(&self.realm_id))?;
        writeln!(f, "rim:        {}", utils::arr_to_hex(&self.rim))?;
        writeln!(f, "hash_algo:  {}", HashAlgorithm::try_from(self.hash_algo).unwrap())?;
        writeln!(f, "version:    {}.{}.{}", self.version_major, self.version_minor, self.version_patch)?;
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

    pub fn set_public_key(&mut self, public_key: &p384::PublicKey) {
        let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
        let point = verifying_key.to_encoded_point(false);

        match point.coordinates() {
            Coordinates::Uncompressed { x, y } => {
                self.public_key[0..PUBLIC_KEY_SIZE / 2].copy_from_slice(x);
                self.public_key[PUBLIC_KEY_SIZE / 2..PUBLIC_KEY_SIZE].copy_from_slice(y);
            }
            _ => panic!("Invalid type of Coordinates, they should be Uncompressed!"),
        }
    }

    pub fn get_verifying_key(&self) -> Result<VerifyingKey> {
        let point = EncodedPoint::from_untagged_bytes(GenericArray::from_slice(&self.public_key));
        Ok(VerifyingKey::from_encoded_point(&point)?)
    }

    pub fn sign(&self, private_key: &p384::SecretKey) -> Result<SignedMetadata> {
        let encoded = utils::serialize(self)?;
        let signature = crypto::sign(&encoded, private_key)?;

        let mut signed_metadata = SignedMetadata {
            metadata: self.clone(),
            signature: array_init(|_| 0),
        };

        signed_metadata
            .signature
            .copy_from_slice(signature.to_bytes().as_slice());

        Ok(signed_metadata)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignedMetadata {
    metadata: Metadata,
    #[serde(with = "BigArray")]
    signature: [u8; SIGNATURE_SIZE],
}

impl Display for SignedMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}signature: '{}'",
            self.metadata, utils::arr_to_hex(&self.signature))
    }
}

impl SignedMetadata {
    pub fn write(&self, path: &PathBuf) -> Result<()> {
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

    pub fn get_signature(&self) -> Result<Signature> {
        Ok(Signature::from_slice(&self.signature)?)
    }

    pub fn verify(&self) -> Result<bool> {
        let verifying_key = self.metadata.get_verifying_key()?;
        let encoded = utils::serialize(&self.metadata)?;
        let signature = self.get_signature()?;

        verifying_key.verify(&encoded, &signature)?;

        Ok(true)
    }

    pub fn hexdump(&self) -> Result<()> {
        println!("====");
        hexdump(&utils::serialize(self)?);
        Ok(())
    }
}
