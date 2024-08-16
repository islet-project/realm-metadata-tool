use semver::Version;
use serde::Deserialize;
use std::fmt::Display;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

const REALM_ID_MAX_LEN: usize = 128;
const SHA256_HEX_STR_LEN: usize = 64;
const SHA512_HEX_STR_LEN: usize = 128;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Invalid realm_id: \"{0}\"")]
    InvalidRealmId(String),
    #[error("Invalid version: \"{0}\"")]
    InvalidVersion(String),
    #[error("Invalid svn: \"{0}\"")]
    InvalidSVN(u64),
    #[error("Invalid rim: \"{0}\"")]
    InvalidRIM(String),
    #[error("Invalid hash algorithm number: \"{0}\"")]
    InvalidHashAlgoNum(u64),
}

#[derive(Deserialize, Debug, Clone)]
pub enum HashAlgorithm {
    SHA256 = 1,
    SHA512 = 2,
}

impl From<HashAlgorithm> for u64 {
    fn from(value: HashAlgorithm) -> Self {
        match value {
            HashAlgorithm::SHA256 => 1,
            HashAlgorithm::SHA512 => 2,
        }
    }
}

impl TryFrom<u64> for HashAlgorithm {
    type Error = ManifestError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HashAlgorithm::SHA256),
            2 => Ok(HashAlgorithm::SHA512),
            n => Err(ManifestError::InvalidHashAlgoNum(n)),
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::SHA256 => write!(f, "SHA256"),
            HashAlgorithm::SHA512 => write!(f, "SHA512"),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct Manifest {
    pub realm_id: String,
    pub version: String,
    pub svn: u64,
    pub rim: String,
    pub hash_algo: HashAlgorithm,
}

impl Manifest {
    pub fn from_yaml(path: &PathBuf) -> crate::error::Result<Manifest> {
        let yaml = fs::read_to_string(path)?;
        let manifest: Manifest = serde_yaml::from_str(&yaml)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        if !self.realm_id.is_ascii()
            || self.realm_id.is_empty()
            || self.realm_id.len() > REALM_ID_MAX_LEN
        {
            return Err(ManifestError::InvalidRealmId(self.realm_id.clone()));
        }

        match Version::parse(self.version.as_str()) {
            Ok(_) => {}
            Err(_) => return Err(ManifestError::InvalidVersion(self.version.clone())),
        }

        if self.svn < 1 {
            return Err(ManifestError::InvalidSVN(self.svn));
        }

        if !self.rim.is_ascii() || !self.rim.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ManifestError::InvalidRIM(self.rim.clone()));
        }

        match self.hash_algo {
            HashAlgorithm::SHA256 => {
                if self.rim.len() != SHA256_HEX_STR_LEN {
                    return Err(ManifestError::InvalidRIM(self.rim.clone()));
                }
            }
            HashAlgorithm::SHA512 => {
                if self.rim.len() != SHA512_HEX_STR_LEN {
                    return Err(ManifestError::InvalidRIM(self.rim.clone()));
                }
            }
        }

        Ok(())
    }
}
