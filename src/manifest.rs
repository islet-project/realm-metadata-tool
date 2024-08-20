use semver::Version;
use serde::Deserialize;
use std::fmt::Display;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

const REALM_ID_MAX_LEN: usize = 128;
const MIN_SVN_NUMBER: u64 = 1;
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
    pub fn from_yaml(path: &PathBuf) -> crate::error::Result<Self> {
        let yaml = fs::read_to_string(path)?;
        let manifest: Manifest = serde_yaml::from_str(&yaml)?;
        manifest
            .validate_realm_id()?
            .validate_version()?
            .validate_svn()?
            .validate_rim()?;
        Ok(manifest)
    }

    fn validate_realm_id(&self) -> Result<&Self, ManifestError> {
        if !self.realm_id.is_ascii()
            || self.realm_id.is_empty()
            || self.realm_id.len() > REALM_ID_MAX_LEN
        {
            Err(ManifestError::InvalidRealmId(self.realm_id.clone()))
        } else {
            Ok(self)
        }
    }

    fn validate_version(&self) -> Result<&Self, ManifestError> {
        match Version::parse(self.version.as_str()) {
            Ok(version) => {
                if !version.pre.is_empty() || !version.build.is_empty() {
                    Err(ManifestError::InvalidVersion(self.version.clone()))
                } else {
                    Ok(self)
                }
            }
            Err(_) => Err(ManifestError::InvalidVersion(self.version.clone())),
        }
    }

    fn validate_svn(&self) -> Result<&Self, ManifestError> {
        if self.svn < MIN_SVN_NUMBER {
            Err(ManifestError::InvalidSVN(self.svn))
        } else {
            Ok(self)
        }
    }

    fn validate_rim(&self) -> Result<&Self, ManifestError> {
        if !self.rim.is_ascii() || !self.rim.chars().all(|c| c.is_ascii_hexdigit()) {
            Err(ManifestError::InvalidRIM(self.rim.clone()))
        } else {
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
            Ok(self)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn get_template_manifest() -> Manifest {
        Manifest {
            realm_id: String::from("ala.ma.kota"),
            version: String::from("1.2.3"),
            svn: 100,
            rim: String::from("deadbeefcafed0dadeadbeefcafed0dadeadbeefcafed0dadeadbeefcafed0da"),
            hash_algo: HashAlgorithm::SHA256,
        }
    }

    #[test]
    fn realm_id_is_valid() {
        assert!(get_template_manifest().validate_realm_id().is_ok());
    }

    #[test]
    fn realm_id_is_empty() {
        let manifest = Manifest {
            realm_id: String::from(""),
            ..get_template_manifest()
        };

        assert!(manifest.validate_realm_id().is_err());
    }

    #[test]
    fn realm_id_contains_non_ascii() {
        let manifest = Manifest {
            realm_id: String::from("👾🌏🚀"),
            ..get_template_manifest()
        };

        assert!(manifest.validate_realm_id().is_err());
    }

    #[test]
    fn version_is_valid() {
        assert!(get_template_manifest().validate_version().is_ok());
    }

    #[test]
    fn version_has_improper_format() {
        let manifest = Manifest {
            version: String::from("abrakadabra"),
            ..get_template_manifest()
        };

        assert!(manifest.validate_version().is_err());
    }

    #[test]
    fn version_is_missing_patch_number() {
        let manifest = Manifest {
            version: String::from("1.2"),
            ..get_template_manifest()
        };

        assert!(manifest.validate_version().is_err());
    }

    #[test]
    fn version_has_prerelease_component() {
        let manifest = Manifest {
            version: String::from("1.2.3-alpha.1"),
            ..get_template_manifest()
        };

        assert!(manifest.validate_version().is_err());
    }

    #[test]
    fn version_has_build_component() {
        let manifest = Manifest {
            version: String::from("1.2.3+build.1.2.3"),
            ..get_template_manifest()
        };

        assert!(manifest.validate_version().is_err());
    }

    #[test]
    fn svn_is_valid() {
        assert!(get_template_manifest().validate_svn().is_ok());
    }

    #[test]
    fn svn_is_invalid() {
        let manifest = Manifest {
            svn: 0,
            ..get_template_manifest()
        };
        assert!(manifest.validate_svn().is_err());
    }

    #[test]
    fn rim_is_valid() {
        assert!(get_template_manifest().validate_rim().is_ok());
    }

    #[test]
    fn rim_doesnt_match_hash_algo() {
        let manifest = Manifest {
            hash_algo: HashAlgorithm::SHA512,
            ..get_template_manifest()
        };
        assert!(manifest.validate_rim().is_err());
    }

    #[test]
    fn rim_is_not_hexadecimal_string() {
        let manifest = Manifest {
            rim: String::from("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas fringilla enim sed sem interdum, non hendrerit neque egestas. Quisque in maximus sapien. Maecenas iaculis diam in feugiat pulvinar. Duis aliquam non nulla in iaculis."),
            ..get_template_manifest()
        };
        assert!(manifest.validate_rim().is_err());
    }

    #[test]
    fn rim_contains_non_ascii() {
        let manifest = Manifest {
            rim: String::from("👾🌏🚀"),
            ..get_template_manifest()
        };
        assert!(manifest.validate_rim().is_err());
    }
}
