use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO File error {0}")]
    IOFile(#[from] std::io::Error),
    #[error("Yaml Deserialization error {0}")]
    YamlDeserialization(#[from] serde_yaml::Error),
    #[error("Json Serialization error")]
    P384EllipticCurve(#[from] p384::elliptic_curve::Error),
    #[error("P384PKCS8DerError: {0}")]
    P384PKCS8Der(#[from] p384::pkcs8::der::Error),
    #[error("P384ECDSAError: {0}")]
    P384ECDSA(#[from] p384::ecdsa::Error),
    #[error("Sec1Error: {0}")]
    Sec1(#[from] sec1::Error),
    #[error("ManifestError: {0}")]
    Manifest(#[from] crate::manifest::ManifestError),
    #[error("SemverError: {0}")]
    Semver(#[from] semver::Error),
    #[error("FromHexError: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("BincodeError: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
}

pub type Result<T> = std::result::Result<T, Error>;
