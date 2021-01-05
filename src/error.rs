//use std::error::Error;
use std::fmt;
use std::io;

//https://blog.burntsushi.net/rust-error-handling/#composing-option-and-result

#[derive(Debug)]
pub enum CborCertError {
    Ed25519(ed25519_dalek::ed25519::Error),
    Cbor(serde_cbor::Error),
    SerDe(toml::de::Error),
    Io(io::Error),
    UnknownFileFormat,
    TooManyArguments,
    TooFewArguments,
    NoPointInFileName,
    UnsupportedAlgorithm,
    KeyCannotBeSavedInTomlFile,
    CSRCannotBeSavedInTomlFile,
    NotASignatureAlgorithm,
    NoIanaVal,
    VerCannotBeSavedInCFile,
    VerCannotBeSavedInDerFile,
}

impl fmt::Display for CborCertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CborCertError::Ed25519(ref err) => err.fmt(f),
            CborCertError::Cbor(ref err) => err.fmt(f),
            CborCertError::SerDe(ref err) => err.fmt(f),
            CborCertError::Io(ref err) => err.fmt(f),
            CborCertError::UnknownFileFormat => write!(f, "Unknown file format."),
            CborCertError::TooManyArguments => write!(f, "Too many arguments."),
            CborCertError::TooFewArguments => write!(f, "Too few arguments."),
            CborCertError::NoPointInFileName => {
                write!(f, "The file must have a format, e.g, key.der oder key.c.")
            }
            CborCertError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm."),
            CborCertError::KeyCannotBeSavedInTomlFile => {
                write!(f, "A key cannot be saved in .toml file.")
            }
            CborCertError::CSRCannotBeSavedInTomlFile => {
                write!(f, "A CSR cannot be saved in .toml file.")
            }
            CborCertError::NotASignatureAlgorithm => {
                write!(f, "This is not a signature algorithm.")
            }
            CborCertError::NoIanaVal => {
                write!(f, "No IANA value.")
            }
            CborCertError::VerCannotBeSavedInCFile => {
                write!(
                    f,
                    "The decoded CBOR certificate content cannot be saved in .c file."
                )
            }
            CborCertError::VerCannotBeSavedInDerFile => {
                write!(
                    f,
                    "The decoded CBOR certificate content cannot be saved in .der file."
                )
            }
        }
    }
}

impl From<io::Error> for CborCertError {
    fn from(err: io::Error) -> CborCertError {
        CborCertError::Io(err)
    }
}

impl From<toml::de::Error> for CborCertError {
    fn from(err: toml::de::Error) -> CborCertError {
        CborCertError::SerDe(err)
    }
}

impl From<serde_cbor::Error> for CborCertError {
    fn from(err: serde_cbor::Error) -> CborCertError {
        CborCertError::Cbor(err)
    }
}

impl From<ed25519_dalek::ed25519::Error> for CborCertError {
    fn from(err: ed25519_dalek::ed25519::Error) -> CborCertError {
        CborCertError::Ed25519(err)
    }
}
