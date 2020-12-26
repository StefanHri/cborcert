//use std::error::Error;
use std::fmt;
use std::io;

//https://blog.burntsushi.net/rust-error-handling/#composing-option-and-result

#[derive(Debug)]
pub enum CborCertError {
    Io(io::Error),
    UnknownFileFormat,
    TooManyArguments,
    TooFewArguments,
    NoPointInFileName,
    UnsupportedAlgorithm,
}

impl fmt::Display for CborCertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CborCertError::Io(ref err) => err.fmt(f),
            CborCertError::UnknownFileFormat => write!(f, "Unknown file format."),
            CborCertError::TooManyArguments => write!(f, "Too many arguments."),
            CborCertError::TooFewArguments => write!(f, "Too few arguments."),
            CborCertError::NoPointInFileName => {
                write!(f, "The file must have a format, e.g, key.der oder key.c.")
            }
            CborCertError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm."),
        }
    }
}

// The Error trait is meant to be implemented for all types that represent
// errors.
// The trait allows you to do at least the following things:
// Obtain a Debug representation of the error.
// Obtain a user-facing Display representation of the error.
// Obtain a short description of the error (via the description method).
// Inspect the causal chain of an error, if one exists (via the cause method).

// impl Error for CborCertError {
//     fn description(&self) -> &str {
//         match *self {
//             CborCertError::Io(ref err) => err.description(),
//             CborCertError::UnknownFileFormat => "Unknown file format.",
//             CborCertError::TooManyArguments => "Too many arguments.",
//             CborCertError::TooFewArguments => "Too few arguments.",
//             CborCertError::NoPointInFileName => {
//                 "The file must have a format, e.g, key.der oder key.c."
//             }
//             CborCertError::UnsupportedAlgorithm => "Unsupported algorithm.",
//         }
//     }
// }

//conversion from io:Error to CborCertError
impl From<io::Error> for CborCertError {
    fn from(err: io::Error) -> CborCertError {
        CborCertError::Io(err)
    }
}
