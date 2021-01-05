use crate::algorithm::{Algorithm, KeyPair};
use crate::error::CborCertError;
use crate::saving::File;
use crate::saving::Out;

pub struct KeyGenConf {
    pub algorithm: Algorithm,
    pub out_files: Vec<File>,
}

pub struct OutKeyPair<'a> {
    pub alg_pk_name: String,
    pub key_pair: KeyPair,
    pub out_files: &'a [File],
}

impl KeyGenConf {
    ///generates a random key pair
    pub fn key_gen(&self) -> Result<Out, CborCertError> {
        Ok(Out::OutKeyPair(OutKeyPair {
            alg_pk_name: self
                .algorithm
                .name_pk_as_string()?
                .replace("-", "_")
                .replace(" ", "")
                .replace("+", "_"),
            key_pair: self.algorithm.key_gen()?,
            out_files: &self.out_files,
        }))
    }
}
