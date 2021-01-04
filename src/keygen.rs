use crate::algorithm::{Algorithm, KeyPair};
use crate::saving::File;

pub struct KeyGenConf {
    pub algorithm: Algorithm,
    pub out_files: Vec<File>,
}

pub struct OutKeyPair<'a> {
    pub alg_pk_name: String,
    pub key_pair: KeyPair,
    pub out_files: &'a [File],
}
