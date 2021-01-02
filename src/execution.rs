use crate::cert::CertGenConf;
use crate::csr::CSRGenConf;
use crate::error::CborCertError;
use crate::keygen::{KeyGenConf, OutKeyPair};
use crate::saving::Out;

//https://stackoverflow.com/questions/57066471/how-do-i-implement-a-trait-for-an-enum-and-its-respective-variants

pub trait Execution {
    fn execute(&self) -> Result<Out, CborCertError>;
}

pub enum Config {
    KeyGen(KeyGenConf),
    CSRGen(CSRGenConf),
    CertGen(CertGenConf),
}

impl Execution for Config {
    fn execute(&self) -> Result<Out, CborCertError> {
        match self {
            Config::KeyGen(key_gen_conf) => key_gen_conf.execute(),
            Config::CSRGen(csr_gen_conf) => csr_gen_conf.execute(),
            Config::CertGen(cert_gen_conf) => cert_gen_conf.execute(),
        }
    }
}

impl Execution for KeyGenConf {
    fn execute(&self) -> Result<Out, CborCertError> {
        Ok(Out::OutKeyPair(OutKeyPair {
            key_pair: self.algorithm.key_gen()?,
            out_files: &self.out_files,
        }))
    }
}

impl Execution for CSRGenConf {
    fn execute(&self) -> Result<Out, CborCertError> {
        self.csr_gen()
    }
}

impl Execution for CertGenConf {
    fn execute(&self) -> Result<Out, CborCertError> {
        self.cert_gen()
    }
}