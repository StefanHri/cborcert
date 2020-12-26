use crate::saving::File;
use crate::saving::Out;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CSRSignedData {
    cbor_certificate_type: u8,
    subject_common_name: String,
    validity_not_before: u64,
    validity_not_after: u64,
    subject_public_key_algorithm: u8,
    extensions: u8,
}

pub struct CSRContent {
    signed_data: CSRSignedData,
    signature: Vec<u8>,
    signature_alg: i16,
    public_key_info: i16,
}

pub struct CSRGenConf {
    pub content: CSRSignedData,
    pub out_files: Vec<File>,
}

pub struct OutCSR<'a> {
    csr_encoded: Vec<u8>,
    pub out_files: &'a [File],
}

impl CSRGenConf {
    pub fn csr_gen(&self) -> Out {
        //todo: Implement the CSR generation here
        let csr_encoded = vec![1];
        let out_files = &self.out_files[..];
        Out::OutCSR(OutCSR {
            csr_encoded,
            out_files,
        })
    }
}
