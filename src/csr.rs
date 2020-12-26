use crate::saving::File;
use crate::saving::Out;

pub struct CSRSignedData {
    pub subject_common_name: Vec<u8>,
    pub public_key: Vec<u8>,
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
