use crate::algorithm::Algorithm;
use crate::error::CborCertError;
use crate::saving::File;
use crate::saving::Out;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;
use serde_cbor::to_vec;

#[derive(Debug, Deserialize, Serialize)]
pub struct CSRMetaData {
    pub cbor_cert_type: u8,
    pub subject_common_name: Vec<u8>,
    pub subject_pk_alg: String,
}

pub struct CSRSignedData {
    pub data: CSRMetaData,
    pub pk: Vec<u8>,
}

pub struct CSRGenConf {
    pub data: CSRMetaData,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub out_files: Vec<File>,
}

pub struct OutCSR<'a> {
    pub csr: Vec<u8>,
    pub out_files: &'a [File],
}

  
impl CSRGenConf {
    /// Generates a CSR
    /// The CSR contains:
    /// 1) cbor_cert_type
    /// 2) subject_common_name
    /// 3) iana public key value indicating the public key algorithm
    /// 4) public key
    /// 5) signature over the above fields
    pub fn csr_gen(&self) -> Result<Out, CborCertError> {
        //1) cbor_cert_type
        let mut data = to_vec(&self.data.cbor_cert_type)?;
        //2) subject_common_name
        data.extend(
            to_vec(&Bytes::new(&self.data.subject_common_name))?
                .iter()
                .cloned(),
        );
        //3) iana public key value indicating the public key algorithm
        let alg = Algorithm::new(&self.data.subject_pk_alg)?;
        data.extend(to_vec(&alg.iana_pk_as_u8()?)?.iter().cloned());
        //4) public key
        data.extend(to_vec(&Bytes::new(&self.pk))?.iter().cloned());
        //5) signature over the above fields
        let signature = alg.sign(&self.pk, &self.sk, &data)?;
        let mut csr = data;
        csr.extend(to_vec(&Bytes::new(&signature))?.iter().cloned());

        Ok(Out::OutCSR(OutCSR {
            csr: csr,
            out_files: &self.out_files,
        }))
    }
}
