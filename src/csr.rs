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
    pub scr_meta_data: CSRMetaData,
    pub pk: Vec<u8>,
}

pub struct CSRGenConf {
    pub csr_meta_data: CSRMetaData,
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
    /// * cbor_cert_type
    /// * subject_common_name
    /// * iana public key value indicating the public key algorithm
    /// * public key
    /// * signature over the above fields
    pub fn csr_gen(&self) -> Result<Out, CborCertError> {
        let mut encoded_signed_data = to_vec(&self.csr_meta_data.cbor_cert_type)?;
        encoded_signed_data.extend(
            to_vec(&Bytes::new(&self.csr_meta_data.subject_common_name))?
                .iter()
                .cloned(),
        );
        let alg = Algorithm::new(&self.csr_meta_data.subject_pk_alg)?;

        encoded_signed_data.extend(to_vec(&alg.iana_pk_as_u8()?)?.iter().cloned());
        encoded_signed_data.extend(to_vec(&Bytes::new(&self.pk))?.iter().cloned());

        //println!("encoded_signed_data: {:x?}", encoded_signed_data);

        let signature = alg.sign(&self.pk, &self.sk, &encoded_signed_data)?;
        let mut csr = encoded_signed_data;
        csr.extend(to_vec(&Bytes::new(&signature))?.iter().cloned());

        Ok(Out::OutCSR(OutCSR {
            csr: csr,
            out_files: &self.out_files,
        }))
    }
}
