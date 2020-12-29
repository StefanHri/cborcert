use crate::error::CborCertError;
use crate::saving::File;
use crate::saving::Out;

use crate::algorithm::Algorithm;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;
use serde_cbor::to_vec;

#[derive(Debug, Deserialize, Serialize)]
pub struct CSRMetaData {
    cbor_certificate_type: u8,
    subject_common_name: Vec<u8>,
    subject_public_key_algorithm: String,
}

#[derive(Debug, Serialize)]
pub struct CSRSignedData {
    // cbor_certificate_type: u8,
    #[serde(with = "serde_bytes")]
    subject_common_name: Vec<u8>,
    // subject_public_key_algorithm: u8,
    // #[serde(with = "serde_bytes")]
    // subject_public_key: Vec<u8>,
}

//pub struct CSRContent {
//    pub signed_data: Vec<u8>,
//    pub signature: Vec<u8>,
//    signature_alg: i16,
//    public_key_info: i16,
//}

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
    pub fn csr_gen(&self) -> Result<Out, CborCertError> {
        let mut encoded_signed_data = to_vec(&self.csr_meta_data.cbor_certificate_type)?;
        encoded_signed_data.extend(
            to_vec(&Bytes::new(&self.csr_meta_data.subject_common_name))?
                .iter()
                .cloned(),
        );
        let alg = Algorithm::alg_from_string(&self.csr_meta_data.subject_public_key_algorithm)?;
        let iana_alg_val = alg.to_iana_pk_value();

        encoded_signed_data.extend(to_vec(&iana_alg_val)?.iter().cloned());
        encoded_signed_data.extend(to_vec(&Bytes::new(&self.pk))?.iter().cloned());

        println!("encoded_signed_data: {:x?}", encoded_signed_data);

        let signature = alg.sign(&self.pk, &self.sk, &encoded_signed_data)?;
        encoded_signed_data.extend(to_vec(&Bytes::new(&signature))?.iter().cloned());

        Ok(Out::OutCSR(OutCSR {
            csr: encoded_signed_data,
            out_files: &self.out_files,
        }))
    }
}
