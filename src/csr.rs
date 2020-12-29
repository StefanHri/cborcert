use crate::error::CborCertError;
use crate::saving::File;
use crate::saving::Out;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;
use serde_cbor::{to_vec, value::to_value, Serializer};

#[derive(Debug, Deserialize, Serialize)]
pub struct CSRMetaData {
    cbor_certificate_type: u8,
    subject_common_name: Vec<u8>,
    subject_public_key_algorithm: u8,
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

pub struct CSRContent {
    signed_data: Vec<u8>,
    signature: Vec<u8>,
    //    signature_alg: i16,
    //    public_key_info: i16,
}

pub struct CSRGenConf {
    pub csr_meta_data: CSRMetaData,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub out_files: Vec<File>,
}

pub struct OutCSR<'a> {
    csr: CSRContent,
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
        encoded_signed_data.extend(
            to_vec(&self.csr_meta_data.subject_public_key_algorithm)?
                .iter()
                .cloned(),
        );
        encoded_signed_data.extend(to_vec(&Bytes::new(&self.pk))?.iter().cloned());

        println!("encoded_signed_data: {:x?}", encoded_signed_data);


        //sign the data with the own sk
        //todo match on the algorithm
        let keypair = Keypair {
            secret: SecretKey::from_bytes(&self.sk)?,
            public: PublicKey::from_bytes(&self.pk)?,
        };
        let signature = keypair.sign(&encoded_signed_data).to_bytes();
        println!("signature: {:x?}", signature);

        let csr = CSRContent {
            signed_data: encoded_signed_data,
            signature: signature.to_vec(),
        };

        Ok(Out::OutCSR(OutCSR {
            csr: csr,
            out_files: &self.out_files,
        }))
    }
}
