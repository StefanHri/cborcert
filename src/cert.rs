use crate::algorithm::Algorithm;
use crate::csr::{CSRMetaData, CSRSignedData};
use crate::error::CborCertError;
use crate::saving::File;
use crate::saving::Out;
use serde::Deserialize;
use serde_bytes::Bytes;
use serde_cbor::{to_vec, Deserializer};
use serde_derive::Serialize;

#[derive(Deserialize)]
pub struct CAconf {
    pub certificate_serial_number: Vec<u8>,
    pub issuer: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub extensions: i8, //to do check if this needs to be provided differently in the toml file
    pub issuer_signature_algorithm: String,
}

pub struct CertGenConf {
    pub ca_conf: CAconf,
    pub csr: Vec<u8>,
    pub ca_pk: Vec<u8>,
    pub ca_sk: Vec<u8>,
    pub out_files: Vec<File>,
}

pub struct CertVerConf {
    pub cert: Vec<u8>,
    pub ca_pk: Vec<u8>,
    pub out_files: Vec<File>,
}

#[derive(Serialize)]
pub struct TBSCertificate {
    cbor_cert_type: u8,
    cert_serial_number: Vec<u8>,
    issuer: Vec<u8>,
    validity_not_before: i64,
    validity_not_after: i64,
    subject: Vec<u8>,
    subject_pk_alg: i16,
    subject_pk: Vec<u8>,
    extensions: i16,
    issuer_sgn_alg: u8,
}

#[derive(Serialize)]
pub struct CBORCertificate {
    pub signed_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub decoded_data: TBSCertificate,
}

struct Field<T> {
    offset: usize,
    field: T,
}

pub struct OutCert<'a> {
    pub cert: Vec<u8>,
    pub out_files: &'a [File],
}

pub struct OutVer<'a> {
    pub cert: CBORCertificate,
    pub out_files: &'a [File],
}

impl CertVerConf {
    pub fn cert_ver(&self) -> Result<Out, CborCertError> {
        let d = decode_native(&self.cert)?;
        let alg = Algorithm::new_sgn_alg_from_sgn_num(d.decoded_data.issuer_sgn_alg)?;
        alg.verify(&d.signed_data, &d.signature, &self.ca_pk)?;
        println!("Certificate verification: OK");
        Ok(Out::OutVer(OutVer {
            cert: d,
            out_files: &self.out_files,
        }))
    }
}

impl CertGenConf {
    //to do check the cbor_cer_type 0 or 1 with the test vector
    pub fn cert_gen(&self) -> Result<Out, CborCertError> {
        //verify the the csr
        let csr = csr_verify(&self.csr)?;
        //start the CBOR encoding
        //1) cborCertificateType
        let mut encoded_signed_data = to_vec(&csr.scr_meta_data.cbor_cert_type)?;
        //2) certificateSerialNumber
        encoded_signed_data.extend(
            to_vec(&Bytes::new(&self.ca_conf.certificate_serial_number))?
                .iter()
                .cloned(),
        );
        //3) issuer
        encoded_signed_data.extend(to_vec(&self.ca_conf.issuer)?.iter().cloned());
        //4) validityNotBefore
        encoded_signed_data.extend(to_vec(&self.ca_conf.validity_not_before)?.iter().cloned());
        //5) validityNotAfter
        encoded_signed_data.extend(to_vec(&self.ca_conf.validity_not_after)?.iter().cloned());
        //6) subject
        encoded_signed_data.extend(
            to_vec(&Bytes::new(&csr.scr_meta_data.subject_common_name))?
                .iter()
                .cloned(),
        );
        //7) subjectPublicKeyAlgorithm
        println!(
            "scr_meta_data.subject_pk_alg {}",
            &csr.scr_meta_data.subject_pk_alg
        );
        let subject_alg = Algorithm::new(&csr.scr_meta_data.subject_pk_alg)?;
        encoded_signed_data.extend(to_vec(&subject_alg.iana_pk_as_u8()?)?.iter().cloned());

        //8) subjectPublicKey
        encoded_signed_data.extend(to_vec(&Bytes::new(&csr.pk))?.iter().cloned());
        //9) extensions
        encoded_signed_data.extend(to_vec(&self.ca_conf.extensions)?.iter().cloned());
        //10) issuerSignatureAlgorithm
        let issuer_alg = Algorithm::new(&self.ca_conf.issuer_signature_algorithm)?;
        encoded_signed_data.extend(to_vec(&issuer_alg.iana_sgn_as_u8()?)?.iter().cloned());

        //calculate signature
        let signature = issuer_alg.sign(&self.ca_pk, &self.ca_sk, &encoded_signed_data)?;
        println!("signature: {:?}", signature);
        let mut cert = encoded_signed_data;
        cert.extend(to_vec(&Bytes::new(&signature))?.iter().cloned());

        Ok(Out::OutCert(OutCert {
            cert: cert,
            out_files: &self.out_files,
        }))
    }
}

fn get_field<'a, T>(cert: &'a [u8], offset: usize) -> Result<Field<T>, CborCertError>
where
    T: serde::de::Deserialize<'a>,
{
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);

    let field = Field {
        field: serde::de::Deserialize::deserialize(&mut d)?,
        offset: offset + d.byte_offset(),
    };

    Ok(field)
}

fn csr_verify(csr: &[u8]) -> Result<CSRSignedData, CborCertError> {
    let cbor_cert_type: Field<u8> = get_field(&csr, 0)?;
    let subject_cn: Field<&[u8]> = get_field(&csr, cbor_cert_type.offset)?;
    let subject_pk_alg: Field<u8> = get_field(&csr, subject_cn.offset)?;
    let pk: Field<&[u8]> = get_field(&csr, subject_pk_alg.offset)?;
    let signature: Field<&[u8]> = get_field(&csr, pk.offset)?;

    let signed_data = csr[..pk.offset].to_vec();

    println!("subject_pk_alg: {}", subject_pk_alg.field);

    let alg = Algorithm::new_sgn_alg_from_pk_num(subject_pk_alg.field)?;
    println!("alg {:?}", alg);
    alg.verify(&signed_data, signature.field, pk.field)?;

    let scr_meta_data = CSRMetaData {
        cbor_cert_type: cbor_cert_type.field,
        subject_common_name: subject_cn.field.to_vec(),
        subject_pk_alg: alg.name_pk_as_string()?,
    };

    Ok(CSRSignedData {
        scr_meta_data: scr_meta_data,
        pk: pk.field.to_vec(),
    })
}

fn decode_native(cert: &[u8]) -> Result<CBORCertificate, CborCertError> {
    let cbor_cert_type: Field<u8> = get_field(&cert, 0)?;
    let cert_serial_number: Field<&[u8]> = get_field(&cert, cbor_cert_type.offset)?;
    let issuer: Field<&[u8]> = get_field(&cert, cert_serial_number.offset)?;
    let validity_not_before: Field<i64> = get_field(&cert, issuer.offset)?;
    let validity_not_after: Field<i64> = get_field(&cert, validity_not_before.offset)?;
    let subject: Field<&[u8]> = get_field(&cert, validity_not_after.offset)?;
    let subject_pk_alg: Field<i16> = get_field(&cert, subject.offset)?;
    let subject_pk: Field<&[u8]> = get_field(&cert, subject_pk_alg.offset)?;
    let extensions: Field<i16> = get_field(&cert, subject_pk.offset)?;
    let issuer_sgn_alg: Field<u8> = get_field(&cert, extensions.offset)?;
    let signature: Field<&[u8]> = get_field(&cert, issuer_sgn_alg.offset)?;

    //here we get the signed data
    let signed_data = cert[..issuer_sgn_alg.offset].to_vec();

    println!("-----------------------------------------------------");
    println!("cbor_cert_type is: {:?}", cbor_cert_type.field);
    println!("cert_serial_number is: {:02x?}", cert_serial_number.field);
    println!("issuer is: {:?}", issuer.field);
    println!("validity_not_before is: {:?}", validity_not_before.field);
    println!("validity_not_after is: {:?}", validity_not_after.field);
    println!("subject is: {:02x?}", subject.field);
    println!("subject_pk_alg is: {:}", subject_pk_alg.field);
    println!("subject_pk is: {:02x?}", subject_pk.field);
    println!("extensions is: {:}", extensions.field);
    println!("issuer_sgn_alg is: {:}", issuer_sgn_alg.field);
    println!("signed_data is: {:02x?}", signed_data);
    println!("signature is: {:02x?}", signature.field);
    println!("-----------------------------------------------------");

    let decoded_data = TBSCertificate {
        cbor_cert_type: cbor_cert_type.field,
        cert_serial_number: cert_serial_number.field.to_vec(),
        issuer: issuer.field.to_vec(),
        validity_not_before: validity_not_before.field,
        validity_not_after: validity_not_after.field,
        subject: subject.field.to_vec(),
        subject_pk_alg: subject_pk_alg.field,
        subject_pk: subject_pk.field.to_vec(),
        extensions: extensions.field,
        issuer_sgn_alg: issuer_sgn_alg.field,
    };

    Ok(CBORCertificate {
        signed_data,
        decoded_data,
        signature: signature.field.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_native_test() {
        let cert = vec![
            0x01, 0x43, 0x01, 0xF5, 0x0D, 0x6B, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x43, 0x41, 0x1A, 0x5E, 0x0B, 0xE1, 0x00, 0x1A, 0x60, 0x18, 0x96, 0x00, 0x46,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x01, 0x58, 0x21, 0x02, 0xB1, 0x21, 0x6A, 0xB9,
            0x6E, 0x5B, 0x3B, 0x33, 0x40, 0xF5, 0xBD, 0xF0, 0x2E, 0x69, 0x3F, 0x16, 0x21, 0x3A,
            0x04, 0x52, 0x5E, 0xD4, 0x44, 0x50, 0xB1, 0x01, 0x9C, 0x2D, 0xFD, 0x38, 0x38, 0xAB,
            0x01, 0x06, 0x58, 0x40, 0x44, 0x5D, 0x79, 0x8C, 0x90, 0xE7, 0xF5, 0x00, 0xDC, 0x74,
            0x7A, 0x65, 0x4C, 0xEC, 0x6C, 0xFA, 0x6F, 0x03, 0x72, 0x76, 0xE1, 0x4E, 0x52, 0xED,
            0x07, 0xFC, 0x16, 0x29, 0x4C, 0x84, 0x66, 0x0D, 0x5A, 0x33, 0x98, 0x5D, 0xFB, 0xD4,
            0xBF, 0xDD, 0x6D, 0x4A, 0xCF, 0x38, 0x04, 0xC3, 0xD4, 0x6E, 0xBF, 0x3B, 0x7F, 0xA6,
            0x26, 0x40, 0x67, 0x4F, 0xC0, 0x35, 0x4F, 0xA0, 0x56, 0xDB, 0xAE, 0xA6,
        ];
        let d = decode_native(&cert).unwrap();
        let e = TBSCertificate {
            cbor_cert_type: 1,
            cert_serial_number: vec![0x01, 0xf5, 0x0d],
            issuer: vec![82, 70, 67, 32, 116, 101, 115, 116, 32, 67, 65],
            validity_not_before: 1577836800,
            validity_not_after: 1612224000,
            subject: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
            subject_pk_alg: 1,
            subject_pk: vec![
                0x02, 0xB1, 0x21, 0x6A, 0xB9, 0x6E, 0x5B, 0x3B, 0x33, 0x40, 0xF5, 0xBD, 0xF0, 0x2E,
                0x69, 0x3F, 0x16, 0x21, 0x3A, 0x04, 0x52, 0x5E, 0xD4, 0x44, 0x50, 0xB1, 0x01, 0x9C,
                0x2D, 0xFD, 0x38, 0x38, 0xAB,
            ],
            extensions: 1,
            issuer_sgn_alg: 6,
        };

        let expected_sgn = vec![
            0x44, 0x5D, 0x79, 0x8C, 0x90, 0xE7, 0xF5, 0x00, 0xDC, 0x74, 0x7A, 0x65, 0x4C, 0xEC,
            0x6C, 0xFA, 0x6F, 0x03, 0x72, 0x76, 0xE1, 0x4E, 0x52, 0xED, 0x07, 0xFC, 0x16, 0x29,
            0x4C, 0x84, 0x66, 0x0D, 0x5A, 0x33, 0x98, 0x5D, 0xFB, 0xD4, 0xBF, 0xDD, 0x6D, 0x4A,
            0xCF, 0x38, 0x04, 0xC3, 0xD4, 0x6E, 0xBF, 0x3B, 0x7F, 0xA6, 0x26, 0x40, 0x67, 0x4F,
            0xC0, 0x35, 0x4F, 0xA0, 0x56, 0xDB, 0xAE, 0xA6,
        ];

        let expected_signed_data = vec![
            0x01, 0x43, 0x01, 0xF5, 0x0D, 0x6B, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x43, 0x41, 0x1A, 0x5E, 0x0B, 0xE1, 0x00, 0x1A, 0x60, 0x18, 0x96, 0x00, 0x46,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x01, 0x58, 0x21, 0x02, 0xB1, 0x21, 0x6A, 0xB9,
            0x6E, 0x5B, 0x3B, 0x33, 0x40, 0xF5, 0xBD, 0xF0, 0x2E, 0x69, 0x3F, 0x16, 0x21, 0x3A,
            0x04, 0x52, 0x5E, 0xD4, 0x44, 0x50, 0xB1, 0x01, 0x9C, 0x2D, 0xFD, 0x38, 0x38, 0xAB,
            0x01, 0x06,
        ];

        assert_eq!(d.decoded_data.cbor_cert_type, e.cbor_cert_type);
        assert_eq!(d.decoded_data.cert_serial_number, e.cert_serial_number);
        assert_eq!(d.decoded_data.issuer, e.issuer);
        assert_eq!(d.decoded_data.validity_not_before, e.validity_not_before);
        assert_eq!(d.decoded_data.validity_not_after, e.validity_not_after);
        assert_eq!(d.decoded_data.subject, e.subject);
        assert_eq!(d.decoded_data.subject_pk_alg, e.subject_pk_alg);
        assert_eq!(d.decoded_data.subject_pk, e.subject_pk);
        assert_eq!(d.decoded_data.extensions, e.extensions);
        assert_eq!(d.decoded_data.issuer_sgn_alg, e.issuer_sgn_alg);
        assert_eq!(d.signature, expected_sgn);
        assert_eq!(d.signed_data, expected_signed_data);
    }
}
