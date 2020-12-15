use serde_cbor::Deserializer;

struct TBSCertificate {
    cbor_cert_type: u8,
    cert_serial_number: Vec<u8>,
    issuer: Vec<u8>,
    validity_not_before: i128,
    validity_not_after: i128,
    subject: Vec<u8>,
    subject_pk_alg: i16,
    subject_pk: Vec<u8>,
    extensions: i16,
    issuer_sgn_alg: i16,
}

struct CBORCertificate {
    signed_data: TBSCertificate,
    signature: Vec<u8>,
}




fn decode_native(cert: Vec<u8>) -> Result<CBORCertificate, &'static str> {
    let mut d = Deserializer::from_slice(&cert);

    //1) type
    let cbor_cert_type: u8 = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //2) serial number
    let mut offset: usize = d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let cert_serial_number: &[u8] = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //3) issuer
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let issuer: &[u8] = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //4) Validity not before
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let validity_not_before: i128 = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //4) Validity not after
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let validity_not_after: i128 = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //4) subject
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let subject: &[u8] = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //5 subject_pk_alg
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let subject_pk_alg: i16 = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //6) subject_pk
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let subject_pk: &[u8] = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //7) extensions
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let extensions: i16 = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //8) issuer_sgn_alg
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let issuer_sgn_alg: i16 = serde::de::Deserialize::deserialize(&mut d).unwrap();

    //9) signature
    offset += d.byte_offset();
    let r = &cert[offset..];
    let mut d = Deserializer::from_slice(&r);
    let signature: &[u8] = serde::de::Deserialize::deserialize(&mut d).unwrap();

    println!("-----------------------------------------------------");
    println!("cbor_cert_type is: {:?}", cbor_cert_type);
    println!("cert_serial_number is: {:02x?}", cert_serial_number);
    println!("issuer is: {:?}", issuer);
    println!("validity_not_before is: {:?}", validity_not_before);
    println!("validity_not_after is: {:?}", validity_not_after);
    println!("subject is: {:02x?}", subject);
    println!("subject_pk_alg is: {:}", subject_pk_alg);
    println!("subject_pk is: {:?}", subject_pk);
    println!("extensions is: {:}", extensions);
    println!("issuer_sgn_alg is: {:}", issuer_sgn_alg);
    println!("signature is: {:?}", signature);
    println!("-----------------------------------------------------");

    let signed_data = TBSCertificate {
        cbor_cert_type,
        cert_serial_number: cert_serial_number.to_vec(),
        issuer: issuer.to_vec(),
        validity_not_before,
        validity_not_after,
        subject: subject.to_vec(),
        subject_pk_alg,
        subject_pk: subject_pk.to_vec(),
        extensions,
        issuer_sgn_alg,
    };

    Ok(CBORCertificate {
        signed_data,
        signature: signature.to_vec(),
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
        let d = decode_native(cert).unwrap();
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

        assert_eq!(d.signed_data.cbor_cert_type, e.cbor_cert_type);
        assert_eq!(d.signed_data.cert_serial_number, e.cert_serial_number);
        assert_eq!(d.signed_data.issuer, e.issuer);
        assert_eq!(d.signed_data.validity_not_before, e.validity_not_before);
        assert_eq!(d.signed_data.validity_not_after, e.validity_not_after);
        assert_eq!(d.signed_data.subject, e.subject);
        assert_eq!(d.signed_data.subject_pk_alg, e.subject_pk_alg);
        assert_eq!(d.signed_data.subject_pk, e.subject_pk);
        assert_eq!(d.signed_data.extensions, e.extensions);
        assert_eq!(d.signed_data.issuer_sgn_alg, e.issuer_sgn_alg);
        assert_eq!(d.signature, expected_sgn);
    }
}
