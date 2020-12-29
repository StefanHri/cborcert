use crate::error::CborCertError;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};

pub enum Algorithm {
    Ed25519,
    //C25519,
}

impl Algorithm {
    pub fn alg_from_string(in_str: &str) -> Result<Algorithm, CborCertError> {
        match in_str {
            "ed25519" => Ok(Algorithm::Ed25519),
            //"c25519" => algorithm = Algorithm::C25519,
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }

    pub fn sign(&self, pk: &[u8], sk: &[u8], data: &[u8]) -> Result<Vec<u8>, CborCertError> {
        match self {
            Algorithm::Ed25519 => {
                let keypair = Keypair {
                    secret: SecretKey::from_bytes(&sk)?,
                    public: PublicKey::from_bytes(&pk)?,
                };
                let signature = keypair.sign(&data).to_bytes();
                println!("signature: {:x?}", signature);
                Ok(signature.to_vec())
            }
        }
    }

    // +-------+---------------------------------------+
    // | Value | X.509 Public Key Algorithm            |
    // +=======+=======================================+
    // |     0 | rsaEncryption                         |
    // |     1 | id-ecPublicKey + secp256r1            |
    // |     2 | id-ecPublicKey + secp384r1            |
    // |     3 | id-ecPublicKey + secp521r1            |
    // |     4 | id-X25519                             |
    // |     5 | id-X448                               |
    // |     6 | id-Ed25519                            |
    // |     7 | id-Ed448                              |
    // |     8 | id-alg-hss-lms-hashsig                |
    // |     9 | id-alg-xmss                           |
    // |    10 | id-alg-xmssmt                         |
    // +-------+---------------------------------------+
    pub fn to_iana_pk_value(&self) -> i16 {
        match self {
            Algorithm::Ed25519 => 6,
        }
    }

    // +-------+---------------------------------------+
    // | Value | X.509 Signature Algorithm             |
    // +=======+=======================================+
    // |  -256 | sha1WithRSAEncryption                 |
    // |  -255 | ecdsa-with-SHA1                       |
    // |     1 | sha256WithRSAEncryption               |
    // |     2 | sha384WithRSAEncryption               |
    // |     3 | sha512WithRSAEncryption               |
    // |     4 | id-RSASSA-PSS-SHAKE128                |
    // |     5 | id-RSASSA-PSS-SHAKE256                |
    // |     6 | ecdsa-with-SHA256                     |
    // |     7 | ecdsa-with-SHA384                     |
    // |     8 | ecdsa-with-SHA512                     |
    // |     9 | id-ecdsa-with-shake128                |
    // |    10 | id-ecdsa-with-shake256                |
    // |    11 | id-Ed25519                            |
    // |    12 | id-Ed448                              |
    // |    13 | id-alg-hss-lms-hashsig                |
    // |    14 | id-alg-xmss                           |
    // |    15 | id-alg-xmssmt                         |
    // |   245 | sha224WithRSAEncryption               |
    // |   246 | id-rsassa-pkcs1-v1_5-with-sha3-224    |
    // |   247 | id-rsassa-pkcs1-v1_5-with-sha3-256    |
    // |   248 | id-rsassa-pkcs1-v1_5-with-sha3-384    |
    // |   249 | id-rsassa-pkcs1-v1_5-with-sha3-512    |
    // |   251 | ecdsa-with-SHA224                     |
    // |   252 | id-ecdsa-with-sha3-224                |
    // |   253 | id-ecdsa-with-sha3-256                |
    // |   254 | id-ecdsa-with-sha3-384                |
    // |   255 | id-ecdsa-with-sha3-512                |
    // +-------+---------------------------------------+
    // pub fn to_iana_sgn_alg_value(&self) -> i16 {
    //     match self {
    //         Algorithm::Ed25519 => 11
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_from_string_test() {
        let correct_algorithm: &str = "ed25519";
        let wrong_algorithm: &str = "wrong_algorithm";

        assert!(matches!(
            Algorithm::alg_from_string(correct_algorithm),
            Ok(Algorithm::Ed25519)
        ));

        assert!(matches!(
            Algorithm::alg_from_string(wrong_algorithm),
            Err(CborCertError::UnsupportedAlgorithm)
        ));
    }
}
