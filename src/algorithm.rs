use crate::error::CborCertError;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::convert::TryFrom;

// +-------+---------------------------------------+
// | Value | X.509 Public Key Algorithm            |
// +=======+=======================================+
// |     0 | rsaEncryption                         |
// |     1 | id-ecPublicKey + secp256r1            |supported
// |     2 | id-ecPublicKey + secp384r1            |
// |     3 | id-ecPublicKey + secp521r1            |
// |     4 | id-X25519                             |
// |     5 | id-X448                               |
// |     6 | id-Ed25519                            |supported
// |     7 | id-Ed448                              |
// |     8 | id-alg-hss-lms-hashsig                |
// |     9 | id-alg-xmss                           |
// |    10 | id-alg-xmssmt                         |
// +-------+---------------------------------------+
#[derive(Copy, Clone)]
pub enum PkIanaVal {
    IdecPublicKeySecp256r1 = 1,
    IdEd25519 = 6,
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
// |     6 | ecdsa-with-SHA256                     |supported
// |     7 | ecdsa-with-SHA384                     |
// |     8 | ecdsa-with-SHA512                     |
// |     9 | id-ecdsa-with-shake128                |
// |    10 | id-ecdsa-with-shake256                |
// |    11 | id-Ed25519                            |supported
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
#[derive(Copy, Clone)]
pub enum SgnIanaVal {
    EcdsaWithSHA256 = 6,
    IdEd25519 = 11,
}

pub struct Algorithm {
    pub name_pk: Option<String>,
    pub iana_pk: Option<PkIanaVal>,
    pub name_sgn: Option<String>,
    pub iana_sgn: Option<SgnIanaVal>,
}

pub struct KeyPair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

impl Algorithm {
    pub fn new(in_str: &str) -> Result<Algorithm, CborCertError> {
        match in_str {
            "id-Ed25519" => Ok(Algorithm {
                name_pk: Some(in_str.to_string()),
                iana_pk: Some(PkIanaVal::IdEd25519),
                name_sgn: Some(in_str.to_string()),
                iana_sgn: Some(SgnIanaVal::IdEd25519),
            }),
            "id-ecPublicKey + secp256r1" | "ecdsa-with-SHA256" => Ok(Algorithm {
                name_pk: Some(in_str.to_string()),
                iana_pk: Some(PkIanaVal::IdecPublicKeySecp256r1),
                name_sgn: Some(in_str.to_string()),
                iana_sgn: Some(SgnIanaVal::EcdsaWithSHA256),
            }),
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }

    pub fn new_sgn_alg_from_num(x: u8) -> Result<Algorithm, CborCertError> {
        const ed25519: u8 = SgnIanaVal::IdEd25519 as u8;
        const ecdsa_sha256: u8 = SgnIanaVal::EcdsaWithSHA256 as u8;
        match x {
            ed25519 => Ok(Algorithm {
                name_pk: Some(String::from("id-Ed25519")),
                iana_pk: Some(PkIanaVal::IdEd25519),
                name_sgn: Some(String::from("id-Ed25519")),
                iana_sgn: Some(SgnIanaVal::IdEd25519),
            }),
            ecdsa_sha256 => Ok(Algorithm {
                name_pk: Some(String::from("id-ecPublicKey + secp256r1")),
                iana_pk: Some(PkIanaVal::IdecPublicKeySecp256r1),
                name_sgn: Some(String::from("ecdsa-with-SHA256")),
                iana_sgn: Some(SgnIanaVal::EcdsaWithSHA256),
            }),
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }

    pub fn iana_sgn_as_u8(&self) -> Result<u8, CborCertError> {
        match self.iana_sgn {
            Some(x) => Ok(x as u8),
            None => return Err(CborCertError::NoIanaVal),
        }
    }

    pub fn iana_pk_as_u8(&self) -> Result<u8, CborCertError> {
        match self.iana_pk {
            Some(x) => Ok(x as u8),
            None => return Err(CborCertError::NoIanaVal),
        }
    }

    pub fn name_pk_as_string(&self) -> Result<String, CborCertError> {
        match &self.name_pk {
            Some(x) => Ok(x.clone()),
            None => return Err(CborCertError::NoIanaVal),
        }
    }

    pub fn sign(&self, pk: &[u8], sk: &[u8], data: &[u8]) -> Result<Vec<u8>, CborCertError> {
        match self.iana_sgn {
            Some(x) => match x {
                SgnIanaVal::IdEd25519 => ed25519_sign(pk, sk, data),
                SgnIanaVal::EcdsaWithSHA256 => ecdsa_sha256_sign(pk, sk, data),
            },

            None => Err(CborCertError::NotASignatureAlgorithm),
        }
    }

    pub fn verify(
        &self,
        signed_data: &[u8],
        signature: &[u8],
        pk: &[u8],
    ) -> Result<(), CborCertError> {
        match self.iana_sgn {
            Some(x) => match x {
                SgnIanaVal::IdEd25519 => ed25519_verify(signed_data, signature, pk),
                SgnIanaVal::EcdsaWithSHA256 => ecdsa_sha256_verify(signed_data, signature, pk),
            },
            None => Err(CborCertError::NotASignatureAlgorithm),
        }
    }

    pub fn key_gen(&self) -> Result<KeyPair, CborCertError> {
        match self.iana_sgn {
            Some(x) => match x {
                SgnIanaVal::IdEd25519 => ed25519_key_gen(),
                SgnIanaVal::EcdsaWithSHA256 => ecdsa_sha256_key_gen(),
            },
                None => Err(CborCertError::NotASignatureAlgorithm),

        }
    }
}

pub fn ecdsa_sha256_verify(
    signed_data: &[u8],
    signature: &[u8],
    pk: &[u8],
) -> Result<(), CborCertError> {
    //todo implement this
    Ok(())
}

pub fn ed25519_verify(
    signed_data: &[u8],
    signature: &[u8],
    pk: &[u8],
) -> Result<(), CborCertError> {
    let sgn: Signature = Signature::try_from(&signature[..])?;
    let public = PublicKey::from_bytes(&pk)?;
    public.verify(&signed_data, &sgn)?;
    Ok(())
}

fn ed25519_key_gen() -> Result<KeyPair, CborCertError> {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let sk = keypair.secret.to_bytes();
    let pk = keypair.public.to_bytes();
    println!("Secret key: {:X?}", sk);
    println!("Public key: {:X?}", pk);
    Ok(KeyPair {
        sk: sk.to_vec(),
        pk: pk.to_vec(),
    })
}

fn ecdsa_sha256_key_gen() -> Result<KeyPair, CborCertError> {
    //todo implement this
    let sk = vec![1, 2, 3];
    let pk = vec![1, 2, 3];
    println!("Secret key: {:X?}", sk);
    println!("Public key: {:X?}", pk);
    Ok(KeyPair {
        sk: sk.to_vec(),
        pk: pk.to_vec(),
    })
}

fn ed25519_sign(pk: &[u8], sk: &[u8], data: &[u8]) -> Result<Vec<u8>, CborCertError> {
    let keypair = Keypair {
        secret: SecretKey::from_bytes(&sk)?,
        public: PublicKey::from_bytes(&pk)?,
    };
    let signature = keypair.sign(&data).to_bytes();
    println!("signature: {:x?}", signature);
    Ok(signature.to_vec())
}

fn ecdsa_sha256_sign(pk: &[u8], sk: &[u8], data: &[u8]) -> Result<Vec<u8>, CborCertError> {
    //todo implement this
    let signature = vec![1, 2, 3];
    println!("signature: {:x?}", signature);
    Ok(signature)
}
