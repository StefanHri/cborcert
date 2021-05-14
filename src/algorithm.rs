use crate::error::CborCertError;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::convert::TryFrom;

use pkcs8::PrivateKeyInfo;
use ring::rand as rrand;
use ring::signature::KeyPair as rKeyPair;
use ring::signature::{self};

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
#[derive(Copy, Clone, Debug, PartialEq)]
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
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SgnIanaVal {
    EcdsaWithSHA256 = 6,
    IdEd25519 = 11,
}

#[derive(Debug, PartialEq)]
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
    /// Generates new ed25519 algorithm
    fn alg_ed25519() -> Result<Algorithm, CborCertError> {
        Ok(Algorithm {
            name_pk: Some(String::from("id-Ed25519")),
            iana_pk: Some(PkIanaVal::IdEd25519),
            name_sgn: Some(String::from("id-Ed25519")),
            iana_sgn: Some(SgnIanaVal::IdEd25519),
        })
    }

    /// Generates new ecdsa_sha256 algorithm
    fn alg_ecdsa_sha256() -> Result<Algorithm, CborCertError> {
        Ok(Algorithm {
            name_pk: Some(String::from("id-ecPublicKey + secp256r1")),
            iana_pk: Some(PkIanaVal::IdecPublicKeySecp256r1),
            name_sgn: Some(String::from("ecdsa-with-SHA256")),
            iana_sgn: Some(SgnIanaVal::EcdsaWithSHA256),
        })
    }

    /// Generates new algorithm from a string
    pub fn new(in_str: &str) -> Result<Algorithm, CborCertError> {
        //println!("in_str: {}", in_str);
        match in_str {
            "id-Ed25519" => Algorithm::alg_ed25519(),
            "id-ecPublicKey + secp256r1" | "ecdsa-with-SHA256" => Algorithm::alg_ecdsa_sha256(),
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }

    /// Generates a new algorithm from the IANA public key algorithm value
    pub fn new_sgn_alg_from_pk_num(iana_pk_num: u8) -> Result<Algorithm, CborCertError> {
        const ED25519: u8 = PkIanaVal::IdEd25519 as u8;
        const ECDSA_SHA256: u8 = PkIanaVal::IdecPublicKeySecp256r1 as u8;
        match iana_pk_num {
            ED25519 => Algorithm::alg_ed25519(),
            ECDSA_SHA256 => Algorithm::alg_ecdsa_sha256(),
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }
    //todo merge this and the above function
    /// Generates a new algorithm from the IANA signature algorithm value
    pub fn new_sgn_alg_from_sgn_num(iana_sgn_num: u8) -> Result<Algorithm, CborCertError> {
        const ED25519: u8 = SgnIanaVal::IdEd25519 as u8;
        const ECDSA_SHA256: u8 = SgnIanaVal::EcdsaWithSHA256 as u8;
        match iana_sgn_num {
            ED25519 => Algorithm::alg_ed25519(),
            ECDSA_SHA256 => Algorithm::alg_ecdsa_sha256(),
            _ => return Err(CborCertError::UnsupportedAlgorithm),
        }
    }

    /// Returns the IANA value of the signature algorithm
    pub fn iana_sgn_as_u8(&self) -> Result<u8, CborCertError> {
        match self.iana_sgn {
            Some(x) => Ok(x as u8),
            None => return Err(CborCertError::NoIanaVal),
        }
    }

    /// Returns the IANA value of the public key algorithm
    pub fn iana_pk_as_u8(&self) -> Result<u8, CborCertError> {
        match self.iana_pk {
            Some(x) => Ok(x as u8),
            None => return Err(CborCertError::NoIanaVal),
        }
    }

    /// Returns the name of the public key algorithm as string
    pub fn name_pk_as_string(&self) -> Result<String, CborCertError> {
        match &self.name_pk {
            Some(x) => Ok(x.clone()),
            None => return Err(CborCertError::NoIanaVal),
        }
    }

    /// Sings Data
    pub fn sign(&self, pk: &[u8], sk: &[u8], data: &[u8]) -> Result<Vec<u8>, CborCertError> {
        match self.iana_sgn {
            Some(x) => match x {
                SgnIanaVal::IdEd25519 => ed25519_sign(pk, sk, data),
                SgnIanaVal::EcdsaWithSHA256 => ecdsa_sha256_sign(pk, sk, data),
            },

            None => Err(CborCertError::NotASignatureAlgorithm),
        }
    }

    /// Verifies a Signature
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

    /// Generates a key pair
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

//----------------------------- ed25519 ----------------------------------------
/// Generates a random ed25519 key pair
fn ed25519_key_gen() -> Result<KeyPair, CborCertError> {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let sk = keypair.secret.to_bytes();
    let pk = keypair.public.to_bytes();
    Ok(KeyPair {
        sk: sk.to_vec(),
        pk: pk.to_vec(),
    })
}

/// Generates a ed25519 signature
fn ed25519_sign(pk: &[u8], sk: &[u8], data: &[u8]) -> Result<Vec<u8>, CborCertError> {
    let keypair = Keypair {
        secret: SecretKey::from_bytes(&sk)?,
        public: PublicKey::from_bytes(&pk)?,
    };
    let signature = keypair.sign(&data).to_bytes();
    Ok(signature.to_vec())
}

/// Verifies a sd25519 signature
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

//--------------------------ecdsa_sha256----------------------------------------

/// generates a random ecdsa key pair
fn ecdsa_sha256_key_gen() -> Result<KeyPair, CborCertError> {
    //todo implement this
    let rng = rrand::SystemRandom::new();

    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();

    println!();
    println!("pkcs8: ");
    for b in pkcs8.as_ref() {
        print!("{:02x}", *b);
    }

    let sk = PrivateKeyInfo::from_der(pkcs8.as_ref()).unwrap();
    println!("sk: {:02x?}", sk.private_key);
    println!("sk_all: {:?}", sk);

    //#[cfg(feature = "alloc")]
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
    )
    .unwrap();
    println!();
    println!("pk: ");
    for b in key_pair.public_key().as_ref() {
        print!("{:02x}", *b);
    }

    println!();

    Ok(KeyPair {
        sk: sk.private_key[..32].to_vec(),
        pk: key_pair.public_key().as_ref().to_vec(),
    })
}

/// Generates an ecdsa+sha256 signature
fn ecdsa_sha256_sign(_pk: &[u8], _sk: &[u8], _data: &[u8]) -> Result<Vec<u8>, CborCertError> {
    //todo implement this
    let signature = vec![1, 2, 3];
    Ok(signature)
}

/// Verifies an ecdsa+sha256 signature
pub fn ecdsa_sha256_verify(
    _signed_data: &[u8],
    _signature: &[u8],
    _pk: &[u8],
) -> Result<(), CborCertError> {
    //todo implement this
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_alg_ed25519_test() {
        let alg = Algorithm {
            name_pk: Some(String::from("id-Ed25519")),
            iana_pk: Some(PkIanaVal::IdEd25519),
            name_sgn: Some(String::from("id-Ed25519")),
            iana_sgn: Some(SgnIanaVal::IdEd25519),
        };

        let _alg1: Algorithm = Algorithm::new("id-Ed25519").unwrap();
        let _alg2: Algorithm = Algorithm::new_sgn_alg_from_pk_num(6).unwrap();
        let _alg3: Algorithm = Algorithm::new_sgn_alg_from_sgn_num(11).unwrap();
        assert_eq!(&alg, &_alg1);
        assert_eq!(&alg, &_alg2);
        assert_eq!(&alg, &_alg3);
    }

    #[test]
    fn new_alg_ecdsa_test() {
        let alg = Algorithm {
            name_pk: Some(String::from("id-ecPublicKey + secp256r1")),
            iana_pk: Some(PkIanaVal::IdecPublicKeySecp256r1),
            name_sgn: Some(String::from("ecdsa-with-SHA256")),
            iana_sgn: Some(SgnIanaVal::EcdsaWithSHA256),
        };

        let _alg1: Algorithm = Algorithm::new("id-ecPublicKey + secp256r1").unwrap();
        let _alg2: Algorithm = Algorithm::new("ecdsa-with-SHA256").unwrap();
        let _alg3: Algorithm = Algorithm::new_sgn_alg_from_pk_num(1).unwrap();
        let _alg4: Algorithm = Algorithm::new_sgn_alg_from_sgn_num(6).unwrap();
        assert_eq!(&alg, &_alg1);
        assert_eq!(&alg, &_alg2);
        assert_eq!(&alg, &_alg3);
        assert_eq!(&alg, &_alg4);
    }

    #[test]
    fn ed25519_keygen_sgn_ver() {
        let alg: Algorithm = Algorithm::new("id-Ed25519").unwrap();
        let keypair = alg.key_gen().unwrap();
        let message = "bla-bla";
        let signature = alg
            .sign(&keypair.pk, &keypair.sk, &message.as_bytes())
            .unwrap();
        alg.verify(&message.as_bytes(), &signature, &keypair.pk)
            .unwrap();
    }
}
