use crate::algorithm::{Algorithm, KeyPair};
use crate::error::CborCertError;
use crate::saving::File;
use crate::saving::Out;

pub struct KeyGenConf {
    pub algorithm: Algorithm,
    pub out_files: Vec<File>,
}

pub struct OutKeyPair<'a> {
    pub key_pair: KeyPair,
    pub out_files: &'a [File],
}

// impl KeyGenConf {
//     pub fn key_gen(&self) -> Result<Out, CborCertError> {
//         match self.algorithm {
//             Algorithm::Ed25519 => {
//                 let mut csprng = OsRng {};
//                 let keypair: Keypair = Keypair::generate(&mut csprng);
//                 let sk = keypair.secret.to_bytes();
//                 let pk = keypair.public.to_bytes();
//                 println!("Secret key: {:X?}", sk);
//                 println!("Public key: {:X?}", pk);
//                 let out_files = &self.out_files[..];

//                 Ok(Out::OutEd25519(OutEd25519Data { sk, pk, out_files }))
//             } // Algorithm::C25519 => {}
//         }
//     }
// }

// pub fn key_gen(conf: Config) -> Result<(), &'static str> {
//     match conf.algorithm {
//         Algorithm::Ed25519 => {
//             let mut csprng = OsRng {};
//             let keypair: Keypair = Keypair::generate(&mut csprng);
//             println!("Secret key: {:X?}", keypair.secret.to_bytes());
//             println!("Public key: {:X?}", keypair.public.to_bytes());
//         }
//         Algorithm::C25519 => {}
//     }
//     Ok(())
// }
