use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

use crate::config::{Config, SignatureAlgorithm};

use crate::files::save_file;

pub fn key_gen(conf: Config) -> Result<(), &'static str> {
    match conf.algorithm {
        SignatureAlgorithm::Ed25519 => {
            let mut csprng = OsRng {};
            let keypair: Keypair = Keypair::generate(&mut csprng);
            println!("Secret key: {:X?}", keypair.secret.to_bytes());
            println!("Public key: {:X?}", keypair.public.to_bytes());
            save_file(&conf.out_files[0], keypair.secret.to_bytes());
        }
        SignatureAlgorithm::C25519 => {}
    }
    Ok(())
}
