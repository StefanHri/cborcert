// use ed25519_dalek::Keypair;
// use rand::rngs::OsRng;

pub enum Algorithm {
    Ed25519,
    //C25519,
}

// impl Algorithm {
//     pub fn key_gen(&self) {
//         match self {
//             Algorithm::Ed25519 => {
//                 let mut csprng = OsRng {};
//                 let keypair: Keypair = Keypair::generate(&mut csprng);
//                 println!("Secret key: {:X?}", keypair.secret.to_bytes());
//                 println!("Public key: {:X?}", keypair.public.to_bytes());
//             }
//             Algorithm::C25519 => {}
//         }
//     }
// }
