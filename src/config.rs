use crate::files::{File, FileFormat};

pub enum SignatureAlgorithm {
    Ed25519,
    C25519,
}

pub enum Command {
    SgnKeyGen,
    DHKeyGen,
    NativeCertGen,
    NonNativeCertGen,
}

pub struct Config {
    pub algorithm: SignatureAlgorithm,
    pub out_files: Vec<File>,
}

impl Config {
    pub fn new(c: Command, args: Vec<&str>) -> Result<Config, &'static str> {
        match c {
            Command::SgnKeyGen => {
                if args.len() > 4 {
                    return Err("Too much arguments for ..!");
                }
                if args.len() < 2 {
                    return Err("Too few arguments for ..!");
                }

                let algorithm;
                match args[0] {
                    "ed25519" => algorithm = SignatureAlgorithm::Ed25519,
                    "c25519" => algorithm = SignatureAlgorithm::C25519,
                    _ => return Err("Unsupported algorithm!"),
                }

                let mut out_files = Vec::new();
                for i in 1..args.len() {
                    let mut split = args[i].split(".");
                    //todo handle unwrap properly
                    let name = split.next().unwrap().to_string();
                    let formatstr = split.next().unwrap();
                    let format;
                    match formatstr {
                        "c" => format = FileFormat::C,
                        "pem" => format = FileFormat::PEM,
                        "der" => format = FileFormat::DER,
                        _ => return Err("Unsupported file format!"),
                    }
                    out_files.push(File { name, format });
                }
                Ok(Config {
                    algorithm,
                    out_files,
                })
            }
            Command::DHKeyGen => {
                return Err("Not implemented yet!");
            }
            Command::NativeCertGen => {
                return Err("Not implemented yet!");
            }
            Command::NonNativeCertGen => {
                return Err("Not implemented yet!");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_key_gen() {
        let in_params = vec!["ed25519", "ca.c"];
        let config = Config::new(Command::SgnKeyGen, in_params).unwrap();

        assert!(matches!(config.algorithm, SignatureAlgorithm::Ed25519));
        assert!(matches!(config.out_files[0].format, FileFormat::C));
        assert_eq!(config.out_files[0].name, String::from("ca"));
    }
}
