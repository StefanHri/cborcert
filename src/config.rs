use crate::algorithm::Algorithm;
use crate::csr::{CSRGenConf, CSRSignedData};
use crate::error::CborCertError;
use crate::execution::Config;
use crate::keygen::KeyGenConf;
use crate::saving::{File, FileFormat};

pub enum Command {
    KeyGen,
    CSRGen,
}

impl Config {
    pub fn new(c: Command, args: Vec<&str>) -> Result<Config, CborCertError> {
        match c {
            Command::KeyGen => {
                Config::num_arguments_check(&args, 3, 2)?;

                Ok(Config::KeyGen(KeyGenConf {
                    algorithm: Algorithm::alg_from_string(&args[0])?,
                    out_files: Config::get_out_files(&args[1..])?,
                }))
            }
            Command::CSRGen => {
                Config::num_arguments_check(&args, 3, 2)?;
                Ok(Config::CSRGen(CSRGenConf {
                    content: Config::get_csr_content(&args[0])?,
                    out_files: Config::get_out_files(&args[1..])?,
                }))
            }
        }
    }

    fn num_arguments_check(args: &[&str], max: usize, min: usize) -> Result<(), CborCertError> {
        if args.len() > max {
            return Err(CborCertError::TooManyArguments);
        }
        if args.len() < min {
            return Err(CborCertError::TooFewArguments);
        }
        Ok(())
    }
    fn get_out_files(in_vec: &[&str]) -> Result<Vec<File>, CborCertError> {
        let mut out_files = Vec::new();
        for file in in_vec {
            let mut split = file.split(".");
            let name = split
                .next()
                .ok_or(CborCertError::NoPointInFileName)?
                .to_string();
            let format_str = split.next().ok_or(CborCertError::NoPointInFileName)?;
            let format;
            match format_str {
                "c" => format = FileFormat::C,
                "der" => format = FileFormat::DER,
                _ => return Err(CborCertError::UnknownFileFormat),
            }
            out_files.push(File { name, format });
        }
        Ok(out_files)
    }
    fn get_csr_content(file: &str) -> Result<CSRSignedData, CborCertError> {
        //todo check the file format

        //pars out the the CSR data to be signed from the .toml file
        let csr2sign_data = CSRSignedData {
            subject_common_name: vec![1, 2, 3],
            public_key: vec![1, 2, 3],
        };
        Ok(csr2sign_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_arguments_check_test() {
        let in_params = vec!["ed25519", "ca.c", "ca.der"];
        assert!(matches!(
            Config::num_arguments_check(&in_params, 3, 2),
            Ok(())
        ));
        assert!(matches!(
            Config::num_arguments_check(&in_params, 2, 2),
            Err(CborCertError::TooManyArguments)
        ));
        assert!(matches!(
            Config::num_arguments_check(&in_params, 5, 4),
            Err(CborCertError::TooFewArguments)
        ));
    }

    #[test]
    fn ed25519_key_gen() {
        let in_params = vec!["ed25519", "ca.c"];
        let config = Config::new(Command::KeyGen, in_params).unwrap();

        match config {
            Config::KeyGen(x) => assert!(matches!(x.algorithm, Algorithm::Ed25519)),
            Config::CSRGen(_x) => assert!(false),
        };

        // assert!(matches!(config.out_files[0].format, FileFormat::C));
        // assert_eq!(config.out_files[0].name, String::from("ca"));
    }
}
