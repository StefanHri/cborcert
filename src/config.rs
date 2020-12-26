use crate::algorithm::Algorithm;
use crate::csr::{CSRGenConf, CSRSignedData};
use crate::error::CborCertError;
use crate::execution::Config;
use crate::keygen::KeyGenConf;
use crate::saving::{File, FileFormat};
use std::io::Read;

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

    /// Gets a vector of files (type File) from a slice of strings
    fn get_out_files(in_vec: &[&str]) -> Result<Vec<File>, CborCertError> {
        Config::get_files(in_vec, &[FileFormat::C, FileFormat::DER])
    }

    /// pars the csr content from a toml file to a CSRSignedData struct
    fn get_csr_content(file: &str) -> Result<CSRSignedData, CborCertError> {
        let f = Config::get_files(&[file], &[FileFormat::TOML])?;
        let mut csr_toml = String::new();
        let mut fh = std::fs::File::open(&f[0].full_name)?;
        fh.read_to_string(&mut csr_toml)?;

        let csr_data: CSRSignedData = toml::from_str(&csr_toml)?;
        println!("csr_data: {:?}", csr_data);
        Ok(csr_data)
    }

    ///coverts a slice of strings to a vector of File
    fn get_files(in_vec: &[&str], formats: &[FileFormat]) -> Result<Vec<File>, CborCertError> {
        let mut out_files = Vec::new();
        for file in in_vec {
            let mut split = file.split(".");
            let name = split
                .next()
                .ok_or(CborCertError::NoPointInFileName)?
                .to_string();
            let format_str = split.next().ok_or(CborCertError::NoPointInFileName)?;

            if format_str != "c" && format_str != "der" && format_str != "toml" {
                return Err(CborCertError::UnknownFileFormat);
            }

            for f in formats {
                if f == &FileFormat::C && format_str == "c" {
                    out_files.push(File {
                        full_name: file.to_string(),
                        name,
                        format: FileFormat::C,
                    });
                    break;
                } else if f == &FileFormat::DER && format_str == "der" {
                    out_files.push(File {
                        full_name: file.to_string(),
                        name,
                        format: FileFormat::DER,
                    });
                    break;
                } else if f == &FileFormat::TOML && format_str == "toml" {
                    out_files.push(File {
                        full_name: file.to_string(),
                        name,
                        format: FileFormat::TOML,
                    });
                    break;
                }
            }
        }
        Ok(out_files)
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
