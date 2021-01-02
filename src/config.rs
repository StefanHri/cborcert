use crate::algorithm::{Algorithm, PkIanaVal, SgnIanaVal};
use crate::cert::{CAconf, CertGenConf};
use crate::csr::{CSRGenConf, CSRMetaData};
use crate::error::CborCertError;
use crate::execution::Config;
use crate::keygen::KeyGenConf;
use crate::saving::{File, FileFormat};
use serde::de::DeserializeOwned;
use std::io::Read;

pub enum Command {
    KeyGen,
    CSRGen,
    CertGen,
}

impl Config {
    pub fn new(c: Command, args: Vec<&str>) -> Result<Config, CborCertError> {
        match c {
            Command::KeyGen => {
                Config::num_arguments_check(&args, 3, 2)?;

                Ok(Config::KeyGen(KeyGenConf {
                    algorithm: Algorithm::new(&args[0])?,
                    out_files: Config::get_out_files(&args[1..])?,
                }))
            }
            Command::CSRGen => {
                Config::num_arguments_check(&args, 5, 4)?;
                Ok(Config::CSRGen(CSRGenConf {
                    csr_meta_data: Config::conf_from_toml(&args[0])?,
                    pk: Config::get_der_file_content(&args[1])?,
                    sk: Config::get_der_file_content(&args[2])?,
                    out_files: Config::get_out_files(&args[3..])?,
                }))
            }
            Command::CertGen => {
                Config::num_arguments_check(&args, 6, 5)?;
                Ok(Config::CertGen(CertGenConf {
                    ca_conf: Config::conf_from_toml(&args[0])?,
                    csr: Config::get_der_file_content(&args[1])?,
                    ca_pk: Config::get_der_file_content(&args[2])?,
                    ca_sk: Config::get_der_file_content(&args[3])?,
                    out_files: Config::get_out_files(&args[4..])?,
                }))
            }
        }
    }

    ///parse the content of ca_conf.toml file
    fn conf_from_toml<T: DeserializeOwned>(file: &str) -> Result<T, CborCertError> {
        let f = Config::get_files(&[file], &[FileFormat::TOML])?;
        let mut toml_str = String::new();
        let mut fh = std::fs::File::open(&f[0].full_name)?;
        fh.read_to_string(&mut toml_str)?;

        let conf: T = toml::from_str(&toml_str)?;
        Ok(conf)
    }

    ///checks the number of arguments
    fn num_arguments_check(args: &[&str], max: usize, min: usize) -> Result<(), CborCertError> {
        if args.len() > max {
            return Err(CborCertError::TooManyArguments);
        }
        if args.len() < min {
            return Err(CborCertError::TooFewArguments);
        }
        Ok(())
    }

    ///gets the content of a .der file, e.g., a public key or a private key
    fn get_der_file_content(file: &str) -> Result<Vec<u8>, CborCertError> {
        let f = Config::get_files(&[file], &[FileFormat::DER])?;
        let mut fh = std::fs::File::open(&f[0].full_name)?;
        let metadata = std::fs::metadata(&f[0].full_name)?;
        let mut buffer = vec![0; metadata.len() as usize];
        fh.read(&mut buffer)?;
        println!("{} content is: {:x?}", f[0].full_name, buffer);
        Ok(buffer)
    }

    /// Gets a vector of files (type File) from a slice of strings
    fn get_out_files(in_vec: &[&str]) -> Result<Vec<File>, CborCertError> {
        Config::get_files(in_vec, &[FileFormat::C, FileFormat::DER])
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
        let _name: String = String::from("id-Ed25519");

        match config {
            Config::KeyGen(x) => {
                assert!(matches!(x.algorithm.iana_pk, Some(PkIanaVal::IdEd25519)));
                assert!(matches!(x.algorithm.iana_sgn, Some(SgnIanaVal::IdEd25519)));
                assert!(matches!(x.algorithm.name_pk, Some(_name)));
                assert!(matches!(x.algorithm.name_sgn, Some(_name)))
            }
            Config::CSRGen(_x) => assert!(false),
            Config::CertGen(_x) => assert!(false),
        };
    }
}
