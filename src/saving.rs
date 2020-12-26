use crate::csr::OutCSR;
use crate::keygen::OutEd25519Data;
use itertools::Itertools;
use std::fs;

pub trait Saving {
    fn save(&self);
}

pub enum Out<'a> {
    OutEd25519(OutEd25519Data<'a>),
    OutCSR(OutCSR<'a>),
}

impl Saving for Out<'_> {
    fn save(&self) {
        match self {
            Out::OutEd25519(ed25519_data) => ed25519_data.save(),
            Out::OutCSR(_not_implemented_yet) => panic!("bot implemented yet"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum FileFormat {
    C,
    DER,
    TOML,
}
pub struct File {
    pub full_name: String,
    pub name: String,
    pub format: FileFormat,
}

const C_HEADER: &str = "/*
    This file is automatically generated with cborcert.   
 ";
const ED25519_META: &str = "
    It contains random Ed25519 signature keys.
*/\n\n";

impl Saving for OutEd25519Data<'_> {
    fn save(&self) {
        for file in self.out_files {
            match &file.format {
                FileFormat::C => {
                    fs::write(
                        format!("{}.c", file.name),
                        format!(
                            "{}{}const char sk []= {{ {:#04x} }};\n\nconst char pk []=  {{ {:#04x} }};\n\nconst unsigned int sk_len = sizeof(sk);\n\nconst unsigned int pk_len = sizeof(pk);",
                            C_HEADER,
                            ED25519_META,
                            self.sk.iter().format(", "),
                            self.pk.iter().format(", ")
                        ),
                    )
                    //todo remove expect -> use proper error handling
                    .expect("Unable to write file");
                }
                FileFormat::TOML => {
                    panic!("A key cannot be saved in toml file!");
                }
                FileFormat::DER => {
                    println!("file.name {}:", file.name);
                    fs::write(format!("{}_sk_ed25519.der", file.name), self.sk)
                        .expect("Unable to write file");
                    fs::write(format!("{}_pk_ed25519.der", file.name), self.pk)
                        .expect("Unable to write file");
                }
            }
        }
    }
}

// pub fn save_file(file: &File, data: [u8; 32]) -> Result<(), &'static str> {
//     match &file.format {
//         FileFormat::C => {
//             fs::write(format!("{}.c", file.name),format!("{:#04x?}",data)
//             ).expect("Unable to write file");
//             Ok(())
//         }
//         FileFormat::PEM => {
//             fs::write(&file.name, data).expect("Unable to write file");
//             Ok(())
//         }
//         FileFormat::DER => {
//             fs::write(&file.name, data).expect("Unable to write file");
//             Ok(())
//         }
//     }
// }
