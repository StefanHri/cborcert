use std::fs;

pub enum FileFormat {
    C,
    DER,
    PEM,
}
pub struct File {
    pub name: String,
    pub format: FileFormat,
}

pub fn save_file(file: &File, data: [u8; 32]) -> Result<(), &'static str> {
    match &file.format {
        FileFormat::C => {
            fs::write(format!("{}.c", file.name),format!("{:#04x?}",data)
            ).expect("Unable to write file");
            Ok(())
        }
        FileFormat::PEM => {
            fs::write(&file.name, data).expect("Unable to write file");
            Ok(())
        }
        FileFormat::DER => {
            fs::write(&file.name, data).expect("Unable to write file");
            Ok(())
        }
    }
}
