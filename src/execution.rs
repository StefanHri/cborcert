use crate::keygen::KeyGenConf;
use crate::saving::Out;

//https://stackoverflow.com/questions/57066471/how-do-i-implement-a-trait-for-an-enum-and-its-respective-variants

pub trait Execution {
    fn execute(&self) -> Out;
}

pub enum Config {
    KeyGen(KeyGenConf),
}

impl Execution for Config {
    fn execute(&self) -> Out {
        match self {
            Config::KeyGen(key_gen_conf) => key_gen_conf.execute(),
        }
    }
}

impl Execution for KeyGenConf {
    fn execute(&self) -> Out {
        self.key_gen()
    }
}
