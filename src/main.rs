#[macro_use]
extern crate clap;
use clap::{App, Arg};
use std::process;

mod config;
mod keygen;
mod files;
mod cert;
use config::{Config, Command};


fn main() {

    let matches = App::new("CBORcert")
        .version(crate_version!())
        .author(crate_authors!())
        //.before_help("DOTO: Put here license information")
        .about(
            "\nCBORcert is a command line tool for generation and parsing of CBOR encoded X.509 Certificates. It is based on the IETF draft \"CBOR Encoding of X.509 Certificates (CBOR Certificates)\", version draft-mattsson-cose-cbor-cert-compress-05 from December 01, 2020.")
        .arg(Arg::with_name("SGNKEY")
            .short("k")
            .long("sgn-key-gen")
            .takes_value(true)//this makes it option
            .multiple(true)//we can have the same option repeating many times with many values
            //.required(true)//options can be required
            //.number_of_values(3)
            .help("Generates a random asymmetric keypair (Currently only ED25519 is supported!)")   
        )     
        .get_matches();


    if let Some(args) = matches.values_of("SGNKEY"){

    let config = Config::new(Command::SgnKeyGen, args.collect()).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    if let Err(e) = keygen::key_gen(config) {
        eprintln!("Error during key generation: {}", e);
        process::exit(1); 
    }

    }
}

