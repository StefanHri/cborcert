#[macro_use]
extern crate clap;
use clap::{App, Arg};
use std::process;

mod config;
mod keygen;
mod saving;
//mod cert;
mod execution;
mod algorithm;
use config::{ Command};
use execution::{Config,Execution};
use saving::Saving;

fn main() {

    let matches = App::new("CBORcert")
        .version(crate_version!())
        .author(crate_authors!())
        //.before_help("DOTO: Put here license information")
        .about(
            "\nCBORcert is a command line tool for generation and parsing of CBOR encoded X.509 Certificates. It is based on the IETF draft \"CBOR Encoding of X.509 Certificates (CBOR Certificates)\", version draft-mattsson-cose-cbor-cert-compress-05 from December 01, 2020.")
        .arg(Arg::with_name("KEYGEN")
            .short("k")
            .long("sgn-key-gen")
            .takes_value(true)
            .multiple(true)
            .help("Generates a random asymmetric keypair. Example: cborcert -k ed25519 ca/ca.c ca/ca.der")   
        )     
        .get_matches();


    if let Some(args) = matches.values_of("KEYGEN"){

    let config = Config::new(Command::KeyGen, args.collect()).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    config.execute().save();

    }
}

