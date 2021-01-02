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
mod csr;
mod error;
mod cert;
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
            .help("Generates a random asymmetric keypair. Example: cborcert -k ed25519 ca/ca.c ca/ca.der. ed25519 is the used algorithm. ca.c and ca.der are files where the key is saved.")   
        )
        .arg(Arg::with_name("CSRGEN")
            .short("c")
            .long("csr-gen")
            .takes_value(true)
            .multiple(true)
            .help("Generates a certificate signature request. Example: cborcert -c in.toml pk.der sk.der csr.c csr.der. The .toml file contains metadata of the SCR. The pk.der sk.der contain the own secret and private key. The csr.c csr.der are files where the csr is saved.")   
        )   
        .arg(Arg::with_name("CERTGEN")
        .short("g")
        .long("cert-gen")
        .takes_value(true)
        .multiple(true)
        .help("Generates a certificate. Example: cborcert -g ca_conf.toml csr.der ca_pk.der ca_sk.der csr.c csr.der. \t
            ca_conf.toml contains CA specific values \t
            csr.der contains the CSR \t
            ca_pk.der contains the public key of the CA \t
            ca_sk.der contains the secret key of the CA  \t 
            csr.c and csr.der are output files.")   
    )   
        .get_matches();


    if let Some(args) = matches.values_of("KEYGEN"){
        let config = Config::new(
            Command::KeyGen, args.collect())
            .unwrap_or_else(|err| {
            eprintln!("Problem parsing arguments: {}", err);
            process::exit(1);
        });

        config.execute().unwrap_or_else(|err| {
            eprintln!("Problem during executing the command: {}", err);
            process::exit(1);
        }).save().unwrap_or_else(|err| {
            eprintln!("Problem during saving the results: {}", err);
            process::exit(1);
        });
    }


    if let Some(args) = matches.values_of("CSRGEN"){
        let config = Config::new(
            Command::CSRGen, args.collect())
            .unwrap_or_else(|err| {
            eprintln!("Problem parsing arguments: {}", err);
            process::exit(1);
        }); 
        config.execute().unwrap_or_else(|err| {
            eprintln!("Problem during executing the command: {}", err);
            process::exit(1);
        }).save().unwrap_or_else(|err| {
            eprintln!("Problem during saving the results: {}", err);
            process::exit(1);
        });
    }

    if let Some(args) = matches.values_of("CERTGEN"){
        let config = Config::new(
            Command::CertGen, args.collect())
            .unwrap_or_else(|err| {
            eprintln!("Problem parsing arguments: {}", err);
            process::exit(1);
        }); 
        config.execute().unwrap_or_else(|err| {
            eprintln!("Problem during executing the command: {}", err);
            process::exit(1);
        }).save().unwrap_or_else(|err| {
            eprintln!("Problem during saving the results: {}", err);
            process::exit(1);
        });
    }
}

