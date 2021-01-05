#[macro_use]
extern crate clap;
use clap::{App, Arg};
use std::process;

mod config;
mod keygen;
mod saving;
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
        .long("key-gen")
        .takes_value(true)
        .multiple(true)
        .help(
        "Generates a random asymmetric keypair. 
        Example: cborcert -k \"id-Ed25519\" ca/ca.c ca/ca.der. \t
            * id-Ed25519 -- is the algorithm. \t
            * ca.c and ca.der are output files where the keys will be saved. \n
        Supported algorithms are:\t
            * \"id-ecPublicKey + secp256r1\"\t
            * \"id-Ed25519\"")   
        )
        .arg(Arg::with_name("CSRGEN")
        .short("c")
        .long("csr-gen")
        .takes_value(true)
        .multiple(true)
        .help(
        "Generates a certificate signature request (CSR). 
        Example: cborcert -c in.toml own_pk.der own_sk.der csr.c csr.der. \t
            * in.toml -- contains metadata of the SCR. \t
            * own_pk.der -- contain the own public key. \t
            * own_sk.der -- contain the own secret key. \t 
            * csr.c csr.der -- are output files where the CSR will be saved.")   
        )   
        .arg(Arg::with_name("CERTGEN")
        .short("g")
        .long("cert-gen")
        .takes_value(true)
        .multiple(true)
        .help(
        "Generates a certificate. 
        Example: cborcert -g ca_conf.toml csr.der ca_pk.der ca_sk.der csr.c csr.der. \t
            * ca_conf.toml -- contains specific to CA configuration values \t
            * csr.der -- contains the CSR \t
            * ca_pk.der -- contains the public key of the CA \t
            * ca_sk.der -- contains the secret key of the CA  \t 
            * cert.c and cert.der -- are output files where the certificate will be saved.")   
        )   
        .arg(Arg::with_name("CERTVER")
        .short("v")
        .long("cert-ver")
        .takes_value(true)
        .multiple(true)
        .help(
        "Verifies a certificate. 
        Example: cborcert -v cert.der ca_pk.der cert.toml. \t
            * cert.der -- contains the certificate \t
            * ca_pk.der -- contains the public key of the CA \t
            * cert.toml -- is an output file where the decoded certificate content will be saved.")   
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

    if let Some(args) = matches.values_of("CERTVER"){
        let config = Config::new(
            Command::CertVer, args.collect())
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

