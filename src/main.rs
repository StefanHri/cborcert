#[macro_use]
extern crate clap;
use clap::{App, Arg};

//use cbor::{Decoder, Encoder};

fn main() {
    // The data we want to encode. Each element in the list is encoded as its
    // own separate top-level data item.
    // let data = vec![('a', 1), ('b', 2), ('c', 3)];
    // let data1 = vec!["A"];

    // Create an in memory encoder. Use `Encoder::from_writer` to write to
    // anything that implements `Writer`.
    // let mut e = Encoder::from_memory();
    // e.encode(&data1).unwrap();

    // println!("{:?}", e.as_bytes());

    // Create an in memory decoder. Use `Decoder::from_reader` to read from
    // anything that implements `Reader`.
    // let mut d = Decoder::from_bytes(e.as_bytes());
    // let items: Vec<(char, i32)> = d.decode().collect::<Result<_, _>>().unwrap();

    // assert_eq!(items, data);

    let matches = App::new("CBORcert")
        .version(crate_version!())
        .author(crate_authors!())
        //.before_help("DOTO: Put here license information")
        .about(
            "\nCBORcert is a command line tool for generation and parsing of CBOR encoded X.509 Certificates. It is based on the IETF draft \"CBOR Encoding of X.509 Certificates (CBOR Certificates)\", version draft-mattsson-cose-cbor-cert-compress-05 from December 01, 2020.")
        .arg(Arg::with_name("ARG1")
                .index(1)
                .help("Generates a random asymmetric keypair (Currently only ED25519 is supported!)"))
        .arg(Arg::with_name("FLAG")
                //flags are boolean values. They are provided by the user or not
                //flags have no value
                .short("f")//this or long makes it flag 
                .long("flag-keypair-gen")
                .multiple(true)
                .help("Generates a random asymmetric keypair (Currently only ED25519 is supported!)"))   
        .arg(Arg::with_name("OPT1")
            .short("k")
            .long("keypair-gen")
            .takes_value(true)//this makes it option
            .multiple(true)//we can have the same option repeating many times with many values
            //.required(true)//options can be required
            .help("Generates a random asymmetric keypair (Currently only ED25519 is supported!)")   
        )     
        .get_matches();

    if matches.is_present("ARG1") {
        println!("ARG1 was used");
    }

    if matches.is_present("FLAG") {
        println!("FLAG was used");
    }

    if let Some(a1_val) = matches.value_of("ARG1") {
        println!("ARG1={}", a1_val);
    }

    if let Some(ov_itr) = matches.values_of("OPT1"){
       
       for v in ov_itr{
           println!("values of OPT1 is {}", v);
       }
    }
}
