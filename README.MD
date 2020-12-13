# CBORcert -- A Command Line Tool for Generation and Parsing  of CBOR Encoded X.509 Certificates 

This tool is based on [CBOR Encoding of X.509 Certificates (CBOR Certificates)](https://datatracker.ietf.org/doc/draft-mattsson-cose-cbor-cert-compress/)

* Version: draft-mattsson-cose-cbor-cert-compress-05

* From: December 01, 2020

The usage model follows [Guide for building an EDDSA pki](https://datatracker.ietf.org/doc/draft-moskowitz-eddsa-pki/)

* Version: draft-moskowitz-eddsa-pki-04
* From: draft-moskowitz-eddsa-pki-04

## Usage

```bash
#
# non-native CBOR ceriticates
#

# Convert PEM or DER encoded certificate to non-native CBOR encoded certificate
cborcert -tocborcert certificate.<pem or der> certificate.<h or bin>

# Convert non-native CBOR encoded certificate to PEM or DER encoded certificate 
cborcert -fromcborcert certificate.<bin> certificate.<pem or der> 


#
# native CBOR certificates
#
cborcert -create 

```

## Building PKI with cborcert 

#### Root Level

Root level contains:

* root private key
* root public key
* root public certificate
* database of all signed certificates 

Root level may also contains:

* Intermediate level public certificate
* Root level CRL

#### Intermediate Level

Intermediate level contains:

* intermediate private key
* intermediate public key  
* intermediate level public certificate
* database of all signed certificates,
* the certificate trust chain
* Intermediate level CRL

Intermediate level may also contain:

* End Entity public certificates

#### End Entity Level

End Entity Level contains:

* End entity private key
* End entity public key
* End entity certificate



set up folder structure

```bash
mkdir root
mkdir intermediate
mkdir endentity1
```



set up root level

```bash
#create a key pair 
cd root
cborcer -create keypair -out ca.c 
#alternative format is row binary .der or .pem
#cborcer -create keypair -out ca.c
```

