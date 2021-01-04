# CBORcert -- A Command Line Tool for Generation and Verification of natively encoded CBOR Certificates 

This tool is based on [CBOR Encoding of X.509 Certificates (CBOR Certificates)](https://datatracker.ietf.org/doc/draft-mattsson-cose-cbor-cert-compress/)

* Version: draft-mattsson-cose-cbor-cert-compress-05

* From: December 01, 2020

The usage model follows [Guide for building an EDDSA pki](https://datatracker.ietf.org/doc/draft-moskowitz-eddsa-pki/)

* Version: draft-moskowitz-eddsa-pki-04
* From: draft-moskowitz-eddsa-pki-04

## Usage Example: Building two stage PKI 

#### Preparation

create a folder structure with three folders one for each CA and one for the entity

```bash
mkdir tests tests/ca0 tests/ca1 tests/entity
cd tests
```

#### Root Level (CA0)

* In the ca0 folder create .toml configuration file with the following content:
    ```toml
    certificate_serial_number = [1, 245, 13]
    issuer = "RFC test CA"
    validity_not_before = 1577836800
    validity_not_after = 1612224000 
    extensions = 1
    issuer_signature_algorithm = "id-Ed25519"
    ```

* Adjust the values to your needs

* create key pair 

  ```bash
  cborcert -k "id-Ed25519" tests/ca0/ca0.c tests/ca0/ca0.der
  ```

  This command will output the secret and private key in separate .der files and also in a .c file.

#### Intermediate Level (CA1)

* Create a configuration file  ca1.toml  in the ca1 folder with the following content (adjust the values to your needs):

  ```toml
  certificate_serial_number = [1, 245, 13]
  issuer = "RFC test CA"
  validity_not_before = 1577836800
  validity_not_after = 1612224000 
  extensions = 1
  issuer_signature_algorithm = "id-Ed25519"
  ```

* Create a CSR configuration file  csr_ca1.toml  in the ca1 folder with the following content (adjust the values to your needs):

  ```toml
  cbor_cert_type = 0
  subject_common_name = [1, 35, 69, 103, 137, 171] # h'0123456789AB 
  subject_pk_alg = "id-Ed25519"
  ```

* create a key pair 

  ```bash
  cborcert -k "id-Ed25519" tests/ca1/ca1.c tests/ca1/ca1.der
  ```

  This command will output the secret and private key in separate .der files and also in a .c file.

* Create a Certificate Signing Request (SCR)

  ```bash
  cborcert -c tests/ca1/csr_ca1.toml tests/ca1/ca1_pk_id_Ed25519.der tests/ca1/ca1_sk_id_Ed25519.der tests/ca1/ca1_csr.c tests/ca1/ca1_csr.der
  ```

* Create certificate for CA1

  ```bash
  cborcert -g tests/ca0/ca0.toml tests/ca1/ca1_csr.der tests/ca0/ca0_pk_id_Ed25519.der tests/ca0/ca0_sk_id_Ed25519.der tests/ca1/ca1_cert.c tests/ca1/ca1_cert.der
  ```

* Parse and verify the certificate (optional just as test)

  ```bash
  cborcert -v tests/ca1/ca1_cert.der tests/ca0/ca0_pk_id_Ed25519.der tests/ca1/ca1_cert_ver.toml
  ```

  This command will output the decoded certificate content in the ca1_cert_ver.toml file.

#### End Entity Level

* Create a CSR configuration file  csr_entity.toml  in the entity folder with the following content (adjust the values to your needs):

  ```toml
  cbor_cert_type = 0
  subject_common_name = [1, 35, 69, 103, 137, 171] # h'0123456789AB 
  subject_pk_alg = "id-Ed25519"
  ```

* create a key pair 

  ```bash
  cborcert -k "id-Ed25519" tests/entity/entity.c tests/entity/entity.der
  ```
This command will output the secret and private key in separate .der files and also in a .c file.

* Create a Certificate Signing Request (SCR)

  ```bash
  cborcert -c tests/entity/csr_entity.toml tests/entity/entity_pk_id_Ed25519.der tests/entity/entity_sk_id_Ed25519.der tests/entity/entity_csr.c tests/entity/entity_csr.der
  ```

* Create certificate for the entity

  ```bash
  cborcert -g tests/ca1/ca1.toml tests/entity/entity_csr.der tests/entity/entity_pk_id_Ed25519.der tests/entity/entity_sk_id_Ed25519.der tests/entity/entity_cert.c tests/entity/entity_cert.der
  ```

* Parse and verify the certificate (optional just as test)

  ```bash
  cborcert -v tests/entity/entity_cert.der tests/ca1/ca1_pk_id_Ed25519.der tests/entity/entity_cert_ver.toml
  ```

  This command will output the decoded certificate content in the entity_cert_ver.toml file.