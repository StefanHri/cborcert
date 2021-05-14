#!/bin/sh

#run this script in order to generate a two-stage PKI

PKI_ROOT_DIR="sample_pki"
CBORCERT_PATH="target/debug"

rm -r $PKI_ROOT_DIR

mkdir $PKI_ROOT_DIR
mkdir $PKI_ROOT_DIR/ca0
mkdir $PKI_ROOT_DIR/ca1
mkdir $PKI_ROOT_DIR/entity

################################################################################
#CA0
echo "generate a keypair for CA0..."
$CBORCERT_PATH/cborcert -k "id-Ed25519" $PKI_ROOT_DIR/ca0/ca0.c $PKI_ROOT_DIR/ca0/ca0.der


echo "generate a configuration file for CA0.."
echo "certificate_serial_number = [1, 245, 13]
issuer = \"RFC test CA\"
validity_not_before = 1577836800
validity_not_after = 1612224000 
extensions = 1
issuer_signature_algorithm = \"id-Ed25519\"" >> $PKI_ROOT_DIR/ca0/ca0.toml

################################################################################
#CA1
echo "generate a configuration file for CA1.."
echo "certificate_serial_number = [1, 245, 13]
issuer = \"RFC test CA\"
validity_not_before = 1577836800
validity_not_after = 1612224000 
extensions = 1
issuer_signature_algorithm = \"id-Ed25519\"" >> $PKI_ROOT_DIR/ca1/ca1.toml

###
echo "generate a CSR configuration file for CA1.."
echo "
cbor_cert_type = 0
subject_common_name = [1, 35, 69, 103, 137, 171] # h'0123456789AB 
subject_pk_alg = \"id-Ed25519\"" >> $PKI_ROOT_DIR/ca1/csr_ca1.toml

###
echo "generate a keypair for CA1..."
$CBORCERT_PATH/cborcert -k "id-Ed25519" $PKI_ROOT_DIR/ca1/ca1.c $PKI_ROOT_DIR/ca1/ca1.der

###
echo "generate a CSR for CA1..."
$CBORCERT_PATH/cborcert -c $PKI_ROOT_DIR/ca1/csr_ca1.toml $PKI_ROOT_DIR/ca1/ca1_pk_id_Ed25519.der $PKI_ROOT_DIR/ca1/ca1_sk_id_Ed25519.der $PKI_ROOT_DIR/ca1/ca1_csr.c $PKI_ROOT_DIR/ca1/ca1_csr.der

###
echo "generate a certificate for CA1..."
$CBORCERT_PATH/cborcert -g $PKI_ROOT_DIR/ca0/ca0.toml $PKI_ROOT_DIR/ca1/ca1_csr.der $PKI_ROOT_DIR/ca0/ca0_pk_id_Ed25519.der $PKI_ROOT_DIR/ca0/ca0_sk_id_Ed25519.der $PKI_ROOT_DIR/ca1/ca1_cert.c $PKI_ROOT_DIR/ca1/ca1_cert.der

### 
echo "Parse and verify the certificate (optional just as test)"
$CBORCERT_PATH/cborcert -v $PKI_ROOT_DIR/ca1/ca1_cert.der $PKI_ROOT_DIR/ca0/ca0_pk_id_Ed25519.der $PKI_ROOT_DIR/ca1/ca1_cert_ver.toml

################################################################################
#Entity
echo "generate a CSR configuration file for entity..."
echo "cbor_cert_type = 0
subject_common_name = [1, 35, 69, 103, 137, 171] # h'0123456789AB 
subject_pk_alg = \"id-Ed25519\"" >> $PKI_ROOT_DIR/entity/csr_entity.toml

###
echo "generate a keypair for entity..."
$CBORCERT_PATH/cborcert -k "id-Ed25519" $PKI_ROOT_DIR/entity/entity.c $PKI_ROOT_DIR/entity/entity.der

###
echo "generate a CSR for entity..."
$CBORCERT_PATH/cborcert -c $PKI_ROOT_DIR/entity/csr_entity.toml $PKI_ROOT_DIR/entity/entity_pk_id_Ed25519.der $PKI_ROOT_DIR/entity/entity_sk_id_Ed25519.der $PKI_ROOT_DIR/entity/entity_csr.c $PKI_ROOT_DIR/entity/entity_csr.der

###
echo "generate a certificate for entity..."
$CBORCERT_PATH/cborcert -g $PKI_ROOT_DIR/ca1/ca1.toml $PKI_ROOT_DIR/entity/entity_csr.der $PKI_ROOT_DIR/ca1/ca1_pk_id_Ed25519.der $PKI_ROOT_DIR/ca1/ca1_sk_id_Ed25519.der $PKI_ROOT_DIR/entity/entity_cert.c $PKI_ROOT_DIR/entity/entity_cert.der

###
echo "Parse and verify the certificate (optional just as test)"
$CBORCERT_PATH/cborcert -v $PKI_ROOT_DIR/entity/entity_cert.der $PKI_ROOT_DIR/ca1/ca1_pk_id_Ed25519.der $PKI_ROOT_DIR/entity/entity_cert_ver.toml