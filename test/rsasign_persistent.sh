#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx
tpm2_createprimary -a o -g sha256 -G rsa -o ${PARENT_CTX}

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
tpm2_create -C ${PARENT_CTX} -g sha256 -G rsa -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -A sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load -C ${PARENT_CTX} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -o ${RSA_CTX}
HANDLE=$(tpm2_evictcontrol -a o -c ${RSA_CTX} | cut -d ' ' -f 2)

# Signing Data
openssl pkeyutl -engine libtpm2tss -keyform engine -inkey ${HANDLE} -sign -in ${DIR}/mydata.txt -out ${DIR}/mysig
# Get public key of handle
tpm2_readpublic -c ${HANDLE} -o ${DIR}/mykey.pem -f pem

# Release persistent HANDLE
tpm2_evictcontrol -a o -c ${HANDLE}

R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pem -verify -in ${DIR}/mydata.txt -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
