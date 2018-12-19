#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

PHANDLE=0x81010002

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_startup -T mssim -c || true

tpm2_createprimary -T mssim -H o -g sha256 -G rsa -C ${PARENT_CTX}

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
tpm2_create -T mssim -K abc -c ${PARENT_CTX} -g sha256 -G rsa -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -A sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load -T mssim -c ${PARENT_CTX} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -C ${RSA_CTX}

HANDLE=$(tpm2_evictcontrol -T mssim -A o -c ${RSA_CTX} -S ${PHANDLE} | cut -d ' ' -f 2)

# Signing Data
echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in ${DIR}/mydata.txt -out ${DIR}/mysig -passin stdin
# Get public key of handle
tpm2_readpublic -T mssim -H ${HANDLE} -o ${DIR}/mykey.pem -f pem

# Release persistent HANDLE
tpm2_evictcontrol -T mssim -A o -H ${HANDLE} -S ${HANDLE}

R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pem -verify -in ${DIR}/mydata.txt -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
