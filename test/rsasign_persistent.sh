#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary -a o -g sha256 -G rsa -o ${PARENT_CTX}
tpm2_flushcontext -t

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=rsakey.pub
TPM_RSA_KEY=rsakey
tpm2_create -p abc -C ${PARENT_CTX} -g sha256 -G rsa -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -b sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext -t

# Load Key to persistent handle
RSA_CTX=rsakey.ctx
tpm2_load -C ${PARENT_CTX} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -o ${RSA_CTX}
tpm2_flushcontext -t

HANDLE=$(tpm2_evictcontrol -a o -c ${RSA_CTX} | cut -d ' ' -f 2)
tpm2_flushcontext -t

# Signing Data
echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in mydata.txt -out mysig -passin stdin
# Get public key of handle
tpm2_readpublic -c ${HANDLE} -o mykey.pem -f pem

# Release persistent HANDLE
tpm2_evictcontrol -a o -c ${HANDLE}

R="$(openssl pkeyutl -pubin -inkey mykey.pem -verify -in mydata.txt -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
