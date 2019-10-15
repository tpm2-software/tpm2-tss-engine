#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create a Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary --hierarchy=o --hash-algorithm=sha256 --key-algorithm=ecc \
                   --key-context=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Create an ECDSA key pair
echo "Generating ECDSA key pair"
TPM_ECDSA_PUBKEY=ecdsakey.pub
TPM_ECDSA_KEY=ecdsakey
tpm2_create --key-auth=abc \
            --parent-context=${PARENT_CTX} \
            --hash-algorithm=sha256 --key-algorithm=ecc \
            --public=${TPM_ECDSA_PUBKEY} --private=${TPM_ECDSA_KEY} \
            --attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
ECDSA_CTX=ecdsakey.ctx
tpm2_load --parent-context=${PARENT_CTX} \
          --public=${TPM_ECDSA_PUBKEY} --private=${TPM_ECDSA_KEY} \
          --key-context=${ECDSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${ECDSA_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Signing Data
R="$(echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in mydata.txt -out mysig -passin stdin 2>&1 || true)"
if echo $R | grep "ErrorCode (0x000001c4)" > /dev/null; then
    echo $R
    exit 1
fi
# Get public key of handle
tpm2_readpublic --object-context=${HANDLE} --output=mykey.pem --format=pem

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}

R="$(openssl pkeyutl -pubin -inkey mykey.pem -verify -in mydata.txt -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
