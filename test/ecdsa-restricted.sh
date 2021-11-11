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
tpm2_create --parent-context=${PARENT_CTX} \
            --hash-algorithm=sha256 --key-algorithm=ecc256:ecdsa-sha256:null \
            --public=${TPM_ECDSA_PUBKEY} --private=${TPM_ECDSA_KEY} \
            --attributes=sign\|restricted\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
ECDSA_CTX=ecdsakey.ctx
tpm2_load --parent-context=${PARENT_CTX} \
          --public=${TPM_ECDSA_PUBKEY} --private=${TPM_ECDSA_KEY} \
          --key-context=${ECDSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${ECDSA_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

tpm2_readpublic --object-context=${HANDLE}

# Digest & sign Data
openssl dgst -engine tpm2tss -keyform engine -sha256 -sign ${HANDLE} -out mysig mydata.txt

# Get public key of handle
tpm2_readpublic --object-context=${HANDLE} --output=mykey.pem --format=pem

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}

R="$(openssl dgst -verify mykey.pem -sha256 -signature mysig mydata.txt || true)"
if ! echo $R | grep "Verified OK" >/dev/null; then
    echo $R
    exit 1
fi
