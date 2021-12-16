#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create a Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary --hierarchy=o --hash-algorithm=sha256 --key-algorithm=rsa \
                   --key-context=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=rsakey.pub
TPM_RSA_KEY=rsakey
tpm2_create --parent-context=${PARENT_CTX} \
            --hash-algorithm=sha256 --key-algorithm=rsa:rsassa-sha256:null \
            --public=${TPM_RSA_PUBKEY} --private=${TPM_RSA_KEY} \
            --attributes=sign\|restricted\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
RSA_CTX=rsakey.ctx
tpm2_load --parent-context=${PARENT_CTX} \
          --public=${TPM_RSA_PUBKEY} --private=${TPM_RSA_KEY} \
          --key-context=${RSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${RSA_CTX} | cut -d ' ' -f 2 | head -n 1)
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
