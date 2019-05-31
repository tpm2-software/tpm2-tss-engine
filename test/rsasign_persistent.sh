#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_startup -c || true

tpm2_createprimary --hierarchy=o --halg=sha256 --kalg=rsa \
                   --context=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
tpm2_create --pwdk=abc \
            --context-parent=${PARENT_CTX} \
            --halg=sha256 --kalg=rsa \
            --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
            --object-attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load --context-parent=${PARENT_CTX} \
          --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
          --context=${RSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --auth=o --context=${RSA_CTX} --persistent=0x81010001 | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Signing Data
echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in ${DIR}/mydata.txt -out ${DIR}/mysig -passin stdin
# Get public key of handle
tpm2_readpublic --object=${HANDLE} --opu=${DIR}/mykey.pem --format=pem

# Release persistent HANDLE
tpm2_evictcontrol --auth=o --handle=${HANDLE} --persistent=${HANDLE}

R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pem -verify -in ${DIR}/mydata.txt -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
