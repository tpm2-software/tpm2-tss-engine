#!/bin/bash

set -eufx

DIR=$(mktemp -d)
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
PARENT_CTX=${DIR}/primary_owner_key.ctx

echo -n "abcde12345abcde12345">${DIR}/mydata

tpm2_startup -c || true

# Create primary key as persistent handle
tpm2_createprimary --hierarchy=o --hash-algorithm=sha256 --key-algorithm=ecc \
                   --key-context=${PARENT_CTX} \
                   --attributes="decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted"
tpm2_flushcontext --transient-object

# Create an RSA key pair
echo "Generating RSA key pair"
tpm2_create --key-auth=abc --parent-context=${PARENT_CTX} \
            --hash-algorithm=sha256 --key-algorithm=rsa \
            --public=${TPM_RSA_PUBKEY} --private=${TPM_RSA_KEY} \
            --attributes="sign|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda"
tpm2_flushcontext --transient-object

tpm2tss-genkey --public ${TPM_RSA_PUBKEY} --private ${TPM_RSA_KEY} --password abc ${DIR}/mykey

echo "abc" | openssl rsa -engine tpm2tss -inform engine -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub -passin stdin

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig -passin stdin

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pub -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
