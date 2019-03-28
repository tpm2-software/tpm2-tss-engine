#!/bin/bash

set -eufx

DIR=$(mktemp -d)
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
PARENT_CTX=${DIR}/primary_owner_key.ctx

echo -n "abcde12345abcde12345">${DIR}/mydata

tpm2_startup -c || true

# Create primary key as persistent handle
tpm2_createprimary --hierarchy=o -g sha256 -G rsa --context=${PARENT_CTX}
tpm2_flushcontext -t
#tpm2_evictcontrol --auth=o --context=${PARENT_CTX} --persistent 0x81010003
#tpm2_evictcontrol --auth=o --handle 0x81010003     --persistent 0x81010003
#tpm2_flushcontext -t
HANDLE=$(tpm2_evictcontrol --auth=o --context=${PARENT_CTX} --persistent 0x81010003 | cut -d ' ' -f 2)
tpm2_flushcontext -t

# Create an RSA key pair
echo "Generating RSA key pair"
tpm2_create --pwdk=abc --parent=${HANDLE} -g sha256 -G rsa \
    --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
    --object-attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext -t

tpm2tss-genkey -i ${TPM_RSA_PUBKEY} -k ${TPM_RSA_KEY} -p abc -P ${HANDLE} ${DIR}/mykey

echo "abc" | openssl rsa -engine tpm2tss -inform engine -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub -passin stdin

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig -passin stdin

# Release persistent HANDLE
tpm2_evictcontrol --auth=o --handle 0x81010003     --persistent 0x81010003

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pub -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
