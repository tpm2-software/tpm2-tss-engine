#!/bin/bash

set -eufx

if [ -z "${OPENSSL_ENGINES-}" ]; then export OPENSSL_ENGINES=${PWD}/.libs; fi
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_startup --clear || true

tpm2_createprimary --hierarchy=o --halg=sha256 --kalg=rsa \
                   --out-context-name=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
tpm2_create --context-parent=${PARENT_CTX} \
            --halg=sha256 --kalg=rsa \
            --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
            --object-attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load --context-parent=${PARENT_CTX} \
          --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
          --out-context=${RSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --context=${RSA_CTX} | cut -d ' ' -f 2)
tpm2_flushcontext --transient-object

# Signing Data
#Actually signing should not require an auth value
if ! openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in ${DIR}/mydata.txt -out ${DIR}/mysig -passin file:notexists; then
#The expect script is only here, because tpm2-tss <2.2 had some bug, and thus us asking for passwords when none were required.
expect <<EOF
spawn openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in ${DIR}/mydata.txt -out ${DIR}/mysig -passin stdin
expect "Enter password for user key:"
send "\r\n"
expect eof
EOF
fi

# Get public key of handle
tpm2_readpublic --context=${HANDLE} --out-file=${DIR}/mykey.pem --format=pem

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --context=${HANDLE} --persistent=${HANDLE}

R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pem -verify -in ${DIR}/mydata.txt -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
