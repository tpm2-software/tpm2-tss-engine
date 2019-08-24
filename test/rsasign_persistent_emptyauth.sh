#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create an Primary key pair
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
            --hash-algorithm=sha256 --key-algorithm=rsa \
            --public=${TPM_RSA_PUBKEY} --private=${TPM_RSA_KEY} \
            --attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
RSA_CTX=rsakey.ctx
tpm2_load --parent-context=${PARENT_CTX} \
          --public=${TPM_RSA_PUBKEY} --private=${TPM_RSA_KEY} \
          --key-context=${RSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${RSA_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Signing Data
#Actually signing should not require an auth value
if ! openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in mydata.txt -out mysig -passin file:notexists; then
#The expect script is only here, because tpm2-tss <2.2 had some bug, and thus us asking for passwords when none were required.
expect <<EOF
spawn openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${HANDLE} -sign -in mydata.txt -out mysig -passin stdin
expect "Enter password for user key:"
send "\r\n"
expect eof
EOF
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
