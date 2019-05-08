#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary --hierarchy=o --halg=sha256 --kalg=rsa \
                   --out-context-name=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Create an RSA key pair
echo "Generating RSA key pair"
TPM_RSA_PUBKEY=rsakey.pub
TPM_RSA_KEY=rsakey
tpm2_create --context-parent=${PARENT_CTX} \
            --halg=sha256 --kalg=rsa \
            --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
            --object-attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load Key to persistent handle
RSA_CTX=rsakey.ctx
tpm2_load --context-parent=${PARENT_CTX} \
          --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
          --out-context=${RSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --context=${RSA_CTX} | cut -d ' ' -f 2 | head -n 1)
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
tpm2_readpublic --context=${HANDLE} --out-file=mykey.pem --format=pem

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --context=${HANDLE} --persistent=${HANDLE}

R="$(openssl pkeyutl -pubin -inkey mykey.pem -verify -in mydata.txt -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
