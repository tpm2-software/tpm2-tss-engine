#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary --hierarchy=o --hash-algorithm=sha256 --key-algorithm=rsa \
                   --key-context=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Load primary key to persistent handle
HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${PARENT_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Generating a key underneath the persistent parent
tpm2tss-genkey -a rsa -s 2048 -p abc -P ${HANDLE} mykey

echo "abc" | openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub -passin stdin
cat mykey.pub

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata.txt -out mysig -passin stdin

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey mykey.pub -verify -in mydata.txt -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
